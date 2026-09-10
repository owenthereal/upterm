package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/owenthereal/upterm/internal/version"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

func (p *SSHRouting) serveStock(ln net.Listener) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.mux.Lock()
	p.listener, p.cancel = ln, cancel
	select {
	case <-p.getDoneChanLocked():
		cancel()
	default:
	}
	p.mux.Unlock()
	if ctx.Err() != nil {
		_ = ln.Close()
		return ErrListnerClosed
	}
	inst := newSSHRoutingInstruments(p.MetricsProvider)
	defer p.workers.Wait()
	defer cancel()
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ErrListnerClosed
			}
			return err
		}
		p.mux.Lock()
		if ctx.Err() != nil {
			p.mux.Unlock()
			_ = raw.Close()
			return ErrListnerClosed
		}
		p.workers.Add(1)
		p.mux.Unlock()
		go func() {
			defer p.workers.Done()
			start := time.Now()
			inst.connections.Add(1)
			inst.activeConnections.Add(1)
			defer inst.activeConnections.Add(-1)
			defer func() { inst.connectionDuration.Observe(time.Since(start).Seconds()) }()
			if err := p.stockConnection(ctx, raw, inst); err != nil {
				p.Logger.Debug("SSH connection ended", "addr", raw.RemoteAddr(), "error", err)
				var ne net.Error
				if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
					inst.connectionTimeouts.Add(1)
				} else {
					inst.errors.Add(1)
				}
			}
		}()
	}
}

func (p *SSHRouting) stockConnection(ctx context.Context, raw net.Conn, inst *routingInstruments) error {
	defer func() { _ = raw.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	// Permissions are returned from the key that actually signs, including when
	// x/crypto reuses a cached unsigned query. Never choose the last offered key.
	prepared := make(map[*ssh.Permissions]*ssh.ClientConfig)
	cfg := &ssh.ServerConfig{ServerVersion: version.ServerSSHVersion(), PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		upstream, err := p.Auth.prepare(meta, key)
		if err != nil {
			return nil, err
		}
		permissions := &ssh.Permissions{}
		prepared[permissions] = upstream
		return permissions, nil
	}}
	for _, key := range p.HostSigners {
		cfg.AddHostKey(key)
	}
	stage := p.handshakeTimeout() / 2
	if err := raw.SetDeadline(time.Now().Add(stage)); err != nil {
		return err
	}
	downstream, channels, requests, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = downstream.Close() }()
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return err
	}
	clientConfig := prepared[downstream.Permissions]
	if clientConfig == nil {
		return fmt.Errorf("missing authenticated upstream credentials")
	}
	peer := sshPeer{downstream, channels, requests}
	upstreamCtx, cancel := context.WithTimeout(ctx, stage)
	defer cancel()
	upstreamRaw, err := p.Auth.dialUpstreamContext(upstreamCtx, downstream)
	if err == nil {
		defer func() { _ = upstreamRaw.Close() }()
		stopUpstream := context.AfterFunc(ctx, func() { _ = upstreamRaw.Close() })
		defer stopUpstream()
		deadline, _ := upstreamCtx.Deadline()
		err = upstreamRaw.SetDeadline(deadline)
		if err == nil {
			var upstream ssh.Conn
			var upstreamChannels <-chan ssh.NewChannel
			var upstreamRequests <-chan *ssh.Request
			upstream, upstreamChannels, upstreamRequests, err = ssh.NewClientConn(upstreamRaw, upstreamRaw.RemoteAddr().String(), clientConfig)
			if err == nil {
				defer func() { _ = upstream.Close() }()
				if err = upstreamRaw.SetDeadline(time.Time{}); err == nil {
					cancel()
					if string(downstream.ClientVersion()) == upterm.HostSSHClientVersion {
						inst.authenticatedHost.Add(1)
					} else {
						inst.authenticatedClient.Add(1)
					}
					return forwardSSH(ctx, peer, sshPeer{upstream, upstreamChannels, upstreamRequests})
				}
			}
		}
	}
	// Use the remaining upstream budget for clients that have no channel yet.
	// The helper also answers global requests, including hosts' first request.
	_ = rejectSSHChannels(upstreamCtx, peer, err)
	return err
}
