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

// maxSSHRejectTimeout caps delivery of an upstream failure to a peer whose
// downstream authentication already succeeded. One packet is enough, and a
// host disconnects as soon as its global request is answered, so the cap only
// bites when a peer authenticates and then says nothing at all.
const maxSSHRejectTimeout = 5 * time.Second

// errUpstreamUnavailable is what a peer is told when the upstream dial fails.
// The underlying error names internal socket paths and node addresses.
var errUpstreamUnavailable = errors.New("upstream unavailable")

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
	defer p.joinWorkers()
	defer cancel()
	var retryDelay time.Duration // how long to sleep on accept failure
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ErrListnerClosed
			}
			// A temporary accept error must not take the whole listener down:
			// returning here fails the run.Group actor and terminates uptermd.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if retryDelay == 0 {
					retryDelay = 5 * time.Millisecond
				} else {
					retryDelay *= 2
				}
				retryDelay = min(retryDelay, maxAcceptRetryDelay)
				p.logger().Error("tcp: Accept error; retrying", "error", err, "retry_delay", retryDelay)
				select {
				case <-time.After(retryDelay):
				case <-ctx.Done():
					return ErrListnerClosed
				}
				continue
			}
			p.logger().Error("failed to accept connection", "error", err)
			inst.errors.Add(1)
			return err
		}
		retryDelay = 0
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
				p.logger().Debug("SSH connection ended", "addr", raw.RemoteAddr(), "error", err)
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
	var clientConfig *ssh.ClientConfig
	cfg := &ssh.ServerConfig{
		ServerVersion: version.ServerSSHVersion(),
		// Authorization only. x/crypto invokes this for unsigned public-key
		// queries too, and a successful query takes `continue userAuthLoop`
		// without incrementing authFailures, so MaxAuthTries does not bound it.
		// Anything expensive here is reachable before any signature is verified.
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if _, _, _, err := p.Auth.authorize(meta, key); err != nil {
				return nil, err
			}
			return &ssh.Permissions{}, nil
		},
		// Minting upstream credentials costs a certificate signature per
		// configured signer, so it waits until the client has proven it holds
		// the key. Running once, after verification, also removes any need to
		// match credentials back to an offered key after the handshake.
		VerifiedPublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey, permissions *ssh.Permissions, _ string) (*ssh.Permissions, error) {
			upstream, err := p.Auth.prepare(meta, key)
			if err != nil {
				return nil, err
			}
			clientConfig = upstream
			return permissions, nil
		},
	}
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
	if clientConfig == nil {
		return fmt.Errorf("missing authenticated upstream credentials")
	}
	peer := sshPeer{downstream, channels, requests}
	upstreamCtx, cancel := context.WithTimeout(ctx, stage)
	defer cancel()
	// What the peer is told. A dial error names internal socket paths and node
	// addresses, so it stays in the log; upstream handshake errors ("unable to
	// authenticate", "host key mismatch") are already generic and worth passing
	// through, and hosts and clients both act on them.
	reason := errUpstreamUnavailable
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
			if err != nil {
				reason = err
			} else {
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
	// Report the failure on a fresh budget rather than upstreamCtx's: on a dial
	// or handshake timeout — the most common way to get here — that budget is
	// already spent, and the peer would be dropped without ever being told why.
	// Deriving it from stage keeps a short configured timeout short overall.
	// The helper also answers global requests, including hosts' first request.
	rejectCtx, rejectCancel := context.WithTimeout(ctx, min(stage, maxSSHRejectTimeout))
	defer rejectCancel()
	_ = rejectSSHChannels(rejectCtx, peer, reason)
	return err
}
