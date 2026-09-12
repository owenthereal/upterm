package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
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

// What an authenticated peer may be told about an upstream that would not
// complete. Each is a fixed string uptermd owns, so no upstream error text is
// ever relayed: a transport failure reads "read tcp <local>-><node>: i/o
// timeout" and a dial failure names the session socket path.
var (
	errUpstreamUnavailable = errors.New("upstream unavailable")
	errUpstreamAuthFailed  = errors.New("ssh: unable to authenticate with the upstream")
)

// sshAuthFailure is the message x/crypto composes when no auth method is left
// (client_auth.go). It carries no addresses, but there is no exported error to
// match on, so match the text: if it ever drifts the peer is simply told the
// upstream is unavailable, which is the safe direction to fail in.
const sshAuthFailure = "unable to authenticate"

// upstreamFailureReason maps an upstream failure onto what the peer is told.
// It is an allowlist: only outcomes recognized here are named, and everything
// else — most importantly any transport error, which carries the address of an
// internal node or socket — becomes the generic reason. The detail stays in the
// connection log either way.
func upstreamFailureReason(err error) error {
	switch {
	case errors.Is(err, errUpstreamHostKeyMismatch):
		return errUpstreamHostKeyMismatch
	case err != nil && strings.Contains(err.Error(), sshAuthFailure):
		return errUpstreamAuthFailed
	default:
		return errUpstreamUnavailable
	}
}

// abortScopeFor decides how far a stalled channel on this connection may
// escalate, from the same client version the metrics below count. A host's
// transport carries the reverse tunnel every guest's traffic rides, so a
// stalled channel on it must never take it down; a guest's transport is that
// guest's alone. Getting this backwards costs a host's whole session the first
// time any one guest stops reading, so it is a function with a test rather than
// a condition inline at the call.
func abortScopeFor(clientVersion string) sshAbortScope {
	if clientVersion == upterm.HostSSHClientVersion {
		return abortChannel
	}
	return abortConnection
}

// isRecoverableAcceptError reports whether Accept is worth retrying. A timeout
// comes from a deadline set on a wrapped listener; the rest are resource
// exhaustion, which clears as open connections drain and which taking the
// daemon down would only make worse. Go reports these as Temporary, but that
// method is deprecated and ill-defined, so match the errno values directly.
// Anything else means the listener itself is gone and Serve must return.
func isRecoverableAcceptError(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM)
}

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
			// A recoverable accept error must not take the whole listener down:
			// returning here fails the run.Group actor and terminates uptermd.
			if isRecoverableAcceptError(err) {
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
	// What the peer is told; see upstreamFailureReason. A dial failure has no
	// recognized outcome of its own, so it stays generic.
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
				reason = upstreamFailureReason(err)
			} else {
				defer func() { _ = upstream.Close() }()
				if err = upstreamRaw.SetDeadline(time.Time{}); err == nil {
					cancel()
					clientVersion := string(downstream.ClientVersion())
					if clientVersion == upterm.HostSSHClientVersion {
						inst.authenticatedHost.Add(1)
					} else {
						inst.authenticatedClient.Add(1)
					}
					return forwardSSH(ctx, peer, sshPeer{upstream, upstreamChannels, upstreamRequests}, abortScopeFor(clientVersion), p.logger())
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
