package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/internal/version"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

const DefaultHandshakeTimeout = 60 * time.Second

var ErrListnerClosed = errors.New("routing: listener closed")

type SSHRouting struct {
	StockSSH         bool
	HandshakeTimeout time.Duration
	HostSigners      []ssh.Signer
	AuthPiper        *authPiper
	Decoder          routing.Decoder
	Logger           *slog.Logger
	MetricsProvider  provider.Provider

	stockCancel context.CancelFunc
	workers     sync.WaitGroup
	listener    net.Listener
	mux         sync.Mutex
	doneChan    chan struct{}
}

type routingInstruments struct {
	connections        metrics.Counter
	activeConnections  metrics.Gauge
	connectionDuration metrics.Histogram
	errors             metrics.Counter
	connectionTimeouts metrics.Counter
	// authenticatedHost and authenticatedClient count connections whose
	// downstream and upstream authentication both completed, split by what
	// connected. connections counts every accepted TCP connection, scanners
	// included.
	authenticatedHost   metrics.Counter
	authenticatedClient metrics.Counter
}

func newSSHRoutingInstruments(p provider.Provider) *routingInstruments {
	authenticated := newLabeledCounter(p, "routing_authenticated_connections_count", "kind")
	inst := &routingInstruments{
		connections:         p.NewCounter("routing_connections_count"),
		errors:              p.NewCounter("routing_errors_count"),
		activeConnections:   p.NewGauge("routing_active_connections_count"),
		connectionDuration:  p.NewHistogram("routing_connection_duration_seconds", 50),
		connectionTimeouts:  p.NewCounter("routing_connection_timeout_count"),
		authenticatedHost:   authenticated.With("kind", "host"),
		authenticatedClient: authenticated.With("kind", "client"),
	}
	inst.authenticatedHost.Add(0) // export both series from startup
	inst.authenticatedClient.Add(0)
	return inst
}

func (p *SSHRouting) Serve(ln net.Listener) error {
	if p.HandshakeTimeout < 0 {
		return fmt.Errorf("handshake-timeout must not be negative")
	}
	if p.StockSSH {
		return p.serveStock(ln)
	}
	p.mux.Lock()
	p.listener = ln
	p.mux.Unlock()

	piperCfg := &ssh.PiperConfig{
		PublicKeyCallback: p.AuthPiper.PublicKeyCallback,
		ServerVersion:     version.ServerSSHVersion(),
		NextAuthMethods: func(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) ([]string, error) {
			// Fail early if the user is not a valid identifier.
			user := conn.User()
			if user != "" {
				clientVersion := string(conn.ClientVersion())

				// HOST connections: just validate user is not empty
				if clientVersion == upterm.HostSSHClientVersion {
					if user == "" {
						return nil, fmt.Errorf("empty session ID for host connection")
					}
				} else {
					// CLIENT connections: validate SSH user format
					_, _, err := p.Decoder.Decode(user)
					if err != nil {
						return nil, fmt.Errorf("invalid SSH user format: %w", err)
					}
				}
			}

			return []string{"publickey"}, nil
		},
	}
	for _, s := range p.HostSigners {
		piperCfg.AddHostKey(s)
	}

	inst := newSSHRoutingInstruments(p.MetricsProvider)

	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		dconn, err := ln.Accept()
		if err != nil {
			select {
			case <-p.getDoneChan():
				return ErrListnerClosed
			default:
			}

			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				p.Logger.Error("tcp: Accept error; retrying", "error", err, "retry_delay", tempDelay)
				time.Sleep(tempDelay)
				continue
			}

			p.Logger.Error("failed to accept connection", "error", err)
			inst.errors.Add(1)
			return err
		}

		tempDelay = 0

		logger := p.Logger.With("addr", dconn.RemoteAddr())
		go func(dconn net.Conn, inst *routingInstruments, logger *slog.Logger) {
			startTime := time.Now()

			defer func() {
				_ = dconn.Close()
			}()
			defer func() {
				// Track connection duration in seconds
				durationSec := time.Since(startTime).Seconds()
				inst.connectionDuration.Observe(durationSec)
			}()
			defer inst.activeConnections.Add(-1)

			inst.connections.Add(1)
			inst.activeConnections.Add(1)

			type pipeResult struct {
				conn *ssh.PiperConn
				err  error
			}
			results := make(chan pipeResult)
			establishment, cancel := context.WithTimeout(context.Background(), p.handshakeTimeout())
			defer cancel()
			go func() {
				conn, err := ssh.NewSSHPiperConn(dconn, piperCfg)
				select {
				case results <- pipeResult{conn, err}:
				case <-establishment.Done():
					if conn != nil {
						conn.Close()
					}
				}
			}()
			select {
			case result := <-results:
				if result.err != nil {
					logger.Debug("connection establishing failed", "error", result.err)
					inst.errors.Add(1)
					return
				}
				pconn := result.conn
				defer pconn.Close()

				// NewSSHPiperConn returns only once both sides have
				// authenticated. PublicKeyCallback is too early: the
				// server also invokes it for unsigned key queries.
				if string(pconn.DownstreamConnMeta().ClientVersion()) == upterm.HostSSHClientVersion {
					inst.authenticatedHost.Add(1)
				} else {
					inst.authenticatedClient.Add(1)
				}

				if err := pconn.Wait(); err != nil {
					logger.Debug("error waiting for pipe", "error", err)
					inst.errors.Add(1)
				}
			case <-establishment.Done():
				logger.Debug("pipe establishing timeout")
				inst.connectionTimeouts.Add(1)
			}
		}(dconn, inst, logger)
	}
}

func (p *SSHRouting) Shutdown() error {
	p.mux.Lock()
	lnerr := p.closeListenersLocked()
	p.closeDoneChanLocked()
	if p.stockCancel != nil {
		p.stockCancel()
	}
	p.mux.Unlock()

	p.workers.Wait()
	return lnerr
}

func (p *SSHRouting) getDoneChan() <-chan struct{} {
	p.mux.Lock()
	defer p.mux.Unlock()

	return p.getDoneChanLocked()
}

func (p *SSHRouting) getDoneChanLocked() chan struct{} {
	if p.doneChan == nil {
		p.doneChan = make(chan struct{})
	}

	return p.doneChan
}

func (p *SSHRouting) closeDoneChanLocked() {
	ch := p.getDoneChanLocked()
	select {
	case <-ch:
		// Already closed. Don't close again.
	default:
		// Safe to close here. We're the only closer, guarded
		// by p.mux.
		close(ch)
	}
}

func (p *SSHRouting) closeListenersLocked() error {
	if p.listener == nil {
		return nil
	}
	return p.listener.Close()
}

func (p *SSHRouting) handshakeTimeout() time.Duration {
	if p.HandshakeTimeout == 0 {
		return DefaultHandshakeTimeout
	}
	return p.HandshakeTimeout
}
