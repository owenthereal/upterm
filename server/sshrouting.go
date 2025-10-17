package server

import (
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

var (
	ErrListnerClosed        = errors.New("routing: listener closed")
	pipeEstablishingTimeout = 60 * time.Second
)

type SSHRouting struct {
	HostSigners     []ssh.Signer
	AuthPiper       *authPiper
	Decoder         routing.Decoder
	Logger          *slog.Logger
	MetricsProvider provider.Provider

	listener net.Listener
	mux      sync.Mutex
	doneChan chan struct{}
}

type routingInstruments struct {
	connections        metrics.Counter
	activeConnections  metrics.Gauge
	connectionDuration metrics.Histogram
	errors             metrics.Counter
	connectionTimeouts metrics.Counter
}

func newSSHRoutingInstruments(p provider.Provider) *routingInstruments {
	return &routingInstruments{
		connections:        p.NewCounter("routing_connections_count"),
		errors:             p.NewCounter("routing_errors_count"),
		activeConnections:  p.NewGauge("routing_active_connections_count"),
		connectionDuration: p.NewHistogram("routing_connection_duration_seconds", 50),
		connectionTimeouts: p.NewCounter("routing_connection_timeout_count"),
	}
}

func (p *SSHRouting) Serve(ln net.Listener) error {
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

			pipec := make(chan *ssh.PiperConn)
			errorc := make(chan error)

			go func() {
				defer func() {
					close(pipec)
					close(errorc)
				}()

				pconn, err := ssh.NewSSHPiperConn(dconn, piperCfg)
				if err != nil {
					errorc <- err
					return
				}

				pipec <- pconn
			}()

			select {
			case pconn := <-pipec:
				defer pconn.Close()

				if err := pconn.Wait(); err != nil {
					logger.Debug("error waiting for pipe", "error", err)
					inst.errors.Add(1)
				}
			case err := <-errorc:
				logger.Debug("connection establishing failed", "error", err)
				inst.errors.Add(1)
			case <-time.After(pipeEstablishingTimeout):
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
	p.mux.Unlock()

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
	return p.listener.Close()
}
