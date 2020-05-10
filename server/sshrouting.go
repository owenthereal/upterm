package server

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/metrics/provider"
	libmetrics "github.com/jingweno/upterm/metrics"
	"github.com/jingweno/upterm/upterm"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var (
	ErrListnerClosed        = errors.New("routing: listener closed")
	pipeEstablishingTimeout = 5 * time.Second
)

const (
	errReadConnectionResetByPeer = "read: connection reset by peer"
	errSshDisconnectReason11     = "ssh: disconnect, reason 11:"
	errUnknownClient             = "unknown client:"
)

type FindUpstreamFunc func(conn ssh.ConnMetadata, challengeCtx ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error)

type SSHRouting struct {
	HostSigners      []ssh.Signer
	FindUpstreamFunc FindUpstreamFunc
	Logger           log.FieldLogger
	MetricsProvider  provider.Provider

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
		connectionDuration: p.NewHistogram("routing_connection_duration_ms", 50),
		connectionTimeouts: p.NewCounter("routing_connection_timeout_count"),
	}
}

func (p *SSHRouting) Serve(ln net.Listener) error {
	p.mux.Lock()
	p.listener = ln
	p.mux.Unlock()

	piper := &ssh.PiperConfig{
		FindUpstream:  p.FindUpstreamFunc,
		ServerVersion: upterm.ServerSSHServerVersion,
	}
	for _, signer := range p.HostSigners {
		piper.AddHostKey(signer)
	}

	inst := newSSHRoutingInstruments(p.MetricsProvider)

	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-p.getDoneChan():
				return ErrListnerClosed
			default:
			}

			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				p.Logger.WithError(err).Errorf("tcp: Accept error; retrying in %v", tempDelay)
				time.Sleep(tempDelay)
				continue
			}

			p.Logger.WithError(err).Error("failed to accept connection")
			inst.errors.Add(1)
			return err
		}

		tempDelay = 0

		logger := p.Logger.WithField("addr", conn.RemoteAddr())
		go func(c net.Conn, inst *routingInstruments, logger log.FieldLogger) {
			defer c.Close()

			defer libmetrics.MeasureSince(inst.connectionDuration, time.Now())
			defer inst.activeConnections.Add(-1)
			inst.connections.Add(1)
			inst.activeConnections.Add(1)

			pipec := make(chan *ssh.PiperConn)
			errorc := make(chan error)

			go func() {
				p, err := ssh.NewSSHPiperConn(c, piper)
				if err != nil {
					errorc <- err
					return
				}

				pipec <- p
			}()

			select {
			case pc := <-pipec:
				defer pc.Close()

				if err := pc.Wait(); err != nil {
					logger.WithError(err).Debug("error waiting for pipe")
					inst.errors.Add(1)
				}
			case err := <-errorc:
				logger.WithError(err).Debug("connection establishing failed")
				inst.errors.Add(1)
			case <-time.After(pipeEstablishingTimeout):
				logger.Debug("pipe establishing timeout")
				inst.connectionTimeouts.Add(1)
			}
		}(conn, inst, logger)
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

func isIgnoredErr(err error) bool {
	return errors.Is(err, io.EOF) ||
		strings.Contains(err.Error(), errReadConnectionResetByPeer) ||
		strings.Contains(err.Error(), errSshDisconnectReason11) ||
		strings.Contains(err.Error(), errUnknownClient)
}
