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
	"golang.org/x/crypto/ssh"
)

const DefaultHandshakeTimeout = 60 * time.Second

var ErrListnerClosed = errors.New("routing: listener closed")

type SSHRouting struct {
	HandshakeTimeout time.Duration
	HostSigners      []ssh.Signer
	Auth             *proxyAuth
	Logger           *slog.Logger
	MetricsProvider  provider.Provider

	cancel   context.CancelFunc
	workers  sync.WaitGroup
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
	return p.serveStock(ln)
}

func (p *SSHRouting) Shutdown() error {
	p.mux.Lock()
	lnerr := p.closeListenersLocked()
	p.closeDoneChanLocked()
	if p.cancel != nil {
		p.cancel()
	}
	p.mux.Unlock()

	p.workers.Wait()
	return lnerr
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
