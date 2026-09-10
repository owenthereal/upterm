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

const (
	// routingShutdownDeadline bounds how long shutdown joins in-flight
	// connections. Cancelling closes both transports of every forwarder, so
	// workers normally exit at once; the deadline covers one wedged on a mux
	// that never drains. Routing is one of several serial run.Group interrupts,
	// so an unbounded wait here stalls every other component behind it.
	routingShutdownDeadline = 5 * time.Second
	// maxAcceptRetryDelay caps the backoff applied to temporary Accept errors.
	maxAcceptRetryDelay = 1 * time.Second
	// maxHandshakeTimeout keeps the establishment budget inside the validity of
	// the user certificate minted during downstream authentication. That
	// certificate is good for certClockSkewTolerance and is presented to the
	// upstream up to one stage (handshake-timeout/2) later, so a larger budget
	// would have uptermd's own sshd reject uptermd's own freshly minted cert.
	maxHandshakeTimeout = 2 * certClockSkewTolerance
	// minHandshakeTimeout rejects budgets too small to complete a key exchange
	// and authentication over a network. Each half of the budget must cover a
	// full handshake, so anything below this fails every connection, and the
	// misconfiguration then looks like a total outage with no stated cause.
	// Only Opt applies it: operator config is held to a stricter standard than
	// the library API, which tests drive directly with much shorter budgets.
	minHandshakeTimeout = 1 * time.Second
)

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
	if err := validateHandshakeTimeout(p.HandshakeTimeout); err != nil {
		return err
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

	p.joinWorkers()
	return lnerr
}

// joinWorkers waits for in-flight connections to finish, bounded so a forwarder
// that never unblocks cannot hold up the rest of the shutdown chain.
func (p *SSHRouting) joinWorkers() {
	joined := make(chan struct{})
	go func() { defer close(joined); p.workers.Wait() }()
	timer := time.NewTimer(routingShutdownDeadline)
	defer timer.Stop()
	select {
	case <-joined:
	case <-timer.C:
		p.logger().Warn("timed out joining SSH connections", "deadline", routingShutdownDeadline)
	}
}

// logger tolerates a zero-value SSHRouting, which Serve and Shutdown both
// accept and which tests construct directly.
func (p *SSHRouting) logger() *slog.Logger {
	if p.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return p.Logger
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

// validateHandshakeTimeout is shared by Opt.Validate and SSHRouting.Serve so
// the operator-facing and library-facing entrypoints cannot disagree on the
// bounds they do share.
func validateHandshakeTimeout(d time.Duration) error {
	if d < 0 {
		return fmt.Errorf("handshake-timeout must not be negative")
	}
	if d >= maxHandshakeTimeout {
		return fmt.Errorf("handshake-timeout must be less than %s: half of it bounds the upstream handshake, which must present a user certificate only valid for %s", maxHandshakeTimeout, certClockSkewTolerance)
	}
	return nil
}

func (p *SSHRouting) handshakeTimeout() time.Duration {
	if p.HandshakeTimeout == 0 {
		return DefaultHandshakeTimeout
	}
	return p.HandshakeTimeout
}
