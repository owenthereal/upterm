package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"log/slog"

	gliderssh "charm.land/ssh"
	"github.com/go-kit/kit/metrics/provider"
	"github.com/oklog/run"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/utils"
	"github.com/owenthereal/upterm/ws"
	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ssh"
)

const (
	tcpDialTimeout = 1 * time.Second
)

type Opt struct {
	HandshakeTimeout         time.Duration `mapstructure:"handshake-timeout"`
	SSHAddr                  string        `mapstructure:"ssh-addr"`
	SSHNetwork               string        `mapstructure:"ssh-network"`
	SSHProxyProtocol         bool          `mapstructure:"ssh-proxy-protocol"`
	SSHProxyProtocolRequired bool          `mapstructure:"ssh-proxy-protocol-required"`
	WSAddr                   string        `mapstructure:"ws-addr"`
	NodeAddr                 string        `mapstructure:"node-addr"`
	InternalAddr             string        `mapstructure:"internal-addr"`
	AuthorizedKeysFiles      []string      `mapstructure:"authorized-keys"`
	HopKeys                  []string      `mapstructure:"hop-key"`
	HopTrustedKeys           []string      `mapstructure:"hop-trusted-key"`
	HopRefuseHostKey         bool          `mapstructure:"hop-refuse-host-key"`
	PrivateKeys              []string      `mapstructure:"private-key"`
	Hostnames                []string      `mapstructure:"hostname"`
	Network                  string        `mapstructure:"network"`
	NetworkOpts              []string      `mapstructure:"network-opt"`
	MetricAddr               string        `mapstructure:"metric-addr"`
	Debug                    bool          `mapstructure:"debug"`
	Routing                  routing.Mode  `mapstructure:"routing"`
	ConsulURL                string        `mapstructure:"consul-url"`
	ConsulSessionTTL         string        `mapstructure:"consul-session-ttl"`
	SentryDSN                string        `mapstructure:"sentry-dsn"`
}

// ResolvedRouting returns the effective routing mode. It resolves ModeAuto
// against whether a Consul URL was configured, and supplies the ModeEmbedded
// default for a zero value.
func (opt *Opt) ResolvedRouting() routing.Mode {
	switch opt.Routing {
	case routing.ModeAuto:
		if opt.ConsulURL != "" {
			return routing.ModeConsul
		}
		return routing.ModeEmbedded
	case "":
		return routing.ModeEmbedded
	default:
		return opt.Routing
	}
}

// Validate validates the server configuration
func (opt *Opt) Validate() error {
	if err := validateHandshakeTimeout(opt.HandshakeTimeout); err != nil {
		return err
	}
	// Operator config gets the stricter floor; 0 still selects the default.
	if opt.HandshakeTimeout > 0 && opt.HandshakeTimeout < minHandshakeTimeout {
		return fmt.Errorf("handshake-timeout must be at least %s: half of it must cover a full SSH handshake", minHandshakeTimeout)
	}
	switch opt.SSHNetwork {
	case "", "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("ssh-network must be tcp, tcp4 or tcp6")
	}
	if opt.SSHProxyProtocolRequired && opt.InternalAddr == "" {
		return fmt.Errorf("ssh-proxy-protocol-required needs internal-addr: node hops and WebSocket bridges can't send a PROXY header")
	}
	if opt.HopRefuseHostKey && len(opt.HopKeys) == 0 && len(opt.HopTrustedKeys) == 0 && os.Getenv("HOP_KEY") == "" {
		return fmt.Errorf("hop-refuse-host-key needs hop-key or hop-trusted-key, or no node could hop")
	}
	// Basic validation
	if opt.SSHAddr == "" {
		return fmt.Errorf("ssh-addr is required")
	}
	if err := opt.validateInternalAddr(); err != nil {
		return err
	}

	// Routing-specific validation
	switch routingMode := opt.ResolvedRouting(); routingMode {
	case routing.ModeConsul:
		return opt.validateConsulConfig()
	case routing.ModeEmbedded:
		return opt.validateEmbeddedConfig()
	default:
		return fmt.Errorf("unsupported routing mode: %s", routingMode)
	}
}

// validateInternalAddr requires node-addr beside an internal-addr whose host
// is a wildcard. NodeAddr is where neighbours hop to this node, and without
// node-addr it is the internal listener's bound address, which for a wildcard
// is no address another machine can dial.
func (opt *Opt) validateInternalAddr() error {
	if opt.InternalAddr == "" || opt.NodeAddr != "" {
		return nil
	}
	host, _, err := net.SplitHostPort(opt.InternalAddr)
	if err != nil {
		// Left to the listen, whose error says what is wrong with it.
		return nil
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		return fmt.Errorf("internal-addr is a wildcard; set node-addr to the address neighbours dial")
	}
	return nil
}

// validateConsulConfig validates Consul-specific configuration
func (opt *Opt) validateConsulConfig() error {
	if opt.ConsulURL == "" {
		return fmt.Errorf("consul-url is required for consul routing mode")
	}

	// Validate Consul URL format
	if _, err := url.Parse(opt.ConsulURL); err != nil {
		return fmt.Errorf("invalid consul URL format: %w", err)
	}

	// Validate TTL format if provided
	if opt.ConsulSessionTTL != "" {
		if _, err := time.ParseDuration(opt.ConsulSessionTTL); err != nil {
			return fmt.Errorf("invalid consul session TTL format: %w", err)
		}
	}

	return nil
}

// validateEmbeddedConfig validates embedded mode configuration
func (opt *Opt) validateEmbeddedConfig() error {
	// No special validation needed for embedded mode
	return nil
}

func Start(ctx context.Context, opt Opt, logger *slog.Logger) error {
	// Validate configuration upfront
	if err := opt.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	network := networks.Get(opt.Network)
	if network == nil {
		return fmt.Errorf("unsupported network provider %q", opt.Network)
	}

	opts := parseNetworkOpt(opt.NetworkOpts)
	if err := network.SetOpts(opts); err != nil {
		return fmt.Errorf("network provider option error: %s", err)
	}

	privateKeys, err := utils.ReadFiles(opt.PrivateKeys)
	if err != nil {
		return err
	}

	if pp := os.Getenv("PRIVATE_KEY"); pp != "" {
		privateKeys = append(privateKeys, []byte(pp))
	}

	signers, err := utils.CreateSigners(privateKeys)
	if err != nil {
		return err
	}

	hopKeys, err := utils.ReadFiles(opt.HopKeys)
	if err != nil {
		return err
	}
	if key := os.Getenv("HOP_KEY"); key != "" {
		hopKeys = append(hopKeys, []byte(key))
	}
	var hopSigners []ssh.Signer
	if len(hopKeys) > 0 {
		hopSigners, err = utils.CreateSigners(hopKeys)
		if err != nil {
			return err
		}
	}
	var hopTrusted []ssh.PublicKey
	for i, line := range opt.HopTrustedKeys {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return fmt.Errorf("hop-trusted-key at index %d: %w", i, err)
		}
		hopTrusted = append(hopTrusted, key)
	}

	// key signers + corresponding cert signers
	hostSigners := slices.Clone(signers)
	for _, s := range signers {
		hs := HostCertSigner{
			Hostnames: opt.Hostnames,
		}
		ss, err := hs.SignCert(s)
		if err != nil {
			return err
		}

		hostSigners = append(hostSigners, ss)
	}

	// logger is already the parameter, just add context
	logger = logger.With("app", "uptermd", "network", opt.Network, "network_opt", opt.NetworkOpts)

	var (
		sshln      net.Listener
		wsln       net.Listener
		internalln net.Listener
	)
	listenersOwned := true
	defer func() {
		if listenersOwned {
			closeListeners(logger, sshln, wsln, internalln)
		}
	}()

	if opt.SSHAddr != "" {
		sshln, err = listenSSH(opt.SSHNetwork, opt.SSHAddr)
		if err != nil {
			return err
		}
		logger = logger.With("ssh_addr", sshln.Addr().String())
		if opt.SSHProxyProtocolRequired {
			sshln = RequireProxyV2(sshln)
		} else if opt.SSHProxyProtocol {
			// Wrap the SSH listener with proxyproto.Listener to preserve the real client IP
			// when connections are coming through a TCP proxy (e.g., AWS ELB, HAProxy).
			// Headers remain optional so direct SSH connections still work.
			sshln = &proxyproto.Listener{
				Listener: sshln,
				ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
					return proxyproto.USE, nil
				},
			}
		}
	}

	if opt.WSAddr != "" {
		wsln, err = net.Listen("tcp", opt.WSAddr)
		if err != nil {
			return err
		}
		logger = logger.With("ws_addr", wsln.Addr().String())
	}

	if opt.InternalAddr != "" {
		internalln, err = net.Listen("tcp", opt.InternalAddr)
		if err != nil {
			return err
		}
		logger = logger.With("internal_addr", internalln.Addr().String())
	}

	// fallback node addr to the internal, ssh or ws addr if empty. Neighbours
	// hop to a node at its NodeAddr, and with an internal listener that is
	// where they hop. Validate has refused a wildcard here without node-addr.
	nodeAddr := opt.NodeAddr
	if nodeAddr == "" && internalln != nil {
		nodeAddr = internalln.Addr().String()
	}
	if nodeAddr == "" && sshln != nil {
		nodeAddr = sshln.Addr().String()
	}
	if nodeAddr == "" && wsln != nil {
		nodeAddr = wsln.Addr().String()
	}
	if nodeAddr == "" {
		return fmt.Errorf("node address can't by empty")
	}

	logger = logger.With("node_addr", nodeAddr)

	// Written by the server actor's interrupt below and read after g.Run
	// returns; see the comment there for why that needs no synchronisation.
	var serverShutdownErr error

	var g run.Group
	{
		var mp provider.Provider
		if opt.MetricAddr == "" {
			mp = provider.NewDiscardProvider()
		} else {
			mp = newPrometheusProvider("upterm", "uptermd", prometheus.DefaultRegisterer)
		}

		// Determine session routing mode
		sessionRouting := opt.ResolvedRouting()

		// Create session manager with the appropriate routing mode
		var sessionManager *SessionManager
		switch sessionRouting {
		case routing.ModeConsul:
			var consulTTL time.Duration
			if opt.ConsulSessionTTL != "" {
				if parsedTTL, err := time.ParseDuration(opt.ConsulSessionTTL); err == nil {
					consulTTL = parsedTTL
				} else {
					logger.Warn("invalid consul session TTL, using default", "error", err)
				}
			}

			// Parse Consul address as URL
			consulURL, err := url.Parse(opt.ConsulURL)
			if err != nil {
				return fmt.Errorf("invalid consul address URL: %w", err)
			}

			sm, err := NewSessionManager(routing.ModeConsul,
				WithSessionManagerLogger(logger.With("component", "session-manager")),
				WithSessionManagerConsulURL(consulURL),
				WithSessionManagerConsulTTL(consulTTL))
			if err != nil {
				return fmt.Errorf("failed to create consul session manager: %w", err)
			}
			sessionManager = sm

			logger.Info("using consul session store for routing")
		case routing.ModeEmbedded:
			sm, err := NewSessionManager(routing.ModeEmbedded,
				WithSessionManagerLogger(logger.With("component", "session-manager")))
			if err != nil {
				return fmt.Errorf("failed to create embedded session manager: %w", err)
			}
			sessionManager = sm
			logger.Info("using embedded session routing (in-memory session store)")
		default:
			return fmt.Errorf("invalid session routing mode: %s (supported: %s, %s)", sessionRouting, routing.ModeEmbedded, routing.ModeConsul)
		}

		s := &Server{
			HandshakeTimeout:    opt.HandshakeTimeout,
			NodeAddr:            nodeAddr,
			AuthorizedKeysFiles: opt.AuthorizedKeysFiles,
			HostSigners:         hostSigners,
			Signers:             signers,
			HopSigners:          hopSigners,
			HopTrusted:          hopTrusted,
			RefuseHostKeyHops:   opt.HopRefuseHostKey,
			NetworkProvider:     network,
			SessionManager:      sessionManager,
			Logger:              logger.With("component", "server"),
			MetricsProvider:     mp,
		}
		// run.Group's interrupt signature is func(error), so a failing Shutdown
		// has nowhere to report to and used to be logged and dropped: Start
		// returned g.Run's error, which on a requested stop is the nil that
		// ServeWithContext reports, and the process exited 0. A deploy that
		// failed to delete this node's sessions looked successful to the
		// supervisor -- the same class of blind spot as #573, one layer in.
		//
		// Capturing it here is race-free: run.Group calls every interrupt
		// serially on the goroutine already inside Run, before Run returns, so
		// this write happens before the read below.
		g.Add(func() error {
			return s.ServeListeners(ctx, Listeners{SSH: sshln, WS: wsln, Internal: internalln})
		}, func(err error) {
			if shutdownErr := s.Shutdown(); shutdownErr != nil {
				logger.Error("error during server shutdown", "error", shutdownErr)
				serverShutdownErr = shutdownErr
			}
		})
	}
	{
		if opt.MetricAddr != "" {
			logger = logger.With("metric_addr", opt.MetricAddr)

			m := &metricServer{}
			g.Add(func() error {
				return m.ListenAndServe(opt.MetricAddr)
			}, func(err error) {
				_ = m.Shutdown(ctx)
			})
		}
	}

	logger.Info("starting server")
	defer logger.Info("shutting down server")

	// A requested stop comes back nil from g.Run, so on that path this returns
	// whatever Shutdown reported and nothing else. Both are joined rather than
	// either winning: an actor that failed and a shutdown that then failed to
	// clean up are two separate things the operator needs to see.
	// ServeListeners takes ownership as soon as the server actor starts.
	listenersOwned = false
	return errors.Join(g.Run(), serverShutdownErr)
}

func parseNetworkOpt(opts []string) NetworkOptions {
	result := make(NetworkOptions)
	for _, opt := range opts {
		split := strings.SplitN(opt, "=", 2)
		result[split[0]] = split[1]
	}

	return result
}

type Server struct {
	HandshakeTimeout    time.Duration
	NodeAddr            string
	AuthorizedKeysFiles []string
	HostSigners         []ssh.Signer
	Signers             []ssh.Signer
	HopSigners          []ssh.Signer
	HopTrusted          []ssh.PublicKey
	RefuseHostKeyHops   bool
	NetworkProvider     NetworkProvider
	MetricsProvider     provider.Provider
	SessionManager      *SessionManager
	Logger              *slog.Logger

	mux    sync.Mutex
	ctx    context.Context
	cancel func()
	// served closes when ServeListeners returns, which is the moment every
	// component has run its own shutdown and released its listener. Shutdown
	// waits on it so that callers keep the guarantee they had when Shutdown
	// closed the listeners itself: once it returns, nothing is still bound.
	served chan struct{}

	// serveStopDeadline and sessionCleanupDeadline bound Shutdown's two waits.
	// Zero or negative takes defaultServeStopDeadline and
	// defaultSessionCleanupDeadline, so uptermd, which sets neither, gets
	// those. Shutdown reads each once, as it starts; tests set them to shorten
	// a wait.
	stopResult             *serverServeStopResult
	serveStopDeadline      time.Duration
	sessionCleanupDeadline time.Duration
}

// serverServeStopResult belongs to one Serve invocation. Shutdown retains the
// same result even if another invocation replaces the Server's current fields.
type serverServeStopResult struct {
	mu      sync.Mutex
	stopErr error
}

func (r *serverServeStopResult) add(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopErr = errors.Join(r.stopErr, err)
}

func (r *serverServeStopResult) err() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopErr
}

// errShutdownIncomplete reports that serving did not finish inside the
// shutdown deadline, so a listener may still be bound.
var errShutdownIncomplete = errors.New("serving did not stop within the shutdown deadline")

// defaultServeStopDeadline bounds how long Shutdown waits for serving to stop,
// unless the Server's serveStopDeadline is positive.
//
// run.Group runs its interrupts one after another, so the components' own
// budgets add up: routing joins its workers for up to routingShutdownDeadline,
// then the websocket server and sshd each drain for up to
// serverShutDownDeadline. That sum is the floor, not the target -- a saturated
// shutdown that spends all of it is still healthy, and scheduling, timer
// granularity and the race detector all push it over. Budgeting exactly the sum
// would answer such a shutdown with a false errShutdownIncomplete and an Error
// log, which is the noise this deadline exists alongside. Hence the extra
// serverShutDownDeadline of slack.
const defaultServeStopDeadline = routingShutdownDeadline + 3*serverShutDownDeadline

// errSessionCleanupTimeout reports that deleting this node's sessions did not
// finish in time, so the store may still route joiners to a node that is gone
// until the entries reach their TTL.
var errSessionCleanupTimeout = errors.New("session cleanup did not finish within its deadline")

// defaultSessionCleanupDeadline bounds Server's wait for cleanup after serving
// stops, unless the instance has a positive sessionCleanupDeadline. Consul's
// requests and retry waits carry this context and finish before store Close.
// Legacy contextless calls can outlive it; their worker checks cancellation
// before deleting a listing returned later. Close retains its separate bound,
// so a timeout here does not promise that finalization has already finished.
const defaultSessionCleanupDeadline = 3 * time.Second

// waitForServerSessionCleanup retains a published manager result without a
// grace wait, and reports this Server deadline independently of a store's own
// cancellation or Close deadline.
func waitForServerSessionCleanup(ctx context.Context, cleaned <-chan error) error {
	var err error
	select {
	case err = <-cleaned:
	case <-ctx.Done():
		select {
		case err = <-cleaned:
		default:
		}
	}
	if err != nil {
		err = fmt.Errorf("session cleanup: %w", err)
	}
	if ctx.Err() != nil {
		err = errors.Join(err, errSessionCleanupTimeout)
	}
	return err
}

// Shutdown cancels serving and waits for it to finish. It deliberately does not
// close the listeners: each is owned by the component serving it, which closes
// it from its own run.Group interrupt as the context unwinds. Closing them here
// as well made every listener close twice with no ordering between the two, and
// the loser of that race reported "use of closed network connection" from
// whichever side it landed on.
func (s *Server) Shutdown() error {
	// Resolved once, here: both waits below use these.
	serveStop, cleanupDeadline := s.serveStopDeadline, s.sessionCleanupDeadline
	if serveStop <= 0 {
		serveStop = defaultServeStopDeadline
	}
	if cleanupDeadline <= 0 {
		cleanupDeadline = defaultSessionCleanupDeadline
	}

	s.mux.Lock()
	cancel, served, stopResult := s.cancel, s.served, s.stopResult
	s.mux.Unlock()

	var err error

	if cancel != nil {
		cancel()
	}

	// A Server that never served has nothing to wait for. Waiting on a nil
	// channel would block until the deadline and report a false timeout.
	if served != nil {
		timer := time.NewTimer(serveStop)
		defer timer.Stop()
		select {
		case <-served:
		case <-timer.C:
			s.Logger.Error("timed out waiting for serving to stop", "deadline", serveStop)
			err = errors.Join(err, errShutdownIncomplete)
		}
	}

	if stopErr := stopResult.err(); stopErr != nil {
		err = errors.Join(err, errShutdownIncomplete, stopErr)
	}

	// Giving up cancels Consul cleanup work and revokes a legacy worker's
	// permission to delete a listing returned after this deadline.
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), cleanupDeadline)
	defer cancelCleanup()

	cleaned := make(chan error, 1)
	go func() { cleaned <- s.SessionManager.Shutdown(cleanupCtx, s.NodeAddr) }()

	sessionErr := waitForServerSessionCleanup(cleanupCtx, cleaned)
	if errors.Is(sessionErr, errSessionCleanupTimeout) {
		s.Logger.Error("timed out cleaning up sessions during shutdown", "deadline", cleanupDeadline, "error", sessionErr)
	} else if sessionErr != nil {
		s.Logger.Error("failed to cleanup sessions during shutdown", "error", sessionErr)
	} else {
		s.Logger.Debug("cleaned up sessions during shutdown")
	}
	err = errors.Join(err, sessionErr)

	if err == nil {
		s.Logger.Debug("server shutdown completed")
	}

	return err
}

// Listeners are the sockets a Server serves; any may be nil.
type Listeners struct {
	SSH      net.Listener // the public SSH listener
	WS       net.Listener // the WebSocket listener
	Internal net.Listener // node hops and bridged WebSocket guests; needs SSH
}

// errInternalNeedsSSH refuses an internal listener served without the SSH
// listener. An internal listener takes node hops and bridged WebSocket guests
// off the SSH listener, and without one there is nothing to take them off: a
// WebSocket listener alone reaches the sshd and other nodes directly, with no
// SSH proxy in between.
var errInternalNeedsSSH = errors.New("an internal listener needs the SSH listener")

// ServeWithContext serves sshln and wsln, either of which may be nil, with no
// internal listener.
func (s *Server) ServeWithContext(ctx context.Context, sshln net.Listener, wsln net.Listener) error {
	return s.ServeListeners(ctx, Listeners{SSH: sshln, WS: wsln})
}

// ServeListeners serves ls until ctx is done or Shutdown is called, alongside
// this node's own sshd, and owns every listener in ls from the moment it is
// called.
//
// Without an internal listener, everything arrives on the SSH listener: direct
// clients, other nodes' hops, and the guests that a WebSocket listener, this
// node's or a neighbour's, bridges to it. With one, the SSH listener is left
// direct clients alone. Other nodes hop to the internal listener and hand it
// their WebSocket guests, and this node's WebSocket listener bridges to a
// loopback listener opened here for it alone, so each listener knows what
// arrives on it.
func (s *Server) ServeListeners(ctx context.Context, ls Listeners) error {
	if ls.Internal != nil && ls.SSH == nil {
		// Handed over all the same, so released as a failed start releases them.
		closeListeners(s.Logger, ls.WS, ls.Internal)
		return errInternalNeedsSSH
	}

	s.mux.Lock()
	s.ctx, s.cancel = context.WithCancel(ctx)
	// Shutdown may already be waiting on a previous run's channel, so give it a
	// fresh one rather than reusing whatever is there.
	s.served = make(chan struct{})
	served := s.served
	stopResult := &serverServeStopResult{}
	s.stopResult = stopResult
	s.mux.Unlock()
	defer close(served)

	sshdDialListener := s.NetworkProvider.SSHD()
	sessionDialListener := s.NetworkProvider.Session()
	// The proxy's connections from hosts, which the sshd pings by. They are
	// one process's: the proxy routes a host to this node's own sshd.
	activity := newHostActivity()

	// run.Group actors do not start until Run, so until then nothing has taken
	// any listener over, and each, handed over or opened here, is still this
	// call's to release.
	var bridgeln net.Listener
	if ls.WS != nil && ls.Internal != nil {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			closeListeners(s.Logger, ls.SSH, ls.WS, ls.Internal)
			return err
		}
		bridgeln = ln
		// The one listener no caller handed in, and so the one whose address
		// nothing else reports.
		s.Logger.Info("listening for this node's WebSocket bridge", "bridge_addr", ln.Addr().String())
	}
	sshdln, err := sshdDialListener.Listen()
	if err != nil {
		closeListeners(s.Logger, ls.SSH, ls.WS, ls.Internal, bridgeln)
		return err
	}

	var g run.Group
	{
		g.Add(func() error {
			<-s.ctx.Done()
			return s.ctx.Err()
		}, func(err error) {
			s.cancel()
		})
	}
	{
		cd := sidewayConnDialer{
			NodeAddr:            s.NodeAddr,
			SSHDDialListener:    sshdDialListener,
			SessionDialListener: sessionDialListener,
			NeighbourDialer:     tcpConnDialer{},
			Logger:              s.Logger.With("component", "ssh-conn-dialer"),
		}
		// One set of routing metrics for all the SSH proxies, as there was for
		// the one SSH listener everything used to arrive on: the same totals,
		// and each metric registered once, which a Prometheus registry insists
		// on.
		var instruments *routingInstruments
		if ls.SSH != nil {
			instruments = newSSHRoutingInstruments(s.MetricsProvider)
		}
		// The SSH listener establishes an entry point only once an internal
		// listener takes everything else off it.
		sshKind := listenerShared
		if ls.Internal != nil {
			sshKind = listenerPublic
		}
		for _, l := range []struct {
			ln        net.Listener
			kind      listenerKind
			component string
		}{
			{ls.SSH, sshKind, "ssh-proxy"},
			{ls.Internal, listenerInternal, "internal-ssh-proxy"},
			{bridgeln, listenerBridge, "bridge-ssh-proxy"},
		} {
			if l.ln == nil {
				continue
			}
			sp := &sshProxy{
				HandshakeTimeout:    s.HandshakeTimeout,
				HostSigners:         s.HostSigners,
				Signers:             s.Signers,
				HopSigners:          s.HopSigners,
				HopTrusted:          s.HopTrusted,
				RefuseHostKeyHops:   s.RefuseHostKeyHops,
				NodeAddr:            s.NodeAddr,
				AuthorizedKeysFiles: s.AuthorizedKeysFiles,
				ConnDialer:          cd,
				SessionManager:      s.SessionManager,
				Logger:              s.Logger.With("component", l.component),
				MetricsProvider:     s.MetricsProvider,
				// The bridge carries WebSocket hosts, as the SSH listener
				// carries the rest, and the internal listener refuses them.
				hostActivity: activity,
				listener:     l.kind,
				instruments:  instruments,
			}
			g.Add(func() error {
				return sp.Serve(l.ln)
			}, func(err error) {
				if err := sp.Shutdown(); err != nil {
					sp.Logger.Error("error during ssh proxy shutdown", "error", err)
				}
			})
		}
	}
	{
		if ls.WS != nil {
			var cd connDialer
			if ls.SSH == nil {
				cd = sidewayConnDialer{
					NodeAddr:            s.NodeAddr,
					SSHDDialListener:    sshdDialListener,
					SessionDialListener: sessionDialListener,
					NeighbourDialer:     wsConnDialer{},
					Logger:              s.Logger.With("component", "ws-conn-dialer"),
				}
			} else {
				// With an SSH listener, always dial to SSHProxy.
				// So Host/Client -> WSProxy -> SSHProxy -> sshd/Session
				// This makes sure that SSHProxy terminates all SSH requests
				// which provides a consistent authentication mechanism.
				d := sshProxyDialer{
					sshProxyAddr: ls.SSH.Addr().String(),
					// Only Consul mode resolves a guest's node from the
					// session store, so only there does an identifier's
					// NodeAddr name a relay node. Embedded mode takes it from
					// the guest's own SSH user.
					nodeAddrFromStore: s.SessionManager.GetRoutingMode() == routing.ModeConsul,
					Logger:            s.Logger.With("component", "ws-sshproxy-dialer"),
				}
				if bridgeln != nil {
					// The bridge takes the SSH proxy's place. This node's
					// NodeAddr is then the internal listener, which the store
					// names for every session on this node, so the dialer is
					// told it: a guest the store places there is this node's
					// own, and goes to the bridge as well.
					d.sshProxyAddr, d.ownNodeAddr = bridgeln.Addr().String(), s.NodeAddr
				}
				cd = d
			}
			ws := &webSocketProxy{
				ConnDialer:     cd,
				SessionManager: s.SessionManager,
				Logger:         s.Logger.With("component", "ws-proxy"),
			}
			g.Add(func() error {
				return ws.Serve(ls.WS)
			}, func(err error) {
				if err := ws.Shutdown(); err != nil {
					ws.Logger.Error("error during websocket proxy shutdown", "error", err)
				}
			})
		}
	}
	{
		sshd := sshd{
			SessionManager:      s.SessionManager,
			HostSigners:         s.HostSigners, // TODO: use different host keys
			Signers:             s.Signers,
			NodeAddr:            s.NodeAddr,
			SessionDialListener: sessionDialListener,
			MetricsProvider:     s.MetricsProvider,
			Logger:              s.Logger.With("component", "sshd"),
			HostGateEnabled:     len(s.AuthorizedKeysFiles) > 0,
			hostActivity:        activity,
		}
		g.Add(func() error {
			return sshd.Serve(sshdln)
		}, func(err error) {
			if err := sshd.Shutdown(); err != nil {
				stopResult.add(err)
				sshd.Logger.Error("error during sshd shutdown", "error", err)
			}
		})
	}

	// A shutdown someone asked for is not a failure. Each component reports the
	// stop in its own vocabulary -- routing its ErrListnerClosed, http.Server
	// its ErrServerClosed, the context watcher a cancellation -- and run.Group
	// hands back whichever happened to return first, so without this the same
	// clean shutdown surfaced a different error run to run and every caller,
	// the ftests harness included, logged it.
	err = g.Run()
	if isRequestedStop(err) {
		err = nil
	}
	return errors.Join(err, stopResult.err())
}

// closeListeners releases listeners that no component has taken over, for the
// paths that give up before serving starts. Each listener otherwise has exactly
// one owner, so this is only ever reached when there is no owner at all.
func closeListeners(logger *slog.Logger, lns ...net.Listener) {
	for _, ln := range lns {
		if ln == nil {
			continue
		}
		if err := ln.Close(); err != nil {
			logger.Error("error releasing listener after a failed start", "error", err)
		}
	}
}

// isRequestedStop reports whether err is how a component says it stopped
// because it was told to, rather than because something went wrong.
func isRequestedStop(err error) bool {
	return err == nil ||
		errors.Is(err, ErrListnerClosed) ||
		errors.Is(err, http.ErrServerClosed) ||
		errors.Is(err, gliderssh.ErrServerClosed) ||
		errors.Is(err, context.Canceled)
}

// connDialer reaches the node or socket an identifier resolves to. DialContext
// is required, not optional: the SSH front door bounds upstream establishment
// with it, and a dialer that only offers Dial would pass every Dial-based path
// (the WebSocket proxy, sshd) and then fail every SSH connection after
// downstream authentication had already succeeded.
type connDialer interface {
	Dial(id *api.Identifier) (net.Conn, error)
	DialContext(ctx context.Context, id *api.Identifier) (net.Conn, error)
}

type sshProxyDialer struct {
	sshProxyAddr string
	// nodeAddrFromStore says that a guest identifier's NodeAddr was resolved
	// from the session store, so it names a relay node and may be dialed
	// directly. Where it is not set, a guest's upstream goes to this node's SSH
	// proxy, which resolves the guest's own SSH user itself.
	nodeAddrFromStore bool
	// ownNodeAddr is this node's NodeAddr when that is not where sshProxyAddr
	// listens: the internal listener, with sshProxyAddr the bridge. A guest the
	// store places there is this node's own, and goes to sshProxyAddr like any
	// other. Empty without an internal listener, where NodeAddr is the SSH
	// listener neighbours hop to, the same proxy sshProxyAddr reaches, and
	// dialing it stays as it always was.
	ownNodeAddr string
	Logger      *slog.Logger
}

func (d sshProxyDialer) Dial(id *api.Identifier) (net.Conn, error) {
	return d.DialContext(context.Background(), id)
}

func (d sshProxyDialer) DialContext(ctx context.Context, id *api.Identifier) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: tcpDialTimeout}

	// If it's a host request, dial to SSHProxy in the same node.
	// Otherwise, dial to the specified SSHProxy.
	if id.Type == api.Identifier_HOST {
		d.Logger.With("host", id.Id, "sshproxy_addr", d.sshProxyAddr).Info("dialing sshproxy sshd")
		return dialer.DialContext(ctx, "tcp", d.sshProxyAddr)
	}
	// A guest whose node this dialer cannot place goes to this node's SSHProxy,
	// which authorizes the guest's user itself. That is a guest with no node:
	// the WebSocket proxy sends one here when it can't resolve the user, so the
	// refusal can say why, and in Consul mode when the resolved node won't take
	// the dial, so the route can be refreshed. It is also every guest of a mode
	// that resolves no node at all, where the address rides in the guest's own
	// SSH user and the SSHProxy is the component that decodes it. And it is a
	// guest the store places on this node at its internal listener, which
	// would take the guest raw and claim no entry for it.
	if id.NodeAddr == "" || !d.nodeAddrFromStore || id.NodeAddr == d.ownNodeAddr {
		d.Logger.With("session", id.Id, "sshproxy_addr", d.sshProxyAddr, "node_addr_from_store", d.nodeAddrFromStore).Info("dialing this node's sshproxy for a guest")
		return dialer.DialContext(ctx, "tcp", d.sshProxyAddr)
	}

	d.Logger.With("session", id.Id, "sshproxy_addr", d.sshProxyAddr, "addr", id.NodeAddr).Info("dialing sshproxy session")
	return dialer.DialContext(ctx, "tcp", id.NodeAddr)
}

type tcpConnDialer struct {
}

func (d tcpConnDialer) Dial(id *api.Identifier) (net.Conn, error) {
	return d.DialContext(context.Background(), id)
}

func (d tcpConnDialer) DialContext(ctx context.Context, id *api.Identifier) (net.Conn, error) {
	return (&net.Dialer{Timeout: tcpDialTimeout}).DialContext(ctx, "tcp", id.NodeAddr)
}

type wsConnDialer struct {
}

func (d wsConnDialer) Dial(id *api.Identifier) (net.Conn, error) {
	return d.DialContext(context.Background(), id)
}

func (d wsConnDialer) DialContext(_ context.Context, id *api.Identifier) (net.Conn, error) {
	u, err := url.Parse("ws://" + id.NodeAddr)
	if err != nil {
		return nil, err
	}
	encodedNodeAddr := base64.StdEncoding.EncodeToString([]byte(id.NodeAddr))
	u.User = url.UserPassword(id.Id, encodedNodeAddr)

	return ws.NewWSConn(u, true, nil)
}

type sidewayConnDialer struct {
	NodeAddr            string
	SSHDDialListener    SSHDDialListener
	SessionDialListener SessionDialListener
	NeighbourDialer     connDialer
	Logger              *slog.Logger
}

func (cd sidewayConnDialer) Dial(id *api.Identifier) (net.Conn, error) {
	return cd.DialContext(context.Background(), id)
}

// DialContext makes the routing decision, so it owns the logging for it. The
// SSH front door only ever calls this path, and these three lines are the
// breadcrumb that tells a local dial from a cross-node hop.
func (cd sidewayConnDialer) DialContext(ctx context.Context, id *api.Identifier) (net.Conn, error) {
	logger := cd.logger().With("session", id.Id, "node", cd.NodeAddr, "type", api.Identifier_Type_name[int32(id.Type)])

	if id.Type == api.Identifier_HOST {
		logger.Info("dialing sshd")
		return cd.SSHDDialListener.DialContext(ctx)
	}

	host, port, err := net.SplitHostPort(id.NodeAddr)
	if err != nil {
		return nil, fmt.Errorf("host address %s is malformed: %w", id.NodeAddr, err)
	}
	addr := net.JoinHostPort(host, port)
	logger = logger.With("addr", addr)

	// if current node is matching, dial to session.
	// Otherwise, dial to neighbour node
	if cd.NodeAddr == addr {
		logger.Info("dialing session")
		return cd.SessionDialListener.DialContext(ctx, id.Id)
	}

	logger.Info("dialing neighbour")
	return cd.NeighbourDialer.DialContext(ctx, id)
}

// logger tolerates the zero value, which tests construct directly.
func (cd sidewayConnDialer) logger() *slog.Logger {
	if cd.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return cd.Logger
}
