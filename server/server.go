package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/oklog/run"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/utils"
	"github.com/owenthereal/upterm/ws"
	"github.com/pires/go-proxyproto"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	tcpDialTimeout = 1 * time.Second
)

type Opt struct {
	SSHAddr          string       `mapstructure:"ssh-addr"`
	SSHProxyProtocol bool         `mapstructure:"ssh-proxy-protocol"`
	WSAddr           string       `mapstructure:"ws-addr"`
	NodeAddr         string       `mapstructure:"node-addr"`
	PrivateKeys      []string     `mapstructure:"private-key"`
	Hostnames        []string     `mapstructure:"hostname"`
	Network          string       `mapstructure:"network"`
	NetworkOpts      []string     `mapstructure:"network-opt"`
	MetricAddr       string       `mapstructure:"metric-addr"`
	Debug            bool         `mapstructure:"debug"`
	Routing          routing.Mode `mapstructure:"routing"`
	ConsulURL        string       `mapstructure:"consul-url"`
	ConsulSessionTTL string       `mapstructure:"consul-session-ttl"`
}

// Validate validates the server configuration
func (opt *Opt) Validate() error {
	// Basic validation
	if opt.SSHAddr == "" {
		return fmt.Errorf("ssh-addr is required")
	}

	// Routing-specific validation
	routingMode := opt.Routing
	if routingMode == "" {
		routingMode = routing.ModeEmbedded
	}

	switch routingMode {
	case routing.ModeConsul:
		return opt.validateConsulConfig()
	case routing.ModeEmbedded:
		return opt.validateEmbeddedConfig()
	default:
		return fmt.Errorf("unsupported routing mode: %s", routingMode)
	}
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

func Start(opt Opt) error {
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
		return nil
	}

	if pp := os.Getenv("PRIVATE_KEY"); pp != "" {
		privateKeys = append(privateKeys, []byte(pp))
	}

	signers, err := utils.CreateSigners(privateKeys)
	if err != nil {
		return err
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

	l := log.New()
	if opt.Debug {
		l.SetLevel(log.DebugLevel)
	}

	logger := l.WithFields(log.Fields{"app": "uptermd", "network": opt.Network, "network-opt": opt.NetworkOpts})

	var (
		sshln net.Listener
		wsln  net.Listener
	)

	if opt.SSHAddr != "" {
		sshln, err = net.Listen("tcp", opt.SSHAddr)
		if err != nil {
			return err
		}
		logger = logger.WithField("ssh-addr", sshln.Addr())
		if opt.SSHProxyProtocol {
			// Wrap the SSH listener with proxyproto.Listener to preserve the real client IP
			// when connections are coming through a TCP proxy (e.g., AWS ELB, HAProxy).
			sshln = &proxyproto.Listener{Listener: sshln}
		}
	}

	if opt.WSAddr != "" {
		wsln, err = net.Listen("tcp", opt.WSAddr)
		if err != nil {
			return err
		}
		logger = logger.WithField("ws-addr", wsln.Addr())
	}

	// fallback node addr to ssh addr or ws addr if empty
	nodeAddr := opt.NodeAddr
	if nodeAddr == "" && sshln != nil {
		nodeAddr = sshln.Addr().String()
	}
	if nodeAddr == "" && wsln != nil {
		nodeAddr = wsln.Addr().String()
	}
	if nodeAddr == "" {
		return fmt.Errorf("node address can't by empty")
	}

	logger = logger.WithField("node-addr", nodeAddr)

	var g run.Group
	{
		var mp provider.Provider
		if opt.MetricAddr == "" {
			mp = provider.NewDiscardProvider()
		} else {
			mp = provider.NewPrometheusProvider("upterm", "uptermd")
		}

		// Determine session routing mode
		sessionRouting := opt.Routing
		if sessionRouting == "" {
			sessionRouting = routing.ModeEmbedded // Default to embedded mode
		}

		// Create session manager with the appropriate routing mode
		var sessionManager *SessionManager
		switch sessionRouting {
		case routing.ModeConsul:
			var consulTTL time.Duration
			if opt.ConsulSessionTTL != "" {
				if parsedTTL, err := time.ParseDuration(opt.ConsulSessionTTL); err == nil {
					consulTTL = parsedTTL
				} else {
					logger.WithError(err).Warn("invalid consul session TTL, using default")
				}
			}

			// Parse Consul address as URL
			consulURL, err := url.Parse(opt.ConsulURL)
			if err != nil {
				return fmt.Errorf("invalid consul address URL: %w", err)
			}

			sm, err := NewSessionManager(routing.ModeConsul,
				WithSessionManagerLogger(logger.WithField("com", "session-manager")),
				WithSessionManagerConsulURL(consulURL),
				WithSessionManagerConsulTTL(consulTTL))
			if err != nil {
				return fmt.Errorf("failed to create consul session manager: %w", err)
			}
			sessionManager = sm

			logger.Info("using consul session store for routing")
		case routing.ModeEmbedded:
			sm, err := NewSessionManager(routing.ModeEmbedded,
				WithSessionManagerLogger(logger.WithField("com", "session-manager")))
			if err != nil {
				return fmt.Errorf("failed to create embedded session manager: %w", err)
			}
			sessionManager = sm
			logger.Info("using embedded session routing (in-memory session store)")
		default:
			return fmt.Errorf("invalid session routing mode: %s (supported: %s, %s)", sessionRouting, routing.ModeEmbedded, routing.ModeConsul)
		}

		s := &Server{
			NodeAddr:        nodeAddr,
			HostSigners:     hostSigners,
			Signers:         signers,
			NetworkProvider: network,
			SessionManager:  sessionManager,
			Logger:          logger.WithField("com", "server"),
			MetricsProvider: mp,
		}
		g.Add(func() error {
			return s.ServeWithContext(context.Background(), sshln, wsln)
		}, func(err error) {
			if err := s.Shutdown(); err != nil {
				s.Logger.WithError(err).Error("error during server shutdown")
			}
		})
	}
	{
		if opt.MetricAddr != "" {
			logger = logger.WithField("metric-addr", opt.MetricAddr)

			m := &metricServer{}
			g.Add(func() error {
				return m.ListenAndServe(opt.MetricAddr)
			}, func(err error) {
				_ = m.Shutdown(context.Background())
			})
		}
	}

	logger.Info("starting server")
	defer logger.Info("shutting down server")

	return g.Run()
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
	NodeAddr        string
	HostSigners     []ssh.Signer
	Signers         []ssh.Signer
	NetworkProvider NetworkProvider
	MetricsProvider provider.Provider
	SessionManager  *SessionManager
	Logger          log.FieldLogger

	sshln net.Listener
	wsln  net.Listener

	mux    sync.Mutex
	ctx    context.Context
	cancel func()
}

func (s *Server) Shutdown() error {
	s.mux.Lock()
	defer s.mux.Unlock()

	var err error

	// Stop accepting new connections first
	if s.sshln != nil {
		if sshErr := s.sshln.Close(); sshErr != nil {
			err = errors.Join(err, fmt.Errorf("ssh listener close: %w", sshErr))
		}
	}

	if s.wsln != nil {
		if wsErr := s.wsln.Close(); wsErr != nil {
			err = errors.Join(err, fmt.Errorf("websocket listener close: %w", wsErr))
		}
	}

	// Cancel context to signal graceful shutdown
	if s.cancel != nil {
		s.cancel()
	}

	// Clean up sessions created by this node
	if sessionErr := s.SessionManager.Shutdown(s.NodeAddr); sessionErr != nil {
		s.Logger.WithError(sessionErr).Error("failed to cleanup sessions during shutdown")
		err = errors.Join(err, fmt.Errorf("session cleanup: %w", sessionErr))
	} else {
		s.Logger.Debug("cleaned up sessions during shutdown")
	}

	if err == nil {
		s.Logger.Debug("server shutdown completed")
	}

	return err
}

func (s *Server) ServeWithContext(ctx context.Context, sshln net.Listener, wsln net.Listener) error {
	s.mux.Lock()
	s.sshln, s.wsln = sshln, wsln
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mux.Unlock()

	sshdDialListener := s.NetworkProvider.SSHD()
	sessionDialListener := s.NetworkProvider.Session()

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
		if sshln != nil {
			cd := sidewayConnDialer{
				NodeAddr:            s.NodeAddr,
				SSHDDialListener:    sshdDialListener,
				SessionDialListener: sessionDialListener,
				NeighbourDialer:     tcpConnDialer{},
				Logger:              s.Logger.WithField("com", "ssh-conn-dialer"),
			}
			sp := &sshProxy{
				HostSigners:     s.HostSigners,
				Signers:         s.Signers,
				NodeAddr:        s.NodeAddr,
				ConnDialer:      cd,
				SessionManager:  s.SessionManager,
				Logger:          s.Logger.WithField("com", "ssh-proxy"),
				MetricsProvider: s.MetricsProvider,
			}
			g.Add(func() error {
				return sp.Serve(sshln)
			}, func(err error) {
				if err := sp.Shutdown(); err != nil {
					s.Logger.WithError(err).Error("error during ssh proxy shutdown")
				}
			})
		}
	}
	{
		if wsln != nil {
			var cd connDialer
			if sshln == nil {
				cd = sidewayConnDialer{
					NodeAddr:            s.NodeAddr,
					SSHDDialListener:    sshdDialListener,
					SessionDialListener: sessionDialListener,
					NeighbourDialer:     wsConnDialer{},
					Logger:              s.Logger.WithField("com", "ws-conn-dialer"),
				}
			} else {
				// If sshln is not nil, always dial to SSHProxy.
				// So Host/Client -> WSProxy -> SSHProxy -> sshd/Session
				// This makes sure that SSHProxy terminates all SSH requests
				// which provides a consistent authentication mechanism.
				cd = sshProxyDialer{
					sshProxyAddr: sshln.Addr().String(),
					Logger:       s.Logger.WithField("com", "ws-sshproxy-dialer"),
				}
			}
			ws := &webSocketProxy{
				ConnDialer:     cd,
				SessionManager: s.SessionManager,
				Logger:         s.Logger.WithField("com", "ws-proxy"),
			}
			g.Add(func() error {
				return ws.Serve(wsln)
			}, func(err error) {
				if err := ws.Shutdown(); err != nil {
					s.Logger.WithError(err).Error("error during websocket proxy shutdown")
				}
			})
		}
	}
	{
		ln, err := sshdDialListener.Listen()
		if err != nil {
			return err
		}

		sshd := sshd{
			SessionManager:      s.SessionManager,
			HostSigners:         s.HostSigners, // TODO: use different host keys
			NodeAddr:            s.NodeAddr,
			SessionDialListener: sessionDialListener,
			Logger:              s.Logger.WithField("com", "sshd"),
		}
		g.Add(func() error {
			return sshd.Serve(ln)
		}, func(err error) {
			if err := sshd.Shutdown(); err != nil {
				s.Logger.WithError(err).Error("error during sshd shutdown")
			}
		})
	}

	return g.Run()
}

type connDialer interface {
	Dial(id *api.Identifier) (net.Conn, error)
}

type sshProxyDialer struct {
	sshProxyAddr string
	Logger       log.FieldLogger
}

func (d sshProxyDialer) Dial(id *api.Identifier) (net.Conn, error) {
	// If it's a host request, dial to SSHProxy in the same node.
	// Otherwise, dial to the specified SSHProxy.
	if id.Type == api.Identifier_HOST {
		d.Logger.WithFields(log.Fields{"host": id.Id, "sshproxy-addr": d.sshProxyAddr}).Info("dialing sshproxy sshd")
		return net.DialTimeout("tcp", d.sshProxyAddr, tcpDialTimeout)
	}

	d.Logger.WithFields(log.Fields{"session": id.Id, "sshproxy-addr": d.sshProxyAddr, "addr": id.NodeAddr}).Info("dialing sshproxy session")
	return net.DialTimeout("tcp", id.NodeAddr, tcpDialTimeout)
}

type tcpConnDialer struct {
}

func (d tcpConnDialer) Dial(id *api.Identifier) (net.Conn, error) {
	return net.DialTimeout("tcp", id.NodeAddr, tcpDialTimeout)
}

type wsConnDialer struct {
}

func (d wsConnDialer) Dial(id *api.Identifier) (net.Conn, error) {
	u, err := url.Parse("ws://" + id.NodeAddr)
	if err != nil {
		return nil, err
	}
	encodedNodeAddr := base64.StdEncoding.EncodeToString([]byte(id.NodeAddr))
	u.User = url.UserPassword(id.Id, encodedNodeAddr)

	return ws.NewWSConn(u, true)
}

type sidewayConnDialer struct {
	NodeAddr            string
	SSHDDialListener    SSHDDialListener
	SessionDialListener SessionDialListener
	NeighbourDialer     connDialer
	Logger              log.FieldLogger
}

func (cd sidewayConnDialer) Dial(id *api.Identifier) (net.Conn, error) {
	logger := cd.Logger.WithFields(log.Fields{"session": id.Id, "node": cd.NodeAddr, "type": api.Identifier_Type_name[int32(id.Type)]})

	if id.Type == api.Identifier_HOST {
		logger.Info("dialing sshd")
		return cd.SSHDDialListener.Dial()
	} else {
		host, port, ee := net.SplitHostPort(id.NodeAddr)
		if ee != nil {
			return nil, fmt.Errorf("host address %s is malformed: %w", id.NodeAddr, ee)
		}
		addr := net.JoinHostPort(host, port)
		logger = logger.WithField("addr", addr)

		// if current node is matching, dial to session.
		// Otherwise, dial to neighbour node
		if cd.NodeAddr == addr {
			logger.Info("dialing session")
			return cd.SessionDialListener.Dial(id.Id)
		}

		logger.Info("dialing neighbour")
		return cd.NeighbourDialer.Dial(id)
	}
}
