package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/utils"
	"github.com/oklog/run"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	tcpDialTimeout = 1 * time.Second
)

type DialNodeAddrFunc func(addr string) (net.Conn, error)

type Opt struct {
	SSHAddr    string
	WSAddr     string
	KeyFiles   []string
	Network    string
	NetworkOpt []string
	MetricAddr string
}

func Start(opt Opt) error {
	network := networks.Get(opt.Network)
	if network == nil {
		return fmt.Errorf("unsupport network provider %q", opt.Network)
	}

	opts := parseNetworkOpt(opt.NetworkOpt)
	if err := network.SetOpts(opts); err != nil {
		return fmt.Errorf("network provider option error: %s", err)
	}

	signers, err := utils.CreateSignersFromFiles(opt.KeyFiles)
	if err != nil {
		return err
	}

	mp := provider.NewPrometheusProvider("upterm", "uptermd")
	logger := log.New().WithField("app", "uptermd")

	// default node addr to ssh addr or ws addr
	nodeAddr := opt.SSHAddr
	if nodeAddr == "" {
		nodeAddr = opt.WSAddr
	}

	var (
		sshln net.Listener
		wsln  net.Listener
	)

	if opt.SSHAddr != "" {
		sshln, err = net.Listen("tcp", opt.SSHAddr)
		if err != nil {
			return err
		}
	}

	if opt.WSAddr != "" {
		wsln, err = net.Listen("tcp", opt.SSHAddr)
		if err != nil {
			return err
		}
	}

	var g run.Group
	{
		var dialNodeAddrFunc DialNodeAddrFunc
		if sshln != nil {
			dialNodeAddrFunc = func(addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", addr, tcpDialTimeout)
			}
		} else {
			dialNodeAddrFunc = func(addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", addr, tcpDialTimeout)
			}
		}

		s := &Server{
			NodeAddr:         nodeAddr,
			HostSigners:      signers,
			NetworkProvider:  network,
			DialNodeAddrFunc: dialNodeAddrFunc,
			Logger:           logger.WithField("component", "server"),
			MetricsProvider:  mp,
		}
		g.Add(func() error {
			return s.ServeWithContext(context.Background(), sshln, wsln)
		}, func(err error) {
			s.Shutdown()
		})
	}
	{
		m := &MetricsServer{}
		g.Add(func() error {
			return m.ListenAndServe(opt.MetricAddr)
		}, func(err error) {
			_ = m.Shutdown(context.Background())
		})
	}

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
	NodeAddr         string
	HostSigners      []ssh.Signer
	NetworkProvider  NetworkProvider
	MetricsProvider  provider.Provider
	DialNodeAddrFunc DialNodeAddrFunc
	Logger           log.FieldLogger

	sshln net.Listener
	wsln  net.Listener

	mux    sync.Mutex
	ctx    context.Context
	cancel func()
}

func (s *Server) Shutdown() {
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.sshln != nil {
		s.sshln.Close()
	}

	if s.wsln != nil {
		s.wsln.Close()
	}

	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Server) ServeWithContext(ctx context.Context, sshln net.Listener, wsln net.Listener) error {
	s.mux.Lock()
	s.sshln, s.wsln = sshln, wsln
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mux.Unlock()

	sshdDialListener := s.NetworkProvider.SSHD()
	sessionDialListener := s.NetworkProvider.Session()

	cd := connDialer{
		NodeAddr:            s.NodeAddr,
		SSHDDialListener:    sshdDialListener,
		SessionDialListener: sessionDialListener,
		DialNodeAddrFunc:    s.DialNodeAddrFunc,
		Logger:              s.Logger.WithField("compoent", "conn-dialer"),
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
		if sshln != nil {
			sshProxy := &SSHProxy{
				HostSigners:     s.HostSigners,
				ConnDialer:      cd,
				Logger:          s.Logger.WithField("componet", "ssh-proxy"),
				MetricsProvider: s.MetricsProvider,
			}
			g.Add(func() error {
				return sshProxy.Serve(sshln)
			}, func(err error) {
				_ = sshProxy.Shutdown()
			})

		}
	}
	{
		if wsln != nil {
			ws := &WebSocketProxy{
				ConnDialer: cd,
			}
			g.Add(func() error {
				return ws.Serve(wsln)
			}, func(err error) {
				_ = ws.Shutdown()
			})
		}
	}
	{
		ln, err := sshdDialListener.Listen()
		if err != nil {
			return err
		}

		sshd := SSHD{
			HostSigners:         s.HostSigners, // TODO: use different host keys
			NodeAddr:            s.NodeAddr,
			SessionDialListener: sessionDialListener,
			Logger:              s.Logger.WithField("componet", "sshd"),
		}
		g.Add(func() error {
			return sshd.Serve(ln)
		}, func(err error) {
			_ = sshd.Shutdown()
		})
	}

	return g.Run()
}

type connDialer struct {
	NodeAddr            string
	SSHDDialListener    SSHDDialListener
	SessionDialListener SessionDialListener
	DialNodeAddrFunc    DialNodeAddrFunc
	Logger              log.FieldLogger
}

func (cd connDialer) Dial(id *api.Identifier) (net.Conn, error) {
	if id.Type == api.Identifier_HOST {
		cd.Logger.WithField("user", id.Id).Info("dialing sshd")
		return cd.SSHDDialListener.Dial()
	} else {
		host, port, ee := net.SplitHostPort(id.NodeAddr)
		if ee != nil {
			return nil, fmt.Errorf("host address %s is malformed: %w", id.NodeAddr, ee)
		}
		addr := net.JoinHostPort(host, port)

		if cd.NodeAddr == addr {
			cd.Logger.WithFields(log.Fields{"session": id.Id, "addr": addr}).Info("dialing session")
			return cd.SessionDialListener.Dial(id.Id)
		}

		// route to neighbour nodes
		cd.Logger.WithFields(log.Fields{"session": id.Id, "addr": addr}).Info("routing session")
		return cd.DialNodeAddrFunc(addr)
	}
}
