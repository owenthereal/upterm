package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/jingweno/upterm/utils"
	"github.com/oklog/run"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

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

	sshdDialListener := network.SSHD()
	sessionDialListener := network.Session()
	logger := log.New().WithField("app", "uptermd")

	// default node addr to ssh addr or ws addr
	nodeAddr := opt.SSHAddr
	if nodeAddr == "" {
		nodeAddr = opt.WSAddr
	}

	var g run.Group
	{
		mp := provider.NewPrometheusProvider("upterm", "uptermd")
		ln, err := net.Listen("tcp", opt.SSHAddr)
		if err != nil {
			return err
		}
		// TODO: break apart proxy and sshd
		s := &Server{
			HostSigners:         signers,
			NodeAddr:            nodeAddr,
			SSHDDialListener:    sshdDialListener,
			SessionDialListener: sessionDialListener,
			Logger:              logger.WithField("component", "server"),
			MetricsProvider:     mp,
		}
		g.Add(func() error {
			return s.Serve(ln)
		}, func(err error) {
			s.Shutdown()
			ln.Close()
		})
	}
	{
		if opt.WSAddr != "" {
			ln, err := net.Listen("tcp", opt.WSAddr)
			if err != nil {
				return err
			}

			ws := &WebsocketServer{
				SSHDDialListener:    sshdDialListener,
				SessionDialListener: sessionDialListener,
				Logger:              logger.WithField("component", "ws-server"),
			}
			g.Add(func() error {
				return ws.Serve(ln)
			}, func(err error) {
				_ = ws.Shutdown()
			})
		}
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
	HostSigners         []ssh.Signer
	NodeAddr            string
	SSHDDialListener    SSHDDialListener
	SessionDialListener SessionDialListener
	Logger              log.FieldLogger
	MetricsProvider     provider.Provider

	mux    sync.Mutex
	ctx    context.Context
	cancel func()
}

func (s *Server) Shutdown() {
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Server) Serve(ln net.Listener) error {
	s.mux.Lock()
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.mux.Unlock()

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
		router := SSHProxy{
			HostSigners:         s.HostSigners,
			SSHDDialListener:    s.SSHDDialListener,
			SessionDialListener: s.SessionDialListener,
			NodeAddr:            s.NodeAddr,
			Logger:              s.Logger.WithField("componet", "proxy"),
			MetricsProvider:     s.MetricsProvider,
		}
		g.Add(func() error {
			return router.Serve(ln)
		}, func(err error) {
			_ = router.Shutdown()
		})
	}
	{
		ln, err := s.SSHDDialListener.Listen()
		if err != nil {
			return err
		}

		sshd := SSHD{
			HostSigners:         s.HostSigners, // TODO: use different host keys
			NodeAddr:            s.NodeAddr,
			SessionDialListener: s.SessionDialListener,
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
