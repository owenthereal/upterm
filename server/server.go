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

type ServerOpt struct {
	Addr         string
	KeyFiles     []string
	Network      string
	NetworkOpt   []string
	UpstreamNode bool
	MetricAddr   string
}

func StartServer(opt ServerOpt) error {
	network := Networks.Get(opt.Network)
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

	var g run.Group
	{
		mp := provider.NewPrometheusProvider("upterm", "uptermd")
		ln, err := net.Listen("tcp", opt.Addr)
		if err != nil {
			return err
		}
		s := &Server{
			HostSigners:     signers,
			NodeAddr:        opt.Addr,
			NetworkProvider: network,
			UpstreamNode:    opt.UpstreamNode,
			Logger:          log.New().WithField("app", "uptermd"),
			MetricsProvider: mp,
		}
		g.Add(func() error {
			return s.Serve(ln)
		}, func(err error) {
			_ = s.Shutdown()
			ln.Close()
		})
	}
	{
		m := &MetricsServer{}
		g.Add(func() error {
			return m.ListenAndServe(opt.MetricAddr)
		}, func(err error) {
			m.Shutdown(context.Background())
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
	HostSigners     []ssh.Signer
	NodeAddr        string
	NetworkProvider NetworkProvider
	UpstreamNode    bool
	Logger          log.FieldLogger
	MetricsProvider provider.Provider

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
	sshdDialListener := s.NetworkProvider.SSHD()
	sessionDialListener := s.NetworkProvider.Session()

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
		router := Proxy{
			HostSigners:         s.HostSigners,
			SSHDDialListener:    sshdDialListener,
			SessionDialListener: sessionDialListener,
			UpstreamNode:        s.UpstreamNode,
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
