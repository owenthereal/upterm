package server

import (
	"context"
	"net"

	"github.com/oklog/run"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	HostSigners     []ssh.Signer
	NodeAddr        string
	NetworkProvider NetworkProvider
	UpstreamNode    bool
	Logger          log.FieldLogger

	ctx    context.Context
	cancel func()
}

func (s *Server) Shutdown() {
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Server) Serve(ln net.Listener) error {
	sshdDialListener := s.NetworkProvider.SSHD()
	sessionDialListener := s.NetworkProvider.Session()

	s.ctx, s.cancel = context.WithCancel(context.Background())

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
