package server

import (
	"context"
	"net"

	"github.com/jingweno/upterm/utils"
	"github.com/oklog/run"
	log "github.com/sirupsen/logrus"
)

type Server struct {
	HostPrivateKeys [][]byte
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

	signers, err := utils.CreateSigners(s.HostPrivateKeys)
	if err != nil {
		return err
	}

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
		router := LocalRouter{
			HostSigners:         signers,
			SSHDDialListener:    sshdDialListener,
			SessionDialListener: sessionDialListener,
			UpstreamNode:        s.UpstreamNode,
			Logger:              s.Logger.WithField("app", "proxy"),
		}
		g.Add(func() error {
			return router.Serve(ln)
		}, func(err error) {
			router.Shutdown()
		})
	}
	{
		ln, err := sshdDialListener.Listen()
		if err != nil {
			return err
		}

		sshd := SSHD{
			HostSigners:         signers, // TODO: use different host keys
			NodeAddr:            s.NodeAddr,
			SessionDialListener: sessionDialListener,
			Logger:              s.Logger.WithField("app", "sshd"),
		}
		g.Add(func() error {
			return sshd.Serve(ln)
		}, func(err error) {
			sshd.Shutdown()
		})
	}

	return g.Run()
}
