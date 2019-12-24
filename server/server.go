package server

import (
	"context"
	"crypto/ed25519"
	"net"

	"github.com/oklog/run"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	HostPrivateKeys [][]byte
	NetworkProvider NetworkProvider
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

	signers, err := createSigners(s.HostPrivateKeys)
	if err != nil {
		return err
	}
	upstreamSigner := signers[0] // TODO: generate a new one

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
		proxy := Proxy{
			HostSigners:         signers,
			UpstreamSigner:      upstreamSigner,
			SSHDDialListener:    sshdDialListener,
			SessionDialListener: sessionDialListener,
			Logger:              s.Logger.WithField("app", "proxy"),
		}
		g.Add(func() error {
			return proxy.Serve(ln)
		}, func(err error) {
			proxy.Shutdown()
		})
	}
	{
		ln, err := sshdDialListener.Listen()
		if err != nil {
			return err
		}

		sshd := SSHD{
			HostSigners:         signers, // TODO: use different host keys
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

func createSigners(privateKeys [][]byte) ([]ssh.Signer, error) {
	var signers []ssh.Signer

	for _, pk := range privateKeys {
		signer, err := ssh.ParsePrivateKey(pk)
		if err != nil {
			return nil, err
		}

		signers = append(signers, signer)
	}

	// generate one if no signer
	if len(signers) == 0 {
		_, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}

		signer, err := ssh.NewSignerFromKey(private)
		if err != nil {
			return nil, err
		}

		signers = append(signers, signer)
	}

	return signers, nil
}
