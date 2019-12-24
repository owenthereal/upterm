package server

import (
	"context"
	"net"

	"github.com/gliderlabs/ssh"
	"github.com/jingweno/upterm/upterm"
	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

type SSHD struct {
	HostSigners         []gossh.Signer
	SessionDialListener SessionDialListener
	Logger              log.FieldLogger

	server *ssh.Server
}

func (s *SSHD) Shutdown() error {
	return s.server.Shutdown(context.Background())
}

func (s *SSHD) Serve(ln net.Listener) error {
	var signers []ssh.Signer
	for _, signer := range s.HostSigners {
		signers = append(signers, signer)
	}

	sh := newStreamlocalForwardHandler(s.SessionDialListener, s.Logger.WithField("handler", "streamlocalForwardHandler"))
	s.server = &ssh.Server{
		HostSigners: signers,
		Handler: func(s ssh.Session) {
			s.Exit(1) // disable ssh login
		},
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) (granted bool) {
			s.Logger.WithFields(log.Fields{"tunnel-host": host, "tunnel-port": port}).Info("attempt to bind")
			return true
		}),
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			// TODO: validate public keys from proxy
			return true
		},
		RequestHandlers: map[string]ssh.RequestHandler{
			streamlocalForwardChannelType:       sh.Handler,
			cancelStreamlocalForwardChannelType: sh.Handler,
			upterm.ServerPingRequestType:        pingRequestHandler,
		},
	}

	return s.server.Serve(ln)
}

func pingRequestHandler(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	return true, nil
}
