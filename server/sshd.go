package server

import (
	"context"
	"encoding/json"
	"net"
	"sync"

	"github.com/gliderlabs/ssh"
	"github.com/jingweno/upterm/upterm"
	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

type ServerInfo struct {
	NodeAddr string
}

type SSHD struct {
	HostSigners         []gossh.Signer
	NodeAddr            string
	SessionDialListener SessionDialListener
	Logger              log.FieldLogger

	server *ssh.Server
	mux    sync.Mutex
}

func (s *SSHD) Shutdown() error {
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.server != nil {
		return s.server.Shutdown(context.Background())
	}

	return nil
}

func (s *SSHD) Serve(ln net.Listener) error {
	var signers []ssh.Signer
	for _, signer := range s.HostSigners {
		signers = append(signers, signer)
	}

	sh := newStreamlocalForwardHandler(s.SessionDialListener, s.Logger.WithField("handler", "streamlocalForwardHandler"))
	s.mux.Lock()
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
			// This function is never executed and it's as an indicator
			// to crypto/ssh that public key auth is enabled.
			// This allows the Router to convert the public key auth to
			// password auth with public key as the password in authorized
			// key format.
			return false
		},
		PasswordHandler: func(ctx ssh.Context, password string) bool {
			// TODO: validate host authorized_keys
			return true
		},
		RequestHandlers: map[string]ssh.RequestHandler{
			streamlocalForwardChannelType:       sh.Handler,
			cancelStreamlocalForwardChannelType: sh.Handler,
			upterm.ServerServerInfoRequestType:  s.serverInfoRequestHandler,
			upterm.ServerPingRequestType:        pingRequestHandler,
		},
	}
	s.mux.Unlock()

	return s.server.Serve(ln)
}

func (s *SSHD) serverInfoRequestHandler(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	info := ServerInfo{
		NodeAddr: s.NodeAddr,
	}

	b, err := json.Marshal(info)
	if err != nil {
		return false, []byte(err.Error())
	}

	return true, b
}

func pingRequestHandler(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	return true, nil
}
