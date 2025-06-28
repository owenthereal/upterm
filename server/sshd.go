package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/charmbracelet/ssh"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

var (
	serverShutDownDeadline = 1 * time.Second
)

type ServerInfo struct {
	NodeAddr string
}

type sshd struct {
	SessionManager      *SessionManager
	HostSigners         []gossh.Signer
	NodeAddr            string
	SessionDialListener SessionDialListener
	Logger              log.FieldLogger

	server *ssh.Server
	mux    sync.Mutex
}

func (s *sshd) Shutdown() error {
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.server != nil {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(serverShutDownDeadline))
		defer cancel()

		return s.server.Shutdown(ctx)
	}

	return nil
}

func (s *sshd) Serve(ln net.Listener) error {
	var signers []ssh.Signer
	for _, signer := range s.HostSigners {
		signers = append(signers, signer)
	}

	sh := newStreamlocalForwardHandler(
		s.SessionManager.GetStore(),
		s.SessionDialListener,
		s.Logger.WithField("com", "stream-local-handler"),
	)
	s.mux.Lock()
	s.server = &ssh.Server{
		HostSigners: signers,
		Handler: func(s ssh.Session) {
			_ = s.Exit(1) // disable ssh login
		},
		ConnectionFailedCallback: func(conn net.Conn, err error) {
			s.Logger.WithError(err).Error("connection failed")
		},
		ServerConfigCallback: func(ctx ssh.Context) *gossh.ServerConfig {
			config := &gossh.ServerConfig{
				ServerVersion: upterm.ServerSSHServerVersion,
			}
			return config
		},
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) (granted bool) {
			s.Logger.WithFields(log.Fields{"tunnel-host": host, "tunnel-port": port}).Info("attempt to bind")
			return true
		}),
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			checker := UserCertChecker{}
			_, _, err := checker.Authenticate(ctx.User(), key)
			if err != nil {
				s.Logger.WithError(err).Error("error parsing auth request from cert")
				return false
			}

			// TOOD: validate pk

			return true
		},
		ChannelHandlers: make(map[string]ssh.ChannelHandler), // disallow channel requests, e.g. shell
		RequestHandlers: map[string]ssh.RequestHandler{
			streamlocalForwardChannelType:         sh.Handler,
			cancelStreamlocalForwardChannelType:   sh.Handler,
			upterm.ServerCreateSessionRequestType: s.createSessionHandler,
		},
	}
	s.mux.Unlock()

	return s.server.Serve(ln)
}

func (s *sshd) createSessionHandler(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	var sessReq CreateSessionRequest
	if err := proto.Unmarshal(req.Payload, &sessReq); err != nil {
		return false, []byte(err.Error())
	}

	sessionID := utils.GenerateSessionID()

	// Store complete session data for routing and session management
	session := NewSession(
		sessionID,
		s.NodeAddr,
		sessReq.HostUser,
		sessReq.HostPublicKeys,
		sessReq.ClientAuthorizedKeys,
	)

	sshUser, err := s.SessionManager.CreateSession(session)
	if err != nil {
		s.Logger.WithError(err).WithFields(log.Fields{
			"session": sessionID,
			"node":    s.NodeAddr,
		}).Error("failed to create session")
		return false, []byte(fmt.Sprintf("failed to create session: %v", err))
	}

	sessResp := &CreateSessionResponse{
		SessionID: sessionID,
		NodeAddr:  s.NodeAddr,
		SshUser:   sshUser,
	}

	b, err := proto.Marshal(sessResp)
	if err != nil {
		return false, []byte(err.Error())
	}

	return true, b
}
