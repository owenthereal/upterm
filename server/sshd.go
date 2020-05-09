package server

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/gliderlabs/ssh"
	proto "github.com/golang/protobuf/proto"
	"github.com/jingweno/upterm/upterm"
	"github.com/jingweno/upterm/utils"
	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

var (
	serverShutDownDeadline = 1 * time.Second
)

type ServerInfo struct {
	NodeAddr string
}

type sshd struct {
	SessionRepo         *sessionRepo
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
		s.SessionRepo,
		s.SessionDialListener,
		s.Logger.WithField("component", "stream-local-handler"),
	)
	s.mux.Lock()
	s.server = &ssh.Server{
		HostSigners: signers,
		Handler: func(s ssh.Session) {
			_ = s.Exit(1) // disable ssh login
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
			// This function is never executed when the protocol is ssh.
			// It acts as an indicator to crypto/ssh that public key auth
			// is enabled. This allows the ssh router to convert the public
			// key auth to password auth with public key as the password in
			// authorized key format.
			//
			// However, this function needs to return true to allow publickey
			// auth when the protocol is websocket.
			// TODO: validate publickey when it's websocket.
			return true
		},
		PasswordHandler: func(ctx ssh.Context, password string) bool {
			_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(password))
			// TODO: validate publickey
			return err == nil
		},
		ChannelHandlers: make(map[string]ssh.ChannelHandler), // disallow channl requests, e.g. shell
		RequestHandlers: map[string]ssh.RequestHandler{
			streamlocalForwardChannelType:         sh.Handler,
			cancelStreamlocalForwardChannelType:   sh.Handler,
			upterm.ServerCreateSessionRequestType: s.createSessionHandler,
			upterm.ServerServerInfoRequestType:    s.serverInfoRequestHandler, // TODO: deprecate
			upterm.ServerPingRequestType:          pingRequestHandler,         // TODO: deprecate
		},
	}
	s.mux.Unlock()

	return s.server.Serve(ln)
}

// TODO: Remove it. SessionService should take care of routing by session
func (s *sshd) serverInfoRequestHandler(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	info := ServerInfo{
		NodeAddr: s.NodeAddr,
	}

	b, err := json.Marshal(info)
	if err != nil {
		return false, []byte(err.Error())
	}

	return true, b
}

func (s *sshd) createSessionHandler(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	var sessReq CreateSessionRequest
	if err := proto.Unmarshal(req.Payload, &sessReq); err != nil {
		return false, []byte(err.Error())
	}

	sess, err := newSession(
		utils.GenerateSessionID(),
		sessReq.HostUser,
		sessReq.HostPublicKeys,
		sessReq.ClientAuthorizedKeys,
	)
	if err != nil {
		return false, []byte(err.Error())
	}

	if err := s.SessionRepo.Add(*sess); err != nil {
		return false, []byte(err.Error())
	}

	sessResp := &CreateSessionResponse{
		SessionID: sess.ID,
		NodeAddr:  s.NodeAddr,
	}

	b, err := proto.Marshal(sessResp)
	if err != nil {
		return false, []byte(err.Error())
	}

	return true, b
}

func pingRequestHandler(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	return true, nil
}
