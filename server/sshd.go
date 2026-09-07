package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/charmbracelet/ssh"
	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/internal/version"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"log/slog"
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
	MetricsProvider     provider.Provider
	Logger              *slog.Logger

	server   *ssh.Server
	sessions *localSessions
	mux      sync.Mutex
}

// localSessions tracks sessions created by this process. It drives
// sessions_active_count and guarantees each session is deleted from the store
// exactly once, whether the host cancels its forward or its connection ends
// first. Sessions visible in a shared store but created on another node are
// never touched. It is not persisted; a crash loses the count along with the
// sessions.
type localSessions struct {
	gauge          metrics.Gauge
	sessionManager *SessionManager
	logger         *slog.Logger

	mu  sync.Mutex
	ids map[string]struct{}
}

func newLocalSessions(p provider.Provider, sessionManager *SessionManager, logger *slog.Logger) *localSessions {
	gauge := p.NewGauge("sessions_active_count")
	gauge.Set(0) // export the series from startup rather than from the first session
	return &localSessions{
		gauge:          gauge,
		sessionManager: sessionManager,
		logger:         logger,
		ids:            make(map[string]struct{}),
	}
}

func (l *localSessions) add(sessionID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ids[sessionID] = struct{}{}
	l.gauge.Add(1)
}

// active reports whether sessionID was created by this process and has not
// been ended.
func (l *localSessions) active(sessionID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.ids[sessionID]
	return ok
}

// end deletes sessionID from the store and releases its count. It is a no-op
// for sessions this process did not create or has already ended. The count is
// released even if the store delete fails: the host is gone either way.
func (l *localSessions) end(sessionID string) {
	l.mu.Lock()
	_, ok := l.ids[sessionID]
	if ok {
		delete(l.ids, sessionID)
		l.gauge.Add(-1)
	}
	// Release before touching the store: a Consul delete can be slow, and
	// holding the lock across it would stall unrelated session creation.
	l.mu.Unlock()
	if !ok {
		return
	}

	if err := l.sessionManager.DeleteSession(sessionID); err != nil {
		l.logger.Error("error deleting session", "error", err, "session-id", sessionID)
	}
}

// contextKeyOwnedSessions holds, per SSH connection, the set of session IDs
// created on that connection. Forward and cancel requests are only honoured
// for sessions the requesting connection owns.
type contextKeyOwnedSessions struct{}

func ownSession(ctx ssh.Context, sessionID string) {
	ctx.Lock()
	defer ctx.Unlock()
	owned, _ := ctx.Value(contextKeyOwnedSessions{}).(map[string]struct{})
	if owned == nil {
		owned = make(map[string]struct{})
		ctx.SetValue(contextKeyOwnedSessions{}, owned)
	}
	owned[sessionID] = struct{}{}
}

func ownsSession(ctx ssh.Context, sessionID string) bool {
	ctx.Lock()
	defer ctx.Unlock()
	owned, _ := ctx.Value(contextKeyOwnedSessions{}).(map[string]struct{})
	_, ok := owned[sessionID]
	return ok
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

	sessions := newLocalSessions(s.MetricsProvider, s.SessionManager, s.Logger)
	sh := newStreamlocalForwardHandler(
		s.SessionManager,
		s.SessionDialListener,
		sessions,
		s.Logger.With("com", "stream-local-handler"),
	)
	s.mux.Lock()
	s.sessions = sessions
	s.server = &ssh.Server{
		HostSigners: signers,
		Handler: func(s ssh.Session) {
			_ = s.Exit(1) // disable ssh login
		},
		ConnectionFailedCallback: func(conn net.Conn, err error) {
			s.Logger.Error("connection failed", "error", err)
		},
		ServerConfigCallback: func(ctx ssh.Context) *gossh.ServerConfig {
			config := &gossh.ServerConfig{
				ServerVersion: version.ServerSSHVersion(),
			}
			return config
		},
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) (granted bool) {
			s.Logger.Info("attempt to bind", "tunnel-host", host, "tunnel-port", port)
			return true
		}),
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			checker := UserCertChecker{}
			_, _, err := checker.Authenticate(ctx.User(), key)
			if err != nil {
				s.Logger.Error("error parsing auth request from cert", "error", err)
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
		s.Logger.Error("failed to create session",
			"error", err,
			"session", sessionID,
			"node", s.NodeAddr,
		)
		return false, []byte(fmt.Sprintf("failed to create session: %v", err))
	}
	s.sessions.add(sessionID)
	ownSession(ctx, sessionID)
	// The tunnel handler ends the session when the host cancels its forward.
	// A host that disconnects before forwarding never reaches that path, so
	// also end it when the owning connection does.
	go func() {
		<-ctx.Done()
		s.sessions.end(sessionID)
	}()

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
