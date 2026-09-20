package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"charm.land/ssh"
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
	// stopped records a Shutdown that arrived before Serve. run.Group fires
	// its interrupts once, when the first actor returns, so an actor still
	// starting up misses its shutdown entirely and would then serve forever
	// with nobody left to stop it.
	stopped bool
	// ln is the listener Serve was handed, recorded under mux so Shutdown can
	// close it whatever the library is doing. ssh.Server only starts tracking a
	// listener inside its own Serve, and it clears its done channel when it
	// takes the first one -- so a Shutdown landing between this struct being
	// populated and that tracking finds nothing to close, closes a done channel
	// that is then discarded, and leaves Accept blocked forever. Owning the
	// listener here closes that window: the flag decides what Serve reports,
	// and this decides that it stops at all.
	ln *closeOnceListener
}

// closeOnceListener makes Close idempotent, reporting the first result to every
// later caller. sshd closes the listener itself and ssh.Server closes it again
// from its own bookkeeping; without this the second close reports ErrClosed,
// and ssh.Server hands that back as a failed shutdown.
type closeOnceListener struct {
	net.Listener
	once sync.Once
	err  error
}

func (l *closeOnceListener) Close() error {
	l.once.Do(func() { l.err = l.Listener.Close() })
	return l.err
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

	s.stopped = true

	// Close first, before handing the shutdown to ssh.Server. It only stops
	// what it has already tracked, and it begins waiting on its listener wait
	// group after tracking -- so a listener tracked between its close pass and
	// that wait is never closed by it, and the wait then runs to its deadline
	// while Accept sits on an open listener. Closing here ends Accept whatever
	// the library has seen yet, and the close is idempotent, so the library's
	// own close pass reports success rather than ErrClosed.
	if s.ln != nil {
		_ = s.ln.Close()
	}

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
	once := &closeOnceListener{Listener: ln}
	s.mux.Lock()
	if s.stopped {
		s.mux.Unlock()
		// Shutdown already ran and found no server to stop, so nothing else
		// will close ln or end this call.
		_ = once.Close()
		return ErrListnerClosed
	}
	s.sessions = sessions
	s.ln = once
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
	srv := s.server
	s.mux.Unlock()

	err := srv.Serve(once)

	// ssh.Server reports its own sentinel when it sees the shutdown itself. In
	// the window where Shutdown closed the listener before the library tracked
	// it, the library misses that and hands back the raw closed-listener error
	// instead -- the same stop, named differently by an accident of timing.
	s.mux.Lock()
	stopped := s.stopped
	s.mux.Unlock()
	if stopped && errors.Is(err, net.ErrClosed) {
		return ssh.ErrServerClosed
	}

	return err
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
