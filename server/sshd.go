package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"charm.land/ssh"
	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/internal/registration"
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
	SessionManager *SessionManager
	HostSigners    []gossh.Signer
	// Signers is what the relay mints guest certificates with, and so the only
	// authority whose AuthRequest this door believes. Certificates reaching it
	// were minted by a proxy in this cluster; nothing else should get in.
	Signers             []gossh.Signer
	NodeAddr            string
	SessionDialListener SessionDialListener
	MetricsProvider     provider.Provider
	Logger              *slog.Logger
	// HostGateEnabled is set when the relay admits only the host keys in its
	// --authorized-keys. Without the gate any key gets in, so a host can redial
	// with its session key alone and never touch its agent.
	HostGateEnabled bool

	// onRegistered is a test hook, run after the store takes a registration and
	// before this node adopts it: the window in which two registrations can
	// commit in one order and adopt in the other.
	onRegistered func(*Registration)

	server         *ssh.Server
	sessions       *localSessions
	forwardHandler *streamlocalForwardHandler
	mux            sync.Mutex
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

// localSessions tracks the registrations this process adopted, one per session
// ID: a host that reconnects registers the same ID again, possibly while its
// old connection lingers, so the ID alone can't say whose a resource is.
// It drives sessions_active_count, which counts IDs, so a takeover on this node
// leaves the count alone. Every registration's store entry is released when it
// ends, whether the host cancels its forward or its connection ends first; the
// store makes that conditional, so a replaced registration's cleanup leaves its
// successor's entry in place. Sessions visible in a shared store but
// registered on another node are never touched. It is not persisted; a crash
// loses the count along with the sessions.
type localSessions struct {
	gauge          metrics.Gauge
	sessionManager *SessionManager
	logger         *slog.Logger
	timing         leaseTiming

	mu   sync.Mutex
	regs map[string]*localRegistration // by session ID
}

// localRegistration is a registration this node adopted, and the host
// connection it was made on, which a takeover closes. reg is the handle
// its lease keeper last rebuilt, if the keeper rebuilt one.
type localRegistration struct {
	reg  *Registration
	conn io.Closer
	// stopLease stops the lease keeper; nil when the store's entries don't
	// expire.
	stopLease context.CancelFunc
}

func newLocalSessions(p provider.Provider, sessionManager *SessionManager, logger *slog.Logger) *localSessions {
	gauge := p.NewGauge("sessions_active_count")
	gauge.Set(0) // export the series from startup rather than from the first session
	return &localSessions{
		gauge:          gauge,
		sessionManager: sessionManager,
		logger:         logger,
		timing:         defaultLeaseTiming,
		regs:           make(map[string]*localRegistration),
	}
}

// add adopts reg for conn, and returns the registration it replaced.
// ErrSuperseded: the one this node serves for the ID is not superseded by
// reg; nothing changes.
//
// The store already ordered reg against the entry it replaced, but two
// registrations can commit in one order and adopt in the other. Checking again
// here, under the lock, means a delayed older registration can never evict a
// newer one.
//
// reg's lease keeper starts only once reg is accepted, so a refused
// registration is never renewed or rebuilt, and the one it replaced stops
// being kept at the moment it's replaced.
func (l *localSessions) add(reg *Registration, conn io.Closer) (*localRegistration, error) {
	ttl := l.sessionManager.LeaseTTL()

	l.mu.Lock()
	cur, ok := l.regs[reg.ID()]
	if ok && cur.conn != conn && !supersedes(reg.Session, cur.reg.Session) {
		l.mu.Unlock()
		return nil, supersededError(reg.Session, cur.reg.Session)
	}
	lr := &localRegistration{reg: reg, conn: conn}
	var (
		keeper    *leaseKeeper
		keeperCtx context.Context
	)
	if ttl > 0 {
		keeperCtx, lr.stopLease = context.WithCancel(context.Background())
		keeper = &leaseKeeper{
			sm:        l.sessionManager,
			ttl:       ttl,
			timing:    l.timing,
			closeConn: func() { _ = conn.Close() },
			replace:   l.replace,
			logger:    l.logger.With("session-id", reg.ID(), "generation", reg.Generation()),
		}
	}
	l.regs[reg.ID()] = lr
	if !ok {
		l.gauge.Add(1)
	} else if cur.stopLease != nil {
		cur.stopLease()
	}
	l.mu.Unlock()

	if keeper != nil {
		go keeper.run(keeperCtx, reg)
	}
	if !ok {
		return nil, nil
	}
	return cur, nil
}

// replace makes next, a rebuilt handle, the one this node serves for its
// registration, and reports whether it did. It doesn't once that registration
// has ended or been replaced: the rebuild then belongs to no one, and the
// keeper releases it.
func (l *localSessions) replace(next *Registration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cur, ok := l.regs[next.ID()]
	if !ok || !cur.reg.Same(next) {
		return false
	}
	l.regs[next.ID()] = &localRegistration{reg: next, conn: cur.conn, stopLease: cur.stopLease}
	return true
}

// active reports whether reg is the registration this node serves for its ID:
// adopted, not ended, and not replaced.
func (l *localSessions) active(reg *Registration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cur, ok := l.regs[reg.ID()]
	return ok && cur.reg.Same(reg)
}

// end releases reg's store entry, and its slot, count and lease keeper while
// reg is still the one this node serves. It releases every time, because a
// replaced registration still holds a lease of its own; the store leaves an
// entry reg no longer holds alone. The count is released even if the store
// release fails: the host is gone either way.
//
// Every path that ends a registration holds the handle it was adopted with,
// but a rebuild stores the registration under a new lease that only the slot
// knows. So ending the one this node serves releases the slot's handle, and
// reg's too if its lease differs; otherwise a rebuilt entry would outlive its
// host until the lease expired.
func (l *localSessions) end(reg *Registration) {
	release := []*Registration{reg}
	l.mu.Lock()
	if cur, ok := l.regs[reg.ID()]; ok && cur.reg.Same(reg) {
		delete(l.regs, reg.ID())
		l.gauge.Add(-1)
		// Stopped before the release below, so the keeper can't take that
		// release for a lost lease and rebuild the entry.
		if cur.stopLease != nil {
			cur.stopLease()
		}
		release = []*Registration{cur.reg}
		if cur.reg.lease != reg.lease {
			release = append(release, reg)
		}
	}
	// Release before touching the store: a Consul call can be slow, and
	// holding the lock across it would stall unrelated session creation.
	l.mu.Unlock()

	for _, r := range release {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultConsulTimeout)
		if err := l.sessionManager.Release(ctx, r); err != nil {
			l.logger.Error("error deleting session", "error", err, "session-id", r.ID())
		}
		cancel()
	}
}

// contextKeyOwnedSessions holds, per SSH connection, the registrations made on
// that connection, by session ID. Forward and cancel requests act only on the
// requesting connection's own registration, never on another connection's
// registration of the same ID.
type contextKeyOwnedSessions struct{}

func ownSession(ctx ssh.Context, reg *Registration) {
	ctx.Lock()
	defer ctx.Unlock()
	owned, _ := ctx.Value(contextKeyOwnedSessions{}).(map[string]*Registration)
	if owned == nil {
		owned = make(map[string]*Registration)
		ctx.SetValue(contextKeyOwnedSessions{}, owned)
	}
	owned[reg.ID()] = reg
}

// ownedRegistration returns the registration of sessionID made on this
// connection, or nil if there is none.
func ownedRegistration(ctx ssh.Context, sessionID string) *Registration {
	ctx.Lock()
	defer ctx.Unlock()
	owned, _ := ctx.Value(contextKeyOwnedSessions{}).(map[string]*Registration)
	return owned[sessionID]
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
	s.forwardHandler = sh
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
		PublicKeyHandler: s.handlePublicKey,
		ChannelHandlers:  make(map[string]ssh.ChannelHandler), // disallow channel requests, e.g. shell
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

// handlePublicKey admits a peer on the internal node door. Everything that
// reaches it was minted by a proxy in this cluster, so an unrecognized
// authority is refused outright rather than falling back to the offered key:
// this door has no authorized-key check of its own to catch it.
func (s *sshd) handlePublicKey(ctx ssh.Context, key ssh.PublicKey) bool {
	checker := UserCertChecker{IsUserAuthority: s.isOwnAuthority}
	if _, _, err := checker.Authenticate(ctx.User(), key); err != nil {
		s.Logger.Error("error parsing auth request from cert", "error", err)
		return false
	}

	// The proxy minted the host's own SSH session ID into the certificate. It
	// is the one value both ends of that connection share, and so what a
	// session proof is bound to.
	if cert, ok := key.(*gossh.Certificate); ok {
		ctx.Lock()
		ctx.SetValue(contextKeyDownstreamSessionID{}, []byte(cert.KeyId))
		ctx.Unlock()
	}

	return true
}

// contextKeyDownstreamSessionID holds the SSH session ID of the host's
// connection to the proxy, which this connection carries.
type contextKeyDownstreamSessionID struct{}

// sessionIdentity returns the session ID and generation req registers. A
// request without a proof is an old host's, and gets a random ID as it always
// has. One with a proof gets the ID derived from its host key, but only if the
// proof verifies over the host's own connection, so neither the ID nor a proof
// captured elsewhere is enough to claim it.
func (s *sshd) sessionIdentity(ctx ssh.Context, req *CreateSessionRequest) (id string, generation uint64, err error) {
	if len(req.HostKeyProof) == 0 {
		return utils.GenerateSessionID(), 0, nil
	}
	// The ID derives from one key, and the proxy accepts the host's end of a
	// guest's connection by these keys: a second key would be one whose holder
	// proved nothing.
	if n := len(req.HostPublicKeys); n != 1 {
		return "", 0, fmt.Errorf("a proof needs exactly one host key, got %d", n)
	}
	key, _, _, _, err := gossh.ParseAuthorizedKey(req.HostPublicKeys[0])
	if err != nil {
		return "", 0, fmt.Errorf("parsing host key: %w", err)
	}
	ctx.Lock()
	sshSessionID, _ := ctx.Value(contextKeyDownstreamSessionID{}).([]byte)
	ctx.Unlock()
	if len(sshSessionID) == 0 {
		return "", 0, errors.New("no host SSH session ID to verify the proof over")
	}
	if err := registration.Verify(key, sshSessionID, req.SessionSecret, req.Generation, req.HostKeyProof); err != nil {
		return "", 0, err
	}
	return registration.ID(key, req.SessionSecret), req.Generation, nil
}

// isOwnAuthority reports whether key is one of this relay's signing keys.
func (s *sshd) isOwnAuthority(key gossh.PublicKey) bool {
	return signerAuthority(s.Signers, key)
}

// adopt makes reg the registration this node serves for its ID, over conn. It
// reports false with a registration.Superseded reply when a newer registration
// holds the ID here, and false with no reply when conn closed while
// registering.
func (s *sshd) adopt(ctx ssh.Context, reg *Registration, conn *gossh.ServerConn) (ok bool, refusal []byte) {
	prev, err := s.sessions.add(reg, conn)
	if err != nil {
		// The store took reg, but a newer registration was adopted here first.
		// The release is conditional, so it can't touch the newer entry.
		s.Logger.Warn("refused a superseded registration", "error", err, "session-id", reg.ID())
		rctx, cancel := context.WithTimeout(context.Background(), DefaultConsulTimeout)
		defer cancel()
		if err := s.SessionManager.Release(rctx, reg); err != nil {
			s.Logger.Error("error deleting session", "error", err, "session-id", reg.ID())
		}
		return false, []byte(registration.Superseded)
	}
	if prev != nil && prev.conn != conn {
		// A takeover on this node. The old listener goes first, so the new
		// registration can bind the session socket's name, and then the old
		// host connection, so its guests go with it.
		s.forwardHandler.closeListener(prev.reg)
		_ = prev.conn.Close()
	}

	ownSession(ctx, reg)
	// The tunnel handler ends the registration when the host cancels its
	// forward. A host that disconnects before forwarding never reaches that
	// path, so also end it when the owning connection does.
	go func() {
		<-ctx.Done()
		s.sessions.end(reg)
	}()

	// The host may have gone while the store call ran. Its registration would
	// then hold the ID for no one, so end it before replying.
	if ctx.Err() != nil {
		s.sessions.end(reg)
		return false, nil
	}
	return true, nil
}

func (s *sshd) createSessionHandler(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
	conn := ctx.Value(ssh.ContextKeyConn).(*gossh.ServerConn)

	var sessReq CreateSessionRequest
	if err := proto.Unmarshal(req.Payload, &sessReq); err != nil {
		return false, []byte(err.Error())
	}

	sessionID, generation, err := s.sessionIdentity(ctx, &sessReq)
	if err != nil {
		s.Logger.Warn("refused a session proof", "error", err, "node", s.NodeAddr)
		return false, []byte(registration.RefusedProof + ": " + err.Error())
	}

	// Store complete session data for routing and session management
	session := NewSession(
		sessionID,
		s.NodeAddr,
		sessReq.HostUser,
		sessReq.HostPublicKeys,
		sessReq.ClientAuthorizedKeys,
	)
	session.Generation = generation

	reg, sshUser, err := s.SessionManager.Register(context.Background(), session)
	if errors.Is(err, ErrSuperseded) {
		s.Logger.Warn("refused a superseded registration", "error", err, "session-id", sessionID)
		return false, []byte(registration.Superseded)
	}
	if err != nil {
		s.Logger.Error("failed to create session",
			"error", err,
			"session", sessionID,
			"node", s.NodeAddr,
		)
		return false, []byte(fmt.Sprintf("failed to create session: %v", err))
	}
	if s.onRegistered != nil {
		s.onRegistered(reg)
	}
	if ok, refusal := s.adopt(ctx, reg, conn); !ok {
		return false, refusal
	}

	sessResp := &CreateSessionResponse{
		SessionID:        sessionID,
		NodeAddr:         s.NodeAddr,
		SshUser:          sshUser,
		SessionKeyRedial: !s.HostGateEnabled,
	}

	b, err := proto.Marshal(sessResp)
	if err != nil {
		return false, []byte(err.Error())
	}

	return true, b
}
