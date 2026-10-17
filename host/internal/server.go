package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	gssh "charm.land/ssh"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/internal/replay"
	"github.com/owenthereal/upterm/host/sftp"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
	"golang.org/x/crypto/ssh"
)

// DefaultInitialClientTimeout bounds how long a server told to await its
// initial client waits before giving up on the session.
const DefaultInitialClientTimeout = 10 * time.Second

// ErrNoInitialClient is returned by ServeWithContext when AwaitInitialClient
// was set and nobody attached within InitialClientTimeout. The command never
// started; the caller records startup_abandoned.
var ErrNoInitialClient = errors.New("no client attached before the command could start")

// ErrJoinTimeout marks the winning first-guest deadline. Host passes it as
// the server context cancellation cause so attached clients also exit zero.
var ErrJoinTimeout = errors.New("no guest joined within the join timeout")

// ErrSessionStopped is the cause of a session stopped through the admin API;
// host aliases it as errSessionStopped.
var ErrSessionStopped = fmt.Errorf("session stopped: %w", context.Canceled)

type Server struct {
	Command      []string
	CommandEnv   []string
	ForceCommand []string
	// HideClientIP keeps a guest's address out of its forced command's
	// SSH_CONNECTION and SSH_CLIENT, as --hide-client-ip keeps it out of
	// what upterm prints.
	HideClientIP bool
	// HostKey is the key both doors present. A session's key, not the
	// operator's identity: a key exchange signs with whatever is here, on
	// every join, attach and rekey, and an identity held by a confirming
	// agent would be asked each time.
	HostKey        ssh.Signer
	AuthorizedKeys []ssh.PublicKey
	// GuestCertAuthority reports whether a key may vouch for a guest
	// certificate's AuthRequest -- in production, the relay key the host key
	// callback accepted, via RelayAuthority. Nil admits no guest: the only
	// legitimate guest credential is one the relay minted, and without knowing
	// which relay, no claim in one can be believed.
	GuestCertAuthority      func(ssh.PublicKey) bool
	EventEmitter            *emitter.Emitter
	KeepAliveDuration       time.Duration
	Logger                  *slog.Logger
	ReadOnly                bool
	AllowLocalTCPForwarding bool
	Forwards                *Forwards // where each jump's destinations are recorded, for GetSession; optional
	PtySize                 termsize.Size
	PinPtySize              bool
	Term                    string

	// AwaitInitialClient defers starting the command until the first host
	// client's output subscription is installed, and defers serving guests
	// until the command has started. Foreground use sets it: a command that
	// exits at once — `upterm host -- false` — would otherwise race the local
	// terminal's attach, and lose. Headless use leaves it off.
	AwaitInitialClient bool
	// InitialClientTimeout bounds that wait; zero means
	// DefaultInitialClientTimeout.
	InitialClientTimeout time.Duration

	// StopGrace bounds each step of the command's teardown; zero means
	// DefaultStopGrace.
	StopGrace time.Duration

	// OnCommandStarted, if set, is called once the hosted command is running.
	// Readiness is a claim about facts, and this is one of the two facts it
	// rests on: until this fires, "ready" would mean a command that may still
	// fail to start.
	OnCommandStarted func()

	// OnGuestServerStopped is called when the guest listener stops serving,
	// which behind a TunnelListener means the tunnel is lost for good. The
	// session does not end: the command keeps running and keeps its pty.
	// Reporting it is the caller's job, because internal must not know about
	// on-disk state.
	OnGuestServerStopped func(error)

	// SFTP configuration
	SFTPDisabled          bool                   // Disable SFTP subsystem entirely
	SFTPPermissionChecker sftp.PermissionChecker // Optional: prompts user for SFTP permissions (nil = auto-allow)

	// cmd is the hosted command, kept so its outcome can be read after
	// ServeWithContext returns.
	cmd *command

	// hostClients elects the primary among the clients on the host door. A
	// value rather than a pointer built in ServeWithContext: the elector's
	// state is read from outside the serving goroutine, and a pointer written
	// there would be a race with every such read.
	hostClients hostClients

	// order is the session's shutdown cause, as host publishes it, and the
	// order of each command's end against it. A value, so that it exists
	// before ServeWithContext runs: host can publish a cause before the
	// server has started.
	order endOrder
}

// CommandResult returns the hosted command's outcome. Valid after
// ServeWithContext returns.
func (s *Server) CommandResult() CommandResult {
	if s.cmd == nil {
		return CommandResult{}
	}
	return s.cmd.Result()
}

// sessionContext derives the context guest sessions live under.
//
// It is deliberately detached from the parent. The fan-out's final flush
// happens as the command's output copy returns, and a session context that died
// with the parent would let HandleSession close a guest's channel while that
// flush was still writing into it. Only the SSH server actor's interrupt
// releases sessions, and it does so after giving the command a bounded chance
// to finish.
func sessionContext(ctx context.Context) context.Context {
	return context.WithoutCancel(ctx)
}

// waitClosed waits for done, giving up after timeout.
func waitClosed(done <-chan struct{}, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

// releaseSessions holds guest sessions open until the fan-out has finished
// delivering into them, then releases them.
//
// Named rather than inlined into the interrupt so the ordering it establishes
// can be tested on its own: it is the half of the mechanism that a detached
// session context is useless without.
func releaseSessions(cmdDone <-chan struct{}, timeout time.Duration, release func()) {
	waitClosed(cmdDone, timeout)
	release()
}

// onGuestPacer, when set, is handed each session's pacer as ServeWithContext
// builds it, so a test can watch the gate hold. Nil in production.
var onGuestPacer func(*guestPacer)

// sessionReplayer builds the replayer each session's fan-out reconstructs a
// joining terminal's screen with, rather than handing it the raw ring. A var
// so that a test can install its own; nil hands every join the raw ring.
var sessionReplayer = replay.New

// logReplayFallback is what a session's fan-out tells of each join it handed
// the raw ring rather than a reconstruction of the screen, and why. A screen
// holding state the reconstruction doesn't restore is expected, so that is
// logged at Info; a panic in the replayer is a bug, logged at Error with its
// stack. The fan-out calls it with none of its locks held.
func logReplayFallback(logger *slog.Logger) func(error) {
	return func(err error) {
		var p *uio.ReplayPanic
		if errors.As(err, &p) {
			logger.Error("replay fell back to the raw ring", "reason", err, "stack", string(p.Stack))
			return
		}
		logger.Info("replay fell back to the raw ring", "reason", err)
	}
}

// ServeWithContext runs the session: the hosted command, the guest door on
// guest, and — when host is not nil — the host door on host, for clients that
// are already on this machine.
func (s *Server) ServeWithContext(ctx context.Context, guest, host net.Listener) error {
	if s.HostKey == nil {
		return errors.New("host server: HostKey is required")
	}

	writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
	// Installed before anything can join: SetReplayer is once, before any
	// join.
	if sessionReplayer != nil {
		writers.SetReplayer(sessionReplayer(), logReplayFallback(s.Logger))
	}
	// The pty as the doors see it: the host door serves before the command
	// starts, so a client can reach this handle before there is a pty behind
	// it.
	shared := newSharedPTY()

	// Before anything that ends can record its end against it.
	s.order.watch(ctx)

	cmdCtx, cmdCancel := context.WithCancel(ctx)
	defer cmdCancel()
	cmd := newCommand(
		s.Command[0],
		s.Command[1:],
		s.CommandEnv,
		s.PtySize,
		s.PinPtySize,
		s.Term,
		s.EventEmitter,
		writers,
		s.Logger,
	)
	cmd.stopGrace = s.StopGrace
	// With no primary, the earliest guest paces the command, through this.
	// It lives on the command's context, so stopping the session ends any
	// hold at once rather than waiting on a slow guest.
	pacer := newGuestPacer(cmdCtx, writers)
	if onGuestPacer != nil {
		onGuestPacer(pacer)
	}
	cmd.pacer = pacer
	cmd.order = &s.order
	s.cmd = cmd

	var g run.Group
	// The three facts the session's order rests on: a client has reached the
	// host door and is subscribed to the output, the command is running, and
	// its Run has returned.
	var firstOnce sync.Once
	firstHostClient := make(chan struct{})
	cmdStarted := make(chan struct{})
	cmdDone := make(chan struct{})
	{
		g.Add(func() error {
			defer close(cmdDone)
			if s.AwaitInitialClient {
				timeout := s.InitialClientTimeout
				if timeout <= 0 {
					timeout = DefaultInitialClientTimeout
				}
				timer := time.NewTimer(timeout)
				defer timer.Stop()
				select {
				case <-firstHostClient:
				case <-timer.C:
					shared.abandon()
					return ErrNoInitialClient
				case <-cmdCtx.Done():
					shared.abandon()
					return cmdCtx.Err()
				}
			}
			ptmx, err := cmd.Start(cmdCtx, shared.initialSize())
			if err != nil {
				shared.abandon()
				return fmt.Errorf("error starting command: %w", err)
			}
			shared.set(ptmx)
			if s.OnCommandStarted != nil {
				s.OnCommandStarted()
			}
			close(cmdStarted)
			return cmd.Run()
		}, func(err error) {
			cmdCancel()
		})
	}
	// Both doors share this: the session ends for one reason, and the guest
	// actor's interrupt is what decides when sessions are released.
	sessCtx, cancel := context.WithCancel(sessionContext(ctx))
	sh := sessionHandler{
		forceCommand:          s.ForceCommand,
		forceCommands:         &guestHandlers{},
		sharedGuests:          &guestHandlers{},
		hostHandlers:          &guestHandlers{},
		forceCommandHangup:    hangupGrace,
		forceCommandGrace:     forceCommandStopGrace,
		commandEnv:            s.CommandEnv,
		hideClientIP:          s.HideClientIP,
		ptmx:                  shared,
		eventEmmiter:          s.EventEmitter,
		terminals:             newTerminalWindows(s.Logger),
		writers:               writers,
		pacer:                 pacer,
		keepAliveDuration:     s.KeepAliveDuration,
		ctx:                   sessCtx,
		stopCtx:               ctx,
		order:                 &s.order,
		logger:                s.Logger,
		readonly:              s.ReadOnly,
		sftpPermissionChecker: s.SFTPPermissionChecker,
		kind:                  kindGuest,
		cmdDone:               cmdDone,
		commandResult:         cmd.Result,
	}

	ss := []gssh.Signer{s.HostKey}

	{
		ph := publicKeyHandler{
			AuthorizedKeys: s.AuthorizedKeys,
			CertAuthority:  s.GuestCertAuthority,
			Logger:         s.Logger,
		}

		// Set up subsystem handlers (SFTP). The door admits a subsystem with
		// the session's end, as it does a shell (see admitGuest), and SFTP
		// hands that admission back as it starts: an SFTP session in progress
		// is not waited for, and is cut off when the session ends, as it
		// always was.
		var subsystemHandlers map[string]gssh.SubsystemHandler
		if !s.SFTPDisabled {
			subsystemHandlers = map[string]gssh.SubsystemHandler{
				"sftp": sh.startAdmitted(sh.HandleSFTP),
			}
		}
		sh.subsystems = subsystemHandlers

		server := gssh.Server{
			HostSigners:      ss,
			Handler:          sh.HandleSession,
			Version:          upterm.HostSSHServerVersion,
			PublicKeyHandler: ph.HandlePublicKey,
			ConnCallback: func(ctx gssh.Context, conn net.Conn) net.Conn {
				// Installed before authentication or any concurrent channel handlers.
				ctx.SetValue(forwardingPresenceKey{}, &forwardingPresence{})
				return conn
			},
			LocalPortForwardingCallback: func(ctx gssh.Context, destinationHost string, destinationPort uint32) bool {
				logArgs := []any{
					"destination-host", destinationHost,
					"destination-port", destinationPort,
					"remote-addr", ctx.RemoteAddr().String(),
					"user", ctx.User(),
					"session-id", ctx.SessionID(),
				}
				if !s.AllowLocalTCPForwarding {
					s.Logger.Warn("rejecting local port forwarding", logArgs...)
					return false
				}

				s.Logger.Info("allowing local port forwarding", logArgs...)
				return true
			},
			ChannelHandlers: map[string]gssh.ChannelHandler{
				"session":      rawSessionHandler,
				"direct-tcpip": forwardingHandler(s.EventEmitter, s.Forwards),
			},
			SubsystemHandlers: subsystemHandlers,
			// Admits a guest's shell with the session's end, or refuses it
			// once that has stopped waiting for guests.
			SessionRequestCallback: sh.admitGuest,
			ConnectionFailedCallback: func(conn net.Conn, err error) {
				s.Logger.Error("connection failed", "error", err)
			},
		}
		g.Add(func() error {
			// Guests are never served a session whose command has not
			// started. The host door is: the gate is defined by a client
			// reaching it.
			select {
			case <-cmdStarted:
			case <-sessCtx.Done():
				return nil
			}

			// Both of those can be ready at the same instant — a command that
			// exits as soon as it starts, `upterm host -- false`, closes
			// cmdStarted and then ends the session — and a select that picked
			// cmdStarted arrives here with our own interrupt already run.
			// Serving then is not merely pointless: charm's Serve has no
			// shutdown guard, and its trackListener resets doneChan to nil
			// whenever the server holds no listener and no connection, which is
			// exactly the state Shutdown leaves behind. The accept loop would
			// park forever on a listener Shutdown no longer knows about, and
			// g.Run would never return.
			select {
			case <-sessCtx.Done():
				return nil
			default:
			}

			err := server.Serve(guest)

			// A tunnel that goes away takes the guests with it and nothing
			// else. Returning here would end the run.Group — which interrupts
			// every actor regardless of the error — and the interrupts would
			// cancel the command: a network blip would destroy work that is
			// still running perfectly well. Park until the session ends for a
			// reason that is actually the session's.

			// Our own Shutdown makes Serve return ErrServerClosed, and our own
			// Close makes it return a use-of-closed-network-connection error
			// instead. Both are the session ending rather than the tunnel
			// going away, and the second is only distinguishable by asking
			// whether the session is still live: reported as a tunnel loss, it
			// would say the tunnel was gone from a session that is merely
			// ending.
			if s.OnGuestServerStopped != nil && sessCtx.Err() == nil && !errors.Is(err, gssh.ErrServerClosed) {
				s.OnGuestServerStopped(err)
			}
			<-sessCtx.Done()
			return nil
		}, func(err error) {
			// Let the fan-out finish delivering before the sessions are
			// released. Only the host door's interrupt runs after this one,
			// and the clients it waits for are sent their ends meanwhile, once
			// the sessions are released, so waiting here holds up only that
			// door's listener's close. A command-led exit has already closed
			// cmdDone by the time this runs.
			releaseSessions(cmdDone, outputDrainTimeout+guestFlushTimeout, cancel)

			// That cancel hangs up every forced command, and each one's guest is
			// sent what it says on the way out and a reset once it has gone.
			// Wait for them, bounded, before the session ends and its tunnel
			// closes under them.
			if bound := forceCommandStopBound(sh.forceCommandHangup, sh.forceCommandGrace); !sh.forceCommands.wait(bound) {
				s.Logger.Warn("gave up waiting for forced commands to end", "bound", bound)
			}
			// And the shared command's guests are each sent the session's
			// status, as the session's last notice to a client. Each handler
			// waits up to guestFlushTimeout for its close to be answered, after
			// unwinding and sending the status, which take time of their own,
			// so the wait for them allows twice that, as forceCommandStopBound
			// does for a forced command's guest: one the size of the close
			// wait alone gave up on a guest whose answer took just under it.
			// Only one of the two waits has anyone to wait for: with a forced
			// command, every guest has one.
			if bound := 2 * guestFlushTimeout; !sh.sharedGuests.wait(bound) {
				s.Logger.Warn("gave up waiting for guests to be sent the session's status", "bound", bound)
			}

			// shut down ssh server. sessCtx, not ctx: Shutdown waits on its
			// connection WaitGroup until the context it is given is done, and
			// on a command-led exit ctx is still live — a guest that keeps its
			// SSH connection open after its channel closed would hang the host
			// forever, and the deferred ReverseTunnel.Close would never run.
			_ = server.Shutdown(sessCtx)

			// And close the listener ourselves, as the host door's interrupt
			// does. Shutdown only closes the listeners Serve registered, so an
			// interrupt that beats Serve to it leaves this one open — and
			// charm's Serve resets its done channel on entry, so it would then
			// block in Accept on a listener nothing will ever close. Closing it
			// here makes that unreachable whichever way the race goes.
			_ = guest.Close()
		})
	}
	if host != nil {
		// The same session state under the other door's policy. A local client
		// is the host: --force-command would mean the host could never reach
		// its own command, --read-only would lock the operator out of their own
		// terminal, and there is no SFTP to serve to a client that already has
		// the filesystem.
		hostSH := sh
		hostSH.kind = kindHost
		hostSH.readonly = false
		hostSH.forceCommand = nil
		hostSH.sftpPermissionChecker = nil
		hostSH.subsystems = nil
		// The gate: the first client through this door is what the command's
		// start is waiting for.
		hostSH.onHostClientAttached = func() { firstOnce.Do(func() { close(firstHostClient) }) }
		// And the elector: exactly one of the clients on this door paces the
		// command and is sent its live terminal queries.
		s.hostClients.logger = s.Logger
		// The pacer stands aside while there is a primary, which paces the
		// command itself, so it is told of every change.
		s.hostClients.onPrimary = pacer.setPrimary
		hostSH.hostClients = &s.hostClients

		hostServer := gssh.Server{
			HostSigners:      ss,
			Handler:          hostSH.HandleSession,
			Version:          upterm.HostSSHServerVersion,
			PublicKeyHandler: (&hostPublicKeyHandler{}).HandlePublicKey,
			ChannelHandlers:  map[string]gssh.ChannelHandler{"session": rawSessionHandler},
			// Admits a client's shell with the session's end, as the guest
			// door does a guest's.
			SessionRequestCallback: hostSH.admitGuest,
			ConnectionFailedCallback: func(conn net.Conn, err error) {
				s.Logger.Error("attach connection failed", "error", err)
			},
		}
		g.Add(func() error {
			err := hostServer.Serve(host)
			// The attach socket failing is not the session failing: the
			// command and its guests carry on, and the operator can no longer
			// attach locally until the session is restarted. Park.
			if !errors.Is(err, gssh.ErrServerClosed) {
				s.Logger.Warn("attach socket stopped serving; command continues", "error", err)
			}
			<-sessCtx.Done()
			return nil
		}, func(err error) {
			// Sessions are released by sessCtx's cancellation, which the
			// guest actor's interrupt performs, and it runs first because
			// run.Group calls interrupts in the order the actors were added.
			// Each client's handler then sends it the session's end and its
			// status, and the reply to the first can take
			// upterm.SessionEndReplyBound. Wait for them, bounded, before the
			// session ends: the daemon exits once it has, and a status still
			// to be sent would go unsent.
			if !hostSH.hostHandlers.wait(hostEndBound) {
				s.Logger.Warn("gave up waiting for local clients to be sent the session's end", "bound", hostEndBound)
			}

			// All that is left is to close the listener, and Shutdown is
			// handed a context that is already done, so that this is all it
			// does. Every handler the door admitted has sent its client the
			// session's end and its status by now, or been given up on above:
			// a connection still open has nothing more coming, and waiting
			// for its client to hang up would only hold the daemon. What gets
			// a client its status is the wait above, not a wait here.
			shutdownCtx, cancelShutdown := context.WithCancel(context.Background())
			cancelShutdown()
			_ = hostServer.Shutdown(shutdownCtx)
			_ = host.Close()
		})
	}

	return g.Run()
}

// forceCommandStopGrace bounds each step of a forced command's teardown after
// the first, which hangupGrace bounds: SIGHUP, then the master's close, then
// SIGTERM, then SIGKILL, as the session's own command is torn down. A second
// rather than the session command's DefaultStopGrace, because a forced command
// is torn down every time its guest leaves, not once per session, and because
// the session's end waits for it: something that ignores everything is gone in
// about four seconds rather than sixteen. A var so a test can change it.
var forceCommandStopGrace = time.Second

// forceCommandStopBound is how long a session that is ending waits for its
// forced commands' teardowns, given their hangup and later grace: terminate's
// worst case, then the drain of what they wrote on the way out, then a guest's
// flush, then the wait for the close sent with its status to be answered. Past
// it the session ends anyway -- a guest that has stopped reading holds its
// handler in a write nothing else releases.
func forceCommandStopBound(hangup, grace time.Duration) time.Duration {
	return hangup + 3*grace + forceCommandDrainTimeout + 2*guestFlushTimeout
}

// guestHandlers tracks guests' handlers still running, so a session that is
// ending can wait for them: in production the tunnel closes behind the
// session, and would cut off what they still have to send their guests.
//
// Not a sync.WaitGroup: a guest can reach the door while the session is ending,
// and a WaitGroup may not be added to from zero while it is being waited on.
// The door stays open until the waits are done, and what a guest gets depends
// on when its shell or exec request arrives, since that is when the door
// registers its handler (see admitGuest). Before the session's end has
// finished waiting, it is admitted and waited for: it is sent an exit status
// -- 0 if it arrived too late for the command's, or 1 if the session ended by
// a stop, signal or cancellation (see exitLate) -- and then the bounded wait
// for that to be answered. After, wait has sealed the set, and the request is
// refused: the guest's client sees its shell fail to start, rather than a
// session that ends without a status.
type guestHandlers struct {
	mu      sync.Mutex
	running map[chan struct{}]struct{}
	// sealed is set by wait as it returns, under mu, so that nothing joins a
	// set it has finished waiting for.
	sealed bool
	// admitted holds, for each session admit has registered and whose
	// handler has not yet taken it, what marks that handler finished.
	admitted map[gssh.Session]func()

	// onWait, if set, is called each time wait has found a handler running
	// and is about to wait on it. Nil in production; a test uses it to know
	// that wait has looked.
	onWait func()
}

// begin registers a handler, returning what marks it finished, or false once
// a wait has returned: that wait was the session's end's one look at these
// handlers, and one registered after it would go unwaited for.
func (t *guestHandlers) begin() (finish func(), ok bool) {
	done := make(chan struct{})
	t.mu.Lock()
	if t.sealed {
		t.mu.Unlock()
		return nil, false
	}
	if t.running == nil {
		t.running = map[chan struct{}]struct{}{}
	}
	t.running[done] = struct{}{}
	t.mu.Unlock()
	return func() {
		t.mu.Lock()
		delete(t.running, done)
		t.mu.Unlock()
		close(done)
	}, true
}

// wait blocks until no handler is running, or until timeout, reporting
// whether none was. A handler that registers while it waits is waited for as
// well as those already running. Whichever way it returns, it seals the set
// first, under the lock begin takes: finding none running and refusing the
// next registration are one step, so no handler can slip in between them.
func (t *guestHandlers) wait(timeout time.Duration) bool {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		t.mu.Lock()
		var next chan struct{}
		for done := range t.running {
			next = done
			break
		}
		if next == nil {
			t.sealed = true
			t.mu.Unlock()
			return true
		}
		t.mu.Unlock()
		if t.onWait != nil {
			t.onWait()
		}
		select {
		case <-next:
		case <-deadline.C:
			t.mu.Lock()
			t.sealed = true
			t.mu.Unlock()
			return false
		}
	}
}

// admit registers sess's handler, as begin does, and keeps what marks it
// finished for that handler to take: the door admits a session before its
// handler runs (see admitGuest). Kept here, keyed by charm's session, rather
// than in the connection's context, which every session on the connection
// shares and whose entries charm can only overwrite: a guest that opens
// session after session on one connection would grow it for as long as the
// connection lasted.
func (t *guestHandlers) admit(sess gssh.Session) bool {
	finish, ok := t.begin()
	if !ok {
		return false
	}
	t.mu.Lock()
	if t.admitted == nil {
		t.admitted = map[gssh.Session]func(){}
	}
	t.admitted[sess] = finish
	t.mu.Unlock()
	return true
}

// take returns what admit kept for sess and forgets it, or nil for a session
// admit did not register -- a test's -- which nothing waits for.
func (t *guestHandlers) take(sess gssh.Session) func() {
	t.mu.Lock()
	defer t.mu.Unlock()
	finish := t.admitted[sess]
	delete(t.admitted, sess)
	return finish
}

// guestTracker is what the door registers this session's clients with: on the
// host door, its own; on the guest door, the forced commands' tracker when
// there is one, the shared command's otherwise. Nil in a test's handler.
func (h *sessionHandler) guestTracker() *guestHandlers {
	if h.kind == kindHost {
		return h.hostHandlers
	}
	if len(h.forceCommand) > 0 {
		return h.forceCommands
	}
	return h.sharedGuests
}

// admitGuest is the guest door's SessionRequestCallback, which charm calls
// before it answers a session's shell, exec or subsystem request. A shell's or
// exec's handler is registered with the session's end here, before the guest
// is told its session started, rather than in the handler, which runs only
// after: registered there, a guest whose request arrived just as the session's
// end finished waiting would have been accepted with nothing left to wait for
// its status. Once the session's end has finished waiting, the request is
// refused instead.
//
// A subsystem is admitted the same way, and its handler hands the admission
// back as it starts (see startAdmitted), so the session's end waits only for
// that: charm accepts the request before the handler starts, and a tunnel
// closed in between would cut off a subsystem the door had just accepted. One
// the door doesn't serve is refused here, before it is admitted: charm would
// refuse it after this says yes, and nothing would ever take the admission. A
// handler with no trackers -- a test's -- admits everything. The host door
// admits its clients the same way, with its own tracker.
func (h *sessionHandler) admitGuest(sess gssh.Session, requestType string) bool {
	handlers := h.guestTracker()
	if handlers == nil {
		return true
	}
	if requestType == "subsystem" && !h.servesSubsystem(sess.Subsystem()) {
		return false
	}
	return handlers.admit(sess)
}

// servesSubsystem reports whether the door has a handler for the named
// subsystem, by the lookup charm makes: the name, then "default".
func (h *sessionHandler) servesSubsystem(name string) bool {
	return h.subsystems[name] != nil || h.subsystems["default"] != nil
}

// startAdmitted wraps a subsystem's handler so that it hands back, as it
// starts, the admission the door made for its session (see admitGuest).
func (h *sessionHandler) startAdmitted(handle gssh.SubsystemHandler) gssh.SubsystemHandler {
	return func(sess gssh.Session) {
		if finish := h.takeAdmission(sess); finish != nil {
			finish()
		}
		handle(sess)
	}
}

// takeAdmission returns what the door kept for sess's handler when it
// admitted sess, and forgets it, or nil for a session it did not admit.
//
// Every session the door admits reaches here: once the callback has said
// yes, charm checks that there is a handler, which the door always has, marks
// the session handled, replies -- ignoring a reply that fails -- and starts
// the handler unconditionally (charm.land/ssh v0.4.3 session.go:261-296), and
// taking the admission is the first thing the handler does.
func (h *sessionHandler) takeAdmission(sess gssh.Session) func() {
	handlers := h.guestTracker()
	if handlers == nil {
		return nil
	}
	// The door's handler is given the session charm admitted wrapped, so
	// that its output goes straight to the channel; the key is charm's own.
	if raw, ok := sess.(*rawSession); ok {
		sess = raw.Session
	}
	return handlers.take(sess)
}

const (
	// forceCommandDrainIdle is how long a forced command's exit waits for more
	// output after the last byte was read. EOF is not a portable signal here:
	// Windows' ConPTY only reports EOF once the pty is closed, and deferring
	// that close is the entire point of the drain, so "nothing has arrived for
	// a while" is what has to stand in for it there.
	forceCommandDrainIdle = 100 * time.Millisecond

	// forceCommandDrainTimeout caps the drain overall, so a command that exits
	// while a background child keeps writing cannot hold the session open.
	forceCommandDrainTimeout = 2 * time.Second
)

// activityReader records when output was last seen so the exit path can tell
// "still streaming" from "nothing more is coming".
type activityReader struct {
	r    io.Reader
	last atomic.Int64 // unix nanos
}

func newActivityReader(r io.Reader) *activityReader {
	a := &activityReader{r: r}
	a.touch()
	return a
}

func (a *activityReader) touch() { a.last.Store(time.Now().UnixNano()) }

func (a *activityReader) idleFor() time.Duration {
	return time.Since(time.Unix(0, a.last.Load()))
}

func (a *activityReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 {
		a.touch()
	}
	return n, err
}

// drainForceCommandOutput holds the forced command's exit until its output has
// reached the guest: until the reader reports EOF, or until nothing has arrived
// for forceCommandDrainIdle, whichever happens first.
func drainForceCommandOutput(logger *slog.Logger, output *activityReader, drained, done <-chan struct{}) {
	// Start the idle window now rather than at construction. The command may
	// have run for a while before exiting, and a stale timestamp would read as
	// "idle" immediately and skip the drain entirely.
	output.touch()

	deadline := time.NewTimer(forceCommandDrainTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(forceCommandDrainIdle / 2)
	defer ticker.Stop()

	for {
		select {
		case <-drained:
			return
		case <-done:
			return
		case <-deadline.C:
			logger.Warn("timed out draining forced command output", "timeout", forceCommandDrainTimeout)
			return
		case <-ticker.C:
			if output.idleFor() >= forceCommandDrainIdle {
				return
			}
		}
	}
}

// clientKind is which door a session came in by. Policy is a property of the
// door: what --force-command, --read-only, SFTP and the query filter do to a
// session depends on it, and HandleSession is otherwise the same code.
type clientKind int

const (
	kindGuest clientKind = iota
	kindHost
)

// serverConn returns the SSH connection under a session, or nil when the
// context carries none (a test's fake session). charm stores it under
// ContextKeyConn once the handshake has completed.
func serverConn(sess gssh.Session) *ssh.ServerConn {
	c, _ := sess.Context().Value(gssh.ContextKeyConn).(*ssh.ServerConn)
	return c
}

type publicKeyHandler struct {
	AuthorizedKeys []ssh.PublicKey
	// CertAuthority is the key allowed to have signed a guest's certificate.
	// Nil refuses every guest.
	CertAuthority func(ssh.PublicKey) bool
	Logger        *slog.Logger
}

type authenticatedGuestKey struct{}

type authenticatedGuest struct {
	auth *server.AuthRequest
	key  ssh.PublicKey
}

var clientEventSequence atomic.Uint64

func clientEventID(transportID string) string {
	return fmt.Sprintf("%s/%d", transportID, clientEventSequence.Add(1))
}

func (h *publicKeyHandler) HandlePublicKey(ctx gssh.Context, key gssh.PublicKey) bool {
	checker := server.UserCertChecker{IsUserAuthority: h.CertAuthority}
	auth, pk, err := checker.Authenticate(ctx.User(), key)
	if err != nil {
		// A certificate from anyone but the verified relay is refused here and
		// not passed on as a plain key: the AuthorizedKeys check below cannot
		// catch it, because a session with no authorized keys admits anyone.
		h.Logger.Error("error parsing auth request from cert", "error", err)
		return false
	}

	// TODO: sshproxy already rejects unauthorized keys
	// Does host still need to check them?
	if len(h.AuthorizedKeys) == 0 {
		ctx.SetValue(authenticatedGuestKey{}, authenticatedGuest{auth, pk})
		return true
	}

	for _, k := range h.AuthorizedKeys {
		if utils.KeysEqual(k, pk) {
			ctx.SetValue(authenticatedGuestKey{}, authenticatedGuest{auth, pk})
			return true
		}
	}

	h.Logger.Info("unauthorized public key")
	return false
}

// hostPublicKeyHandler admits any key on the host door. Authentication there
// is the ability to open the socket, bound the way the admin socket is: no
// chmod, because the 0700 session directory is the boundary — and the key
// only names the client.
//
// Naming it is HandleSession's job, not this one's: a connection that
// authenticates and never opens a session has not joined anything.
type hostPublicKeyHandler struct{}

func (h *hostPublicKeyHandler) HandlePublicKey(ctx gssh.Context, key gssh.PublicKey) bool {
	return true
}

type sessionHandler struct {
	forceCommand []string
	commandEnv   []string
	hideClientIP bool
	ptmx         PTY
	eventEmmiter *emitter.Emitter
	// terminals is the geometry of every terminal attached to the session,
	// shared by both doors: guests count towards the minimum as host clients
	// do.
	terminals *terminalWindows
	writers   *uio.MultiWriter
	// pacer is what a guest's sink registers with as it attaches, so that
	// with no primary the earliest guest paces the command. Host clients and
	// viewers never register. Nil attaches guests straight to writers.
	pacer             *guestPacer
	keepAliveDuration time.Duration
	ctx               context.Context
	// stopCtx preserves the winning Host error while ctx waits for output drain.
	stopCtx  context.Context
	logger   *slog.Logger
	readonly bool
	kind     clientKind

	// cmdDone closes when the hosted command's Run has returned, and
	// commandResult reports how it ended. A shared-pty client whose session
	// ends because the command exited is closed with the command's status,
	// which is what makes `upterm attach`'s exit status mean something.
	cmdDone       <-chan struct{}
	commandResult func() CommandResult

	// order is the session's published shutdown cause, which decides a
	// client's status ahead of stopCtx's cause (see shutdownCause), and what a
	// forced command's end is recorded against. Nil in a test's handler.
	order *endOrder

	// onHostClientAttached, set on the host door only, reports that a local
	// client's output subscription is installed. That is what a server told to
	// await its initial client starts the command on.
	onHostClientAttached func()

	// hostClients, set on the host door only, is the elector every client that
	// could be primary registers with.
	hostClients *hostClients

	// forceCommands is what the session's end waits on for the forced
	// commands' teardowns: each is hung up and sends its guest a reset once
	// it has gone. Shared by every guest's handler; nil in a test's handler,
	// which waits for nothing.
	forceCommands *guestHandlers
	// sharedGuests is the same for the shared command's guests, each of which
	// is sent the session's status. Nil in a test's handler.
	sharedGuests *guestHandlers
	// hostHandlers is the same for the host door's clients, each of which is
	// sent the session's end and then its status. Nil in a test's handler.
	hostHandlers *guestHandlers
	// forceCommandHangup and forceCommandGrace bound a forced command's
	// teardown: hangupGrace and forceCommandStopGrace, read once when the
	// session starts. A handler can outlive its session -- one whose guest
	// stopped reading is parked in a write -- so it must not read the package
	// vars, which a test restores when it ends.
	forceCommandHangup time.Duration
	forceCommandGrace  time.Duration

	// SFTP configuration
	sftpPermissionChecker sftp.PermissionChecker // Optional: prompts user for SFTP permissions

	// subsystems are the guest door's subsystem handlers, by name, so that
	// admitGuest refuses one the door doesn't serve. Nil in a test's handler.
	subsystems map[string]gssh.SubsystemHandler
}

func (h *sessionHandler) HandleSession(sess gssh.Session) {
	// The door registered this client's handler as it accepted the shell (see
	// admitGuest). Finished last, after the client's status and, for a guest,
	// the wait for it to be answered.
	if finish := h.takeAdmission(sess); finish != nil {
		defer finish()
	}

	sessionID := sess.Context().Value(gssh.ContextKeySessionID).(string)
	if h.kind == kindHost {
		id := clientEventID(sessionID)
		emitHostClientJoinEvent(h.eventEmmiter, id, sess.Context().ClientVersion(), sess.PublicKey())
		defer emitClientLeftEvent(h.eventEmmiter, id)
	}

	// Whether this client is still connected, handed to the size tracking so
	// that it can ask under its own lock. charm cancels this context from the
	// conn.Close it defers in handleConn, whichever side hung up.
	alive := func() bool { return sess.Context().Err() == nil }

	ptyReq, winCh, isPty := sess.Pty()

	// However a guest's handler ends, the Exit it sends is waited on, bounded,
	// until the close that follows it is answered. A session that is ending
	// closes its tunnel once its guests' handlers have returned, and the tunnel
	// takes with it whatever the relay has not yet passed on: a status written
	// and not yet delivered was lost as surely as one never written -- and the
	// session can end within a round trip of any guest's Exit, not only of one
	// it sent because it was ending. Whatever terminates the guest's SSH on the
	// far side of the tunnel answers the close only once it has read
	// everything sent before it, the status included: x/crypto answers a CLOSE
	// from the read loop that has already queued the requests ahead of it
	// (channel.go:460-464 at v0.57.0). That is the relay, which goes on to
	// deliver what it has read once the tunnel is gone --
	// TestSSHForwardTransportCloseDrainsBufferedData in server/ pins it -- or,
	// for a ws guest of a relay with no SSH listener, which pipes it through
	// raw, the guest itself.
	//
	// Deferred here, so that it runs after everything the handler defers below
	// -- the guest's sink leaves the fan-out and the client-left event goes out
	// before the wait, not a round trip after it -- and before the admission's
	// finish above, which the session's end waits on. winCh is read when it
	// runs, since the window-change loop sets it to nil once it has seen the
	// channel close. A guest that has already gone returns at once.
	if h.kind == kindGuest {
		closed := channelClosed(sess)
		defer func() { awaitChannelClosed(closed, winCh, guestFlushTimeout) }()
	}

	// A local client may be a viewer: a backgrounded host that displays the
	// session without owning a terminal. It gets no window-change channel,
	// which the loop below is content with. A guest still needs a pty, because
	// a guest with no terminal has nothing to show the session on.
	if !isPty && h.kind == kindGuest {
		_, _ = io.WriteString(sess, "PTY is required.\n")
		_ = sess.Exit(1)
		// Exit closes the channel. Without returning, the rest of the handler
		// ran against a dead session: it attached it to the shared output
		// writer, started a keepalive ticker and a window-change loop, and
		// finished with a second Exit that could only fail.
		return
	}

	var (
		g    run.Group
		err  error
		ptmx = h.ptmx
	)

	// The forced command's exit status, recorded by the actor that waits on it
	// rather than read back off run.Group's return value.
	//
	// run.Group.Run returns whichever actor finished first, and when a forced
	// command exits, two of them unblock at the same instant: the wait, which
	// carries the status, and the output copy, which sees the pty's EOF and
	// returns nil. Reading the status off Run therefore made the guest's exit
	// code a coin toss; measured, `--force-command 'exit 42'` reported 42 or 0
	// depending on scheduling. Run drains every actor before returning, so
	// reading these afterwards is ordered. cmdAfterShutdown is whether the
	// command ended after the session's shutdown was published.
	var (
		cmdCode          int
		cmdExited        bool
		cmdAfterShutdown bool
	)

	// simulate openssh keepalive
	{
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			ticker := time.NewTicker(h.keepAliveDuration)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					if _, err := sess.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil); err != nil {
						h.logger.Debug("error pinging client to keepalive", "error", err)
					}
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, func(err error) {
			cancel()
		})
	}

	// Everything this handler sends the guest itself goes here rather than to
	// sess, so it stays behind whatever is already queued for delivery. In the
	// fan-out path that is the guest's sink: the replay is handed over during
	// attach and delivered by the sink's goroutine, so a direct write to sess
	// races it — arriving ahead of the replay, or between the packets of a chunk
	// already in flight. The forced-command path has no such queue and no
	// concurrent writer, since its copy is a run.Group actor that has not
	// started yet.
	guestOutput := io.Writer(sess)

	if h.kind == kindGuest && len(h.forceCommand) > 0 {
		if h.ctx.Err() != nil {
			// The session is already tearing down. This guest arrived a moment
			// too late, which is not its error, and a command started now
			// would only be hung up again. Its shell was accepted before the
			// session's end stopped waiting for guests, so it is sent a status
			// (see exitLate) and the wait every guest's status gets (see the
			// top of HandleSession). One that arrives after that is refused at
			// its request (see admitGuest).
			h.exitLate(sess)
			return
		}

		// Cancelling ctx starts the teardown: the guest leaving, the session
		// ending, or any actor below returning. It does not end the output
		// copy, which runs on outCtx until the command has gone.
		ctx, cancel := context.WithCancel(h.ctx)
		defer cancel()

		var auth *server.AuthRequest
		if guest, ok := sess.Context().Value(authenticatedGuestKey{}).(authenticatedGuest); ok {
			auth = guest.auth
		}
		ptmx, err = h.startForceCommand(ptyReq.Term, ptyReq.Window.Width, ptyReq.Window.Height, auth)
		if err != nil {
			h.logger.Error("error starting force command", "error", err)
			_ = sess.Exit(1)
			return
		}

		// Waited on outside the group, so the wait actor and terminate can
		// both watch it. Its end is recorded against the session's shutdown
		// the moment Wait returns, before exited closes: which branch the
		// wait actor's select then takes, where both can be ready, says
		// nothing about which came first.
		exited := make(chan struct{})
		var (
			waitErr       error
			afterShutdown bool
		)
		go func() {
			waitErr = ptmx.Wait()
			afterShutdown = h.order.commandEnded()
			close(exited)
		}()

		// The copy below and the wait beneath it are both run.Group actors, and
		// run.Group interrupts every actor as soon as any one of them returns. A
		// forced command like `echo hi` exits almost as soon as it writes, so the
		// wait routinely wins the race, and an interrupt that ended the copy cut
		// off what the command had already produced: the guest saw a clean exit
		// with no output at all, measured on Linux one run in ten. So the copy
		// ends on outCtx, which only the wait actor cancels, once the command
		// has gone and its output has drained -- which is also what lets the
		// output of a hangup handler through, a full-screen program putting
		// the guest's terminal back on its way out.
		outCtx, cancelOut := context.WithCancel(context.WithoutCancel(h.ctx))
		defer cancelOut()
		outputDrained := make(chan struct{})
		output := newActivityReader(uio.NewContextReader(outCtx, ptmx))
		{
			// reattach output
			modes := uio.NewModeTracker()
			g.Add(func() error {
				_, err := io.Copy(sess, io.TeeReader(output, modes))
				close(outputDrained)
				// Whatever the command left set, undone, behind its last
				// output and before the guest's exit status: a guest's ssh
				// client restores termios on the way out and nothing more, so
				// a command killed on the alternate screen, or one that exits
				// without cleaning up, would leave it there. Nothing at all
				// for a command that put everything back itself.
				//
				// Bounded as the session's last notice to a client is: the
				// command's last output may have filled the guest's window,
				// and a guest that has stopped taking output is not one to
				// hold the handler, and the exit status behind it, for.
				if restore := modes.Restore(); len(restore) > 0 {
					release := time.AfterFunc(guestFlushTimeout, func() {
						if conn := serverConn(sess); conn != nil {
							_ = conn.Close()
						} else {
							_ = sess.Close()
						}
					})
					_, _ = sess.Write(restore)
					release.Stop()
				}
				return ptyError(err)
			}, func(err error) {
				cancel()
			})
		}
		{
			g.Add(func() error {
				select {
				case <-exited:
				case <-ctx.Done():
					// The guest has left, or the session is ending, and the
					// command is still running: hang it up as a terminal going
					// away would, and escalate only if it stays. Killing it
					// outright left a full-screen program no chance to put the
					// guest's terminal back.
					terminateWith(ptmx, exited, h.forceCommandHangup, h.forceCommandGrace, h.logger, h.forceCommand[0])
				}
				// terminate's own waits are bounded, so the command may not be
				// confirmed gone; waitErr is only safe to read once it is.
				select {
				case <-exited:
					cmdCode, cmdExited = exitCode(waitErr)
					cmdAfterShutdown = afterShutdown
				default:
				}

				drainForceCommandOutput(h.logger, output, outputDrained, nil)
				cancelOut()
				// Fired, not waited on: see terminate for why a close of the
				// master can never be relied on to return.
				closeAsync(ptmx)

				select {
				case <-exited:
					return waitErr
				default:
					return ctx.Err()
				}
			}, func(err error) {
				cancel()
			})
		}
	} else {
		// output

		// The join begins here, and so does its budget for having the
		// screen reconstructed: time it spends waiting its turn,
		// behind another join's emulation at the pacer, is its own, so the
		// deadline is taken before anything it can wait on.
		deadline := time.Now().Add(uio.ReplayBudget)

		// The pty's geometry follows the terminals watching it, and this
		// one is counted before it attaches, not after: the
		// fan-out reconstructs a joiner's screen at the size the pty has
		// when the join takes its capture, so the pty has to have the size
		// this terminal gives it by then. Counted after, the reconstruction
		// would be at the old size, and the joiner's own resize would
		// reach it as live output.
		//
		// The window-change loop would get there too — charm seeds a
		// session's window channel with the pty request's own window
		// (session.go:373-375), so an arriving terminal's size reaches that
		// loop without anybody resizing anything. But that loop is an actor,
		// started further down, after the nudge below, which is what makes a
		// full-screen program repaint: a repaint at the size the session had
		// before this terminal arrived is one the arriving terminal has to
		// sit through. Both doors, because a guest arrives with a terminal
		// exactly as a local client does.
		var size termsize.Size
		stop := func() bool { return false }
		if isPty {
			size = termsize.Size{Cols: ptyReq.Window.Width, Rows: ptyReq.Window.Height}
			h.terminals.changed(ptmx, sessionID, size.Cols, size.Rows, alive)
			// The attach below takes the fan-out's lock, and a synchronous
			// primary parked in a write to a terminal that has stopped holds
			// that lock for as long as the terminal stays stopped. A client
			// that hangs up meanwhile is still waiting for it: the guard
			// below cannot run, and the departures further down are actors
			// that start only after the attach. Its size would go on
			// constraining the pty until the primary resumes, so its
			// departure takes it out from here. The attach stops this: an
			// attached client is taken out as it was before the reorder, by
			// the actors below.
			stop = context.AfterFunc(sess.Context(), func() {
				h.terminals.detached(ptmx, sessionID)
			})
		}
		// Once counted, a terminal that never attaches is taken out again,
		// whatever stopped it: the session ending, the client leaving,
		// another join at the pacer, a sink that couldn't take the replay,
		// a panic. Nothing else would: the departures below that take a
		// terminal out are actors, and a join that failed never starts
		// them. One attached by the raw ring, after a replay that failed or
		// panicked, is attached, and keeps its size.
		attached := false
		defer func() {
			stop()
			if isPty && !attached {
				h.terminals.detached(ptmx, sessionID)
			}
		}()

		if h.kind == kindHost {
			// A client on the host door gets a sink that can become the
			// primary: synchronous and unfiltered, so the command cannot
			// outrun the terminal and its live queries reach one. Until it is
			// elected it is the same bounded, filtered, asynchronous sink a
			// guest gets.

			// The connection close is the one thing that releases a write
			// parked in SSH; the elector learns of the departure from the
			// connection's end, like every other departure — see the actor
			// below.
			disconnect := func() {
				if conn := serverConn(sess); conn != nil {
					_ = conn.Close()
				}
			}
			sink := newHostSink(sess, disconnect, sessionID, h.logger)
			if err := attachGuestOutput(sess.Context(), deadline, h.writers, sink, size); err != nil {
				switch {
				case errors.Is(err, uio.ErrClosed):
					// The session is already tearing down. This client
					// arrived a moment too late, which is not its error (see
					// exitLate).
					h.exitLate(sess)
				case errors.Is(err, context.Canceled):
					// The client left while its screen was reconstructed:
					// there is nobody to tell.
					h.logger.Debug("client left before its output was attached", "session-id", sessionID)
				default:
					h.logger.Error("error attaching guest output", "session-id", sessionID, "error", err)
					_ = sess.Exit(1)
				}
				return
			}
			attached = true
			stop()
			sink.markAttached()

			defer func() {
				// Registered first, so it runs last: by the time this sink
				// leaves the fan-out the elector below has already chosen a
				// successor. In the window between the two there are briefly
				// two unfiltered primaries, so a live query in it is answered
				// twice — by a terminal that is going away and by the one
				// taking over — and that is the whole cost.
				h.writers.Remove(sink)
				_ = sink.Close()
			}()

			// Only a client with a terminal on both ends — a pty here, and a
			// declaration that it forwards that terminal's keystrokes — can
			// answer the queries a primary is sent. A viewer, pty or not, is a
			// filtered asynchronous sink for as long as it stays.
			//
			// Before the gate is signalled below, not after: the gate is what
			// starts the command, and a client elected only afterwards would
			// take the command's first output through the filtered async path
			// — swallowing a query in the first frame a full-screen program
			// draws.
			if isPty && isInteractive(sess) && h.hostClients != nil {
				c := &hostClient{id: sessionID, sink: sink}
				h.hostClients.add(c)
				defer h.hostClients.remove(c) // runs before the removal above

				// Election cleanup is tied to the connection's end, not to
				// this handler's return. The handler cannot return while its
				// input actor is parked in ptmx.Write — the command stopped
				// reading its pty, and a kernel write there is released by
				// the command reading; on macOS also by the command's exit,
				// which fails the write, but on Linux by nothing short of
				// the daemon's exit — so the deferred removal above can be
				// an arbitrarily long way off, and until it runs the elector
				// holds a gone client as primary: no election runs, every
				// later client stays a filtered secondary, and live queries
				// reach nobody.
				//
				// sess.Context() is what every departure shares. charm's
				// handleConn defers conn.Close(), which cancels it, whether
				// the transport ended because the client hung up or because
				// the daemon closed it; a server-side close (the watchdog's,
				// the overflow path's) cancels it synchronously in the same
				// call, so this actor wakes at the same instant either way.
				//
				// It must not end the group, though: run.Group's interrupt
				// would cancel the input actor's context too, and
				// contextReader.Read never starts a read on a context already
				// cancelled — so the bytes the client sent before hanging up,
				// still pending in the SSH channel, would be lost instead of
				// delivered the next time the command reads. The input actor
				// ends the group itself, from the EOF it reads once its write
				// returns, exactly as before this actor existed; this one
				// only frees the elector and then waits to be interrupted,
				// like the window-change loop below.
				//
				// What is left behind until then is the handler goroutine
				// itself, still parked in that pty write until the command
				// reads — on macOS also until the command exits, which fails
				// the write, but on Linux until nothing short of the
				// daemon's exit — and with it everything the handler defers:
				// writers.Remove, sink.Close and the client-left event all
				// wait for it, so a client that left with its input parked
				// is still listed by session info until then. That stays
				// bounded by the session's life because upterm host exits
				// with its session; an embedder that keeps the process
				// alive keeps this goroutine — and, on Linux, the thread
				// blocked in the write — running until it exits. It holds
				// nothing the fan-out or the elector needs.
				ctx, cancel := context.WithCancel(h.ctx)
				g.Add(func() error {
					select {
					case <-sess.Context().Done():
						h.hostClients.remove(c)

						// The pty actor's deferred interrupt says the same
						// thing -- that this client is gone -- but only runs
						// once the group ends, which this actor deliberately
						// does not do (see above), and which a write parked
						// in ptmx.Write may not do on its own for as long as
						// the session lives. Until then resizeWindow keeps
						// treating a client that is provably gone as one of
						// the terminals it takes the minimum across. Saying
						// it here as well, next to the elector removal, frees
						// the size calculation at the same moment; the
						// deferred one below still runs when the handler
						// eventually does return, and detached deletes by id,
						// so the second is a no-op.
						//
						// Only interactive clients reach here, since only
						// they register this actor; a viewer forwards no
						// input, so nothing parks its handler and its own
						// deferred detach arrives on time.
						h.terminals.detached(ptmx, sessionID)
					case <-ctx.Done():
					}
					<-ctx.Done()
					return ctx.Err()
				}, func(error) {
					cancel()
				})
			}

			guestOutput = sink
		} else {
			// Wrap SSH session with TerminalQueryFilter to filter out terminal query
			// sequences (like OSC 10/11 color queries, CSI 6n cursor position) before
			// they reach the client. This prevents client terminals from responding
			// to queries meant for the host terminal.
			filtered := uio.NewTerminalQueryFilter(sess)

			// And wrap that in a sink with its own goroutine and a bounded buffer,
			// so this guest cannot hold up the fan-out for the host or anyone else.
			// A guest that overflows is disconnected, and so is one that paces the
			// session and delivers nothing for the stall timeout: a terminal stream
			// is not resumable, so dropping bytes out of the middle would leave a
			// corrupted screen it could not detect, while a closed session it can
			// simply rejoin. See owenthereal/upterm#524.
			onDrop := guestDropHandler(sess.Close, h.logger, sessionID, pacingStallTimeout)

			sink := uio.NewAsyncWriter(filtered, uio.DefaultGuestBufferSize, onDrop)
			if err := h.attachGuest(sess.Context(), deadline, sink, size); err != nil {
				switch {
				case errors.Is(err, uio.ErrClosed):
					// The session is already tearing down. This guest arrived a
					// moment too late, which is not its error. Its shell was
					// accepted before the session's end stopped waiting for
					// guests, so it is sent a status (see exitLate) and the wait
					// every guest's status gets (see the top of HandleSession).
					// One that arrives after that is refused at its request
					// (see admitGuest).
					h.exitLate(sess)
				case errors.Is(err, context.Canceled):
					// The guest left while it waited its turn at the pacer, or
					// while its screen was reconstructed: there is nobody to
					// tell.
					h.logger.Debug("guest left before its output was attached", "session-id", sessionID)
				default:
					h.logger.Error("error attaching guest output", "session-id", sessionID, "error", err)
					_ = sess.Exit(1)
				}
				return
			}
			attached = true
			stop()

			defer func() {
				h.detachGuest(sink)
				_ = sink.Close()
			}()

			guestOutput = sink
		}

		// Attached, in the sense the gate is defined by: the subscription is
		// installed, so nothing the command writes from here on can be missed.
		// The geometry the command's start reads the moment the gate opens is
		// already recorded: counting this terminal, above, resized the shared
		// pty, which before the command starts records the minimum over the
		// terminals attached as the size to open with.
		if h.kind == kindHost && h.onHostClientAttached != nil {
			h.onHostClientAttached()
		}

		// Everything a repaint needs is now queued: the mode snapshot, the
		// ring, and this client's subscription. Ask the command to redraw
		// without changing geometry. Best-effort, and the only use this
		// branch makes of the handle, so a handler built without one — a
		// test's — is left alone.
		if ptmx != nil {
			if err := ptmx.Redraw(); err != nil {
				h.logger.Debug("redraw nudge skipped", "session-id", sessionID, "error", err)
			}
		}
	}

	if h.kind == kindGuest {
		if guest, ok := sess.Context().Value(authenticatedGuestKey{}).(authenticatedGuest); ok {
			id := clientEventID(sessionID)
			emitClientJoinEvent(h.eventEmmiter, id, guest.auth, guest.key)
			defer emitClientLeftEvent(h.eventEmmiter, id)
		}
	}

	if h.kind == kindHost && isPty {
		// A WINCH signal request is a repaint nudge from a client that has
		// just come back from a stop. Buffered and drained continuously,
		// because charm delivers a signal request with the session lock held
		// (charm.land/ssh session.go, "signal"): a channel nobody reads
		// parks its whole request loop, and with it Pty, Signals and Exit.
		// The bound is this buffer once ctx is done — our own client sends
		// one WINCH per resume, and the session is ending by then.
		//
		// Past that bound — any signal request arriving after this actor has
		// returned, which any group unwind causes, not only shutdown — there
		// is nothing left to drain sigs, and charm's next one parks its whole
		// request loop with the session lock held; HandleSession's own
		// closing sess.Exit takes that same lock and would never return
		// either. Host-door only, and the host door is a unix socket, so this
		// is the local user's own foot: no guest can reach it.
		sigs := make(chan gssh.Signal, 8)
		sess.Signals(sigs)
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			for {
				select {
				case sig := <-sigs:
					if sig != gssh.Signal("WINCH") || ptmx == nil {
						continue
					}
					if err := ptmx.Redraw(); err != nil {
						h.logger.Debug("redraw nudge skipped", "session-id", sessionID, "error", err)
					}
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, func(err error) { cancel() })
	}

	// Closed once the guest's channel has gone: charm closes winCh when the
	// channel's request loop ends, which is the channel closing or, with
	// every channel on it, the connection. Unlike the end of the guest's
	// input, that is the guest leaving. Only a pty session has a winCh, and
	// only the forced-command path below asks, which always has one.
	channelGone := make(chan struct{})

	{
		// pty
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			for {
				select {
				case win, ok := <-winCh:
					if !ok {
						close(channelGone)
						// charm closes this channel when the session's
						// request loop ends, and a closed channel yields the
						// zero Window immediately and forever. Without this
						// the loop spins, announcing 0x0 resizes until the
						// cancellation below happens to win the select —
						// and one landing after the detach below re-adds a
						// terminal nothing will ever remove, pinning the
						// minimum resizeWindow takes to nothing for the rest
						// of the session. Stop listening rather than
						// returning: this actor ending would end the whole
						// group, and the input actor's own EOF is what has
						// to do that.
						winCh = nil
						continue
					}
					// A resize this client sent before it went away is still
					// buffered in charm's one-deep channel, and applying it
					// now would re-add a client that has already been taken
					// out of the size calculation — with nothing left to take
					// it out again. Which is why the liveness check is passed
					// in rather than made here: changed makes it under the
					// same lock the removal takes, so the two cannot
					// interleave.
					h.terminals.changed(ptmx, sessionID, win.Width, win.Height, alive)
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, func(err error) {
			h.terminals.detached(ptmx, sessionID)
			cancel()
		})
	}

	// The end of a forced command's guest's input is not the guest leaving:
	// `ssh -tt door < /dev/null`, or a script feeding the door from a file,
	// sends EOF at once and stays to read the output. OpenSSH ignores a
	// client's EOF on a pty session, and the command runs to its end. Ending
	// the group on it instead hung the command up before it had finished, or
	// before it had started, and the guest got nothing. So the input actor
	// holds on after the EOF until the channel itself has gone, or the group
	// ends some other way -- the command exiting, the session ending.
	//
	// The shared command's guests are left as they were: their EOF still
	// detaches them, and nothing of theirs is hung up by it.
	untilGuestLeaves := func(ctx context.Context, err error) error {
		if err == nil && h.kind == kindGuest && len(h.forceCommand) > 0 {
			select {
			case <-channelGone:
			case <-ctx.Done():
			}
		}
		return err
	}

	// if a readonly session has been requested, don't connect stdin. --read-only
	// is about what guests may do; the host is not a guest of its own session.
	if h.kind == kindGuest && h.readonly {
		// write to client to notify them that they have connected to a read-only session
		_, _ = io.WriteString(guestOutput, "\r\n=== Attached to read-only session ===\r\n\r\n")

		// Still read the client's input, discarding it. Reading is what
		// tells us the client has gone (EOF), and it keeps the channel
		// window from filling up if the client types.
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			_, err := io.Copy(io.Discard, uio.NewContextReader(ctx, sess))
			return untilGuestLeaves(ctx, err)
		}, func(err error) {
			cancel()
		})
	} else {
		// input
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			_, err := io.Copy(ptmx, uio.NewContextReader(ctx, sess))
			return untilGuestLeaves(ctx, err)
		}, func(err error) {
			cancel()
		})
	}

	runErr := g.Run()

	// Classified once, from the cause host published, so that a handler that
	// ends between that and the cancellation which follows it still sees it.
	kind, sig, res, commandDone := h.endingCause()

	switch {
	case cmdExited && (!cmdAfterShutdown || !kind.overrides()):
		// A forced command ran and terminated under its own control, before
		// any shutdown. Its status is the session's, whichever actor
		// unblocked run.Group first.
		_ = sess.Exit(cmdCode)
	case kind.overrides():
		// The session was stopped, or its daemon signalled or cancelled, and
		// this client's command -- the shared one, or this guest's forced
		// command -- ended after that, or hasn't ended. What it returned while
		// it was torn down is not its own outcome: the teardown starts with a
		// hangup, and a command that handles it and exits 0 would tell every
		// client the session succeeded.
		h.exitWith(sess, kind.end(sig), 1)
	case h.kind == kindHost && kind == shutdownJoinTimeout:
		// The command was killed by a successful first-guest deadline. Its
		// resulting signal is not the attached foreground client's outcome.
		sendSessionEnd(serverConn(sess), kind.end(sig))
		// The group has drained command output before this final notice. Bound
		// both the write and exit request: a terminal that stopped reading must
		// not hold teardown open. Closing the transport releases blocked SSH I/O.
		noticeTimer := time.AfterFunc(guestFlushTimeout, func() {
			if conn := serverConn(sess); conn != nil {
				_ = conn.Close()
			} else {
				_ = sess.Close()
			}
		})
		defer noticeTimer.Stop()
		_, _ = io.WriteString(sess, "\r\nupterm: no guest joined within the join timeout; session ended\r\n")
		_ = sess.Exit(0)
	case commandDone && h.commandResult != nil:
		// The session ended because the command did. Its status is the
		// client's; a command that was signalled rather than exited has none
		// to give, and 1 is what this client has always been told then.
		if res.Exited {
			h.exitWith(sess, commandEnd(res), res.Code)
		} else {
			h.exitWith(sess, commandEnd(res), 1)
		}
	case runErr != nil:
		_ = sess.Exit(1)
	default:
		_ = sess.Exit(0)
	}
}

// channelClosed is what closes once sess's channel has been closed from the
// far side (see rawSession), or nil for a session the door did not build -- a
// test's -- which has only its window-change channel to say so.
func channelClosed(sess gssh.Session) <-chan struct{} {
	if raw, ok := sess.(*rawSession); ok {
		return raw.closed
	}
	return nil
}

// awaitChannelClosed waits, up to timeout, for a session's channel to be
// closed from the far side: for closed to close, or for winCh to, which charm
// does for a session with a pty as the channel's request loop ends. It drains
// winCh as it waits: charm delivers a window change from inside the request
// loop, so one nobody reads would park the loop, and the close with it. A nil
// winCh is one already seen closed, or a session with no pty; with closed nil
// too, there is nothing to wait for.
func awaitChannelClosed(closed <-chan struct{}, winCh <-chan gssh.Window, timeout time.Duration) {
	if closed == nil && winCh == nil {
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-closed:
			return
		case _, ok := <-winCh:
			if !ok {
				return
			}
		case <-timer.C:
			return
		}
	}
}

// attachGuestOutput attaches a client's sink to the fan-out, releasing it if
// the fan-out refuses.
//
// A client with a terminal of size joins by AppendSized: handed a
// reconstruction of the screen at the pty's size, if the fan-out has a
// replayer and the reconstruction is ready by deadline, and the raw ring
// otherwise, with ctx, the client's, ending the wait for it. A zero size, a
// viewer's, is Append and the raw ring.
//
// The release is the one path nothing else covers: the sink's goroutine is
// idle rather than blocked in I/O, so neither closing the session nor the
// fan-out's teardown can reach it — and a refused attach became reachable in
// normal operation the moment MultiWriter learned to quiesce.
//
// It takes a built sink rather than building one so the caller, and a test,
// keeps a handle on what it must release. The sink is whatever the door built:
// an AsyncWriter for a guest, a hostSink for a local client.
func attachGuestOutput(ctx context.Context, deadline time.Time, writers *uio.MultiWriter, sink interface {
	io.Writer
	Close() error
}, size termsize.Size) error {
	var err error
	if size == (termsize.Size{}) {
		err = writers.Append(sink)
	} else {
		err = writers.AppendSized(ctx, deadline, size, sink)
	}
	if err != nil {
		_ = sink.Close()
		return err
	}
	return nil
}

// attachGuest attaches a guest's sink to the fan-out through the pacer, which
// registers it first and takes the registration back if the fan-out refuses:
// see guestPacer.attach for why the order is what bounds a new guest's
// exposure. Without a pacer it attaches directly.
//
// The pacer can also refuse, before the fan-out is reached: a guest that
// leaves while it waits its turn there. attachGuestOutput's release never
// runs then, and the sink, built before the wait, is released here instead,
// or its goroutine would wait for a first write for the rest of the session.
func (h *sessionHandler) attachGuest(ctx context.Context, deadline time.Time, sink *uio.AsyncWriter, size termsize.Size) error {
	attach := func() error { return attachGuestOutput(ctx, deadline, h.writers, guestSink{sink}, size) }
	if h.pacer == nil {
		return attach()
	}
	if err := h.pacer.attach(ctx, sink, attach); err != nil {
		// Close is idempotent: a refusal by the fan-out has closed it already.
		_ = sink.Close()
		return err
	}
	return nil
}

// detachGuest takes a guest's sink out of the fan-out, then out of the
// pacer's order. The caller closes it.
func (h *sessionHandler) detachGuest(sink *uio.AsyncWriter) {
	h.writers.Remove(guestSink{sink})
	if h.pacer != nil {
		h.pacer.remove(sink)
	}
}

// guestSink is a guest's sink as the fan-out holds it: one that wants the
// session's reset when the session ends (uio.ResetTarget). A guest always has
// a terminal, and behind a plain ssh client nothing else puts it back. Two
// guestSinks of the same AsyncWriter are equal, which is what lets
// detachGuest remove the one attachGuest appended.
type guestSink struct{ *uio.AsyncWriter }

func (guestSink) WantsReset() bool { return true }

// guestDropHandler is what a guest's sink calls when it gives up on the guest:
// it closes the guest's session, then says why.
//
// Closing the channel is what makes the drop real: it fails the write the
// sink's goroutine is blocked in, and it fails the handler's stdin copy, so
// run.Group returns and the deferred client-left event fires. The close comes
// before the line, as it does in hostSink's callbacks: a logger blocked on a
// stopped terminal must not keep a dropped guest attached.
//
// stall is the bound to report for a stalled pacer, passed in rather than read
// from pacingStallTimeout when the drop happens: this runs on a goroutine of
// its own, where reading the package var would race a test that restores it.
func guestDropHandler(closeSession func() error, logger *slog.Logger, sessionID string, stall time.Duration) func(error) {
	return func(err error) {
		_ = closeSession()
		switch {
		case errors.Is(err, uio.ErrOverflow):
			logger.Warn("dropping guest: too far behind to keep up with output",
				"session-id", sessionID, "buffer-bytes", uio.DefaultGuestBufferSize)
		case errors.Is(err, uio.ErrStalled):
			logger.Warn("dropping guest: no output delivered within the stall timeout",
				"session-id", sessionID, "timeout", stall)
		default:
			logger.Debug("guest output sink failed", "session-id", sessionID, "error", err)
		}
	}
}

// isInteractive reports whether a host client declared that it forwards its
// terminal's keystrokes (attach.Client sends the env request when it has
// both a pty and a Stdin). Without the declaration a pty says only that
// the client displays on a terminal, and a terminal nobody reads answers a
// query into whatever shell owns it.
func isInteractive(sess gssh.Session) bool {
	return slices.Contains(sess.Environ(), upterm.AttachInteractiveEnvVar+"=1")
}

func emitClientJoinEvent(eventEmmiter *emitter.Emitter, sessionID string, auth *server.AuthRequest, pk ssh.PublicKey) {
	c := &api.Client{
		Id:                   sessionID,
		Version:              auth.ClientVersion,
		Addr:                 auth.RemoteAddr,
		PublicKeyFingerprint: utils.FingerprintSHA256(pk),
		Kind:                 api.Client_GUEST,
	}
	eventEmmiter.Emit(upterm.EventClientJoined, c)
}

// emitHostClientJoinEvent announces a client on the host door. There is no
// certificate to parse: the socket's permissions are the authentication and
// the key only names the client, so the fields come from the connection.
func emitHostClientJoinEvent(eventEmmiter *emitter.Emitter, sessionID, version string, pk ssh.PublicKey) {
	c := &api.Client{
		Id:                   sessionID,
		Version:              version,
		Addr:                 "local",
		PublicKeyFingerprint: utils.FingerprintSHA256(pk),
		Kind:                 api.Client_HOST,
	}
	eventEmmiter.Emit(upterm.EventClientJoined, c)
}

func emitClientLeftEvent(eventEmmiter *emitter.Emitter, sessionID string) {
	eventEmmiter.Emit(upterm.EventClientLeft, sessionID)
}

// startForceCommand runs the forced command for a guest on its own pty.
// CommandEnv wins over anything the host inherited, and the guest's own TERM
// wins over both. The command is the guest's SSH session, so it is described
// as sshd describes one, from auth -- the guest's certificate -- and its pty,
// and the host's own SSH session variables are not passed on. The session's
// shared command gets none of this: it is nobody's SSH session.
func (h *sessionHandler) startForceCommand(term string, width, height int, auth *server.AuthRequest) (PTY, error) {
	cmd := setupCommand(h.forceCommand[0], h.forceCommand[1:])
	cmd.Env = append(withoutSSHSessionVars(os.Environ()), h.commandEnv...)
	cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", term))
	cmd.Env = append(cmd.Env, guestConnectionEnv(auth, h.hideClientIP)...)
	// The guest's own geometry, taken from its pty request. A full-screen
	// program reads its window size before the first window-change request
	// arrives, so opening at the default drew that first frame at 80x24 on a
	// terminal that is nothing of the sort. A request that carries no usable
	// size falls back inside startSessionPty.
	return startSessionPty(cmd, termsize.Size{Cols: width, Rows: height})
}
