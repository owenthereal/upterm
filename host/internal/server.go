package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"

	gssh "charm.land/ssh"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sftp"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	Command                 []string
	CommandEnv              []string
	ForceCommand            []string
	Signers                 []ssh.Signer
	AuthorizedKeys          []ssh.PublicKey
	EventEmitter            *emitter.Emitter
	KeepAliveDuration       time.Duration
	Stdin                   *os.File
	Stdout                  *os.File
	Logger                  *slog.Logger
	ReadOnly                bool
	AllowLocalTCPForwarding bool
	// ForceForwardingInputForTesting forces stdin forwarding even when stdin is not a TTY.
	// This is used in tests where stdin is a pipe but we still want to forward test data.
	ForceForwardingInputForTesting bool

	// SFTP configuration
	SFTPDisabled          bool                   // Disable SFTP subsystem entirely
	SFTPPermissionChecker sftp.PermissionChecker // Optional: prompts user for SFTP permissions (nil = auto-allow)
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

func (s *Server) ServeWithContext(ctx context.Context, l net.Listener) error {
	writers := uio.NewMultiWriter(5)

	cmdCtx, cmdCancel := context.WithCancel(ctx)
	defer cmdCancel()
	cmd := newCommand(
		s.Command[0],
		s.Command[1:],
		s.CommandEnv,
		s.Stdin,
		s.Stdout,
		s.EventEmitter,
		writers,
		s.ForceForwardingInputForTesting,
	)
	ptmx, err := cmd.Start(cmdCtx)
	if err != nil {
		return fmt.Errorf("error starting command: %w", err)
	}

	var g run.Group
	cmdDone := make(chan struct{})
	{
		ctx, cancel := context.WithCancel(ctx)
		teh := terminalEventHandler{
			eventEmitter: s.EventEmitter,
			logger:       s.Logger,
		}
		g.Add(func() error {
			return teh.Handle(ctx)
		}, func(err error) {
			cancel()
		})
	}
	{
		g.Add(func() error {
			defer close(cmdDone)
			return cmd.Run()
		}, func(err error) {
			cmdCancel()
		})
	}
	{
		sessCtx, cancel := context.WithCancel(sessionContext(ctx))
		sh := sessionHandler{
			forceCommand:          s.ForceCommand,
			ptmx:                  ptmx,
			eventEmmiter:          s.EventEmitter,
			writers:               writers,
			keepAliveDuration:     s.KeepAliveDuration,
			ctx:                   sessCtx,
			logger:                s.Logger,
			readonly:              s.ReadOnly,
			sftpPermissionChecker: s.SFTPPermissionChecker,
		}
		ph := publicKeyHandler{
			AuthorizedKeys: s.AuthorizedKeys,
			EventEmmiter:   s.EventEmitter,
			Logger:         s.Logger,
		}

		var ss []gssh.Signer
		for _, signer := range s.Signers {
			ss = append(ss, signer)
		}

		// Set up subsystem handlers (SFTP)
		var subsystemHandlers map[string]gssh.SubsystemHandler
		if !s.SFTPDisabled {
			subsystemHandlers = map[string]gssh.SubsystemHandler{
				"sftp": sh.HandleSFTP,
			}
		}

		server := gssh.Server{
			HostSigners:      ss,
			Handler:          sh.HandleSession,
			Version:          upterm.HostSSHServerVersion,
			PublicKeyHandler: ph.HandlePublicKey,
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
				"session":      gssh.DefaultSessionHandler,
				"direct-tcpip": gssh.DirectTCPIPHandler,
			},
			SubsystemHandlers: subsystemHandlers,
			ConnectionFailedCallback: func(conn net.Conn, err error) {
				s.Logger.Error("connection failed", "error", err)
			},
		}
		g.Add(func() error {
			return server.Serve(l)
		}, func(err error) {
			// Let the fan-out finish delivering before the sessions are
			// released. This is the last interrupt in the group, so waiting
			// here holds up nothing else, and a command-led exit has already
			// closed cmdDone by the time it runs.
			releaseSessions(cmdDone, outputDrainTimeout+guestFlushTimeout, cancel)

			// shut down ssh server. sessCtx, not ctx: Shutdown waits on its
			// connection WaitGroup until the context it is given is done, and
			// on a command-led exit ctx is still live — a guest that keeps its
			// SSH connection open after its channel closed would hang the host
			// forever, and the deferred ReverseTunnel.Close would never run.
			_ = server.Shutdown(sessCtx)
		})
	}

	return g.Run()
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

type publicKeyHandler struct {
	AuthorizedKeys []ssh.PublicKey
	EventEmmiter   *emitter.Emitter
	Logger         *slog.Logger
}

func (h *publicKeyHandler) HandlePublicKey(ctx gssh.Context, key gssh.PublicKey) bool {
	checker := server.UserCertChecker{}
	auth, pk, err := checker.Authenticate(ctx.User(), key)
	if err != nil {
		h.Logger.Error("error parsing auth request from cert", "error", err)
		return false
	}

	// TODO: sshproxy already rejects unauthorized keys
	// Does host still need to check them?
	if len(h.AuthorizedKeys) == 0 {
		emitClientJoinEvent(h.EventEmmiter, ctx.SessionID(), auth, pk)
		return true
	}

	for _, k := range h.AuthorizedKeys {
		if utils.KeysEqual(k, pk) {
			emitClientJoinEvent(h.EventEmmiter, ctx.SessionID(), auth, pk)
			return true
		}
	}

	h.Logger.Info("unauthorized public key")
	return false
}

type sessionHandler struct {
	forceCommand      []string
	ptmx              PTY
	eventEmmiter      *emitter.Emitter
	writers           *uio.MultiWriter
	keepAliveDuration time.Duration
	ctx               context.Context
	logger            *slog.Logger
	readonly          bool

	// SFTP configuration
	sftpPermissionChecker sftp.PermissionChecker // Optional: prompts user for SFTP permissions
}

func (h *sessionHandler) HandleSession(sess gssh.Session) {
	sessionID := sess.Context().Value(gssh.ContextKeySessionID).(string)
	defer emitClientLeftEvent(h.eventEmmiter, sessionID)

	ptyReq, winCh, isPty := sess.Pty()
	if !isPty {
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
	// reading these afterwards is ordered.
	var (
		cmdCode   int
		cmdExited bool
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

	if len(h.forceCommand) > 0 {
		ctx, cancel := context.WithCancel(h.ctx)
		defer cancel()

		ptmx, err = startAttachCmd(ctx, h.forceCommand, ptyReq.Term)
		if err != nil {
			h.logger.Error("error starting force command", "error", err)
			_ = sess.Exit(1)
			return
		}

		// The copy below and the wait beneath it are both run.Group actors, and
		// run.Group interrupts every actor as soon as any one of them returns. A
		// forced command like `echo hi` exits almost as soon as it writes, so the
		// wait routinely wins the race and its interrupt closes the pty before the
		// copy has drained what the command already produced. The guest then sees
		// a clean exit with no output at all. Measured on Linux, that lost the
		// output roughly one run in ten.
		outputDrained := make(chan struct{})
		output := newActivityReader(uio.NewContextReader(ctx, ptmx))
		{
			// reattach output
			g.Add(func() error {
				defer close(outputDrained)
				_, err := io.Copy(sess, output)
				return ptyError(err)
			}, func(err error) {
				cancel()
				_ = ptmx.Close()
			})
		}
		{
			g.Add(func() error {
				err := ptmx.Wait()
				cmdCode, cmdExited = exitCode(err)

				// Hold this actor open until the output is drained, so the
				// interrupts above cannot close the pty out from under the copy.
				drainForceCommandOutput(h.logger, output, outputDrained, ctx.Done())

				return err
			}, func(err error) {
				cancel()
				_ = ptmx.Close()
			})
		}
	} else {
		// output
		// Wrap SSH session with TerminalQueryFilter to filter out terminal query
		// sequences (like OSC 10/11 color queries, CSI 6n cursor position) before
		// they reach the client. This prevents client terminals from responding
		// to queries meant for the host terminal.
		filtered := uio.NewTerminalQueryFilter(sess)

		// And wrap that in a sink with its own goroutine and a bounded buffer,
		// so this guest cannot hold up the fan-out for the host or anyone else.
		// A guest that overflows is disconnected: a terminal stream is not
		// resumable, so dropping bytes out of the middle would leave a corrupted
		// screen it could not detect, while a closed session it can simply
		// rejoin. See owenthereal/upterm#524.
		onDrop := func(err error) {
			if errors.Is(err, uio.ErrOverflow) {
				h.logger.Warn("dropping guest: too far behind to keep up with output",
					"session-id", sessionID, "buffer-bytes", uio.DefaultGuestBufferSize)
			} else {
				h.logger.Debug("guest output sink failed", "session-id", sessionID, "error", err)
			}
			// Closing the channel is what makes the drop real: it fails the
			// blocked write, and it fails the stdin copy below, so run.Group
			// returns and the deferred client-left event fires.
			_ = sess.Close()
		}

		sink := uio.NewAsyncWriter(filtered, uio.DefaultGuestBufferSize, onDrop)
		if err := attachGuestOutput(h.writers, sink); err != nil {
			if errors.Is(err, uio.ErrClosed) {
				// The session is already tearing down. This guest arrived a
				// moment too late, which is not its error.
				_ = sess.Exit(0)
			} else {
				h.logger.Error("error attaching guest output", "session-id", sessionID, "error", err)
				_ = sess.Exit(1)
			}
			return
		}

		defer func() {
			h.writers.Remove(sink)
			_ = sink.Close()
		}()
	}

	{
		// pty
		ctx, cancel := context.WithCancel(h.ctx)
		tee := terminalEventEmitter{h.eventEmmiter}
		g.Add(func() error {
			for {
				select {
				case win := <-winCh:
					tee.TerminalWindowChanged(sessionID, ptmx, win.Width, win.Height)
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, func(err error) {
			tee.TerminalDetached(sessionID, ptmx)
			cancel()
		})
	}

	// if a readonly session has been requested, don't connect stdin
	if h.readonly {
		// write to client to notify them that they have connected to a read-only session
		_, _ = io.WriteString(sess, "\r\n=== Attached to read-only session ===\r\n\r\n")

		// Still read the client's input, discarding it. Reading is what
		// tells us the client has gone (EOF), and it keeps the channel
		// window from filling up if the client types.
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			_, err := io.Copy(io.Discard, uio.NewContextReader(ctx, sess))
			return err
		}, func(err error) {
			cancel()
		})
	} else {
		// input
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			_, err := io.Copy(ptmx, uio.NewContextReader(ctx, sess))
			return err
		}, func(err error) {
			cancel()
		})
	}

	runErr := g.Run()

	switch {
	case cmdExited:
		// A forced command ran and terminated under its own control. Its
		// status is the session's, whichever actor unblocked run.Group first.
		_ = sess.Exit(cmdCode)
	case runErr != nil:
		_ = sess.Exit(1)
	default:
		_ = sess.Exit(0)
	}
}

// attachGuestOutput attaches a guest's sink to the fan-out, releasing it if the
// fan-out refuses.
//
// That release is the one path nothing else covers: the sink's goroutine is
// idle rather than blocked in I/O, so neither closing the session nor the
// fan-out's teardown can reach it — and a refused attach became reachable in
// normal operation the moment MultiWriter learned to quiesce.
//
// It takes a built sink rather than building one so the caller, and a test,
// keeps a handle on what it must release.
func attachGuestOutput(writers *uio.MultiWriter, sink *uio.AsyncWriter) error {
	if err := writers.Append(sink); err != nil {
		_ = sink.Close()
		return err
	}
	return nil
}

func emitClientJoinEvent(eventEmmiter *emitter.Emitter, sessionID string, auth *server.AuthRequest, pk ssh.PublicKey) {
	c := &api.Client{
		Id:                   sessionID,
		Version:              auth.ClientVersion,
		Addr:                 auth.RemoteAddr,
		PublicKeyFingerprint: utils.FingerprintSHA256(pk),
	}
	eventEmmiter.Emit(upterm.EventClientJoined, c)
}

func emitClientLeftEvent(eventEmmiter *emitter.Emitter, sessionID string) {
	eventEmmiter.Emit(upterm.EventClientLeft, sessionID)
}

func startAttachCmd(ctx context.Context, c []string, term string) (PTY, error) {
	cmd := setupCommand(ctx, c[0], c[1:])
	cmd.Env = append(os.Environ(), fmt.Sprintf("TERM=%s", term))
	// Pass nil for stdin since this is a remote attach - size will come from SSH client
	pty, err := startPty(cmd, nil)

	return pty, err
}
