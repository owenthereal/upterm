package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/logging"
	"golang.org/x/crypto/ssh"
)

type spawnFunc func(spawnOptions) (net.Conn, *os.Process, error)
type clientFunc func(ctx context.Context, socket string, keys []ssh.PublicKey) (attach.Result, error)
type displayFunc func(ctx context.Context, sess *api.GetSessionResponse, name string) error

// startedWaitTimeout bounds how long a foreground parent whose terminal has
// already left waits to be told whether the command started. The daemon's
// own gate is DefaultInitialClientTimeout (10 s), after which it reports
// abandonment itself; this is that plus a margin. A var for tests.
var startedWaitTimeout = 15 * time.Second

// spawnedSession is upterm host as the process that starts a session: it
// spawns the daemon, runs the exchange, and then either attaches its
// terminal (foreground) or prints and leaves (--detach).
type spawnedSession struct {
	name    string
	detach  bool
	jsonOut bool
	logPath string

	stdin      io.Reader
	stdout     io.Writer
	stderr     io.Writer
	readSecret func(prompt string) ([]byte, error)

	spawn        spawnFunc
	display      displayFunc // shows the session and reports the operator's decision
	attachClient clientFunc  // nil with --detach
	logger       *slog.Logger
}

type clientOutcome struct {
	res attach.Result
	err error // non-nil: never attached
}

func (s *spawnedSession) run(ctx context.Context) error {
	conn, _, err := s.spawn(spawnOptions{name: s.name, logPath: s.logPath})
	if err != nil {
		return fmt.Errorf("could not start the session daemon: %w", err)
	}
	parent := bootstrap.NewParent(conn, s.stdin, s.stderr, s.readSecret)
	defer func() { _ = parent.Close() }()

	// Read once, here: the value is used from the client's goroutine and
	// reported from this one, and a test that shortens the package var must
	// not be racing a goroutine still finishing the run before it.
	verdictWait := startedWaitTimeout

	var (
		claimed    *api.Claimed
		created    *api.GetSessionResponse
		displayErr error
		clientDone chan clientOutcome
		closedByUs atomic.Bool
	)
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	// Atomic because the client's goroutine arms it and this one stops it:
	// the two are concurrent by construction, since the whole point of the
	// timer is to bound a wait that outlives the client.
	var verdictTimer atomic.Pointer[time.Timer]
	defer func() {
		if t := verdictTimer.Load(); t != nil {
			t.Stop()
		}
	}()

	// The attach client's cancel, held where the tail can reach it:
	// cancelling is how a client that will not come back on its own is made
	// to, and the handler that created it returned long before.
	var clientCancel atomic.Pointer[context.CancelFunc]
	cancelClientNow := func() {
		if c := clientCancel.Load(); c != nil {
			(*c)()
		}
	}
	// Every way out from listening onwards waits for the client, because the
	// client is what holds the terminal: attachLocalTerminal restores raw
	// mode only when its own callback returns, so returning here while the
	// client is still inside it exits with the operator's terminal raw. A
	// startup that fails after the gate opened is the ordinary way in —
	// `upterm host -- /no/such/binary` attaches, the gate opens, the exec
	// fails, and the daemon reports failed microseconds later.
	//
	// Deferred rather than written out before each return, so no path out
	// can skip it. A path that takes the outcome for itself nils the channel
	// afterwards, exactly as runLocalSession does.
	defer func() {
		if clientDone == nil {
			return
		}
		_ = s.drainClient(clientDone, cancelClientNow)
	}()

	handlers := bootstrap.Handlers{
		Claimed: func(c *api.Claimed) { claimed = c },
		SessionCreated: func(sess *api.GetSessionResponse) api.Accept_Decision {
			created = sess
			displayErr = s.display(ctx, sess, s.name)
			switch {
			case displayErr == nil:
				return api.Accept_ACCEPTED
			case errors.As(displayErr, new(UserDiscardedError)):
				return api.Accept_DECLINED
			default:
				return api.Accept_INTERRUPTED
			}
		},
		Listening: func(l *api.Listening) {
			if s.detach || s.attachClient == nil {
				return
			}
			keys, err := parseHostKeys(l.HostKeys)
			// done, not the clientDone variable, is what the goroutine
			// below writes to: the tail nils clientDone once it has taken
			// the outcome, and a goroutine reading it would be racing that.
			done := make(chan clientOutcome, 1)
			clientDone = done
			if err != nil {
				done <- clientOutcome{err: err}
				closedByUs.Store(true)
				_ = parent.Close()
				return
			}
			// From here a signal is a detach, exactly as it is for upterm
			// attach; before here the default disposition ends this process,
			// which closes the channel, which is abandonment.
			clientCtx, cancelClient := notifyDetachSignals(ctx)
			clientCancel.Store(&cancelClient)
			go func() {
				defer cancelClient()
				res, err := s.attachClient(clientCtx, l.AttachSocket, keys)
				if err == nil {
					// Attached and gone. If the command has not started yet
					// the daemon still owes a verdict; wait for it, bounded.
					//
					// Armed before the outcome is delivered, so the deferred
					// Stop — which runs after the drain that receives it —
					// cannot miss a timer armed a moment too late.
					verdictTimer.Store(time.AfterFunc(verdictWait, cancelRun))
				}
				done <- clientOutcome{res: res, err: err}
				if err != nil {
					// Never attached: the gate has nobody, and EOF tells the
					// daemon now rather than after its timeout.
					logging.WarnWithin(s.logger, logging.LogBound, "could not attach the local terminal", "error", err)
					closedByUs.Store(true)
					_ = parent.Close()
				}
			}()
		},
	}

	outcome, runErr := parent.Run(runCtx, handlers)

	switch {
	case runErr != nil && closedByUs.Load():
		out := s.drainClient(clientDone, cancelClientNow)
		clientDone = nil
		return fmt.Errorf("could not attach the local terminal to session %s: %w", s.name, out.err)
	case errors.Is(runErr, context.Canceled) && ctx.Err() == nil:
		return fmt.Errorf("session %s: the daemon did not report whether the command started within %s; see %s", s.name, verdictWait, s.logPath)
	case runErr != nil:
		return fmt.Errorf("session %s: %w (see %s)", s.name, runErr, s.logPath)
	case outcome.Failed != nil:
		f := outcome.Failed
		switch {
		case f.NameInUse:
			return fmt.Errorf("%w: %s", sessiondir.ErrNameInUse, s.name)
		case f.Abandoned && displayErr != nil:
			// The operator's own answer; shareRunE knows what to do with it.
			return displayErr
		case f.Abandoned:
			return fmt.Errorf("session %s was not started: %s", s.name, f.Error)
		default:
			return fmt.Errorf("session %s could not start: %s (see %s)", s.name, f.Error, s.logPath)
		}
	}

	if s.detach {
		return s.printStarted(claimed, created, outcome.Started)
	}
	if clientDone == nil {
		// Started without ever being told listening: not a daemon this
		// process built. Nothing to wait for.
		return nil
	}
	// Unbounded, and deliberately not the deferred drain: the command has
	// started, so this wait is the session itself running, for as long as the
	// operator keeps it. The bounded drain is for the ways out where the
	// session is already over and the client is only holding the terminal.
	out := <-clientDone
	clientDone = nil
	if out.err != nil {
		return fmt.Errorf("could not attach the local terminal to session %s: %w", s.name, out.err)
	}
	switch out.res.Reason {
	case attach.Detached:
		logging.WriteWithin(s.stderr, logging.LogBound, "\r\n"+detachedMessage(s.name)+"\r\n")
		return nil
	case attach.Exited:
		if out.res.Status == 0 {
			return nil
		}
		// The same account `upterm attach` gives, for the same reason: the
		// line is the whole story and the status below is for a script, so
		// the error carries no message of its own and host.go silences
		// cobra's.
		logging.WriteWithin(s.stderr, logging.LogBound, "\r\n"+commandExitedMessage(s.name, out.res.Status)+"\r\n")
		return ExitCodeError{Code: out.res.Status}
	case attach.Disconnected:
		logging.WriteWithin(s.stderr, logging.LogBound, "\r\n"+localDisconnectMessage(s.name, s.logPath, out.res)+"\r\n")
		return ExitCodeError{Code: exitDisconnected}
	}
	return nil
}

// drainClient waits for the attach client to finish and reports how it did.
//
// Freely for localClientDrainTimeout, because the client is draining the
// session's channel into stdout and restoring the terminal on its way out,
// and a stdout nobody reads must not hold the exit forever; and after
// cancelling it beyond that, but always until it has returned, since
// cancellation is what makes it finish and returning before it has is
// exiting with the terminal in raw mode. The same contract runLocalSession
// keeps for the in-process foreground, for the same reason.
func (s *spawnedSession) drainClient(done <-chan clientOutcome, cancel context.CancelFunc) clientOutcome {
	select {
	case out := <-done:
		return out
	case <-time.After(localClientDrainTimeout):
	}
	logging.WarnWithin(s.logger, logging.LogBound, "the local terminal did not finish draining; cancelling it", "timeout", localClientDrainTimeout)
	cancel()
	return <-done
}

// detachedMessage is what upterm host prints when its own terminal leaves.
func detachedMessage(name string) string {
	return fmt.Sprintf("upterm: detached from session %s; the session continues; reattach with 'upterm attach %s' or stop it with 'upterm session stop %s'", name, name, name)
}

func parseHostKeys(lines []string) ([]ssh.PublicKey, error) {
	keys := make([]ssh.PublicKey, 0, len(lines))
	for _, l := range lines {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err != nil {
			return nil, fmt.Errorf("the daemon reported a host key that cannot be read: %w", err)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("the daemon reported no host key to pin")
	}
	return keys, nil
}

// printStarted is --detach's output: the JSON session info a script parses,
// or one line saying how to reach the session.
func (s *spawnedSession) printStarted(claimed *api.Claimed, sess *api.GetSessionResponse, st *api.Started) error {
	if claimed == nil {
		return fmt.Errorf("session %s started but the daemon never reported its claim (see %s)", s.name, s.logPath)
	}
	if !s.jsonOut {
		_, err := fmt.Fprintf(s.stdout, "Session %s is running in the background. Attach with 'upterm attach %s'; stop it with 'upterm session stop %s'.\n", s.name, s.name, s.name)
		return err
	}
	info := sessionInfo{
		Name:         claimed.Name,
		LaunchID:     claimed.LaunchId,
		Status:       sessiondir.StatusReady,
		SessionID:    st.SessionId,
		AdminSocket:  claimed.AdminSocket,
		AttachSocket: claimed.AttachSocket,
		LogPath:      claimed.LogPath,
		Pid:          int(claimed.Pid),
		// What the record says at this moment, and what `session info -o
		// json` would answer if asked a moment later: the claim writes
		// ReasonUnknown and nothing has replaced it, since the session has
		// only just started. Set explicitly so the two shapes match —
		// reason is a key `session info` always publishes.
		Reason: sessiondir.ReasonUnknown,
	}
	if sess != nil {
		if detail, err := buildSessionDetail(sess); err == nil {
			info.Command = detail.Command
			info.ForceCommand = detail.ForceCommand
			info.SSHCommand = detail.SSHCommand
		}
	}
	enc := json.NewEncoder(s.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(info)
}
