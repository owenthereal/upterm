package command

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/internal/tty"
	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
)

// localClientDrainTimeout bounds how long upterm host waits freely, after
// the daemon has ended, for its own terminal to finish: the client drains
// the channel into stdout and restores the terminal on its way out, and a
// stdout nobody drains must not hold the exit forever. Past it the client is
// cancelled — and still waited for, since cancellation is what makes it
// finish. A var so tests can shorten it.
var localClientDrainTimeout = 5 * time.Second

// attachLocalTerminal attaches the local terminal to a session's attach
// socket in the shape lt describes, holding raw mode and following resizes
// for exactly as long as the attachment lasts. keys is the daemon's host
// keys, kept beside socket since the two travel together.
func attachLocalTerminal(ctx context.Context, socket string, keys []ssh.PublicKey, lt localTerminal, escape byte, stdin, stdout *os.File, logger *slog.Logger) (attach.Result, error) {
	return attachLocalTerminalWith(ctx, socket, keys, lt, escape, stdin, stdout, tty.Owned, logger)
}

// attachLocalTerminalWith is attachLocalTerminal with the foreground-ownership
// predicate injected, for the reason withRawTerminal takes one: job control
// cannot be staged in-process, so a test that needs raw mode to be restored
// has no way to be the foreground of the pty pair it opened.
func attachLocalTerminalWith(ctx context.Context, socket string, keys []ssh.PublicKey, lt localTerminal, escape byte, stdin, stdout *os.File, owned func(*os.File) bool, logger *slog.Logger) (attach.Result, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	client := &attach.Client{
		Socket:   socket,
		HostKeys: keys,
		Stdin:    lt.stdin,
		Stdout:   stdout,
		Pty:      lt.pty,
		Escape:   escape,
		Logger:   logger,
	}
	if lt.sizeOf != nil {
		client.Resizes = watchResize(ctx, lt.sizeOf)
	}

	if !lt.rawMode {
		return client.Run(ctx)
	}
	raw := &rawTerminal{f: stdin, owned: owned}
	if err := raw.enter(); err != nil {
		return attach.Result{}, fmt.Errorf("unable to set terminal to raw mode: %w", err)
	}
	defer raw.restore()
	if suspendSupported {
		client.Suspend = func() termsize.Size { return suspendLocalTerminal(raw, stdout, stopSelf) }
	}
	return client.Run(ctx)
}

// suspendLocalTerminal is the ~^Z hook's body, lifted out of the closure that
// builds it so both halves of it can be pinned by a test: give the terminal
// back before stopping and take it again after, so a shell prompt printed
// while this process still held raw mode is not left without echo. The size
// is measured after the resume, because the terminal may have been resized
// while we were stopped.
//
// Re-entering is conditional on raw.owned, unlike the give-it-back half —
// deliberately asymmetric, and not pushed into rawTerminal.enter itself,
// whose contract elsewhere is to fail loudly when raw mode is unavailable
// rather than silently no-op. ^Z then bg leaves this process resuming in the
// background: the shell sent SIGCONT without handing the terminal back, and
// SIGTTOU is ignored (host.InstallSignalPolicy), so the re-entering
// tcsetattr would otherwise succeed against a terminal that is no longer
// this process's to touch — writing raw termios over the foreground shell's,
// exactly the hazard withRawTerminal's own comment describes for its
// deferred restore. Left cooked in that case; the EIO the input goroutine
// gets on its next read of a background terminal is what detaches it.
//
// stop is stopSelf in production; a test injects one that does not actually
// stop the process, so the terminal's state at the instant it runs — and
// after this returns — can both be observed without staging real job
// control.
func suspendLocalTerminal(raw *rawTerminal, stdout *os.File, stop func() error) termsize.Size {
	raw.restore()
	_ = stop()
	if raw.owned(raw.f) {
		_ = raw.enter()
	}
	size, _ := tty.Size(stdout)
	return size
}

// localDisconnectMessage is what upterm host prints when the daemon
// disconnected its own terminal. The session continues; the reason is in the
// log, and the way back is upterm attach.
func localDisconnectMessage(name, logPath string, res attach.Result) string {
	if res.Reason != attach.Disconnected {
		return ""
	}
	return fmt.Sprintf("upterm: the local terminal was disconnected from session %s (see %s); the session continues; reattach with 'upterm attach %s'", name, logPath, name)
}

// localAttachFailureMessage is what upterm host prints when the local
// terminal could not be attached to the session at all. The session
// continues regardless; the reason is in the log, and the way in is upterm
// attach.
func localAttachFailureMessage(name, logPath string) string {
	return fmt.Sprintf("upterm: could not attach the local terminal to session %s (see %s); the session continues; attach with 'upterm attach %s'", name, logPath, name)
}

// daemonFunc runs the daemon until the session ends, reporting the attach
// socket through onAttachSocket once it is bound and the hosted command's
// start through onCommandStarted. Host.Run in production.
//
// The second is what tells a failed attach whether there is a session to
// leave alone: with AwaitInitialClient the command is held behind a gate
// that the first client through the door opens, so until this fires there is
// nothing running.
type daemonFunc func(ctx context.Context, onAttachSocket func(string), onCommandStarted func()) error

// inProcessClientFunc attaches the local terminal and reports how the
// attachment ended. attachLocalTerminal in production.
//
// It takes no host keys because the process that runs this daemon holds its
// signers directly; the spawning parent's clientFunc, which learns them from
// the exchange, does.
type inProcessClientFunc func(ctx context.Context, socket string) (attach.Result, error)

// runLocalSession runs the daemon and attaches the local terminal to it
// before the command starts. Foreground and headless are one code path:
// what differs is the shape of the client, which classifyTerminal decides.
//
// The daemon's outcome is the session's; the client's result only decides
// what to print. And the daemon ending is not the end: the client is still
// draining the channel into stdout and restoring the terminal, and delivery
// into SSH is not delivery into stdout — an immediate-exit command's output
// would be cut off by process exit. So the client is waited for before this
// returns: freely for localClientDrainTimeout, and after cancelling it
// beyond that, but always until it has returned.
func runLocalSession(ctx context.Context, name string, stderr io.Writer, logger *slog.Logger, runDaemon daemonFunc, attachClient inProcessClientFunc) error {
	attachSocket := make(chan string, 1)
	runErr := make(chan error, 1)
	// Cancelled here, not only by the caller: a local terminal that never
	// attached leaves a daemon holding a command behind a gate nothing is
	// going to open. See the failed case below.
	daemonCtx, cancelDaemon := context.WithCancel(ctx)
	defer cancelDaemon()
	commandStarted := make(chan struct{})
	var startedOnce sync.Once
	go func() {
		runErr <- runDaemon(daemonCtx,
			func(s string) { attachSocket <- s },
			func() { startedOnce.Do(func() { close(commandStarted) }) })
	}()

	// No timeout of its own: the daemon either binds the socket or returns,
	// and a daemon doing neither is one that has stopped honouring ctx — which
	// is the caller's context, so cancelling it is what ends this wait.
	var socket string
	select {
	case socket = <-attachSocket:
	case err := <-runErr:
		// Failed before the socket existed; there is nothing to attach to.
		return err
	}

	// clientOutcome is what the client goroutine hands back: either how the
	// attachment ended (reported via localDisconnectMessage) or that it
	// could not be established at all (reported via
	// localAttachFailureMessage) — attachClient returned an error rather
	// than an attach.Result.
	type clientOutcome struct {
		res attach.Result
		err error // non-nil: never attached at all
	}

	clientCtx, cancelClient := context.WithCancel(ctx)
	defer cancelClient()
	clientDone := make(chan clientOutcome, 1)
	go func() {
		res, err := attachClient(clientCtx, socket)
		if err != nil {
			// Bounded: a handler blocked on a stopped terminal must not keep
			// this result from being delivered, or the wait below would
			// never end.
			logging.WarnWithin(logger, logging.LogBound, "could not attach the local terminal", "error", err)
			clientDone <- clientOutcome{err: err}
			return
		}
		clientDone <- clientOutcome{res: res}
	}()
	// attachErr is a local terminal that never attached while the command was
	// still behind the gate. Reported by returning it rather than by printing
	// it, so there is one diagnostic and it is the caller's to handle.
	var attachErr error
	report := func(out clientOutcome) {
		msg := localDisconnectMessage(name, utils.UptermLogFilePath(), out.res)
		if out.err != nil {
			select {
			case <-commandStarted:
				// Another terminal got through the door first and the command
				// is running: this is a session somebody is using, and losing
				// our own terminal is not a reason to end it.
				msg = localAttachFailureMessage(name, utils.UptermLogFilePath())
			default:
				// Nothing is attached and the command has not started. The
				// gate only opens for a client, so waiting out its timeout
				// buys ten seconds of nothing and then fails anyway — while
				// telling the operator the session continues, which it does
				// not.
				attachErr = fmt.Errorf("could not attach the local terminal to session %s: %w", name, out.err)
				cancelDaemon()
				return
			}
		}
		if msg != "" {
			// stderr may be the very terminal that stopped.
			logging.WriteWithin(stderr, logging.LogBound, "\r\n"+msg+"\r\n")
		}
	}

	var err error
	for daemonRunning := true; daemonRunning; {
		select {
		case err = <-runErr:
			daemonRunning = false
		case res := <-clientDone:
			report(res)
			clientDone = nil
		}
	}

	if clientDone != nil {
		select {
		case res := <-clientDone:
			report(res)
		case <-time.After(localClientDrainTimeout):
			// Cancel, and then still wait. The client restores the terminal
			// on its way out, so returning before it has returned is
			// exiting with the terminal in raw mode. The wait is bounded
			// because attach.Client.Run is bounded after cancellation: the
			// connection is closed, and its own drain has a bound.
			logging.WarnWithin(logger, logging.LogBound, "the local terminal did not finish draining; cancelling it", "timeout", localClientDrainTimeout)
			cancelClient()
			report(<-clientDone)
		}
	}
	if attachErr != nil {
		// Preferred over the daemon's own error, whichever way round the two
		// arrived: a daemon cancelled by the line above says only that it was
		// cancelled, and one that gave up on its own says only that nobody
		// attached. Neither says why nobody could.
		return attachErr
	}
	return err
}

// shouldNotifyClient reports whether a client arriving or leaving is worth a
// desktop notification. The host's own terminal is not: the operator is
// looking at it. Both sites ask the same question, because notifying only one
// of them would announce a departure with no arrival — which is what every
// `upterm attach` detach would look like.
func shouldNotifyClient(c *api.Client) bool { return c.Kind != api.Client_HOST }
