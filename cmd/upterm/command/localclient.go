package command

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/tty"
	"github.com/owenthereal/upterm/utils"
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
// for exactly as long as the attachment lasts.
func attachLocalTerminal(ctx context.Context, socket string, lt localTerminal, escape byte, stdin, stdout *os.File, logger *slog.Logger) (attach.Result, error) {
	return attachLocalTerminalWith(ctx, socket, lt, escape, stdin, stdout, tty.Owned, logger)
}

// attachLocalTerminalWith is attachLocalTerminal with the foreground-ownership
// predicate injected, for the reason withRawTerminal takes one: job control
// cannot be staged in-process, so a test that needs raw mode to be restored
// has no way to be the foreground of the pty pair it opened.
func attachLocalTerminalWith(ctx context.Context, socket string, lt localTerminal, escape byte, stdin, stdout *os.File, owned func(*os.File) bool, logger *slog.Logger) (attach.Result, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	client := &attach.Client{
		Socket: socket,
		Stdin:  lt.stdin,
		Stdout: stdout,
		Pty:    lt.pty,
		Escape: escape,
		Logger: logger,
	}
	if lt.sizeOf != nil {
		client.Resizes = watchResize(ctx, lt.sizeOf)
	}

	if !lt.rawMode {
		return client.Run(ctx)
	}
	var (
		res attach.Result
		err error
	)
	if rawErr := withRawTerminal(stdin, owned, func() error {
		res, err = client.Run(ctx)
		return nil
	}); rawErr != nil {
		return attach.Result{}, fmt.Errorf("unable to set terminal to raw mode: %w", rawErr)
	}
	return res, err
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
// socket through onAttachSocket once it is bound. Host.Run in production.
type daemonFunc func(ctx context.Context, onAttachSocket func(string)) error

// clientFunc attaches the local terminal and reports how the attachment
// ended. attachLocalTerminal in production.
type clientFunc func(ctx context.Context, socket string) (attach.Result, error)

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
func runLocalSession(ctx context.Context, name string, stderr io.Writer, logger *slog.Logger, runDaemon daemonFunc, attachClient clientFunc) error {
	attachSocket := make(chan string, 1)
	runErr := make(chan error, 1)
	go func() {
		runErr <- runDaemon(ctx, func(s string) { attachSocket <- s })
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
		res    attach.Result
		failed bool
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
			clientDone <- clientOutcome{failed: true}
			return
		}
		clientDone <- clientOutcome{res: res}
	}()
	report := func(out clientOutcome) {
		msg := localDisconnectMessage(name, utils.UptermLogFilePath(), out.res)
		if out.failed {
			msg = localAttachFailureMessage(name, utils.UptermLogFilePath())
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
	return err
}

// shouldNotifyClient reports whether a client arriving or leaving is worth a
// desktop notification. The host's own terminal is not: the operator is
// looking at it. Both sites ask the same question, because notifying only one
// of them would announce a departure with no arrival — which is what every
// `upterm attach` detach would look like.
func shouldNotifyClient(c *api.Client) bool { return c.Kind != api.Client_HOST }
