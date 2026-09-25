package command

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/internal/tty"
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
	if suspendSupported && suspendAvailable() {
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

// shouldNotifyClient reports whether a client arriving or leaving is worth a
// desktop notification. The host's own terminal is not: the operator is
// looking at it. Both sites ask the same question, because notifying only one
// of them would announce a departure with no arrival — which is what every
// `upterm attach` detach would look like.
func shouldNotifyClient(c *api.Client) bool { return c.Kind != api.Client_HOST }
