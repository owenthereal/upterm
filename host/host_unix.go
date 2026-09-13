//go:build !windows

package host

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/oklog/run"
)

// setupSignalHandler configures OS signal handling for Unix systems.
// Listens for both SIGINT (Ctrl+C) and SIGTERM for graceful shutdown.
// On Unix, PTY isolation ensures that Ctrl+C sent to upterm's terminal
// doesn't affect child processes in the PTY.
//
// It sets shutdownRequested when the teardown is ours to own, which is why it
// replaces run.SignalHandler: the flag has to be set before the group unwinds,
// and a handler that only cancels cannot do that.
func setupSignalHandler(g *run.Group, ctx context.Context, shutdownRequested *atomic.Bool) {
	{
		// Only the *parent* context counts here — the one the caller passed to
		// Run. Actor contexts are internal cleanup and must never reach this
		// flag.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

		// The third case is not optional. run.SignalHandler cancels its own
		// context on interrupt; this replacement has to do the same job by
		// hand, and an earlier draft's interrupt called only signal.Stop —
		// which stops delivery but unblocks nothing. On a normal command exit
		// this actor stayed parked in the select and run.Group, which waits for
		// every actor, hung forever.
		//
		// Returning through this branch must not set shutdownRequested: it
		// fires on every ordinary teardown, which is precisely what the flag
		// exists to distinguish from.
		stop := make(chan struct{})
		g.Add(func() error {
			select {
			case sig := <-sigCh:
				shutdownRequested.Store(true)
				return fmt.Errorf("received signal %s", sig)
			case <-ctx.Done():
				shutdownRequested.Store(true)
				return ctx.Err()
			case <-stop:
				return nil
			}
		}, func(err error) {
			signal.Stop(sigCh)
			close(stop)
		})
	}

	// SIG_IGN, not a handler. A backgrounded process reading its controlling
	// terminal is sent SIGTTIN, and the default disposition stops it — so
	// `upterm host … &` would suspend. With a handler installed the read
	// returns EINTR and Go retries, which spins. Ignored, it returns EIO, which
	// the stdin actor above now survives. SIGTTOU is the same story for writes.
	//
	// Ignoring SIGTTOU also means a background tcsetattr would succeed, which
	// is why command.Run checks foreground ownership before touching terminal
	// modes at all.
	signal.Ignore(syscall.SIGTTIN, syscall.SIGTTOU)
}
