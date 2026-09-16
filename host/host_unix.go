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
//
// The process-wide dispositions — SIGPIPE converted, SIGTTIN and SIGTTOU
// ignored — are InstallSignalPolicy's, which this calls; see there for why
// they outlive the session and are never restored.
func setupSignalHandler(g *run.Group, ctx context.Context, shutdownRequested *atomic.Bool) {
	// Run has already done this by the time it gets here, and the Once makes
	// saying so again free. It is repeated so that the policy is a property
	// of setting up a host's signals rather than of Run: a future caller that
	// assembles its own group would otherwise get none of it.
	InstallSignalPolicy()

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
}
