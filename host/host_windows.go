//go:build windows

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

// setupSignalHandler configures OS signal handling for Windows.
// Only listens for SIGTERM (console close, logoff, shutdown) for graceful shutdown.
// Explicitly ignores os.Interrupt (Ctrl+C, Ctrl+Break) to prevent upterm from dying
// when SSH clients send Ctrl+C to child processes via ConPTY.
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
		signal.Notify(sigCh, syscall.SIGTERM)

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

	// Consume and ignore os.Interrupt (Ctrl+C, Ctrl+Break)
	// This prevents the default OS behavior (process termination) while allowing
	// child processes in ConPTY to receive these signals normally.
	{
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		g.Add(func() error {
			for range sigCh {
				// Consume and ignore - prevents upterm from being killed
			}
			return nil
		}, func(err error) {
			signal.Stop(sigCh)
			close(sigCh)
		})
	}
}
