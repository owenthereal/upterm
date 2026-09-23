//go:build windows

package host

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/oklog/run"
)

// setupSignalHandler configures OS signal handling for Windows.
// Only listens for SIGTERM (console close, logoff, shutdown) for graceful shutdown.
// Explicitly ignores os.Interrupt (Ctrl+C, Ctrl+Break) to prevent upterm from dying
// when SSH clients send Ctrl+C to child processes via ConPTY.
func setupSignalHandler(g *run.Group, ctx context.Context) {
	// Nothing to install on this platform, and Run has called it already in
	// any case. Called on both so that the policy is a property of setting up
	// a host's signals rather than of being Unix. See InstallSignalPolicy.
	InstallSignalPolicy()

	{
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM)

		// The interrupt unblocks the actor without manufacturing a shutdown cause.
		stop := make(chan struct{})
		g.Add(func() error {
			select {
			case sig := <-sigCh:
				return hostSignalError{signal: sig.(syscall.Signal)}
			case <-ctx.Done():
				return errors.Join(ctx.Err(), context.Cause(ctx))
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
