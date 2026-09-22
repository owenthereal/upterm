//go:build !windows

package host

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/oklog/run"
)

// setupSignalHandler configures OS signal handling for Unix systems.
// Listens for both SIGINT (Ctrl+C) and SIGTERM for graceful shutdown.
// On Unix, PTY isolation ensures that Ctrl+C sent to upterm's terminal
// doesn't affect child processes in the PTY.
func setupSignalHandler(g *run.Group, ctx context.Context) {
	// Run has already done this by the time it gets here, and the Once makes
	// saying so again free. It is repeated so that the policy is a property
	// of setting up a host's signals rather than of Run: a future caller that
	// assembles its own group would otherwise get none of it.
	InstallSignalPolicy()

	{
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

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
}
