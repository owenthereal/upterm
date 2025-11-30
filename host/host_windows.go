//go:build windows

package host

import (
	"context"
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
	// Listen for SIGTERM for graceful shutdown
	g.Add(run.SignalHandler(ctx, syscall.SIGTERM))

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
