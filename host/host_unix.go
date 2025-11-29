//go:build !windows

package host

import (
	"context"
	"os"
	"syscall"

	"github.com/oklog/run"
)

// setupSignalHandler configures OS signal handling for Unix systems.
// Listens for both SIGINT (Ctrl+C) and SIGTERM for graceful shutdown.
// On Unix, PTY isolation ensures that Ctrl+C sent to upterm's terminal
// doesn't affect child processes in the PTY.
func setupSignalHandler(g *run.Group, ctx context.Context) {
	g.Add(run.SignalHandler(ctx, os.Interrupt, syscall.SIGTERM))
}
