//go:build !windows

package host

import (
	"context"
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
	g.Add(run.SignalHandler(ctx, os.Interrupt, syscall.SIGTERM))

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
