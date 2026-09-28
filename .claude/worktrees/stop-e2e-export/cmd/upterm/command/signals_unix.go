//go:build !windows

package command

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// notifyDetachSignals derives a context that ends when this process is told
// to stop or its terminal goes away. For an attached terminal both mean the
// same thing — detach, restoring the terminal on the way out — and in raw
// mode Ctrl-C is a byte the session sees, so os.Interrupt here is `kill -INT`.
func notifyDetachSignals(ctx context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
}
