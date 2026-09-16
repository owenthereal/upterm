package command

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// notifyDetachSignals derives a context that ends when this process is told
// to stop. For an attached terminal that means detach, restoring the terminal
// on the way out — and in raw mode Ctrl-C is a byte the session sees, so
// os.Interrupt here is a console control event rather than a keystroke.
//
// There is no SIGHUP on Windows: a console going away arrives as
// CTRL_CLOSE_EVENT, which the Go runtime delivers as SIGTERM, not
// os.Interrupt — only CTRL_C and CTRL_BREAK map to that.
func notifyDetachSignals(ctx context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
}
