package command

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// shutdownSignals are the ways a supervisor asks uptermd to stop.
//
// os.Interrupt is what Fly sends -- fly.toml sets kill_signal = "SIGINT" -- and
// what Ctrl-C delivers; SIGTERM is what Docker, Kubernetes and systemd send.
// Both are portable: syscall.SIGTERM exists on Windows in Go, where it is
// simply never delivered, and os.Interrupt arrives there as a console control
// event. SIGHUP is deliberately absent. On a daemon it conventionally means
// "reload", uptermd has nothing to reload, and it does not exist on Windows.
var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

// NotifyShutdownSignals derives a context that ends when the process is asked
// to stop, and hands the signals back to the runtime once that has happened.
//
// Handing them back is the difference from signal.NotifyContext, which leaves
// the handler installed with nothing draining its channel: a second Ctrl-C, or
// a second SIGTERM aimed at a shutdown that has wedged, is swallowed, and the
// operator who meant "stop now" is left reaching for SIGKILL. Restoring the
// default disposition makes the second signal do what sending it twice means.
// It is also what oklog/run's SignalHandler does, via the signal.Stop it defers
// around its own channel.
func NotifyShutdownSignals(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, shutdownSignals...)

	go func() {
		// Both branches reach the stop: a signal that has been acted on, and a
		// caller that cancelled instead. The process outlives either -- tests
		// call this more than once -- so the notification must not outlive the
		// context it was installed for.
		defer signal.Stop(ch)
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
	}()

	return ctx, cancel
}
