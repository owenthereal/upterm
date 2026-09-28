package host

import (
	"context"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/oklog/run"
	"github.com/stretchr/testify/require"
)

// Test_setupSignalHandler_KeepsACancellationTheSelectLostToStop pins what the
// signal actor reports when the parent context is cancelled and another actor
// derived from it returns first. run.Group then interrupts the signal actor,
// which closes stop; if the actor reaches its select only then, ctx.Done()
// and stop are both ready and Go picks one at random. Returning through stop
// used to leave shutdownRequested unset, and the command killed during
// teardown was recorded as signaled on Unix and as an ordinary exit on
// Windows -- for a cancellation the caller asked for.
//
// The window is the actor's first instants: the context is cancelled before
// the group runs, the second actor is done the moment it runs, and the
// interrupt has to land before the signal actor's goroutine reaches its
// select. What normally keeps it from landing in time is signal.Stop in the
// interrupt: with nobody else registered for the same signals it drops the
// last reference and disables them, and the runtime does that through a
// handshake with its signal thread that parks the interrupting goroutine and
// hands the CPU to the actor before stop is closed. Holding a second
// registration for the loop keeps Stop on its cheap path, and the race is
// then reached in roughly a quarter of the iterations; each of those fails on
// the unfixed code only when the select picks stop, so the loop is what makes
// one run conclusive and the count is what makes a failure say how often it
// lost.
func Test_setupSignalHandler_KeepsACancellationTheSelectLostToStop(t *testing.T) {
	held := make(chan os.Signal, 1)
	signal.Notify(held, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(held)

	const iterations = 200

	var lost int
	for i := 0; i < iterations; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		var g run.Group
		var shutdownRequested atomic.Bool
		setupSignalHandler(&g, ctx, &shutdownRequested)
		g.Add(func() error {
			<-ctx.Done()
			return ctx.Err()
		}, func(error) {})

		require.ErrorIs(t, g.Run(), context.Canceled)
		if !shutdownRequested.Load() {
			lost++
		}
	}

	require.Zero(t, lost,
		"%d of %d iterations returned through stop without keeping the parent context's cancellation", lost, iterations)
}
