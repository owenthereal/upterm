package host

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"testing"

	"github.com/oklog/run"
	"github.com/stretchr/testify/require"
)

// The selected cancellation remains the outcome even if the signal actor
// loses its select to its interrupt. Classification uses the group winner.
func Test_setupSignalHandler_KeepsACancellationTheSelectLostToStop(t *testing.T) {
	held := make(chan os.Signal, 1)
	signal.Notify(held, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(held)

	const iterations = 200

	for i := 0; i < iterations; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		var g run.Group
		setupSignalHandler(&g, ctx)
		g.Add(func() error {
			<-ctx.Done()
			return ctx.Err()
		}, func(error) {})

		require.ErrorIs(t, g.Run(), context.Canceled)
	}
}
