package internal

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// blockingReader never returns, standing in for a pty whose reader does not
// report EOF when the command exits.
type blockingReader struct{}

func (blockingReader) Read([]byte) (int, error) {
	select {}
}

func TestDrainForceCommandOutput(t *testing.T) {
	t.Run("returns as soon as the reader reports EOF", func(t *testing.T) {
		drained := make(chan struct{})
		close(drained)

		start := time.Now()
		drainForceCommandOutput(discardLogger(), newActivityReader(blockingReader{}), drained, make(chan struct{}))

		require.Less(t, time.Since(start), forceCommandDrainIdle,
			"EOF should end the drain immediately, without waiting out the idle window")
	})

	// Windows' ConPTY only reports EOF once the pty is closed, and the drain
	// exists to defer that close — so on Windows `drained` never fires and the
	// idle window is the only thing that can end the wait. Before this was
	// idle-based, every forced command on Windows paid the full timeout.
	t.Run("returns after the idle window when the reader never reports EOF", func(t *testing.T) {
		start := time.Now()
		drainForceCommandOutput(discardLogger(), newActivityReader(blockingReader{}),
			make(chan struct{}), make(chan struct{}))
		elapsed := time.Since(start)

		require.GreaterOrEqual(t, elapsed, forceCommandDrainIdle,
			"the drain must give output a chance to arrive")
		require.Less(t, elapsed, forceCommandDrainTimeout/2,
			"the drain must not wait out the hard timeout when the reader is simply idle")
	})

	t.Run("keeps waiting while output is still arriving", func(t *testing.T) {
		output := newActivityReader(blockingReader{})

		// Report activity for well over one idle window, then stop.
		stop := make(chan struct{})
		go func() {
			ticker := time.NewTicker(forceCommandDrainIdle / 4)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					output.touch()
				case <-stop:
					return
				}
			}
		}()
		time.AfterFunc(3*forceCommandDrainIdle, func() { close(stop) })

		start := time.Now()
		drainForceCommandOutput(discardLogger(), output, make(chan struct{}), make(chan struct{}))

		require.GreaterOrEqual(t, time.Since(start), 3*forceCommandDrainIdle,
			"the drain must not give up while output is still being read")
	})

	t.Run("returns when the session is done", func(t *testing.T) {
		done := make(chan struct{})
		close(done)

		start := time.Now()
		drainForceCommandOutput(discardLogger(), newActivityReader(blockingReader{}), make(chan struct{}), done)

		require.Less(t, time.Since(start), forceCommandDrainIdle)
	})
}

func TestActivityReaderTracksReads(t *testing.T) {
	output := newActivityReader(newRepeatReader())

	time.Sleep(20 * time.Millisecond)
	idleBefore := output.idleFor()

	buf := make([]byte, 4)
	n, err := output.Read(buf)
	require.NoError(t, err)
	require.Positive(t, n)

	require.Less(t, output.idleFor(), idleBefore, "a successful read should reset the idle clock")
}

// repeatReader always yields a byte, so Read reports progress.
type repeatReader struct{}

func newRepeatReader() repeatReader { return repeatReader{} }

func (repeatReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'x'
	return 1, nil
}
