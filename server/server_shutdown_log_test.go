package server

import (
	"bytes"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// syncBuffer collects log output from the several goroutines a shutdown runs
// on. slog's own level filter does the selecting, so a handler at LevelError
// leaves this empty unless something logged an error.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestServerShutdownIsQuiet pins the whole shutdown chain, not just the error
// Server.Shutdown returns. Every component logs at Error if its own shutdown
// reports anything, so a listener closed twice -- once by its owner and once by
// Server.Shutdown -- turned a routine shutdown into a stream of "use of closed
// network connection" errors in the log.
func TestServerShutdownIsQuiet(t *testing.T) {
	logs := &syncBuffer{}
	ts := newServingTestServer(t,
		slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelError})))

	require.NoError(t, ts.Shutdown())

	select {
	case err := <-ts.served:
		// A requested stop is not a failure, and the value no longer depends on
		// which component happened to return first.
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("ServeWithContext did not return after Shutdown")
	}

	require.Empty(t, logs.String(), "a clean shutdown must not log at Error")
}
