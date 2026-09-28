package logging

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// blockingHandler never finishes a record until it is released: a log file on
// a wedged filesystem, or a console that stopped.
type blockingHandler struct {
	release chan struct{}
	entered chan struct{}
	once    *sync.Once
}

func newBlockingHandler(release chan struct{}) blockingHandler {
	return blockingHandler{release: release, entered: make(chan struct{}), once: &sync.Once{}}
}

func (h blockingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h blockingHandler) Handle(context.Context, slog.Record) error {
	h.once.Do(func() { close(h.entered) })
	<-h.release
	return nil
}
func (h blockingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h blockingHandler) WithGroup(string) slog.Handler      { return h }

func TestWithinReturnsWhenFnBlocks(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{})

	start := time.Now()
	Within(50*time.Millisecond, func() {
		close(entered)
		<-release
	})
	require.Less(t, time.Since(start), 5*time.Second, "a blocked fn made the wait unbounded")

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("fn never ran")
	}
}

func TestWithinWaitsForFnToFinish(t *testing.T) {
	var done bool
	Within(5*time.Second, func() {
		time.Sleep(10 * time.Millisecond)
		done = true
	})
	require.True(t, done, "Within returned before a working fn had finished")
}

func TestLogWithinDeliversTheLine(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	LogWithin(logger, slog.LevelDebug, 5*time.Second, "window change not delivered", "error", "closed")
	require.Contains(t, buf.String(), "window change not delivered")
	require.Contains(t, buf.String(), "error=closed")
}

func TestLogWithinWithoutALogger(t *testing.T) {
	LogWithin(nil, slog.LevelDebug, 5*time.Second, "nothing to log to")
}

func TestWarnWithinReturnsWithABlockedHandler(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	handler := newBlockingHandler(release)

	start := time.Now()
	WarnWithin(slog.New(handler), 50*time.Millisecond, "abandoning output")
	require.Less(t, time.Since(start), 5*time.Second, "a blocked handler made the wait unbounded")

	select {
	case <-handler.entered:
	case <-time.After(time.Second):
		t.Fatal("the line was never handed to the handler")
	}
}

// blockingWriter stands in for the terminal the diagnostic is about.
type blockingWriter struct {
	release chan struct{}
	entered chan struct{}
	once    *sync.Once
}

func (w blockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

func TestWriteWithinReturnsWhenTheWriterBlocks(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	w := blockingWriter{release: release, entered: make(chan struct{}), once: &sync.Once{}}

	start := time.Now()
	WriteWithin(w, 50*time.Millisecond, "the terminal stopped\n")
	require.Less(t, time.Since(start), 5*time.Second, "a blocked writer made the wait unbounded")

	select {
	case <-w.entered:
	case <-time.After(time.Second):
		t.Fatal("nothing was written")
	}
}

func TestWriteWithinDeliversToAWorkingWriter(t *testing.T) {
	var buf bytes.Buffer
	WriteWithin(&buf, 5*time.Second, "restoring the terminal\n")
	require.Equal(t, "restoring the terminal\n", buf.String())
}
