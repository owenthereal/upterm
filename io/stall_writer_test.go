package io

import (
	"bytes"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stallBlockingWriter blocks every Write until released, recording what it was
// given. It stands in for an SSH channel whose window has filled.
type stallBlockingWriter struct {
	mu      sync.Mutex
	got     []byte
	writes  int
	release chan struct{}
}

func newStallBlockingWriter() *stallBlockingWriter {
	return &stallBlockingWriter{release: make(chan struct{})}
}

func (b *stallBlockingWriter) Write(p []byte) (int, error) {
	<-b.release
	b.mu.Lock()
	defer b.mu.Unlock()
	b.got = append(b.got, p...)
	b.writes++
	return len(p), nil
}

// slowWriter delivers every chunk after a fixed delay: slow, but progressing.
type slowWriter struct {
	delay time.Duration
	buf   bytes.Buffer
}

func (s *slowWriter) Write(p []byte) (int, error) {
	time.Sleep(s.delay)
	return s.buf.Write(p)
}

func TestStallWriterChunksLargeWrites(t *testing.T) {
	b := newStallBlockingWriter()
	close(b.release)
	w := NewStallWriter(b, 4, time.Hour, func() { t.Error("stall fired") })
	defer func() { _ = w.Close() }()

	n, err := w.Write([]byte("0123456789"))
	require.NoError(t, err)
	require.Equal(t, 10, n)
	require.Equal(t, "0123456789", string(b.got))
	require.Equal(t, 3, b.writes, "10 bytes in 4-byte chunks is three writes")
}

func TestStallWriterIdleNeverFires(t *testing.T) {
	var fired atomic.Int32
	w := NewStallWriter(io.Discard, 4096, 20*time.Millisecond, func() { fired.Add(1) })
	defer func() { _ = w.Close() }()

	// Nothing outstanding for many timeouts.
	time.Sleep(200 * time.Millisecond)
	require.Zero(t, fired.Load(), "an idle writer must never be judged stalled")
}

func TestStallWriterSlowButProgressingNeverFires(t *testing.T) {
	var fired atomic.Int32
	s := &slowWriter{delay: 10 * time.Millisecond}
	// Each 4-byte chunk takes 10ms; the timeout is 250ms; the whole write takes ~250ms.
	w := NewStallWriter(s, 4, 250*time.Millisecond, func() { fired.Add(1) })
	defer func() { _ = w.Close() }()

	_, err := w.Write(bytes.Repeat([]byte("x"), 100))
	require.NoError(t, err)
	require.Zero(t, fired.Load(), "a write that completes chunks inside the timeout is progress, not a stall")
	require.Equal(t, 100, s.buf.Len())
}

func TestStallWriterFiresOnceWhenNoChunkCompletes(t *testing.T) {
	b := newStallBlockingWriter()
	fired := make(chan struct{}, 4)
	w := NewStallWriter(b, 4, 30*time.Millisecond, func() { fired <- struct{}{} })
	defer func() { _ = w.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = w.Write([]byte("blocked"))
	}()

	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not fire while a write was outstanding with no progress")
	}
	// Still blocked: onStall's job (closing the connection) is what would
	// release it in production. Release it here and make sure the watchdog
	// does not fire a second time.
	close(b.release)
	<-done
	time.Sleep(100 * time.Millisecond)
	require.Len(t, fired, 0, "onStall must be called at most once")
}

func TestStallWriterResetsTheClockWhenAWriteBeginsAfterIdleness(t *testing.T) {
	// Two writes, each blocked for 80% of the timeout, separated by an idle
	// period longer than the timeout. Judged against a stale stamp the second
	// would look stalled; judged from its own start it is fine.
	const timeout = 400 * time.Millisecond
	var fired atomic.Int32
	b := newStallBlockingWriter()
	w := NewStallWriter(b, 4096, timeout, func() { fired.Add(1) })
	defer func() { _ = w.Close() }()

	for i := 0; i < 2; i++ {
		b.release = make(chan struct{})
		done := make(chan struct{})
		go func() { defer close(done); _, _ = w.Write([]byte("x")) }()
		time.Sleep(timeout * 4 / 5)
		close(b.release)
		<-done
		time.Sleep(timeout * 2) // idle, disarmed
	}
	require.Zero(t, fired.Load(), "the progress clock must restart with each write, not carry over an idle period")
}

func TestStallWriterReportsShortWrites(t *testing.T) {
	w := NewStallWriter(writerFunc(func(p []byte) (int, error) { return len(p) - 1, nil }), 4096, time.Hour, nil)
	defer func() { _ = w.Close() }()
	_, err := w.Write([]byte("abc"))
	require.ErrorIs(t, err, io.ErrShortWrite)
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
