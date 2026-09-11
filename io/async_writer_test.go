package io

import (
	"bytes"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// recordingWriter accumulates what it is given. The drain runs on its own
// goroutine, so every field is read under the mutex.
type recordingWriter struct {
	mu      sync.Mutex
	written []byte
	sizes   []int
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.written = append(r.written, p...)
	r.sizes = append(r.sizes, len(p))
	return len(p), nil
}

func (r *recordingWriter) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.written)
}

func (r *recordingWriter) writeSizes() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.sizes)
}

// gateWriter models a guest whose SSH channel window has filled: every Write
// blocks until the test releases it. entered closes on the first Write so a
// test can wait for the drain to actually be inside the writer rather than for
// its goroutine to be scheduled.
type gateWriter struct {
	recordingWriter
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func newGateWriter() *gateWriter {
	return &gateWriter{entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *gateWriter) Write(p []byte) (int, error) {
	g.once.Do(func() { close(g.entered) })
	<-g.release
	return g.recordingWriter.Write(p)
}

// The property the whole change rests on: the fan-out hands off instead of
// waiting for a guest that has stopped reading.
func TestAsyncWriterWriteDoesNotBlockOnStuckWriter(t *testing.T) {
	gate := newGateWriter()
	defer close(gate.release)

	a := NewAsyncWriter(gate, DefaultGuestBufferSize, nil)
	defer func() { _ = a.Close() }()

	_, err := a.Write([]byte("first"))
	require.NoError(t, err)
	<-gate.entered // the drain is now blocked inside the writer

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			_, _ = a.Write([]byte("more output"))
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Write blocked behind a stuck writer")
	}
}

func TestAsyncWriterDeliversInOrder(t *testing.T) {
	var rec recordingWriter
	a := NewAsyncWriter(&rec, DefaultGuestBufferSize, nil)
	defer func() { _ = a.Close() }()

	var want []byte
	for i := range 50 {
		p := []byte{byte('a' + i%26)}
		want = append(want, p...)
		_, err := a.Write(p)
		require.NoError(t, err)
	}

	require.Eventually(t, func() bool { return bytes.Equal(rec.bytes(), want) },
		2*time.Second, time.Millisecond, "bytes should arrive in order and intact")
}

// io.Copy reuses its buffer, so a sink that retained p would corrupt output for
// every attached guest the moment the copy looped.
func TestAsyncWriterCopiesTheCallersBuffer(t *testing.T) {
	gate := newGateWriter()
	a := NewAsyncWriter(gate, DefaultGuestBufferSize, nil)
	defer func() { _ = a.Close() }()

	buf := []byte("original")
	_, err := a.Write(buf)
	require.NoError(t, err)
	copy(buf, "OVERWRIT")

	close(gate.release)
	require.Eventually(t, func() bool { return string(gate.bytes()) == "original" },
		2*time.Second, time.Millisecond, "the sink must not alias the caller's buffer")
}

func TestAsyncWriterOverflowDropsOnce(t *testing.T) {
	gate := newGateWriter()
	defer close(gate.release)

	drops := make(chan error, 4)
	a := NewAsyncWriter(gate, 16, func(err error) { drops <- err })
	defer func() { _ = a.Close() }()

	_, err := a.Write([]byte("12345678"))
	require.NoError(t, err)
	<-gate.entered

	// The first 8 bytes are in flight, so the cap applies to what follows.
	_, err = a.Write([]byte("12345678"))
	require.NoError(t, err)
	_, err = a.Write([]byte("123456789"))
	require.ErrorIs(t, err, ErrOverflow, "writing past the cap must fail")

	select {
	case err := <-drops:
		require.ErrorIs(t, err, ErrOverflow)
	case <-time.After(2 * time.Second):
		t.Fatal("onDrop never fired")
	}

	_, err = a.Write([]byte("x"))
	require.ErrorIs(t, err, ErrOverflow, "the error must be sticky")

	select {
	case <-drops:
		t.Fatal("onDrop fired more than once")
	case <-time.After(100 * time.Millisecond):
	}
}

// onDrop runs on the pty copy's behalf, so it must never be able to hold it up.
func TestAsyncWriterSlowDropCallbackDoesNotBlockWrite(t *testing.T) {
	gate := newGateWriter()
	defer close(gate.release)

	blocked := make(chan struct{})
	defer close(blocked)
	a := NewAsyncWriter(gate, 8, func(error) { <-blocked })
	defer func() { _ = a.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = a.Write([]byte("0123456789"))
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Write blocked behind onDrop")
	}
}

func TestAsyncWriterUnderlyingErrorIsTreatedAsADrop(t *testing.T) {
	drops := make(chan error, 1)
	a := NewAsyncWriter(&failingWriter{}, DefaultGuestBufferSize, func(err error) { drops <- err })
	defer func() { _ = a.Close() }()

	_, err := a.Write([]byte("output"))
	require.NoError(t, err, "the failure surfaces on the drain, not this write")

	select {
	case err := <-drops:
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrOverflow)
	case <-time.After(2 * time.Second):
		t.Fatal("onDrop never fired for an underlying write error")
	}

	require.Eventually(t, func() bool {
		_, err := a.Write([]byte("more"))
		return err != nil
	}, 2*time.Second, time.Millisecond, "later writes must fail once the sink is dead")
}

// MultiWriter treats a short write as a failed writer, and wrapping the guest
// in a sink must not quietly give that up: a writer that reports n < len(p)
// with no error would otherwise truncate the stream and stay attached.
func TestAsyncWriterShortWriteIsADrop(t *testing.T) {
	drops := make(chan error, 1)
	a := NewAsyncWriter(shortWriter{}, DefaultGuestBufferSize, func(err error) { drops <- err })
	defer func() { _ = a.Close() }()

	_, err := a.Write([]byte("output"))
	require.NoError(t, err)

	select {
	case err := <-drops:
		require.ErrorIs(t, err, io.ErrShortWrite)
	case <-time.After(2 * time.Second):
		t.Fatal("a short write was accepted as complete delivery")
	}
}

// shortWriter accepts everything but the last byte, without reporting an error.
type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

// An idle drain has no I/O to fail, so Close is the only thing that can ever
// release it. This is the refused-attach path: the sink is built, the attach is
// rejected, and nothing was ever written.
func TestAsyncWriterCloseStopsAnIdleDrain(t *testing.T) {
	var rec recordingWriter
	a := NewAsyncWriter(&rec, DefaultGuestBufferSize, nil)

	require.NoError(t, a.Close())
	require.Eventually(t, a.stopped, 2*time.Second, time.Millisecond,
		"an idle drain must exit on Close")
}

// Close must not wait for the goroutine: in the case this whole change exists
// for, that goroutine is blocked in a write that only session teardown releases.
func TestAsyncWriterCloseDoesNotWaitAndStopsTheDrain(t *testing.T) {
	gate := newGateWriter()
	a := NewAsyncWriter(gate, DefaultGuestBufferSize, nil)

	_, err := a.Write([]byte("first"))
	require.NoError(t, err)
	<-gate.entered

	done := make(chan struct{})
	go func() { defer close(done); _ = a.Close() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for a goroutine blocked in a write")
	}

	_, err = a.Write([]byte("after close"))
	require.ErrorIs(t, err, ErrWriterClosed)
	require.NoError(t, a.Close(), "Close must be repeatable")

	close(gate.release) // release the in-flight write
	require.Eventually(t, func() bool { return a.stopped() },
		2*time.Second, time.Millisecond, "the drain goroutine must exit")
}

func TestAsyncWriterCoalescesUpToTheChunkCap(t *testing.T) {
	gate := newGateWriter()
	a := NewAsyncWriter(gate, DefaultGuestBufferSize, nil)
	defer func() { _ = a.Close() }()

	_, err := a.Write([]byte("first"))
	require.NoError(t, err)
	<-gate.entered // the drain holds "first"; everything below queues behind it

	block := bytes.Repeat([]byte("y"), 32<<10)
	const blocks = 8 // 256 KiB, four chunks' worth
	for range blocks {
		_, err := a.Write(block)
		require.NoError(t, err)
	}

	close(gate.release)
	wantLen := len("first") + blocks*len(block)
	require.Eventually(t, func() bool { return len(gate.bytes()) == wantLen },
		5*time.Second, time.Millisecond, "everything queued must be delivered")

	sizes := gate.writeSizes()
	require.Less(t, len(sizes), blocks, "queued writes should coalesce, not arrive one by one")
	for _, n := range sizes {
		require.LessOrEqual(t, n, maxDrainChunk, "no write may exceed the chunk cap")
	}
}

// A burst that has been fully delivered must not leave its backing array behind
// for the rest of the session. Advancing pending past the bytes taken walks the
// slice to the end of its array, so this holds without any explicit release —
// measured at 0-4096 bytes across bursts from 256 KiB to 1000 KiB. The bound
// here is deliberately loose: it pins "the array is given back", not the exact
// arithmetic of Go's size classes.
func TestAsyncWriterReleasesPendingCapacityWhenItCatchesUp(t *testing.T) {
	gate := newGateWriter()
	a := NewAsyncWriter(gate, DefaultGuestBufferSize, nil)
	defer func() { _ = a.Close() }()

	_, err := a.Write([]byte("first"))
	require.NoError(t, err)
	<-gate.entered

	_, err = a.Write(bytes.Repeat([]byte("z"), 512<<10))
	require.NoError(t, err)

	close(gate.release)
	require.Eventually(t, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return len(a.pending) == 0 && cap(a.pending) <= maxDrainChunk
	}, 5*time.Second, time.Millisecond, "a one-off burst must not be retained for the session")
}

// The drain's chunk must stay a bounded buffer of its own rather than a window
// into pending: `a.chunk = a.pending[:n]` would keep the guest's whole grown
// array — up to max — reachable for as long as the write is in flight, which is
// the memory term the 64 KiB cap exists to bound.
//
// This pins memory, not content. Delivered bytes cannot be rewritten under the
// writer either way: pending only ever advances past the bytes taken, so every
// later append lands beyond the range a window would cover. A content
// comparison therefore cannot tell a copy from a window — capacity can.
func TestAsyncWriterChunkStaysABoundedBuffer(t *testing.T) {
	gate := newGateWriter()
	a := NewAsyncWriter(gate, DefaultGuestBufferSize, nil)
	defer func() { _ = a.Close() }()

	// A burst far larger than one chunk, so a windowing takeChunk would inherit
	// a correspondingly large capacity.
	const burst = 512 << 10
	_, err := a.Write(bytes.Repeat([]byte("a"), burst))
	require.NoError(t, err)
	<-gate.entered // the drain is inside Write, holding the first chunk

	a.mu.Lock()
	chunkCap := cap(a.chunk)
	a.mu.Unlock()
	require.Equal(t, maxDrainChunk, chunkCap,
		"the chunk must not inherit pending's backing array")

	close(gate.release)
	require.Eventually(t, func() bool { return len(gate.bytes()) == burst },
		5*time.Second, time.Millisecond, "all bytes delivered")
}
