package io

import (
	"context"
	"errors"
	"io"
	"sync"
)

const (
	// DefaultGuestBufferSize bounds how much output may sit in pending before a
	// guest is dropped; the worst case for undelivered output is this plus one
	// in-flight maxDrainChunk. A guest merely slower than the host's terminal,
	// rather than stalled, is throttled only by the host's own ingest rate, so
	// backlog accrues at the difference between that rate and the guest's
	// drain rate, and a sustained mismatch exhausts any finite cap: this
	// number sets how long a slow guest survives, not whether. Total slack is
	// roughly 5 MiB, the cap plus a 2 MiB SSH window on each of the two legs
	// between host and guest. The buffer exists to decouple the fan-out from a
	// blocking write, not to store the session.
	DefaultGuestBufferSize = 1 << 20 // 1 MiB
)

var (
	// ErrOverflow is returned once a sink has passed its cap. A guest that
	// cannot receive output is not attached in any useful sense, so the sink
	// fails permanently rather than dropping bytes out of the middle of a
	// terminal stream, which the guest could not detect.
	ErrOverflow = errors.New("asyncwriter: buffer overflow")

	// ErrWriterClosed is returned by Write after Close.
	ErrWriterClosed = errors.New("asyncwriter: closed")
)

// AsyncWriter delivers to one writer from one goroutine, so writing to it never
// blocks on that writer's I/O.
//
// It exists because the host fans its pty output out to every guest serially:
// a guest that stops reading its SSH channel blocks in Write once the channel
// window fills, and holds up every writer behind it, including the host's own
// terminal. Handing off into a bounded buffer means the slowest viewer no
// longer sets the pace. See owenthereal/upterm#524.
//
// The buffer is bounded in bytes rather than in writes, because pty writes run
// from one byte to io.Copy's 32 KiB and a count of writes is therefore not a
// bound on memory at all.
type AsyncWriter struct {
	w      io.Writer
	max    int
	onDrop func(error)

	// chunk is owned by the drain goroutine and never aliases pending. Handing
	// out a sub-slice of pending instead would pin its whole grown backing
	// array for the length of the write, which is exactly what
	// TestAsyncWriterChunkStaysABoundedBuffer guards against.
	chunk []byte

	mu      sync.Mutex
	cond    *sync.Cond
	pending []byte
	err     error
	closed  bool
	writing bool
	// idle is closed and replaced every time the drain catches up, which is how
	// Flush waits without polling.
	idle     chan struct{}
	dropOnce sync.Once
	done     chan struct{}
}

// NewAsyncWriter starts delivery to w immediately. max bounds the payload held
// undelivered; onDrop, which may be nil, is called once if the sink dies,
// always on its own goroutine so the caller of Write is never held up by it.
//
// The caller owns w. Close stops the goroutine but does not close w.
func NewAsyncWriter(w io.Writer, max int, onDrop func(error)) *AsyncWriter {
	a := &AsyncWriter{
		w:      w,
		max:    max,
		onDrop: onDrop,
		chunk:  make([]byte, maxDrainChunk),
		idle:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	a.cond = sync.NewCond(&a.mu)
	go a.drain()
	return a
}

// Write copies p into the pending buffer and returns. It never performs I/O and
// never blocks on the underlying writer.
//
// It reports overflow as an error so that MultiWriter, which already drops a
// writer that fails, removes this one without needing to know anything about
// buffering.
func (a *AsyncWriter) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch {
	case a.err != nil:
		return 0, a.err
	case a.closed:
		return 0, ErrWriterClosed
	case len(a.pending)+len(p) > a.max:
		a.fail(ErrOverflow)
		return 0, a.err
	}

	// The copy is not optional: io.Copy reuses its buffer, so retaining p would
	// corrupt this guest's output as soon as the copy looped.
	a.pending = append(a.pending, p...)
	a.cond.Broadcast()
	return len(p), nil
}

// Close stops accepting writes and signals the drain. It deliberately does not
// wait for the goroutine to exit: in the case this type exists for, that
// goroutine is blocked in a write that only session teardown will release, and
// waiting here would deadlock exactly then. The goroutine exits when its
// in-flight write returns.
//
// Close always returns nil and is safe to call repeatedly. Pending bytes are
// discarded; MultiWriter.Shutdown is the path that delivers a tail.
func (a *AsyncWriter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		a.closed = true
		a.cond.Broadcast()
		a.signalIdle()
	}
	return nil
}

// Flush waits until everything written so far has been delivered, or until ctx
// is done.
//
// It waits on the idle signal the drain publishes once it has emptied the
// buffer and its last write has returned, rather than polling, and it honours
// ctx so that one stuck guest cannot hold up the host's exit. A dead or closed
// sink flushes to nil: there is nothing left to deliver and a guest that is
// already gone is not a shutdown error.
func (a *AsyncWriter) Flush(ctx context.Context) error {
	for {
		a.mu.Lock()
		if a.err != nil || a.closed || (len(a.pending) == 0 && !a.writing) {
			a.mu.Unlock()
			return nil
		}
		idle := a.idle
		a.mu.Unlock()

		select {
		case <-idle:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// fail records a terminal error and releases everything waiting on this sink.
// Callers must hold a.mu.
//
// onDrop runs on its own goroutine because the caller here is the pty copy that
// feeds every attached guest: a callback that blocks would reintroduce the
// head-of-line blocking this type removes.
func (a *AsyncWriter) fail(err error) {
	if a.err != nil {
		return
	}
	a.err = err
	a.pending = nil
	a.cond.Broadcast()
	a.signalIdle()
	if a.onDrop != nil {
		a.dropOnce.Do(func() { go a.onDrop(err) })
	}
}

// signalIdle releases anything waiting for delivery to catch up. Callers must
// hold a.mu.
func (a *AsyncWriter) signalIdle() {
	close(a.idle)
	a.idle = make(chan struct{})
}

func (a *AsyncWriter) drain() {
	defer close(a.done)
	for {
		a.mu.Lock()
		for len(a.pending) == 0 && !a.closed && a.err == nil {
			a.cond.Wait()
		}
		if a.closed || a.err != nil {
			a.mu.Unlock()
			return
		}
		n := a.takeChunk()
		a.writing = true
		a.mu.Unlock()

		written, err := a.w.Write(a.chunk[:n])
		if err == nil && written != n {
			// MultiWriter refuses a short write from an attached writer, and
			// wrapping the guest in a sink must not quietly give that up:
			// accepting it would truncate the stream and leave the guest
			// attached, which is worse than dropping it.
			err = io.ErrShortWrite
		}

		a.mu.Lock()
		a.writing = false
		if err != nil {
			a.fail(err)
			a.mu.Unlock()
			return
		}
		if len(a.pending) == 0 {
			a.signalIdle()
		}
		a.mu.Unlock()
	}
}

// stopped reports whether the drain goroutine has exited. It exists so tests
// can assert the goroutine is not leaked without reaching into unexported state.
func (a *AsyncWriter) stopped() bool {
	select {
	case <-a.done:
		return true
	default:
		return false
	}
}

const maxDrainChunk = 64 << 10 // 64 KiB

// takeChunk moves pending bytes into the goroutine's own buffer. Callers must
// hold a.mu.
func (a *AsyncWriter) takeChunk() int {
	n := copy(a.chunk, a.pending)
	a.pending = a.pending[n:]
	return n
}
