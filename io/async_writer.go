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

	// ErrStalled is the error a caller enforcing a delivery deadline passes to
	// AbortIfNoProgress. It becomes Err() and reaches onDrop like any other
	// failure.
	ErrStalled = errors.New("asyncwriter: no progress within the stall timeout")

	// deadProgress is the Progress channel a writer that has already failed or
	// closed hands out. Such a writer's own progress channel is the
	// replacement that Close or fail installed, and nothing will ever close
	// it; handing out one that is already closed instead wakes a waiter at
	// once, so it re-reads the Backlog and sees Live is false.
	deadProgress = func() <-chan struct{} {
		ch := make(chan struct{})
		close(ch)
		return ch
	}()
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
	// inflight is the undelivered rest of the chunk currently being handed to
	// w piece by piece: set to the chunk's length when the drain starts it,
	// reduced by each piece delivered, and cleared once the chunk is done.
	inflight int
	// delivered is the total number of bytes handed to w across every piece
	// ever completed. It only advances; AbortIfNoProgress and Backlog compare
	// snapshots of it to tell whether anything landed in between.
	delivered uint64
	// idle is closed and replaced every time the drain catches up, which is how
	// Flush waits without polling.
	idle chan struct{}
	// progress is closed and replaced after every delivered piece, and once
	// more on fail or close. Unlike idle, it fires long before the queue
	// empties, which is what lets a pacer see the relay's ~32 KiB steps rather
	// than waiting for a whole chunk.
	progress chan struct{}
	dropOnce sync.Once
	done     chan struct{}
}

// Backlog reports what a caller pacing on this writer needs to know: how much
// output is not yet delivered, how far delivery has gotten, and a channel to
// wait on for the next change.
type Backlog struct {
	Bytes     int             // pending plus the undelivered rest of the chunk in flight
	Delivered uint64          // total bytes delivered; advances with every piece
	Progress  <-chan struct{} // closed after the next delivered piece, or on fail or close
	Live      bool            // false once failed or closed
}

// NewAsyncWriter starts delivery to w immediately. max bounds the payload held
// undelivered; onDrop, which may be nil, is called once if the sink dies,
// always on its own goroutine so the caller of Write is never held up by it.
//
// The caller owns w. Close stops the goroutine but does not close w.
func NewAsyncWriter(w io.Writer, max int, onDrop func(error)) *AsyncWriter {
	a := &AsyncWriter{
		w:        w,
		max:      max,
		onDrop:   onDrop,
		chunk:    make([]byte, maxDrainChunk),
		idle:     make(chan struct{}),
		progress: make(chan struct{}),
		done:     make(chan struct{}),
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
		a.pending = nil
		a.cond.Broadcast()
		a.signalIdle()
		a.signalProgress()
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

// Drained returns a channel closed the next time delivery catches up: the
// buffer empties and the last write returns. It is Flush for a caller that
// wants to be told rather than to wait — one holding a lock, or one with
// nothing to do until the news arrives.
//
// The second return is false for a writer that has already failed or been
// closed, and there is nothing else it could be: the signal those publish is
// the one the writer had at the time, and the channel that replaces it is
// never closed by anything. Answered under the lock the two of them take, so
// a caller that is told true holds a channel that failing and closing will
// still close.
func (a *AsyncWriter) Drained() (<-chan struct{}, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil || a.closed {
		return nil, false
	}
	return a.idle, true
}

// Err reports the error that ended delivery, if any.
//
// Flush cannot answer this: it reports nil for a sink that has already failed,
// because a guest that is gone is not a shutdown error. A caller that needs to
// know whether everything written was actually delivered — rather than merely
// that nothing more is coming — has to ask here as well.
func (a *AsyncWriter) Err() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

// Closed reports whether Close has been called.
//
// Like Err, it is the other half of what Flush does not say: Flush returns nil
// for a closed sink too, and a caller that needs to know whether what it wrote
// was delivered rather than discarded has to ask.
func (a *AsyncWriter) Closed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}

// Backlog reports how much output this writer is carrying and how far
// delivery has gotten, for a caller pacing on it rather than merely waiting
// for it to catch up.
func (a *AsyncWriter) Backlog() Backlog {
	a.mu.Lock()
	defer a.mu.Unlock()
	b := Backlog{
		Bytes:     len(a.pending) + a.inflight,
		Delivered: a.delivered,
		Progress:  a.progress,
		Live:      true,
	}
	if a.closed || a.err != nil {
		b.Progress = deadProgress
		b.Live = false
	}
	return b
}

// AbortIfNoProgress fails the writer, exactly as an overflow does — sticky
// error, onDrop once, on its own goroutine — but only if Delivered still
// equals since. It reports whether it aborted. The check and the failure
// happen under one lock, so a piece delivered after the caller's last
// snapshot always wins.
func (a *AsyncWriter) AbortIfNoProgress(since uint64, err error) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.err != nil || a.delivered != since {
		return false
	}
	a.fail(err)
	return true
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
	a.signalProgress()
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

// signalProgress releases anything waiting on the next piece landing. Callers
// must hold a.mu.
func (a *AsyncWriter) signalProgress() {
	close(a.progress)
	a.progress = make(chan struct{})
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
		a.inflight = n
		a.mu.Unlock()

		err := a.deliver(n)

		a.mu.Lock()
		a.writing = false
		a.inflight = 0
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

// deliver hands the first n bytes of the chunk to the underlying writer in
// pieces of at most maxDrainWrite, publishing progress after each. writing
// stays set across all of them, so Flush and Drained still mean "the whole
// chunk has landed".
//
// It stops between pieces once the writer is closed or has failed: Close
// promises the goroutine exits when its in-flight write returns, and a
// dropped guest must not be handed another write that may block on its link.
func (a *AsyncWriter) deliver(n int) error {
	for off := 0; off < n; {
		end := min(off+maxDrainWrite, n)
		written, err := a.w.Write(a.chunk[off:end])
		if err == nil && written != end-off {
			// MultiWriter refuses a short write from an attached writer, and
			// wrapping the guest in a sink must not quietly give that up:
			// accepting it would truncate the stream and leave the guest
			// attached, which is worse than dropping it.
			err = io.ErrShortWrite
		}
		if err != nil {
			return err
		}
		off = end
		a.mu.Lock()
		a.inflight = n - off
		a.delivered += uint64(written)
		a.signalProgress()
		stop := a.closed || a.err != nil
		a.mu.Unlock()
		if stop {
			return nil // the drain loop sees closed or err and exits, silently
		}
	}
	return nil
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

// maxDrainWrite bounds each write deliver makes to the underlying writer.
// uptermd forwards with io.Copy, whose buffer is 32 KiB, so under sustained
// relay backpressure the host observes a guest's progress in steps of about
// that; it is also SSH's largest packet, so splitting the chunk here is free
// on the wire.
const maxDrainWrite = 32 << 10 // 32 KiB

// takeChunk moves pending bytes into the goroutine's own buffer. Callers must
// hold a.mu.
//
// Dropping the slice once it empties is what gives the burst's memory back.
// Advancing past the bytes taken shrinks the slice's length and capacity but
// leaves its pointer inside the array append grew, and Go frees an allocation
// only as a whole: a guest that caught up after a 512 KiB burst and then went
// quiet would hold every byte of it until some later write happened to
// reallocate. Measured over that burst in io.Copy-sized appends: 589 KiB still
// resident after a full drain, 5 KiB once pending is dropped.
func (a *AsyncWriter) takeChunk() int {
	n := copy(a.chunk, a.pending)
	a.pending = a.pending[n:]
	if len(a.pending) == 0 {
		a.pending = nil
	}
	return n
}
