package io

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
)

// DefaultReplayBytes bounds the replay ring handed to a joining writer.
//
// It must stay well under DefaultGuestBufferSize: Append replays into a joining
// writer before attaching it, so a ring at or above a guest's sink size would
// overflow that guest with its own replay and drop it at the door.
const DefaultReplayBytes = 256 << 10

// ringChunkSize is the size a replay chunk is grown to before another is
// started, which is what bounds the ring's chunk count as well as its bytes.
//
// A chunk is only closed once the next write no longer fits in it, so any two
// adjacent closed chunks hold more than ringChunkSize bytes between them:
// that caps the queue at 2*max/ringChunkSize + 2 chunks, the two being the
// partially trimmed head and the still-growing tail. A stream of one-byte
// writes, which is the case that motivated this, packs them full and reaches
// only max/ringChunkSize + 1.
const ringChunkSize = 4096

type buffer struct {
	mu sync.Mutex

	queue [][]byte
	max   int // cap in bytes
	size  int // bytes currently held

	// onEvict is handed every byte that leaves the ring, in stream order.
	// What it feeds is state the replay can no longer reconstruct from the
	// ring itself; see NewMultiWriter.
	onEvict func([]byte)
}

// Append copies p into the ring and hands whatever that pushed out to
// onEvict, in stream order, before returning.
func (c *buffer) Append(p []byte) {
	evicted := c.push(p)
	if c.onEvict == nil {
		return
	}

	// Called outside c.mu: what onEvict feeds is not this type's to lock, and
	// a callback under a lock invites one. Order is still the stream's, since
	// Append is only ever reached under the fan-out's writeMu. The slices
	// handed over are read before this returns and not retained, so the ones
	// that alias p are safe.
	for _, e := range evicted {
		c.onEvict(e)
	}
}

// push does Append's bookkeeping and returns the evicted bytes for it to
// deliver.
func (c *buffer) push(p []byte) [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.max <= 0 {
		// Nothing is kept, so everything handed over has already left.
		return [][]byte{p}
	}

	var evicted [][]byte

	// A single write larger than the ring keeps only its tail. Everything
	// queued is older than the prefix being dropped, so it leaves first.
	if len(p) > c.max {
		evicted = append(evicted, c.queue...)
		evicted = append(evicted, p[:len(p)-c.max])
		c.queue = c.queue[:0]
		c.size = 0
		p = p[len(p)-c.max:]
	}

	// Grow the tail chunk in place where p fits in it, so a producer writing a
	// byte at a time does not get a chunk per byte. Only the spare capacity
	// past the tail's length is written, and that is never part of a slice
	// Data has already handed out: the ring only ever appends after what it
	// has already returned, and only ever trims in front of it.
	if tail := len(c.queue) - 1; len(p) < ringChunkSize && tail >= 0 &&
		len(c.queue[tail])+len(p) <= ringChunkSize &&
		cap(c.queue[tail])-len(c.queue[tail]) >= len(p) {
		c.queue[tail] = append(c.queue[tail], p...)
	} else {
		// A write of ringChunkSize or more gets a chunk of its own; a smaller
		// one gets room to be grown into.
		chunk := make([]byte, len(p), max(len(p), ringChunkSize))
		copy(chunk, p)
		c.queue = append(c.queue, chunk)
	}
	c.size += len(p)

	// Trim from the front, re-slicing the oldest chunk rather than dropping it
	// when it is larger than the excess, so the ring holds exactly max bytes
	// rather than the largest prefix of whole chunks that fits.
	for c.size > c.max {
		excess := c.size - c.max
		head := c.queue[0]
		if len(head) > excess {
			evicted = append(evicted, head[:excess])
			c.queue[0] = head[excess:]
			c.size -= excess
			break
		}
		evicted = append(evicted, head)
		c.queue = c.queue[1:]
		c.size -= len(head)
	}

	return evicted
}

func (c *buffer) Data() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Length, not capacity, was the bug: this returned len(queue) nil entries
	// followed by the real ones.
	result := make([][]byte, 0, len(c.queue))
	return append(result, c.queue...)
}

// bufferWriter adapts the replay ring to io.Writer so a filter can sit in
// front of it.
type bufferWriter struct{ b *buffer }

func (w bufferWriter) Write(p []byte) (int, error) {
	w.b.Append(p)
	return len(p), nil
}

// NewMultiWriter returns a fan-out whose replay ring holds the most recent
// replayBytes bytes of output.
func NewMultiWriter(replayBytes int, writers ...io.Writer) *MultiWriter {
	b := &buffer{max: replayBytes}
	modes := NewModeTracker()

	// The tracker watches what leaves the ring, not what enters it. Append
	// replays the snapshot ahead of the ring's bytes, so the state it
	// describes has to be the state as of the ring's first byte, with the
	// ring itself carrying everything after. Fed at the entrance it described
	// the state after the ring, and any mode set inside the ring window was
	// applied twice: once by the snapshot, far too early, and again by the
	// replay.
	b.onEvict = func(p []byte) { _, _ = modes.Write(p) }

	return &MultiWriter{
		writers: writers,
		buffer:  b,
		replay:  NewTerminalQueryFilter(bufferWriter{b: b}),
		modes:   modes,
	}
}

// ErrClosed is returned by Append once Shutdown has run. A guest that reaches
// the door as the session is ending is refused rather than attached to a
// fan-out nothing will flush again.
var ErrClosed = errors.New("multiwriter: closed to new writers")

// Flusher is implemented by attached writers that deliver asynchronously and so
// can still be holding output when the producer stops.
type Flusher interface {
	Flush(ctx context.Context) error
}

// MultiWriter is a concurrent safe writer that allows appending/removing writers.
// Newly appended writers get the last write to preserve last output.
//
// Attached writers are tracked by identity, so they must be comparable; see
// checkRemovable, which is how Append enforces it. NewMultiWriter does not,
// because it cannot report the error, so prefer Append.
type MultiWriter struct {
	// writeMu serializes the fan-out. Two producers must not write to the
	// same attached writer at once: many writers are not concurrency safe,
	// and even those that are would interleave halves of two writes.
	writeMu sync.Mutex

	// membersMu guards writers. It is deliberately not writeMu: it is never
	// held while writing to an attached writer, so Append and Remove never
	// wait on one. See Write for why that matters.
	membersMu sync.Mutex
	writers   []io.Writer

	buffer *buffer

	// replay is the producer-side path into the ring. Terminal queries are
	// stripped here rather than on the way out: a query that was live an hour
	// ago is not live now, and answering it on replay feeds a reply to whatever
	// the command is doing today. Stateful across writes; only touched under
	// writeMu.
	replay *TerminalQueryFilter

	// modes records terminal state the ring loses once it scrolls out, so a
	// joining writer can be restored to it before the replay. It is fed by
	// the ring's evictions rather than by Write; see NewMultiWriter.
	modes *ModeTracker

	// closed is guarded by writeMu, so Shutdown's quiesce and a concurrent
	// Append cannot interleave: an attach in progress either completes before
	// the snapshot and is flushed, or finds this set and is refused.
	closed bool
}

// Append attaches writers, handing each the replay buffer first so it starts
// from recent output rather than mid-screen.
//
// Both steps happen under writeMu, the fan-out lock, so attaching is atomic
// with respect to a Write: a joining writer gets the replay and every write
// after it, never a write that is also in its replay and never a gap between
// them. Holding the fan-out lock here is only safe because attached guest
// writers no longer block on I/O; under the old design it would have
// reintroduced the deadlock #523 removed.
func (t *MultiWriter) Append(writers ...io.Writer) error {
	// Reject anything Remove could not later take back out, before it is
	// attached and before it is written to.
	for _, w := range writers {
		if err := checkRemovable(w); err != nil {
			return err
		}
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if t.closed {
		return ErrClosed
	}

	for _, w := range writers {
		// The snapshot describes the terminal as of the ring's first byte,
		// so it has to go immediately in front of the ring and nowhere else:
		// it can end mid-sequence, where the ring's own first bytes are the
		// rest of that sequence.
		if snap := t.modes.Snapshot(); len(snap) > 0 {
			if _, err := w.Write(snap); err != nil {
				return err
			}
		}
		for _, d := range t.buffer.Data() {
			if _, err := w.Write(d); err != nil {
				return err
			}
		}

		// A partial escape sequence the filter is still holding is live output,
		// not history: it is not in the ring yet, so the loop above never sees
		// it. A joiner that misses it would see only the tail once the
		// remainder arrives live, which is garbage on its terminal. Replaying
		// the lead-in lets the joiner's own filter (or terminal) see the
		// sequence whole.
		if pending := t.replay.Pending(); len(pending) > 0 {
			if _, err := w.Write(pending); err != nil {
				return err
			}
		}
	}

	t.membersMu.Lock()
	defer t.membersMu.Unlock()
	t.writers = append(t.writers, writers...)

	return nil
}

// checkRemovable rejects a writer that Remove could not match.
//
// Writers are tracked by identity, so Remove compares interface values, and
// comparing two interface values that hold the same non-comparable dynamic
// type -- a slice, map, or func with a value receiver -- panics at run time.
// Write removes the writers that failed it, so that panic would land in the
// host's pty copy and take the whole process down. Refusing the writer at the
// door reports the mistake to the caller that made it, at the one point where
// it is still fixable.
//
// The question has to be asked of the value, not the type. A struct wrapping
// an io.Writer is a comparable type, because an interface field is one, yet
// comparing two of them still panics if the writers inside are funcs.
// reflect.Value.Comparable walks into the interface and answers for what is
// actually there, and promises the comparison will not panic when it says yes.
//
// This is checked once per attached writer, on a path that runs when a guest
// joins, so the reflection costs nothing that matters.
func checkRemovable(w io.Writer) error {
	if w == nil {
		return errors.New("multiwriter: writer is nil")
	}
	if !reflect.ValueOf(w).Comparable() {
		return fmt.Errorf("multiwriter: writer of type %T is not comparable, so it could never be removed", w)
	}
	return nil
}

func (t *MultiWriter) Remove(writers ...io.Writer) {
	t.membersMu.Lock()
	defer t.membersMu.Unlock()

	// Counts down to zero: the loop used to stop at 1, so whichever writer sat
	// at index 0 could never be removed.
	for i := len(t.writers) - 1; i >= 0; i-- {
		for _, v := range writers {
			if t.writers[i] == v {
				t.writers = append(t.writers[:i], t.writers[i+1:]...)
				break
			}
		}
	}
}

// Write fans p out to every attached writer. It always reports success.
//
// Two things here are deliberate, and both were bugs.
//
// The membership lock is released before any writer is written to. Holding one
// lock for both jobs made Append and Remove wait on whatever the slowest
// attached writer was doing, and a guest that stops reading its SSH channel
// blocks in Write indefinitely once the channel window fills. That wedged the
// host: HandleSession removes its writer on the way out, so Remove blocked,
// HandleSession never returned, and the client-left event it emits on the way
// out was never sent. Writes are still serialized among themselves, by
// writeMu, because concurrent producers must not interleave in a writer or
// race one that is not concurrency safe.
//
// A failing writer is dropped rather than reported. This is a broadcast to
// whoever is attached, and the producer is the host's pty: returning an error
// aborted the io.Copy feeding it, which ended the command and tore down the
// whole session. One guest losing its connection at the wrong moment must not
// take the session with it. Errors used to abandon the rest of the slice too,
// so a broken guest silenced everyone attached after it.
//
// A writer removed between the snapshot and the write still receives this one
// write. That is harmless: it is a session on its way out.
//
// Writers that buffer are what keep this serial loop honest: each attached
// guest is an AsyncWriter, so its Write is a copy and a signal rather than SSH
// I/O, and a guest that cannot keep up overflows and is dropped instead of
// pacing everyone else. The host's own stdout is attached unwrapped only when
// it is a terminal, which is the one place back-pressure belongs: the pty
// should not run ahead of the screen that owns it. A non-terminal stdout is
// wrapped, because a pipe nobody drains would otherwise block here with
// writeMu held and wedge the whole session.
func (t *MultiWriter) Write(p []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	_, _ = t.replay.Write(p)

	t.membersMu.Lock()
	writers := make([]io.Writer, len(t.writers))
	copy(writers, t.writers)
	t.membersMu.Unlock()

	var failed []io.Writer
	for _, w := range writers {
		n, err := w.Write(p)
		if err != nil || n != len(p) {
			failed = append(failed, w)
		}
	}

	// Drop what broke, so the next write does not retry it.
	if len(failed) > 0 {
		t.Remove(failed...)
	}

	return len(p), nil
}

// Shutdown closes the fan-out to new writers and then waits for everything
// already accepted to be delivered.
//
// The two halves are inseparable. Flushing a snapshot alone would leave a
// window: the SSH server keeps serving while the flush runs, so a guest
// attaching after the snapshot has its replay queued into a sink this call will
// never flush, and teardown closes it before delivery. Quiescing under writeMu,
// the same lock Append takes, leaves no such window — an attach is either
// inside the snapshot or refused.
//
// Members that do not buffer are skipped: a synchronous writer is delivered by
// definition. A sink that has already failed flushes to nil, because a guest
// that is already gone is not a shutdown error.
func (t *MultiWriter) Shutdown(ctx context.Context) error {
	t.writeMu.Lock()
	t.closed = true
	t.membersMu.Lock()
	writers := make([]io.Writer, len(t.writers))
	copy(writers, t.writers)
	t.membersMu.Unlock()
	t.writeMu.Unlock()

	var (
		wg   sync.WaitGroup
		errs = make([]error, len(writers))
	)
	for i, w := range writers {
		f, ok := w.(Flusher)
		if !ok {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = f.Flush(ctx)
		}()
	}
	wg.Wait()

	return errors.Join(errs...)
}
