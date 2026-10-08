package io

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	"github.com/owenthereal/upterm/internal/termsize"
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

	// total counts every byte ever appended, so it is the stream offset of
	// the next byte to arrive, and total-size that of the ring's first. A
	// resize's boundary is kept as an offset because a position in the queue
	// moves every time the ring is trimmed.
	total uint64

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

	c.total += uint64(len(p))

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

// End is the stream offset of the next byte the ring is handed.
func (c *buffer) End() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

// Split returns what Data does, cut at the stream offset at: before runs from
// the ring's first byte up to at, and from runs on from it. An offset the ring
// has already evicted puts all of it in from.
func (c *buffer) Split(at uint64) (before, from [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var skip uint64
	if first := c.total - uint64(c.size); at > first {
		skip = at - first
	}
	for i, chunk := range c.queue {
		if skip < uint64(len(chunk)) {
			if skip > 0 {
				before = append(before, chunk[:skip])
			}
			from = append(from, chunk[skip:])
			return before, append(from, c.queue[i+1:]...)
		}
		before = append(before, chunk)
		skip -= uint64(len(chunk))
	}
	return before, nil
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

	// resized is the size the pty last reported, until the fan-out applies
	// it; the zero size is none. sizeMu guards it and nothing else, and is
	// never held across anything, so Resized never waits. See Resized.
	sizeMu  sync.Mutex
	resized termsize.Size

	// size is the pty's size as of the ring's newest byte, and boundary the
	// stream offset from which the ring was recorded at it. The zero size is
	// none: no size has been reported. Both are guarded by writeMu and moved
	// only by applyResize.
	size     termsize.Size
	boundary uint64

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
//
// This is the whole replay, whatever the size it was recorded at, which is
// what a viewer wants. A joiner with a terminal is attached with AppendSized.
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

	t.applyResize()
	if t.closed {
		return ErrClosed
	}

	for _, w := range writers {
		if err := t.replayTo(w, t.modes.Snapshot(), t.buffer.Data()); err != nil {
			return err
		}
	}
	t.attach(writers...)

	return nil
}

// AppendSized attaches w, whose terminal is size, handing it only the replay
// that fits it. A size that isn't Valid is a viewer's, and AppendSized then
// does exactly what Append does.
//
// The replay is weighed against the pty's size as w joins, which is the size
// the ring's newest output was recorded at: the host shrinks the pty to its
// smallest terminal only after the join. A joiner at least as big as the pty
// in both dimensions gets the ring from the last resize on, behind the
// snapshot as of there, which is output recorded at a size its terminal fits.
// A joiner smaller in either dimension is about to shrink the pty and have the
// command repaint at its size, and a replay recorded wider or taller than its
// terminal would wrap and split under that repaint. So it gets the modes as
// they are now and none of the ring. A pty that has never reported a size
// gives neither answer, and the joiner gets what Append gives it.
//
// Attaching is atomic with respect to a Write, as it is for Append.
func (t *MultiWriter) AppendSized(size termsize.Size, w io.Writer) error {
	if err := checkRemovable(w); err != nil {
		return err
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	t.applyResize()
	if t.closed {
		return ErrClosed
	}

	snap, ring := t.sizedReplay(size)
	if err := t.replayTo(w, snap, ring); err != nil {
		return err
	}
	t.attach(w)

	return nil
}

// sizedReplay is the snapshot and the ring bytes AppendSized hands a joiner
// whose terminal is j. Called with writeMu held.
func (t *MultiWriter) sizedReplay(j termsize.Size) ([]byte, [][]byte) {
	p := t.size
	if !j.Valid() || p == (termsize.Size{}) {
		return t.modes.Snapshot(), t.buffer.Data()
	}
	if j.Cols < p.Cols || j.Rows < p.Rows {
		return t.snapshotAfter(t.buffer.Data()), nil
	}

	// A boundary the ring has already evicted leaves all of it recorded at p,
	// and the tracker already describes its first byte.
	before, since := t.buffer.Split(t.boundary)
	if len(before) == 0 {
		return t.modes.Snapshot(), since
	}
	return t.snapshotAfter(before), since
}

// snapshotAfter is the snapshot as of the end of chunks, which run on from the
// ring's first byte. It feeds a clone and never t.modes itself: the tracker
// has to go on describing the ring's first byte for every joiner after this
// one, and only restore may spend it.
//
// chunks can end inside an escape sequence, as the ring's first byte can
// fall inside one. The clone then holds the sequence's head as its partial,
// which its Snapshot replays last, so the head meets the tail that follows it
// on the joiner's terminal. Called with writeMu held.
func (t *MultiWriter) snapshotAfter(chunks [][]byte) []byte {
	m := t.modes.Clone()
	for _, c := range chunks {
		_, _ = m.Write(c)
	}
	return m.Snapshot()
}

// replayTo hands w its replay: snap, the ring bytes it goes with, and the
// lead-in the query filter is still holding. Called with writeMu held.
func (t *MultiWriter) replayTo(w io.Writer, snap []byte, ring [][]byte) error {
	// The snapshot describes the terminal as of ring's first byte, or as of
	// whatever follows when ring is empty, so it has to go immediately in
	// front of that and nowhere else: it can end mid-sequence, where the
	// bytes after it are the rest of that sequence.
	if len(snap) > 0 {
		if _, err := w.Write(snap); err != nil {
			return err
		}
	}
	for _, d := range ring {
		if _, err := w.Write(d); err != nil {
			return err
		}
	}

	// A partial escape sequence the filter is still holding is live output,
	// not history: it is not in the ring yet, so the loop above never sees
	// it. A joiner that misses it would see only the tail once the remainder
	// arrives live, which is garbage on its terminal. Replaying the lead-in
	// lets the joiner's own filter (or terminal) see the sequence whole.
	if pending := t.replay.Pending(); len(pending) > 0 {
		if _, err := w.Write(pending); err != nil {
			return err
		}
	}
	return nil
}

// attach makes writers members of the fan-out, once each has had its replay.
// Called with writeMu held, which is what makes the replay and the attach one
// step to a Write.
func (t *MultiWriter) attach(writers ...io.Writer) {
	t.membersMu.Lock()
	defer t.membersMu.Unlock()
	t.writers = append(t.writers, writers...)
}

// Resized tells the fan-out that the pty is now size. It never waits on
// writeMu.
//
// It only records the size. The pty reports a resize from its Setsize with
// terminalWindows's lock held, and terminalWindows promises its updates never
// block, while Write holds writeMu for as long as a synchronous primary writer
// takes, which for one whose terminal is stopped is indefinitely. So the next
// Write or join to take writeMu applies it instead, before it adds anything to
// the ring; see applyResize.
//
// A size that isn't Valid is ignored. Nothing is drawn at a geometry with no
// columns or no rows, and recorded, it would overwrite a size still waiting to
// be applied. The pty does take one: an ssh -tt guest whose stdin is not a
// terminal asks for a 0x0 window.
func (t *MultiWriter) Resized(size termsize.Size) {
	if !size.Valid() {
		return
	}
	t.sizeMu.Lock()
	defer t.sizeMu.Unlock()
	t.resized = size
}

// applyResize applies the size Resized last recorded, if any. A size other
// than the one recorded moves the boundary to the stream offset of the next
// byte to enter the ring, everything from which is recorded at that size. An
// equal size moves nothing, so a resize and a resize back with no write
// between them make no boundary. Called with writeMu held, at the start of
// Write, Append and AppendSized, so a join weighs the size the pty is now.
func (t *MultiWriter) applyResize() {
	t.sizeMu.Lock()
	size := t.resized
	t.resized = termsize.Size{}
	t.sizeMu.Unlock()

	if size == (termsize.Size{}) || size == t.size {
		return
	}
	t.size = size
	t.boundary = t.buffer.End()
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
// it is a terminal: the pty should not run ahead of the screen that owns it.
// A non-terminal stdout is wrapped, because a pipe nobody drains would
// otherwise block here with writeMu held and wedge the whole session. With no
// primary, a pacer in front of Write holds the pty to the earliest guest's
// drain instead; Write itself still never blocks on a guest.
func (t *MultiWriter) Write(p []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	// Ahead of p, so a resize reported before p was written has p after its
	// boundary.
	t.applyResize()
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
//
// Then each member that wants one (ResetTarget) is sent what puts its terminal
// back where it started -- the modes the session left set, undone -- and
// flushed again. A session can end with its command still holding the
// terminal, killed on the alternate screen with the mouse on, and a guest's
// terminal is not one anything else will put back. A member's reset waits for
// its own first flush: queued behind a tail, it could take a sink that was
// going to drain past its bound, and a sink that overflows is a guest dropped.
// It waits for nothing else, so a guest stuck until the deadline costs the
// others nothing; and one still behind at the deadline loses the reset with
// its tail, as it would have lost the tail anyway. The reset's own flush gets
// ResetFlushTimeout, which may run past ctx's deadline.
func (t *MultiWriter) Shutdown(ctx context.Context) error {
	t.writeMu.Lock()
	first := !t.closed
	t.closed = true
	t.membersMu.Lock()
	writers := make([]io.Writer, len(t.writers))
	copy(writers, t.writers)
	t.membersMu.Unlock()
	var restore []byte
	if first {
		restore = t.restore()
	}
	t.writeMu.Unlock()

	var (
		wg   sync.WaitGroup
		errs = make([]error, len(writers))
	)
	for i, w := range writers {
		f, flushes := w.(Flusher)
		r, resets := w.(ResetTarget)
		resets = resets && len(restore) > 0 && r.WantsReset()
		if !flushes && !resets {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if flushes {
				if errs[i] = f.Flush(ctx); errs[i] != nil {
					return
				}
			}
			if !resets {
				return
			}
			t.writeMu.Lock()
			_, err := w.Write(restore)
			t.writeMu.Unlock()
			if err == nil && flushes {
				// A window of its own, not what is left of ctx's: a guest
				// that took its tail just inside the deadline would get
				// none, and its reset would be closed out of the sink.
				rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ResetFlushTimeout)
				errs[i] = f.Flush(rctx)
				cancel()
			}
		}()
	}
	wg.Wait()

	return errors.Join(errs...)
}

// ResetFlushTimeout bounds how long Shutdown waits for a member's reset to be
// delivered once its tail has been. Shutdown can therefore return this much
// past its context's deadline. A reset is a few hundred bytes at most, but the
// tail may have used up the guest's SSH window, and then the reset waits a
// round trip for the window to open again: so a whole guest flush's bound, the
// one the host gives a guest's tail, not a guess at how fast a small write is.
const ResetFlushTimeout = time.Second

// ResetTarget is implemented by an attached writer that wants the session's
// reset when the fan-out shuts down: one whose far end is a terminal nothing
// else will put back. A guest's is the one -- behind a plain ssh client, which
// restores termios on the way out and nothing more. Every other member is sent
// none: a viewer capturing the output to a file gets what the command wrote,
// and a local client puts its own terminal back. Its Write must not block, as
// an AsyncWriter's does not: Shutdown writes the reset with writeMu held.
type ResetTarget interface {
	WantsReset() bool
}

// restore is what puts a terminal that watched the whole stream back where it
// started. The tracker describes the terminal as of the ring's first byte, so
// it is first brought up to date with the ring, and with the sequence the
// replay filter is still holding, which together are everything sent since.
//
// That spends the tracker: its snapshot no longer describes the ring's start.
// So it runs once, from Shutdown, after which Append refuses every joiner and
// nothing asks for a snapshot again. Called with writeMu held.
func (t *MultiWriter) restore() []byte {
	for _, d := range t.buffer.Data() {
		_, _ = t.modes.Write(d)
	}
	_, _ = t.modes.Write(t.replay.Pending())
	return t.modes.Restore()
}
