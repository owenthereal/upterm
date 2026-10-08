package io

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
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

// Start is the stream offset of the ring's first byte, or, while it holds
// none, of the next byte it is handed.
func (c *buffer) Start() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total - uint64(c.size)
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

// ringWriter adapts the replay ring to io.Writer so a filter can sit in front
// of it. Only ever written to by the filter, under writeMu; see record.
type ringWriter struct{ t *MultiWriter }

func (w ringWriter) Write(p []byte) (int, error) {
	w.t.record(p)
	return len(p), nil
}

// redrawScanner reads the bytes entering the ring for vertical cursor
// movement, which is what makes a stretch of them a redraw; see boundary. It
// is no parser: it only has to find a CSI's final byte, and ESC M, so it keeps
// only where it is in a sequence. That carries from one write to the next, so
// a sequence the ring receives in two halves is still seen.
//
// A string sequence -- an OSC, a DCS -- needs no state of its own. Its payload
// holds no ESC but the one that ends it, as a terminal reads it: ESC \ is its
// terminator, and an ESC before anything else abandons it and opens a new
// sequence, which is what this reads it as too. Read as text, then, the
// payload is text, and a title that spells "[H" moves nothing.
type redrawScanner struct{ state redrawState }

type redrawState int

const (
	rsText redrawState = iota // outside any sequence
	rsEsc                     // after an ESC
	rsCSI                     // inside a CSI, before its final byte
)

// verticalFinals are the final bytes of the CSIs that move the cursor up or
// down, or the screen under it, whatever their parameters: CUU, CUD, CNL,
// CPL, CUP, HVP, VPA, SU, SD, and DECSTBM, which homes the cursor.
const verticalFinals = "ABEFHfdSTr"

// scan reports whether p ends a sequence that moves the cursor vertically:
// one of verticalFinals' CSIs, or ESC M, reverse index.
func (s *redrawScanner) scan(p []byte) bool {
	redraws := false
	for _, b := range p {
		switch {
		case b == 0x1b:
			// From anywhere: an ESC abandons a CSI, and ESC ESC starts over.
			s.state = rsEsc
		case b == 0x18 || b == 0x1a:
			// CAN and SUB cancel whatever sequence is in progress.
			s.state = rsText
		case s.state == rsEsc:
			switch b {
			case '[':
				s.state = rsCSI
			case 'M':
				redraws = true
				s.state = rsText
			default:
				s.state = rsText
			}
		case s.state == rsCSI && b >= 0x40 && b <= 0x7e:
			if strings.ContainsRune(verticalFinals, rune(b)) {
				redraws = true
			}
			s.state = rsText
		}
	}
	return redraws
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

	t := &MultiWriter{
		writers: writers,
		buffer:  b,
		modes:   modes,
	}
	t.replay = NewTerminalQueryFilter(ringWriter{t: t})
	return t
}

// ErrClosed is returned by Append and AppendSized once Shutdown has run. A
// guest that reaches the door as the session is ending is refused rather than
// attached to a fan-out nothing will flush again.
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

	// boundaries are the sizes the ring was recorded at, oldest first. Each
	// holds from its offset to the next one's, and the newest, whose size is
	// the pty's as of the ring's newest byte, to the ring's end. Bytes before
	// the oldest were recorded before any size was reported, or at a size the
	// cap has since dropped: unsized says which. Empty is no size reported.
	// Guarded by writeMu, and moved only by applyResize and prune; record
	// marks the newest a redraw.
	boundaries []boundary

	// unsized is the stream offset before which the bytes were recorded at a
	// size the cap has dropped. Any of them still in the ring fit no joiner.
	// Guarded by writeMu.
	unsized uint64

	// scanner reads what enters the ring for vertical cursor movement, and
	// leadRedraws is whether the bytes written before the first boundary had
	// any. Guarded by writeMu.
	scanner     redrawScanner
	leadRedraws bool

	// closed is guarded by writeMu, so Shutdown's quiesce and a concurrent
	// Append cannot interleave: an attach in progress either completes before
	// the snapshot and is flushed, or finds this set and is refused.
	closed bool
}

// boundary is a stream offset from which the ring was recorded at size, up to
// the next boundary. redraws is whether the bytes entering the ring over that
// stretch move the cursor vertically, which is what replaying them at another
// size can garble. Plain output only wraps, and wraps afresh on whatever
// terminal it is replayed onto. A redraw moves the cursor over lines as they
// wrapped at the size it was drawn at, and on a terminal where they wrap
// otherwise it lands on the wrong ones.
type boundary struct {
	offset  uint64
	size    termsize.Size
	redraws bool
}

// maxBoundaries caps the sizes the fan-out remembers, against a window
// dragged across a screen with output between every step. Past it the oldest
// is dropped, and the bytes recorded at it fit no joiner: they could have been
// recorded at any size.
const maxBoundaries = 64

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
// that renders on it as it was drawn. A size that isn't Valid is a viewer's,
// and AppendSized then does exactly what Append does.
//
// Plain output replays at any size: it only wraps, and wraps afresh on the
// joiner's terminal. A redraw, output that moves the cursor vertically, does
// not (see boundary), so the sizes matter only from the newest redraw back.
// The joiner gets the longest stretch, back from the ring's end, in which
// every redraw renders as drawn, behind the snapshot as of the stretch's
// first byte. The newest redraw in it was recorded at a size that fits the
// joiner, no wider and no taller, and from it back the size never shrank:
// each earlier size, plain or not, fits the one after it, so every one fits
// the joiner. Output recorded before a growth renders the same at the larger
// size, because nothing in it wrapped at the smaller one. Output recorded
// before a shrink does not: the command's repaint at the smaller size moves
// the cursor relative to a screen on which the earlier lines wrapped, and
// replayed onto a wider terminal, where they don't, it lands on top of them.
// A redraw recorded wider or taller than the joiner would wrap and split on
// its terminal, under the repaint its arrival brings once it shrinks the pty,
// so the replay starts after it: with only that redraw in the ring's newest
// stretch, the joiner gets the modes as they are now and none of the ring. A
// pty that has never reported a size gives no answer, and the joiner gets what
// Append gives it.
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
	if !j.Valid() || len(t.boundaries) == 0 {
		return t.modes.Snapshot(), t.buffer.Data()
	}

	// An offset the ring has already evicted puts all of it in since, and the
	// tracker already describes its first byte. The ring's end puts all of it
	// in before, and the snapshot is then the modes as they are now.
	before, since := t.buffer.Split(t.replayFrom(j))
	if len(before) == 0 {
		return t.modes.Snapshot(), since
	}
	return t.snapshotAfter(before), since
}

// replayFrom is the stream offset sizedReplay replays from: where the
// earliest stretch the walk back from the ring's end takes begins. Called with
// writeMu held, and with at least one boundary.
//
// Until the walk meets a redraw, it takes each stretch whatever its size. The
// first redraw it meets has to fit j, and from there on the walk is
// constrained: each earlier stretch, plain or not, has to fit the one after
// it, since the redraw's cursor moves depend on how everything before it
// wrapped. It stops before the first stretch that doesn't, and at bytes whose
// size it doesn't know: those recorded at a size the cap dropped, whose flag
// went with it, and those written before any size was reported, unless they
// are plain and the walk is not constrained, the one case their size doesn't
// matter.
func (t *MultiWriter) replayFrom(j termsize.Size) uint64 {
	from := t.buffer.End()
	constrained := false
	for k := len(t.boundaries) - 1; k >= 0; k-- {
		b := t.boundaries[k]
		switch {
		case constrained:
			if !fits(b.size, t.boundaries[k+1].size) {
				return from
			}
		case b.redraws:
			if !fits(b.size, j) {
				return from
			}
			constrained = true
		}
		from = b.offset
	}
	if constrained || t.leadRedraws || t.unsized > t.buffer.Start() {
		return from
	}
	return 0
}

// fits reports whether a redraw recorded at size renders on a terminal of j as
// it was drawn: it is no wider and no taller. Asked of a recorded size and the
// one after it, it reports that the size did not shrink between them.
func fits(size, j termsize.Size) bool {
	return size.Cols <= j.Cols && size.Rows <= j.Rows
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
// It only records the size. The pty reports a resize from its Setsize, which
// runs with a lock held: terminalWindows's, whose updates promise never to
// block, or sharedPTY.mu, which sharedPTY.set holds while it applies a size
// offered before the pty existed. Write holds writeMu for as long as a
// synchronous primary writer takes, which for one whose terminal is stopped
// is indefinitely. So the next Write or join to take writeMu applies it
// instead, before it adds anything to the ring; see applyResize.
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

// record appends p, what the replay filter passed, to the ring. If p moves the
// cursor vertically, the stretch it lands in is a redraw: the newest
// boundary's, or, before any size was reported, the bytes written before the
// first. A sequence p only finishes counts where its final byte lands, since
// that is where the cursor moves. Called with writeMu held, from Write, after
// applyResize: everything in p is recorded at the newest boundary's size.
func (t *MultiWriter) record(p []byte) {
	if t.scanner.scan(p) {
		if n := len(t.boundaries); n > 0 {
			t.boundaries[n-1].redraws = true
		} else {
			t.leadRedraws = true
		}
	}
	t.buffer.Append(p)
}

// applyResize applies the size Resized last recorded, if any. A size other
// than the newest boundary's adds a boundary at the stream offset of the next
// byte to enter the ring, everything from which is recorded at that size. An
// equal size adds nothing, so a resize and a resize back with no write between
// them make no boundary. Called with writeMu held, at the start of Write,
// Append and AppendSized. A size applied at a join has nothing recorded at it
// yet, so it weighs nothing in that join's replay.
//
// A newest boundary nothing was written after holds no bytes, so the new size
// replaces it rather than following it: kept, it would be a size the walk back
// could stop at with nothing recorded at it, and would cut a joiner's replay
// off there. Two joins before the command writes anything leave one: the first
// joiner's size is applied at the second's join, and the second's own size
// follows before any output. Holding no bytes, it held no redraw either, so
// the size that replaces it starts out plain, as any new boundary does.
func (t *MultiWriter) applyResize() {
	t.sizeMu.Lock()
	size := t.resized
	t.resized = termsize.Size{}
	t.sizeMu.Unlock()

	if size == (termsize.Size{}) || size == t.newestSize() {
		return
	}
	end := t.buffer.End()
	if n := len(t.boundaries); n > 0 && t.boundaries[n-1].offset == end {
		t.boundaries = t.boundaries[:n-1]
		if size == t.newestSize() {
			return
		}
	}
	t.boundaries = append(t.boundaries, boundary{offset: end, size: size})
	if len(t.boundaries) > maxBoundaries {
		t.boundaries = t.boundaries[1:]
		t.unsized = t.boundaries[0].offset
	}
}

// newestSize is the newest boundary's size, the pty's as of the ring's newest
// byte, or the zero size if none has been reported. Called with writeMu held.
func (t *MultiWriter) newestSize() termsize.Size {
	if n := len(t.boundaries); n > 0 {
		return t.boundaries[n-1].size
	}
	return termsize.Size{}
}

// prune forgets the sizes of bytes the ring has evicted. A boundary goes once
// the next one starts at or before the ring's first byte; the one that covers
// that byte stays, as the size it was recorded at. Its redraw flag stays with
// it, and may have been set by bytes since evicted: that errs towards a redraw,
// which costs a joiner some replay but never garbles it. Called with writeMu
// held, after the ring is fed.
func (t *MultiWriter) prune() {
	first := t.buffer.Start()
	i := 0
	for i+1 < len(t.boundaries) && t.boundaries[i+1].offset <= first {
		i++
	}
	t.boundaries = t.boundaries[i:]
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
	t.prune()

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
// So it runs once, from Shutdown, after which Append and AppendSized refuse
// every joiner and nothing asks for a snapshot again. Called with writeMu
// held.
func (t *MultiWriter) restore() []byte {
	for _, d := range t.buffer.Data() {
		_, _ = t.modes.Write(d)
	}
	_, _ = t.modes.Write(t.replay.Pending())
	return t.modes.Restore()
}
