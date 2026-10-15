// Package replay reconstructs, for a joining terminal, the screen the
// fan-out's ring drew: it emulates the ring on upterm's fork of x/vt, outside
// every fan-out lock, and renders what the emulator holds. It is io's
// Replayer, and the only upterm package that imports the fork.
package replay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owenthereal/x/ansi"
	"github.com/owenthereal/x/vt"

	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
)

// MaxCells caps the size of any screen a replay emulates (spec E4): 512x256
// is about 15 MB a screen, and a guest can ask for a 65535-column window.
const MaxCells = 1 << 17

// budget is the most a render, and the history it carries, may take:
// io's DefaultReplayBytes. A var for tests.
var budget = uio.DefaultReplayBytes

// piece is the most of the stream one Write hands the emulator (spec E7).
const piece = 4 << 10

// testHookResize, when a test sets it, is called before each resize the
// emulation applies. Nil outside tests.
var testHookResize func(termsize.Size)

// errNoHandoff is a ring that starts inside a sequence and doesn't end it:
// no point in it is one to hand off at.
var errNoHandoff = errors.New("replay: the ring starts inside a sequence it doesn't end")

// errRingStartsInsideALongSequence is a ring whose first byte is inside a
// sequence longer than the tracker keeps.
var errRingStartsInsideALongSequence = errors.New("replay: the ring starts inside a sequence too long to prime")

// errNoRender is what Render returns once the emulation is consistent, until
// the render is built.
var errNoRender = errors.New("replay: the render isn't built")

// New returns the replayer the host installs in its fan-out. It logs
// nothing: io tells the fan-out's fallback callback why a join fell back.
func New() uio.Replayer { return replayer{} }

type replayer struct{}

// emulation is one join's emulation of the stream, from the ring's first
// byte to a handoff point that moves on as the stream is fed.
//
// It consumes the stream in batches, each ending where the emulator's parser
// is outside every sequence and carries no cluster a later byte could extend
// (spec E7, A13): there, and only there, the render and the raw gap after it
// add up to the stream. What follows the last such point, its bytes and the
// events among them, waits unconsumed in the tail.
type emulation struct {
	term  *vt.Emulator
	modes *uio.ModeTracker // the tracker clone, fed exactly what term is
	join  termsize.Size    // the joiner's terminal, which must contain the render's (spec E1)
	size  termsize.Size    // term's, the size of the last event passed
	stop  func() bool      // ctx or the deadline, for the meter and the encoder
	hist  history
	title string

	// The handoff point: the end of what the emulator consumed, and the last
	// event it passed, applied or skipped as a no-op.
	h, lastSeq uint64
	// tail is what was offered past h: bytes the emulator hasn't consumed,
	// a copy, since the lookahead needs them in one piece.
	tail []byte
	// events are the committed events offered and not yet passed, in Seq
	// order, each at or after h.
	events []uio.SizeEvent
	// offeredSeq is the last event offered.
	offeredSeq uint64

	// err spends the emulation: every Feed and Render returns it.
	err error
}

// Start emulates c for a joiner whose terminal is size: from the state the
// tracker clone holds as of the ring's first byte, through the ring, as far
// as a handoff point (rules 1 and 2).
func (replayer) Start(ctx context.Context, deadline time.Time, c *uio.Capture, size termsize.Size) (uio.Emulation, error) {
	if len(c.Sizes) == 0 {
		return nil, uio.ErrReplayCoverage
	}
	for _, s := range c.Sizes {
		if err := validSize(s.Size); err != nil {
			return nil, err
		}
	}
	end := c.Start
	for _, chunk := range c.Chunks {
		end += uint64(len(chunk))
	}
	first := c.Sizes[0]
	if err := placed(c.Sizes[1:], first.Seq, c.Start, end); err != nil {
		return nil, err
	}

	e := &emulation{
		term:       vt.NewEmulator(first.Size.Cols, first.Size.Rows),
		modes:      c.Modes,
		join:       size,
		size:       first.Size,
		hist:       history{max: budget},
		h:          c.Start,
		lastSeq:    first.Seq,
		offeredSeq: first.Seq,
	}
	e.stop = func() bool { return ctx.Err() != nil || !time.Now().Before(deadline) }
	e.setUp()

	// Priming (spec E6): the tracker clone is already in the state it
	// describes, a sequence the ring starts inside included, so only the
	// emulator is told.
	if _, err := e.term.Write(c.Modes.Snapshot()); err != nil {
		return nil, stopped(err)
	}
	// Both are now inside the sequence the ring starts in, if it starts in
	// one, or neither is. But the tracker keeps a sequence's bytes only up to
	// its bound (a string's 4 KiB, a CSI's 64 bytes), and past it has none to
	// prime with: the emulator, outside the sequence, would print its rest as
	// text. An OSC 52 copy in flight at the ring's start is enough, so this is
	// the tracker's bound, not a disagreement. The emulator inside a sequence
	// the tracker isn't is one: the two parsers read the snapshot apart.
	switch inTracker, inEmulator := !e.modes.AtGround(), !e.term.AtBoundary(); {
	case inTracker && !inEmulator:
		return nil, errRingStartsInsideALongSequence
	case inEmulator && !inTracker:
		return nil, fmt.Errorf("%w: at the ring's first byte", ErrTrackerDisagrees)
	}
	if err := e.offer(c.Chunks, c.Sizes[1:]); err != nil {
		return nil, err
	}
	return e, nil
}

// setUp makes the emulator a replay's (spec E5): no scrollback on either
// screen, the history kept through the scroll-off function instead, replies
// to queries discarded, the title kept, and the meter stopped by ctx or the
// deadline. Each callback runs inside the emulator's Write and touches only
// the emulation.
func (e *emulation) setUp() {
	t := e.term
	t.SetScrollbackSize(0)
	// The alternate screen has a scrollback of its own, which the main
	// screen's size leaves at 10,000 lines (spec A25).
	t.AltScreen().SetScrollback(nil)
	t.SetScrollOffFunc(e.hist.push)
	t.SetScrollbackClearFunc(e.hist.clear)
	t.SetReplyFunc(func([]byte) {})
	t.SetCallbacks(vt.Callbacks{Title: func(title string) { e.title = title }})
	t.SetStopFunc(func() bool { return e.stop() })
}

// Feed offers the emulation more of the stream and runs on to the next
// handoff point it can reach (rule 4). Every event offered is validated
// before anything else, so a size over the cap allocates nothing (spec A1).
func (e *emulation) Feed(chunks [][]byte, sizes []uio.SizeEvent) error {
	if e.err != nil {
		return e.err
	}
	for _, s := range sizes {
		if err := validSize(s.Size); err != nil {
			e.err = err
			return err
		}
	}
	from := e.h + uint64(len(e.tail))
	end := from
	for _, chunk := range chunks {
		end += uint64(len(chunk))
	}
	if err := placed(sizes, e.offeredSeq, from, end); err != nil {
		e.err = err
		return err
	}
	return e.offer(chunks, sizes)
}

// validSize fails a size no emulation can be at: one that isn't a size, or
// is over the cap. The product is taken in 64 bits, where two valid
// dimensions can't overflow it, as they can a 32-bit int.
func validSize(s termsize.Size) error {
	switch {
	case !s.Valid():
		return uio.ErrReplayCoverage
	case int64(s.Cols)*int64(s.Rows) > MaxCells:
		return ErrSizeCap
	}
	return nil
}

// placed fails events that can't be placed in the stream offered from from
// to end: each after the last offered, by Seq, and in order within it. io
// offers nothing else; this keeps a mistake there from being emulated.
func placed(events []uio.SizeEvent, afterSeq, from, end uint64) error {
	for _, ev := range events {
		if ev.Seq <= afterSeq || ev.Offset < from || ev.Offset > end {
			return fmt.Errorf("%w: event %d at %d, offered after %d in [%d, %d]",
				uio.ErrReplayCoverage, ev.Seq, ev.Offset, afterSeq, from, end)
		}
		afterSeq, from = ev.Seq, ev.Offset
	}
	return nil
}

// offer adds chunks and events, already validated, to what waits in the
// tail, and runs a batch. A failure spends the emulation.
func (e *emulation) offer(chunks [][]byte, sizes []uio.SizeEvent) error {
	for _, chunk := range chunks {
		e.tail = append(e.tail, chunk...)
	}
	e.events = append(e.events, sizes...)
	if len(sizes) > 0 {
		e.offeredSeq = sizes[len(sizes)-1].Seq
	}
	x, n, err := e.batchEnd()
	if err == nil {
		err = e.consume(x, n)
	}
	if err != nil {
		e.err = err
		return err
	}
	return nil
}

// batchEnd finds where the next batch ends: the furthest offset x at which
// the parser, continuing from where h left it, is outside every sequence and
// no cluster is carried (rule 2, spec A13). That is the larger of two: the
// end of the last action in the tail that isn't a print; and the latest
// event that changes the size and at which the parser is outside every
// sequence, since that resize, applied at the batch's end, closes any
// cluster. An event of the size already in effect is skipped, so it closes
// nothing and is no candidate.
//
// n is how many of the events waiting the batch passes: every one at or
// before x.
//
// The lookahead runs outside the emulator's meter. Each pass is one scan of
// the tail, but a candidate before the end of the tail's ground prefix needs
// a scan of its own, of the tail up to it, and there can be one per event:
// about 1,024 scans of 256 KiB, for events inside a span that ends with no
// closure (a string CAN aborts, then text). So the stop function is asked
// before each, which bounds the overshoot past the deadline to one scan
// (spec §6.2).
func (e *emulation) batchEnd() (x uint64, n int, err error) {
	x = e.h + uint64(e.term.HandoffPrefix(e.tail))
	ground := -1 // the longest prefix of the tail at ground, once needed
	for i := len(e.events) - 1; i >= 0; i-- {
		ev := e.events[i]
		if ev.Offset <= x {
			break
		}
		before := e.size
		if i > 0 {
			before = e.events[i-1].Size
		}
		if ev.Size == before {
			continue
		}
		if ground < 0 {
			ground = e.term.GroundPrefix(e.tail)
		}
		// The parser is at ground after the tail's first k bytes, k > 0,
		// exactly when GroundPrefix of them is k; and no prefix longer than
		// ground ends there. (Of the empty prefix it can't tell, as it is 0
		// both at ground and where no prefix reaches it; but a candidate is
		// past x, which is h at least.)
		k := int(ev.Offset - e.h)
		if k > ground {
			continue
		}
		if k < ground {
			if e.stop() {
				return 0, 0, uio.ErrReplayDeadline
			}
			if e.term.GroundPrefix(e.tail[:k]) != k {
				continue
			}
		}
		x = ev.Offset
		break
	}
	for n < len(e.events) && e.events[n].Offset <= x {
		n++
	}
	return x, n, nil
}

// consume runs the batch from h to x, passing the first n events waiting,
// and publishes x as the handoff point once the batch is whole and both
// parsers are where a handoff point needs them. Bytes and events go in stream
// order: up to an event's offset, then the event, then on. A batch may write
// up to an event inside a sequence, and resize there, as the stream's own
// terminal did (spec E7, revision 3); only its end must be outside one.
func (e *emulation) consume(x uint64, n int) error {
	pos, size := 0, e.size
	for _, ev := range e.events[:n] {
		k := int(ev.Offset - e.h)
		if err := e.write(e.tail[pos:k]); err != nil {
			return err
		}
		pos = k
		// The same size again is a no-op the terminal never saw as a
		// resize, and applying it would reset the margins and the tab stops.
		if ev.Size != size {
			e.resize(ev.Size)
			size = ev.Size
		}
	}
	if err := e.write(e.tail[pos : x-e.h]); err != nil {
		return err
	}
	// A stop inside the last resize leaves no error behind but a spent
	// emulator, which only a Write reports (PF-11).
	if _, err := e.term.Write(nil); err != nil {
		return stopped(err)
	}
	// Every x past h is outside every sequence, so only a batch that
	// consumed nothing ends inside one: the first, at a ring that starts
	// inside a sequence it doesn't end. io can't wait for the rest from here,
	// so the join falls back.
	if !e.term.AtBoundary() {
		return errNoHandoff
	}
	if !e.modes.AtGround() {
		return fmt.Errorf("%w: the tracker is inside a sequence at %d", ErrTrackerDisagrees, x)
	}
	if e.term.Carrying() {
		return fmt.Errorf("%w: at %d", ErrHandoffInvariant, x)
	}

	if n > 0 {
		e.lastSeq = e.events[n-1].Seq
	}
	e.size = size
	e.tail = e.tail[x-e.h:]
	e.events = e.events[n:]
	e.h = x
	return nil
}

// write hands p to the emulator, in pieces, and to the tracker clone.
func (e *emulation) write(p []byte) error {
	_, _ = e.modes.Write(p)
	for len(p) > 0 {
		k := min(len(p), piece)
		if _, err := e.term.Write(p[:k]); err != nil {
			return stopped(err)
		}
		p = p[k:]
	}
	return nil
}

// resize applies a committed event to the emulator and to the tracker clone,
// which resets its margins as the terminal does.
func (e *emulation) resize(size termsize.Size) {
	if testHookResize != nil {
		testHookResize(size)
	}
	e.term.Resize(size.Cols, size.Rows)
	e.modes.Resized(size)
}

// stopped says why a Write failed: the meter's stop is the deadline or ctx,
// which io reports as the deadline (rule 3).
func stopped(err error) error {
	if errors.Is(err, vt.ErrStopped) {
		return uio.ErrReplayDeadline
	}
	return err
}

// Handoff is the point the render reconstructs.
func (e *emulation) Handoff() (offset, lastSeq uint64) {
	return e.h, e.lastSeq
}

// Render is the reconstruction as of Handoff, once the tracker clone and the
// emulator agree on what both track (rule 6).
func (e *emulation) Render() ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	if err := e.consistent(); err != nil {
		e.err = err
		return nil, err
	}
	return nil, errNoRender
}

// consistent checks that the tracker clone and the emulator agree, at the
// handoff point, on the screen showing and on each DEC mode the tracker
// tracks, either way (spec E10, PF-10). They are two parsers of one stream,
// and a render built from both would otherwise contradict itself.
func (e *emulation) consistent() error {
	p := e.modes.ReplayParts()
	if alt := p.AltVia != 0; alt != e.term.IsAltScreen() {
		return fmt.Errorf("%w: the tracker's alternate screen showing is %v", ErrTrackerDisagrees, alt)
	}
	for n, set := range p.DECModes {
		if e.term.Mode(ansi.DECMode(n)).IsSet() != set {
			return fmt.Errorf("%w: the tracker's mode ?%d set is %v", ErrTrackerDisagrees, n, set)
		}
	}
	return nil
}
