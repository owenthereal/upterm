// Package replay reconstructs, for a joining terminal, the screen the
// fan-out's ring drew: it emulates the ring on upterm's fork of x/vt, outside
// every fan-out lock, and renders what the emulator holds. It is io's
// Replayer, and the only upterm package that imports the fork.
package replay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/owenthereal/x/ansi"
	"github.com/owenthereal/x/vt"

	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
)

// MaxCells caps the size of any screen a replay emulates: 512x256 is about
// 15 MB a screen, and a guest can ask for a 65535-column window.
const MaxCells = 1 << 17

// budget is the most a render, and the history it carries, may take:
// io's DefaultReplayBytes. A var for tests.
var budget = uio.DefaultReplayBytes

// piece is the most of the stream one Write hands the emulator.
const piece = 4 << 10

// testHookResize, when a test sets it, is called before each resize the
// emulation applies. Nil outside tests.
var testHookResize func(termsize.Size)

// errNoHandoff is a ring that starts inside a sequence with no handoff
// point after it: the sequence doesn't end, or it ends by CAN or SUB, or as a
// CSI the parser ignores, which close no cluster, with nothing after it that
// does.
var errNoHandoff = errors.New("replay: the ring starts inside a sequence with no handoff point after it")

// errRingStartsInsideALongSequence is a ring whose first byte is inside a
// sequence longer than the tracker keeps.
var errRingStartsInsideALongSequence = errors.New("replay: the ring starts inside a sequence too long to prime")

// New returns the replayer the host installs in its fan-out. It logs
// nothing: io tells the fan-out's fallback callback why a join fell back.
func New() uio.Replayer { return replayer{} }

type replayer struct{}

// emulation is one join's emulation of the stream, from the ring's first
// byte to a handoff point that moves on as the stream is fed.
//
// It consumes the stream in batches, each ending where the emulator's parser
// is outside every sequence and carries no cluster a later byte could
// extend: there, and only there, the render and the raw gap after it add up
// to the stream. What follows the last such point, its bytes and the
// events among them, waits unconsumed in the tail.
type emulation struct {
	term  *vt.Emulator
	modes *uio.ModeTracker // the tracker clone, fed exactly what term is
	join  termsize.Size    // the joiner's terminal, which must contain the render's
	size  termsize.Size    // term's, the size of the last event passed
	stop  func() bool      // ctx or the deadline, for the meter and the encoder
	hist  history
	enc   encoder

	// title is the window title the stream last set, by OSC 0 or OSC 2, and
	// titled whether it set one at all: an empty title clears the joiner's,
	// as the raw ring would, where a stream that set none leaves it.
	title  string
	titled bool
	// cwd is the working directory the stream last reported, by OSC 7, and
	// cwdTold whether it reported one at all, as title and titled are.
	cwd     string
	cwdTold bool
	// colours is what the stream changed of the terminal's colours.
	colours colours
	// graphics is set once the stream has drawn an image (see watchGraphics).
	graphics bool
	// dcs is set once the stream has sent a device control string (see
	// watchDCS).
	dcs bool
	// clips are the stream's clipboard writes still in force.
	clips clipboard
	// protected is set once the stream has turned character protection on,
	// and selective once it has erased selectively (see watchProtection).
	protected, selective bool
	// savedTitle is set once the stream has pushed a title (see watchSaves).
	savedTitle bool

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
// as a handoff point.
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

	// Priming: the tracker clone is already in the state it
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

// setUp makes the emulator a replay's: no scrollback on either
// screen, the history kept through the scroll-off function instead, replies
// to queries discarded, the title, the working directory, the colours and the
// clipboard kept, images, device control strings, character protection,
// selective erases and saves noted, and the meter stopped by ctx or the
// deadline. Each callback and handler runs inside the emulator's Write and
// touches only the emulation.
func (e *emulation) setUp() {
	t := e.term
	t.SetScrollbackSize(0)
	// The alternate screen has a scrollback of its own, which the main
	// screen's size leaves at 10,000 lines: about 600 MiB at 512 columns.
	t.AltScreen().SetScrollback(nil)
	t.SetScrollOffFunc(e.hist.push)
	t.SetScrollbackClearFunc(e.hist.clear)
	t.SetReplyFunc(func([]byte) {})
	t.SetCallbacks(vt.Callbacks{
		Title: func(title string) { e.title, e.titled = title, true },
		// x/vt keeps the directory too, as this string, which keeping it here
		// doesn't copy: it is what follows the OSC's first ';', as the stream
		// sent it, and an OSC 7 without one reports nothing.
		WorkingDirectory: func(dir string) { e.cwd, e.cwdTold = dir, true },
	})
	t.SetStopFunc(func() bool { return e.stop() })
	e.watchColours()
	e.watchGraphics()
	e.watchDCS()
	e.watchClipboard()
	e.watchProtection()
	e.watchSaves()
}

// colours is what the stream changed, by OSC, of the colours a terminal keeps
// until they are reset, which the render doesn't restore: a raw replay
// carries them to the joiner, and a render without them leaves the joiner
// drawing in its own.
//
// x/vt keeps the default foreground, background and cursor colours, but only
// those its colour parser reads, which takes no X11 colour name such as
// "navy", and only from an OSC that sets one of them; it keeps no palette
// from the stream at all. So the stream's OSCs are read here instead. A
// palette entry or a special colour (OSC 4 or 5) counts once set, a reset
// after it included: telling which entries a reset (OSC 104 or 105) puts
// back would take keeping the palette. Each of xterm's ten dynamic colours,
// OSC 10 to 19, the default foreground, background and cursor colours among
// them, counts from a setting to its own reset, OSC 110 to 119.
type colours struct {
	palette bool
	dynamic [10]bool
}

// changed reports a colour the stream set and hasn't reset.
func (c *colours) changed() bool {
	return c.palette || slices.Contains(c.dynamic[:], true)
}

// watchColours registers the OSC handlers that keep colours. The last
// handler registered for an OSC is called first, so each of these is called
// before x/vt's own, and returns false, so that x/vt's still handles the OSC.
func (e *emulation) watchColours() {
	t := e.term
	for _, cmd := range []int{4, 5} {
		t.RegisterOscHandler(cmd, func([]byte) bool {
			e.colours.palette = true
			return false
		})
	}
	for i := range e.colours.dynamic {
		t.RegisterOscHandler(10+i, func(data []byte) bool {
			// After the number, each specification sets the next colour on,
			// as in xterm, so OSC 10 ; fg ; bg sets the background too. Each
			// one counts: the query filter drops an OSC that asks for any.
			n := bytes.Count(data, []byte{';'})
			for k := i; k < min(i+n, len(e.colours.dynamic)); k++ {
				e.colours.dynamic[k] = true
			}
			return false
		})
		t.RegisterOscHandler(110+i, func([]byte) bool {
			e.colours.dynamic[i] = false
			return false
		})
	}
}

// watchGraphics registers the handlers that note an image the stream drew: a
// sixel (DCS q), a kitty graphics command (an APC whose first byte is G), or
// an iTerm2 inline image (OSC 1337 File=, or its multipart form, which starts
// with MultipartFile=). x/vt draws none of them, so the render has no image to
// send, where a raw replay carries each to the joiner. Of these, the query
// filter drops only kitty's query, a=q. x/vt keys a DCS handler by the
// sequence's prefix, intermediate and final byte, so the sixel's, for a bare
// q, sees neither DECRQSS ($ q) nor XTGETTCAP (+ q). x/vt has no handler of
// its own for any of these; each returns false all the same, as
// watchColours' do.
func (e *emulation) watchGraphics() {
	t := e.term
	t.RegisterDcsHandler('q', func(ansi.Params, []byte) bool {
		e.graphics = true
		return false
	})
	t.RegisterApcHandler(func(data []byte) bool {
		if bytes.HasPrefix(data, []byte("G")) {
			e.graphics = true
		}
		return false
	})
	t.RegisterOscHandler(1337, func(data []byte) bool {
		_, arg, _ := bytes.Cut(data, []byte{';'})
		if bytes.HasPrefix(arg, []byte("File=")) || bytes.HasPrefix(arg, []byte("MultipartFile=")) {
			e.graphics = true
		}
		return false
	})
}

// watchDCS registers a handler, under every key x/vt's parser can dispatch a
// DCS by, that notes the stream sent one. x/vt has no DCS handler of its own,
// so it drops each one, where a raw replay carries it to the joiner's
// terminal, which acts on it: a tmux passthrough, which a joiner running in
// tmux hands on to the terminal tmux runs in, DECUDK's keys, DECDLD's soft
// font, ReGIS. Of the DCS a program sends, the query filter drops only the
// requests, DECRQSS, XTGETTCAP and XTGETXRES, before the ring. A sixel is one
// too, which watchGraphics also notes.
//
// Synchronized output's DCS form, DCS = 1 s and DCS = 2 s, which begins and
// ends an update, isn't noted: like ?2026, which the render ignores (see
// ignoredModes), it only holds back the drawing. Its key gets a handler of its
// own, which notes anything else sent under it.
//
// The key is the DCS's prefix, its last intermediate and its final byte. The
// parser takes a prefix only as the first byte, one of < = > ?, and after an
// intermediate any byte from 0 on as the final (a DEC terminal ignores such a
// string). A C0 control or an ESC as the first byte makes the key 0: x/vt
// keeps it and what follows as the string's data, up to the next ESC, where a
// DEC terminal ignores the C0, or ends the string at that first ESC, and reads
// what follows as it comes, so the two read those bytes apart. That is 6,636
// keys, registered in well under a millisecond.
func (e *emulation) watchDCS() {
	t := e.term
	note := func(ansi.Params, []byte) bool {
		e.dcs = true
		return false
	}
	sync := ansi.Command('=', 0, 's')
	t.RegisterDcsHandler(sync, func(params ansi.Params, data []byte) bool {
		if n, _, _ := params.Param(0, 0); len(params) != 1 || n != 1 && n != 2 || len(data) != 0 {
			e.dcs = true
		}
		return false
	})
	t.RegisterDcsHandler(0, note)
	for _, prefix := range []byte{0, '<', '=', '>', '?'} {
		for final := byte(0x40); final <= 0x7e; final++ {
			if cmd := ansi.Command(prefix, 0, final); cmd != sync {
				t.RegisterDcsHandler(cmd, note)
			}
		}
		for inter := byte(0x20); inter <= 0x2f; inter++ {
			for final := byte(0x30); final <= 0x7e; final++ {
				t.RegisterDcsHandler(ansi.Command(prefix, inter, final), note)
			}
		}
	}
}

// clipboard is what the stream wrote to the terminal's selections, by OSC 52,
// that is still in force. A raw replay hands the joiner every write in the
// ring, in order; the render sends, in the stream's order, each one that is
// still the last write to some selection, and leaves out the others, so the
// joiner's selections end as the raw replay leaves them.
//
// The selections are xterm's: OSC 52 ; Pc ; Pd writes Pd to each selection Pc
// names, c, p, q, s and the cut buffers 0 to 7, and an empty Pc names s and 0;
// a character xterm has no selection for names nothing. A Pd that isn't
// base64 clears the selections instead, which the joiner's terminal does as
// well when it is sent the same write, so the two needn't be told apart. A Pd
// of ? asks for a selection, which the query filter drops, and an OSC 52 with
// no ';' after Pc does nothing.
type clipboard []clipWrite

// clipWrite is a clipboard write still in force.
type clipWrite struct {
	// sel is the selections it is the last write to, a bit for each, by its
	// index in selections.
	sel    uint16
	pc, pd string // as the stream sent them
	// over is a write longer than any render may be, whose bytes aren't kept.
	over bool
}

// selections are xterm's, in the order clipWrite.sel indexes them.
const selections = "cpqs01234567"

// write records a write of pd to the selections pc names, which no earlier
// write is the last to any more.
func (c *clipboard) write(pc, pd []byte) {
	names := pc
	if len(names) == 0 {
		names = []byte("s0")
	}
	var sel uint16
	for _, b := range names {
		if i := strings.IndexByte(selections, b); i >= 0 {
			sel |= 1 << i
		}
	}
	if sel == 0 {
		return
	}
	kept := (*c)[:0]
	for _, w := range *c {
		if w.sel &^= sel; w.sel != 0 {
			kept = append(kept, w)
		}
	}
	// The writes dropped leave copies past kept's length, which would keep
	// their bytes alive.
	clear((*c)[len(kept):])
	w := clipWrite{sel: sel}
	if len("\x1b]52;;\x07")+len(pc)+len(pd) > budget {
		w.over = true
	} else {
		w.pc, w.pd = string(pc), string(pd)
	}
	*c = append(kept, w)
}

// watchClipboard registers the handler that keeps the clipboard writes. x/vt
// has no OSC 52 handler of its own; this returns false all the same, as
// watchColours' do.
func (e *emulation) watchClipboard() {
	e.term.RegisterOscHandler(52, func(data []byte) bool {
		// data is the whole OSC, its number first.
		_, pt, ok := bytes.Cut(data, []byte{';'})
		if !ok {
			return false
		}
		if pc, pd, ok := bytes.Cut(pt, []byte{';'}); ok && string(pd) != "?" {
			e.clips.write(pc, pd)
		}
		return false
	})
}

// watchProtection registers the handlers that note DECSCA (CSI Ps " q)
// turning character protection on, and a selective erase, DECSED (CSI ? Ps J)
// or DECSEL (CSI ? Ps K). The cells printed under protection are protected
// from DECSED and DECSEL on the session's terminal, and on a joiner given the
// raw ring, but the render's rows don't carry protection, and x/vt keeps none,
// of a cell or of the pen, so once it is on the render can't tell which cells
// it covers. DECSCA reads only its first parameter, as xterm's does, and 1 is
// the value that protects. x/vt ignores DECSED and DECSEL altogether, so the
// cells either erased, protected or not, are still in the emulator. x/vt has
// no handler of its own for any of the three; these return false all the
// same, as watchColours' do.
func (e *emulation) watchProtection() {
	t := e.term
	t.RegisterCsiHandler(ansi.Command(0, '"', 'q'), func(params ansi.Params) bool {
		if n, _, _ := params.Param(0, 0); n == 1 {
			e.protected = true
		}
		return false
	})
	for _, final := range []byte{'J', 'K'} {
		t.RegisterCsiHandler(ansi.Command('?', 0, final), func(ansi.Params) bool {
			e.selective = true
			return false
		})
	}
}

// watchSaves registers the handlers that note the stream saving state the
// terminal keeps aside for a later sequence to put back: a title pushed onto
// the title stack, by XTWINOPS 22 (CSI 22 ; Ps t), whichever names Ps saves.
// x/vt keeps no such stack and ignores the pop, XTWINOPS 23, that restores
// from it, so once a title is pushed the render can't tell what a pop on the
// session's terminal puts back, and a joiner's terminal, which the push never
// reached, would put back its own. x/vt has no CSI t handler of its own; this
// returns false all the same, as watchColours' do.
func (e *emulation) watchSaves() {
	e.term.RegisterCsiHandler('t', func(params ansi.Params) bool {
		if n, _, _ := params.Param(0, 0); n == 22 {
			e.savedTitle = true
		}
		return false
	})
}

// Feed offers the emulation more of the stream and runs on to the next
// handoff point it can reach. Every event offered is validated before
// anything else, so a size over the cap allocates nothing.
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
// no cluster is carried. That is the larger of two: the
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
// before each, which bounds the overshoot past the deadline to one scan.
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
// terminal did; only its end must be outside one.
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
	// emulator, which only a Write reports.
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
// which io reports as the deadline.
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
// emulator agree on what both track. A failure spends the emulation, as io
// falls back on it.
func (e *emulation) Render() ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	err := e.consistent()
	var out []byte
	if err == nil {
		out, err = e.render()
	}
	if err != nil {
		e.err = err
		return nil, err
	}
	return out, nil
}

// consistent checks that the tracker clone and the emulator agree, at the
// handoff point, on the screen showing and on each DEC mode the tracker
// tracks, either way. They are two parsers of one stream,
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
