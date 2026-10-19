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
	"image/color"
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

	// title is the window title the stream last set, by OSC 0 or OSC 2, or
	// that a pop of the title stack put back, and titled whether it is one
	// the stream set: an empty title clears the joiner's, as the raw ring
	// would, where a stream that set none, or a pop that put back the
	// terminal's own, leaves it. titleOver is a title a pop put back that was
	// too long to keep (see titleEntry).
	title             string
	titled, titleOver bool
	// icon is the icon name the stream last set, by OSC 0 or OSC 1, or that a
	// pop of the title stack put back, kept as the title is: iconed whether it
	// is one the stream set, and iconOver one a pop put back too long to keep.
	icon             string
	iconed, iconOver bool
	// titles is the title stack (see titleStack), and titleIndexed is set
	// once the stream has saved or restored a title by its index on it.
	// titleModes is set once the stream has set a title mode (see
	// watchTitles).
	titles                   titleStack
	titleIndexed, titleModes bool
	// cwd is the working directory the stream last reported, by OSC 7, and
	// cwdTold whether it reported one at all, as title and titled are.
	cwd     string
	cwdTold bool
	// colours is the last change the stream made to each of the terminal's
	// colours.
	colours colours
	// graphics is set once the stream has drawn an image (see watchGraphics).
	graphics bool
	// dcs is set once the stream has sent a device control string that
	// changes the terminal's state (see watchDCS).
	dcs bool
	// sync is what the stream last did with synchronized output's DCS form.
	sync syncForms
	// clips are the stream's clipboard writes still in force.
	clips clipboard
	// protected is set once the stream has turned character protection on,
	// and selective once it has erased selectively (see watchProtection).
	protected, selective bool
	// savedModes is set once the stream has saved DEC modes, savedRendition
	// once it has pushed a rendition, and savedPalette once it has pushed
	// its colours (see watchSaves).
	savedModes, savedRendition, savedPalette bool
	// defaultReset is the first mode of those a terminal starts with set
	// that the stream has reset (see watchDefaultModes), or 0.
	defaultReset int
	// undrawable is set once the stream has set an attribute a cell doesn't
	// keep, and doubleSize once it has made a line double-width or
	// double-height (see watchRendition).
	undrawable, doubleSize bool
	// statusLine is set once the stream has made a status line it can write
	// to, or made it active (see watchStatusLine).
	statusLine bool
	// font is set once the stream has set the terminal's font (see
	// watchFont).
	font bool
	// rectExtent is set once the stream has made DECCARA and DECRARA change
	// a rectangle (see watchAttributeExtent).
	rectExtent bool
	// conformance is set once the stream has set the terminal's conformance
	// level (see watchConformanceLevel).
	conformance bool
	// pastEdge is what the emulator keeps of the tab stops past the screen's
	// right edge (see the type).
	pastEdge pastEdge

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
// screen, the history kept through the scroll-off function instead, and a
// clear of it noted (see history.erase), replies to queries discarded, the title, the icon name and the title stack, the
// working directory, the colours, the clipboard and synchronized output's
// DCS form kept, images, device control strings that change the terminal's
// state, title modes, character protection, selective erases, saves,
// renditions and line sizes the cells can't hold, a status line, a font, a
// rectangular attribute extent, a conformance level and a reset of a mode a
// terminal starts with set noted, the tab stops past the screen's edge kept,
// and the meter stopped by ctx or the deadline. Each callback and handler
// runs inside the emulator's Write and touches only the emulation.
func (e *emulation) setUp() {
	t := e.term
	t.SetScrollbackSize(0)
	// The alternate screen has a scrollback of its own, which the main
	// screen's size leaves at 10,000 lines: about 600 MiB at 512 columns.
	t.AltScreen().SetScrollback(nil)
	t.SetScrollOffFunc(e.hist.push)
	t.SetScrollbackClearFunc(e.hist.erase)
	t.SetReplyFunc(func([]byte) {})
	t.SetCallbacks(vt.Callbacks{
		Title:    func(title string) { e.title, e.titled, e.titleOver = title, true, false },
		IconName: func(icon string) { e.icon, e.iconed, e.iconOver = icon, true, false },
		// x/vt keeps the directory too, as this string, which keeping it here
		// doesn't copy: it is what follows the OSC's first ';', as the stream
		// sent it, and an OSC 7 without one reports nothing.
		WorkingDirectory: func(dir string) { e.cwd, e.cwdTold = dir, true },
		EnableMode:       e.syncByMode,
		DisableMode:      e.syncByMode,
	})
	t.SetStopFunc(func() bool { return e.stop() })
	e.watchColours()
	e.watchGraphics()
	e.watchDCS()
	e.watchClipboard()
	e.watchProtection()
	e.watchTitles()
	e.watchSaves()
	e.watchRendition()
	e.watchStatusLine()
	e.watchFont()
	e.watchAttributeExtent()
	e.watchConformanceLevel()
	e.watchTabStops()
	e.watchDefaultModes()
}

// colours is the last change the stream made, by OSC, to each of the colours
// a terminal keeps until they are reset. The render can't set one again: a
// colour the stream set fails it, as a raw replay carries the setting to the
// joiner. But it resets each one the stream reset last (see
// renderer.colourResets), as a raw replay does on a joiner's terminal that a
// program of its own left with colours of their own.
//
// x/vt keeps the default foreground, background and cursor colours, but only
// those its colour parser reads, which takes no X11 colour name such as
// "navy", and only from an OSC that sets one of them; it keeps no palette
// from the stream at all. So the stream's OSCs are read here instead, as
// xterm reads them: its ten dynamic colours, OSC 10 to 19, the default
// foreground, background and cursor colours among them, each reset by its
// own OSC 110 to 119; and its colour table (see tableSize), whose entries
// OSC 4 and 5 set and OSC 104 and 105 reset.
type colours struct {
	dynamic [10]colourChange
	table   [tableSize]colourChange
}

// colourChange is the last change the stream made to one colour, the zero
// value none.
type colourChange uint8

const (
	// colourSet is a setting, or a change terminals don't all read alike,
	// which the render can't make the same on every joiner's.
	colourSet colourChange = iota + 1
	// colourReset is a reset every terminal reads as one.
	colourReset
)

// tableSize is how many entries xterm's colour table holds: the palette's
// paletteSize entries, then its five special colours, those it draws bold,
// underlined, blinking, reversed and italic text in. OSC 5 and 105 number the
// special colours from 0, and OSC 4 and 104 from 256, after the palette.
const (
	paletteSize = 256
	tableSize   = paletteSize + 5
)

// changed reports a colour the stream set and hasn't reset.
func (c *colours) changed() bool {
	return slices.Contains(c.dynamic[:], colourSet) || slices.Contains(c.table[:], colourSet)
}

// tableEntry is the entry of the colour table f names in an OSC 4, 5, 104 or
// 105 that numbers the entries from first, if f is the number of one: digits
// and nothing else, short of the table's end.
func tableEntry(f []byte, first int) (int, bool) {
	n := 0
	for _, b := range f {
		if b < '0' || b > '9' {
			return 0, false
		}
		if n = 10*n + int(b-'0'); first+n >= tableSize {
			return 0, false
		}
	}
	return first + n, len(f) > 0
}

// setEntries notes OSC 4 or 5, numbering the table's entries from first, whose
// pairs of an entry and a colour each set the entry, whatever the colour. An
// entry that isn't the number of one, which xterm stops at, makes the whole
// table count as set, as which entries another terminal set then can't be
// told.
func (c *colours) setEntries(data []byte, first int) {
	// data is the whole OSC, its number first.
	_, pairs, _ := bytes.Cut(data, []byte{';'})
	entry := true // each pair's first field
	for f := range bytes.SplitSeq(pairs, []byte{';'}) {
		if entry {
			i, ok := tableEntry(f, first)
			if !ok {
				c.fillTable(0, colourSet)
				return
			}
			c.table[i] = colourSet
		}
		entry = !entry
	}
}

// resetEntries notes OSC 104 or 105, numbering the table's entries from
// first, which resets each entry it lists, or with none listed, every entry
// from first on: the whole table for OSC 104, the special colours for
// OSC 105. A list xterm can't read all of, which it stops in, makes the whole
// table count as set, as which entries another terminal reset then can't be
// told: for OSC 104 ; ; 1, xterm resets none and Alacritty every one.
func (c *colours) resetEntries(data []byte, first int) {
	_, list, _ := bytes.Cut(data, []byte{';'})
	if len(list) == 0 {
		c.fillTable(first, colourReset)
		return
	}
	for f := range bytes.SplitSeq(list, []byte{';'}) {
		i, ok := tableEntry(f, first)
		if !ok {
			c.fillTable(0, colourSet)
			return
		}
		c.table[i] = colourReset
	}
}

// fillTable makes ch the last change to every entry of the table from first
// on.
func (c *colours) fillTable(first int, ch colourChange) {
	for i := first; i < tableSize; i++ {
		c.table[i] = ch
	}
}

// watchColours registers the OSC handlers that keep colours. The last
// handler registered for an OSC is called first, so each of these is called
// before x/vt's own, and returns false, so that x/vt's still handles the OSC.
func (e *emulation) watchColours() {
	t, c := e.term, &e.colours
	for i := range c.dynamic {
		t.RegisterOscHandler(10+i, func(data []byte) bool {
			// After the number, each specification sets the next colour on,
			// as in xterm, so OSC 10 ; fg ; bg sets the background too. Each
			// one counts: the query filter drops an OSC that asks for any.
			n := bytes.Count(data, []byte{';'})
			for k := i; k < min(i+n, len(c.dynamic)); k++ {
				c.dynamic[k] = colourSet
			}
			return false
		})
		t.RegisterOscHandler(110+i, func(data []byte) bool {
			// xterm resets the colour for a reset with nothing after the
			// number or its ';', and ignores one with more, which other
			// terminals, Alacritty and VTE among them, read as a reset all
			// the same: a raw replay of one leaves a colour set before it
			// set on xterm and reset on those, so it counts as a setting.
			if _, rest, _ := bytes.Cut(data, []byte{';'}); len(rest) == 0 {
				c.dynamic[i] = colourReset
			} else {
				c.dynamic[i] = colourSet
			}
			return false
		})
	}
	for _, osc := range []struct{ set, reset, first int }{{4, 104, 0}, {5, 105, paletteSize}} {
		t.RegisterOscHandler(osc.set, func(data []byte) bool {
			c.setEntries(data, osc.first)
			return false
		})
		t.RegisterOscHandler(osc.reset, func(data []byte) bool {
			c.resetEntries(data, osc.first)
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

// watchDCS registers the handlers that note a device control string that
// changes the terminal's state. x/vt has no DCS handler of its own, so it
// drops each one, where a raw replay carries it to the joiner's terminal,
// which acts on it: a tmux passthrough, which a joiner running in tmux hands
// on to the terminal tmux runs in, DECUDK's keys, DECDLD's soft font, ReGIS,
// DECRSTS's and DECRSPS's restores, XTSETTCAP's key names, DECAUPSS's
// character set, DECDMAC's macros, which DECINVM (CSI Pn * z) later invokes,
// and kitty's own strings, DCS @kitty-, among them its remote control, DCS
// @kitty-cmd, which runs a command in kitty where the user allows it. Of
// these xterm ignores DECRSTS and DECDMAC, which Windows Terminal and DEC's
// terminals act on, and kitty's, which only kitty acts on. xterm ignores the
// rest, so for them the raw replay hands an xterm joiner nothing the render
// leaves out: vim's probe of whether it does, DCS z z ST, a final xterm has
// no use for, or one of these under a private prefix, which xterm reads as
// the final. Another terminal may act on one of its own all the same, which
// isn't noted. Of the DCS a program sends, the query filter drops only the
// requests, DECRQSS, XTGETTCAP and XTGETXRES, before the ring, and
// watchGraphics notes a sixel, as an image.
//
// x/vt keys a handler by the DCS's prefix, its last intermediate and its
// final byte, not its parameters, so these are noted whatever their
// parameters: xterm takes DECAUPSS and DECRSPS only with a one-digit one and
// XTSETTCAP only with none, where a DEC terminal reads a number, and kitty
// takes its own only with none; kitty's are noted whatever their data too.
// tmux's passthrough is DCS tmux;, its final the t and its data what
// follows, which tmux takes under any prefix, parameters and intermediate,
// so every key whose final is t gets a handler that notes data that starts
// mux;. A C0 control or an ESC as the first byte makes the key 0: x/vt keeps
// it and what follows as the string's data, up to the next ESC, where a DEC
// terminal ignores the control and reads the string after it, which may be
// any of these, or ends the string at that first ESC and reads what follows
// as it comes; so key 0 is noted whatever its data.
//
// Synchronized output's DCS form, DCS = 1 s and DCS = 2 s, which begins and
// ends an update, isn't noted: like ?2026, it only holds back the drawing, and
// the render begins an update open at the handoff point again (see
// syncForms). Its key gets a handler of its own, which keeps that, and notes
// anything else sent under it, data after the s included, which a terminal
// that takes the form may read as a beginning or an end; and RIS (ESC c)
// gets one that ends such an update, as x/vt's own RIS, which runs after it,
// resets ?2026.
func (e *emulation) watchDCS() {
	t := e.term
	note := func(ansi.Params, []byte) bool {
		e.dcs = true
		return false
	}
	for _, cmd := range []int{
		0,                         // a C0 control or an ESC first
		ansi.Command(0, 0, '|'),   // DECUDK
		ansi.Command(0, 0, '{'),   // DECDLD
		ansi.Command(0, 0, 'p'),   // ReGIS, and iTerm2's tmux integration
		ansi.Command(0, '$', 'p'), // DECRSTS
		ansi.Command(0, '$', 't'), // DECRSPS
		ansi.Command(0, '+', 'p'), // XTSETTCAP
		ansi.Command(0, '!', 'u'), // DECAUPSS
		ansi.Command(0, '!', 'z'), // DECDMAC
		ansi.Command(0, 0, '@'),   // kitty's own, its remote control among them
	} {
		t.RegisterDcsHandler(cmd, note)
	}
	passthrough := func(_ ansi.Params, data []byte) bool {
		if bytes.HasPrefix(data, []byte("mux;")) {
			e.dcs = true
		}
		return false
	}
	for _, prefix := range []byte{0, '<', '=', '>', '?'} {
		t.RegisterDcsHandler(ansi.Command(prefix, 0, 't'), passthrough)
		for inter := byte(0x20); inter <= 0x2f; inter++ {
			t.RegisterDcsHandler(ansi.Command(prefix, inter, 't'), passthrough)
		}
	}
	t.RegisterDcsHandler(ansi.Command('=', 0, 's'), func(params ansi.Params, data []byte) bool {
		if n, _, _ := params.Param(0, 0); len(params) != 1 || n != 1 && n != 2 || len(data) != 0 {
			e.dcs = true
		} else {
			e.sync = syncForms{began: n == 1, dcsLast: true}
		}
		return false
	})
	// RIS ends an update the DCS form began, as x/vt's resets ?2026.
	t.RegisterEscHandler('c', func() bool {
		e.sync.began = false
		return false
	})
}

// syncForms is what the stream last did with synchronized output's DCS form,
// of which x/vt keeps nothing, and whether that came after the last ?2026h
// or ?2026l, which x/vt keeps as a mode. The two forms begin and end one
// update, as iTerm2's description of both has it: either end closes what
// either beginning opened, a beginning inside an update leaves it open, and
// an end outside one does nothing. But a terminal that takes only one form
// follows that form's last, so the render begins each again (see synced).
type syncForms struct {
	// began is set when the DCS form's last was DCS = 1 s, a beginning, and
	// dcsLast when the DCS form was the last of the two.
	began, dcsLast bool
}

// syncByMode notes ?2026 set or reset, as the last of the two forms.
func (e *emulation) syncByMode(m ansi.Mode) {
	if m == ansi.ModeSynchronizedOutput {
		e.sync.dcsLast = false
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

// maxTitles is how many entries xterm's title stack holds.
const maxTitles = 10

// titleStack is the title stack the stream pushed onto, by XTWINOPS 22
// (CSI 22 ; Ps t), and popped, by XTWINOPS 23 (CSI 23 ; Ps t), as xterm keeps
// it. x/vt keeps none, where a raw replay's pushes and pops reach the
// joiner's terminal, which then puts back on a later pop what the session's
// does: so the render pushes the entries again (see renderer.titleStack).
//
// xterm's holds ten entries. A push past them takes the place of the oldest,
// and a pop that comes down to where that was finds nothing there, nor in
// any place below it: lost counts those places, under the entries. A pop
// past them all pops what the session's terminal pushed before the ring,
// which neither a raw replay nor the render holds, so it changes nothing
// here.
type titleStack struct {
	entries []titleEntry // oldest first
	lost    int
}

// titleEntry is what a push saved. ps is its second parameter, which says
// which names: 0, or none given, both; 1 the icon name; 2 the window title;
// any other neither, which xterm pushes all the same. Each name ps saves is
// the emulation's as of the push, the terminal's own where the stream had set
// none (see emulation.title): xterm saves the names its window has, so an
// entry of both that the stream had set only one of holds the terminal's own
// as the other, which a pop of both puts back. A name longer than any render
// may be is over, its bytes not kept.
type titleEntry struct {
	ps               int
	title            string
	titled, over     bool
	icon             string
	iconed, iconOver bool
}

// savesTitle reports whether XTWINOPS 22 or 23 with ps saves or puts back
// the window title.
func savesTitle(ps int) bool { return ps == 0 || ps == 2 }

// savesIcon reports whether XTWINOPS 22 or 23 with ps saves or puts back the
// icon name.
func savesIcon(ps int) bool { return ps == 0 || ps == 1 }

// watchTitles registers the handlers that keep the title stack and note the
// title modes. A third parameter from 1 on is an index on xterm's stack,
// counted from its bottom: a push stores into that entry in place and a pop
// reads it, where the session's terminal may have pushed below the ring's
// first entry, so which entry that is can't be told, and the render falls
// back on it.
//
// XTSMTITLE (CSI > Pm t) sets title modes, each parameter from 0 to 3 one,
// as xterm reads them: titles set, or reported, in hexadecimal, or as UTF-8.
// x/vt keeps none, where a raw replay sets them on the joiner's terminal, so
// a title the program sets in hexadecimal after the handoff point would show
// as its digits on a joiner given the render. One with no parameters sets
// the defaults, which set none. The note stays once XTRMTITLE (CSI > Pm T)
// turns them off again: the raw ring is exact whatever came after. x/vt keys
// a CSI handler by its prefix too, so the window operations' handler sees no
// XTSMTITLE, and x/vt's SD (CSI Ps T) no XTRMTITLE.
//
// x/vt has no handler of its own for either; these return false all the same,
// as watchColours' do.
func (e *emulation) watchTitles() {
	e.term.RegisterCsiHandler(ansi.Command('>', 0, 't'), func(params ansi.Params) bool {
		for _, p := range params {
			if n := p.Param(-1); n >= 0 && n <= 3 {
				e.titleModes = true
			}
		}
		return false
	})
	e.term.RegisterCsiHandler('t', func(params ansi.Params) bool {
		op, _, _ := params.Param(0, 0)
		if op != 22 && op != 23 {
			return false
		}
		ps, _, _ := params.Param(1, 0)
		switch i, _, _ := params.Param(2, 0); {
		case i > 0:
			e.titleIndexed = true
		case op == 22:
			e.pushTitle(ps)
		default:
			e.popTitle(ps)
		}
		return false
	})
}

// pushTitle pushes what ps saves, the oldest entry giving its place up to
// it once there are ten.
func (e *emulation) pushTitle(ps int) {
	en := titleEntry{ps: ps}
	if savesTitle(ps) && e.titled {
		en.titled = true
		if en.over = e.titleOver || len(e.title) > budget; !en.over {
			en.title = e.title
		}
	}
	if savesIcon(ps) && e.iconed {
		en.iconed = true
		if en.iconOver = e.iconOver || len(e.icon) > budget; !en.iconOver {
			en.icon = e.icon
		}
	}
	s := &e.titles
	if len(s.entries) == maxTitles {
		copy(s.entries, s.entries[1:])
		s.entries[maxTitles-1] = titleEntry{}
		s.entries = s.entries[:maxTitles-1]
		s.lost++
	}
	s.entries = append(s.entries, en)
}

// popTitle pops an entry, or a lost place, and puts back each name ps
// restores, the window title and the icon name apart (see titleStack.saved).
func (e *emulation) popTitle(ps int) {
	s := &e.titles
	n := len(s.entries)
	if n == 0 {
		s.lost = max(s.lost-1, 0)
		return
	}
	top := s.entries[n-1]
	s.entries[n-1] = titleEntry{}
	s.entries = s.entries[:n-1]
	if en, ok := s.saved(top, savesTitle); ok && savesTitle(ps) {
		e.title, e.titled, e.titleOver = en.title, en.titled, en.over
	}
	if en, ok := s.saved(top, savesIcon); ok && savesIcon(ps) {
		e.icon, e.iconed, e.iconOver = en.icon, en.iconed, en.iconOver
	}
}

// saved is the entry a pop of top takes a name from, saves saying which Ps
// saves that name: top, or for an entry that saved none, as xterm takes it,
// the nearest one below it, of the entries left, that saved one. Below the
// entries there is none to take: a lost place holds nothing, and what the
// session's terminal pushed before the ring isn't known.
func (s *titleStack) saved(top titleEntry, saves func(int) bool) (titleEntry, bool) {
	if saves(top.ps) {
		return top, true
	}
	for i := len(s.entries) - 1; i >= 0; i-- {
		if saves(s.entries[i].ps) {
			return s.entries[i], true
		}
	}
	return titleEntry{}, false
}

// watchSaves registers the handlers that note the stream saving state the
// terminal keeps aside for a later sequence to put back: DEC private modes
// saved by XTSAVE (CSI ? Pm s), whichever modes Pm names; a rendition pushed
// by XTPUSHSGR (CSI Pm # {, or its alias CSI Pm # p), the whole pen or the
// attributes Pm names; and the dynamic and ANSI colours saved by
// XTPUSHCOLORS (CSI Pm # P), pushed on xterm's stack of palettes or, by a
// parameter, stored in a place on it. x/vt keeps none of them and ignores
// what restores each, XTRESTORE (CSI ? Pm r), XTPOPSGR (CSI # }, or CSI # q)
// and XTPOPCOLORS (CSI Pm # Q), so once one is saved the render can't tell
// what a restore on the session's terminal puts back, and a joiner's
// terminal, which the save never reached, would put back its own. x/vt keys a
// CSI handler by its prefix and intermediate too, so XTSAVE's handler sees
// neither SCOSC nor DECSLRM, both the bare CSI s, the alias's sees no CSI p
// without the #, such as DECSTR's CSI ! p, and XTPUSHCOLORS's no DCH, the
// bare CSI P. x/vt has no handler of its own for any of them; these return
// false all the same, as watchColours' do.
func (e *emulation) watchSaves() {
	t := e.term
	t.RegisterCsiHandler(ansi.Command('?', 0, 's'), func(ansi.Params) bool {
		e.savedModes = true
		return false
	})
	for _, final := range []byte{'{', 'p'} {
		t.RegisterCsiHandler(ansi.Command(0, '#', final), func(ansi.Params) bool {
			e.savedRendition = true
			return false
		})
	}
	t.RegisterCsiHandler(ansi.Command(0, '#', 'P'), func(ansi.Params) bool {
		e.savedPalette = true
		return false
	})
}

// watchRendition registers the handlers that note the stream drawing what
// the render's cells can't: the SGR handler, for an attribute a cell doesn't
// keep (see sgrUndrawable), which x/vt's SGR, keeping the rest in the pen,
// runs after, as it returns false; and those for a line made double-width,
// by DECDWL (ESC # 6), or double-height, by DECDHL (ESC # 3 and ESC # 4).
// x/vt keeps no line size, so it draws such a line single-width, where the
// session's terminal draws each character twice as wide and shows half the
// line. DECSWL (ESC # 5) makes a line single-width, as every line starts.
// x/vt has no ESC # handler of its own; these return false all the same, as
// watchColours' do.
func (e *emulation) watchRendition() {
	t := e.term
	t.RegisterCsiHandler('m', func(params ansi.Params) bool {
		if sgrUndrawable(params) {
			e.undrawable = true
		}
		return false
	})
	for _, final := range []byte{'3', '4', '6'} {
		t.RegisterEscHandler(ansi.Command(0, '#', final), func() bool {
			e.doubleSize = true
			return false
		})
	}
}

// watchStatusLine registers the handlers that note the stream making a status
// line it can write to, by DECSSDT 2 (CSI 2 $ ~), or sending its output there,
// by DECSASD 1 (CSI 1 $ }). x/vt has no status line, so it draws what the
// program writes to one on the main display, where the session's terminal
// shows it on a line of its own. Each reads only its first parameter, as
// xterm's do. DECSSDT 1, the indicator line, which the terminal draws itself
// and the program can't write to, isn't noted. x/vt has no handler of its own
// for either; these return false all the same, as watchColours' do.
func (e *emulation) watchStatusLine() {
	t := e.term
	for _, sel := range []struct {
		final byte
		ps    int
	}{{'~', 2}, {'}', 1}} {
		t.RegisterCsiHandler(ansi.Command(0, '$', sel.final), func(params ansi.Params) bool {
			if n, _, _ := params.Param(0, 0); n == sel.ps {
				e.statusLine = true
			}
			return false
		})
	}
}

// watchFont registers the handler that notes an OSC 50 setting the
// terminal's font. x/vt keeps none, so the render would leave a joiner's
// terminal in its own, where a raw replay changes it as the session's
// changed. Every OSC 50 counts but a query, whose font starts with ?, as
// xterm reads one: a font name, a font by its index (#), and an empty one,
// which xterm answers with the bell; iTerm2 and Konsole read key=value
// settings from it too, such as the cursor's shape. The query filter drops
// the queries before the ring. x/vt has no handler of its own for it; this
// returns false all the same, as watchColours' do.
func (e *emulation) watchFont() {
	e.term.RegisterOscHandler(50, func(data []byte) bool {
		// data is the whole OSC, its number first.
		if _, font, _ := bytes.Cut(data, []byte{';'}); !bytes.HasPrefix(font, []byte("?")) {
			e.font = true
		}
		return false
	})
}

// watchAttributeExtent registers the handler that notes DECSACE 2
// (CSI 2 * x), which makes DECCARA and DECRARA change the exact rectangle
// they name instead of the stream of cells from its first corner to its
// last, which is how a terminal starts. x/vt keeps no extent, where a raw
// replay sets the joiner's terminal's, so a DECCARA the program sends after
// the handoff point would change other cells on a joiner given the render
// than on the session's terminal. DECSACE reads only its first parameter, as
// xterm's does, and 0, 1 or none select the stream. x/vt has no handler of
// its own for it; this returns false all the same, as watchColours' do.
func (e *emulation) watchAttributeExtent() {
	e.term.RegisterCsiHandler(ansi.Command(0, '*', 'x'), func(params ansi.Params) bool {
		if n, _, _ := params.Param(0, 0); n == 2 {
			e.rectExtent = true
		}
		return false
	})
}

// watchConformanceLevel registers the handler that notes DECSCL
// (CSI Pl ; Pc " p), which sets the terminal's conformance level, a VT100's
// to a VT500's, and whether it sends its controls as 7-bit or 8-bit bytes.
// xterm's soft-resets the terminal too, as DECSTR does, and at a lower level
// ignores what a higher one added, SS2 and SS3 at a VT100's among them. x/vt
// does nothing for it, where a raw replay does all of that on the joiner's
// terminal, so the render would restore what the session's had reset and
// leave the joiner at its own level. Every one counts, whatever its
// parameters: xterm ignores a level it doesn't have, which another terminal
// may not. x/vt keys a CSI handler by its intermediate too, so this one sees
// neither DECSTR (CSI ! p) nor DECRQM (CSI Ps $ p and CSI ? Ps $ p), which
// the query filter drops. x/vt has no handler of its own for it; this returns
// false all the same, as watchColours' do.
func (e *emulation) watchConformanceLevel() {
	e.term.RegisterCsiHandler(ansi.Command(0, '"', 'p'), func(ansi.Params) bool {
		e.conformance = true
		return false
	})
}

// pastEdge is what x/vt keeps of the tab stops past the screen's right edge,
// which TabStops doesn't report. As in xterm, whose 1,024 columns of stops are
// wider than any screen, a resize changes none of them: a narrowing leaves
// the stops of the columns it takes off the screen for a widening to bring
// back, and a widening past every width the screen has had gives each new
// column a stop every 8 columns, as a terminal starts, or none once the
// stream has cleared every stop. The render sets those in a joiner wider than
// the pty, where they are on its screen (see renderer.tabStops), so a live tab
// there lands as on the session's terminal once the pty is as wide.
type pastEdge struct {
	// stops are the stops each narrowing took off the screen, ascending, all
	// before width, the widest the screen has been since every stop was last
	// cleared or set afresh (by TBC 3, DECST8C or RIS); past width, there is
	// a stop every 8 columns, unless cleared. Those in columns a widening has
	// since brought back onto the screen are the screen's again, and between
	// leaves them out.
	stops []int
	width int
	// cleared is set once TBC 3 or DECST8C has cleared every stop, until a
	// RIS sets them every 8 columns again.
	cleared bool
}

// narrow keeps the stops a narrowing from from columns to to takes off the
// screen: those of stops, the screen's before it, from to on, then those kept
// past from already.
func (p *pastEdge) narrow(stops []int, from, to int) {
	i, _ := slices.BinarySearch(stops, to)
	j, _ := slices.BinarySearch(p.stops, from)
	p.stops = append(slices.Clone(stops[i:]), p.stops[j:]...)
	p.width = max(p.width, from)
}

// reset forgets every stop past the edge, as clearing every stop and setting
// them afresh do, cleared saying whether every stop was cleared.
func (p *pastEdge) reset(cleared bool) {
	p.stops, p.width, p.cleared = nil, 0, cleared
}

// between returns the stops past the screen's edge from column from, the
// screen's width, up to column to, ascending.
func (p *pastEdge) between(from, to int) []int {
	var stops []int
	for _, x := range p.stops {
		if x >= from && x < to {
			stops = append(stops, x)
		}
	}
	if p.cleared {
		return stops
	}
	for x := (max(from, p.width) + 7) / 8 * 8; x < to; x += 8 {
		stops = append(stops, x)
	}
	return stops
}

// watchTabStops registers the handlers that keep what x/vt does to the stops
// past the screen's edge (see pastEdge), each read as x/vt reads it: TBC 3
// (CSI 3 g) clears every stop; DECST8C (CSI ? 5 W, only so) sets a stop every
// 8 columns as far as the screen goes and clears the rest, as xterm's does;
// and RIS (ESC c) sets one every 8 columns everywhere. xterm reads TBC alike,
// and its RIS, but takes DECST8C only at a VT510's level and up, which isn't
// its default. Each returns false, so that x/vt's own handler still runs.
func (e *emulation) watchTabStops() {
	t := e.term
	t.RegisterCsiHandler('g', func(params ansi.Params) bool {
		if n, _, _ := params.Param(0, 0); n == 3 {
			e.pastEdge.reset(true)
		}
		return false
	})
	t.RegisterCsiHandler(ansi.Command('?', 0, 'W'), func(params ansi.Params) bool {
		if len(params) == 1 && params[0] == 5 {
			e.pastEdge.reset(true)
		}
		return false
	})
	t.RegisterEscHandler('c', func() bool {
		e.pastEdge.reset(false)
		return false
	})
}

// watchDefaultModes registers the handler that notes DECRST (CSI ? Pm l)
// resetting a mode a terminal starts with set and the render doesn't restore
// (see defaultModes), by any of its parameters, each read as x/vt reads them.
// x/vt keeps every mode a DECSET or DECRST names, but of these only the
// setting, and its RIS forgets it, where xterm's keeps ?1046 as it is and,
// in VT52 mode, isn't read as RIS at all; nor does a set after it undo
// DECANM's reset, after which xterm reads the set as a VT52 does, or what
// xterm ignored while ?1046 was reset. So the note stays, whatever follows,
// for the colour registers too, which xterm's RIS puts back. It returns false, so that x/vt's own handler still runs.
func (e *emulation) watchDefaultModes() {
	e.term.RegisterCsiHandler(ansi.Command('?', 0, 'l'), func(params ansi.Params) bool {
		for _, p := range params {
			if n := p.Param(-1); e.defaultReset == 0 && defaultModes[ansi.DECMode(n)] {
				e.defaultReset = n
			}
		}
		return false
	})
}

// sgrUndrawable reports whether params, an SGR's, hold a number x/vt's SGR
// skips that changes how a terminal draws what is printed after it: an
// alternative font (11 to 19), Fraktur (20), SGR 21, which x/vt reads neither
// as a double underline, as xterm does, nor as bold off, as some terminals
// do (a cell keeps a double underline, but set by 4:2), proportional spacing
// (26), framed or encircled (51, 52), overlined (53), an ideogram line or
// stress mark (60 to 64), superscript or subscript (73, 74). The session's
// terminal draws the cells printed under one so, and the render would draw
// them as x/vt keeps them. Once none is set, the numbers that turn them off
// (10, 50, 54, 55, 65 and 75) change nothing the render draws.
//
// The parameters are read as ultraviolet's ReadStyle, x/vt's SGR, reads
// them: 38, 48 and 58 take the colour ansi.ReadStyleColor reads after them,
// so a colour's own numbers, the 53 of 38;5;53, are no attribute. ReadStyle's
// other jump, over an underline's style (4:0 to 4:5), passes over no number
// listed here.
func sgrUndrawable(params ansi.Params) bool {
	for i := 0; i < len(params); i++ {
		switch p, _, _ := params.Param(i, 0); p {
		case 38, 48, 58:
			var c color.Color
			if n := ansi.ReadStyleColor(params[i:], &c); n > 0 {
				i += n - 1
			}
		case 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 26, 51, 52, 53, 60, 61, 62, 63, 64, 73, 74:
			return true
		}
	}
	return false
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
		// resize, and applying it would reset the margins and origin mode,
		// as x/vt's Resize does at any size.
		if ev.Size != size {
			if err := e.resize(ev.Size); err != nil {
				return err
			}
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
// which resets its margins as the terminal does. A narrowing first keeps the
// tab stops it takes off the screen (see pastEdge), which the emulator keeps
// too but no longer reports. Reading them is a scan as wide as the screen,
// outside the emulator's meter, which a spent emulator would run for every
// event left in the batch, so the stop function is asked before it, as
// batchEnd asks it before each of its scans.
func (e *emulation) resize(size termsize.Size) error {
	if testHookResize != nil {
		testHookResize(size)
	}
	if w := e.term.Width(); size.Cols < w {
		if e.stop() {
			return uio.ErrReplayDeadline
		}
		e.pastEdge.narrow(e.term.TabStops(), w, size.Cols)
	}
	e.term.Resize(size.Cols, size.Rows)
	e.modes.Resized(size)
	return nil
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
