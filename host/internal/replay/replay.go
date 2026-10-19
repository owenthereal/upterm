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
	// conEmuCwd is the working directory the stream last reported by ConEmu's
	// OSC 9 ; 9, and conEmuCwdTold whether it reported one at all, as cwd and
	// cwdTold are; conEmuCwdOver is one longer than any render may be, whose
	// bytes aren't kept, and conEmuCwdLast says it came after the last OSC 7
	// (see watchConEmuCwd).
	conEmuCwd                                   string
	conEmuCwdTold, conEmuCwdOver, conEmuCwdLast bool
	// pointer is the pointer shape the stream last set, by OSC 22, and
	// pointerSet whether it set one at all, as title and titled are;
	// pointerOver is one longer than any render may be, whose bytes aren't
	// kept (see watchPointer).
	pointer                 string
	pointerSet, pointerOver bool
	// warningBell and marginBell are the volumes the stream last set the
	// warning bell and the margin bell to (see watchBellVolumes).
	warningBell, marginBell bellVolume
	// progress is the progress indicator the stream last set (see
	// watchProgress).
	progress progress
	// colours is the last change the stream made to each of the terminal's
	// colours, and colourModes is set once it has turned the use of a special
	// colour on or off (see watchColourModes).
	colours     colours
	colourModes bool
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
	// charset94 is set once the stream has designated a 94-character set
	// that x/vt drops and xterm acts on (see watchCharsets94), and charset96
	// once it has designated a 96-character set (see watchCharsets96).
	charset94, charset96 bool
	// windowOp is set once the stream has changed the terminal's window (see
	// watchWindowOps).
	windowOp bool
	// printerController is set once the stream has turned printer
	// controller mode on, and autoPrint is whether it left auto print on (see
	// watchPrinter).
	printerController, autoPrint bool
	// memoryLock is set once the stream has locked or unlocked memory so as
	// to move the scroll region's top margin (see watchMemoryLock).
	memoryLock bool
	// keyFormat is set once the stream has set how the terminal encodes a
	// key's modifiers otherwise than the tracker restores (see
	// watchKeyFormats).
	keyFormat bool
	// locator is set once the stream has turned DEC locator reporting on, and
	// locatorEvents once it has selected a button event for a report (see
	// watchLocator).
	locator, locatorEvents bool
	// iTerm2 is the key of the first command the stream has sent that changes
	// iTerm2's state for as long as it lasts (see watchITerm2), or "".
	iTerm2 string
	// leds is set once the stream has lit or put out the keyboard's LEDs (see
	// watchLEDs).
	leds bool
	// logFile is set once the stream has set the file the terminal logs to
	// (see watchLogFile).
	logFile bool
	// windowProperty is set once the stream has set or deleted a property of
	// the terminal's window (see watchWindowProperty).
	windowProperty bool
	// nonUTF8 is set once the stream has left UTF-8 for another coding (see
	// watchCoding).
	nonUTF8 bool
	// eightBit is whether the stream left the terminal sending the program
	// 8-bit controls (see watchControls).
	eightBit bool
	// sizedText is set once the stream has drawn text in kitty's sizes (see
	// watchSizedText).
	sizedText bool
	// extraCursors is set once the stream has shown an extra cursor of
	// kitty's, or coloured them (see watchExtraCursors).
	extraCursors bool
	// unscroll is set once the stream has scrolled the screen down filling
	// it from the scrollback (see watchUnscroll).
	unscroll bool
	// pastEdge is what the emulator keeps of the tab stops past the screen's
	// right edge (see the type).
	pastEdge pastEdge

	// The handoff point: the end of what the emulator consumed, and the last
	// event it passed, applied or skipped as a no-op.
	h, lastSeq uint64
	// tail is what was offered past h: bytes the emulator hasn't consumed,
	// a copy, since the lookahead needs them in one piece, and the
	// emulation's own, in which screen title strings are made x/vt's (see
	// screenTitles), which follows what was offered.
	tail         []byte
	screenTitles screenTitles
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
	// emulator is told. A snapshot that ends with an ESC, as one the ring
	// starts just after does, leaves screenTitles to read the ring's first
	// byte after it.
	snapshot := c.Modes.Snapshot()
	e.screenTitles.read(snapshot)
	if _, err := e.term.Write(snapshot); err != nil {
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

// setUp makes the emulator a replay's: no scrollback on either screen, the
// history kept through the scroll-off function instead, and a clear of it
// noted (see history.erase), replies to queries discarded, the title, the
// icon name and the title stack, the working directory, by OSC 7 and by
// ConEmu's OSC 9 ; 9, the pointer shape, the bell's volumes, the progress
// indicator, the colours, the clipboard and synchronized output's DCS form
// kept, images, special colour modes, device control strings that change the
// terminal's state, title modes, character protection, selective erases,
// saves, renditions and line sizes the cells can't hold, a status line, a
// font, a rectangular attribute extent, a conformance level, a reset of a
// mode a terminal starts with set, a 94-character set x/vt drops, a
// 96-character set, a window operation, printer controller mode, a memory
// lock, a key format, locator reporting, the locator's events, a change to
// iTerm2's state, the keyboard's LEDs, a log file, a window property, a
// coding other than UTF-8, sized text, extra cursors and an unscroll noted,
// auto print, 8-bit controls and the tab stops past the screen's edge kept,
// and the meter stopped by ctx or the deadline.
// Each callback and handler runs inside the emulator's Write and touches only
// the emulation.
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
		WorkingDirectory: func(dir string) { e.cwd, e.cwdTold, e.conEmuCwdLast = dir, true, false },
		EnableMode:       e.syncByMode,
		DisableMode:      e.syncByMode,
	})
	t.SetStopFunc(func() bool { return e.stop() })
	e.watchColours()
	e.watchColourModes()
	e.watchGraphics()
	e.watchDCS()
	e.watchClipboard()
	e.watchPointer()
	e.watchBellVolumes()
	e.watchProgress()
	e.watchConEmuCwd()
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
	e.watchCharsets94()
	e.watchCharsets96()
	e.watchWindowOps()
	e.watchPrinter()
	e.watchMemoryLock()
	e.watchKeyFormats()
	e.watchLocator()
	e.watchITerm2()
	e.watchLEDs()
	e.watchLogFile()
	e.watchWindowProperty()
	e.watchCoding()
	e.watchControls()
	e.watchSizedText()
	e.watchExtraCursors()
	e.watchUnscroll()
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

// watchColourModes registers the handlers that note an OSC 6, or its alias
// OSC 106, with which xterm turns on or off, for each pair of a special
// colour (see tableSize) and a flag, whether it draws bold, underlined,
// blinking, reversed or italic text in that colour. x/vt keeps none of it,
// where a raw replay sets each on the joiner's terminal, and xterm's RIS
// leaves them. The note stays, whatever follows: which way each starts is a
// terminal's own setting, so turning one off needn't leave it as the joiner's
// started. Every one counts, one xterm ignores too: iTerm2 reads OSC 6 as a
// tab's colour. xterm has no query of them, and the query filter drops none.
// x/vt has no handler of its own for either; these return false all the
// same, as watchColours' do.
func (e *emulation) watchColourModes() {
	for _, osc := range []int{6, 106} {
		e.term.RegisterOscHandler(osc, func([]byte) bool {
			e.colourModes = true
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

// watchPointer registers the handler that keeps the pointer shape the stream
// last set by OSC 22, which x/vt drops, where a raw replay sets it on the
// joiner's terminal. It keeps the OSC 22s xterm acts on: those with a name
// after the number and its ';'. xterm ignores one with no name, with no ';',
// or with anything but digits before the ';', which x/vt still hands this
// handler as OSC 22, by the digits it starts with. It acts on a name it has no
// shape for too, setting the shape it starts with, so that is kept as the
// stream sent it; and its RIS leaves the shape as it is. The query filter
// drops no OSC 22. x/vt has no handler of its own for it; this returns false
// all the same, as watchColours' do.
func (e *emulation) watchPointer() {
	e.term.RegisterOscHandler(22, func(data []byte) bool {
		// data is the whole OSC, its number first.
		num, name, _ := bytes.Cut(data, []byte{';'})
		if len(name) == 0 || bytes.ContainsFunc(num, func(r rune) bool { return r < '0' || r > '9' }) {
			return false
		}
		e.pointerSet = true
		if e.pointerOver = len("\x1b]22;\x07")+len(name) > budget; e.pointerOver {
			e.pointer = ""
		} else {
			e.pointer = string(name)
		}
		return false
	})
}

// bellVolume is the last setting the stream made of one of the bell's
// volumes, if set: the first parameter it sent, or -1 for none.
type bellVolume struct {
	set bool
	ps  int
}

// watchBellVolumes registers the handlers that keep the volumes the stream
// last set the warning bell to, by DECSWBV (CSI Ps SP t), and the margin bell
// to, by DECSMBV (CSI Ps SP u), which x/vt drops, where a raw replay sets each
// on the joiner's terminal. Each is kept by its first parameter as the stream
// sent it, an omitted one too: xterm reads that parameter alone, an omitted
// one as 0, and every value sets a volume: 1, and 9 and up, off, 2 to 4 low, 5
// to 8 high, and 0 off for the warning bell and high for the margin bell. It
// ignores one with a sub-parameter, which isn't kept, and its RIS leaves both
// volumes as they are. x/vt keys a CSI handler by its prefix and intermediate
// too, so these see neither DECSCUSR (CSI Ps SP q), XTWINOPS (CSI Ps t), SCORC
// (CSI u) nor kitty's keyboard forms of CSI u, which carry a prefix; and the
// query filter drops neither, as it drops a window report only with no
// intermediate. x/vt has no handler of its own for either; these return false
// all the same, as watchColours' do.
func (e *emulation) watchBellVolumes() {
	for _, bell := range []struct {
		final byte
		vol   *bellVolume
	}{{'t', &e.warningBell}, {'u', &e.marginBell}} {
		e.term.RegisterCsiHandler(ansi.Command(0, ' ', bell.final), func(params ansi.Params) bool {
			if !slices.ContainsFunc(params, ansi.Param.HasMore) {
				ps, _, _ := params.Param(0, -1)
				*bell.vol = bellVolume{set: true, ps: ps}
			}
			return false
		})
	}
}

// progress is the last setting the stream made of the progress indicator, if
// set: its state, and its value, or -1 for none.
type progress struct {
	set          bool
	state, value int
}

// watchProgress registers the handler that keeps the progress indicator the
// stream last set by ConEmu's OSC 9 ; 4 ; state ; value, which Windows
// Terminal and kitty show until a state of 0 removes it, and which x/vt
// drops, where a raw replay hands the joiner every one, which leave it at the
// last. A state of 0 is kept too: sent, it removes the joiner's own, as a raw
// replay's does. Kept are those the two read alike: a 4 after the OSC's
// number, then the state, from 0 to 4, the value, if any, and any fields
// after it, each of digits alone, and the number before them of digits alone
// too, as x/vt hands this handler an OSC by the digits it starts with,
// whatever follows them. A value past 100, which both read as 100, is kept as
// 100. Both ignore a state past 4 and a field that isn't a number; they read
// apart an empty field, and a second field that is a 4 written otherwise or
// has no ';' after it, which kitty takes for a notification: none of those is
// kept. OSC 9 ; 9 is watchConEmuCwd's, and every other OSC 9 iTerm2's
// notification, shown once, which the render doesn't send again. Windows
// Terminal's RIS leaves the indicator as it is, and it is kept through one.
// The query filter drops no OSC 9. x/vt has no handler of its own for it;
// this returns false all the same, as watchColours' do.
func (e *emulation) watchProgress() {
	e.term.RegisterOscHandler(9, func(data []byte) bool {
		// data is the whole OSC, its number first.
		num, rest, _ := bytes.Cut(data, []byte{';'})
		fields, ok := bytes.CutPrefix(rest, []byte("4;"))
		if _, digits := decimal(num); !ok || !digits {
			return false
		}
		p := progress{set: true, value: -1}
		for i, f := range bytes.Split(fields, []byte{';'}) {
			n, ok := decimal(f)
			if !ok {
				return false
			}
			switch i {
			case 0:
				p.state = n
			case 1:
				p.value = min(n, 100)
			}
		}
		if p.state <= 4 {
			e.progress = p
		}
		return false
	})
}

// decimal reads f as a decimal number, of digits alone and at least one,
// which past 1000 is 1000, more than any it is read for.
func decimal(f []byte) (int, bool) {
	n := 0
	for _, b := range f {
		if b < '0' || b > '9' {
			return 0, false
		}
		n = min(n*10+int(b-'0'), 1000)
	}
	return n, len(f) > 0
}

// watchConEmuCwd registers the handler that keeps the working directory the
// stream last reported by ConEmu's OSC 9 ; 9 ; path, which Windows Terminal
// starts a tab or pane duplicated from the session's in, and which x/vt drops,
// where a raw replay hands the joiner every one, which leave it at the last
// one Windows Terminal acts on. Kept are the ones it acts on, read as it
// reads them: the OSC's number is 9 by its digits, Windows Terminal skipping
// any other byte there, where x/vt hands this handler an OSC by the digits it
// starts with, so 9x is 9 to both and 9x5 is 95 to Windows Terminal; the
// field after the number is 9, of digits alone, with a ';' after it; and the
// path, the field after that, up to the next ';', holds none of '"', '*',
// '<', '>', '?' and '|' once the '"' at each end of a path of three bytes or
// more are dropped, as ConEmu's documentation wraps one. An empty path is
// kept too, which empties Windows Terminal's directory. What follows the
// second ';' is kept as the stream sent it, which the joiner's Windows
// Terminal then reads as the session's did, but not when it is longer than
// any render may be (conEmuCwdOver).
//
// Windows Terminal reads OSC 7 into the same directory, so the later of the
// two sets it, and conEmuCwdLast keeps which that was, the WorkingDirectory
// callback clearing it. Windows Terminal's RIS leaves the directory as it is,
// and it is kept through one, as OSC 7's is. kitty and iTerm2 read an OSC 9
// as a notification, so on them the one the render sends shows as one, once
// a join, where a raw replay shows one for each in the ring. Every other
// OSC 9 is watchProgress's, or iTerm2's notification, shown once, which the
// render doesn't send again. The query filter drops no OSC 9. x/vt has no
// handler of its own for it; this returns false all the same, as
// watchColours' do.
func (e *emulation) watchConEmuCwd() {
	e.term.RegisterOscHandler(9, func(data []byte) bool {
		// data is the whole OSC, its number first.
		num, args, _ := bytes.Cut(data, []byte{';'})
		n := 0
		for _, b := range num {
			if b >= '0' && b <= '9' {
				n = min(n*10+int(b-'0'), 1000)
			}
		}
		action, rest, ok := bytes.Cut(args, []byte{';'})
		if a, _ := decimal(action); n != 9 || a != 9 || !ok {
			return false
		}
		path, _, _ := bytes.Cut(rest, []byte{';'})
		if len(path) >= 3 && path[0] == '"' && path[len(path)-1] == '"' {
			path = path[1 : len(path)-1]
		}
		if bytes.ContainsAny(path, `"*<>?|`) {
			return false
		}
		e.conEmuCwdTold, e.conEmuCwdLast = true, true
		if e.conEmuCwdOver = len("\x1b]9;9;\x07")+len(rest) > budget; e.conEmuCwdOver {
			e.conEmuCwd = ""
		} else {
			e.conEmuCwd = string(rest)
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
// parameter, stored in a place on it, or by kitty's OSC 30001, which pushes
// them on the stack kitty's own XTPUSHCOLORS pushes on, as one with no
// parameter does: every one counts, whatever follows its number, of which
// kitty reads nothing. x/vt keeps none of them and ignores what restores each,
// XTRESTORE (CSI ? Pm r), XTPOPSGR (CSI # }, or CSI # q), XTPOPCOLORS
// (CSI Pm # Q) and kitty's OSC 30101, so once one is saved the render can't
// tell what a restore on the session's terminal puts back, and a joiner's
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
	t.RegisterOscHandler(30001, func([]byte) bool {
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

// vtCharsets94 are the finals x/vt designates a 94-character set by, with
// ESC ( to ESC +: 0 (DEC's line drawing), A (the UK set) and B (ASCII).
const vtCharsets94 = "0AB"

// xtermCharsets94 are the finals xterm acts on in a 94-character set
// designation, ESC ( to ESC + and the final: those its scstable passes on to
// be decoded. xtermCharsets94After are those it acts on with %, " or & between
// the two, by that intermediate, which it decodes at a VT320's level and up
// for %, its default VT420 among them, and at a VT510's for " and &.
const xtermCharsets94 = "0124567<=ABCEHIJKQRYZf9>`"

var xtermCharsets94After = map[byte]string{'%': "02356=", '"': "4>?", '&': "45"}

// watchCharsets94 registers the handlers that note a 94-character set
// designated into G0 to G3 that x/vt drops and xterm acts on (see
// xtermCharsets94). x/vt takes only the finals in vtCharsets94 and keeps the
// set designated before for the rest, where xterm takes ESC ( < as DEC's
// user-preferred supplemental set, ESC ( > as DEC Technical and ESC ( % 5 as
// DEC's supplemental graphic set, and sets the G-set to ASCII for each final
// it knows of no set for at its level: the national sets, which it takes only
// in NRCS mode, among them. So the cells printed under one may be other than
// the emulator's, and a live print shifted there lands otherwise on a joiner
// given the render than on the session's terminal. The note stays, whatever
// follows, as watchCharsets96's does. The snapshot designates G0 by the SCS
// the tracker keeps for it, through these handlers too, so one the ring has
// evicted is noted. A final xterm ignores leaves the set before on both, and
// isn't noted. x/vt keys a handler by the last intermediate alone, so
// ESC % 5 and ESC $ ( C, which xterm ignores, are noted too, as ESC ( % 5 and
// ESC ( C are. x/vt has no handler of its own for any of these; these return
// false all the same, as watchColours' do.
func (e *emulation) watchCharsets94() {
	note := func() bool {
		e.charset94 = true
		return false
	}
	for _, final := range []byte(xtermCharsets94) {
		if strings.IndexByte(vtCharsets94, final) >= 0 {
			continue
		}
		for _, inter := range []byte("()*+") {
			e.term.RegisterEscHandler(ansi.Command(0, inter, final), note)
		}
	}
	// x/vt keys a handler by the last intermediate alone, the %, " or &.
	for inter, finals := range xtermCharsets94After {
		for _, final := range []byte(finals) {
			e.term.RegisterEscHandler(ansi.Command(0, inter, final), note)
		}
	}
}

// watchCharsets96 registers the handlers that note a 96-character set
// designated into G1, G2 or G3, by ESC - F, ESC . F or ESC / F. x/vt takes
// only 94-character sets, by ESC ( to ESC + with A, B or 0, and drops these,
// keeping the set designated before, where xterm takes ESC - A, at its
// default VT420 level, as ISO Latin-1's supplemental set, whose characters a
// print shifted there draws in place of ASCII's, and more finals at a
// VT510's (B, F, H, L and M). So the cells printed under one may be other
// than the emulator's, and a live print shifted there lands otherwise on a
// joiner given the render than on the session's terminal. The note stays,
// whatever follows: a later designation or RIS sets the G-set again on both,
// but leaves the cells printed before it, and a DECSC saves the set for a
// DECRC to put back. x/vt keys an ESC handler by its last intermediate and
// its final byte, so each final, 0x30 to 0x7E, gets a handler: one xterm
// ignores, another terminal may take. x/vt has no handler of its own for any
// of them; these return false all the same, as watchColours' do.
func (e *emulation) watchCharsets96() {
	note := func() bool {
		e.charset96 = true
		return false
	}
	for _, inter := range []byte{'-', '.', '/'} {
		for final := byte(0x30); final <= 0x7e; final++ {
			e.term.RegisterEscHandler(ansi.Command(0, inter, final), note)
		}
	}
}

// watchWindowOps registers the handlers that note XTWINOPS (CSI Ps ; Ps ;
// Ps t) changing the terminal's window, by its first parameter as xterm reads
// it: de-iconifying or iconifying it (1, 2), moving it (3), resizing it in
// pixels or in characters (4, 8), raising or lowering it (5, 6), maximizing
// it or making it full screen (9, 10), and DECSLPP (24 and up), which resizes
// it to that many lines; and the other two that resize it, by their first
// parameters too: DECSCPP (CSI Ps $ |), to 132 columns for 132 and to 80 for
// 80, 0 or none, and DECSNLS (CSI Ps * |), to Ps lines for 1 to 255. x/vt
// keeps no window, where a raw replay does each of them to the joiner's, as
// xterm allows by default, DECSCPP at a VT320's level and up and DECSNLS at a
// VT420's, which is its default. The note stays, whatever follows: a later
// operation can't be told to undo one, as what the joiner's window was
// before isn't known. A refresh (7) only redraws, and xterm does nothing for
// 0, 12, 17 and the rest below 24 it doesn't list, nor for a DECSCPP or a
// DECSNLS to another size; the reports (11, 13 to 21) the query filter drops,
// and the render rebuilds the title stack (22, 23, see watchTitles). x/vt
// keys a CSI handler by its prefix and intermediate too, so these see no
// XTSMTITLE (CSI > Pm t). iTerm2's SetWindowFrame is noted as one too (see
// watchITerm2). x/vt has no handler of its own for any of them; these return
// false all the same, as watchColours' do.
func (e *emulation) watchWindowOps() {
	t := e.term
	t.RegisterCsiHandler('t', func(params ansi.Params) bool {
		switch op, _, _ := params.Param(0, 0); {
		case op >= 1 && op <= 6, op >= 8 && op <= 10, op >= 24:
			e.windowOp = true
		}
		return false
	})
	t.RegisterCsiHandler(ansi.Command(0, '$', '|'), func(params ansi.Params) bool {
		switch cols, _, _ := params.Param(0, 0); cols {
		case 0, 80, 132:
			e.windowOp = true
		}
		return false
	})
	t.RegisterCsiHandler(ansi.Command(0, '*', '|'), func(params ansi.Params) bool {
		if lines, _, _ := params.Param(0, 0); lines >= 1 && lines <= 255 {
			e.windowOp = true
		}
		return false
	})
}

// watchPrinter registers the handlers that note the printer's modes, as xterm
// reads the media copies that set them, each by its first parameter: CSI 5 i
// turns printer controller mode on and CSI 4 i off; CSI ? 5 i turns auto print
// on and CSI ? 4 i off, and CSI 4 i turns it off too. x/vt has no printer,
// where a raw replay sets each mode on a joiner's terminal that has one. In
// printer controller mode such a terminal sends every byte to the printer
// instead of drawing it, until it matches CSI 4 i byte for byte, so a raw
// replay leaves off its screen the bytes the mode covered, ended before the
// handoff or not, where the render draws them, as x/vt drew them: the note
// stays once the mode is on (see eligible). An xterm with no printer command,
// as it starts, takes neither mode and draws those bytes as x/vt does, but a
// joiner's terminal may have a printer. Auto print draws everything all the
// same, and prints each line the cursor leaves by a line feed, a form feed, a
// vertical tab or a wrap, so it fails the render only when on at the handoff,
// as the live lines would print. RIS ends neither mode. The media copies that
// only print, the screen (CSI i) or the cursor's line (CSI ? 1 i) among them,
// change no mode. x/vt has no handler of its own for either; these return
// false all the same, as watchColours' do.
func (e *emulation) watchPrinter() {
	t := e.term
	t.RegisterCsiHandler('i', func(params ansi.Params) bool {
		switch n, _, _ := params.Param(0, 0); n {
		case 4:
			e.autoPrint = false
		case 5:
			e.printerController = true
		}
		return false
	})
	t.RegisterCsiHandler(ansi.Command('?', 0, 'i'), func(params ansi.Params) bool {
		switch n, _, _ := params.Param(0, 0); n {
		case 4:
			e.autoPrint = false
		case 5:
			e.autoPrint = true
		}
		return false
	})
}

// watchMemoryLock registers the handlers that note HP's memory lock (ESC l)
// and unlock (ESC m), which xterm implements by moving the scroll region's
// top margin, keeping its bottom one: a lock moves it to the cursor's row,
// locking the rows above in place, and an unlock back to the screen's top,
// but neither sets a region that ends at or above its top. x/vt implements
// neither. Once one has moved the margin, xterm scrolls only the rows from it
// down and moves the cursor up no further than it, where x/vt scrolls and
// moves as before, so the emulator's screen may differ from the session's
// terminal's from there on, and neither an unlock nor a DECSTBM after it
// brings it back: the note stays. One that leaves the margin where it is, a
// lock on the region's top row, on its bottom row or below it, or an unlock
// with the region at the screen's top, changes nothing and isn't noted. The
// region and the cursor read are the emulator's, which the session's
// terminal holds too until a lock or an unlock has moved the margin. x/vt has
// no handler of its own for either; these return false all the same, as
// watchColours' do.
func (e *emulation) watchMemoryLock() {
	t := e.term
	t.RegisterEscHandler('l', func() bool {
		reg, y := t.ActiveScreen().ScrollRegion(), t.CursorPosition().Y
		if y != reg.Min.Y && y < reg.Max.Y-1 {
			e.memoryLock = true
		}
		return false
	})
	t.RegisterEscHandler('m', func() bool {
		if t.ActiveScreen().ScrollRegion().Min.Y != 0 {
			e.memoryLock = true
		}
		return false
	})
}

// watchKeyFormats registers the handlers that note the stream setting how the
// terminal encodes the modifiers of a key it sends the program, where the
// tracker doesn't restore it: XTMODKEYS (CSI > Pp ; Pv m) for any resource
// but modifyOtherKeys (4), which the tracker keeps; XTFMTKEYS
// (CSI > Pp ; Pv f) for any; and XTMODKEYS's disable (CSI > Pp n), the bare
// one too, which xterm reads as disabling modifyFunctionKeys, but CSI > 4 n,
// which the tracker keeps. x/vt keeps none of them, where a raw replay sets
// each on the joiner's terminal, so the joiner's keys would reach the program
// otherwise encoded. One that moves no resource off the value a terminal
// starts with isn't noted (see keyResets), as the tracker reads CSI > 4 ; m.
// The note stays, whatever follows, though xterm's DECSTR and
// RIS put every resource back. x/vt keys a CSI handler by its prefix too, so
// these see neither SGR (CSI Pm m) nor DSR (CSI Ps n) nor HVP
// (CSI Ps ; Ps f), and the query filter drops XTQMODKEYS (CSI ? Pp m). x/vt
// has no handler of its own for any of them; these return false all the
// same, as watchColours' do.
func (e *emulation) watchKeyFormats() {
	t := e.term
	t.RegisterCsiHandler(ansi.Command('>', 0, 'm'), func(params ansi.Params) bool {
		if n, _, _ := params.Param(0, -1); n != 4 && !keyResets(params) {
			e.keyFormat = true
		}
		return false
	})
	t.RegisterCsiHandler(ansi.Command('>', 0, 'f'), func(params ansi.Params) bool {
		if !keyResets(params) {
			e.keyFormat = true
		}
		return false
	})
	t.RegisterCsiHandler(ansi.Command('>', 0, 'n'), func(params ansi.Params) bool {
		if len(params) != 1 || params[0] != 4 {
			e.keyFormat = true
		}
		return false
	})
}

// keyResets reports whether params, an XTMODKEYS's or an XTFMTKEYS's, move no
// resource off the value a terminal starts with: a resource with nothing
// after it, no value nor a mask, which x/ansi keeps as parameters after it,
// puts that one back; and none at all, which ctlseqs documents as putting
// every resource back, xterm's parser reads as naming no resource, as it gives
// a CSI one omitted parameter from the start, and so does nothing. Neither is
// noted, whichever a terminal does.
func keyResets(params ansi.Params) bool {
	for i := 1; i < len(params); i++ {
		if params[i].Param(-1) >= 0 {
			return false
		}
	}
	return true
}

// watchLocator registers the handlers that note DECELR (CSI Ps ; Pu ' z)
// turning DEC locator reporting on, by its first parameter as xterm reads it:
// 1 on, 2 on for one report, and any other value off; and DECSLE
// (CSI Pm ' {) selecting a button event a report is sent for, by any of its
// parameters as xterm reads them: 1 a press, 3 a release, where 0 clears
// both, 2 and 4 one each, and xterm ignores the rest. x/vt keeps none of it,
// where a raw replay sets each on the joiner's terminal: one with reporting
// on reports the joiner's mouse to the program by itself, and xterm keeps the
// events selected, RIS included, for a DECELR that turns reporting on later,
// the program's live one among them. The notes stay, whatever follows, though
// a later DECELR or RIS turns reporting off and a DECSLE clears an event:
// falling back costs only the raw replay, and a one-report locator turns
// itself off on the session's terminal once the mouse is reported, which the
// stream doesn't show. DECEFR (CSI Pt ; Pl ; Pb ; Pr ' w), which sends a
// report once the pointer leaves a rectangle, xterm takes only while
// reporting is on and forgets at the next DECELR, so it isn't noted. The
// query filter drops DECRQLP (CSI Ps ' |), which asks for the locator's
// position. x/vt has no handler of its own for either; these return false all
// the same, as watchColours' do.
func (e *emulation) watchLocator() {
	t := e.term
	t.RegisterCsiHandler(ansi.Command(0, '\'', 'z'), func(params ansi.Params) bool {
		if n, _, _ := params.Param(0, 0); n == 1 || n == 2 {
			e.locator = true
		}
		return false
	})
	t.RegisterCsiHandler(ansi.Command(0, '\'', '{'), func(params ansi.Params) bool {
		for _, p := range params {
			if n := p.Param(0); n == 1 || n == 3 {
				e.locatorEvents = true
			}
		}
		return false
	})
}

// iTerm2State are the keys of iTerm2's commands, OSC 1337 ; key = value,
// that change what it shows, or how, until another changes it again: its
// profile and the profile's properties, its colours, its background image,
// its badge, the cursor's shape and its guide line, the Unicode version its
// character widths follow, the Touch Bar's key labels and their stack, and
// CopyToClipboard, after which it copies what is printed to the pasteboard
// until EndCopy. So do those that leave on the output something a cell
// doesn't hold, which stays as long as the output does: an annotation
// (AddNote and AddHiddenNote are its old names), a block, a block folded or
// unfolded, and a button, which iTerm2 draws in four cells of its own, moving
// the cursor; and ClearScrollback, which clears the scrollback, and the screen
// but for the prompt.
var iTerm2State = map[string]bool{
	"SetProfile":             true,
	"SetProfileProperty":     true,
	"SetColors":              true,
	"SetBackgroundImageFile": true,
	"SetBadgeFormat":         true,
	"CursorShape":            true,
	"HighlightCursorLine":    true,
	"UnicodeVersion":         true,
	"SetKeyLabel":            true,
	"PushKeyLabels":          true,
	"PopKeyLabels":           true,
	"CopyToClipboard":        true,
	"AddAnnotation":          true,
	"AddHiddenAnnotation":    true,
	"AddNote":                true,
	"AddHiddenNote":          true,
	"Block":                  true,
	"UpdateBlock":            true,
	"Button":                 true,
	"ClearScrollback":        true,
}

// watchITerm2 registers the handler that notes the first of the commands in
// iTerm2State the stream sent, by its key. x/vt has no OSC 1337 handler of
// its own, so it drops every one, where a raw replay hands each to a joiner's
// iTerm2, which acts on it. iTerm2 reads the key as what follows the OSC's
// number and its ';' up to the first '=', or all of it with none, and takes
// it exactly, so a key in another case, or with more after it, is none of
// these. Every one counts, whatever its value, one iTerm2 ignores too, and
// the note stays, whatever follows, RIS included: the raw ring is exact
// whatever came after. SetWindowFrame, which moves and resizes iTerm2's
// window, is noted as a window operation (see watchWindowOps).
//
// The other commands render: what iTerm2's shell integration sends at every
// prompt (RemoteHost, CurrentDir, ShellIntegrationVersion, SetUserVar and
// SetMark), which the next prompt sends again, and which noted would fail
// every join to a shell that has it; and those that leave nothing on iTerm2's
// display: a request for attention or for the focus, a notification, a Copy
// to the pasteboard, the reports iTerm2 answers, which the query filter lets
// into the ring, and a key it doesn't have. watchGraphics notes an image, and
// watchFont every OSC 50, which iTerm2 reads as OSC 1337 too. x/vt has no
// handler of its own for it; this returns false all the same, as
// watchColours' do.
func (e *emulation) watchITerm2() {
	e.term.RegisterOscHandler(1337, func(data []byte) bool {
		// data is the whole OSC, its number first.
		_, cmd, _ := bytes.Cut(data, []byte{';'})
		key, _, _ := bytes.Cut(cmd, []byte{'='})
		switch {
		case string(key) == "SetWindowFrame":
			e.windowOp = true
		case e.iTerm2 == "" && iTerm2State[string(key)]:
			e.iTerm2 = string(key)
		}
		return false
	})
}

// watchLEDs registers the handler that notes DECLL (CSI Ps q), which lights
// or puts out the keyboard's LEDs, each parameter in turn as xterm reads
// them: 0 or none puts every one out, 1 to 3 light Num Lock, Caps Lock and
// Scroll Lock, and 21 to 23 are documented as putting each out. x/vt keeps
// no LEDs, where a raw replay sets those of the joiner's keyboard, as xterm
// does through the X server's keyboard control. Every one counts, whatever
// its parameters, a clear too, as it puts out LEDs the joiner's keyboard had
// lit, and the note stays, whatever follows, though xterm's RIS puts every
// LED out. x/vt keys a CSI handler by its prefix and intermediate too, so
// this one sees neither DECSCUSR (CSI Ps SP q), DECSCA (CSI Ps " q) nor
// XTVERSION (CSI > Ps q), and no other sequence has a bare q, nor does the
// query filter drop any DECLL. A prefix byte after a parameter, which makes
// xterm ignore the sequence, x/vt's parser skips, so CSI 1 > q is noted too.
// x/vt has no handler of its own for it; this returns false all the same, as
// watchColours' do.
func (e *emulation) watchLEDs() {
	e.term.RegisterCsiHandler('q', func(ansi.Params) bool {
		e.leds = true
		return false
	})
}

// watchLogFile registers the handler that notes OSC 46, which sets the file
// xterm logs what it receives to once logging starts, by DECSET 46 or its
// menu. x/vt keeps no log file, where a raw replay sets the joiner's, and so
// where its logging writes. xterm takes it only when built to allow logging
// and a change of its file, neither of which it is by default: built with
// logging alone it rings the bell instead, as it does for a ?, and it ignores
// one with no file. Every one counts all the same, as another build or
// terminal may take it, and the note stays, whatever follows, RIS included,
// which leaves xterm's file as it is. The query filter drops no OSC 46. x/vt
// has no handler of its own for it; this returns false all the same, as
// watchColours' do.
func (e *emulation) watchLogFile() {
	e.term.RegisterOscHandler(46, func([]byte) bool {
		e.logFile = true
		return false
	})
}

// watchWindowProperty registers the handler that notes OSC 3, which sets an X
// property on xterm's window, OSC 3 ; prop = value, for other X clients, a
// window manager among them, to read, or deletes one, OSC 3 ; prop. x/vt
// keeps no window, where a raw replay sets or deletes the joiner's property.
// xterm takes it only once its allowed window operations include SetXprop,
// which they don't by default, and ignores one with no property. Every one
// counts all the same, as another configuration or terminal may take it, and
// the note stays, whatever follows: RIS leaves the window's properties as
// they are, and a deletion can't be told to put back what the joiner's window
// held before, which isn't known. OSC 3 asks for nothing, so the query filter
// drops none. x/vt has no handler of its own for it; this returns false all
// the same, as watchColours' do.
func (e *emulation) watchWindowProperty() {
	e.term.RegisterOscHandler(3, func([]byte) bool {
		e.windowProperty = true
		return false
	})
}

// watchCoding registers the handler that notes ESC % @, which xterm and the
// Linux console read as leaving UTF-8 for their default coding, ISO-8859-1.
// x/vt reads UTF-8 alone, where a raw replay hands the joiner's terminal the
// selection, after which it reads each byte past ASCII as a character of its
// own, as the session's terminal does, where x/vt reads a UTF-8 sequence:
// the bytes printed after the handoff, the program's own, among them. The
// note stays, whatever follows: an ESC % G that selects UTF-8 again leaves
// what was printed in between, which x/vt may have read as other characters,
// and xterm puts back at ESC % @ the character sets it saved at the ESC % G
// before it, and resets them at the next, which x/vt doesn't; and RIS leaves
// the coding as it is. ESC % G itself, UTF-8 as x/vt reads, isn't noted.
// Every one counts, though an xterm whose resources make UTF-8 its only
// coding ignores it. x/vt keys a handler by the last intermediate alone, so
// ESC ( % @, which xterm ignores, is noted too; watchCharsets94 notes other
// finals after %. x/vt has no handler of its own for it; this returns false
// all the same, as watchColours' do.
func (e *emulation) watchCoding() {
	e.term.RegisterEscHandler(ansi.Command(0, '%', '@'), func() bool {
		e.nonUTF8 = true
		return false
	})
}

// watchControls registers the handlers that keep whether the stream left the
// terminal sending the program 8-bit controls: S8C1T (ESC SP G) selects them,
// and S7C1T (ESC SP F) puts back the 7-bit controls a terminal starts with, as
// xterm's RIS does too, though not its DECSTR. xterm takes either at a VT220's
// level and up, its default VT420 among them, and then sends the program the C1
// control in place of ESC and its 7-bit character, CSI for ESC [ and SS3 for
// ESC O, in each key, mouse report and reply that starts with one. x/vt keeps
// no such setting, where a raw replay selects it on the joiner's terminal,
// whose keys would then reach the program as the session's terminal's do. It
// changes nothing the terminal draws, so it fails the render only when selected
// at the handoff. A DECSCL, which selects either form too, is noted as a
// conformance level (see watchConformanceLevel). x/vt has no handler of its own
// for either, nor for any other ESC with SP before its final; these return
// false all the same, as watchColours' do.
func (e *emulation) watchControls() {
	t := e.term
	t.RegisterEscHandler(ansi.Command(0, ' ', 'G'), func() bool {
		e.eightBit = true
		return false
	})
	t.RegisterEscHandler(ansi.Command(0, ' ', 'F'), func() bool {
		e.eightBit = false
		return false
	})
	t.RegisterEscHandler('c', func() bool {
		e.eightBit = false
		return false
	})
}

// watchSizedText registers the handler that notes OSC 66, kitty's text
// sizing, OSC 66 ; metadata ; text, which draws the text scaled, each
// character over a block of cells up to seven rows high, or in as many cells
// as the metadata says, and moves the cursor past them on its row. x/vt drops
// the whole OSC, the text and the cursor's move with it, where a raw replay
// hands it to the joiner's kitty, which draws it as the session's did, and
// what follows it on that row lands where kitty's cursor went. Every one
// counts, one kitty ignores too, as one with metadata it can't read or with
// no text, and the note stays, whatever follows, RIS included: the raw ring
// is exact whatever came after. OSC 66 asks for nothing, so the query filter
// drops none. x/vt has no handler of its own for it; this returns false all
// the same, as watchColours' do.
func (e *emulation) watchSizedText() {
	e.term.RegisterOscHandler(66, func([]byte) bool {
		e.sizedText = true
		return false
	})
}

// watchExtraCursors registers the handler that notes kitty's multiple
// cursors, CSI > Ps ; … SP q, which show extra cursors, or colour them, as
// extraCursorsSet reads them. x/vt has no handler for them, so it drops them,
// where a raw replay hands them to the joiner's kitty, which shows them as the
// session's did. The note stays, whatever follows: the raw ring is exact
// whatever came after, though kitty takes the cursors away at a clear, at an
// ED 2, 3 or 22 and at a switch of screens, and both them and their colours
// at RIS and DECSTR. x/vt keys a CSI handler by its prefix and intermediate
// too, so this one sees neither DECSCUSR (CSI Ps SP q), XTVERSION (CSI > Ps
// q), DECSCA (CSI Ps " q) nor DECLL (CSI Ps q). x/vt has no handler of its
// own for them; this returns false all the same, as watchColours' do.
func (e *emulation) watchExtraCursors() {
	e.term.RegisterCsiHandler(ansi.Command('>', ' ', 'q'), func(params ansi.Params) bool {
		if extraCursorsSet(params) {
			e.extraCursors = true
		}
		return false
	})
}

// extraCursorsSet reports whether params, those of kitty's CSI > Ps ; … SP q,
// show an extra cursor or colour them, as kitty reads them: the first is a
// shape, or 30 or 40 for the colour of the text under the extra cursors or of
// the cursors themselves, and each group of parameters after it a place for
// the shape, or a colour. Three forms show nothing: shape 0 only takes
// cursors away, which a joiner's kitty, taken to be at its defaults, doesn't
// show; a colour of 0 in every parameter puts back the main cursor's, which a
// terminal starts with; and with no group, kitty only answers a query, which
// the query filter lets into the ring and x/vt drops, or does nothing. Every
// other shape counts, one kitty doesn't have too, whatever its place, a cell
// off the screen included, and so does every other colour.
func extraCursorsSet(params ansi.Params) bool {
	if len(params) < 2 {
		return false
	}
	switch params[0].Param(0) {
	case 0:
		return false
	case 30, 40:
		for _, p := range params[1:] {
			if p.Param(0) != 0 {
				return true
			}
		}
		return false
	}
	return true
}

// watchUnscroll registers the handler that notes kitty's unscroll, CSI Ps +
// T, which scrolls the screen down Ps lines, as SD does, but fills the lines
// it opens at the top from the scrollback, taking each line out of it, as
// mintty does too. x/vt drops it, scrolling nothing, where a raw replay hands
// it to the joiner's kitty, which scrolls its screen and its scrollback as
// the session's did. Every one counts, one kitty ignores too, as one with
// more than one parameter, or one of 0 lines, which moves nothing, and the
// note stays, whatever follows, RIS included: the raw ring is exact whatever
// came after. x/vt keys a CSI handler by its prefix and intermediate too, so
// this one sees neither SD (CSI Ps T), which x/vt follows, nor XTRMTITLE
// (CSI > Pm T), nor one with a prefix as well, which kitty ignores. The query
// filter drops none. x/vt has no handler of its own for it; this returns
// false all the same, as watchColours' do.
func (e *emulation) watchUnscroll() {
	e.term.RegisterCsiHandler(ansi.Command(0, '+', 'T'), func(ansi.Params) bool {
		e.unscroll = true
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

// screenTitles hands x/vt the window title strings of GNU screen and tmux,
// ESC k title ST, as those terminals read them when one is the session's own
// terminal, under whose TERM oh-my-zsh sends one at every prompt: a string,
// ended by an ESC, CAN or SUB, BEL included, none of which is drawn (tmux's
// rename_string state). x/vt, as xterm, reads ESC k as a sequence done at the
// k and draws the title as text. So the k of each ESC k is handed to it as
// ^, which makes the string a PM: x/ansi's parser consumes one as tmux does
// the title, to an ESC, CAN or SUB, with BEL and well-formed UTF-8 inside it.
// A PM rather than an APC, which the parser reads alike, as watchGraphics
// notes an APC whose data starts with G, as a title may, and nothing handles
// a PM. The tracker clone, fed what x/vt is, reads the PM as a string too,
// and tracks nothing a title holds either way. The byte is replaced in the
// emulation's own copy of the stream, never in the ring's chunks, and in
// place, so every offset, the handoff point's included, stays the stream's.
//
// esc is that x/vt's parser is in its escape state with no intermediate,
// where a k completes an ESC k: after an ESC, which enters that state from
// every state, ending a string too, and through any C0 control but CAN and
// SUB, which it executes there, and DEL, which it ignores. It carries from
// the tracker's snapshot into the ring, and across every piece of the stream
// offered, so an ESC and its k split between them are read as one.
//
// A ring that starts inside a title, after its k, starts it as text, as a
// raw replay does on a joiner's tmux.
type screenTitles struct{ esc bool }

// read replaces in p, the next bytes x/vt's parser reads, the k of each
// ESC k with ^.
func (s *screenTitles) read(p []byte) {
	for i, b := range p {
		switch {
		case b == 0x1b:
			s.esc = true
		case !s.esc:
		case b == 'k':
			p[i] = '^'
			s.esc = false
		case b < 0x18 || b == 0x19 || b >= 0x1c && b <= 0x1f || b == 0x7f:
			// Executed or ignored where it stands, in the escape state.
		default:
			s.esc = false
		}
	}
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
// tail, with each screen title string made x/vt's (see screenTitles), and
// runs a batch. A failure spends the emulation.
func (e *emulation) offer(chunks [][]byte, sizes []uio.SizeEvent) error {
	for _, chunk := range chunks {
		e.tail = append(e.tail, chunk...)
		e.screenTitles.read(e.tail[len(e.tail)-len(chunk):])
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
