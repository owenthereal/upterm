package replay

import (
	"cmp"
	"fmt"
	"image/color"
	"maps"
	"slices"
	"strconv"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/owenthereal/x/ansi"
	"github.com/owenthereal/x/vt"

	uio "github.com/owenthereal/upterm/io"
)

// preamble starts every render: the cursor to the start of its row, the
// default pen, and the screen erased from there down. The joiner's own
// output above the cursor stays, for the blank screen drawn after the
// history to scroll into its scrollback.
const preamble = "\r\x1b[m\x1b[J"

// render reconstructs the emulator's state at the handoff point on the
// joiner's terminal, which it takes to be at its defaults: the history that
// scrolled off, then both screens, both saved cursors and every state that
// decides how the next bytes are read, so that the raw stream from the
// handoff point on lands on it as it did on the session's own terminal.
//
// State it can't restore fails it before anything is written. Within the
// budget, everything but the history must fit on its own, or the render
// fails; the history then fills what is left, newest lines first, cut at
// whole lines, between the preamble and the rest.
func (e *emulation) render() ([]byte, error) {
	parts := e.modes.ReplayParts()
	rep, err := e.eligible(parts)
	if err != nil {
		return nil, err
	}
	enc := &e.enc
	enc.reset(budget - len(preamble))
	enc.stop = e.stop
	r := renderer{
		enc:   enc,
		term:  e.term,
		parts: parts,
		title: e.title,
		rows:  e.join.Rows,
		fits:  e.join.Cols == e.term.Width(),
		rep:   rep,
	}
	r.draw()
	if enc.err != nil {
		return nil, enc.err
	}
	first, size := e.hist.newest(budget - len(preamble) - len(enc.buf))
	out := make([]byte, 0, len(preamble)+size+len(enc.buf))
	out = append(out, preamble...)
	out = e.hist.appendFrom(out, first)
	return append(out, enc.buf...), nil
}

// renderer draws what follows the history. Each step writes through the
// encoder, whose first failure sticks and makes every later call return at
// once, so the steps write on regardless and render checks the encoder's
// error once, at the end.
type renderer struct {
	enc   *encoder
	term  *vt.Emulator
	parts uio.ReplayParts
	title string
	rows  int // the joiner's
	// fits is a joiner as wide as the render, where a character printed in
	// the render's last column leaves a wrap pending, as it did on the
	// session's terminal. A wider joiner gets no wrap, as a wider live
	// client doesn't.
	fits bool
	rep  rep
}

// draw writes everything but the preamble and the history, in an order each
// step depends on.
func (r *renderer) draw() {
	enc, t := r.enc, r.term
	// A blank screen, top-aligned: from whatever row the history left the
	// cursor on, a line feed short of the joiner's height reaches its bottom
	// row and scrolls every row above it off, into its scrollback, in order.
	// The preamble's erase and the history's last CRLF leave the cursor's own
	// row blank, so one more would scroll a blank line in.
	for range r.rows - 1 {
		_ = enc.put(crlf)
	}
	r.screen(t.MainScreen())
	// The hidden alternate screen's trip uses the main screen's slot, so it
	// comes before that slot is set.
	if !t.IsAltScreen() {
		r.hiddenAlt()
	}
	// ?1049h saves the main screen's slot itself, as the alternate screen is
	// entered.
	if r.parts.AltVia != 1049 {
		r.slot(t.MainScreen(), mainScreen)
	}
	// The tracker's modes, but for autowrap, which goes off only after the
	// last wrap reprint, and its kitty keyboard stack for the main screen,
	// which shows.
	_ = enc.bytes(r.parts.Modes)
	_ = enc.bytes(r.parts.MainKeys)
	r.alt()
	r.tabStops()
	r.region()
	reprinted := r.cursor()
	r.continuation(reprinted)
}

// screen draws each row of scr that holds anything but blank cells at its
// own row, on a screen that is blank already.
func (r *renderer) screen(scr *vt.Screen) {
	for y := range scr.Height() {
		line := scr.Line(y)
		if blankLine(line) {
			continue
		}
		_ = r.enc.cup(y+1, 1)
		_ = r.enc.row(line)
	}
}

// hiddenAlt rebuilds the alternate screen while the main screen shows, when
// there is anything to rebuild: its cells, which a later ?47h shows as they
// are; its saved slot; and its kitty keyboard stack, which a push changes only
// while that screen shows. It goes there and back by ?47, which carries the
// cursor both ways, inside an ESC 7 and ESC 8 of the main screen's slot that
// put the pen, link and charsets back after it.
func (r *renderer) hiddenAlt() {
	enc, alt := r.enc, r.term.AltScreen()
	if !hasCells(alt) && defaultSlot(alt.SavedCursor()) && r.parts.HiddenAltKeys == nil {
		return
	}
	_ = enc.save(mainScreen)
	_ = enc.put("\x1b[?47h")
	// ?47h shows whatever the joiner's terminal last left there, and ED 2
	// erases in the pen's background.
	_ = enc.penTo(uv.Style{})
	_ = enc.put("\x1b[2J")
	r.screen(alt)
	if !defaultSlot(alt.SavedCursor()) {
		r.slot(alt, altScreen)
	}
	_ = enc.bytes(r.parts.HiddenAltKeys)
	_ = enc.put("\x1b[?47l")
	_ = enc.restore(mainScreen)
}

// slot sets the saved slot of scr, the screen showing, to what a DECRC there
// would restore.
func (r *renderer) slot(scr *vt.Screen, screen int) {
	r.slotState(scr)
	_ = r.enc.save(screen)
	r.slotDone()
}

// slotState puts the joiner's terminal in the state the saved slot of scr,
// the screen showing, holds, for a DECSC there to save it: the cursor at the
// slot's position, the wrap pending if the slot holds one, then the slot's
// pen and link, and its charsets.
//
// The position is the one saved, which a resize leaves even off the screen,
// for DECRC to clamp; a joiner the size of the render clamps it the same way
// as it moves there. A wrap is set by printing the cell in the last column
// (the wide character whose second half that is, for one), on the row DECRC
// would restore, in that cell's own pen and link, under the ASCII charsets
// the model holds here, so the cell is as it was. The slot's own pen and link
// come after it, since the print leaves the cell's, and neither SGR nor OSC 8
// clears the wrap.
func (r *renderer) slotState(scr *vt.Screen) {
	enc, c := r.enc, scr.SavedCursor()
	if c.Saved.Wrap && r.fits {
		y := min(c.Y, scr.Height()-1)
		x, cell := lastColumn(scr, y)
		_ = enc.cup(y+1, x+1)
		_ = enc.cell(cell)
	} else {
		_ = enc.cup(c.Y+1, c.X+1)
	}
	_ = enc.penTo(c.Pen)
	_ = enc.linkTo(c.Link)
	_ = enc.charsetsTo(charsets{g: c.Saved.Designations, gl: c.Saved.GL})
}

// slotDone puts back the ASCII charsets and no link after a slot is saved,
// so the drawing still to come is neither remapped nor linked.
func (r *renderer) slotDone() {
	_ = r.enc.charsetsTo(ascii)
	_ = r.enc.linkTo(uv.Link{})
}

// alt shows the alternate screen through the mode that entered it, when it
// shows, and draws it: its rows, its saved slot and its kitty keyboard
// stack.
//
// ?47h and ?1047h carry the cursor in, and back out on the program's own ?47l
// or ?1047l, so the main screen's cursor is no state of its own; neither
// clears, and the joiner's alternate screen may hold anything, so it is
// erased. ?1049h saves the main screen's slot as it enters, so the slot's
// state is set first, and it clears the alternate screen itself.
func (r *renderer) alt() {
	enc, t := r.enc, r.term
	switch r.parts.AltVia {
	case 0:
		return
	case 1049:
		r.slotState(t.MainScreen())
		_ = enc.saveBy("\x1b[?1049h", mainScreen)
		r.slotDone()
	default:
		_ = enc.put("\x1b[?", strconv.Itoa(r.parts.AltVia), "h")
		_ = enc.penTo(uv.Style{})
		_ = enc.put("\x1b[2J")
	}
	alt := t.AltScreen()
	r.screen(alt)
	if !defaultSlot(alt.SavedCursor()) {
		r.slot(alt, altScreen)
	}
	_ = enc.bytes(r.parts.AltKeys)
}

// tabStops sets the tab stops when they aren't a stop every 8 columns, as a
// terminal starts: every stop cleared, then one set at each column. They
// move the cursor, so they come before it is placed.
func (r *renderer) tabStops() {
	stops := r.term.TabStops()
	if slices.Equal(stops, defaultTabStops(r.term.Width())) {
		return
	}
	_ = r.enc.put("\x1b[3g")
	for _, x := range stops {
		_ = r.enc.cha(x + 1)
		_ = r.enc.put("\x1bH")
	}
}

// defaultTabStops are the columns of a screen width wide that have a tab
// stop when the terminal starts.
func defaultTabStops(width int) []int {
	ts := uv.DefaultTabStops(width)
	var stops []int
	for x := range width {
		if ts.IsStop(x) {
			stops = append(stops, x)
		}
	}
	return stops
}

// region sets the scroll region, the terminal's one, which no screen switch
// changes, once both screens are drawn: DECSTBM homes the cursor and clears a
// pending wrap, so it comes before the final cursor, and it is the screen
// showing at the end that a terminal keeping a region per screen would give
// it to. The left and right margins are always the screen's edges here (see
// unrestored).
func (r *renderer) region() {
	reg := r.term.ActiveScreen().ScrollRegion()
	if reg.Min.Y == 0 && reg.Max.Y == r.term.Height() {
		return
	}
	_ = r.enc.put("\x1b[", strconv.Itoa(reg.Min.Y+1), ";", strconv.Itoa(reg.Max.Y), "r")
}

// rep is how the render leaves REP's character, which every one-byte
// character it prints sets, as the session's terminal holds it.
type rep struct {
	// prime is a print of the character before the final cursor. Without
	// it, the wrap reprint sets it.
	prime bool
	at    uv.Position // where it is printed
	// blank is a print on a blank cell, which is then erased in bg, its
	// background; else the cell at holds the character already.
	blank bool
	bg    color.Color
}

// cursor sets REP's character, then places the active cursor: by a reprint
// of the last column's cell when a wrap is pending there and the joiner is
// as wide, which leaves it pending, so nothing after it moves the cursor;
// else by CUP. It returns the length of the render once the reprint was
// written, or -1 without one.
func (r *renderer) cursor() (reprinted int) {
	enc, t := r.enc, r.term
	scr := t.ActiveScreen()
	if p := r.rep; p.prime {
		// The charsets are ASCII here and insert mode is off, which come back
		// only after the last print, so the character prints as itself and
		// replaces the cell.
		_ = enc.cup(p.at.Y+1, p.at.X+1)
		if p.blank {
			_ = enc.penTo(uv.Style{Bg: p.bg})
			_ = enc.put(string(t.LastChar()))
			_ = enc.cup(p.at.Y+1, p.at.X+1)
			_ = enc.put("\x1b[X")
		} else {
			_ = enc.cell(scr.CellAt(p.at.X, p.at.Y))
		}
	}
	cur := t.CursorPosition()
	if t.PendingWrap() && r.fits {
		x, c := lastColumn(scr, cur.Y)
		_ = enc.cup(cur.Y+1, x+1)
		_ = enc.cell(c)
		return len(enc.buf)
	}
	_ = enc.cup(cur.Y+1, cur.X+1)
	return -1
}

// continuation sets the state that decides how the next bytes are read and
// that neither moves the cursor nor clears a pending wrap, after the last
// print, which the charsets would remap and insert mode would shift: the
// charsets, insert mode, the application keypad, reverse video, the title,
// the cursor's style, autowrap, and last the active pen and link.
//
// Autowrap goes off here, after every wrap reprint. A character that fills
// the line leaves a wrap pending with autowrap on or off, so where ?7l goes
// changes nothing; it is kept after the last reprint, and the tests pin that
// order.
//
// A render whose last action is the reprint ends with a NUL, which a
// terminal ignores, so the live bytes extend no cluster the render printed:
// the handoff point is after an action that isn't a print, where the
// session's terminal carries none.
func (r *renderer) continuation(reprinted int) {
	enc, t := r.enc, r.term
	d, gl, _ := t.Charsets()
	_ = enc.charsetsTo(charsets{g: d, gl: gl})
	if t.Mode(ansi.ModeInsertReplace).IsSet() {
		_ = enc.put("\x1b[4h")
	}
	if t.Mode(ansi.ModeNumericKeypad).IsSet() {
		_ = enc.put("\x1b=")
	}
	if t.Mode(modeReverseVideo).IsSet() {
		_ = enc.put("\x1b[?5h")
	}
	if r.title != "" {
		_ = enc.put("\x1b]2;", r.title, "\x07")
	}
	if style, blink := t.CursorStyle(); style != vt.CursorBlock || !blink {
		_ = enc.put(decscusr(style, blink))
	}
	if !r.parts.Autowrap {
		_ = enc.put("\x1b[?7l")
	}
	cur := t.ActiveScreen().Cursor()
	_ = enc.penTo(cur.Pen)
	_ = enc.linkTo(cur.Link)
	if len(enc.buf) == reprinted {
		_ = enc.put("\x00")
	}
}

// decscusr is the DECSCUSR that sets style: 1 and 2 a blinking and a steady
// block, 3 and 4 an underline, 5 and 6 a bar.
func decscusr(style vt.CursorStyle, blink bool) string {
	n := 2*int(style) + 1
	if !blink {
		n++
	}
	return "\x1b[" + strconv.Itoa(n) + " q"
}

// The DEC private modes the render treats apart from the tracker's: reverse
// video and the keypad, which it restores; the cursor's blink and a
// synchronized update, which are appearance only and not replayed.
var (
	modeReverseVideo = ansi.DECMode(5)
	restoredModes    = map[ansi.DECMode]bool{modeReverseVideo: true, ansi.ModeNumericKeypad: true}
	appearanceModes  = map[ansi.DECMode]bool{ansi.DECMode(12): true, ansi.ModeSynchronizedOutput: true}
)

// eligible fails the render, before anything is written, for a joiner that
// can't hold it or for state it doesn't restore, named; and says how it sets
// REP's character.
func (e *emulation) eligible(parts uio.ReplayParts) (rep, error) {
	w, h := e.term.Width(), e.term.Height()
	if e.join.Cols < w || e.join.Rows < h {
		return rep{}, fmt.Errorf("%w: %dx%d in %dx%d", ErrNotContained, w, h, e.join.Cols, e.join.Rows)
	}
	if state := e.unrestored(parts); state != "" {
		return rep{}, &IneligibleError{State: state}
	}
	return e.repPlan()
}

// unrestored names the first state, in a fixed order, that would change how
// the next bytes are read and that the render doesn't restore, or "". A
// render without it would make them land elsewhere than on the session's
// terminal, so the join falls back on it instead.
//
// A wrap is rebuilt only by a print at the last column, so a wrap pending
// anywhere else, which a widening, CBT and DECSTR can leave, is one of them;
// a saved slot's wrap is off the last column when DECRC wouldn't clamp it
// there. GR invokes no character set for a print of the UTF-8 bytes x/vt
// reads, but a terminal reading 8-bit bytes uses it, and the render leaves it
// at G2.
func (e *emulation) unrestored(parts uio.ReplayParts) string {
	t := e.term
	w := t.Width()
	reg := t.ActiveScreen().ScrollRegion()
	_, _, gr := t.Charsets()
	switch {
	case t.Mode(ansi.ModeOrigin).IsSet():
		return "origin mode"
	case reg.Min.X != 0 || reg.Max.X != w:
		return "DECSLRM left and right margins"
	case t.Mode(ansi.ModeLineFeedNewLine).IsSet():
		return "LNM"
	case t.SingleShift() != 0:
		return "a pending single shift"
	case gr != 2:
		return "GR other than G2"
	case t.PendingWrap() && t.CursorPosition().X != w-1:
		return "a pending wrap off the last column"
	}
	for _, s := range [...]struct {
		name string
		scr  *vt.Screen
	}{{"main", t.MainScreen()}, {"alternate", t.AltScreen()}} {
		c := s.scr.SavedCursor()
		switch {
		case c.Saved.Origin:
			return "the " + s.name + " screen's saved origin mode"
		case c.Saved.GR != 2:
			return "the " + s.name + " screen's saved GR other than G2"
		case c.Saved.Wrap && c.X < w-1:
			return "the " + s.name + " screen's saved pending wrap off the last column"
		}
	}
	return e.unrestoredMode(parts)
}

// unrestoredMode names the first mode, DEC modes first, then by number, that
// is set otherwise than as it starts and that the render neither restores
// nor leaves out as appearance only, or "".
//
// It restores the tracker's modes, which the emulator agrees on (see
// consistent), the screen switch the tracker says entered the alternate
// screen, insert mode, the keypad and reverse video. So a switch mode set
// otherwise than as that one entry leaves it is one; so are 1048, whose save
// the slot holds but whose mode the render doesn't set, DECLRMM, which
// changes what CSI s means, and any mode the tracker doesn't know.
func (e *emulation) unrestoredMode(p uio.ReplayParts) string {
	modes := e.term.Modes()
	for _, m := range slices.SortedFunc(maps.Keys(modes), compareModes) {
		set := modes[m].IsSet()
		dec, ok := m.(ansi.DECMode)
		if !ok {
			if set && m != ansi.ModeInsertReplace {
				return fmt.Sprintf("mode %d", m.Mode())
			}
			continue
		}
		n := int(dec)
		if _, tracked := p.DECModes[n]; tracked || restoredModes[dec] || appearanceModes[dec] {
			continue
		}
		switch dec {
		case ansi.DECMode(47), ansi.ModeAltScreen, ansi.ModeAltScreenSaveCursor:
			if set != (n == p.AltVia) {
				return fmt.Sprintf("mode ?%d", n)
			}
		default:
			if set {
				return fmt.Sprintf("mode ?%d", n)
			}
		}
	}
	return ""
}

// compareModes orders DEC modes before ANSI ones, each by number.
func compareModes(a, b ansi.Mode) int {
	_, aDEC := a.(ansi.DECMode)
	_, bDEC := b.(ansi.DECMode)
	if aDEC != bDEC {
		if aDEC {
			return -1
		}
		return 1
	}
	return cmp.Compare(a.Mode(), b.Mode())
}

// repPlan says how the render leaves REP's character as the emulator holds
// it, or fails. Each one-byte character the render prints sets it, so the
// last such print must be of that character:
//   - with a wrap pending and the joiner as wide, the reprint of the last
//     column's cell is the last print. One holding a byte sets it, which
//     fails the render unless that is the character; one of more bytes sets
//     nothing, so the character is printed first, as below;
//   - else, a print of the character before the final cursor: on the cell
//     nearest the cursor that holds it, in the cell's own pen and link; or on
//     a blank cell outside the last column whose style is a background only,
//     which an erase in that background then puts back.
//
// Nothing printed since the emulator started leaves no character, which no
// render that prints can keep, so that fails too.
func (e *emulation) repPlan() (rep, error) {
	t := e.term
	char := t.LastChar()
	if char == 0 {
		return rep{}, &IneligibleError{State: "REP's last character"}
	}
	want := string(char)
	scr := t.ActiveScreen()
	cur := t.CursorPosition()
	w := t.Width()
	if t.PendingWrap() && e.join.Cols == w {
		if _, c := lastColumn(scr, cur.Y); c.Width == 1 && len(content(c)) == 1 {
			if content(c) != want {
				return rep{}, &IneligibleError{State: "REP's last character under a pending wrap"}
			}
			return rep{}, nil
		}
	}

	// The nearest cell of each kind in row order, by its distance from the
	// cursor's.
	at := cur.Y*w + cur.X
	held, blank := -1, -1
	var heldDist, blankDist int
	var bg color.Color
	for y := range scr.Height() {
		line := scr.Line(y)
		for x := range line {
			c := &line[x]
			if c.Width != 1 {
				continue
			}
			d := abs(y*w + x - at)
			switch {
			case content(c) == want:
				if held < 0 || d < heldDist {
					held, heldDist = y*w+x, d
				}
			case x != w-1 && blankCell(c):
				if blank < 0 || d < blankDist {
					blank, blankDist, bg = y*w+x, d, c.Style.Bg
				}
			}
		}
	}
	switch {
	case held >= 0:
		return rep{prime: true, at: uv.Pos(held%w, held/w)}, nil
	case blank >= 0:
		return rep{prime: true, at: uv.Pos(blank%w, blank/w), blank: true, bg: bg}, nil
	}
	return rep{}, &IneligibleError{State: "REP's last character"}
}

// lastColumn is the cell a wrap pending on row y of scr was set by: the one
// in the last column, or the wide character whose second half that is, with
// its column.
func lastColumn(scr *vt.Screen, y int) (int, *uv.Cell) {
	x := scr.Width() - 1
	c := scr.CellAt(x, y)
	if c != nil && c.Width == 0 && x > 0 {
		x--
		c = scr.CellAt(x, y)
	}
	if c == nil {
		c = &uv.Cell{Content: " ", Width: 1}
	}
	return x, c
}

// blankCell reports a blank cell an erase in its background makes: a space,
// unlinked, with no style but that background.
func blankCell(c *uv.Cell) bool {
	return content(c) == " " && c.Width == 1 && c.Link == (uv.Link{}) && c.Style == (uv.Style{Bg: c.Style.Bg})
}

// blankLine reports a line of blank cells, which a cleared screen holds
// already.
func blankLine(line uv.Line) bool {
	for i := range line {
		if line[i] != uv.EmptyCell {
			return false
		}
	}
	return true
}

// hasCells reports a screen holding anything but blank cells.
func hasCells(scr *vt.Screen) bool {
	for y := range scr.Height() {
		if !blankLine(scr.Line(y)) {
			return true
		}
	}
	return false
}

// unsaved is what DECRC restores from a slot no DECSC has filled, but for the
// position, pen and link: ASCII in G0-G3, G0 in GL, G2 in GR, no origin mode
// and no wrap.
var unsaved = vt.SavedState{Designations: ascii.g, GR: 2}

// defaultSlot reports a slot that restores what a slot no DECSC has filled
// restores, which the joiner's own, untouched, does too.
func defaultSlot(c vt.Cursor) bool {
	st := c.Saved
	st.Saved = false
	return c.Position == (uv.Position{}) && c.Pen == (uv.Style{}) && c.Link == (uv.Link{}) && st == unsaved
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
