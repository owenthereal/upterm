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
// State it can't restore fails it before anything is written; a history line
// it can't rebuild fails it once the lines to send are known. Within the
// budget, everything but the history must fit on its own, or the render
// fails, named when what doesn't fit is a clipboard write; the history then
// fills what is left, newest lines first, cut at whole lines, between the
// preamble and the rest.
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
		enc:     enc,
		term:    e.term,
		parts:   parts,
		title:   e.title,
		titled:  e.titled,
		rows:    e.join.Rows,
		fits:    e.join.Cols == e.term.Width(),
		rep:     rep,
		cwd:     e.cwd,
		cwdTold: e.cwdTold,
		clips:   e.clips,
	}
	r.draw()
	if r.cwdOver {
		return nil, &IneligibleError{State: "a working directory too long to replay"}
	}
	if r.clipOver {
		return nil, &IneligibleError{State: "a clipboard write too large to replay"}
	}
	if enc.err != nil {
		return nil, enc.err
	}
	from, size := e.hist.newest(budget - len(preamble) - len(enc.buf))
	// A history line goes as it scrolled off, so one holding a split wide
	// character can't be rebuilt either. Only the lines sent count, and which
	// those are is known only once the rest is drawn.
	if e.hist.splitFrom(from) {
		return nil, &IneligibleError{State: splitWideState}
	}
	out := make([]byte, 0, len(preamble)+size+len(enc.buf))
	out = append(out, preamble...)
	out = e.hist.appendFrom(out, from)
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
	// title is the one the stream last set, if titled: an empty one too,
	// which clears the joiner's.
	title  string
	titled bool
	rows   int // the joiner's
	// fits is a joiner as wide as the render, where a character printed in
	// the render's last column leaves a wrap pending, as it did on the
	// session's terminal. A wider joiner gets no wrap, as a wider live
	// client doesn't.
	fits bool
	rep  rep
	// cwd is the working directory to send, if cwdTold, and cwdOver says it
	// didn't fit.
	cwd              string
	cwdTold, cwdOver bool
	// clips are the clipboard writes to send, and clipOver says one didn't
	// fit.
	clips    clipboard
	clipOver bool
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
	// The hidden alternate screen's trip saves the cursor in the main
	// screen's slot and restores it from there, so it comes before that slot
	// is set.
	if !t.IsAltScreen() {
		r.hiddenAlt()
	}
	// ?1049h saves the main screen's slot itself, as the alternate screen is
	// entered.
	if r.parts.AltVia != 1049 {
		r.slot(t.MainScreen(), mainScreen)
	}
	// The tracker's modes, but for autowrap, which goes off only after the
	// last wrap reprint; the report modes it doesn't know; and its kitty
	// keyboard stack for the main screen, which shows.
	_ = enc.bytes(r.parts.Modes)
	r.reportModes()
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
// while that screen shows.
//
// It goes there and back by ?1049, not ?47: Alacritty and Windows Terminal
// have ?1049 but ignore ?47, so on them a trip by ?47 would erase the main
// screen just drawn and draw the alternate screen over it.
// ?1049h saves the cursor in the main screen's slot, as ESC 7 does, then
// switches and clears; ?1049l switches back and restores the cursor from that
// slot, as ESC 8 does, so the pen, link and charsets after the trip are those
// before it.
func (r *renderer) hiddenAlt() {
	enc, alt := r.enc, r.term.AltScreen()
	if !hasCells(alt) && defaultSlot(alt.SavedCursor()) && r.parts.HiddenAltKeys == nil {
		return
	}
	// ?1049h clears what the joiner's terminal last left there, which xterm
	// does in the pen's background, as ED 2 does, so the pen goes to the
	// default first. The clear then leaves the blank screen the rows are
	// drawn on, and no ED 2 is needed after it.
	_ = enc.penTo(uv.Style{})
	_ = enc.saveBy("\x1b[?1049h", mainScreen)
	r.screen(alt)
	if !defaultSlot(alt.SavedCursor()) {
		r.slot(alt, altScreen)
	}
	_ = enc.bytes(r.parts.HiddenAltKeys)
	_ = enc.restoreBy("\x1b[?1049l", mainScreen)
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

// reportModes sets the modes that make the terminal send reports unasked and
// that the tracker doesn't know, after the tracker's own and by number, as the
// tracker would send them if it did.
func (r *renderer) reportModes() {
	t := r.term
	if t.Mode(ansi.ModeLightDark).IsSet() {
		_ = r.enc.put(ansi.SetModeLightDark)
	}
}

// continuation sets the state that decides how the next bytes are read and
// that neither moves the cursor nor clears a pending wrap, after the last
// print, which the charsets would remap and insert mode would shift: the
// charsets, insert mode, the application keypad, reverse video, the title,
// the cursor's style, autowrap, and the active pen and link. The working
// directory and the clipboard writes still in force, which change none of
// that, come last of all.
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
	if r.titled {
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
	r.workingDirectory()
	r.clipboard()
	if len(enc.buf) == reprinted {
		_ = enc.put("\x00")
	}
}

// workingDirectory writes the working directory the stream last reported, as
// the stream sent it, ended by BEL: a raw replay hands the joiner every OSC 7
// in the ring, which leave it at the last. One that doesn't fit the budget
// with everything before it sets cwdOver instead, and the render fails on it.
func (r *renderer) workingDirectory() {
	if !r.cwdTold || r.enc.err != nil {
		return
	}
	if r.enc.put("\x1b]7;", r.cwd, "\x07") != nil {
		r.cwdOver = true
	}
}

// clipboard writes the clipboard writes still in force, each as the stream
// sent it, ended by BEL. One that doesn't fit the budget with everything
// before it, or that was too long to keep, sets clipOver instead, and the
// render fails on it.
func (r *renderer) clipboard() {
	if r.enc.err != nil {
		return
	}
	for _, w := range r.clips {
		if w.over || r.enc.put("\x1b]52;", w.pc, ";", w.pd, "\x07") != nil {
			r.clipOver = true
			return
		}
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

// The DEC private modes the render treats apart from the tracker's.
var (
	modeReverseVideo = ansi.DECMode(5)

	// restoredModes are restored by the render itself, apart from the
	// tracker's modes: reverse video and the keypad with the continuation
	// state, the others after the tracker's modes (see reportModes).
	restoredModes = map[ansi.DECMode]bool{
		modeReverseVideo:       true,
		ansi.ModeNumericKeypad: true,
		// ?2031: after this, the terminal reports a change of its colour
		// scheme, light or dark, unasked. The program asked for those
		// reports, and a raw replay passes the mode through.
		ansi.ModeLightDark: true,
	}

	// ignoredModes are left as the joiner's terminal has them: neither
	// restored nor a reason to fall back, since none changes where output
	// lands or what the screen or the cursor hold, and only one changes what
	// the terminal sends unasked, whose reports would be wrong from a joiner
	// (in-band resize, below). The mode snapshot a raw replay starts with
	// holds none of them either; only the ring's own bytes can carry one.
	// Most change only how the terminal encodes the keyboard or the mouse,
	// which the joiner's own terminal does for the joiner, and a program
	// that relies on one sends it again (readline sends ?1034h at every
	// prompt where the terminfo entry has it, as xterm-256color's does).
	ignoredModes = map[ansi.DECMode]bool{
		// The cursor's blink: appearance only.
		ansi.DECMode(12): true,
		// A synchronized update, which only holds back the drawing.
		ansi.ModeSynchronizedOutput: true,
		// In-band resize reports: setting the mode makes a terminal report
		// its size at once, and again on every change, in the input. From a
		// joiner that is the joiner's own size, not the session's, which the
		// program learns from the pty's resizes anyway.
		ansi.ModeInBandResize: true,
		// Set, xterm's DECSC; reset, its DECRC: actions, not a mode. Nothing
		// reads the bit back, and the slot the save filled is restored with
		// the saved cursors.
		ansi.ModeSaveCursor: true,
		// On the alternate screen, the mouse wheel sends cursor up and down
		// keys instead of scrolling the terminal's own view.
		ansi.DECMode(1007): true,
		// Mouse reports in urxvt's decimal encoding.
		ansi.DECMode(1015): true,
		// The Meta key sets the eighth bit of keyboard input.
		ansi.DECMode(1034): true,
		// Special modifiers for the Alt and NumLock keys.
		ansi.DECMode(1035): true,
		// Meta sends ESC before the key it modifies.
		ansi.DECMode(1036): true,
		// The editing keypad's Delete key sends DEL.
		ansi.DECMode(1037): true,
		// Alt sends ESC before the key it modifies.
		ansi.DECMode(1039): true,
		// The function keys as terminfo or termcap, Sun, HP and SCO keyboards
		// send them.
		ansi.DECMode(1050): true,
		ansi.DECMode(1051): true,
		ansi.DECMode(1052): true,
		ansi.DECMode(1053): true,
		// The keyboard of X11R6's xterm, and a VT220's.
		ansi.DECMode(1060): true,
		ansi.DECMode(1061): true,
		// win32-input-mode: keys as Windows' own key events. ConPTY sets it as
		// it starts, and takes keyboard input either way.
		ansi.DECMode(9001): true,
	}
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
	if e.colours.changed() {
		return rep{}, &IneligibleError{State: "a changed palette or dynamic colour"}
	}
	// A sixel is a device control string too, named as what it draws.
	if e.graphics {
		return rep{}, &IneligibleError{State: "terminal graphics"}
	}
	if e.dcs {
		return rep{}, &IneligibleError{State: "a device control string"}
	}
	if e.protected {
		return rep{}, &IneligibleError{State: "character protection"}
	}
	if e.selective {
		return rep{}, &IneligibleError{State: "a selective erase"}
	}
	if e.savedTitle {
		return rep{}, &IneligibleError{State: "a saved title"}
	}
	if e.savedModes {
		return rep{}, &IneligibleError{State: "saved DEC modes"}
	}
	if splitWide(e.term.MainScreen()) || splitWide(e.term.AltScreen()) {
		return rep{}, &IneligibleError{State: splitWideState}
	}
	return e.repPlan()
}

// splitWideState is what a render falls back on when a row it would draw, of
// a screen or of the history, holds a wide character split in two.
const splitWideState = "a wide character split in two"

// splitWide reports a row of scr that holds a wide character split in two.
// A screen the render doesn't draw holds nothing, so both are checked.
func splitWide(scr *vt.Screen) bool {
	for y := range scr.Height() {
		if splitLine(scr.Line(y)) {
			return true
		}
	}
	return false
}

// splitLine reports whether line holds a wide character split in two: a
// placeholder not right after the wide cell it belongs to, or a wide cell not
// followed by its placeholders. A scroll inside left and right margins can
// move half of a wide character across a margin, and no print draws what it
// leaves, as printing a wide character brings its placeholders: the render
// would draw another row, a line of history included, which a joiner's
// terminal also wraps where it prints wider than the screen.
func splitLine(line uv.Line) bool {
	owed := 0 // the placeholders the last wide cell has yet to be followed by
	for x := range line {
		switch w := line[x].Width; {
		case w == 0:
			if owed == 0 {
				return true
			}
			owed--
		case owed > 0:
			return true
		default:
			owed = w - 1
		}
	}
	return owed > 0
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
// nor ignores (see ignoredModes), or "".
//
// It restores the tracker's modes, which the emulator agrees on (see
// consistent), the screen switch the tracker says entered the alternate
// screen, insert mode, the keypad, reverse video and the report modes. So a
// switch mode set otherwise than as that one entry leaves it is one; so are
// DECLRMM, which changes what CSI s means, and any other mode the tracker
// doesn't know.
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
		if _, tracked := p.DECModes[n]; tracked || restoredModes[dec] || ignoredModes[dec] {
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
