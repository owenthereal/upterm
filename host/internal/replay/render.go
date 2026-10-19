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

// preamble starts every render, after what begins again a synchronized
// update open at the handoff point (see synced). It makes the terminal what
// the encoder takes it to be, whatever a program left it holding, with the
// cursor kept on its row of the main screen, where the history starts:
//   - the main screen showing, after a DECSC: ?1047l clears the alternate
//     screen and leaves it, if it shows; ?1049l leaves it if it still shows,
//     on a terminal that has ?1049 only, and either way restores the cursor
//     from the main screen's slot, where ?1049h saved it on the way there,
//     and where the DECSC just saved it on a joiner already on its main
//     screen; ?47l leaves it on a terminal that has ?47 only. On the main
//     screen, that restore of what the DECSC just saved is all any of them
//     does, and resetting all three leaves none set on a terminal that keeps
//     each apart, as x/vt does;
//   - the whole screen as the scroll region (DECSTBM) and no left and right
//     margins (DECLRMM off, which resets them, as xterm's does), between a
//     DECSC and a DECRC, since DECSTBM homes the cursor. The DECRC puts it
//     back where it was, under origin mode or not, since both address the
//     same cells once the whole screen is the region. The two use the main
//     screen's slot, as the first DECSC does on a joiner already on its main
//     screen, and the render sets that slot again before anything reads it
//     (see draw);
//   - insert mode, LNM and reverse video off, autowrap on, and the cursor
//     shown, in the terminal's default style (DECSCUSR 0), none of which
//     moves the cursor or is what a DECRC restores;
//   - ASCII designated into G0 to G3, G0 in GL (SI) and G2 in GR (LS2R),
//     after the DECRCs, which put back the charsets their DECSCs saved;
//   - the cursor to the start of its row, the default pen and no link (an
//     OSC 8 with no URL closes one), and the screen erased from there down.
//
// A program that exits or is killed can leave any of them: on the alternate
// screen, the render would draw over the program's screen, which the
// joiner's next ?1049l would put away, its own shell's screen coming back
// over the session's; a region would scroll only its own rows as the
// history's line feeds come, none of them into the scrollback, and margins
// only theirs; insert mode would shift the cells a reprint lands on; LNM
// would make the live line feeds return the carriage, where the session's
// don't; autowrap off would keep the live text that reaches the last column
// there; reverse video, a hidden cursor or a style of its own would show the
// screen otherwise than the session's terminal does; and the render's text
// would print through a link or a charset left in place, linked or remapped.
// GR maps no UTF-8 a print sends, but DECSC saves it, and the render takes it
// to be G2 (see unrestored). Origin mode, which DECRC restores and whose
// reset homes the cursor, goes off after the history (see draw).
//
// A joiner left on its alternate screen holds in that screen's slot what the
// first DECSC saved there, which the render sets again only when it draws on
// that screen (see hiddenAlt), as it leaves a joiner's own slot there
// otherwise.
//
// The charsets come before the CR because a terminal with no SCS for G2 or
// G3, as the Linux console's, takes the ESC alone and prints the final byte
// after it, at the cursor; the erase from the row's start then clears it. The
// joiner's own output above the cursor stays, for the blank screen drawn
// after the history to scroll into its scrollback.
const preamble = "\x1b7\x1b[?1047;1049;47l" +
	"\x1b7\x1b[?69l\x1b[r\x1b8\x1b[4l\x1b[20l\x1b[?5l\x1b[?7;25h\x1b[0 q" +
	"\x1b(B\x1b)B\x1b*B\x1b+B\x0f\x1b}\r\x1b[m\x1b]8;;\x07\x1b[J"

// render reconstructs the emulator's state at the handoff point on the
// joiner's terminal, which it takes to be at its defaults, the preamble
// making it so for the screen showing, the scroll region and margins, the
// modes that change where a print lands or how the screen shows, the
// cursor's visibility and style, the pen, the link and the charsets, and
// draw for origin mode: the history that
// scrolled off, then both screens, both saved cursors and every state that
// decides how the next bytes are read, so that the raw stream from the
// handoff point on lands on it as it did on the session's own terminal.
//
// State it can't restore fails it before anything is written; a history line
// it can't rebuild fails it once the lines to send are known. Within the
// budget, everything but the history must fit on its own, or the render
// fails, named when what doesn't fit is a clipboard write or the working
// directory; the history then fills what is left, newest lines first, cut at
// whole lines, between the preamble and the rest. A synchronized update open
// at the handoff point is begun before all of it (see synced).
func (e *emulation) render() ([]byte, error) {
	parts := e.modes.ReplayParts()
	rep, err := e.eligible(parts)
	if err != nil {
		return nil, err
	}
	lead := e.synced()
	head := len(lead) + len(preamble)
	enc := &e.enc
	enc.reset(budget - head)
	enc.stop = e.stop
	r := renderer{
		enc:    enc,
		term:   e.term,
		parts:  parts,
		title:  e.title,
		titled: e.titled,
		icon:   e.icon,
		iconed: e.iconed,
		titles: e.titles,
		// A name a pop put back too long to keep can't be sent.
		titleOver: e.titled && e.titleOver,
		iconOver:  e.iconed && e.iconOver,
		rows:      e.join.Rows,
		cols:      e.join.Cols,
		fits:      e.join.Cols == e.term.Width(),
		stops:     append(e.term.TabStops(), e.pastEdge.between(e.term.Width(), e.join.Cols)...),
		rep:       rep,
		colours:   &e.colours,
		cwd:       e.cwd,
		cwdTold:   e.cwdTold,
		clips:     e.clips,
	}
	r.draw()
	if r.titleOver {
		return nil, &IneligibleError{State: "a saved title too long to replay"}
	}
	if r.iconOver {
		return nil, &IneligibleError{State: "a saved icon name too long to replay"}
	}
	if r.cwdOver {
		return nil, &IneligibleError{State: "a working directory too long to replay"}
	}
	if r.clipOver {
		return nil, &IneligibleError{State: "a clipboard write too large to replay"}
	}
	if enc.err != nil {
		return nil, enc.err
	}
	from, size := e.hist.newest(budget - head - len(enc.buf))
	// A history line goes as it scrolled off, so one holding a split wide
	// character can't be rebuilt either. Only the lines sent count, and which
	// those are is known only once the rest is drawn.
	if e.hist.splitFrom(from) {
		return nil, &IneligibleError{State: splitWideState}
	}
	out := make([]byte, 0, head+size+len(enc.buf))
	out = append(out, lead...)
	out = append(out, preamble...)
	out = e.hist.appendFrom(out, from)
	return append(out, enc.buf...), nil
}

// The DCS form of synchronized output's beginning and end.
const (
	beginSyncDCS = "\x1bP=1s\x1b\\"
	endSyncDCS   = "\x1bP=2s\x1b\\"
)

// synced is what the render starts with: the beginning of a synchronized
// update when the stream is inside one at the handoff point, a frame the
// program began and has yet to end, and nothing otherwise. The session's
// terminal holds its display until the program's own end, which the live
// bytes carry, and a joiner's terminal begun the same way holds the render
// and what follows it until then too.
//
// That is the last the stream sent of each form, ?2026 and the DCS form (see
// syncForms), in the stream's order, but for an end that comes first, which
// closes nothing: a terminal that takes one form then follows that form's
// last, and one that takes both the later of the two, as the session's does.
// So an update both forms began begins by both again, of which a terminal
// that takes both reads the second as inside the first, and either end then
// closes it; and an update one form began and the other ended is begun and
// ended again. An update ended leaves nothing to restore, which is why ?2026
// is otherwise among the modes the render ignores.
func (e *emulation) synced() string {
	type form struct {
		seq    string
		begins bool
	}
	mode := form{ansi.ResetModeSynchronizedOutput, false}
	if e.term.Mode(ansi.ModeSynchronizedOutput).IsSet() {
		mode = form{ansi.SetModeSynchronizedOutput, true}
	}
	dcs := form{endSyncDCS, false}
	if e.sync.began {
		dcs = form{beginSyncDCS, true}
	}
	order := [2]form{dcs, mode}
	if e.sync.dcsLast {
		order = [2]form{mode, dcs}
	}
	lead := ""
	for _, f := range order {
		if f.begins || lead != "" {
			lead += f.seq
		}
	}
	return lead
}

// renderer draws what follows the history. Each step writes through the
// encoder, whose first failure sticks and makes every later call return at
// once, so the steps write on regardless and render checks the encoder's
// error once, at the end.
type renderer struct {
	enc   *encoder
	term  *vt.Emulator
	parts uio.ReplayParts
	// title is the one the stream last set or a pop put back, if titled: an
	// empty one too, which clears the joiner's. icon is the icon name, if
	// iconed, as title is.
	title  string
	titled bool
	icon   string
	iconed bool
	// titles is the title stack to push again, and titleOver and iconOver say
	// a title or an icon name it or the current one holds was too long to
	// keep.
	titles              titleStack
	titleOver, iconOver bool
	rows, cols          int // the joiner's
	// fits is a joiner as wide as the render, where a character printed in
	// the render's last column leaves a wrap pending, as it did on the
	// session's terminal. A wider joiner gets no wrap, as a wider live
	// client doesn't.
	fits bool
	// stops are the tab stops to set across the joiner's width: the
	// emulator's, then past its width those it keeps there (see pastEdge).
	stops []int
	rep   rep
	// colours is the last change the stream made to each colour, none of
	// them a setting once the render is eligible.
	colours *colours
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
	// Origin mode off, which a program can leave set: under it, the final
	// cursor's CUP, after the region the render sets, would land inside that
	// region, and so would the live bytes' CUPs after one they set. Resetting
	// it homes the cursor, so it can't come with the preamble, which keeps
	// the cursor's row for the history to start on; with the whole screen as
	// the region, which the preamble set, it moves none of the history's
	// prints, CRs and line feeds before it. Everything after it places the
	// cursor by CUP before it writes.
	_ = enc.put(ansi.ResetModeOrigin)
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
// while that screen shows. Once there, it sets the slot whatever it holds, as
// alt does. A slot no DECSC filled is no reason to go there: the trip costs
// two screen switches, and a joiner's own slot there then stays, which only a
// program that restores on the alternate screen before saving there reads.
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
	r.slot(alt, altScreen)
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
// stack. The slot is set even when no DECSC filled it, as the main screen's
// always is, so that a live DECRC there restores the defaults it restores on
// the session's terminal, not what the joiner's own programs saved there.
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
	r.slot(alt, altScreen)
	_ = enc.bytes(r.parts.AltKeys)
}

// tabStops sets the tab stops in every render, as the session's terminal
// holds them, since a program can leave a joiner's with any: every stop
// cleared, then one set at each column, reached from the row's start (CR) by
// CUF, the shortest move that lands exactly, as no left margin is set here
// (see unrestored). A joiner wider than the render gets, past the render's
// width, the stops the session's terminal keeps there, which a widening of
// the pty would bring onto its screen. Neither CR nor CUF writes a cell, but
// both move the cursor, so they come before it is placed.
func (r *renderer) tabStops() {
	_ = r.enc.put("\x1b[3g\r")
	at := 0
	for _, x := range r.stops {
		if x > at {
			_ = r.enc.cuf(x - at)
			at = x
		}
		_ = r.enc.put("\x1bH")
	}
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
// charsets, insert mode, the application keypad, reverse video, the title
// stack and then the icon name and the title, the cursor's style, autowrap,
// and the active pen and link. The colours the stream reset, the working
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
	r.titleStack()
	if r.iconed && !r.iconOver {
		_ = enc.put("\x1b]1;", r.icon, "\x07")
	}
	if r.titled && !r.titleOver {
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
	r.colourResets()
	r.workingDirectory()
	r.clipboard()
	if len(enc.buf) == reprinted {
		_ = enc.put("\x00")
	}
}

// colourResets resets each colour whose last change in the stream was its
// reset (see colours), as a raw replay leaves it on a joiner's terminal that
// a program of its own gave a colour of its own. The palette's entries go by
// one OSC 104 listing them, and the special colours by one OSC 105 listing
// them, numbered from 0, as every terminal that has OSC 105 reads them:
// xterm's OSC 104 takes them too, numbered on from the palette's 256, but
// another terminal's may skip the numbers past 255, as Alacritty's does. Each
// goes with no list, which resets them all, once every entry it resets was
// reset, but OSC 104 only once the whole table was: xterm's with no list
// resets the special colours as well. Each dynamic colour goes by its own
// reset, OSC 110 to 119, as xterm ignores one that names more.
func (r *renderer) colourResets() {
	c := r.colours
	special := c.table[paletteSize:]
	r.tableResets("104", c.table[:paletteSize], allReset(c.table[:]))
	r.tableResets("105", special, allReset(special))
	for i, ch := range c.dynamic {
		if ch == colourReset {
			_ = r.enc.put("\x1b]", strconv.Itoa(110+i), "\x07")
		}
	}
}

// tableResets sends osc, OSC 104 or 105, for part, the entries of the colour
// table it numbers from 0: with no list when bare, else listing each entry
// whose last change was a reset, and nothing at all when none was.
func (r *renderer) tableResets(osc string, part []colourChange, bare bool) {
	if bare {
		_ = r.enc.put("\x1b]", osc, "\x07")
		return
	}
	list := append([]byte("\x1b]"), osc...)
	head := len(list)
	for i, ch := range part {
		if ch == colourReset {
			list = strconv.AppendInt(append(list, ';'), int64(i), 10)
		}
	}
	if len(list) > head {
		_ = r.enc.bytes(append(list, '\a'))
	}
}

// allReset reports whether the last change to every colour of part was its
// reset.
func allReset(part []colourChange) bool {
	return !slices.ContainsFunc(part, func(ch colourChange) bool { return ch != colourReset })
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

// titleStack pushes the title stack's entries again, oldest first, the icon
// name and the window title each saved set before it where the stream had set
// that one. Where it hadn't, the joiner's own name still shows, as the
// session's own did: such an entry is pushed only while the name is the
// terminal's own, so every entry under it that saved the name saved the
// terminal's own too, and none of their names is set first. That holds of
// each name apart, so an entry of both that saved only the title the stream
// set is pushed under the joiner's own icon name, which the joiner then
// saves, as the session's saved its own. A name too long to keep sets
// titleOver or iconOver instead, and the render fails on it.
//
// Places lost under the entries (see the type) say the session's terminal
// pushed past ten: each of the ten places of xterm's stack holds what the
// stream pushed there, or nothing once popped, and what the stack held
// before the ring is gone. The joiner's is made so too: entries of neither
// name, which put nothing back, as a lost place doesn't, fill the places the
// entries leave, below them, so that what the joiner's held is gone as well.
func (r *renderer) titleStack() {
	enc, s := r.enc, r.titles
	if s.lost > 0 {
		for range maxTitles - len(s.entries) {
			_ = enc.put("\x1b[22;3t")
		}
	}
	for _, en := range s.entries {
		if en.titled && en.over {
			r.titleOver = true
			return
		}
		if en.iconed && en.iconOver {
			r.iconOver = true
			return
		}
		if en.iconed {
			_ = enc.put("\x1b]1;", en.icon, "\x07")
		}
		if en.titled {
			_ = enc.put("\x1b]2;", en.title, "\x07")
		}
		_ = enc.put("\x1b[22;", strconv.Itoa(en.ps), "t")
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
	// or what a key does, which the joiner's own terminal does for the
	// joiner, and a program that relies on one sends it again (readline
	// sends ?1034h at every prompt where the terminfo entry has it, as
	// xterm-256color's does); a few change only how the terminal shows its
	// own view of the output, which is the joiner's own too. That holds
	// whichever way the stream left one, so neither a set nor a reset counts,
	// though a terminal starts with some of them set.
	ignoredModes = map[ansi.DECMode]bool{
		// The cursor's blink: appearance only.
		ansi.DECMode(12): true,
		// The keypad's shifted plus and minus change the font's size (rxvt's
		// mode, which xterm starts with set).
		ansi.DECMode(35): true,
		// DECBKM: the backarrow key sends BS, or DEL once reset (xterm starts
		// with it set).
		ansi.DECMode(67): true,
		// A synchronized update, which only holds back the drawing. One open
		// at the handoff point is begun again, before the rest (see synced).
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
		// Output scrolls the terminal's own view back to the bottom (rxvt's
		// mode, which xterm starts with set).
		ansi.DECMode(1010): true,
		// xterm skips repainting while output scrolls fast: appearance only
		// (it starts with it set).
		ansi.DECMode(1014): true,
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
		// The selection is kept once it is no longer highlighted (xterm
		// starts with it set).
		ansi.DECMode(1040): true,
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

	// defaultModes are the DEC private modes a terminal starts with set, as
	// xterm does with its default resources, that the render neither
	// restores nor ignores. A set of one leaves it as it starts; a reset
	// fails the render once the stream has sent it (see watchDefaultModes),
	// as the joiner's terminal would keep the mode set. Of the others xterm
	// starts with set, the render restores autowrap and the cursor's
	// visibility; it ignores ?35, ?67, ?1034, ?1035 and ?1037, which only
	// change what keys do or send, and ?1010, ?1014 and ?1040, which only
	// change how the terminal shows its own view of the output; and xterm
	// itself ignores a set or reset of autorepeat (?8), of the cursor's XOR
	// blink (?14) and of ?1020 to ?1023, which it only reports.
	defaultModes = map[ansi.DECMode]bool{
		// DECANM: reset, xterm reads what follows as a VT52 does, until
		// ESC <, where a DECSET, a CSI of any kind and RIS are no sequences.
		// x/vt has no VT52 mode, so it reads those bytes otherwise.
		ansi.DECMode(2): true,
		// The alternate screen may be shown: reset, xterm leaves it at once
		// and ignores ?47, ?1047, ?1048 and ?1049 until it is set again
		// (titeInhibit), none of which x/vt does.
		ansi.DECMode(1046): true,
		// Each sixel image gets colour registers of its own
		// (privateColorRegisters).
		ansi.DECMode(1070): true,
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
	// An image in a tmux passthrough is both, named as what it draws.
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
	if e.titleIndexed {
		return rep{}, &IneligibleError{State: "a title stack entry by index"}
	}
	if e.titleModes {
		return rep{}, &IneligibleError{State: "a title mode"}
	}
	if e.savedModes {
		return rep{}, &IneligibleError{State: "saved DEC modes"}
	}
	if e.defaultReset != 0 {
		return rep{}, &IneligibleError{State: fmt.Sprintf("a default mode reset (?%d)", e.defaultReset)}
	}
	if e.savedRendition {
		return rep{}, &IneligibleError{State: "a saved rendition"}
	}
	if e.savedPalette {
		return rep{}, &IneligibleError{State: "a saved palette"}
	}
	if e.undrawable {
		return rep{}, &IneligibleError{State: "a rendition the render can't draw"}
	}
	if e.doubleSize {
		return rep{}, &IneligibleError{State: "a double-size line"}
	}
	if e.statusLine {
		return rep{}, &IneligibleError{State: "a status line"}
	}
	if e.font {
		return rep{}, &IneligibleError{State: "a font change"}
	}
	if e.rectExtent {
		return rep{}, &IneligibleError{State: "a rectangular attribute extent"}
	}
	if e.conformance {
		return rep{}, &IneligibleError{State: "a conformance level"}
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
// doesn't know, but those a terminal starts with set, whose set leaves them
// as they start and whose reset eligible fails on (see defaultModes).
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
		if _, tracked := p.DECModes[n]; tracked || restoredModes[dec] || ignoredModes[dec] || defaultModes[dec] {
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
