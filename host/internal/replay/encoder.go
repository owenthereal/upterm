package replay

import (
	"image/color"
	"strconv"
	"unicode/utf8"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/owenthereal/x/ansi"

	uio "github.com/owenthereal/upterm/io"
)

// encoder writes a reconstruction into a buffer with a hard cap, and models
// the joiner's terminal as it goes: the pen, link and charsets it has
// emitted, and what each screen's DECSC slot holds of them. Every SGR, OSC 8
// and SCS it writes goes from the model, never from a default, so it is
// right whatever the render wrote before it; and an ESC 8 takes the model
// back to what the matching ESC 7 recorded. The model starts from a terminal
// at its defaults (see reset): the render's preamble makes the pen, link and
// charsets so, and the render sets the saved slots itself before any restore
// of its own reads them, the main screen's always and the alternate screen's
// whenever it draws on that screen.
//
// Each method fails before an append would cross the cap, leaving the buffer
// and the model as they were, so nothing past the cap is ever allocated;
// the first failure sticks, and every later call returns it. The
// stop function is checked once per row.
type encoder struct {
	buf  []byte
	max  int
	stop func() bool // ctx or the deadline; nil never stops
	pen  uv.Style
	link uv.Link
	cs   charsets
	slot [2]savedModel // by screen: mainScreen, altScreen
	err  error
}

// The screens, as the encoder's slots are indexed.
const (
	mainScreen = 0
	altScreen  = 1
)

// charsets is what the joiner's terminal maps a printed byte through: the
// character set designated to each of G0-G3, by the final byte of the SCS
// that designated it, and which of them GL invokes. GR invokes none of them
// for a print, whose byte is ASCII, so only its default is ever rendered.
type charsets struct {
	g  [4]byte
	gl int
}

// ascii is a terminal's charsets as it starts: ASCII in G0-G3, G0 in GL.
var ascii = charsets{g: [4]byte{'B', 'B', 'B', 'B'}}

// savedModel is what the model says a DECSC slot holds.
type savedModel struct {
	pen  uv.Style
	link uv.Link
	cs   charsets
}

// reset empties e for a new reconstruction of at most limit bytes, from a
// terminal at its defaults: the zero pen and link, ASCII charsets, and slots
// no DECSC has filled, which DECRC restores the same defaults from. It keeps
// its buffer's storage.
func (e *encoder) reset(limit int) {
	e.buf, e.max = e.buf[:0], max(limit, 0)
	e.pen, e.link, e.cs, e.err = uv.Style{}, uv.Link{}, ascii, nil
	e.slot = [2]savedModel{{cs: ascii}, {cs: ascii}}
}

// room makes room for n more bytes within the cap, or fails. It grows the
// buffer itself rather than leaving it to append, whose doubling would
// allocate past the cap.
func (e *encoder) room(n int) error {
	if e.err != nil {
		return e.err
	}
	need := len(e.buf) + n
	if need > e.max {
		e.err = ErrOverBudget
		return e.err
	}
	if need > cap(e.buf) {
		grown := make([]byte, len(e.buf), min(max(2*cap(e.buf), need, 256), e.max))
		copy(grown, e.buf)
		e.buf = grown
	}
	return nil
}

// bytes appends p.
func (e *encoder) bytes(p []byte) error {
	if err := e.room(len(p)); err != nil {
		return err
	}
	e.buf = append(e.buf, p...)
	return nil
}

// put appends each of s, all of them or none.
func (e *encoder) put(s ...string) error {
	n := 0
	for _, p := range s {
		n += len(p)
	}
	if err := e.room(n); err != nil {
		return err
	}
	for _, p := range s {
		e.buf = append(e.buf, p...)
	}
	return nil
}

// cup moves the cursor to a 1-based row and column.
func (e *encoder) cup(row, col int) error {
	var b [24]byte
	s := strconv.AppendInt(append(b[:0], "\x1b["...), int64(row), 10)
	s = strconv.AppendInt(append(s, ';'), int64(col), 10)
	return e.bytes(append(s, 'H'))
}

// cha moves the cursor to a 1-based column of its row.
func (e *encoder) cha(col int) error {
	var b [16]byte
	s := strconv.AppendInt(append(b[:0], "\x1b["...), int64(col), 10)
	return e.bytes(append(s, 'G'))
}

// shifts invoke G0-G3 into GL: SI, SO, LS2 and LS3.
var shifts = [4]string{"\x0f", "\x0e", "\x1bn", "\x1bo"}

// charsetsTo writes the SCS for each designation that differs from the
// model's, then the shift that invokes to's GL if that differs, and nothing
// if the two are the same.
func (e *encoder) charsetsTo(to charsets) error {
	if e.err != nil {
		return e.err
	}
	if e.cs == to {
		return nil
	}
	var b [16]byte
	s := b[:0]
	for i, d := range to.g {
		if e.cs.g[i] != d {
			s = append(s, 0x1b, "()*+"[i], d)
		}
	}
	if e.cs.gl != to.gl {
		s = append(s, shifts[to.gl]...)
	}
	if err := e.bytes(s); err != nil {
		return err
	}
	e.cs = to
	return nil
}

// save writes ESC 7, recording the modelled pen, link and charsets as the
// slot of screen, the one showing.
func (e *encoder) save(screen int) error {
	return e.saveBy("\x1b7", screen)
}

// saveBy writes seq, a sequence that saves the cursor in screen's slot as
// DECSC does, and records the model there.
func (e *encoder) saveBy(seq string, screen int) error {
	if err := e.put(seq); err != nil {
		return err
	}
	e.slot[screen] = savedModel{e.pen, e.link, e.cs}
	return nil
}

// restore writes ESC 8, setting the model back from the slot of screen, the
// one showing.
func (e *encoder) restore(screen int) error {
	return e.restoreBy("\x1b8", screen)
}

// restoreBy writes seq, a sequence that restores the cursor from screen's
// slot as DECRC does, and sets the model back from there.
func (e *encoder) restoreBy(seq string, screen int) error {
	if err := e.put(seq); err != nil {
		return err
	}
	s := e.slot[screen]
	e.pen, e.link, e.cs = s.pen, s.link, s.cs
	return nil
}

// penTo writes the SGR that takes the modelled pen to to, and nothing if the
// two are the same.
//
// The same means exactly the same, colour types included: ultraviolet
// compares colours by value, so SGR 31 and 38;5;1 compare equal, but a
// terminal whose palette was changed shows them apart, and its own SGR
// reports tell them apart too. ultraviolet's diff leaves out a colour it
// compares equal, so where a colour changes only in its type, the pen is
// written whole after a reset instead.
func (e *encoder) penTo(to uv.Style) error {
	if e.err != nil {
		return e.err
	}
	if e.pen == to {
		return nil
	}
	var err error
	if retyped(e.pen, to) {
		err = e.put("\x1b[m", to.String())
	} else {
		err = e.put(uv.StyleDiff(&e.pen, &to))
	}
	if err != nil {
		return err
	}
	e.pen = to
	return nil
}

// retyped reports a colour of to that ultraviolet compares equal to from's
// and isn't the same: a change its diff leaves out.
func retyped(from, to uv.Style) bool {
	return retypedColor(from.Fg, to.Fg) || retypedColor(from.Bg, to.Bg) ||
		retypedColor(from.UnderlineColor, to.UnderlineColor)
}

func retypedColor(from, to color.Color) bool {
	if from == to || from == nil || to == nil {
		return false
	}
	fr, fg, fb, fa := from.RGBA()
	tr, tg, tb, ta := to.RGBA()
	return fr == tr && fg == tg && fb == tb && fa == ta
}

// linkTo writes the OSC 8 that takes the modelled link to to, and nothing
// if the two are the same. One OSC 8 sets both the parameters and the URL,
// and an empty one closes the link, so it needs no close first.
func (e *encoder) linkTo(to uv.Link) error {
	if e.err != nil {
		return e.err
	}
	if e.link == to {
		return nil
	}
	if err := e.put("\x1b]8;", to.Params, ";", to.URL, "\x07"); err != nil {
		return err
	}
	e.link = to
	return nil
}

// cell writes c at the cursor, in its own pen and link.
func (e *encoder) cell(c *uv.Cell) error {
	return e.cellAfter("", c)
}

// cellAfter writes c as cell does, right after a cell whose text was prev,
// or "" when anything but that print came before. A terminal segments the
// text it prints, so two cells the emulator kept apart, because something
// other than a print came between them, can print back to back as one
// cluster: a lone regional indicator and another, an emoji and a skin tone,
// a base and a spacing mark. Where nothing else comes between them and they
// would, a NUL goes first, which a terminal ignores and which ends the
// cluster.
func (e *encoder) cellAfter(prev string, c *uv.Cell) error {
	return e.whole(func() error {
		n := len(e.buf)
		if err := e.penTo(c.Style); err != nil {
			return err
		}
		if err := e.linkTo(c.Link); err != nil {
			return err
		}
		text := content(c)
		if len(e.buf) == n && joins(prev, text) {
			if err := e.put("\x00"); err != nil {
				return err
			}
		}
		return e.put(text)
	})
}

// joins reports two clusters that printed back to back segment as one, as
// the fork's parser segments printed text. Printable ASCII never joins the
// cluster before it.
func joins(prev, next string) bool {
	if prev == "" || next[0] < utf8.RuneSelf {
		return false
	}
	var b [64]byte
	both := append(append(b[:0], prev...), next...)
	cluster, _ := ansi.FirstGraphemeCluster(both, ansi.GraphemeWidth)
	return len(cluster) > len(prev)
}

// content is what the encoder prints for c: a cell holding nothing is a
// space.
func content(c *uv.Cell) string {
	if c.Content == "" {
		return " "
	}
	return c.Content
}

// row writes line's cells from the cursor on, each in its own pen and link,
// but for its trailing blanks, which the joiner's screen, cleared before any
// row is drawn, holds already. A wide character's placeholder is left out:
// the character itself moves the cursor past it. Two cells that would print
// as one cluster are kept apart (see cellAfter). The row ends at the zero pen
// and link, so whatever follows starts from them.
func (e *encoder) row(line uv.Line) error {
	if e.err != nil {
		return e.err
	}
	if e.stop != nil && e.stop() {
		e.err = uio.ErrReplayDeadline
		return e.err
	}
	return e.whole(func() error {
		end := len(line)
		for end > 0 && line[end-1] == uv.EmptyCell {
			end--
		}
		prev := ""
		for i := range line[:end] {
			if line[i].Width == 0 {
				continue
			}
			if err := e.cellAfter(prev, &line[i]); err != nil {
				return err
			}
			prev = content(&line[i])
		}
		if err := e.penTo(uv.Style{}); err != nil {
			return err
		}
		return e.linkTo(uv.Link{})
	})
}

// whole runs f, a method made of others, as one: if it fails, the buffer and
// the model are put back as they were before it.
func (e *encoder) whole(f func() error) error {
	n, pen, link := len(e.buf), e.pen, e.link
	err := f()
	if err != nil {
		e.buf, e.pen, e.link = e.buf[:n], pen, link
	}
	return err
}

// encodeLine renders line, a line of history, on its own: from the zero pen
// and link back to them, in at most limit bytes.
func encodeLine(line uv.Line, limit int) ([]byte, error) {
	var e encoder
	e.reset(limit)
	if err := e.row(line); err != nil {
		return nil, err
	}
	return e.buf, nil
}
