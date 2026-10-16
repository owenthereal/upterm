package replay

import (
	"image/color"

	uv "github.com/charmbracelet/ultraviolet"

	uio "github.com/owenthereal/upterm/io"
)

// encoder writes a reconstruction into a buffer with a hard cap, and models
// the joiner's terminal as it goes: the pen and link it has emitted. Every
// SGR and OSC 8 it writes goes from the model, never from a default, so it is
// right whatever the joiner's terminal held before.
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
	err  error
}

// reset empties e for a new reconstruction of at most limit bytes, from the
// zero pen and link, keeping its buffer's storage.
func (e *encoder) reset(limit int) {
	e.buf, e.max = e.buf[:0], limit
	e.pen, e.link, e.err = uv.Style{}, uv.Link{}, nil
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
	return e.whole(func() error {
		if err := e.penTo(c.Style); err != nil {
			return err
		}
		if err := e.linkTo(c.Link); err != nil {
			return err
		}
		content := c.Content
		if content == "" {
			content = " "
		}
		return e.put(content)
	})
}

// row writes line's cells from the cursor on, each in its own pen and link,
// but for its trailing blanks, which the joiner's screen, cleared before any
// row is drawn, holds already. A wide character's placeholder is left out:
// the character itself moves the cursor past it. The row ends at the zero pen
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
		for i := range line[:end] {
			if line[i].Width == 0 {
				continue
			}
			if err := e.cell(&line[i]); err != nil {
				return err
			}
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
