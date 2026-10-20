package replay

import (
	"bytes"
	"iter"

	uv "github.com/charmbracelet/ultraviolet"
)

// crlf follows each history line in the render.
const crlf = "\r\n"

// history keeps the newest lines that scrolled off the emulator's main
// screen, each encoded as it left and followed by the CRLF the render
// follows it with, within a budget: the oldest lines go to keep the total
// within max. So the history takes at most its budget, and holds as many
// lines as a render of that budget carries, even of a flood of blank lines,
// which cost a CRLF each.
//
// The lines are kept end to end in one buffer, rather than a slice each: a
// short line would cost more in its own allocation and slice header than in
// its bytes. The CRLFs are what mark where each line ends, since no line
// holds one of its own: a cell holds no control, and neither does a link's
// URL, as the parser leaves the C0 controls out of an OSC string.
type history struct {
	max  int
	data []byte // the lines kept, oldest first, each followed by a CRLF
	// split is where the newest line kept that holds a wide character split
	// in two ends, its CRLF included, or 0 for none. Only the newest matters:
	// a render sends the newest lines, so one that sends any such line sends
	// that one.
	split int
	// erased is set once the stream has cleared the history (see erase).
	erased bool
	enc    encoder
}

// push encodes line and keeps it, dropping the oldest lines past the
// budget. A line that alone, with its CRLF, costs more than the budget is
// dropped itself: no render could hold it. Every older line goes with it, as
// the render sends the lines kept one after another, and the joiner would
// see the older ones run on into the newer ones with that line missing
// between; a joiner's history then starts after it. It runs inside the
// emulator's Write, as its scroll-off function, and the line is the screen's
// own storage, so it is encoded here and never kept, and whether it holds a
// split wide character is told here too.
func (h *history) push(line uv.Line) {
	h.enc.reset(max(h.max-len(crlf), 0))
	if h.enc.row(line) != nil {
		// The split mark goes too, with the lines it is in.
		h.clear()
		return
	}
	h.data = append(append(h.data, h.enc.buf...), crlf...)
	if splitLine(line) {
		h.split = len(h.data)
	}
	if over := len(h.data) - h.max; over > 0 {
		cut := h.lineAt(over)
		h.data = h.data[cut:]
		// The cut is at a line's start, so a split line it took is gone whole,
		// and the mark with it.
		h.split = max(h.split-cut, 0)
	}
}

// lineAt is where the first line that starts at or after off starts: the
// end of the CRLF that ends at or after off, or the end of the history.
func (h *history) lineAt(off int) int {
	switch {
	case off <= 0:
		return 0
	case off >= len(h.data):
		return len(h.data)
	}
	from := max(off-len(crlf), 0)
	i := bytes.Index(h.data[from:], []byte(crlf))
	if i < 0 {
		return len(h.data)
	}
	return from + i + len(crlf)
}

// clear forgets every line.
func (h *history) clear() {
	h.data, h.split = nil, 0
}

// erase forgets every line, as ED 3 and RIS clear the history, and notes
// it: the session's terminal emptied its scrollback there, and a raw replay
// empties a joiner's, of the joiner's own lines too, so the render empties
// the joiner's as well (see render). A line push drops is no such clear: the
// session's terminal keeps it.
func (h *history) erase() {
	h.clear()
	h.erased = true
}

// all yields the lines kept, oldest first, without their CRLFs. Each is the
// history's own storage, valid until the next push or clear.
func (h *history) all() iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		for rest := h.data; len(rest) > 0; {
			i := bytes.Index(rest, []byte(crlf))
			if !yield(rest[:i:i]) {
				return
			}
			rest = rest[i+len(crlf):]
		}
	}
}

// newest returns where the newest lines that fit in room start, each with
// the CRLF the render follows it with, and the bytes they take. Lines are
// kept whole, so the history a render carries is cut at a line.
func (h *history) newest(room int) (from, size int) {
	from = h.lineAt(len(h.data) - room)
	return from, len(h.data) - from
}

// splitFrom reports whether a line from from, a line's start, on holds a
// wide character split in two: the newest such line ends past from.
func (h *history) splitFrom(from int) bool {
	return h.split > from
}

// appendFrom appends the lines from from on, oldest first, each followed by
// its CRLF.
func (h *history) appendFrom(out []byte, from int) []byte {
	return append(out, h.data[from:]...)
}
