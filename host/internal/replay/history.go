package replay

import (
	"iter"

	uv "github.com/charmbracelet/ultraviolet"
)

// crlf follows each history line in the render (R2), so each line kept costs
// it too.
const crlf = "\r\n"

// history keeps the newest lines that scrolled off the emulator's main
// screen, each encoded as it left (spec E8), within a budget: a line costs
// its bytes and the CRLF the render follows it with, and the oldest lines go
// to keep the total within max. Counting the CRLF bounds the number of lines
// too, so a flood of blank lines can't grow it past the budget.
//
// The lines are kept end to end in one buffer, with their lengths, rather
// than a slice each: a short line would cost more in its own allocation and
// slice header than in its bytes.
type history struct {
	max  int
	data []byte // the lines kept, oldest first
	lens []int  // the length of each, oldest first
	cost int    // what they cost: their bytes and a CRLF each
	enc  encoder
}

// push encodes line and keeps it, dropping the oldest lines past the
// budget. A line that alone costs more than the budget is dropped itself:
// no render could hold it. It runs inside the emulator's Write, as its
// scroll-off function, and the line is the screen's own storage, so it is
// encoded here and never kept.
func (h *history) push(line uv.Line) {
	h.enc.reset(max(h.max-len(crlf), 0))
	if h.enc.row(line) != nil {
		return
	}
	h.data = append(h.data, h.enc.buf...)
	h.lens = append(h.lens, len(h.enc.buf))
	h.cost += len(h.enc.buf) + len(crlf)
	for h.cost > h.max {
		n := h.lens[0]
		h.data, h.lens = h.data[n:], h.lens[1:]
		h.cost -= n + len(crlf)
	}
}

// clear forgets every line, as ED 3 and RIS clear history.
func (h *history) clear() {
	h.data, h.lens, h.cost = nil, nil, 0
}

// all yields the lines kept, oldest first. Each is the history's own storage,
// valid until the next push or clear.
func (h *history) all() iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		off := 0
		for _, n := range h.lens {
			if !yield(h.data[off : off+n : off+n]) {
				return
			}
			off += n
		}
	}
}
