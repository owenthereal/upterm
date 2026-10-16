package replay

import (
	"iter"

	uv "github.com/charmbracelet/ultraviolet"
)

// crlf follows each history line in the render.
const crlf = "\r\n"

// lineCost is what a line costs the history besides its bytes: the CRLF the
// render follows it with, and the length the history keeps of it, a uint32.
const lineCost = len(crlf) + 4

// history keeps the newest lines that scrolled off the emulator's main
// screen, each encoded as it left, within a budget: a line costs
// its bytes and lineCost, and the oldest lines go to keep the total within
// max. So both the render's share and the history's own bookkeeping stay
// within the budget, even for a flood of blank lines, which
// cost nothing else.
//
// The lines are kept end to end in one buffer, with their lengths, rather
// than a slice each: a short line would cost more in its own allocation and
// slice header than in its bytes. A line is never longer than the budget,
// so its length fits 32 bits.
type history struct {
	max  int
	data []byte   // the lines kept, oldest first
	lens []uint32 // the length of each, oldest first
	cost int      // what they cost: their bytes and lineCost each
	enc  encoder
}

// push encodes line and keeps it, dropping the oldest lines past the
// budget. A line that alone costs more than the budget is dropped itself:
// no render could hold it. It runs inside the emulator's Write, as its
// scroll-off function, and the line is the screen's own storage, so it is
// encoded here and never kept.
func (h *history) push(line uv.Line) {
	h.enc.reset(max(h.max-lineCost, 0))
	if h.enc.row(line) != nil {
		return
	}
	n := len(h.enc.buf)
	h.data = append(h.data, h.enc.buf...)
	h.lens = append(h.lens, uint32(n))
	h.cost += n + lineCost
	for h.cost > h.max {
		n := int(h.lens[0])
		h.data, h.lens = h.data[n:], h.lens[1:]
		h.cost -= n + lineCost
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
			end := off + int(n)
			if !yield(h.data[off:end:end]) {
				return
			}
			off = end
		}
	}
}
