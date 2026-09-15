package io

import (
	"bytes"
	"sort"
	"strconv"
)

// maxSequenceBytes caps how much of an in-progress escape sequence the tracker
// will hold. Real mode sequences are a handful of bytes; anything longer is
// either not a mode sequence or is a stream that will never terminate it, and
// neither is worth unbounded memory in a process whose entire point is running
// unattended.
const maxSequenceBytes = 64

// restorable lists the DEC private modes worth putting a reattaching terminal
// back into, mapped to the value a terminal holds them at before anything has
// touched them. Everything else is ignored, which is what keeps both the
// tracked set and the emitted snapshot bounded by a constant rather than by
// whatever the command decided to emit.
//
// The defaults are what let Snapshot stay quiet about state a joiner is
// already in: it joins with a terminal at its own defaults, so replaying them
// back to it is bytes that say nothing.
//
// The three alternate-screen modes are listed here because they are worth
// restoring, but they are not kept in decPrivate: see altScreenModes.
var restorable = map[int]bool{
	1:    false, // DECCKM, application cursor keys
	7:    true,  // DECAWM, autowrap
	25:   true,  // DECTCEM, cursor visibility
	47:   false, // legacy alternate screen
	1000: false, // X11 mouse: button events
	1002: false, // mouse: button + drag
	1003: false, // mouse: any motion
	1004: false, // focus reporting
	1005: false, // UTF-8 mouse encoding
	1006: false, // SGR mouse encoding
	1047: false, // alternate screen
	1048: false, // save/restore cursor
	1049: false, // alternate screen + cursor, the common one
	2004: false, // bracketed paste
}

// restorableModes returns the tracked mode numbers. It exists for tests.
func restorableModes() []int {
	out := make([]int, 0, len(restorable))
	for n := range restorable {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// ModeTracker watches terminal output and remembers the modes set on it, so a
// reader joining later can be put into the same modes before it is handed the
// replay ring.
//
// It is deliberately not a terminal emulator: it reconstructs no screen and no
// cursor position. Anything it does not recognise passes through unrecorded.
//
// Not safe for concurrent use. MultiWriter owns one and only touches it under
// writeMu.
type ModeTracker struct {
	decPrivate map[int]bool

	// A terminal has one alternate screen, not one per mode that reaches it,
	// so it is one boolean plus the mode that last entered it. altVia only
	// means anything while altScreen is set; it is what the snapshot replays,
	// because a joiner told to leave by a mode it never entered through is a
	// joiner on the wrong screen.
	altScreen bool
	altVia    int // 47, 1047 or 1049

	// Each screen buffer has its own margins, so the two DECSTBMs are kept
	// apart: replaying the alternate screen's to a joiner sitting on the
	// normal one, or the reverse, confines it to rows nothing set.
	mainRegion []byte // last DECSTBM on the normal screen, verbatim
	altRegion  []byte // last DECSTBM on the alternate screen, verbatim

	charsetG0 []byte // last "ESC ( X", verbatim

	// partial is the raw bytes of the sequence the parser is currently
	// inside, ESC included. The tracker is fed the ring's evictions, so the
	// trim boundary can fall anywhere -- including mid-sequence, leaving the
	// ring starting with a sequence's tail and this holding its head. See
	// Snapshot, which replays it so the two halves meet.
	partial []byte

	seq      []byte
	overflow bool // current sequence exceeded maxSequenceBytes; discard it
	state    modeState
}

type modeState int

const (
	msNormal modeState = iota
	msEsc
	msCSI
	msCharset
)

func NewModeTracker() *ModeTracker {
	return &ModeTracker{decPrivate: map[int]bool{}}
}

// bufferedBytes reports the parser's current accumulation: both the CSI
// parameters it is collecting and the raw partial of the same sequence, which
// is what a test asking whether an unterminated sequence can grow the parser
// wants to know. It exists for tests.
func (m *ModeTracker) bufferedBytes() int { return len(m.seq) + len(m.partial) }

// Write consumes output and records mode changes. It never fails and never
// alters the stream; callers use it as an observer, not a filter.
func (m *ModeTracker) Write(p []byte) (int, error) {
	for _, b := range p {
		m.step(b)
	}
	return len(p), nil
}

func (m *ModeTracker) step(b byte) {
	switch m.state {
	case msNormal:
		if b == 0x1b {
			m.state = msEsc
			m.reset()
			m.openPartial()
		}
	case msEsc:
		switch b {
		case 0x1b:
			// ESC ESC: restart rather than fall out of sync.
			m.reset()
			m.openPartial()
		case '[':
			m.state = msCSI
			m.reset()
			m.partial = append(m.partial, b)
		case '(':
			m.state = msCharset
			m.partial = append(m.partial, b)
		case 'c':
			// RIS, a hard reset: the terminal is back at power-on, so
			// everything recorded before it is no longer true of it.
			m.resetToDefaults()
			m.state = msNormal
			m.closePartial()
		default:
			m.state = msNormal
			m.closePartial()
		}
	case msCharset:
		switch {
		case b == 0x1b:
			// The designation was abandoned. Recording the ESC as the
			// designator both loses whatever sequence it opened and leaves
			// the snapshot ending mid-escape.
			m.state = msEsc
			m.reset()
			m.openPartial()
		case b < 0x30 || b > 0x7e:
			// Not a designator at all; no charset was selected.
			m.state = msNormal
			m.closePartial()
		default:
			m.charsetG0 = []byte{0x1b, '(', b}
			m.state = msNormal
			m.closePartial()
		}
	case msCSI:
		if b >= 0x40 && b <= 0x7e {
			if !m.overflow {
				m.finishCSI(b)
			}
			m.state = msNormal
			m.reset()
			m.closePartial()
			return
		}
		if b == 0x1b {
			// An ESC inside a CSI means the sequence was abandoned. Recover
			// rather than swallow everything that follows.
			m.state = msEsc
			m.reset()
			m.openPartial()
			return
		}
		if len(m.seq) >= maxSequenceBytes {
			// Stop accumulating but stay in msCSI, so the sequence's real
			// terminator still returns the parser to normal.
			m.overflow = true

			// An overflowed sequence is never replayed. The tracker has
			// already given up on completing it, so what it holds is a
			// fragment that would print on the joiner's terminal, and
			// keeping it would let the stream set the snapshot's size.
			m.closePartial()
			return
		}
		m.seq = append(m.seq, b)
		m.partial = append(m.partial, b)
	}
}

func (m *ModeTracker) reset() {
	m.seq = m.seq[:0]
	m.overflow = false
}

// openPartial starts recording a sequence at its ESC, replacing whatever the
// previous one was: an ESC arriving mid-sequence abandons that sequence, and
// an abandoned head is not one the ring's first bytes will complete.
func (m *ModeTracker) openPartial() {
	m.partial = append(m.partial[:0], 0x1b)
}

// closePartial drops the recorded sequence, which is what every way out of one
// -- finished, abandoned or not a sequence after all -- calls for.
func (m *ModeTracker) closePartial() {
	m.partial = m.partial[:0]
}

// resetToDefaults forgets everything recorded, which is what a terminal does
// to itself on RIS: it comes back at power-on, on the normal screen.
func (m *ModeTracker) resetToDefaults() {
	clear(m.decPrivate)
	m.altScreen = false
	m.altVia = 0
	m.mainRegion = nil
	m.altRegion = nil
	m.charsetG0 = nil
}

// softResetModes are the tracked DEC private modes DECSTR returns to their
// default. They are the ones on a terminal's soft-reset list; the rest of
// what the tracker records -- the screen buffer, the mouse modes, focus
// reporting, 1048 and bracketed paste -- all postdates that list and survives
// a DECSTR on tmux and on xterm alike.
var softResetModes = []int{1, 7, 25} // DECCKM, DECAWM, DECTCEM

// softReset applies DECSTR. It is not RIS with a different spelling: it leaves
// the screen buffer alone, which is why a full-screen program can issue one on
// the alternate screen without dropping back to the normal one.
func (m *ModeTracker) softReset() {
	for _, n := range softResetModes {
		delete(m.decPrivate, n)
	}
	// The margins of the buffer that is showing, and only that one: the other
	// buffer's are not the ones being reset.
	if m.altActive() {
		m.altRegion = nil
	} else {
		m.mainRegion = nil
	}
	m.charsetG0 = nil
}

// altScreenModes are the DEC private modes that put the alternate screen
// buffer on show. They are three spellings of one piece of state on a real
// terminal, so the tracker keeps one: "\x1b[?47h\x1b[?1049l" returns to the
// normal screen on tmux and on xterm, and tracking the two modes apart had
// the snapshot replay a "?47h" the session was no longer in.
var altScreenModes = map[int]bool{47: true, 1047: true, 1049: true}

func (m *ModeTracker) altActive() bool { return m.altScreen }

func (m *ModeTracker) finishCSI(final byte) {
	params := m.seq

	switch final {
	case 'h', 'l':
		// Only DEC private modes, marked by a leading '?'.
		if len(params) == 0 || params[0] != '?' {
			return
		}
		wasAlt := m.altActive()
		set := final == 'h'
		for _, field := range bytes.Split(params[1:], []byte{';'}) {
			n, err := strconv.Atoi(string(field))
			if err != nil {
				continue
			}
			if _, ok := restorable[n]; !ok {
				continue
			}
			if altScreenModes[n] {
				m.altScreen = set
				if set {
					// Whichever mode entered last is the one to replay, since
					// it is the one the session's own reset will match.
					m.altVia = n
				}
				continue
			}
			m.decPrivate[n] = set
		}
		if m.altActive() != wasAlt {
			// A fresh alternate screen has no margins, and the ones it had
			// are gone the moment it is left.
			m.altRegion = nil
		}
	case 'r':
		// DECSTBM, stored verbatim including a bare reset, against whichever
		// screen buffer is showing.
		seq := make([]byte, 0, len(params)+3)
		seq = append(seq, 0x1b, '[')
		seq = append(seq, params...)
		seq = append(seq, 'r')
		if m.altActive() {
			m.altRegion = seq
		} else {
			m.mainRegion = seq
		}
	case 'p':
		// DECSTR, a soft reset. Its parameter is the intermediate '!', which
		// is what separates it from the several other CSI ... p sequences.
		if len(params) == 1 && params[0] == '!' {
			m.softReset()
		}
	}
}

// Snapshot returns the bytes that put a fresh terminal into the recorded
// modes. State already at the terminal's default is left out, so a session
// that never changed anything replays nothing. Its length is bounded by
// len(restorable) plus the screen switch, the three verbatim sequences and one
// partial sequence.
//
// The order is the order the stream would have had to use to reach this
// state: the normal screen's margins, then the modes, then the switch to the
// alternate screen, then that screen's own margins, and only while it is the
// one showing.
//
// The state as of the ring's first byte includes being partway through a
// sequence, so the partial goes last, after the charset. The ring's first
// bytes then complete it on the joiner's terminal instead of printing as text
// -- which is what they did when the trim boundary fell inside a sequence and
// the snapshot said nothing about it.
func (m *ModeTracker) Snapshot() []byte {
	nums := make([]int, 0, len(m.decPrivate))
	for n := range m.decPrivate {
		nums = append(nums, n)
	}
	sort.Ints(nums)

	out := append([]byte(nil), m.mainRegion...)
	for _, n := range nums {
		if m.decPrivate[n] == restorable[n] {
			// Already where a joining terminal starts.
			continue
		}
		out = append(out, 0x1b, '[', '?')
		out = append(out, []byte(strconv.Itoa(n))...)
		if m.decPrivate[n] {
			out = append(out, 'h')
		} else {
			out = append(out, 'l')
		}
	}
	if m.altActive() {
		// Replayed through the mode that entered, so a joiner is left in the
		// state the session's own "l" will match.
		out = append(out, 0x1b, '[', '?')
		out = append(out, []byte(strconv.Itoa(m.altVia))...)
		out = append(out, 'h')
		out = append(out, m.altRegion...)
	}
	out = append(out, m.charsetG0...)
	out = append(out, m.partial...)
	return out
}
