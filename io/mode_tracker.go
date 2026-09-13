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

	// Each screen buffer has its own margins, so the two DECSTBMs are kept
	// apart: replaying the alternate screen's to a joiner sitting on the
	// normal one, or the reverse, confines it to rows nothing set.
	mainRegion []byte // last DECSTBM on the normal screen, verbatim
	altRegion  []byte // last DECSTBM on the alternate screen, verbatim

	charsetG0 []byte // last "ESC ( X", verbatim

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

// bufferedBytes reports the parser's current accumulation. It exists for tests.
func (m *ModeTracker) bufferedBytes() int { return len(m.seq) }

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
		}
	case msEsc:
		switch b {
		case 0x1b:
			// ESC ESC: restart rather than fall out of sync.
			m.reset()
		case '[':
			m.state = msCSI
			m.reset()
		case '(':
			m.state = msCharset
		case 'c':
			// RIS, a hard reset: the terminal is back at power-on, so
			// everything recorded before it is no longer true of it.
			m.resetToDefaults()
			m.state = msNormal
		default:
			m.state = msNormal
		}
	case msCharset:
		switch {
		case b == 0x1b:
			// The designation was abandoned. Recording the ESC as the
			// designator both loses whatever sequence it opened and leaves
			// the snapshot ending mid-escape.
			m.state = msEsc
			m.reset()
		case b < 0x30 || b > 0x7e:
			// Not a designator at all; no charset was selected.
			m.state = msNormal
		default:
			m.charsetG0 = []byte{0x1b, '(', b}
			m.state = msNormal
		}
	case msCSI:
		if b >= 0x40 && b <= 0x7e {
			if !m.overflow {
				m.finishCSI(b)
			}
			m.state = msNormal
			m.reset()
			return
		}
		if b == 0x1b {
			// An ESC inside a CSI means the sequence was abandoned. Recover
			// rather than swallow everything that follows.
			m.state = msEsc
			m.reset()
			return
		}
		if len(m.seq) >= maxSequenceBytes {
			// Stop accumulating but stay in msCSI, so the sequence's real
			// terminator still returns the parser to normal.
			m.overflow = true
			return
		}
		m.seq = append(m.seq, b)
	}
}

func (m *ModeTracker) reset() {
	m.seq = m.seq[:0]
	m.overflow = false
}

// resetToDefaults forgets everything recorded, which is what a terminal does
// to itself on RIS or DECSTR.
func (m *ModeTracker) resetToDefaults() {
	clear(m.decPrivate)
	m.mainRegion = nil
	m.altRegion = nil
	m.charsetG0 = nil
}

// altScreenModes are the DEC private modes that put the alternate screen
// buffer on show. Any one of them is enough.
var altScreenModes = []int{47, 1047, 1049}

func (m *ModeTracker) altActive() bool {
	for _, n := range altScreenModes {
		if m.decPrivate[n] {
			return true
		}
	}
	return false
}

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
			m.resetToDefaults()
		}
	}
}

// Snapshot returns the bytes that put a fresh terminal into the recorded
// modes. State already at the terminal's default is left out, so a session
// that never changed anything replays nothing. Its length is bounded by
// len(restorable) plus the three verbatim sequences.
//
// The order is the order the stream would have had to use to reach this
// state: the normal screen's margins, then the modes -- which is where a
// switch to the alternate screen happens -- then the alternate screen's own
// margins, and only while it is the one showing.
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
		out = append(out, m.altRegion...)
	}
	out = append(out, m.charsetG0...)
	return out
}
