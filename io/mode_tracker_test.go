package io

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ModeTracker_DECPrivateModes(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[?1049h\x1b[?2004h\x1b[?25l"))
	require.NoError(t, err)

	// Ascending numeric order, so the snapshot is deterministic. The switch
	// to the alternate screen is not one of them: it is its own state now,
	// and it goes after them, in front of the margins that belong to it.
	require.Equal(t, "\x1b[?25l\x1b[?2004h\x1b[?1049h", string(m.Snapshot()))
}

func Test_ModeTracker_LastWriteWins(t *testing.T) {
	m := NewModeTracker()

	// 25 is on by default, so the trailing l is the one that has to survive
	// for the snapshot to say anything at all.
	_, err := m.Write([]byte("\x1b[?25l\x1b[?25h\x1b[?25l"))
	require.NoError(t, err)
	require.Equal(t, "\x1b[?25l", string(m.Snapshot()))
}

func Test_ModeTracker_MultipleParamsInOneSequence(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[?1000;1006h"))
	require.NoError(t, err)
	require.Equal(t, "\x1b[?1000h\x1b[?1006h", string(m.Snapshot()))
}

func Test_ModeTracker_ScrollRegionAndCharset(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[5;20r\x1b(0"))
	require.NoError(t, err)
	require.Equal(t, "\x1b[5;20r\x1b(0", string(m.Snapshot()))
}

// Each screen buffer owns its scroll region. Replaying the alternate screen's
// margins to a joiner that is on the normal screen -- or the normal screen's
// after an alt-screen switch -- confines it to rows it never asked for.
func Test_ModeTracker_ScrollRegionFollowsTheScreenBuffer(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "margins set before the switch belong to the normal screen",
			input: "\x1b[1;23r\x1b[?1049h",
			want:  "\x1b[1;23r\x1b[?1049h",
		},
		{
			name:  "margins set after the switch belong to the alternate screen",
			input: "\x1b[?1049h\x1b[5;10r",
			want:  "\x1b[?1049h\x1b[5;10r",
		},
		{
			name:  "leaving the alternate screen discards its margins",
			input: "\x1b[1;23r\x1b[?1049h\x1b[5;10r\x1b[?1049l",
			want:  "\x1b[1;23r",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tt.input))
			require.NoError(t, err)
			require.Equal(t, tt.want, string(m.Snapshot()))
		})
	}
}

// An ESC after "ESC (" abandons the designation. Recording it as the
// designator produced the snapshot "\x1b(\x1b", which both loses the sequence
// that followed and leaves the joiner's terminal mid-escape.
func Test_ModeTracker_CharsetAbandonedByEsc(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b(\x1b[?1049h"))
	require.NoError(t, err)
	require.Equal(t, "\x1b[?1049h", string(m.Snapshot()))
}

func Test_ModeTracker_SplitAcrossWrites(t *testing.T) {
	m := NewModeTracker()
	for _, chunk := range []string{"\x1b", "[?10", "49h"} {
		_, err := m.Write([]byte(chunk))
		require.NoError(t, err)
	}
	require.Equal(t, "\x1b[?1049h", string(m.Snapshot()))
}

func Test_ModeTracker_IgnoresNonModeSequences(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("hello \x1b[31mred\x1b[0m world\x1b[6n"))
	require.NoError(t, err)
	require.Empty(t, m.Snapshot())
}

func Test_ModeTracker_IgnoresUnknownModes(t *testing.T) {
	m := NewModeTracker()

	// Ten thousand distinct mode numbers nobody restores.
	var b strings.Builder
	for i := 3000; i < 13000; i++ {
		fmt.Fprintf(&b, "\x1b[?%dh", i)
	}
	_, err := m.Write([]byte(b.String()))
	require.NoError(t, err)

	require.Empty(t, m.Snapshot(), "only modes worth restoring may be retained")
}

func Test_ModeTracker_BoundsUnterminatedSequence(t *testing.T) {
	m := NewModeTracker()

	// A CSI that never terminates must not grow the parser without limit. The
	// parser holds two things now: maxSequenceBytes of CSI parameters at the
	// most, and the raw partial of that same sequence, which inside a CSI is
	// those parameters plus the two-byte "ESC [" introducer. 2*maxSequenceBytes+2
	// is the ceiling for the pair.
	_, err := m.Write([]byte("\x1b[" + strings.Repeat("1;", 100_000)))
	require.NoError(t, err)
	require.LessOrEqual(t, m.bufferedBytes(), 2*maxSequenceBytes+2,
		"the parser's ceiling holds whatever the stream does")

	// This input ran past that ceiling, so the overflow dropped the partial:
	// the capped parameters are all that is left, and nothing here is still
	// growing with the stream.
	require.Equal(t, maxSequenceBytes, m.bufferedBytes(),
		"an overflowed sequence keeps its capped parameters and no partial")

	// And the parser must have recovered: a real sequence after the garbage
	// still registers.
	_, err = m.Write([]byte("\x1b[?1049h"))
	require.NoError(t, err)
	require.Equal(t, "\x1b[?1049h", string(m.Snapshot()))
}

// The head of a sequence is only worth replaying while the tracker can still
// be holding all of it. Once a sequence has overflowed, the bytes kept are a
// fragment of one: replayed ahead of the ring they would print rather than be
// completed, and they would put the snapshot's own bound at the mercy of the
// stream.
func Test_ModeTracker_PartialIsNotEmittedAfterOverflow(t *testing.T) {
	m := NewModeTracker()

	// A CSI whose parameters run well past maxSequenceBytes and never end.
	_, err := m.Write([]byte("\x1b[" + strings.Repeat("1;", maxSequenceBytes)))
	require.NoError(t, err)

	require.Empty(t, m.Snapshot())
}

// The partial is the one part of the snapshot whose size the stream chooses,
// so its worst case is worth pinning rather than reasoning about: a CSI whose
// parameters stop exactly on the cap is the largest mode sequence that will
// ever be replayed, and one byte more replays nothing at all. A string
// sequence is bounded separately and higher; see
// Test_ModeTracker_BoundsUnterminatedString.
func Test_ModeTracker_PartialIsBoundedAtItsWorstCase(t *testing.T) {
	m := NewModeTracker()

	// maxSequenceBytes of parameters exactly. The cap is checked before each
	// byte is taken, so this is the last one that still fits.
	params := strings.Repeat("1;", maxSequenceBytes/2)
	_, err := m.Write([]byte("\x1b[" + params))
	require.NoError(t, err)

	require.Equal(t, "\x1b["+params, string(m.Snapshot()))

	// "ESC [" plus the parameters: maxSequenceBytes and its introducer, which
	// is the ceiling Snapshot's doc comment claims.
	require.Len(t, m.Snapshot(), maxSequenceBytes+2)
}

// Every way out of a sequence has to take the partial with it, or the joiner
// is replayed the head of a sequence the ring never finishes and the bytes
// print instead. The abandoning ESC is the case to watch: it both ends one
// sequence and opens another.
func Test_ModeTracker_PartialFollowsTheSequenceBeingAbandoned(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "a charset designation the stream stops inside",
			input: "\x1b(",
			want:  "\x1b(",
		},
		{
			name:  "a charset designation abandoned by ESC",
			input: "\x1b(\x1b[?10",
			want:  "\x1b[?10",
		},
		{
			name:  "a CSI abandoned by ESC",
			input: "\x1b[?99\x1b[?10",
			want:  "\x1b[?10",
		},
		{
			name:  "ESC ESC",
			input: "\x1b\x1b[?10",
			want:  "\x1b[?10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tt.input))
			require.NoError(t, err)
			require.Equal(t, tt.want, string(m.Snapshot()))
		})
	}
}

// A string sequence -- OSC, DCS, PM, APC or SOS -- carries a payload that is
// not terminal output: a window title, a hyperlink, an OSC 52 clipboard, a
// terminfo reply. The tracker dropped the introducer and read the payload as
// ordinary output, so it held no partial for a string: a trim boundary inside
// one left the joiner the string's tail alone, and a tail alone is text its
// terminal prints.
func Test_ModeTracker_StringSequenceIsThePartial(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "an OSC the stream stops inside",
			input: "\x1b]0;abc",
			want:  "\x1b]0;abc",
		},
		{
			name:  "a DCS the stream stops inside",
			input: "\x1bP0;1|abc",
			want:  "\x1bP0;1|abc",
		},
		{
			name:  "a PM the stream stops inside",
			input: "\x1b^abc",
			want:  "\x1b^abc",
		},
		{
			name:  "an APC the stream stops inside",
			input: "\x1b_abc",
			want:  "\x1b_abc",
		},
		{
			name:  "an SOS the stream stops inside",
			input: "\x1bXabc",
			want:  "\x1bXabc",
		},
		{
			name:  "a BEL ends an OSC",
			input: "\x1b]0;abc\x07",
			want:  "",
		},
		{
			// xterm takes BEL for an OSC terminator and for nothing else, so
			// a DCS carrying one is still open afterwards.
			name:  "a BEL ends nothing else",
			input: "\x1bPabc\x07def",
			want:  "\x1bPabc\x07def",
		},
		{
			name:  "an ST ends an OSC",
			input: "\x1b]0;abc\x1b\\",
			want:  "",
		},
		{
			name:  "an ST ends a DCS",
			input: "\x1bPabc\x1b\\",
			want:  "",
		},
		{
			// The ESC of a terminator the stream has not finished belongs to
			// the partial like any other byte of the string: the ring's next
			// byte is the backslash that completes it.
			name:  "the ESC of an ST the stream stops on",
			input: "\x1b]0;abc\x1b",
			want:  "\x1b]0;abc\x1b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tt.input))
			require.NoError(t, err)
			require.Equal(t, tt.want, string(m.Snapshot()))
		})
	}
}

// An ESC inside a string is where the string ends, on the DEC state machine
// every terminal implements: it leaves the string, and the byte after it opens
// a new sequence -- unless that byte is a backslash, which makes the pair the
// ST the string was waiting for. The tracker reads it the same way, because
// the session's own terminal did: a mode sequence that arrived like this
// really did run there, and swallowing it as payload would leave a joiner on
// the screen the session had left.
func Test_ModeTracker_StringAbandonedByEsc(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "a mode sequence after an unterminated OSC",
			input: "\x1b]0;abc\x1b[?25l",
			want:  "\x1b[?25l",
		},
		{
			name:  "a mode sequence in an OSC a BEL terminates later",
			input: "\x1b]0;title\x1b[?1049h\x07",
			want:  "\x1b[?1049h",
		},
		{
			name:  "a mode sequence in a DCS an ST terminates later",
			input: "\x1bPq\x1b[?2004h\x1b\\",
			want:  "\x1b[?2004h",
		},
		{
			name:  "a second string abandons the first",
			input: "\x1b]0;abc\x1b]1;d",
			want:  "\x1b]1;d",
		},
		{
			name:  "ESC ESC inside a string",
			input: "\x1b]0;abc\x1b\x1b[?25l",
			want:  "\x1b[?25l",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tt.input))
			require.NoError(t, err)
			require.Equal(t, tt.want, string(m.Snapshot()))
		})
	}
}

// A string whose terminator never arrives must not let the stream choose the
// snapshot's size. Past the bound the parser keeps reading -- only the
// terminator returns it to normal -- but what it is holding is a fragment of a
// string, and a fragment replayed ahead of the ring prints rather than being
// completed, the same bargain an overflowed CSI makes.
func Test_ModeTracker_BoundsUnterminatedString(t *testing.T) {
	m := NewModeTracker()

	// Four bytes of introducer and then the bound again in payload, so the cap
	// falls inside the run and everything after it is the stream trying to
	// grow a partial that is already gone.
	_, err := m.Write([]byte("\x1b]0;" + strings.Repeat("a", maxStringBytes)))
	require.NoError(t, err)
	require.Empty(t, m.Snapshot(), "an overflowed string is never replayed")
	require.Zero(t, m.bufferedBytes(), "nothing of it is still held either")

	// The parser is still inside that string, so its terminator is what ends
	// it, and the sequence after that is tracked as usual.
	_, err = m.Write([]byte("\x1b\\\x1b[?25l"))
	require.NoError(t, err)
	require.Equal(t, "\x1b[?25l", string(m.Snapshot()))

	// The largest string that is still replayed is one that stops exactly on
	// the bound, which makes maxStringBytes the partial's own ceiling.
	m = NewModeTracker()
	_, err = m.Write([]byte("\x1b]0;" + strings.Repeat("a", maxStringBytes-len("\x1b]0;"))))
	require.NoError(t, err)
	require.Len(t, m.Snapshot(), maxStringBytes)
}

func Test_ModeTracker_SnapshotIsBounded(t *testing.T) {
	m := NewModeTracker()

	// The worst case is both screen buffers carrying margins, so the normal
	// screen's are set before the modes switch to the alternate one.
	var b strings.Builder
	b.WriteString("\x1b[1;99999r")
	for _, mode := range restorableModes() {
		fmt.Fprintf(&b, "\x1b[?%dh", mode)
	}
	b.WriteString("\x1b[1;99999r\x1b(0")

	// And then the stream stops inside a string that runs right up to its
	// bound. The partial is the only part of the snapshot the stream sizes, so
	// a worst case without one is a worst case of the constant half alone.
	partial := "\x1b]0;" + strings.Repeat("a", maxStringBytes-len("\x1b]0;"))
	b.WriteString(partial)

	_, err := m.Write([]byte(b.String()))
	require.NoError(t, err)

	snap := string(m.Snapshot())
	require.Contains(t, snap, partial, "the partial must be in it, or the bound below is about an empty slot")

	// Every restorable mode set at once, plus both scroll regions, the charset
	// and a string partial at its own cap, must still be trivially smaller
	// than a guest's sink.
	const constantBudget = 1024 // everything that is not the partial
	require.Less(t, len(snap), constantBudget+maxStringBytes)
}

func Test_ModeTracker_EmitsOnlyNonDefaultState(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "a mode set and then cleared is back at its default",
			input: "\x1b[?2004h\x1b[?2004l",
			want:  "",
		},
		{
			name:  "a hidden cursor differs from the default",
			input: "\x1b[?25l",
			want:  "\x1b[?25l",
		},
		{
			name:  "autowrap on is the default",
			input: "\x1b[?7h",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tt.input))
			require.NoError(t, err)
			require.Equal(t, tt.want, string(m.Snapshot()))
		})
	}
}

// Modes 47, 1047 and 1049 are three ways of asking for one thing, and a real
// terminal has one alternate screen: tmux and xterm both leave it on a reset
// of any of the three, whichever one entered it. Tracked as independent modes
// they contradict each other, and the snapshot replays a switch the session
// had already left.
func Test_ModeTracker_AlternateScreenIsOneState(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "1049l leaves a screen 47h entered",
			input: "\x1b[?47h\x1b[?1049l",
			want:  "",
		},
		{
			name:  "47l leaves a screen 1049h entered",
			input: "\x1b[?1049h\x1b[?47l",
			want:  "",
		},
		{
			name:  "47h is replayed as the mode that entered",
			input: "\x1b[?47h",
			want:  "\x1b[?47h",
		},
		{
			name:  "1047h is replayed as the mode that entered",
			input: "\x1b[?1047h",
			want:  "\x1b[?1047h",
		},
		{
			name:  "the last mode to enter is the one replayed",
			input: "\x1b[?1049h\x1b[?47h",
			want:  "\x1b[?47h",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tt.input))
			require.NoError(t, err)
			require.Equal(t, tt.want, string(m.Snapshot()))
		})
	}
}

// RIS puts the terminal back at power-on, so nothing recorded before it is
// true of it any more -- the screen buffer included.
func Test_ModeTracker_ResetClearsEverything(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[?1049h\x1b[?25l\x1b[1;23r\x1b(0"))
	require.NoError(t, err)
	require.NotEmpty(t, m.Snapshot(), "the state a reset clears must be there first")

	_, err = m.Write([]byte("\x1bc"))
	require.NoError(t, err)
	require.Empty(t, m.Snapshot())
}

// DECSTR is a soft reset, and this test used to be the DECSTR half of
// Test_ModeTracker_ResetClearsEverything, asserting it cleared as much as RIS
// does. No terminal behaves that way: the tracker models xterm's soft reset,
// which keeps the screen buffer, the mouse modes, focus reporting and
// bracketed paste across it, and returns only the cursor keys, autowrap and
// cursor visibility to their defaults, along with the active buffer's margins
// and the charset. tmux keeps even more -- it has no handler for CSI ! p and
// ignores DECSTR outright.
func Test_ModeTracker_SoftResetIsNotAFullReset(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[?1049h\x1b[?1h\x1b[?25l\x1b[?2004h\x1b[5;10r\x1b(0\x1b[!p"))
	require.NoError(t, err)

	require.Equal(t, "\x1b[?2004h\x1b[?1049h", string(m.Snapshot()))
}
