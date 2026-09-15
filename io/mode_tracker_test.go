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
// parameters stop exactly on the cap is the largest one that will ever be
// replayed, and one byte more replays nothing at all.
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
	_, err := m.Write([]byte(b.String()))
	require.NoError(t, err)

	// Every restorable mode set at once, plus both scroll regions and the
	// charset, must still be trivially smaller than a guest's sink.
	require.Less(t, len(m.Snapshot()), 1024)
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
// does. No terminal behaves that way: tmux and xterm both keep the screen
// buffer, the mouse modes, focus reporting and bracketed paste across it, and
// return only the cursor keys, autowrap and cursor visibility to their
// defaults, along with the active buffer's margins and the charset.
func Test_ModeTracker_SoftResetIsNotAFullReset(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[?1049h\x1b[?1h\x1b[?25l\x1b[?2004h\x1b[5;10r\x1b(0\x1b[!p"))
	require.NoError(t, err)

	require.Equal(t, "\x1b[?2004h\x1b[?1049h", string(m.Snapshot()))
}
