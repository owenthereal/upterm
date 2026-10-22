package io

import (
	"fmt"
	"maps"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/owenthereal/upterm/internal/termsize"
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

// A terminal has one scrolling region, which no screen switch changes, as in
// xterm (SwitchBufs leaves top_marg and bot_marg). Kept per screen, the region
// set on one screen went missing on the other, and later line feeds and scrolls
// on a joiner landed where the session's didn't.
func TestMarginsSurviveBufferSwitches(t *testing.T) {
	for _, via := range []int{1049, 47, 1047} {
		t.Run(strconv.Itoa(via), func(t *testing.T) {
			m := NewModeTracker()
			m.Resized(rows(24))
			_, _ = fmt.Fprintf(m, "\x1b[2;10r\x1b[?%dh", via)
			require.Equal(t, fmt.Sprintf("\x1b[2;10r\x1b[?%dh", via), string(m.Snapshot()), "set on the main screen, kept on the alternate one")
			require.Equal(t, 1, strings.Count(string(m.Restore()), "\x1b[r"), "and reset once")

			_, _ = fmt.Fprintf(m, "\x1b[3;8r\x1b[?%dl", via)
			require.Equal(t, "\x1b[3;8r", string(m.Snapshot()), "set on the alternate screen, kept on the main one")
			require.Equal(t, "\x1b[r", string(m.Restore()))
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

	// The worst case is a scrolling region and both screens' kitty keyboard
	// stacks full, the normal screen's set before the modes switch to the
	// alternate one; with no size known, the region is kept as written. The
	// widest numbers are an unsigned 32-bit one's: kitty's flags come back as
	// the seven bits kitty keeps, and modifyOtherKeys as it was written. A G0
	// designated before the switch is saved by its ?1049h and replayed ahead
	// of it, as well as the one designated after.
	widest := strconv.FormatUint(math.MaxUint32, 10)
	var b strings.Builder
	b.WriteString("\x1b[1;99999r")
	b.WriteString(strings.Repeat("\x1b[>"+widest+"u", kittyStackDepth))
	b.WriteString("\x1b[>4;" + widest + "m\x1b(0")
	for _, mode := range restorableModes() {
		fmt.Fprintf(&b, "\x1b[?%dh", mode)
	}
	b.WriteString("\x1b[1;99999r\x1b(0")
	b.WriteString(strings.Repeat("\x1b[>"+widest+"u", kittyStackDepth))

	// And then the stream stops inside a string that runs right up to its
	// bound. The partial is the only part of the snapshot the stream sizes, so
	// a worst case without one is a worst case of the constant half alone.
	partial := "\x1b]0;" + strings.Repeat("a", maxStringBytes-len("\x1b]0;"))
	b.WriteString(partial)

	_, err := m.Write([]byte(b.String()))
	require.NoError(t, err)

	snap := string(m.Snapshot())
	require.Contains(t, snap, partial, "the partial must be in it, or the bound below is about an empty slot")
	require.Equal(t, 2*kittyStackDepth, strings.Count(snap, "\x1b[>127u"), "both kitty stacks must be full, or the bound below is about empty ones")
	require.Contains(t, snap, "\x1b[>4;"+widest+"m", "and modifyOtherKeys set")

	// Every restorable mode set at once, plus the scroll region, both kitty
	// stacks full, modifyOtherKeys, the charset and a string partial at its
	// own cap, must still be trivially smaller than a guest's sink.
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
// cursor visibility to their defaults, along with the margins and the
// charset. tmux keeps even more -- it has no handler for CSI ! p and
// ignores DECSTR outright.
func Test_ModeTracker_SoftResetIsNotAFullReset(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[?1049h\x1b[?1h\x1b[?25l\x1b[?2004h\x1b[5;10r\x1b(0\x1b[!p"))
	require.NoError(t, err)

	require.Equal(t, "\x1b[?2004h\x1b[?1049h", string(m.Snapshot()))
}

// Restore is Snapshot's opposite: for the terminal that is leaving rather
// than the one joining. A full-screen program still on screen when a viewer
// detaches leaves that viewer's shell on the alternate screen, cursor hidden,
// mouse reporting clicks as input, inside the margins the program chose — and
// restoring the termios settings around the attachment says nothing about any
// of it.
func Test_ModeTracker_RestoreUndoesWhatTheSessionSet(t *testing.T) {
	m := NewModeTracker()
	// A full-screen program's opening: margins, then the alternate screen,
	// the cursor hidden, the mouse and bracketed paste on, and margins again.
	_, err := m.Write([]byte("\x1b[2;20r\x1b[?1049h\x1b[?25l\x1b[?1000;1006h\x1b[?2004h\x1b[5;15r"))
	require.NoError(t, err)

	// Leaving the alternate screen comes first, so everything after it lands
	// on the screen the terminal is going back to. The margins are the
	// terminal's, not a screen's, so they outlive the switch and are released
	// once.
	require.Equal(t,
		"\x1b[?1049l"+"\x1b[r"+"\x1b[?25h\x1b[?1000l\x1b[?1006l\x1b[?2004l",
		string(m.Restore()))
}

func Test_ModeTracker_RestoreLeavesThroughTheModeThatEntered(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[?47h"))
	require.NoError(t, err)
	require.Equal(t, "\x1b[?47l", string(m.Restore()),
		"a terminal told to leave by a mode it never entered through is a terminal left on the wrong screen")
}

// ?1048 is not a mode a terminal is left in but an action: set saves the
// cursor, reset restores it, as DECSC and DECRC do. Treated as a mode, Restore
// moved the cursor to wherever the session last saved it — on a detach, and
// on ~^Z just before the shell prints — and Snapshot saved the cursor where
// the terminal happened to be, which on a ~^Z resume overwrote the session's
// own saved cursor with the shell's and sent its next ?1048l somewhere else.
func Test_ModeTracker_SaveCursorIsNotAMode(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[?1048h\x1b[?25l"))
	require.NoError(t, err)
	require.Equal(t, "\x1b[?25l", string(m.Snapshot()), "a saved cursor is not replayed")
	require.Equal(t, "\x1b[?25h", string(m.Restore()), "and not restored on the way out")
}

// A cursor restore brings back the charsets its save held, and one from a slot
// nothing saved gives ASCII: xterm's cursor.c, CursorRestore, and x/vt's
// vt/csi_mode.go, restoreCursor. The tracker took the last ESC ( X for G0
// whatever came after it, so once both were evicted a joiner was handed line
// drawing the session's terminal had already left, and drew its next text in
// it. This is the smallest stream that showed it, at the size it was found at,
// through a ring of one byte.
func TestACursorRestoreWithNothingSavedGivesASCII(t *testing.T) {
	w := NewMultiWriter(1)
	resize(w, termsize.Size{Cols: 89, Rows: 18})
	writeString(w, "\x1b(0\x1b8{")

	var snap string
	withLog(w, func(_ *sizeLog, start uint64) {
		require.Equal(t, uint64(5), start, "the ring holds only the {")
		snap = string(w.modes.Snapshot())
	})
	require.NotContains(t, snap, "\x1b(0")
	require.Empty(t, snap, "G0 is ASCII, which is where a joiner's terminal starts")
}

// A restore of a save brings back the G0 the save held, line drawing here,
// and not the ASCII designated between them.
func TestACursorRestoreBringsBackTheSavedG0(t *testing.T) {
	m := NewModeTracker()
	_, _ = m.Write([]byte("\x1b(0\x1b7\x1b(B\x1b8"))
	require.Equal(t, "\x1b(0", string(m.Snapshot()))
	require.Equal(t, "\x1b(B", string(m.Restore()), "a terminal leaving is put back to ASCII")
}

// Restore leaves the alternate screen through the mode that entered it, and
// ?1049l restores the cursor ?1049h saved, G0 with it, so the G0 the terminal
// ends at is the normal screen's saved one, not the alternate screen's. Going
// by the alternate screen's, Restore left a terminal that entered in line
// drawing and reset G0 there, by a restore with nothing saved or by DECSTR,
// in line drawing, and sent a needless ESC ( B for the opposite. ?47 and ?1047
// restore nothing, so the alternate screen's G0 is the one they leave.
func TestRestoreEndsAtTheG0ItsOwnSequenceLeaves(t *testing.T) {
	for _, tc := range []struct{ name, stream, want string }{
		{"a restore with nothing saved on the alternate screen", "\x1b(0\x1b[?1049h\x1b8", "\x1b[?1049l\x1b(B"},
		{"DECSTR on the alternate screen", "\x1b(0\x1b[?1049h\x1b[!p", "\x1b[?1049l\x1b(B"},
		{"?1049l brings back ASCII", "\x1b[?1049h\x1b(0", "\x1b[?1049l"},
		{"?1047l keeps the alternate screen's G0", "\x1b[?1047h\x1b(0", "\x1b[?1047l\x1b(B"},
		{"?1047l restores nothing", "\x1b(0\x1b7\x1b[?1047h\x1b8", "\x1b[?1047l"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tc.stream))
			require.NoError(t, err)
			require.Equal(t, tc.want, string(m.Restore()))
		})
	}
}

// xterm keeps a saved cursor per screen buffer, sc[whichBuf], and every save
// and restore uses the slot of the screen showing at the time: ?1049h saves
// before it switches, so on the normal screen, and ?1049l restores after it
// switches back, so from the normal screen's slot too. ?1047 switches without
// either. x/vt's vt/csi_mode.go, setMode, does the same. While the alternate
// screen shows, the snapshot designates the normal screen's saved G0 ahead of
// the switch, for the joiner's ?1049h, or an ESC 7, to save.
func TestEachScreenRestoresFromItsOwnSlot(t *testing.T) {
	m := NewModeTracker()
	for _, step := range []struct{ stream, want, why string }{
		{"\x1b(A\x1b7\x1b(0\x1b[?1049h", "\x1b(0\x1b[?1049h\x1b(0", "?1049h saves the normal screen's G0, line drawing, over the UK saved before it"},
		{"\x1b8", "\x1b(0\x1b[?1049h\x1b(B", "the alternate screen's slot is its own, and nothing has filled it"},
		{"\x1b(A\x1b7\x1b(0\x1b8", "\x1b(0\x1b[?1049h\x1b(A", "the alternate screen restores its own save"},
		{"\x1b[?1049l", "\x1b(0", "?1049l restores the normal screen's slot, not the alternate's"},
		{"\x1b[?1047h\x1b(B\x1b8", "\x1b(0\x1b7\x1b[?1047h\x1b(A", "the alternate screen's slot outlives a trip away"},
		{"\x1b[?1047l\x1b8", "\x1b(0", "and so does the normal screen's"},
	} {
		_, err := m.Write([]byte(step.stream))
		require.NoError(t, err)
		require.Equal(t, step.want, string(m.Snapshot()), step.why)
	}
}

// Every save form fills the slot of the screen showing and every restore form
// reads it, so a save of one form is restored by any: DECSC and DECRC, ?1048h
// and ?1048l, and SCOSC and SCORC, which xterm's charproc.c runs as
// CursorSave and CursorRestore too (CASE_ANSI_SC and CASE_ANSI_RC).
//
// xterm saves on CSI s, and restores on CSI u, only with no parameter at all
// (only_default), so a CSI s with parameters is no save even while DECLRMM
// (?69) is reset; see TestDECLRMMMakesABareCSIsMargins for while it is set.
func TestEveryCursorSaveAndRestoreFormCarriesG0(t *testing.T) {
	saves := []struct{ name, seq string }{{"DECSC", "\x1b7"}, {"?1048h", "\x1b[?1048h"}, {"SCOSC", "\x1b[s"}}
	restores := []struct{ name, seq string }{{"DECRC", "\x1b8"}, {"?1048l", "\x1b[?1048l"}, {"SCORC", "\x1b[u"}, {"?1049l", "\x1b[?1049l"}}
	snapshot := func(t *testing.T, stream string) string {
		m := NewModeTracker()
		_, err := m.Write([]byte(stream))
		require.NoError(t, err)
		return string(m.Snapshot())
	}
	for _, save := range saves {
		for _, restore := range restores {
			t.Run(save.name+" then "+restore.name, func(t *testing.T) {
				require.Equal(t, "\x1b(0", snapshot(t, "\x1b(0"+save.seq+"\x1b(B"+restore.seq))
			})
		}
	}
	for _, restore := range restores {
		t.Run(restore.name+" with nothing saved", func(t *testing.T) {
			require.Empty(t, snapshot(t, "\x1b(0"+restore.seq))
		})
	}
	t.Run("?1049h then DECRC", func(t *testing.T) {
		require.Equal(t, "\x1b(0", snapshot(t, "\x1b(0\x1b[?1049h\x1b[?1047l\x1b(B\x1b8"))
	})
	for _, tc := range []struct{ name, seq string }{
		{"DECSLRM, a CSI s with margins", "\x1b[2;40s"},
		{"XTSAVE, a CSI ? s", "\x1b[?1s"},
	} {
		t.Run(tc.name+" is no save", func(t *testing.T) {
			require.Empty(t, snapshot(t, "\x1b(0"+tc.seq+"\x1b8"))
		})
	}
	t.Run("kitty's query, a CSI ? u, is no restore", func(t *testing.T) {
		require.Equal(t, "\x1b(B", snapshot(t, "\x1b(0\x1b7\x1b(B\x1b[?u"), "G0 is still the ASCII designated after the save")
	})
}

// RIS and DECSTR each end with a cursor save, of the charsets they have just
// reset, so the slot it fills restores ASCII: xterm's charproc.c, ReallyReset,
// whose x/vt counterparts are vt/esc.go's fullReset and softReset. RIS first
// leaves the alternate screen (FromAlternate), so its save is the normal
// screen's, and DECSTR's is the slot of the screen showing. Neither touches
// the other screen's slot, which a restore there still brings back.
func TestResetsRefillTheSlotOfTheScreenTheySaveOn(t *testing.T) {
	for _, tc := range []struct{ name, stream, want string }{
		{"RIS", "\x1b(0\x1b7\x1bc\x1b(0\x1b8", ""},
		{"RIS from the alternate screen", "\x1b(0\x1b[?1049h\x1b7\x1bc\x1b(0\x1b8", ""},
		{"RIS keeps the alternate screen's slot", "\x1b[?1049h\x1b(0\x1b7\x1bc\x1b[?1047h\x1b8", "\x1b[?1047h\x1b(0"},
		{"DECSTR", "\x1b(0\x1b7\x1b[!p\x1b(0\x1b8", ""},
		{"DECSTR on the alternate screen", "\x1b(0\x1b[?1049h\x1b(A\x1b7\x1b[!p\x1b(0\x1b8", "\x1b(0\x1b[?1049h\x1b(B"},
		{"DECSTR on the alternate screen keeps the normal screen's slot", "\x1b(0\x1b[?1049h\x1b(A\x1b7\x1b[!p\x1b[?1049l", "\x1b(0"},
		{"DECSTR on the normal screen keeps the alternate screen's slot", "\x1b[?1047h\x1b(A\x1b7\x1b[?1047l\x1b[!p\x1b[?1047h\x1b8", "\x1b[?1047h\x1b(A"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tc.stream))
			require.NoError(t, err)
			require.Equal(t, tc.want, string(m.Snapshot()))
		})
	}
}

// While DECLRMM (?69) is set, xterm takes a bare CSI s for DECSLRM, margins
// at their defaults, and not for a save (charproc.c, CASE_ANSI_SC, which tests
// IsLeftRightMode first). CSI u is a restore either way: CASE_ANSI_RC doesn't
// look at the mode. The mode is one bit of the terminal's flags, not one per
// screen, and ReallyReset clears it for RIS and DECSTR alike
// (resetMarginMode).
//
// So the snapshot replays it while it is set: a joiner whose ring has lost the
// ?69h would otherwise read a later bare CSI s as a save where the session
// reads margins. And Restore resets it, which in xterm resets the left and
// right margins too, where a terminal leaving should have them anyway.
func TestDECLRMMMakesABareCSIsMargins(t *testing.T) {
	for _, tc := range []struct{ name, stream, want string }{
		{"set, CSI s is no save", "\x1b[?69h\x1b(0\x1b[s\x1b(B\x1b[u", "\x1b[?69h"},
		{"reset, it is one again", "\x1b[?69h\x1b[?69l\x1b(0\x1b[s\x1b(B\x1b[u", "\x1b(0"},
		{"one for both screens", "\x1b[?69h\x1b[?1049h\x1b(0\x1b[s\x1b(B\x1b[u", "\x1b[?69h\x1b[?1049h"},
		{"set on the alternate screen, still set on the normal one", "\x1b[?1047h\x1b[?69h\x1b[?1047l\x1b(0\x1b[s\x1b(B\x1b[u", "\x1b[?69h"},
		{"CSI u is still a restore", "\x1b[?69h\x1b(0\x1b7\x1b(B\x1b[u", "\x1b[?69h\x1b(0"},
		{"RIS resets it", "\x1b[?69h\x1bc\x1b(0\x1b[s\x1b(B\x1b[u", "\x1b(0"},
		{"DECSTR resets it", "\x1b[?69h\x1b[!p\x1b(0\x1b[s\x1b(B\x1b[u", "\x1b(0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tc.stream))
			require.NoError(t, err)
			require.Equal(t, tc.want, string(m.Snapshot()))
		})
	}
	for _, tc := range []struct{ name, stream, snapshot, restore string }{
		{"set", "\x1b[?69h", "\x1b[?69h", "\x1b[?69l"},
		{"set among the modes", "\x1b[?2004h\x1b[?69h\x1b[?25l", "\x1b[?25l\x1b[?2004h\x1b[?69h", "\x1b[?25h\x1b[?2004l\x1b[?69l"},
		{"set and reset", "\x1b[?69h\x1b[?69l", "", ""},
		{"never set", "\x1b[?2004h", "\x1b[?2004h", "\x1b[?2004l"},
	} {
		t.Run("replayed and reset: "+tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tc.stream))
			require.NoError(t, err)
			require.Equal(t, tc.snapshot, string(m.Snapshot()))
			require.Equal(t, tc.restore, string(m.Restore()))
		})
	}
}

// The replay and the charset guard read a control inside a G0 designation or
// a cursor save apart, on purpose. xterm executes the control and the
// sequence goes on, so ESC ( CR B designates ASCII, and the snapshot replays
// what xterm then holds. kitty abandons the ESC at the control, which leaves
// G0 as it was, so NonASCIICharset, which answers whether a terminal might be
// off ASCII on any terminal's reading, still says it might.
func TestAControlInsideADesignationIsXtermsToTheReplayAndCautiousToTheGuard(t *testing.T) {
	for _, tc := range []struct{ name, stream, snapshot string }{
		{"inside the designation", "\x1b(0\x1b(\rB", "\x1b(B"},
		{"before its parenthesis", "\x1b(0\x1b\r(B", "\x1b(B"},
		{"a save and a restore", "\x1b(0\x1b\r7\x1b(B\x1b\r8", "\x1b(0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tc.stream))
			require.NoError(t, err)
			require.Equal(t, tc.snapshot, string(m.Snapshot()), "the replay is xterm's")
			require.True(t, m.NonASCIICharset(), "the guard stays cautious")
		})
	}
}

// In an escape sequence, as in a CSI, a C0 control is executed where it
// stands and the sequence goes on, and DEL is ignored: the C0 column of
// xterm's esc_table and of the tables that designate a charset (VTPrsTbl.c)
// leaves the parser where it was. So ESC BEL 7 is DECSC, ESC BS ( BEL 0
// designates line drawing, and an ESC inside a string that a C0 follows is
// still waiting for the byte that ends the string or opens a sequence. The
// tracker fell back to ground at the control instead, and missed the save, the
// restore or the designation behind it. Neither control is part of the
// sequence, so neither is replayed with it.
//
// Only those are followed past a control, for the G0 the snapshot replays: a
// CSI, a string or a RIS begun there is dropped, as by a DEC parser that drops
// the sequence at the control, which is the reading the charset guard is
// built on and the screen its saves are read against.
//
// A joiner's replay never met this: the filter in front of the ring moves
// the control out ahead of the escape. A tracker fed output as it is written
// did, as attach's and the host's per-guest one are.
func TestAC0ControlInsideAnEscapeIsExecutedAndTheEscapeGoesOn(t *testing.T) {
	for _, tc := range []struct{ name, stream, want string }{
		{"a CSI past one is dropped", "\x1b\r[?2004h", ""},
		{"and a RIS", "\x1b[?2004h\x1b\rc", "\x1b[?2004h"},
		{"and a string", "\x1b\r]0;t", ""},
		{"a save", "\x1b(0\x1b\x077\x1b(B\x1b8", "\x1b(0"},
		{"a restore", "\x1b(0\x1b7\x1b(B\x1b\x7f8", "\x1b(0"},
		{"a designation", "\x1b\x08(\x070", "\x1b(0"},
		{"a designation past DEL", "\x1b(\x7f0", "\x1b(0"},
		{"a save after a string's ESC", "\x1b(0\x1bPq\x1b\x087\x1b(B\x1b8", "\x1b(0"},
		{"the partial leaves the control out", "\x1b\x07", "\x1b"},
		{"and so does a designation's", "\x1b(\x07", "\x1b("},
		// xterm ends an OSC at BEL, even after an ESC: the string survives
		// the ESC (charproc.c, CASE_BELL, with string_mode still ANSI_OSC).
		{"an OSC's BEL after its ESC still ends it", "\x1b(0\x1b]0;t\x1b\x077\x1b(B\x1b8", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tc.stream))
			require.NoError(t, err)
			require.Equal(t, tc.want, string(m.Snapshot()))
		})
	}
}

// ?1049h saves the normal screen's cursor on its way to the alternate screen,
// and a ?47h or ?1047h after it, there already, changes nothing of that: the
// session's ?1049l still restores it. The snapshot replays the switch through
// the mode that entered last, so after one of those it replays the ?1049h
// ahead of it, with the saved G0 designated first, for the joiner's ?1049h to
// save the same; a save of ASCII adds nothing, since a joiner's slot that
// nothing filled restores ASCII too.
func TestTheSaveA1049hMadeOutlivesARedundantSwitch(t *testing.T) {
	for _, tc := range []struct{ name, stream, want string }{
		{"?47h", "\x1b(0\x1b[?1049h\x1b[?47h\x1b(B", "\x1b(0\x1b[?1049h\x1b[?47h\x1b(B"},
		{"?1047h", "\x1b(0\x1b[?1049h\x1b[?1047h", "\x1b(0\x1b[?1049h\x1b[?1047h\x1b(0"},
		{"?1049h on the alternate screen still replays the normal screen's save", "\x1b(0\x1b7\x1b[?47h\x1b[?1049h", "\x1b(0\x1b[?1049h\x1b(0"},
		{"a save of ASCII adds nothing", "\x1b(B\x1b[?1049h\x1b[?47h", "\x1b[?47h\x1b(B"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tc.stream))
			require.NoError(t, err)
			require.Equal(t, tc.want, string(m.Snapshot()))
		})
	}
}

// While the alternate screen shows, the normal screen's saved cursor is the
// one a ?1049l, or a ?47l and ESC 8, brings back on the way out, whichever
// form saved it: ESC 7 ?47h is how many a program enters. A ?47h or ?1047h
// saves nothing, so the snapshot designates the saved G0 and saves it with an
// ESC 7 ahead of the switch, then designates the alternate screen's own.
// With nothing saved, or ASCII, the snapshot is as it was: a joiner's slot
// that nothing filled restores ASCII too.
func TestTheNormalScreensSaveIsFilledWhileTheAlternateScreenShows(t *testing.T) {
	for _, tc := range []struct{ name, stream, want string }{
		{"ESC 7, then ?47h", "\x1b(0\x1b7\x1b(B\x1b[?47h", "\x1b(0\x1b7\x1b[?47h\x1b(B"},
		{"ESC 7, then ?1047h", "\x1b(0\x1b7\x1b(B\x1b[?1047h", "\x1b(0\x1b7\x1b[?1047h\x1b(B"},
		{"CSI s, then ?47h", "\x1b(0\x1b[s\x1b[?47h", "\x1b(0\x1b7\x1b[?47h\x1b(0"},
		{"the save ?1049h made, back by ?47h", "\x1b(0\x1b[?1049h\x1b[?47l\x1b[?47h", "\x1b(0\x1b7\x1b[?47h\x1b(0"},
		{"the alternate screen in ASCII", "\x1b(0\x1b7\x1b[?47h\x1b8", "\x1b(0\x1b7\x1b[?47h\x1b(B"},
		{"nothing saved", "\x1b[?47h\x1b(0", "\x1b[?47h\x1b(0"},
		{"ASCII saved", "\x1b7\x1b[?47h\x1b(0", "\x1b[?47h\x1b(0"},
		{"ASCII designated and saved", "\x1b(B\x1b7\x1b[?1047h\x1b(0", "\x1b[?1047h\x1b(0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tc.stream))
			require.NoError(t, err)
			require.Equal(t, tc.want, string(m.Snapshot()))
		})
	}
	t.Run("Restore is as it was", func(t *testing.T) {
		m := NewModeTracker()
		_, err := m.Write([]byte("\x1b(0\x1b7\x1b(B\x1b[?47h"))
		require.NoError(t, err)
		require.Equal(t, "\x1b[?47l\x1b(B", string(m.Restore()))
	})
}

// CAN and SUB cancel a sequence from any state on the DEC parser terminals
// implement, and a terminal that has seen one is back at ground: what follows
// prints. A tracker that stayed inside the sequence recorded that text as the
// sequence's payload, and replayed it as a partial on the next Snapshot — to
// a joiner, or to its own terminal on every ~^Z resume, printing it twice —
// and Restore cancelled a sequence the terminal had already left.
func Test_ModeTracker_CANAndSUBCancelASequence(t *testing.T) {
	for _, cancel := range []string{"\x18", "\x1a"} {
		for _, tc := range []struct {
			name         string
			stream       string // cancel is placed at "|"
			wantSnapshot string
			wantRestore  string
		}{
			{name: "after ESC", stream: "\x1b|hello"},
			{name: "in a CSI", stream: "\x1b[?1049|h"},
			{name: "in an overflowed CSI", stream: "\x1b[" + strings.Repeat("1", 2*maxSequenceBytes) + "|hello"},
			{name: "in a charset designation", stream: "\x1b(|0"},
			{name: "in an OSC", stream: "\x1b]0;a title|hello"},
			{name: "at an ESC in an OSC", stream: "\x1b]0;a title\x1b|hello"},
			{name: "in a DCS", stream: "\x1bPq|hello"},
			{
				name:         "and the next sequence is still read",
				stream:       "\x1b]0;a title|\x1b[?1049h",
				wantSnapshot: "\x1b[?1049h",
				wantRestore:  "\x1b[?1049l",
			},
		} {
			t.Run(fmt.Sprintf("%q %s", cancel, tc.name), func(t *testing.T) {
				m := NewModeTracker()
				_, err := m.Write([]byte(strings.Replace(tc.stream, "|", cancel, 1)))
				require.NoError(t, err)
				require.Equal(t, tc.wantSnapshot, string(m.Snapshot()), "nothing of the cancelled sequence is replayed")
				require.Equal(t, tc.wantRestore, string(m.Restore()), "and there is no sequence left to cancel")
			})
		}
	}
}

// Output can stop anywhere, including inside a sequence: between the chunks a
// suspend lands between, or at the last byte a session sent before it ended.
// The terminal is left inside that sequence too, and whatever the shell
// prints next is read as the rest of it: an unfinished OSC swallows the
// prompt whole. So a terminal leaving mid-sequence is told to abandon it, with
// CAN, which cancels a sequence from any state on the DEC parser every
// terminal implements; and before anything else, so the rest is not read as
// part of it either.
func Test_ModeTracker_RestoreCancelsASequenceInProgress(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream string
		want   string
	}{
		{name: "after ESC", stream: "\x1b", want: "\x18"},
		{name: "in a CSI", stream: "\x1b[?10", want: "\x18"},
		{name: "in a charset designation", stream: "\x1b(", want: "\x18"},
		{name: "in an OSC", stream: "\x1b]0;a title", want: "\x18"},
		{name: "at an ESC in an OSC", stream: "\x1b]0;a title\x1b", want: "\x18"},
		{name: "in an overflowed CSI", stream: "\x1b[" + strings.Repeat("1", 2*maxSequenceBytes), want: "\x18"},
		{name: "before the modes it undoes", stream: "\x1b[?1049h\x1b[?25", want: "\x18\x1b[?1049l"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tc.stream))
			require.NoError(t, err)
			require.Equal(t, tc.want, string(m.Restore()))
		})
	}
}

// The property that makes this safe to send on every detach: a session that
// changed nothing produces nothing, so no terminal is reset on the strength
// of a guess about what might have been done to it.
func Test_ModeTracker_RestoreIsEmptyForAnUntouchedTerminal(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("just output, and \x1b[31mcolour\x1b[m, and \x1b[6n a query"))
	require.NoError(t, err)
	require.Empty(t, m.Restore())

	// Including modes the session set and put back itself.
	_, err = m.Write([]byte("\x1b[?1049h\x1b[?25l\x1b[?25h\x1b[?1049l"))
	require.NoError(t, err)
	require.Empty(t, m.Restore())
}

// The kitty keyboard protocol keeps its flags on a stack, so that a program
// can push what it wants and pop back to what was there. A joiner that is not
// given the stack sends keys the program did not ask for, and a terminal left
// with it reports every keystroke to the shell it returns to as an escape
// sequence. So each push is replayed, and on the way out the whole depth is
// popped at once: a pop past the bottom empties the stack, which is the
// terminal's default, so popping more than a viewer holds costs nothing.
func Test_ModeTracker_KittyKeyboardStack(t *testing.T) {
	for _, tc := range []struct {
		name         string
		input        string
		wantSnapshot string
		wantRestore  string
	}{
		{name: "a push", input: "\x1b[>1u", wantSnapshot: "\x1b[>1u", wantRestore: "\x1b[<1u"},
		{name: "a push with no flags is still an entry", input: "\x1b[>u", wantSnapshot: "\x1b[>0u", wantRestore: "\x1b[<1u"},
		{name: "two pushes, bottom first", input: "\x1b[>1u\x1b[>3u", wantSnapshot: "\x1b[>1u\x1b[>3u", wantRestore: "\x1b[<2u"},
		{name: "a pop", input: "\x1b[>1u\x1b[>3u\x1b[<u", wantSnapshot: "\x1b[>1u", wantRestore: "\x1b[<1u"},
		{name: "a pop of n", input: "\x1b[>1u\x1b[>3u\x1b[>5u\x1b[<2u", wantSnapshot: "\x1b[>1u", wantRestore: "\x1b[<1u"},
		{name: "a pop past the bottom empties it", input: "\x1b[>1u\x1b[<5u"},
		{name: "a set replaces the top", input: "\x1b[>1u\x1b[>7u\x1b[=2u", wantSnapshot: "\x1b[>1u\x1b[>2u", wantRestore: "\x1b[<2u"},
		{name: "a set in mode 1 replaces the top", input: "\x1b[>7u\x1b[=2;1u", wantSnapshot: "\x1b[>2u", wantRestore: "\x1b[<1u"},
		{name: "a set in mode 2 adds flags", input: "\x1b[>1u\x1b[=4;2u", wantSnapshot: "\x1b[>5u", wantRestore: "\x1b[<1u"},
		{name: "a set in mode 3 clears flags", input: "\x1b[>7u\x1b[=2;3u", wantSnapshot: "\x1b[>5u", wantRestore: "\x1b[<1u"},
		{name: "a set on an empty stack makes an entry", input: "\x1b[=5u", wantSnapshot: "\x1b[>5u", wantRestore: "\x1b[<1u"},
		{name: "a query is not state", input: "\x1b[?u"},
		// kitty takes at most two parameters for a set and ignores more.
		{name: "a set with a third parameter is ignored", input: "\x1b[=1;1;1u"},
		// kitty keeps the low seven bits of the 32-bit number it is given
		// (val & 0x7f), and the replay is what it holds.
		{name: "flags past seven bits keep the low seven", input: "\x1b[>255u", wantSnapshot: "\x1b[>127u", wantRestore: "\x1b[<1u"},
		{name: "flags past an int32 keep their low bits too", input: "\x1b[>2147483648u", wantSnapshot: "\x1b[>0u", wantRestore: "\x1b[<1u"},
		{name: "and so does a set", input: "\x1b[=4294967169u", wantSnapshot: "\x1b[>1u", wantRestore: "\x1b[<1u"},
		// Only an omitted count is one; kitty pops nothing for an explicit 0.
		{name: "a pop of zero pops nothing", input: "\x1b[>1u\x1b[<0u", wantSnapshot: "\x1b[>1u", wantRestore: "\x1b[<1u"},
		{name: "a bare CSI u restores the cursor and is not kitty", input: "\x1b[u"},
		{name: "a number that is not one is ignored", input: "\x1b[>1u\x1b[>-1u\x1b[<1:2u", wantSnapshot: "\x1b[>1u", wantRestore: "\x1b[<1u"},
		{
			// The replay keeps the eight newest entries, kitty's own depth.
			// But the protocol leaves the depth to the terminal, and one with
			// a deeper stack holds all nine: the pop is of every push, since
			// a pop past the bottom of a shallower stack only empties it.
			name:         "the replay is bounded at eight, and the pop is not",
			input:        "\x1b[>1u\x1b[>2u\x1b[>3u\x1b[>4u\x1b[>5u\x1b[>6u\x1b[>7u\x1b[>8u\x1b[>9u",
			wantSnapshot: "\x1b[>2u\x1b[>3u\x1b[>4u\x1b[>5u\x1b[>6u\x1b[>7u\x1b[>8u\x1b[>9u",
			wantRestore:  "\x1b[<9u",
		},
		{
			// Pops take the newest entries; what a deeper stack still holds
			// below the replayed ones is popped all the same.
			name:        "pops past the replayed entries leave the deeper ones counted",
			input:       "\x1b[>1u\x1b[>2u\x1b[>3u\x1b[>4u\x1b[>5u\x1b[>6u\x1b[>7u\x1b[>8u\x1b[>9u\x1b[>10u\x1b[<9u",
			wantRestore: "\x1b[<1u",
		},
		{
			// A set on an entry the replay no longer holds changes the top
			// the terminal has, so it is the top the replay gives a joiner.
			name:         "a set after the replayed entries are popped",
			input:        "\x1b[>1u\x1b[>2u\x1b[>3u\x1b[>4u\x1b[>5u\x1b[>6u\x1b[>7u\x1b[>8u\x1b[>9u\x1b[<8u\x1b[=5u",
			wantSnapshot: "\x1b[>5u",
			wantRestore:  "\x1b[<1u",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tc.input))
			require.NoError(t, err)
			require.Equal(t, tc.wantSnapshot, string(m.Snapshot()), "snapshot")
			require.Equal(t, tc.wantRestore, string(m.Restore()), "restore")
		})
	}
}

// The protocol gives the main and alternate screens a stack each, so that a
// full-screen program can push its own flags without knowing what the shell
// beneath it had. The alternate screen's stack is popped while the terminal is
// still on it -- a pop after leaving would empty the main screen's instead --
// and the main screen's once the terminal is back.
func Test_ModeTracker_KittyKeyboardStackPerScreen(t *testing.T) {
	for _, tc := range []struct {
		name         string
		input        string
		wantSnapshot string
		wantRestore  string
	}{
		{
			name:         "each screen's pushes go to its own stack",
			input:        "\x1b[>1u\x1b[?1049h\x1b[>3u",
			wantSnapshot: "\x1b[>1u\x1b[?1049h\x1b[>3u",
			wantRestore:  "\x1b[<1u\x1b[?1049l\x1b[<1u",
		},
		{
			name:         "a pop on the alternate screen leaves the main stack alone",
			input:        "\x1b[>1u\x1b[?1049h\x1b[<u",
			wantSnapshot: "\x1b[>1u\x1b[?1049h",
			wantRestore:  "\x1b[?1049l\x1b[<1u",
		},
		{
			// kitty swaps stacks on a screen switch and clears neither, so a
			// program that leaves without popping finds its flags again the
			// next time anything enters the alternate screen. A push or pop
			// reaches only the screen that is showing, so the stack is
			// replayed and popped on a trip to the alternate screen and back:
			// through 47, which does not clear the hidden screen as 1049
			// does, between a cursor save and restore, because kitty homes
			// the cursor on every switch.
			name:         "the alternate stack off the alternate screen",
			input:        "\x1b[?1049h\x1b[>3u\x1b[?1049l",
			wantSnapshot: "\x1b7\x1b[?47h\x1b[>3u\x1b[?47l\x1b8",
			wantRestore:  "\x1b7\x1b[?47h\x1b[<1u\x1b[?47l\x1b8",
		},
		{
			name:         "and is there again when the alternate screen is",
			input:        "\x1b[?1049h\x1b[>3u\x1b[?1049l\x1b[?1049h",
			wantSnapshot: "\x1b[?1049h\x1b[>3u",
			wantRestore:  "\x1b[<1u\x1b[?1049l",
		},
		{
			name:  "RIS clears both",
			input: "\x1b[>1u\x1b[?1049h\x1b[>3u\x1bc",
		},
		{
			// kitty's soft reset clears both stacks, as its hard reset does.
			name:  "DECSTR clears both",
			input: "\x1b[>1u\x1b[?1049h\x1b[>3u\x1b[?1049l\x1b[!p",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tc.input))
			require.NoError(t, err)
			require.Equal(t, tc.wantSnapshot, string(m.Snapshot()), "snapshot")
			require.Equal(t, tc.wantRestore, string(m.Restore()), "restore")
		})
	}
}

// xterm's modifyOtherKeys is the older way a program asks for keys a terminal
// otherwise folds together: vim turns it on with \e[>4;2m and off with \e[>4;m.
// Left on, a shell gets Ctrl-letter keys as escape sequences, so a leaving
// terminal is put back at the default, and a joiner is given the level.
func Test_ModeTracker_ModifyOtherKeys(t *testing.T) {
	for _, tc := range []struct {
		name         string
		input        string
		wantSnapshot string
		wantRestore  string
	}{
		{name: "level 2", input: "\x1b[>4;2m", wantSnapshot: "\x1b[>4;2m", wantRestore: "\x1b[>4m"},
		{name: "level 1", input: "\x1b[>4;1m", wantSnapshot: "\x1b[>4;1m", wantRestore: "\x1b[>4m"},
		{name: "the last level wins", input: "\x1b[>4;2m\x1b[>4;1m", wantSnapshot: "\x1b[>4;1m", wantRestore: "\x1b[>4m"},
		// An explicit 0 is not the initial value: xterm's resource may set
		// that to something else, and only a reset without a value goes back
		// to it. So it is replayed, and undone.
		{name: "an explicit level 0", input: "\x1b[>4;2m\x1b[>4;0m", wantSnapshot: "\x1b[>4;0m", wantRestore: "\x1b[>4m"},
		{name: "vim's reset, with an empty value", input: "\x1b[>4;2m\x1b[>4;m"},
		{name: "a reset with no value", input: "\x1b[>4;2m\x1b[>4m"},
		{name: "a reset of every resource", input: "\x1b[>4;2m\x1b[>m"},
		// Disabling is xterm's resource value -1, which no XTMODKEYS set can
		// spell, so it is replayed as itself.
		{name: "XTMODKEYS disable", input: "\x1b[>4;2m\x1b[>4n", wantSnapshot: "\x1b[>4n", wantRestore: "\x1b[>4m"},
		// xterm's colon form: a subparameter on the resource is a mask of
		// modifiers to leave out of the encoding, and is replayed with it.
		{name: "a mask and a level", input: "\x1b[>4:1;2m", wantSnapshot: "\x1b[>4:1;2m", wantRestore: "\x1b[>4m"},
		{name: "a mask alone", input: "\x1b[>4:1m", wantSnapshot: "\x1b[>4:1m", wantRestore: "\x1b[>4m"},
		{name: "a reset clears the mask", input: "\x1b[>4:1;2m\x1b[>4m"},
		{name: "a level without a mask clears it", input: "\x1b[>4:1;2m\x1b[>4;1m", wantSnapshot: "\x1b[>4;1m", wantRestore: "\x1b[>4m"},
		// xterm's own parser takes the mask on the value; its documentation
		// puts it on the resource. Either is replayed as it was written.
		{name: "a mask on the value", input: "\x1b[>4;2:1m", wantSnapshot: "\x1b[>4;2:1m", wantRestore: "\x1b[>4m"},
		{name: "a field of more than one subparameter is ignored", input: "\x1b[>4:1:2;2m"},
		{name: "another resource is not this one", input: "\x1b[>1;2m"},
		{name: "SGR underline is not XTMODKEYS", input: "\x1b[4m\x1b[4;2m"},
		{name: "RIS resets it", input: "\x1b[>4;2m\x1bc"},
		// xterm's soft reset puts the key modifiers back to their initial
		// values, mask and all, as its hard reset does.
		{name: "DECSTR resets it", input: "\x1b[>4:1;2m\x1b[!p"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tc.input))
			require.NoError(t, err)
			require.Equal(t, tc.wantSnapshot, string(m.Snapshot()), "snapshot")
			require.Equal(t, tc.wantRestore, string(m.Restore()), "restore")
		})
	}
}

// Where the keyboard state goes among everything else. A joiner is given the
// main screen's stack while it is still on the main screen, and the alternate
// screen's once it has switched; a leaving terminal pops the alternate stack
// before it leaves that screen and the main one after.
func Test_ModeTracker_KeyboardStateOrder(t *testing.T) {
	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[2;20r\x1b[>1u\x1b[>4;2m\x1b[?2004h\x1b[?1049h\x1b[5;15r\x1b[>3u\x1b(0"))
	require.NoError(t, err)

	// The terminal's one region, the last set, goes first, whichever screen
	// set it.
	require.Equal(t,
		"\x1b[5;15r"+"\x1b[?2004h"+"\x1b[>1u"+"\x1b[>4;2m"+"\x1b[?1049h"+"\x1b[>3u"+"\x1b(0",
		string(m.Snapshot()))
	// The charset needs no reset: ?1049l brings back the ASCII ?1049h saved.
	require.Equal(t,
		"\x1b[<1u"+"\x1b[?1049l"+"\x1b[r"+"\x1b[?2004l"+"\x1b[<1u"+"\x1b[>4m",
		string(m.Restore()))
}

// A C0 control inside a CSI is executed where it stands, and the CSI goes on:
// the DEC parser's "execute" in its CSI states, which kitty follows too. A BEL
// or a backspace there is not one of the sequence's parameters, and nor is
// DEL, which the parser ignores.
func Test_ModeTracker_EmbeddedControlInACSI(t *testing.T) {
	for _, tc := range []struct {
		name         string
		input        string
		wantSnapshot string
		wantRestore  string
	}{
		{name: "a DEC mode", input: "\x1b[?10\x0749h", wantSnapshot: "\x1b[?1049h", wantRestore: "\x1b[?1049l"},
		{name: "a kitty push", input: "\x1b[>1\x08u", wantSnapshot: "\x1b[>1u", wantRestore: "\x1b[<1u"},
		{name: "DEL", input: "\x1b[?20\x7f04h", wantSnapshot: "\x1b[?2004h", wantRestore: "\x1b[?2004l"},
		{
			// A joiner is not made to execute it again.
			name:         "in the sequence the stream stopped inside",
			input:        "\x1b[?10\x07",
			wantSnapshot: "\x1b[?10",
			wantRestore:  "\x18",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, err := m.Write([]byte(tc.input))
			require.NoError(t, err)
			require.Equal(t, tc.wantSnapshot, string(m.Snapshot()), "snapshot")
			require.Equal(t, tc.wantRestore, string(m.Restore()), "restore")
		})
	}
}

// CSI parameters are read at the protocols' width, an unsigned 32-bit number,
// whatever an int is on the build: kitty takes a pop's count as a uint32, and
// a 32-bit client must track the same stream a 64-bit one does.
func Test_csiNumberReadsTheProtocolsWidth(t *testing.T) {
	n, ok := csiNumber([]byte("4294967295"), 0)
	require.True(t, ok, "the widest unsigned 32-bit number")
	require.Equal(t, math.MaxInt32, n, "clamped to what every build's int holds, so every build tracks it alike")

	_, ok = csiNumber([]byte("4294967296"), 0)
	require.False(t, ok, "past it")

	m := NewModeTracker()
	_, err := m.Write([]byte("\x1b[>1u\x1b[>2u\x1b[<4294967295u"))
	require.NoError(t, err)
	require.Empty(t, m.Snapshot(), "a pop past any depth empties the stack")
	require.Empty(t, m.Restore())
}

// A tracker's clone is fed bytes the original is not, and the original bytes
// the clone is not, each from the state they shared. Neither may reach the
// other: the original goes on describing the ring's first byte for every
// joiner after, and a clone is only as good as the state it was taken at.
//
// The parser writes into its slices in place -- it rewrites a key stack's top
// entry and modifyOtherKeys, and reuses the arrays behind the sequence it is
// inside -- so a copy that shares one carries each side's writes into the
// other. Each case is one of them, and expects each tracker to end up where a
// fresh tracker fed the same bytes would: the clone's and the original's
// alike, fed one after the other and fed a byte at a time in turn, because a
// shared array is only wrong for whichever side reads it second.
func TestCloneIsIndependent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		base  string // fed before the clone is taken
		clone string // fed to the clone only
		orig  string // fed to the original only
	}{
		{"mode map", "\x1b[?2004h\x1b[?25l", "\x1b[?2004l\x1b[?1004h", "\x1b[?25h\x1b[?1000h"},
		// A set rewrites the top entry of whichever screen's stack is showing.
		{"kitty key stacks", "\x1b[>1u\x1b[?1049h\x1b[>2u", "\x1b[=5u\x1b[?1049l\x1b[=6u", "\x1b[=3u\x1b[?1049l\x1b[=7u"},
		{"modifyOtherKeys", "\x1b[>4;1m", "\x1b[>4;2m", "\x1b[>4;3m"},
		// Both are left inside a sequence, so each Snapshot ends with its
		// partial; a clone that ends the title and opens another writes over
		// the head of the one the original is still holding. It ends the title
		// at once: any text first would grow the partial past the array's
		// capacity, and the clone would be on an array of its own.
		{"partial", "\x1b]0;the-title", "\a\x1b[?2004h\x1b]2;c", "-and-more"},
		// The parameters of a CSI the original and the clone each complete
		// differently.
		{"CSI parameters", "\x1b[?100", "0h", "4h"},
	} {
		for _, interleaved := range []bool{false, true} {
			name := tc.name + "/in turn"
			if interleaved {
				name = tc.name + "/a byte at a time"
			}
			t.Run(name, func(t *testing.T) {
				fresh := func(feeds ...string) *ModeTracker {
					m := NewModeTracker()
					for _, f := range feeds {
						_, err := m.Write([]byte(f))
						require.NoError(t, err)
					}
					return m
				}

				m := fresh(tc.base)
				c := m.Clone()
				require.Equal(t, string(m.Snapshot()), string(c.Snapshot()), "a clone starts where the original is")
				require.Equal(t, string(m.Restore()), string(c.Restore()), "a clone starts where the original is")

				if interleaved {
					for i := 0; i < max(len(tc.clone), len(tc.orig)); i++ {
						if i < len(tc.clone) {
							_, _ = c.Write([]byte{tc.clone[i]})
						}
						if i < len(tc.orig) {
							_, _ = m.Write([]byte{tc.orig[i]})
						}
					}
				} else {
					_, _ = c.Write([]byte(tc.clone))
					_, _ = m.Write([]byte(tc.orig))
				}

				wantC, wantM := fresh(tc.base, tc.clone), fresh(tc.base, tc.orig)
				require.NotEqual(t, string(wantM.Snapshot()), string(wantC.Snapshot()), "the case feeds them differently")
				require.Equal(t, string(wantM.Snapshot()), string(m.Snapshot()), "the original's snapshot")
				require.Equal(t, string(wantM.Restore()), string(m.Restore()), "the original's restore")
				require.Equal(t, string(wantC.Snapshot()), string(c.Snapshot()), "the clone's snapshot")
				require.Equal(t, string(wantC.Restore()), string(c.Restore()), "the clone's restore")
			})
		}
	}
}

// rows is a terminal of n rows, the dimension a DECSTBM is decided against.
func rows(n int) termsize.Size { return termsize.Size{Cols: 80, Rows: n} }

// The tracker decides a DECSTBM as xterm's CASE_DECSTBM does, at the height of
// the moment. Top is 1 if absent or 0; bottom is the height if absent, 0 or
// past it; and the region is set only if bottom > top, or else nothing changes.
// Stored as written, CSI 10;11r replaced 2;5, though a terminal of 8 rows
// ignores it and keeps 2;5.
func TestTrackerDecidesDECSTBMAtTheHeight(t *testing.T) {
	m := NewModeTracker()
	m.Resized(rows(8))
	for _, step := range []struct{ in, want string }{
		{"\x1b[2;5r", "\x1b[2;5r"},
		{"\x1b[10;11r", "\x1b[2;5r"}, // bottom clamps to 8, not below 10
		{"\x1b[10r", "\x1b[2;5r"},
		{"\x1b[3r", "\x1b[3;8r"},
		{"\x1b[r", ""}, // the whole screen, which a joiner starts with
		{"\x1b[5;5r", ""},
	} {
		_, _ = m.Write([]byte(step.in))
		require.Equal(t, step.want, string(m.Snapshot()), "after %q", step.in)
	}
}

// The parameters as xterm reads them: an explicit 0 is a default, a number
// past any height is the height, and a parameter past the second is ignored.
// An r sequence with a prefix, an intermediate or a subparameter is not
// DECSTBM at all -- CSI ? r is XTRESTORE, CSI $ r is DECCARA -- and leaves the
// region alone.
func TestTrackerReadsDECSTBMsParameters(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"\x1b[0;0r", ""},
		{"\x1b[;6r", "\x1b[1;6r"},
		{"\x1b[0;6r", "\x1b[1;6r"},
		{"\x1b[2;0r", "\x1b[2;8r"},
		{"\x1b[2;99999999999999999999r", "\x1b[2;8r"},
		{"\x1b[99999999999999999999r", "\x1b[3;5r"},
		{"\x1b[2;5;7r", "\x1b[2;5r"},
		{"\x1b[?2;6r", "\x1b[3;5r"},
		{"\x1b[>2;6r", "\x1b[3;5r"},
		{"\x1b[2;6$r", "\x1b[3;5r"},
		{"\x1b[2:1;6r", "\x1b[3;5r"},
	} {
		t.Run(fmt.Sprintf("%q", tc.in), func(t *testing.T) {
			m := NewModeTracker()
			m.Resized(rows(8))
			_, _ = m.Write([]byte("\x1b[3;5r" + tc.in))
			require.Equal(t, tc.want, string(m.Snapshot()))
		})
	}
}

// With no size known yet, there is no height to decide a DECSTBM against, so
// the tracker decides it as it did before it heard of sizes: every one is
// taken, the last wins, and it is kept and replayed as written, for the
// joiner's terminal to decide at its own height. Only a tracker nothing feeds
// sizes stays here, as the host's own for a forced command does.
func TestDECSTBMWithNoKnownHeight(t *testing.T) {
	m := NewModeTracker()
	for _, step := range []struct{ in, want string }{
		{"\x1b[2;5r", "\x1b[2;5r"},
		{"\x1b[10;11r", "\x1b[10;11r"},
		{"\x1b[5;5r", "\x1b[5;5r"},
		{"\x1b[?2;6r", "\x1b[5;5r"}, // XTRESTORE, not a region
		{"\x1b[r", "\x1b[r"},
	} {
		_, _ = m.Write([]byte(step.in))
		require.Equal(t, step.want, string(m.Snapshot()), "after %q", step.in)
		require.Equal(t, "\x1b[r", string(m.Restore()), "after %q", step.in)
	}

	// A size that isn't one is no height either.
	m.Resized(termsize.Size{})
	_, _ = m.Write([]byte("\x1b[10;11r"))
	require.Equal(t, "\x1b[10;11r", string(m.Snapshot()))
}

// Candidates {none: 8, e1: 4, e2: 12}, CSI 2;6r (2;6, 2;4, 2;6), then e1
// commits, which removes "none" with e2 still unresolved: 2;4 and 2;6 remain.
// Snapshot, which the raw fallback replays, gives the newest surviving
// candidate's, e2's, the likeliest; a "none" candidate is gone, and the one now
// first is e1's. Restore resets the region.
func TestSnapshotAfterAPartialCommitment(t *testing.T) {
	m := NewModeTracker()
	m.Resized(rows(8))
	m.crossTentative(1, rows(4))
	m.crossTentative(2, rows(12))
	_, _ = m.Write([]byte("\x1b[2;6r"))
	m.resolve(1, true)

	require.True(t, m.uncertain())
	require.Equal(t, "\x1b[2;6r", string(m.Snapshot()))
	require.Equal(t, "\x1b[r", string(m.Restore()))
}

// Restore resets the region if any candidate has one, not only the newest:
// resetting margins a terminal doesn't have is harmless, and missing some
// leaves a guest's shell scrolling inside rows. Here the newest, e2's, was
// crossed after the DECSTBM, so it has none.
func TestRestoreResetsAnyCandidatesRegion(t *testing.T) {
	m := NewModeTracker()
	m.Resized(rows(8))
	m.crossTentative(1, rows(4))
	_, _ = m.Write([]byte("\x1b[2;6r"))
	m.crossTentative(2, rows(12))
	m.resolve(1, true)

	require.True(t, m.uncertain())
	require.Empty(t, m.Snapshot(), "the newest candidate's, the whole screen")
	require.Equal(t, "\x1b[r", string(m.Restore()))
}

// Past 16 unresolved crossed events the tracker keeps one bounded fallback
// state, the newest candidate at the overflow: the 17th's size and the whole
// screen. While overflowed, each DECSTBM is decided at its height, a crossed
// event is assumed to commit, outcomes change nothing, and the tracker is
// uncertain, until a committed resize heard in order.
func TestSnapshotAfterAnOverflow(t *testing.T) {
	m := NewModeTracker()
	m.Resized(rows(8))
	for seq := uint64(1); seq <= maxUnresolvedResizes; seq++ {
		m.crossTentative(seq, rows(12))
	}
	require.False(t, m.uncertain(), "16 candidates, all with the whole screen")

	m.crossTentative(maxUnresolvedResizes+1, rows(4))
	require.True(t, m.uncertain())
	require.Empty(t, m.Snapshot(), "the 17th's candidate: the whole screen")
	_, _ = m.Write([]byte("\x1b[2;6r"))
	require.Equal(t, "\x1b[2;4r", string(m.Snapshot()), "decided at the 17th's height")
	require.Equal(t, "\x1b[r", string(m.Restore()))

	for seq := uint64(1); seq <= maxUnresolvedResizes+1; seq++ {
		m.resolve(seq, seq%2 == 0)
	}
	require.True(t, m.uncertain(), "outcomes change nothing")
	require.Equal(t, "\x1b[2;4r", string(m.Snapshot()))

	m.crossTentative(maxUnresolvedResizes+2, rows(20))
	require.Empty(t, m.Snapshot(), "assumed to commit")
	require.Equal(t, "\x1b[r", string(m.Restore()), "a DECSTBM was taken, and a guest may hold it")
	_, _ = m.Write([]byte("\x1b[2;30r"))
	require.Equal(t, "\x1b[2;20r", string(m.Snapshot()))

	m.Resized(rows(8))
	require.False(t, m.uncertain())
	require.Empty(t, m.Snapshot())
}

// An outcome decides something only for an event the tracker crossed and
// still keeps a candidate for.
func TestResolveIgnoresAnEventNeverCrossed(t *testing.T) {
	m := NewModeTracker()
	m.Resized(rows(8))
	_, _ = m.Write([]byte("\x1b[2;5r"))
	m.resolve(7, true)
	m.resolve(8, false)
	m.resolve(0, false) // never a resize's Seq
	require.False(t, m.uncertain())
	require.Equal(t, "\x1b[2;5r", string(m.Snapshot()))
	_, _ = m.Write([]byte("\x1b[10;11r"))
	require.Equal(t, "\x1b[2;5r", string(m.Snapshot()), "still decided at 8 rows")
}

// AtGround is whether the tracker is outside every sequence, with no partial
// to replay.
func TestAtGround(t *testing.T) {
	m := NewModeTracker()
	require.True(t, m.AtGround())
	for _, step := range []struct {
		in     string
		ground bool
	}{
		{"\x1b", false}, {"[?10", false}, {"49h", true},
		{"\x1b]0;title", false}, {"\x07", true},
		{"\x1b(", false}, {"0", true},
		{"\x1bP", false}, {"q\x1b", false}, {"\\", true},
		{"\x1b[", false}, {"\x18", true},
		{"text", true},
		// Overflowed, a CSI has no partial left, and is still a sequence.
		{"\x1b[" + strings.Repeat("1", 2*maxSequenceBytes), false}, {"m", true},
	} {
		_, _ = m.Write([]byte(step.in))
		require.Equal(t, step.ground, m.AtGround(), "after %q", step.in)
	}
}

// ReplayParts holds every tracked DEC private mode with its value, the
// alternate screen's aside, which AltVia covers; Modes, which a render emits,
// holds only those off their default, as Snapshot does.
func TestReplayPartsHoldsEveryMode(t *testing.T) {
	defaults := maps.Clone(restorable)
	for n := range altScreenModes {
		delete(defaults, n)
	}

	m := NewModeTracker()
	parts := m.ReplayParts()
	require.Equal(t, defaults, parts.DECModes)
	require.True(t, parts.Autowrap)
	require.Empty(t, parts.Modes)
	require.Zero(t, parts.AltVia)

	_, _ = m.Write([]byte("\x1b[?1h\x1b[?7l\x1b[?25h\x1b[?2004h\x1b[?1049h"))
	parts = m.ReplayParts()
	want := maps.Clone(defaults)
	want[1], want[7], want[2004] = true, false, true
	require.Equal(t, want, parts.DECModes)
	require.False(t, parts.Autowrap)
	require.Equal(t, "\x1b[?1h\x1b[?2004h", string(parts.Modes), "DECAWM is the render's to put back last")
	require.Equal(t, 1049, parts.AltVia)
}

// ReplayParts' pieces, reassembled around the screen switch and with DECAWM put
// back in its place, are Snapshot's, less the region, the charset and the
// partial, which the reconstruction gives in its own places.
func TestReplayPartsReassembleSnapshot(t *testing.T) {
	const (
		modes = "\x1b[?1h\x1b[?25l\x1b[?2004h"
		keys  = "\x1b[>1u\x1b[>5u\x1b[>4;2m"
	)
	for _, tc := range []struct{ name, body string }{
		{"the main screen", modes + keys},
		{"the main screen, autowrap off", modes + "\x1b[?7l" + keys},
		{"the main screen, an alternate stack hidden", modes + "\x1b[?7l" + keys + "\x1b[?1049h\x1b[>3u\x1b[?1049l"},
		{"47", modes + "\x1b[?7l" + keys + "\x1b[?47h\x1b[>3u"},
		{"1047", modes + keys + "\x1b[?1047h\x1b[>3u\x1b[>2u"},
		{"1049", modes + "\x1b[?7l" + keys + "\x1b[?1049h\x1b[>3u"},
		{"nothing set", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const region, tail = "\x1b[2;20r", "\x1b(0\x1b[?10"
			m := NewModeTracker()
			m.Resized(rows(24))
			_, _ = m.Write([]byte(region + tc.body + tail))

			snap := string(m.Snapshot())
			require.True(t, strings.HasPrefix(snap, region), "%q", snap)
			require.True(t, strings.HasSuffix(snap, tail), "%q", snap)
			middle := strings.TrimSuffix(strings.TrimPrefix(snap, region), tail)
			require.Equal(t, middle, reassemble(m.ReplayParts()))
		})
	}
}

// reassemble puts ReplayParts back together as Snapshot orders them: the
// modes, with DECAWM after DECCKM, the one tracked mode numbered below it;
// the main stack and modifyOtherKeys; then the trip that pushes a hidden
// alternate stack, or the switch to the alternate screen and its stack.
func reassemble(p ReplayParts) string {
	modes := string(p.Modes)
	if !p.Autowrap {
		if rest, ok := strings.CutPrefix(modes, "\x1b[?1h"); ok {
			modes = "\x1b[?1h\x1b[?7l" + rest
		} else {
			modes = "\x1b[?7l" + modes
		}
	}
	out := modes + string(p.MainKeys)
	switch {
	case p.AltVia != 0:
		out += fmt.Sprintf("\x1b[?%dh", p.AltVia) + string(p.AltKeys)
	case p.HiddenAltKeys != nil:
		out += "\x1b7\x1b[?47h" + string(p.HiddenAltKeys) + "\x1b[?47l\x1b8"
	}
	return out
}

// A clone's candidates, fallback state and heights are its own. Each is changed
// in place -- a resolve deletes from the list, a crossing while overflowed
// rewrites the fallback -- so a list shared with the original would carry one's
// outcomes into the other.
func TestCloneCopiesTheMarginCandidates(t *testing.T) {
	t.Run("candidates", func(t *testing.T) {
		m := NewModeTracker()
		m.Resized(rows(8))
		m.crossTentative(1, rows(4))
		_, _ = m.Write([]byte("\x1b[2;6r"))

		c := m.Clone()
		c.resolve(1, true)
		_, _ = c.Write([]byte("\x1b[2;30r"))
		m.resolve(1, false)
		_, _ = m.Write([]byte("\x1b[3;30r"))

		require.Equal(t, "\x1b[2;4r", string(c.Snapshot()), "the clone kept the 4-row candidate")
		require.Equal(t, "\x1b[3;8r", string(m.Snapshot()), "the original kept the 8-row one")
	})

	t.Run("the fallback state", func(t *testing.T) {
		m := NewModeTracker()
		for seq := uint64(1); seq <= maxUnresolvedResizes+1; seq++ {
			m.crossTentative(seq, rows(8))
		}
		_, _ = m.Write([]byte("\x1b[2;30r"))

		c := m.Clone()
		c.crossTentative(maxUnresolvedResizes+2, rows(4))
		_, _ = c.Write([]byte("\x1b[3;30r"))

		require.Equal(t, "\x1b[3;4r", string(c.Snapshot()))
		require.Equal(t, "\x1b[2;8r", string(m.Snapshot()))
		require.True(t, c.uncertain())
		require.True(t, m.uncertain())

		m.Resized(rows(8))
		require.False(t, m.uncertain())
		require.True(t, c.uncertain(), "the clone is still overflowed")
	})
}

// Clone is a hand-kept list of the fields to copy deep, so this walks the
// tracker by reflection and fails on any reference -- a slice's array or a
// map -- the clone shares with the original, down through the candidates. A
// field added later and left to the shallow copy fails here; so does one the
// fixture leaves empty, which this couldn't check.
func TestCloneSharesNoReference(t *testing.T) {
	m := NewModeTracker()
	// No size yet, so the region is kept as written, a slice; then a
	// candidate per crossed event. Both screens' kitty stacks, the charset and
	// both screens' saved G0, the normal screen's saved by ?1049h,
	// modifyOtherKeys, and a CSI the stream stops inside, for the partial and
	// the parameters.
	_, _ = m.Write([]byte("\x1b[2;5r\x1b(0\x1b[>1u\x1b[?1049h\x1b7\x1b[>2u\x1b[>4;1m\x1b[?25l"))
	m.crossTentative(1, rows(4))
	_, _ = m.Write([]byte("\x1b[?10"))

	c := m.Clone()
	seen := map[string]bool{}
	requireNothingShared(t, "ModeTracker", reflect.ValueOf(m).Elem(), reflect.ValueOf(c).Elem(), seen)
	for path, filled := range seen {
		require.True(t, filled, "%s is empty in the fixture, so its copy goes unchecked: fill it", path)
	}
}

// requireNothingShared walks a and b, which must have the same type, and
// fails where a slice or map of a is b's too. seen records each reference
// field by its path, indices left out, and whether a held anything there.
func requireNothingShared(t *testing.T, path string, a, b reflect.Value, seen map[string]bool) {
	t.Helper()
	switch a.Kind() {
	case reflect.Struct:
		for i := range a.NumField() {
			requireNothingShared(t, path+"."+a.Type().Field(i).Name, a.Field(i), b.Field(i), seen)
		}
	case reflect.Slice:
		seen[path] = seen[path] || a.Cap() > 0
		if a.Cap() > 0 && b.Cap() > 0 {
			require.NotEqual(t, a.Pointer(), b.Pointer(), "%s is shared with the clone", path)
		}
		for i := range min(a.Len(), b.Len()) {
			requireNothingShared(t, path+"[]", a.Index(i), b.Index(i), seen)
		}
	case reflect.Map:
		seen[path] = seen[path] || a.Len() > 0
		if !a.IsNil() {
			require.NotEqual(t, a.Pointer(), b.Pointer(), "%s is shared with the clone", path)
		}
		require.True(t, a.Type().Elem().Kind() <= reflect.Complex128, "%s: the walk doesn't look inside a map of %s", path, a.Type().Elem())
	case reflect.Array:
		for i := range a.Len() {
			requireNothingShared(t, path+"[]", a.Index(i), b.Index(i), seen)
		}
	case reflect.Pointer, reflect.Interface, reflect.Chan, reflect.Func, reflect.UnsafePointer:
		t.Fatalf("%s: the walk doesn't know how to check a %s", path, a.Kind())
	}
}

// Restore resets the margins once any DECSTBM has been taken, decided or
// not, until RIS or DECSTR resets them on every terminal: a guest's own can
// be taller than the pty, where 0;24 at 24 rows is a region. Snapshot keeps
// the region decided at the pty's height.
func TestRestoreRemembersEveryDECSTBMTaken(t *testing.T) {
	m := NewModeTracker()
	m.Resized(rows(24))
	_, _ = m.Write([]byte("\x1b[?2;6r"))
	require.Empty(t, m.Restore(), "XTRESTORE is not a DECSTBM")

	_, _ = m.Write([]byte("\x1b[0;24r"))
	require.Empty(t, m.Snapshot())
	require.Equal(t, "\x1b[r", string(m.Restore()))
	m.Resized(rows(30))
	require.Equal(t, "\x1b[r", string(m.Restore()), "a resize of the pty is no reset of a guest's")
	require.Equal(t, "\x1b[r", string(m.Clone().Restore()))

	_, _ = m.Write([]byte("\x1b[!p"))
	require.Empty(t, m.Restore(), "DECSTR resets the margins")
	_, _ = m.Write([]byte("\x1b[5;5r"))
	require.Equal(t, "\x1b[r", string(m.Restore()), "taken, though no terminal sets it")
	_, _ = m.Write([]byte("\x1bc"))
	require.Empty(t, m.Restore(), "and so does RIS")
}

// A committed resize heard in order is no resize at all where the terminal
// already had its size: no SIGWINCH, nothing reset. Each candidate is its own
// terminal for this, so one at that size keeps its region while one at
// another is reset, and the candidates collapse only when every one resets.
func TestAResizeHeardInOrderResetsOnlyWhereTheSizeChanges(t *testing.T) {
	mixed := func() *ModeTracker {
		m := NewModeTracker()
		m.Resized(rows(24))
		m.crossTentative(1, rows(30))
		_, _ = m.Write([]byte("\x1b[2;10r"))
		m.resizeHeard(rows(24))
		return m
	}

	t.Run("at the size of some candidates", func(t *testing.T) {
		m := mixed()
		require.True(t, m.uncertain(), "2;10 at 24 rows, the whole screen at 30 resized to 24")
		m.resolve(1, false)
		require.False(t, m.uncertain())
		require.Equal(t, "\x1b[2;10r", string(m.Snapshot()))

		m = mixed()
		m.resolve(1, true)
		require.False(t, m.uncertain())
		require.Empty(t, m.Snapshot())
	})

	t.Run("at the size of every candidate", func(t *testing.T) {
		m := NewModeTracker()
		m.Resized(rows(24))
		m.crossTentative(1, rows(24))
		_, _ = m.Write([]byte("\x1b[2;10r"))
		m.resizeHeard(rows(24))
		require.Len(t, m.candidates, 2)
		require.Equal(t, "\x1b[2;10r", string(m.Snapshot()))
	})

	t.Run("at the size of none", func(t *testing.T) {
		m := NewModeTracker()
		m.Resized(rows(24))
		m.crossTentative(1, rows(30))
		_, _ = m.Write([]byte("\x1b[2;10r"))
		m.resizeHeard(termsize.Size{Cols: 100, Rows: 24})
		require.Len(t, m.candidates, 1)
		require.False(t, m.uncertain())
		require.Empty(t, m.Snapshot())
	})

	// Overflowed, the fallback's size is a guess, not the terminal's, so it
	// decides nothing: the pty reports a resize only when its size changes,
	// and every one resets the margins.
	t.Run("overflowed, at the fallback's size", func(t *testing.T) {
		m := NewModeTracker()
		for seq := uint64(1); seq <= maxUnresolvedResizes+1; seq++ {
			m.crossTentative(seq, rows(24))
		}
		_, _ = m.Write([]byte("\x1b[2;10r"))
		require.True(t, m.uncertain())
		m.resizeHeard(rows(24))
		require.False(t, m.uncertain())
		require.Len(t, m.candidates, 1)
		require.Empty(t, m.Snapshot())
	})
}

// A string a program ended with CAN, SUB or an ESC that isn't ST is over for a
// DEC parser and still open for kitty, and for tmux's DCS. InSequence takes
// the cautious reading: it is still open until ST, or BEL for an OSC, which
// end it for every terminal.
func TestAnAmbiguouslyEndedStringStaysUnsafeUntilST(t *testing.T) {
	m := NewModeTracker()
	_, _ = m.Write([]byte("\x1bPq\x18")) // a DCS the program "ended" with CAN
	require.True(t, m.InSequence(), "kitty and tmux may still be inside the DCS")
	require.True(t, m.AtGround(), "the bookkeeping keeps the DEC reading")
	_, _ = m.Write([]byte("more"))
	require.True(t, m.InSequence())
	_, _ = m.Write([]byte("\x1b\\")) // ST: every terminal is out now
	require.False(t, m.InSequence())

	o := NewModeTracker()
	_, _ = o.Write([]byte("\x1b]0;t\x1a")) // an OSC ended by SUB
	require.True(t, o.InSequence())
	_, _ = o.Write([]byte("\x07")) // BEL ends an OSC everywhere
	require.False(t, o.InSequence())

	e := NewModeTracker()
	_, _ = e.Write([]byte("\x1b]0;t\x1b[m")) // an OSC ended by an ESC that isn't ST
	require.True(t, e.InSequence())
	_, _ = e.Write([]byte("\x1b\\"))
	require.False(t, e.InSequence())

	d := NewModeTracker()
	_, _ = d.Write([]byte("\x1bPq\x18\x07")) // BEL ends an OSC, not a DCS
	require.True(t, d.InSequence())
}

func TestInSequenceKnowsEveryPendingFinalByte(t *testing.T) {
	for _, partial := range []string{"\x1b", "\x1b(", "\x1b)", "\x1b*", "\x1b+", "\x1b-", "\x1b.", "\x1b/", "\x1b#", "\x1b%", "\x1b ", "\x1b(%", "\x1b%/", "\x1b[?1000", "\x1b]0;tit", "\x1bPq"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(partial))
		require.True(t, m.InSequence(), "%q", partial)
	}
	for _, whole := range []string{"\x1b(B", "\x1b)0", "\x1b#8", "\x1b%G", "\x1b%/G", "\x1b(%5", "\x1b[?1000l", "\x1b]0;t\x07", "\x1b]0;t\x1b\\", "\x1b)\x18", "plain"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(whole))
		require.False(t, m.InSequence(), "%q", whole)
	}
}

// A character split at a chunk's end is a sequence of its own: text written
// before its continuation bytes would land inside it, and the terminal would
// draw a replacement character where both were meant. UTF8Pending says how
// many of them are still to come.
func TestInSequenceWaitsOutAPartialCharacter(t *testing.T) {
	for _, tc := range []struct {
		partial string
		pending int
	}{
		{"\xc3", 1}, {"\xe2", 2}, {"\xe2\x94", 1}, {"\xf0", 3}, {"\xf0\x9f", 2}, {"\xf0\x9f\x98", 1}, {"ok \xe2\x94", 1},
	} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(tc.partial))
		require.True(t, m.InSequence(), "%q", tc.partial)
		require.Equal(t, tc.pending, m.UTF8Pending(), "%q", tc.partial)
	}
	for _, whole := range []string{"\xc3\xa9", "\xe2\x94\x80", "\xf0\x9f\x98\x80", "\xe2\x94x", "\x80", "\xc0\x80", "\xff"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(whole))
		require.False(t, m.InSequence(), "%q", whole)
		require.Zero(t, m.UTF8Pending(), "%q", whole)
	}
}

// The pending prefix belongs to the tracker at its current offset. Completing
// it on a clone must neither change the original nor retain a completed or
// interrupted character as the prefix of the next one.
func TestUTF8PrefixFollowsTheTrackersOffset(t *testing.T) {
	for _, prefix := range []string{"\xc3", "\xe2\x96", "\xf0\x9f\x98", "\xe0\x80", "\xf4\x90\x80"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte("é" + prefix))
		require.Equal(t, prefix, m.UTF8Prefix())
		c := m.Clone()
		require.Equal(t, prefix, c.UTF8Prefix())
		_, _ = c.Write([]byte{0x80})
		require.Empty(t, c.UTF8Prefix())
		require.Equal(t, prefix, m.UTF8Prefix())
		_, _ = m.Write([]byte("X\xe0\xa0"))
		require.Equal(t, "\xe0\xa0", m.UTF8Prefix())
		require.Empty(t, c.UTF8Prefix())
		_, _ = m.Write([]byte("\xf0\x9f"))
		require.Equal(t, "\xf0\x9f", m.UTF8Prefix())
		_, _ = m.Write([]byte("X"))
		require.Empty(t, m.UTF8Prefix())
	}
}

// RawC1 reports the first byte from 0x80 to 0x9F the output held that
// doesn't continue a UTF-8 character, in any state: alone, as an 8-bit
// introducer, an 8-bit ST ending a string, or inside a string's data, after a
// character ended early or a byte no character begins with. A byte that
// continues a character, split across writes or not, is the character's, and
// the 7-bit forms hold none. A clone reports only what was written to it,
// with the character the original was inside still to finish.
func TestRawC1NotesAC1ByteOutsideACharacter(t *testing.T) {
	for _, tc := range []struct {
		out  []string
		want byte
	}{
		{[]string{"\x84"}, 0x84},
		{[]string{"text\x9b1m"}, 0x9b},
		{[]string{"\x1b]0;t\x9c"}, 0x9c},
		{[]string{"\x1b]0;a\x85b\x07"}, 0x85},
		{[]string{"a\x8db\x8e"}, 0x8d},
		{[]string{"\xe2A\x85"}, 0x85},
		{[]string{"\xc0\x80"}, 0x80},
		{[]string{"\xc5\x85\x85"}, 0x85},
		{[]string{"\xc5\x85"}, 0},
		{[]string{"\xe2\x96\x88"}, 0},
		{[]string{"\xe2", "\x96", "\x88"}, 0},
		{[]string{"\xf0\x9f\x98\x80"}, 0},
		{[]string{"\xa0\xbf"}, 0},
		{[]string{"\x1bD\x1bH\x1bM\x1bN\x1bO\x1b[1m\x1b]0;t\x1b\\"}, 0},
	} {
		m := NewModeTracker()
		for _, p := range tc.out {
			_, _ = m.Write([]byte(p))
		}
		require.Equal(t, tc.want, m.RawC1(), "%q", tc.out)
	}

	m := NewModeTracker()
	_, _ = m.Write([]byte("\x84\xe2"))
	c := m.Clone()
	require.Zero(t, c.RawC1(), "the original's, written before the clone")
	_, _ = c.Write([]byte("\x96\x88"))
	require.Zero(t, c.RawC1(), "the rest of the original's character")
	_, _ = c.Write([]byte("\x8d"))
	require.Equal(t, byte(0x8d), c.RawC1())
	require.Equal(t, byte(0x84), m.RawC1())
}

// A control character inside an ESC sequence is executed where it stands,
// and the sequence goes on waiting for its final byte, as a DEC parser has
// it. The tracker's own bookkeeping drops the sequence there, but the
// terminal hasn't.
func TestInSequenceWaitsPastAControlInsideAnEscape(t *testing.T) {
	for _, partial := range []string{"\x1b\r", "\x1b\x07", "\x1b\x7f", "\x1b(\x7f", "\x1b(\r", "\x1b\r(", "\x1b\r\n", "\x1b]0;t\x1b\r\x07"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(partial))
		require.True(t, m.InSequence(), "%q", partial)
	}
	for _, whole := range []string{"\x1b\rB", "\x1b(\x7fB", "\x1b(\n0", "\x1b\r\x18", "\x1b\r\x1a"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(whole))
		require.False(t, m.InSequence(), "%q", whole)
	}
}

// Text written while G0 is DEC Special Graphics, or while a shift-out has put
// G1 in use, is drawn as line pieces: "upterm" comes out as box corners until
// the program designates ASCII again or shifts back in.
func TestNonASCIICharsetIsWhileTextIsntDrawnAsASCII(t *testing.T) {
	for _, in := range []string{"\x1b(0", "\x1b(A", "\x0e", "\x1b(B\x0e", "\x1b[1\x0e", "\x1b(0\x1b[!p", "\x0e\x1b[!p"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.True(t, m.NonASCIICharset(), "%q", in)
	}
	for _, in := range []string{"plain", "\x1b(B", "\x1b(0\x1b(B", "\x0e\x0f", "\x1b(0\x1bc", "\x0e\x1bc", "\x1b]0;\x0e\x07"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.False(t, m.NonASCIICharset(), "%q", in)
	}
}

// A string the program ended ambiguously -- by CAN, SUB or an ESC that isn't
// ST -- is one terminals disagree about. The tracker reads it as over; kitty,
// and tmux for a DCS, keep it open and take what follows as more of it,
// ignoring an SI there. So an SI inside that window does not put G0 back as
// far as NonASCIICharset can tell: the shift-out stays, and with it the
// status that would be drawn through G1 as graphics once ST ends the string.
// An SO there may still set it, and an SI outside the window clears it.
func TestShiftOutSurvivesAShiftInInsideAnAmbiguouslyEndedString(t *testing.T) {
	for _, tc := range []struct{ name, ambiguous string }{
		{"an ESC that isn't ST", "\x1b]0;t\x1b\x0f"},
		{"CAN", "\x1b]0;t\x18\x0f"},
		{"SUB", "\x1b]0;t\x1a\x0f"},
		{"a DCS", "\x1bPq\x1b\x0f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, _ = m.Write([]byte("\x0e" + tc.ambiguous))
			require.True(t, m.InSequence(), "the string is still open")
			require.True(t, m.NonASCIICharset(), "the SI inside it is the string's")

			_, _ = m.Write([]byte("\x1b\\"))
			require.False(t, m.InSequence(), "ST ends the string")
			require.True(t, m.NonASCIICharset(), "G1 is still in use")

			_, _ = m.Write([]byte("\x0f"))
			require.False(t, m.NonASCIICharset(), "an SI outside the string puts G0 back")
		})
	}

	m := NewModeTracker()
	_, _ = m.Write([]byte("\x0e\x0f"))
	require.False(t, m.NonASCIICharset(), "an SI outside any string")

	m = NewModeTracker()
	_, _ = m.Write([]byte("\x1b]0;t\x1b\x0e\x1b\\"))
	require.False(t, m.InSequence())
	require.True(t, m.NonASCIICharset(), "an SO inside the window still shifts out")
}

// The same holds for everything else a DEC parser takes as putting ASCII
// back: a RIS, a DECSTR or an ESC ( B inside an ambiguously ended string is
// the string's on a terminal that keeps it open, so the graphics are still
// there once ST ends it, and NonASCIICharset keeps saying so. Outside any
// such string a RIS, an SI or an ESC ( B puts ASCII back, as it does on every
// terminal; a DECSTR doesn't anywhere, since tmux ignores it.
func TestNothingInsideAnAmbiguouslyEndedStringPutsASCIIBack(t *testing.T) {
	for _, tc := range []struct{ name, graphics, inside string }{
		{"a RIS after a shift-out", "\x0e", "\x1bc"},
		{"a DECSTR after a shift-out", "\x0e", "\x1b[!p"},
		{"a RIS after CAN, after a shift-out", "\x0e", "\x18\x1bc"},
		{"a RIS after a graphics G0", "\x1b(0", "\x1bc"},
		{"a DECSTR after a graphics G0", "\x1b(0", "\x1b[!p"},
		{"an ESC ( B after a graphics G0", "\x1b(0", "\x1b(B"},
		{"an ESC ( B after SUB, after a graphics G0", "\x1b(0", "\x1a\x1b(B"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModeTracker()
			_, _ = m.Write([]byte(tc.graphics + "\x1b]0;t" + tc.inside))
			require.True(t, m.InSequence(), "the string is still open")
			require.True(t, m.NonASCIICharset(), "what puts ASCII back is the string's")

			_, _ = m.Write([]byte("\x1b\\"))
			require.False(t, m.InSequence(), "ST ends the string")
			require.True(t, m.NonASCIICharset(), "the graphics are still in use")
		})
	}

	for _, in := range []string{"\x0e\x1bc", "\x0e\x0f", "\x1b(0\x1bc", "\x1b(0\x1b(B",
		"\x0e\x1b]0;t\x1bc\x1b\\\x0f", "\x1b(0\x1b]0;t\x1b(B\x1b\\\x1b(B"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.False(t, m.NonASCIICharset(), "outside any string: %q", in)
	}
	for _, in := range []string{"\x0e\x1b[!p", "\x1b(0\x1b[!p"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.True(t, m.NonASCIICharset(), "a DECSTR, outside any string: %q", in)
	}
}

// G2 and G3 are character sets too: a program can designate graphics into
// G2 (ESC * 0) and invoke it into GL with LS2 (ESC n), or G3 with LS3 (ESC o),
// and text is drawn from them until an SI puts G0 back. What G1 to G3 hold
// isn't tracked, so NonASCIICharset takes any of them as not ASCII. A single
// shift, SS2 (ESC N) or SS3 (ESC O), draws just the next character from G2 or
// G3, which leaves the output unsafe until that character has come. The
// locking shifts into GR (ESC ~, ESC }, ESC |) reach only 8-bit bytes, which a
// UTF-8 terminal doesn't read that way.
func TestAShiftToG2OrG3IsNotASCII(t *testing.T) {
	m := NewModeTracker()
	_, _ = m.Write([]byte("\x1b*0\x1bn"))
	require.True(t, m.NonASCIICharset(), "G2 in GL")
	require.False(t, m.InSequence())
	_, _ = m.Write([]byte("\x0f"))
	require.False(t, m.NonASCIICharset(), "an SI puts G0 back")
	_, _ = m.Write([]byte("\x1bo"))
	require.True(t, m.NonASCIICharset(), "G3 in GL")
	_, _ = m.Write([]byte("\x0f"))
	require.False(t, m.NonASCIICharset())

	for _, in := range []string{"\x1bn", "\x1bo", "\x0e\x1bn", "\x1bn\x1b(B", "\x1bn\x1b[!p",
		"\x1bn\x1b]0;t\x1bc\x1b\\", "\x1bo\x1b]0;t\x1b[!p\x1b\\", "\x1bn\x1b]0;t\x1b\x0f\x1b\\"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.True(t, m.NonASCIICharset(), "%q", in)
	}
	for _, in := range []string{"\x1bn\x0f", "\x1bo\x1bc", "\x1b~", "\x1b}", "\x1b|", "\x1b]0;n\x07"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.False(t, m.NonASCIICharset(), "%q", in)
	}

	for _, shift := range []string{"\x1bN", "\x1bO"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(shift))
		require.True(t, m.InSequence(), "%q waits for its character", shift)
		_, _ = m.Write([]byte("\r"))
		require.True(t, m.InSequence(), "%q: a control character draws nothing", shift)
		_, _ = m.Write([]byte("x"))
		require.False(t, m.InSequence(), "%q: its character has come", shift)
		require.False(t, m.NonASCIICharset(), "%q shifts nothing in for longer", shift)
	}
}

// A G0 designation is ASCII only as ESC ( B exactly. Everything else
// designated into G0 is taken as a set other than ASCII, cautiously: one
// with an intermediate of its own (ESC ( % 5, DEC Supplemental), a multibyte
// one (ESC $ B, ESC $ ( B), one with a control executed inside it, and any
// other final. A designation into G1 to G3 leaves G0 as it was, and putting
// ASCII back waits for the end of an ambiguously ended string as before.
func TestEveryG0DesignationButESCParenBIsNotASCII(t *testing.T) {
	for _, in := range []string{"\x1b(%5", "\x1b$B", "\x1b$@", "\x1b$(B", "\x1b$(D", "\x1b(\n0", "\x1b\r(0", "\x1b(\rB",
		"\x1b(%5\x1b]0;t\x1b(B\x1b\\", "\x1b$(B\x1b[!p"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.True(t, m.NonASCIICharset(), "%q", in)
	}
	for _, in := range []string{"\x1b(B", "\x1b$)B", "\x1b)%5", "\x1b*%5", "\x1b(%5\x1b(B", "\x1b$B\x1bc"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.False(t, m.NonASCIICharset(), "%q", in)
	}
}

// A control character inside an ESC sequence is executed there, and the
// sequence goes on to its final byte, as a DEC parser has it: ESC CR n is LS2
// as ESC n is, and so for LS3 and the single shifts. A RIS with a control
// inside it doesn't put ASCII back, though: kitty abandons the ESC at the
// control, and only a bare RIS outside an ambiguously ended string is one
// every terminal takes.
func TestAShiftPastAnExecutedControlStillShifts(t *testing.T) {
	for _, in := range []string{"\x1b*0\x1b\rn", "\x1b\x7fo", "\x1b\r\nn", "\x1b]0;t\x1b\rn\x1b\\", "\x0e\x1b]0;t\x1b\rc\x1b\\",
		"\x0e\x1b\rc", "\x1b(0\x1b\x7fc", "\x1bn\x1b\rc"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.True(t, m.NonASCIICharset(), "%q", in)
	}
	for _, in := range []string{"\x1b \rn", "\x1bn\x1bc"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.False(t, m.NonASCIICharset(), "%q", in)
	}
	for _, shift := range []string{"\x1b\rN", "\x1b\x7fO"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(shift))
		require.True(t, m.InSequence(), "%q waits for its character", shift)
		_, _ = m.Write([]byte("x"))
		require.False(t, m.InSequence(), "%q: its character has come", shift)
	}
}

// After ESC and controls executed inside it, a "[" begins a CSI on a DEC
// parser, and "]", "P", "X", "^" or "_" an OSC, DCS, SOS, PM or APC string,
// though the tracker's own parser dropped the sequence at the control. The
// output is in a sequence until that CSI's final byte, or until the string's
// terminator, ST or BEL for an OSC, with a string ended ambiguously -- by
// CAN, SUB or an ESC that isn't ST -- still open until then, as any string
// is. An intermediate before the "[" makes it an ESC sequence's final byte
// instead.
func TestASequenceBegunPastAnExecutedControlIsFollowed(t *testing.T) {
	for _, tc := range []struct{ inside, out string }{
		{"\x1b\n[?1000", "l"},
		{"\x1b\r\n[1;2", "H"},
		{"\x1b\n]0;t", "\x07"},
		{"\x1b\n]0;t", "\x1b\\"},
		{"\x1b\rPq", "\x1b\\"},
		{"\x1b\rPq\x07", "\x1b\\"},
		{"\x1b\r_x", "\x1b\\"},
		{"\x1b\r]0;t\x18", "\x07"},
		{"\x1b\r]0;t\x1b[m", "\x1b\\"},
	} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(tc.inside))
		require.True(t, m.InSequence(), "%q", tc.inside)
		_, _ = m.Write([]byte(tc.out))
		require.False(t, m.InSequence(), "%q", tc.inside+tc.out)
	}
	for _, in := range []string{"\x1b\r[?10\x18", "\x1b\r[?10\x1a", "\x1b\r[?10\x1b[m", "\x1b \r[", "\x1b\r[?1000\x0fl"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.False(t, m.InSequence(), "%q", in)
	}

	// Inside such a string an SI is the string's, as it is in any other.
	m := NewModeTracker()
	_, _ = m.Write([]byte("\x0e\x1b\r]0;\x0f\x07"))
	require.True(t, m.NonASCIICharset())

	// Begun inside a DCS a terminal may still hold open, an OSC that BEL ends
	// doesn't end the DCS: only ST does.
	m = NewModeTracker()
	_, _ = m.Write([]byte("\x1bPq\x18\x1b\r]0;t\x07"))
	require.True(t, m.InSequence(), "the DCS may still be open")
	_, _ = m.Write([]byte("\x1b\\"))
	require.False(t, m.InSequence())
}

// tmux's passthrough wraps a sequence meant for the outer terminal in a DCS,
// with every ESC inside it doubled: ESC P tmux ; ... ESC ESC \ ... ESC \.
// There ESC ESC is an escaped ESC, so the backslash after it ends nothing, and
// the DCS is open until an ESC \ whose ESC isn't the second of a pair. An OSC
// inside it doesn't make it one a BEL ends.
func TestTmuxPassthroughIsOpenUntilItsOwnST(t *testing.T) {
	m := NewModeTracker()
	_, _ = m.Write([]byte("\x1bPtmux;\x1b\x1b]52;c;x\x1b\x1b\\"))
	require.True(t, m.InSequence(), "the inner ST is an escaped ESC and a backslash")
	_, _ = m.Write([]byte("\x07"))
	require.True(t, m.InSequence(), "the DCS is still the window, which no BEL ends")
	_, _ = m.Write([]byte("\x1b\\"))
	require.False(t, m.InSequence(), "the passthrough's own ST")

	m = NewModeTracker()
	_, _ = m.Write([]byte("\x1bPtmux;\x1b\x1b\x1b\\"))
	require.False(t, m.InSequence(), "an escaped ESC, then ST")
}

// A window only ST ends -- a DCS, SOS, PM or APC left open -- stays one when
// a string begun inside it is ended ambiguously too, an OSC included: the
// BEL that would end the OSC doesn't end the string around it.
func TestAWindowOnlySTEndsIsNeverTakenForAnOSCs(t *testing.T) {
	for _, in := range []string{"\x1bPq\x18\x1b]0;t\x18\x07", "\x1bPq\x1b\x1b]0;t\x1b[m\x07", "\x1b_x\x1a\x1b]0;t\x1a\x07", "\x1bPq\x18\x1bk\x07"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.True(t, m.InSequence(), "%q: still in the first string at the BEL", in)
		_, _ = m.Write([]byte("\x1b\\"))
		require.False(t, m.InSequence(), "%q: ST ends it", in)
	}
}

// ESC k begins a window title on tmux and GNU screen, a string only ST ends,
// which oh-my-zsh sends at every prompt under TERM=screen* or tmux*. The
// parser takes it as an ESC sequence done at the k, so the watch opens it
// itself: straight after ESC, after a string's ESC, and past executed
// controls. With an intermediate before it, the k is that sequence's final
// byte instead.
func TestATitleStringIsOpenUntilST(t *testing.T) {
	for _, in := range []string{"\x1bktitle", "\x1bktitle\x07", "\x1b]0;t\x1bktitle\x07", "\x1b\rktitle"} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.True(t, m.InSequence(), "%q", in)
		_, _ = m.Write([]byte("\x1b\\"))
		require.False(t, m.InSequence(), "%q, then ST", in)
	}
	m := NewModeTracker()
	_, _ = m.Write([]byte("\x1b k"))
	require.False(t, m.InSequence())
}

// A cursor save -- ESC 7, a plain CSI s, or 1048 or 1049 set -- saves the
// character sets too, and its restore -- ESC 8, a plain CSI u, or 1048 or 1049
// reset -- puts them back. The watch keeps a copy of its own of what was
// saved, and a restore from it only ever raises what NonASCIICharset says,
// never lowers it. Outside an ambiguously ended string a save replaces the
// copy; inside one, past a control, or on the alternate screen, it merges
// with it, not ASCII if either is; and a RIS outside one clears it. The
// alternate screen's save merges because a terminal keeps a saved cursor per
// screen, and 1049 reset restores the main screen's, which the copy, one for
// both, has to cover. A CSI begun past a control has parameters the watch
// doesn't read, so one ending in s or h is taken as a save, merged, and one
// ending in u or l as a restore.
func TestARestoredCharsetIsNeverTakenAsLower(t *testing.T) {
	for _, in := range []string{
		"\x1b(0\x1b7\x1b(B\x1b8",
		"\x1b(0\x1b[s\x1b(B\x1b[u",
		"\x1b(0\x1b[?1049h\x1b(B\x1b[?1049l",
		"\x1b(0\x1b[?1049h\x1b(B\x1b7\x1b[?1049l",
		"\x1b(0\x1b[?1048h\x1b(B\x1b[?1048l",
		"\x1b(0\x1b[?25;1049h\x1b(B\x1b[?1049;25l",
		"\x0e\x1b7\x0f\x1b8",
		"\x1b7\x1b(0\x1b8",
		"\x1b(0\x1b7\x1b(B\x1b]0;t\x1b7\x1b\\\x1b8",
		"\x1b(0\x1b7\x1b(B\x1b\n7\x1b8",
		"\x1b(0\x1b7\x1b(B\x1b]0;t\x1bc\x1b\\\x1b8",
		"\x1b(0\x1b7\x1b(B\x1b\rc\x1b8",
		"\x1b(0\x1b\r[s\x1b(B\x1b\r[u",
		"\x1b(0\x1b\r[?1049h\x1b(B\x1b\r[?1049l",
	} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.True(t, m.NonASCIICharset(), "%q", in)
	}
	for _, in := range []string{
		"\x1b7\x1b(0\x1b(B\x1b8",
		"\x1b(0\x1b7\x1b(B\x1b7\x1b8",
		"\x1b(0\x1b7\x1bc\x1b8",
		"\x1b(0\x1b[1;2s\x1b(B\x1b[u",
		"\x1b(0\x1b7\x1b(B\x1b[>1u",
		"\x1b(0\x1b7\x1b(B\x1b[?1047l",
		"\x1b(0\x1b[?1049h\x1b(B",
	} {
		m := NewModeTracker()
		_, _ = m.Write([]byte(in))
		require.False(t, m.NonASCIICharset(), "%q", in)
	}
}
