package io

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminalQueryFilter(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "regular text passes through",
			input:    []byte("hello world"),
			expected: []byte("hello world"),
		},
		{
			name:     "filters OSC 11 query with BEL",
			input:    []byte("\x1b]11;?\x07"),
			expected: nil,
		},
		{
			name:     "filters OSC 11 query with ST",
			input:    []byte("\x1b]11;?\x1b\\"),
			expected: nil,
		},
		{
			name:     "filters OSC 10 query (foreground color)",
			input:    []byte("\x1b]10;?\x07"),
			expected: nil,
		},
		{
			name:     "filters OSC 12 query (cursor color)",
			input:    []byte("\x1b]12;?\x07"),
			expected: nil,
		},
		{
			name:     "filters OSC 4 palette query",
			input:    []byte("\x1b]4;1;?\x07"),
			expected: nil,
		},
		{
			name:     "passes OSC set (not query)",
			input:    []byte("\x1b]11;rgb:ff/ff/ff\x07"),
			expected: []byte("\x1b]11;rgb:ff/ff/ff\x07"),
		},
		{
			name:     "filters CSI 6 n (cursor position request)",
			input:    []byte("\x1b[6n"),
			expected: nil,
		},
		{
			name:     "filters CSI 5 n (device status request)",
			input:    []byte("\x1b[5n"),
			expected: nil,
		},
		{
			name:     "filters CSI c (primary device attributes)",
			input:    []byte("\x1b[c"),
			expected: nil,
		},
		{
			name:     "filters CSI 0 c (primary device attributes)",
			input:    []byte("\x1b[0c"),
			expected: nil,
		},
		{
			name:     "filters CSI > c (secondary device attributes)",
			input:    []byte("\x1b[>c"),
			expected: nil,
		},
		{
			name:     "filters CSI > 0 c (secondary device attributes)",
			input:    []byte("\x1b[>0c"),
			expected: nil,
		},
		{
			name:     "filters terminal version query",
			input:    []byte("\x1b[>q"),
			expected: nil,
		},
		{
			name:     "filters terminal version query with explicit default",
			input:    []byte("\x1b[>0q"),
			expected: nil,
		},
		{
			name:     "passes cursor style and LED controls",
			input:    []byte("\x1b[0 q\x1b[5 q\x1b[0q\x1b[1q"),
			expected: []byte("\x1b[0 q\x1b[5 q\x1b[0q\x1b[1q"),
		},
		{
			name:     "passes regular CSI sequences",
			input:    []byte("\x1b[2J"), // clear screen
			expected: []byte("\x1b[2J"),
		},
		{
			name:     "filters text area size query in pixels",
			input:    []byte("\x1b[14t"),
			expected: nil,
		},
		{
			name:     "filters text area size query in characters",
			input:    []byte("\x1b[18t"),
			expected: nil,
		},
		{
			name:     "passes window resize and title stack operations",
			input:    []byte("\x1b[8;24;80t\x1b[22;0;0t\x1b[23;0;0t"),
			expected: []byte("\x1b[8;24;80t\x1b[22;0;0t\x1b[23;0;0t"),
		},
		{
			name:     "passes cursor movement",
			input:    []byte("\x1b[10;20H"),
			expected: []byte("\x1b[10;20H"),
		},
		{
			name:     "passes SGR (colors/styles)",
			input:    []byte("\x1b[1;32m"),
			expected: []byte("\x1b[1;32m"),
		},
		{
			name:     "mixed content with query in middle",
			input:    []byte("before\x1b[6nafter"),
			expected: []byte("beforeafter"),
		},
		{
			name:     "multiple queries filtered",
			input:    []byte("\x1b]11;?\x07\x1b[6n"),
			expected: nil,
		},
		{
			name:     "query followed by regular output",
			input:    []byte("\x1b[6nhello"),
			expected: []byte("hello"),
		},
		{
			name:     "lone ESC passes through",
			input:    []byte{0x1b, 'a'},
			expected: []byte{0x1b, 'a'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			var buf bytes.Buffer
			filter := NewTerminalQueryFilter(&buf)

			n, err := filter.Write(tt.input)
			assert.NoError(err)
			assert.Equal(len(tt.input), n)
			assert.Equal(tt.expected, buf.Bytes())
		})
	}
}

func TestTerminalQueryFilter_PreservesNonQueryOSC(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "OSC 0 set window title with BEL",
			input:    []byte("\x1b]0;My Title\x07"),
			expected: []byte("\x1b]0;My Title\x07"),
		},
		{
			name:     "OSC 0 set window title with ST",
			input:    []byte("\x1b]0;My Title\x1b\\"),
			expected: []byte("\x1b]0;My Title\x1b\\"),
		},
		{
			name:     "OSC 11 set color (not query)",
			input:    []byte("\x1b]11;rgb:ff/ff/ff\x07"),
			expected: []byte("\x1b]11;rgb:ff/ff/ff\x07"),
		},
		{
			name:     "OSC 52 clipboard (not filtered)",
			input:    []byte("\x1b]52;c;SGVsbG8=\x07"),
			expected: []byte("\x1b]52;c;SGVsbG8=\x07"),
		},
		{
			name:     "OSC 777 notification",
			input:    []byte("\x1b]777;notify;Title;Body\x07"),
			expected: []byte("\x1b]777;notify;Title;Body\x07"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			var buf bytes.Buffer
			filter := NewTerminalQueryFilter(&buf)

			n, err := filter.Write(tt.input)
			assert.NoError(err)
			assert.Equal(len(tt.input), n)
			assert.Equal(tt.expected, buf.Bytes())
		})
	}
}

// An ESC inside an OSC ends the string whatever follows it; only a backslash
// makes it the ST that ends it cleanly. The filter used to keep swallowing
// content across the ESC, so an unterminated title followed by a cursor
// position request reached every joiner whole -- and every joiner's terminal
// answered the request into the shared pty, which is the one thing this filter
// exists to prevent.
//
// An OSC that ends at such an ESC is dropped, not passed, query or not, since
// kitty keeps it open past the ESC. Passed, it was glued to whatever
// followed the dropped query: "ESC ]11;? ESC [6n BEL" came out as
// "ESC ]11;? BEL", a complete colour query.
func TestTerminalQueryFilter_ESCInsideAnOSCEndsIt(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "ESC not followed by backslash ends the OSC, and the query after it is filtered",
			input:    []byte("\x1b]0;t\x1b[6n\x07"),
			expected: []byte("\x07"),
		},
		{
			name:     "ESC followed by backslash is still ST",
			input:    []byte("\x1b]0;t\x1b\\"),
			expected: []byte("\x1b]0;t\x1b\\"),
		},
		{
			name:     "the same inside an OSC colour query",
			input:    []byte("\x1b]11;?\x1b[6n\x07"),
			expected: []byte("\x07"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			filter := NewTerminalQueryFilter(&buf)

			n, err := filter.Write(tt.input)
			require.NoError(t, err)
			require.Equal(t, len(tt.input), n)
			require.Equal(t, tt.expected, buf.Bytes())
		})
	}
}

// "ESC ] 0 ; BEL" is how a shell clears its title, and an empty payload ends
// at its terminator like any other. The filter took the byte after the ";" as
// the payload's first byte whatever it was, so the BEL never closed the string
// and whatever the command printed next was held -- up to the content bound
// -- until another BEL or an ESC came along: a prompt that cleared its title
// stalled every joiner until the bound filled or a later escape sequence let
// the text through. "ESC ] 0 ; ESC \" went the same way, with the ESC as
// content and the ST never seen as one.
func TestTerminalQueryFilter_EmptyOSCEndsAtItsTerminator(t *testing.T) {
	tests := []struct {
		name     string
		writes   [][]byte
		expected []byte
	}{
		{
			name:     "BEL ends it, and the text after it in the same write goes out with it",
			writes:   [][]byte{[]byte("\x1b]0;\x07hello")},
			expected: []byte("\x1b]0;\x07hello"),
		},
		{
			name:     "BEL ends it, and a later write is not held behind it",
			writes:   [][]byte{[]byte("\x1b]0;\x07"), []byte("hello")},
			expected: []byte("\x1b]0;\x07hello"),
		},
		{
			name:     "ST ends it",
			writes:   [][]byte{[]byte("\x1b]0;\x1b\\hello")},
			expected: []byte("\x1b]0;\x1b\\hello"),
		},
		{
			name:     "a ? after the ; still passes through whole",
			writes:   [][]byte{[]byte("\x1b]0;?\x07hello")},
			expected: []byte("\x1b]0;?\x07hello"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			filter := NewTerminalQueryFilter(&buf)

			for _, w := range tt.writes {
				n, err := filter.Write(w)
				require.NoError(t, err)
				require.Equal(t, len(w), n)
			}
			require.Equal(t, tt.expected, buf.Bytes())
		})
	}
}

func TestTerminalQueryFilter_SplitWrites(t *testing.T) {
	tests := []struct {
		name     string
		writes   [][]byte
		expected []byte
	}{
		{
			name:     "OSC query split at ESC",
			writes:   [][]byte{{0x1b}, {']', '1', '1', ';', '?', 0x07}},
			expected: nil,
		},
		{
			name:     "OSC query split at semicolon",
			writes:   [][]byte{{0x1b, ']', '1', '1', ';'}, {'?', 0x07}},
			expected: nil,
		},
		{
			name:     "CSI query split at ESC",
			writes:   [][]byte{{0x1b}, {'[', '6', 'n'}},
			expected: nil,
		},
		{
			name:     "CSI query split mid-sequence",
			writes:   [][]byte{{0x1b, '['}, {'6', 'n'}},
			expected: nil,
		},
		{
			name:     "tmux size queries split across writes",
			writes:   [][]byte{[]byte("before\x1b[1"), []byte("8t\x1b"), []byte("[14"), []byte("tafter")},
			expected: []byte("beforeafter"),
		},
		{
			name:     "tmux version queries split across writes",
			writes:   [][]byte{[]byte("before\x1b[>"), []byte("q\x1b"), []byte("[>0"), []byte("qafter")},
			expected: []byte("beforeafter"),
		},
		{
			name:     "non-query OSC split across writes",
			writes:   [][]byte{{0x1b, ']', '0', ';'}, {'T', 'i', 't', 'l', 'e', 0x07}},
			expected: []byte("\x1b]0;Title\x07"),
		},
		{
			name:     "text with query in middle, split",
			writes:   [][]byte{{'h', 'e', 'l', 'l', 'o', 0x1b}, {'[', '6', 'n', 'w', 'o', 'r', 'l', 'd'}},
			expected: []byte("helloworld"),
		},
		{
			name:     "incomplete sequence at end of write",
			writes:   [][]byte{{'h', 'i', 0x1b}},
			expected: []byte("hi"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			var buf bytes.Buffer
			filter := NewTerminalQueryFilter(&buf)

			for _, w := range tt.writes {
				n, err := filter.Write(w)
				assert.NoError(err)
				assert.Equal(len(w), n)
			}

			assert.Equal(tt.expected, buf.Bytes())
		})
	}
}

func TestTerminalQueryFilter_TertiaryDeviceAttributes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "CSI = c (tertiary device attributes)",
			input:    []byte("\x1b[=c"),
			expected: nil,
		},
		{
			name:     "CSI = 0 c (tertiary device attributes)",
			input:    []byte("\x1b[=0c"),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			var buf bytes.Buffer
			filter := NewTerminalQueryFilter(&buf)

			n, err := filter.Write(tt.input)
			assert.NoError(err)
			assert.Equal(len(tt.input), n)
			assert.Equal(tt.expected, buf.Bytes())
		})
	}
}

// The OSC number guard only tripped once oscCmd passed 99, and a run of zeros
// never raises it, so "ESC ]" followed by zeros accumulated forever: the bytes
// were held out of the replay ring and handed whole to every joining writer.
func TestTerminalQueryFilter_OSCNumberIsBounded(t *testing.T) {
	var buf bytes.Buffer
	filter := NewTerminalQueryFilter(&buf)

	input := append([]byte("\x1b]"), bytes.Repeat([]byte("0"), 2048)...)
	for i, b := range input {
		n, err := filter.Write([]byte{b})
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.LessOrEqual(t, len(filter.Pending()), 9, "after byte %d", i)
	}

	// None of it is a query, so all of it reaches the writer.
	require.Equal(t, string(input), buf.String())
}

// Pending is replayed to every joiner after the ring, so whatever the
// filter is holding has to stay small whatever the stream does.
func TestTerminalQueryFilter_PendingNeverExceedsTheBound(t *testing.T) {
	const runLength = 2048

	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "CSI parameters",
			input: append([]byte("\x1b["), bytes.Repeat([]byte("1;"), runLength)...),
		},
		{
			name:  "OSC content",
			input: append([]byte("\x1b]0;"), bytes.Repeat([]byte("x"), runLength)...),
		},
		{
			name:  "OSC content of escapes",
			input: append([]byte("\x1b]0;"), bytes.Repeat([]byte{0x1b}, runLength)...),
		},
		{
			name:  "OSC query",
			input: append([]byte("\x1b]11;?"), bytes.Repeat([]byte("?"), runLength)...),
		},
		{
			name:  "OSC number",
			input: append([]byte("\x1b]"), bytes.Repeat([]byte("0"), runLength)...),
		},
		{
			name:  "ESC intermediates",
			input: append([]byte("\x1b"), bytes.Repeat([]byte(" "), runLength)...),
		},
		{
			name:  "CSI intermediates",
			input: append([]byte("\x1b[1"), bytes.Repeat([]byte("$"), runLength)...),
		},
		{
			name:  "OSC 4 run",
			input: append([]byte("\x1b]4;"), bytes.Repeat([]byte("0;?;"), runLength)...),
		},
		{
			name:  "passed DCS payload",
			input: append([]byte("\x1bPq"), bytes.Repeat([]byte("#0"), runLength)...),
		},
		{
			name:  "APC payload",
			input: append([]byte("\x1b_G"), bytes.Repeat([]byte("a"), runLength)...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			filter := NewTerminalQueryFilter(&buf)

			for i, b := range tt.input {
				_, err := filter.Write([]byte{b})
				require.NoError(t, err)
				require.LessOrEqual(t, len(filter.Pending()), maxPendingBytes,
					"after byte %d", i)
			}
		})
	}
}

// maxPendingBytes is computed, not remembered: the largest any state holds
// under the bounds, plus the one ESC that Pending adds beyond it, which a held
// OSC keeps to see whether a backslash follows. Both halves are checked, the
// sum from the bound constants and the hold from the filter itself, so raising
// a bound without the constant fails here, and so does a constant larger than
// anything the filter ever holds.
func TestTerminalQueryFilter_MaxPendingBytesIsTheLargestHold(t *testing.T) {
	largest := max(maxEscHeld, maxCSIHeld, maxOSCNumHeld, maxOSCHeld)
	require.Equal(t, largest+1, maxPendingBytes, "the largest hold, plus one held ESC")

	// PR 1: 256 (the largest hold, an OSC with framing) + 1 held ESC. PR 2
	// raises it to 259 for a wrapper's re-encoded inner ESCs. If the bounds
	// change, change both this and the constant's comment.
	require.Equal(t, 257, maxPendingBytes)

	// The filter really does reach it: an OSC held to its bound, then an ESC.
	// One more payload byte instead would have given the OSC up.
	head := "\x1b]0;"
	var out bytes.Buffer
	f := NewTerminalQueryFilter(&out)
	_, _ = f.Write([]byte(head + strings.Repeat("t", maxOSCHeld-len(head))))
	require.Len(t, f.Pending(), maxOSCHeld, "an OSC held to its bound")
	_, _ = f.Write([]byte("\x1b"))
	require.Len(t, f.Pending(), maxPendingBytes, "and the ESC that may begin its ST")
	require.Empty(t, out.String(), "nothing of it has gone out")

	var gaveUp bytes.Buffer
	g := NewTerminalQueryFilter(&gaveUp)
	_, _ = g.Write([]byte(head + strings.Repeat("t", maxOSCHeld-len(head)+1)))
	require.Empty(t, g.Pending(), "one byte past the bound, the OSC is given up on")
	require.Len(t, gaveUp.String(), maxOSCHeld+1, "and goes out")
}

// errWriter is a writer that always returns an error
type errWriter struct {
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	return 0, e.err
}

func TestTerminalQueryFilter_ErrorHandling(t *testing.T) {
	assert := assert.New(t)

	expectedErr := errors.New("write error")
	w := &errWriter{err: expectedErr}
	filter := NewTerminalQueryFilter(w)

	// Write some data that will produce output (not filtered)
	n, err := filter.Write([]byte("hello"))
	assert.Equal(0, n)
	assert.Equal(expectedErr, err)
}

func TestTerminalQueryFilter_ErrorNotReturnedForFilteredContent(t *testing.T) {
	assert := assert.New(t)

	expectedErr := errors.New("write error")
	w := &errWriter{err: expectedErr}
	filter := NewTerminalQueryFilter(w)

	// Write a query that will be filtered (no output, so no error)
	n, err := filter.Write([]byte("\x1b[6n"))
	assert.Equal(4, n)
	assert.NoError(err) // No error because nothing was written to underlying writer
}

// CAN and SUB cancel a sequence from any state on the DEC parser terminals
// implement. A filter holding a head -- a query still arriving -- passes it
// straight through with the cancel, and the terminal discards it. A held OSC
// is dropped instead, and only the cancel goes out: kitty would keep the
// string open past the cancel. Holding on kept the cancel from the terminal:
// the reset a session sends a guest last is a lone CAN when all the session
// left open was a sequence, and nothing after it ever pushed it out.
func TestTerminalQueryFilter_CancelEndsAHeldSequence(t *testing.T) {
	for _, cancel := range []string{"\x18", "\x1a"} {
		for _, tc := range []struct {
			name string
			held string
			out  string // what goes out ahead of the cancel
		}{
			{name: "an OSC", held: "\x1b]0;a title", out: ""},
			{name: "an OSC colour query", held: "\x1b]10;?", out: ""},
			{name: "a CSI query", held: "\x1b[6", out: "\x1b[6"},
			{name: "an ESC", held: "\x1b", out: "\x1b"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var out bytes.Buffer
				f := NewTerminalQueryFilter(&out)
				_, err := f.Write([]byte(tc.held))
				require.NoError(t, err)
				require.Empty(t, out.String(), "held until it ends")

				// On its own, as a reset is when nothing but the sequence
				// was left open: nothing after it would push it out.
				_, err = f.Write([]byte(cancel))
				require.NoError(t, err)
				require.Equal(t, tc.out+cancel, out.String())
				require.Empty(t, f.Pending())

				_, err = f.Write([]byte("\x1b[?2004l"))
				require.NoError(t, err)
				require.Equal(t, tc.out+cancel+"\x1b[?2004l", out.String())
			})
		}
	}
}

type filterCase struct {
	name     string
	in, want string
	kitty    bool // also assert no query under refKitty (refParse on want)
}

// filterCases is every exact-bytes case: escCSICases and oscStringCases, with
// the rows init() generates from the classifier tests' examples. The split,
// continuation and oracle tests range over it, and it seeds the fuzz test.
var filterCases []filterCase

// filterAll runs in through a fresh filter in one Write and returns what it
// emitted.
func filterAll(in string) string {
	var out bytes.Buffer
	_, _ = NewTerminalQueryFilter(&out).Write([]byte(in))
	return out.String()
}

// filterBytewise is filterAll with one Write per byte, so every state has to
// carry across a write boundary.
func filterBytewise(in string) string {
	var out bytes.Buffer
	f := NewTerminalQueryFilter(&out)
	for i := range len(in) {
		_, _ = f.Write([]byte{in[i]})
	}
	return out.String()
}

// The ESC and CSI grammar: restarts, control bytes inside a head, the bounds,
// and the close an emitted, unfinished head is owed when what follows it is
// dropped.
var escCSICases = []filterCase{
	// Generated in init() from query_classify_test.go's examples, not copied
	// out: every entry of csiQueryExamples and "\x1bZ", wrapped as "a"+q+"b",
	// wants "ab"; every csiPassExamples entry wants itself.
	{name: "counter-cases pass", in: "\x1b[?6c\x1b7\x1b8\x1b(B\x1b[>4n\x1b[0n\x1b[!p\x1b[61\"p\x1b[?2026h\x1b[2 q\x1b[1q\x1b[8;24;80t\x1b[22;0t\x1b[>0t\x1b[>4;2m\x1b[38:2::255:0:0m\x1b[3S\x1b[>1u\x1b[<u\x1b[=1;1u\x1b[u\x1b[2*x\x1b[#{\x1b[132$|\x1b[1#Q",
		want: "\x1b[?6c\x1b7\x1b8\x1b(B\x1b[>4n\x1b[0n\x1b[!p\x1b[61\"p\x1b[?2026h\x1b[2 q\x1b[1q\x1b[8;24;80t\x1b[22;0t\x1b[>0t\x1b[>4;2m\x1b[38:2::255:0:0m\x1b[3S\x1b[>1u\x1b[<u\x1b[=1;1u\x1b[u\x1b[2*x\x1b[#{\x1b[132$|\x1b[1#Q"},
	// Spec test 2 (CSI and ESC rows).
	{name: "ESC restarts a lone ESC", in: "\x1b\x1b[6n", want: ""},
	{name: "ESC restarts a CSI head", in: "\x1b[6\x1b[6nhello", want: "hello"},
	{name: "abandoned head then a passed CSI", in: "\x1b[1\x1b[1m", want: "\x1b[1m"},
	{name: "ESC restarts an ESC-intermediate head", in: "\x1b(\x1b[6nBfoo", want: "Bfoo"},
	// Spec test 3.
	{name: "C0 after a lone ESC", in: "\x1b\r[6n", want: "\r"},
	{name: "DEL after a lone ESC", in: "\x1b\x7f[6n", want: ""},
	{name: "C0 inside a CSI query", in: "\x1b[6\rn", want: "\r"},
	{name: "C0 inside a passed CSI", in: "\x1b[1\rm", want: "\r\x1b[1m"},
	{name: "C0 inside an ESC-intermediate", in: "\x1b(\rB", want: "\r\x1b(B"},
	{name: "DEL never counts toward the bound", in: "\x1b[" + strings.Repeat("\x7f", 40) + "6n", want: ""},
	// Spec test 4 (over-bound head).
	{name: "a drop after an over-bound head closes it", in: "\x1b[" + strings.Repeat("0", 31) + "\x1b[6nhello",
		want: "\x1b[" + strings.Repeat("0", 31) + "\x1b\x18hello"},
	{name: "an over-bound CSI passes to its final byte", in: "\x1b[" + strings.Repeat("0", 40) + "mX",
		want: "\x1b[" + strings.Repeat("0", 40) + "mX"},
	{name: "CSI-ignore passes to its final byte", in: "\x1b[1$2qX", want: "\x1b[1$2qX"},
	{name: "a drop after CSI-ignore closes it", in: "\x1b[1$2\x1b[6nX", want: "\x1b[1$2\x1b\x18X"},
	// An ESC sequence given up on past its bound still ends at its final
	// byte, so the X here is text, not the over-bound sequence's final byte.
	{name: "a drop after an over-bound ESC sequence closes it", in: "\x1b" + strings.Repeat(" ", 8) + "\x1b[6nX",
		want: "\x1b" + strings.Repeat(" ", 8) + "\x1b\x18X"},
	// Bytes 0xA0–0xFF inside a head are ignored, as DEL is, as Ghostty's
	// parse table ignores them; 0x80–0x9F still give the head up, since C1
	// introducers aren't covered.
	{name: "a high byte inside a CSI query", in: "\x1b[6\xa0n", want: ""},
	{name: "a high byte after a lone ESC", in: "\x1b\xa0Z", want: ""},
	{name: "a high byte before a CSI's introducer", in: "\x1b\xa0[6nX", want: "X"},
	{name: "a high byte, then an abandoned head", in: "\x1b\xa0[1\x1b[6nX", want: "X"},
	{name: "a high byte inside a passed CSI", in: "\x1b[1\xa0m", want: "\x1b[1m"},
	{name: "a high byte inside an ESC-intermediate", in: "\x1b(\xffB", want: "\x1b(B"},
	{name: "high bytes never count toward the bound", in: "\x1b[" + strings.Repeat("\xa0", 40) + "6n", want: ""},
	{name: "a C1 byte still gives the head up", in: "\x1b[1\x85mX", want: "\x1b[1\x85mX"},
}

// OSCs held to their end, held strings that end abnormally, the close, and
// the strings PR 1 passes opaquely: DCS, APC, PM, SOS and tmux wrappers.
var oscStringCases = []filterCase{
	// Generated in init() from query_classify_test.go's examples: every
	// oscQueryExamples entry, terminated by BEL and by ST and wrapped
	// "a"+q+"b", wants "ab"; every oscPassExamples entry, terminated by BEL,
	// wants itself.
	// Spec tests 2–3 (OSC rows).
	{name: "OSC query, stray ESC, lone ESC", in: "\x1b]11;?\x1b\x1b[6n", want: ""},
	{name: "title ended by a stray ESC is dropped", in: "\x1b]0;t\x1b\x1b[6nhello", want: "hello"},
	{name: "C0 after a dropped title", in: "abc\x1b]0;t\x1b[6\rnX", want: "abc\rX"},
	// Spec test 4.
	{name: "title then a dropped query", in: "\x1b]0;newtitle\x1b[6n", want: ""},
	{name: "no OSC glued back together", in: "\x1b]11;\x1b[6n?\x07", want: "?\x07"},
	{name: "OSC query ended by ESC", in: "\x1b]11;?\x1b[6n\x07", want: "\x07"},
	{name: "OSC query cancelled", in: "\x1b]10;?\x18", want: "\x18"},
	{name: "palette query kitty would continue past CAN", in: "\x1b]4;0;\x18;1;?\x07", want: "\x18;1;?\x07", kitty: true},
	{name: "over-bound title closed with ESC CAN", in: "\x1b]0;" + strings.Repeat("t", 300) + "\x1b[6nhello",
		want: "\x1b]0;" + strings.Repeat("t", 300) + "\x1b\x18hello"},
	{name: "ignored CRs in the number trip the number guard", in: "\x1b]0" + strings.Repeat("\r", 9) + ";t\x1b[6nhello",
		want: "\x1b]0" + strings.Repeat("\r", 9) + ";t\x1b\x18hello"},
	{name: "ignored CRs in the payload don't", in: "\x1b]0;" + strings.Repeat("\r", 9) + "t\x1b[6nhello", want: "hello"},
	// Found by the fuzz test: CRs between the ESC and the ']' are executed
	// before the OSC begins, so they go out at once and the OSC holds only
	// "ESC ]". Held, it is dropped when it ends at the ESC.
	{name: "CRs before the ] aren't held with the OSC", in: "\x1b" + strings.Repeat("\r", 7) + "]\x1b\x18",
		want: strings.Repeat("\r", 7) + "\x1b\x18"},
	{name: "cancel with an obligation drops the held OSC (CAN)", in: "\x1bPq\x07\x1b]4;0;\x18;1;?\x07",
		want: "\x1bPq\x07\x1b\x18;1;?\x07", kitty: true},
	{name: "cancel with an obligation drops the held OSC (SUB)", in: "\x1bPq\x07\x1b]4;0;\x1a;1;?\x07",
		want: "\x1bPq\x07\x1b\x1a;1;?\x07", kitty: true},
	// Spec test 5.
	{name: "query after a passed DCS", in: "\x1bP0;1;0q#0\x1b[6n\x1b\\", want: "\x1bP0;1;0q#0\x1b\x18\x1b\\"},
	// A C0 inside the held head is due before the head is decided, and must
	// not land inside the DCS the input had already ended, so the close goes
	// out first.
	{name: "a C0 in a head settles the close first", in: "\x1bPq#0\x1b[6\rnX", want: "\x1bPq#0\x1b\x18\rX"},
	{name: "DCS-ignore closed too", in: "\x1bP$1qhidden\x1b[6nVISIBLE", want: "\x1bP$1qhidden\x1b\x18VISIBLE"},
	{name: "tmux wrapper", in: "\x1bPtmux;\x1b\x1b[31mX\x1b\\", want: "\x1bPtmux;\x1b\x1b[31mX\x1b\\"},
	{name: "wrapped kitty command", in: "\x1bPtmux;\x1b\x1b_Ga=T,f=100;AAAA\x1b\x1b\\\x1b\\", want: "\x1bPtmux;\x1b\x1b_Ga=T,f=100;AAAA\x1b\x1b\\\x1b\\"},
	{name: "tmux wrapper with CAN inside", in: "\x1bPtmux;\x1b\x1b[31m\x18X\x1b\\", want: "\x1bPtmux;\x1b\x1b[31m\x18X\x1b\\"},
	// An ESC in a wrapper that escapes neither an ESC nor a '\' ends the
	// wrapper, as it ends any DCS on a DEC terminal, and the filter owes the
	// wrapper a close. Kept open there, a malformed or interrupted wrapper let
	// every query through until the next unescaped ST.
	{name: "a lone ESC ends a tmux wrapper", in: "\x1bPtmux;\x1b[6n\x1b\\", want: "\x1bPtmux;\x1b\x18\x1b\\"},
	{name: "an interrupted wrapped image, then tmux attaching",
		in:   "\x1bPtmux;\x1b\x1b_Gf=100;AAAA\r\n$ \x1b[?2026$p\x1b[c\x1b]11;?\x07prompt",
		want: "\x1bPtmux;\x1b\x1b_Gf=100;AAAA\r\n$ \x1b\x18prompt"},
	{name: "a non-query after a lone ESC in a wrapper closes it", in: "\x1bPtmux;\x1b[31mX", want: "\x1bPtmux;\x1b[31mX"},
	// A DEL or a high byte after a wrapper's ESC is dropped, as after any ESC,
	// so nothing that goes out says the wrapper has ended. The close goes out
	// at once instead, as before a C0. Owed until later, it left a joiner's
	// filter inside the wrapper, where it took the held ESC for one escaping
	// the next byte.
	{name: "a DEL after a wrapper's ESC, then a query", in: "\x1bPtmux;\x1b\x7f\x1b[6nX", want: "\x1bPtmux;\x1b\x18X"},
	{name: "a high byte after a wrapper's ESC, then a query", in: "\x1bPtmux;\x1b\xa0\x1b[6nX", want: "\x1bPtmux;\x1b\x18X"},
	{name: "a DEL after a wrapper's ESC, then a doubled ESC", in: "\x1bPtmux;\x1b\x7f\x1b\x1b[6nX", want: "\x1bPtmux;\x1b\x18X"},
	{name: "a DEL after a wrapper's ESC, then a non-query", in: "\x1bPtmux;\x1b\x7f[1mX", want: "\x1bPtmux;\x1b\x18\x1b[1mX"},
	{name: "a high byte after a wrapper's ESC, then a non-query", in: "\x1bPtmux;\x1b\xff[1mX", want: "\x1bPtmux;\x1b\x18\x1b[1mX"},
	{name: "a C0 after a wrapper's ESC settles the close first", in: "\x1bPtmux;\x1b\r[6nX", want: "\x1bPtmux;\x1b\x18\rX"},
	{name: "an ESC sequence with an intermediate ends a wrapper", in: "\x1bPtmux;\x1b(BX", want: "\x1bPtmux;\x1b(BX"},
	{name: "CAN ends a passed DCS", in: "\x1bPq#0\x18X", want: "\x1bPq#0\x18X"},
	{name: "SUB ends a passed DCS", in: "\x1bPq#0\x1aX", want: "\x1bPq#0\x1aX"},
	{name: "BEL doesn't end a DCS", in: "\x1bPq#0\x07X\x1b\\", want: "\x1bPq#0\x07X\x1b\\"},
	{name: "BEL doesn't end an APC", in: "\x1b_Gx\x07Y\x1b\\", want: "\x1b_Gx\x07Y\x1b\\"},
	// Past a BEL the string is still open, so a query dropped after it still
	// owes the string a close.
	{name: "a drop after a BEL in a DCS closes it", in: "\x1bPq#0\x07\x1b[6nX", want: "\x1bPq#0\x07\x1b\x18X"},
	{name: "a drop after a BEL in an APC closes it", in: "\x1b_G\x07\x1b[6nX", want: "\x1b_G\x07\x1b\x18X"},
	{name: "PM and SOS pass", in: "\x1b^privacy\x1b\\\x1bXsos\x1b\\", want: "\x1b^privacy\x1b\\\x1bXsos\x1b\\"},
	// Found by the fuzz test: the DEL after the ESC that ends a passed string
	// is dropped, as after any ESC, and ESC \ then passes as the close. The
	// string ended at the ESC either way.
	{name: "DEL after a passed string's ESC", in: "\x1bX0\x1b\x7f\\", want: "\x1bX0\x1b\\"},
}

func init() {
	for _, q := range append(slices.Clone(csiQueryExamples), "\x1bZ") {
		escCSICases = append(escCSICases, filterCase{name: fmt.Sprintf("query %q", q), in: "a" + q + "b", want: "ab"})
	}
	for _, c := range csiPassExamples {
		escCSICases = append(escCSICases, filterCase{name: fmt.Sprintf("counter-case %q", c), in: c, want: c})
	}
	filterCases = append(filterCases, escCSICases...)

	for _, q := range oscQueryExamples {
		for _, end := range []string{"\x07", "\x1b\\"} {
			oscStringCases = append(oscStringCases, filterCase{name: fmt.Sprintf("query %q", q+end), in: "a" + q + end + "b", want: "ab"})
		}
	}
	for _, c := range oscPassExamples {
		oscStringCases = append(oscStringCases, filterCase{name: fmt.Sprintf("counter-case %q", c+"\x07"), in: c + "\x07", want: c + "\x07"})
	}
	filterCases = append(filterCases, oscStringCases...)
}

// Every exact-bytes case gives the same output whether it arrives in one
// write or one byte per write: a sequence split across writes is the normal
// case for a pty read, not an edge.
func TestTerminalQueryFilter_SplitWritesMatchWholeWrites(t *testing.T) {
	for _, c := range filterCases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, filterAll(c.in), "whole")
			require.Equal(t, c.want, filterBytewise(c.in), "byte by byte")
		})
	}
}

// continuationCheck is spec test 8: a joiner at any boundary ends where the
// filter would. Filter A takes the first k bytes of in; a fresh filter B takes
// what A emitted, then A.Pending(), then the rest. B's output must equal the
// output of one filter fed all of in, which also holds B to re-filtering A's
// output without changing it. k ranges over every boundary, including the one
// between a terminator's ESC and its backslash.
func continuationCheck(t *testing.T, in string) {
	t.Helper()
	whole := filterAll(in)
	for k := 0; k <= len(in); k++ {
		require.Equal(t, whole, continuedAt(in, k), "split at %d of %q", k, in)
	}
}

// continuedAt is continuationCheck's joiner at the one boundary k: it returns
// what filter B emitted. The fuzz test checks it at a boundary of its choice.
func continuedAt(in string, k int) string {
	var outA, outB bytes.Buffer
	a := NewTerminalQueryFilter(&outA)
	_, _ = a.Write([]byte(in[:k]))
	b := NewTerminalQueryFilter(&outB)
	_, _ = b.Write(outA.Bytes())
	_, _ = b.Write(a.Pending())
	_, _ = b.Write([]byte(in[k:]))
	return outB.String()
}

func TestTerminalQueryFilter_ContinuesAtEveryBoundary(t *testing.T) {
	for _, c := range filterCases {
		t.Run(c.name, func(t *testing.T) { continuationCheck(t, c.in) })
	}
}

// A row marked kitty is one whose output a kitty guest could read differently
// from a DEC one; under kitty's string ends it still asks nothing.
func TestTerminalQueryFilter_KittyRowsAskNothing(t *testing.T) {
	for _, c := range filterCases {
		if !c.kitty {
			continue
		}
		for _, ev := range refParse(refKitty, []byte(c.want)) {
			require.False(t, refQuery(refKitty, ev), "%s: %q asks %v under kitty", c.name, c.want, ev)
		}
	}
}

// Every exact-bytes case passes the oracle as it stands, the ones the fuzz
// domain leaves out included. A sequence past its bound passes unclassified,
// so a query there is a stated limit, but a non-query must still reach the
// terminal with the effect it had, and only these rows check that: the fuzz
// never takes a sequence past its bound.
func TestTerminalQueryFilter_CasesPassTheOracle(t *testing.T) {
	for _, c := range filterCases {
		t.Run(c.name, func(t *testing.T) {
			require.Empty(t, refCheck(c.in, filterAll))
		})
	}
}

// A joiner's own filter re-filters what this one emitted, so filtering the
// output again must change nothing. A cancel that carries a held ESC out
// with it, or a close, has to read the second time as what settles the
// obligation, not as the start of another.
func TestTerminalQueryFilter_RefilteringIsStable(t *testing.T) {
	ins := []string{"\x1bPq#0\x1b\x18"}
	for _, c := range oscStringCases {
		if strings.Contains(c.want, "\x1b\x18") || strings.Contains(c.want, "\x1b\x1a") {
			ins = append(ins, c.in)
		}
	}
	for _, in := range ins {
		out := filterAll(in)
		require.Equal(t, out, filterAll(out), "%q", in)
	}
}

// What a shell, a prompt and an editor print every day -- semantic prompt
// marks, hyperlinks, the working directory, colours, cursor shapes,
// synchronized output, the kitty keyboard stack, the alternate screen and
// bracketed paste -- reaches a guest byte for byte.
func TestTerminalQueryFilter_EverydayOutputPasses(t *testing.T) {
	const in = "\x1b]133;A\x07$ \x1b]133;B\x07ls\r\n\x1b]133;C\x07\x1b]8;;https://example.com/?q=1&r=2\x1b\\link\x1b]8;;\x1b\\" +
		"\x1b]7;file://host/tmp\x07\x1b[38:2::255:0:0mred\x1b[m\x1b[5 q\x1b[?2026hframe\x1b[?2026l" +
		"\x1b[>1u\x1b[<u\x1b[?1049h\x1b[?1049l\x1b[?2004h"
	require.Equal(t, in, filterAll(in), "whole")
	require.Equal(t, in, filterBytewise(in), "byte by byte")
}

// Bytes 0x80–0xFF are text in ground and payload in an OSC, so UTF-8 passes
// in both: only inside an ESC or CSI head does the filter drop a high byte.
func TestTerminalQueryFilter_UTF8Passes(t *testing.T) {
	for _, in := range []string{"Ü ünïcödé 🙂", "\x1b]0;Ü-title 🙂\x07"} {
		require.Equal(t, in, filterAll(in), "whole: %q", in)
		require.Equal(t, in, filterBytewise(in), "byte by byte: %q", in)
	}
}
