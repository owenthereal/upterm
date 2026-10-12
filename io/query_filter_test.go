package io

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
		{
			name:  "DCS header",
			input: append([]byte("\x1bP"), bytes.Repeat([]byte("1;"), runLength)...),
		},
		{
			name:  "DCS header intermediates",
			input: append([]byte("\x1bP1"), bytes.Repeat([]byte("+"), runLength)...),
		},
		{
			name:  "dropped DCS payload",
			input: append([]byte("\x1bP+q"), bytes.Repeat([]byte("544e"), runLength)...),
		},
		{
			name:  "APC control data of BELs that ask nothing",
			input: append([]byte("\x1b_G"), bytes.Repeat([]byte("i=1\x07"), runLength)...),
		},
		{
			name:  "dropped APC payload",
			input: append([]byte("\x1b_Ga=q;"), bytes.Repeat([]byte("AAAA"), runLength)...),
		},
		{
			// The ';' is the 256th byte, so it decides: the drop's head is
			// the whole bound, and the payload's last ESC comes on top.
			name:  "APC query decided at its bound",
			input: []byte("\x1b_Ga=q," + strings.Repeat("i", 248) + ";AAAA\x1b"),
		},
		{
			// The ';' would be the 257th byte, so the command is given up on
			// before it decides; a drop's head here would pass the bound.
			name:  "APC query one byte past its bound",
			input: []byte("\x1b_Ga=q," + strings.Repeat("i", 249) + ";AAAA\x1b"),
		},
		{
			name:  "wrapper's leading bytes",
			input: append([]byte("\x1bPtmux;"), bytes.Repeat([]byte("x"), runLength)...),
		},
		{
			name:  "wrapped OSC being decided",
			input: append([]byte("\x1bPtmux;\x1b\x1b]0;"), bytes.Repeat([]byte("t"), runLength)...),
		},
		{
			name:  "wrapped escapes being decided",
			input: append([]byte("\x1bPtmux;\x1b\x1b]0;"), bytes.Repeat([]byte{0x1b}, runLength)...),
		},
		{
			name:  "dropped wrapped payload",
			input: append([]byte("\x1bPtmux;\x1b\x1bP+q"), bytes.Repeat([]byte("544e"), runLength)...),
		},
		{
			name:  "dropped wrapped payload of escapes",
			input: append([]byte("\x1bPtmux;\x1b\x1bP+q"), bytes.Repeat([]byte{0x1b}, runLength)...),
		},
		{
			// The ';' is the 256th raw byte, so it decides: the drop's saved
			// head is the whole bound, and the inner ESC re-encoded and an
			// unpaired raw ESC come on top.
			name:  "wrapped graphics query decided at its bound",
			input: []byte("\x1bPtmux;\x1b\x1b_Gi=" + strings.Repeat("0", 238) + ",a=q;\x1b\x1b\x1b"),
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

// maxPendingBytes is computed, not remembered: the most Pending returns in any
// state, from the bounds. A head, an OSC or a graphics command held to its
// bound can be followed by the ESC that may begin its ST, one more byte; a
// dropped DCS keeps its header, final byte included, and that ESC; a wrapper
// being decided holds its raw bytes, a held ESC among them, within its bound;
// and a wrapper's inner drop adds to the head it saved the pending inner ESC
// re-encoded (two bytes) and an unpaired raw ESC (one). Both halves are
// checked, the maximum from the bound constants and the hold from the filter
// itself, so raising a bound without the constant fails here, and so does a
// constant larger than anything the filter ever holds.
func TestTerminalQueryFilter_MaxPendingBytesIsTheLargestHold(t *testing.T) {
	largest := max(
		max(maxEscHeld, maxCSIHeld, maxOSCNumHeld, maxOSCHeld, maxAPCHeld)+1, // a hold, then an ESC
		maxDCSHeld+2, // a dropped DCS: its header, the final byte, then an ESC
		maxWrapHeld,  // a wrapper being decided, its held ESC within the bound
		maxWrapHeld+2+1,
	)
	require.Equal(t, largest, maxPendingBytes, "the largest Pending any state returns")

	// 256 (the largest hold: an OSC, an APC or a wrapper, with framing) + 2
	// (an inner ESC re-encoded) + 1 (an unpaired raw ESC). If the bounds
	// change, change both this and the constant's comment.
	require.Equal(t, 259, maxPendingBytes)

	// An OSC held to its bound, then an ESC, reaches 257. One more payload
	// byte instead would have given the OSC up.
	head := "\x1b]0;"
	var out bytes.Buffer
	f := NewTerminalQueryFilter(&out)
	_, _ = f.Write([]byte(head + strings.Repeat("t", maxOSCHeld-len(head))))
	require.Len(t, f.Pending(), maxOSCHeld, "an OSC held to its bound")
	_, _ = f.Write([]byte("\x1b"))
	require.Len(t, f.Pending(), maxOSCHeld+1, "and the ESC that may begin its ST")
	require.Empty(t, out.String(), "nothing of it has gone out")

	// A wrapper being decided is held to its bound, its held ESC within it,
	// and the next raw byte, whatever it is, gives it up: the hold goes out,
	// and the wrapper passes byte for byte.
	wrap := "\x1bPtmux;\x1b\x1b]0;" + strings.Repeat("t", maxWrapHeld-len("\x1bPtmux;\x1b\x1b]0;")-1) + "\x1b"
	var held bytes.Buffer
	w := NewTerminalQueryFilter(&held)
	_, _ = w.Write([]byte(wrap))
	require.Len(t, w.Pending(), maxWrapHeld, "a wrapper held to its bound, an unpaired ESC last")
	require.Empty(t, held.String(), "nothing of it has gone out")
	_, _ = w.Write([]byte("\x1b"))
	require.Empty(t, w.Pending(), "one byte past the bound, the wrapper is given up on")
	require.Equal(t, wrap+"\x1b", held.String(), "and passes byte for byte")

	var gaveUp bytes.Buffer
	g := NewTerminalQueryFilter(&gaveUp)
	_, _ = g.Write([]byte(head + strings.Repeat("t", maxOSCHeld-len(head)+1)))
	require.Empty(t, g.Pending(), "one byte past the bound, the OSC is given up on")
	require.Len(t, gaveUp.String(), maxOSCHeld+1, "and goes out")

	// So does a dropped graphics query. The ';' that decides counts toward
	// the APC's bound, so a drop's head is at most the bound, and the ESC
	// that may begin its payload's ST comes on top.
	apc := "\x1b_Ga=q,"
	var dropped bytes.Buffer
	d := NewTerminalQueryFilter(&dropped)
	_, _ = d.Write([]byte(apc + strings.Repeat("i", maxAPCHeld-len(apc)-1) + ";AAAA\x1b"))
	require.Len(t, d.Pending(), maxAPCHeld+1, "a dropped APC's head at its bound, and an ESC")
	require.Empty(t, dropped.String(), "nothing of it has gone out")

	// A dropped DCS keeps its header to its bound, the final byte, and an ESC.
	dcs := "\x1bP" + strings.Repeat("1", maxDCSHeld-len("\x1bP+")) + "+q"
	var droppedDCS bytes.Buffer
	c := NewTerminalQueryFilter(&droppedDCS)
	_, _ = c.Write([]byte(dcs + "544e\x1b"))
	require.Len(t, c.Pending(), maxDCSHeld+2, "a dropped DCS's header at its bound, its final byte, and an ESC")
	require.Empty(t, droppedDCS.String(), "nothing of it has gone out")

	// A ';' one byte later would be held past the bound, so the command is
	// given up on there, unclassified, and passes.
	var passed bytes.Buffer
	p := NewTerminalQueryFilter(&passed)
	in := apc + strings.Repeat("i", maxAPCHeld-len(apc)) + ";AAAA"
	_, _ = p.Write([]byte(in))
	require.Empty(t, p.Pending(), "one byte past the bound, the APC is given up on")
	require.Equal(t, in, passed.String(), "and goes out")
}

// The largest Pending of all is a wrapper's inner drop: the saved head at the
// wrapper's bound, the pending inner ESC re-encoded, and an unpaired raw ESC
// (Owen, 2026-10-11).
func TestTerminalQueryFilter_PendingReachesItsMaximumInAWrapper(t *testing.T) {
	// A wrapped kitty query whose deciding head is exactly 256 raw bytes.
	h := "\x1bPtmux;\x1b\x1b_Gi=" + strings.Repeat("0", 238) + ",a=q;"
	require.Len(t, h, 256)
	f := NewTerminalQueryFilter(io.Discard)
	for i, b := range []byte(h + "\x1b\x1b\x1b") {
		_, _ = f.Write([]byte{b})
		require.LessOrEqual(t, len(f.Pending()), maxPendingBytes, "after byte %d", i)
	}
	// The saved head, the pending inner ESC doubled, and an unpaired decoder ESC.
	require.Len(t, f.Pending(), 259)
	require.Equal(t, 259, maxPendingBytes)
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
	kitty    bool // also assert no query under refKitty (refParse on the filter's output)

	// limit marks a row whose input is past a stated limit, where a query can
	// pass on purpose: it is checked for its bytes, splits and continuation,
	// and not against the oracle.
	limit bool
}

// filterCases is every exact-bytes case: escCSICases, oscStringCases,
// dcsCases, apcCases and wrapperCases, with the rows init() generates from the
// classifier tests' examples. The split, continuation and oracle tests range
// over it, and it seeds the fuzz test.
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
	// An ESC abandons whatever head is held and starts a new sequence.
	{name: "ESC restarts a lone ESC", in: "\x1b\x1b[6n", want: ""},
	{name: "ESC restarts a CSI head", in: "\x1b[6\x1b[6nhello", want: "hello"},
	{name: "abandoned head then a passed CSI", in: "\x1b[1\x1b[1m", want: "\x1b[1m"},
	{name: "ESC restarts an ESC-intermediate head", in: "\x1b(\x1b[6nBfoo", want: "Bfoo"},
	// Control bytes inside a head: a C0 goes out at once, a DEL is dropped.
	{name: "C0 after a lone ESC", in: "\x1b\r[6n", want: "\r"},
	{name: "DEL after a lone ESC", in: "\x1b\x7f[6n", want: ""},
	{name: "C0 inside a CSI query", in: "\x1b[6\rn", want: "\r"},
	{name: "C0 inside a passed CSI", in: "\x1b[1\rm", want: "\r\x1b[1m"},
	{name: "C0 inside an ESC-intermediate", in: "\x1b(\rB", want: "\r\x1b(B"},
	{name: "DEL never counts toward the bound", in: "\x1b[" + strings.Repeat("\x7f", 40) + "6n", want: ""},
	// Heads emitted unfinished, past a bound or in CSI-ignore, and their close.
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
// the strings passed opaquely: DCS, APC, PM, SOS and tmux wrappers.
var oscStringCases = []filterCase{
	// Generated in init() from query_classify_test.go's examples: every
	// oscQueryExamples entry, terminated by BEL and by ST and wrapped
	// "a"+q+"b", wants "ab"; every oscPassExamples entry, terminated by BEL,
	// wants itself.
	// An OSC ended by a stray ESC, and a C0 after one.
	{name: "OSC query, stray ESC, lone ESC", in: "\x1b]11;?\x1b\x1b[6n", want: ""},
	{name: "title ended by a stray ESC is dropped", in: "\x1b]0;t\x1b\x1b[6nhello", want: "hello"},
	{name: "C0 after a dropped title", in: "abc\x1b]0;t\x1b[6\rnX", want: "abc\rX"},
	// OSCs that end abnormally, and the close an emitted one is owed.
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
	// DCS, APC, PM, SOS and tmux wrappers, passed as they stream.
	{name: "query after a passed DCS", in: "\x1bP0;1;0q#0\x1b[6n\x1b\\", want: "\x1bP0;1;0q#0\x1b\x18\x1b\\"},
	// A C0 inside the held head is due before the head is decided, and must
	// not land inside the DCS the input had already ended, so the close goes
	// out first.
	{name: "a C0 in a head settles the close first", in: "\x1bPq#0\x1b[6\rnX", want: "\x1bPq#0\x1b\x18\rX"},
	{name: "DCS-ignore closed too", in: "\x1bP$1qhidden\x1b[6nVISIBLE", want: "\x1bP$1qhidden\x1b\x18VISIBLE"},
	{name: "tmux wrapper", in: "\x1bPtmux;\x1b\x1b[31mX\x1b\\", want: "\x1bPtmux;\x1b\x1b[31mX\x1b\\"},
	{name: "wrapped kitty command", in: "\x1bPtmux;\x1b\x1b_Ga=T,f=100;AAAA\x1b\x1b\\\x1b\\", want: "\x1bPtmux;\x1b\x1b_Ga=T,f=100;AAAA\x1b\x1b\\\x1b\\"},
	{name: "tmux wrapper with CAN inside", in: "\x1bPtmux;\x1b\x1b[31m\x18X\x1b\\", want: "\x1bPtmux;\x1b\x1b[31m\x18X\x1b\\"},
	// An ESC in a passing wrapper that escapes neither an ESC nor a '\' ends
	// the wrapper, as it ends any DCS on a DEC terminal, and the filter owes
	// the wrapper a close. Kept open there, a malformed or interrupted wrapper
	// let every query through until the next unescaped ST. Each of these
	// wrappers passes because its first inner sequence, an SGR, is no query;
	// the same lone ESC while the wrapper is still held drops it instead
	// (wrapperCases).
	{name: "a lone ESC ends a tmux wrapper", in: "\x1bPtmux;\x1b\x1b[1m\x1b[6n\x1b\\", want: "\x1bPtmux;\x1b\x1b[1m\x1b\x18\x1b\\"},
	{name: "an interrupted wrapped image, then tmux attaching",
		in:   "\x1bPtmux;\x1b\x1b_Gf=100;AAAA\r\n$ \x1b[?2026$p\x1b[c\x1b]11;?\x07prompt",
		want: "\x1bPtmux;\x1b\x1b_Gf=100;AAAA\r\n$ \x1b\x18prompt"},
	{name: "a non-query after a lone ESC in a wrapper closes it", in: "\x1bPtmux;\x1b\x1b[1m\x1b[31mX", want: "\x1bPtmux;\x1b\x1b[1m\x1b[31mX"},
	// A DEL or a high byte after a wrapper's ESC is dropped, as after any ESC,
	// so nothing that goes out says the wrapper has ended. The close goes out
	// at once instead, as before a C0. Owed until later, it left a joiner's
	// filter inside the wrapper, where it took the held ESC for one escaping
	// the next byte.
	{name: "a DEL after a wrapper's ESC, then a query", in: "\x1bPtmux;\x1b\x1b[1m\x1b\x7f\x1b[6nX", want: "\x1bPtmux;\x1b\x1b[1m\x1b\x18X"},
	{name: "a high byte after a wrapper's ESC, then a query", in: "\x1bPtmux;\x1b\x1b[1m\x1b\xa0\x1b[6nX", want: "\x1bPtmux;\x1b\x1b[1m\x1b\x18X"},
	{name: "a DEL after a wrapper's ESC, then a doubled ESC", in: "\x1bPtmux;\x1b\x1b[1m\x1b\x7f\x1b\x1b[6nX", want: "\x1bPtmux;\x1b\x1b[1m\x1b\x18X"},
	{name: "a DEL after a wrapper's ESC, then a non-query", in: "\x1bPtmux;\x1b\x1b[1m\x1b\x7f[1mX", want: "\x1bPtmux;\x1b\x1b[1m\x1b\x18\x1b[1mX"},
	{name: "a high byte after a wrapper's ESC, then a non-query", in: "\x1bPtmux;\x1b\x1b[1m\x1b\xff[1mX", want: "\x1bPtmux;\x1b\x1b[1m\x1b\x18\x1b[1mX"},
	{name: "a C0 after a wrapper's ESC settles the close first", in: "\x1bPtmux;\x1b\x1b[1m\x1b\r[6nX", want: "\x1bPtmux;\x1b\x1b[1m\x1b\x18\rX"},
	{name: "an ESC sequence with an intermediate ends a wrapper", in: "\x1bPtmux;\x1b\x1b[1m\x1b(BX", want: "\x1bPtmux;\x1b\x1b[1m\x1b(BX"},
	{name: "CAN ends a passed DCS", in: "\x1bPq#0\x18X", want: "\x1bPq#0\x18X"},
	{name: "SUB ends a passed DCS", in: "\x1bPq#0\x1aX", want: "\x1bPq#0\x1aX"},
	{name: "BEL doesn't end a DCS", in: "\x1bPq#0\x07X\x1b\\", want: "\x1bPq#0\x07X\x1b\\"},
	{name: "BEL doesn't end an APC", in: "\x1b_Gx\x07Y\x1b\\", want: "\x1b_Gx\x07Y\x1b\\"},
	// Past a BEL the string is still open, so a query dropped after it still
	// owes the string a close. The APC is past its ';', so it has gone out: a
	// graphics command still held there is dropped instead (apcCases).
	{name: "a drop after a BEL in a DCS closes it", in: "\x1bPq#0\x07\x1b[6nX", want: "\x1bPq#0\x07\x1b\x18X"},
	{name: "a drop after a BEL in an APC closes it", in: "\x1b_Ga=T;\x07\x1b[6nX", want: "\x1b_Ga=T;\x07\x1b\x18X"},
	{name: "PM and SOS pass", in: "\x1b^privacy\x1b\\\x1bXsos\x1b\\", want: "\x1b^privacy\x1b\\\x1bXsos\x1b\\"},
	// Found by the fuzz test: the DEL after the ESC that ends a passed string
	// is dropped, as after any ESC, and ESC \ then passes as the close. The
	// string ended at the ESC either way.
	{name: "DEL after a passed string's ESC", in: "\x1bX0\x1b\x7f\\", want: "\x1bX0\x1b\\"},
}

// DCS headers, held to their final byte and decided there: a query is dropped
// to the string's end, and anything else goes out and passes as it streams.
var dcsCases = []filterCase{
	// Generated in init() from query_classify_test.go's examples: every
	// dcsQueryExamples header, with a payload and ST, wrapped "a"+q+"b", wants
	// "ab"; every dcsPassExamples header, with a payload and ST, wants itself.
	{name: "DECRQSS", in: "a\x1bP$qm\x1b\\b", want: "ab"},
	{name: "XTGETTCAP", in: "a\x1bP+q544e;524742\x1b\\b", want: "ab"},
	{name: "XTGETXRES", in: "a\x1bP+Q616c6c6f77\x1b\\b", want: "ab"},
	{name: "DCS header C0 dropped with the query", in: "ABC\x1bP$\rqm\x1b\\X", want: "ABCX"},
	{name: "ignored C0 dropped from a passed header", in: "\x1bP1\r;0q#0\x1b\\", want: "\x1bP1;0q#0\x1b\\"},
	{name: "DCS-ignore still closed", in: "\x1bP$1qhidden\x1b[6nVISIBLE", want: "\x1bP$1qhidden\x1b\x18VISIBLE"},
	{name: "sixel passes", in: "\x1bP0;1;0q#0;2;0;0;0#0!10~\x1b\\", want: "\x1bP0;1;0q#0;2;0;0;0#0!10~\x1b\\"},
	{name: "XTSETTCAP passes", in: "\x1bP+p78746572\x1b\\", want: "\x1bP+p78746572\x1b\\"},
	{name: "drop ends at CAN", in: "\x1bP+q544e\x18X", want: "\x18X"},
	{name: "drop ends at ESC-not-ST", in: "\x1bP+q544e\x1b[1mX", want: "\x1b[1mX"},
	{name: "BEL inside a dropped DCS", in: "\x1bP+q544e\x07hello\x1b\\X", want: "X"},
	// A header the input abandons or cancels while it is held is a held string
	// that ends abnormally, so none of it goes out. With a close owed, the
	// cancel carries the header's ESC out as the close.
	{name: "an ESC abandons a held DCS header", in: "\x1bP+\x1b[6nX", want: "X"},
	{name: "a held DCS header ended by CAN", in: "\x1bP1;\x18X", want: "\x18X"},
	{name: "cancel with an obligation drops the held DCS header", in: "\x1bPq\x07\x1bP+\x18q544e\x1b\\X",
		want: "\x1bPq\x07\x1b\x18q544e\x1b\\X", kitty: true},
	// The drop owes nothing, since nothing of it went out, but a close owed
	// from before it is settled as for any drop.
	{name: "a DCS query after a passed DCS closes it", in: "\x1bPq#0\x1bP+q544e\x1b\\X", want: "\x1bPq#0\x1b\x18X"},
	// The ESC that ends a drop starts a sequence of its own, held like any
	// other, and goes out with a cancel as a lone ESC does.
	{name: "a cancel after a drop's ESC", in: "\x1bP+q544e\x1b\x18X", want: "\x1b\x18X"},
	{name: "a DEL after a drop's ESC", in: "\x1bP+q544e\x1b\x7f\\X", want: "\x1b\\X"},
	// Bytes 0xA0–0xFF in a header are ignored, as DEL is; 0x80–0x9F give the
	// header up, as they give up a CSI's, since C1 introducers aren't covered.
	{name: "a high byte inside a DCS header", in: "a\x1bP+\xa0q544e\x1b\\b", want: "ab"},
	{name: "a C1 byte gives a DCS header up", in: "\x1bP1\x85q#0\x1b[6nX", want: "\x1bP1\x85q#0\x1b\x18X"},
	// Past its bound a header passes as a string, to the string's end.
	{name: "an over-bound DCS header passes as a string", in: "\x1bP" + strings.Repeat("0", 31) + "q#0\x1b[6nX",
		want: "\x1bP" + strings.Repeat("0", 31) + "q#0\x1b\x18X"},
}

// APCs: a kitty graphics command (APC G) held to its ';' or its end and
// decided there, or at a BEL before it; any other APC passes as it streams.
var apcCases = []filterCase{
	// Generated in init() from query_classify_test.go's examples: every
	// apcQueryExamples entry, as the control data of a command with a payload
	// and of one ended at a BEL, wrapped "a"+q+"b", wants "ab"; every
	// apcPassExamples entry, with a payload, wants itself.
	{name: "kitty graphics query", in: "a\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\b", want: "ab"},
	{name: "query with no payload", in: "a\x1b_Ga=q\x1b\\b", want: "ab"},
	{name: "query found at a BEL", in: "\x1b_Gi=1,a=q\x07X;\x1b\\", want: "", kitty: true},
	{name: "transmit passes", in: "\x1b_Ga=T,f=100,i=1;AAAA\x1b\\", want: "\x1b_Ga=T,f=100,i=1;AAAA\x1b\\"},
	{name: "a control byte before G", in: "\x1b_\nGa=q\x1b\\", want: "\x1b_\nGa=q\x1b\\"},
	{name: "held APC ended by CAN", in: "\x1b_Ga=T\x18X", want: "\x18X"},
	// Every BEL decides on what came before it, and one that asks nothing is
	// payload, as a DEC terminal takes it.
	{name: "a later BEL latches too", in: "a\x1b_Gi=1\x07,a=q\x07X;\x1b\\b", want: "ab"},
	{name: "a BEL that asks nothing is held as payload", in: "\x1b_Gi=1\x07a=q;AAAA\x1b\\", want: "\x1b_Gi=1\x07a=q;AAAA\x1b\\"},
	{name: "a control byte is part of its pair", in: "\x1b_Ga=q\r;AAAA\x1b\\", want: "\x1b_Ga=q\r;AAAA\x1b\\"},
	// An APC held when it ends abnormally is dropped whole, before its first
	// byte too, and the cancel never carries its head out: kitty would keep
	// it open, and read the ",a=q" after the CAN as more control data.
	{name: "a held APC ended by an ESC after a BEL", in: "\x1b_G\x07\x1b[6nX", want: "X"},
	{name: "a held APC ended by an ESC that isn't ST", in: "\x1b_Ga=T\x1b[1mX", want: "\x1b[1mX"},
	{name: "an empty APC ended by CAN", in: "\x1b_\x18X", want: "\x18X"},
	{name: "an empty APC ended by an ESC that isn't ST", in: "\x1b_\x1b[6nX", want: "X"},
	{name: "an empty APC ended by ST passes", in: "\x1b_\x1b\\X", want: "\x1b_\x1b\\X"},
	{name: "a held APC cancelled", in: "\x1b_Gi=1\x18,a=q;\x1b\\X", want: "\x18,a=q;\x1b\\X", kitty: true},
	{name: "cancel with an obligation drops the held APC", in: "\x1bPq\x07\x1b_Gi=1\x18,a=q;\x1b\\X",
		want: "\x1bPq\x07\x1b\x18,a=q;\x1b\\X", kitty: true},
	// A query is dropped to the string's end, and settles a close owed from
	// before it, as a DCS query does.
	{name: "an APC query after a passed DCS closes it", in: "\x1bPq#0\x1b_Ga=q;AAAA\x1b\\X", want: "\x1bPq#0\x1b\x18X"},
	{name: "an APC query's drop ends at an ESC that isn't ST", in: "\x1b_Ga=q;AAAA\x1b[1mX", want: "\x1b[1mX"},
	// The ';' that decides counts toward the 256-byte bound, here its last
	// byte; past the bound a command passes as a string, to the string's end.
	{name: "a query decided at its bound", in: "a\x1b_Ga=q," + strings.Repeat("i", 248) + ";AAAA\x1b\\b", want: "ab"},
	{name: "an over-bound APC passes as a string", in: "\x1b_Ga=T," + strings.Repeat("i", 260) + ";AAAA\x1b[6nX",
		want: "\x1b_Ga=T," + strings.Repeat("i", 260) + ";AAAA\x1b\x18X"},
}

// tmux passthrough wrappers, ESC P tmux; then a sequence with each ESC doubled,
// then ESC \. The wrapper is held while an inner machine, fed the decoded
// stream, decides its first inner sequence: a query drops the wrapper's head
// and that sequence, and the rest of the wrapper goes out as ordinary output;
// anything else passes the wrapper byte for byte.
var wrapperCases = []filterCase{
	{name: "wrapped DSR", in: "\x1bPtmux;\x1b\x1b[6n\x1b\\", want: "\x1b\\"},
	{name: "text after a wrapped query survives", in: "\x1bPtmux;\x1b\x1b[6nX\x1b\\", want: "X\x1b\\"},
	{name: "wrapped kitty query", in: "\x1bPtmux;\x1b\x1b_Ga=q;AAAA\x1b\x1b\\\x1b\\", want: "\x1b\\"},
	{name: "wrapped SGR passes", in: "\x1bPtmux;\x1b\x1b[31mX\x1b\\", want: "\x1bPtmux;\x1b\x1b[31mX\x1b\\"},
	// A query nested in a wrapper inside a wrapper is not suppressed, so a
	// DEC terminal, which ends the outer DCS at its first ESC, still answers
	// it: a stated limit, not held to the oracle.
	{name: "nested wrapper passes (stated limit)",
		in:    "\x1bPtmux;\x1b\x1bPtmux;\x1b\x1b\x1b\x1b[6n\x1b\x1b\\\x1b\\",
		want:  "\x1bPtmux;\x1b\x1bPtmux;\x1b\x1b\x1b\x1b[6n\x1b\x1b\\\x1b\\",
		limit: true},
	{name: "leading inner bytes go with the dropped head", in: "\x1bPtmux;Y\x1b\x1b[6n\x1b\\", want: "\x1b\\"},
	// Inner endings, read on decoded bytes (Owen, 2026-10-11).
	{name: "wrapped DCS query ended by CAN", in: "\x1bPtmux;\x1b\x1bP+q544e\x18X\x1b\\", want: "\x18X\x1b\\"},
	{name: "wrapped OSC query ended by BEL", in: "\x1bPtmux;\x1b\x1b]11;?\x07X\x1b\\", want: "X\x1b\\"},
	{name: "wrapped DCS query ended by an inner ESC", in: "\x1bPtmux;\x1b\x1bP+q544e\x1b\x1b[1mX\x1b\\", want: "\x1b[1mX\x1b\\"},
	{name: "wrapped held OSC cancelled", in: "\x1bPtmux;\x1b\x1b]0;t\x18X\x1b\\", want: "\x18X\x1b\\"},
	{name: "wrapped CSI head cancelled before deciding passes", in: "\x1bPtmux;\x1b\x1b[6\x18X\x1b\\", want: "\x1bPtmux;\x1b\x1b[6\x18X\x1b\\"},
	// Continuation must carry the inner parser's pending ESC (Owen,
	// 2026-10-11); continuationCheck splits it at every byte, including right
	// after the complete pair.
	{name: "inner drop ended by an inner ESC, after a complete pair", in: "\x1bPtmux;\x1b\x1b_Ga=q;AAAA\x1b\x1b[31mX\x1b\\", want: "\x1b[31mX\x1b\\"},

	// Before the first inner ESC, a CAN or SUB ends the wrapper, as it ends
	// the DCS on a DEC terminal, which then prints what follows (Owen,
	// 2026-10-11). The wrapper is held, so it is dropped whole, and the cancel
	// goes out, as ESC and the cancel when a close is owed.
	{name: "a CAN before the first inner ESC ends the wrapper", in: "\x1bPtmux;\x18hello\x1b\x1b[6n\x1b\\", want: "\x18hello\x1b\\"},
	{name: "a SUB before the first inner ESC ends the wrapper", in: "\x1bPtmux;\x1ahello\x1b\x1b[6n\x1b\\", want: "\x1ahello\x1b\\"},
	{name: "a leading CAN settles a close owed", in: "\x1bPq#0\x1bPtmux;\x18hello", want: "\x1bPq#0\x1b\x18hello", kitty: true},
	// A lone ESC x, x neither ESC nor '\', ends the wrapper in every phase.
	// While the wrapper is held, it is dropped, and the ESC starts a new
	// sequence with x its next byte; during the first inner sequence's drop,
	// output resumes at that ESC.
	{name: "a lone ESC in the deciding hold", in: "\x1bPtmux;\x1b\x1b[6\x1b[1mX", want: "\x1b[1mX"},
	{name: "a lone ESC during the inner drop", in: "\x1bPtmux;\x1b\x1bP+q544e\x1b[6nX\x1b\\", want: "X\x1b\\"},
	{name: "a lone ESC ends a held wrapper", in: "\x1bPtmux;\x1b[6n\x1b\\", want: "\x1b\\"},
	{name: "a non-query after a lone ESC ends a held wrapper", in: "\x1bPtmux;\x1b[31mX", want: "\x1b[31mX"},
	{name: "an ESC-intermediate head after a lone ESC in a held wrapper", in: "\x1bPtmux;\x1b(\x1b[6nX", want: "X"},
	{name: "an ESC sequence with an intermediate ends a held wrapper", in: "\x1bPtmux;\x1b(BX", want: "\x1b(BX"},
	{name: "a DEL after a held wrapper's ESC, then a query", in: "\x1bPtmux;\x1b\x7f\x1b[6nX", want: "X"},
	{name: "a high byte after a held wrapper's ESC, then a non-query", in: "\x1bPtmux;\x1b\xff[1mX", want: "\x1b[1mX"},
	{name: "a C0 after a held wrapper's ESC", in: "\x1bPtmux;\x1b\r[6nX", want: "\rX"},
	{name: "a lone ESC in a held wrapper settles a close owed", in: "\x1bPq#0\x1bPtmux;\x1b\x7f\x1b[6nX", want: "\x1bPq#0\x1b\x18X"},
	{name: "a lone ESC during the inner drop, after a pending inner ESC", in: "\x1bPtmux;\x1b\x1bP+q544e\x1b\x1b\x1b[6nX", want: "X"},
	// Any DCS header whose final byte is t starts a wrapper, whatever its
	// parameters and intermediates, as tmux reads one.
	{name: "a header with a parameter is a wrapper", in: "\x1bP1tmux;\x1b\x1b[31mX\x1b\\", want: "\x1bP1tmux;\x1b\x1b[31mX\x1b\\"},
	{name: "a header with an intermediate is a wrapper", in: "\x1bP$tmux;\x1b\x1b[6n\x1b\\", want: "\x1b\\"},
	// While "mux;" is matched, the DCS is held: a mismatch passes it as a
	// string, ST ends it cleanly and passes it, and any other end drops it.
	{name: "a header ending in t that isn't a wrapper passes", in: "\x1bPtmx;\x1b[6nX", want: "\x1bPtmx;\x1b\x18X"},
	{name: "a DEL in the match isn't a wrapper", in: "\x1bPtm\x7fux;\x1b\x1b[6nX\x1b\\", want: "\x1bPtm\x7fux;\x1b\x18X\x1b\\"},
	{name: "a DCS ending in t, ended by ST in the match, passes", in: "\x1bPtmu\x1b\\X", want: "\x1bPtmu\x1b\\X"},
	{name: "a DCS ending in t, ended by an ESC in the match", in: "\x1bPtmu\x1b[1mX", want: "\x1b[1mX"},
	{name: "a DCS ending in t, cancelled in the match", in: "\x1bPtm\x18X", want: "\x18X"},
	// The outer ST ends a wrapper still deciding, and a DEC terminal reads it
	// as the ST of the inner string it ends: a title passes, a colour query is
	// dropped, and a head it abandons is dropped with the wrapper.
	{name: "an empty wrapper passes", in: "\x1bPtmux;\x1b\\X", want: "\x1bPtmux;\x1b\\X"},
	{name: "a wrapper with no inner ESC passes", in: "\x1bPtmux;hi\x1b\\X", want: "\x1bPtmux;hi\x1b\\X"},
	{name: "a wrapped title ended by the outer ST passes", in: "\x1bPtmux;\x1b\x1b]0;t\x1b\\X", want: "\x1bPtmux;\x1b\x1b]0;t\x1b\\X"},
	{name: "a wrapped colour query ended by the outer ST", in: "\x1bPtmux;\x1b\x1b]11;?\x1b\\X", want: "X"},
	{name: "a wrapped graphics command ended by the outer ST passes", in: "\x1bPtmux;\x1b\x1b_Ga=T\x1b\\X", want: "\x1bPtmux;\x1b\x1b_Ga=T\x1b\\X"},
	{name: "a wrapped head abandoned by the outer ST", in: "\x1bPtmux;\x1b\x1b[6\x1b\\X", want: "X"},
	// A C0 the inner machine forwards from inside a head is executed by a DEC
	// terminal, so it goes out when the head is dropped, after a close owed;
	// when the head passes, it is already in place in the wrapper.
	{name: "a C0 inside a wrapped query goes out", in: "\x1bPtmux;\x1b\x1b[6\rnX\x1b\\", want: "\rX\x1b\\"},
	{name: "a C0 inside a wrapped non-query stays in place", in: "\x1bPtmux;\x1b\x1b[1\rmX\x1b\\", want: "\x1bPtmux;\x1b\x1b[1\rmX\x1b\\"},
	{name: "a C0 inside a wrapped query, with a close owed", in: "\x1bPq#0\x1bPtmux;\x1b\x1b[6\rnX", want: "\x1bPq#0\x1b\x18\rX"},
	// The inner drop's other ends: the outer ST, which ends both, and a
	// cancel after a pending inner ESC, which cancels the ESC that ended it.
	{name: "the outer ST ends an inner drop", in: "\x1bPtmux;\x1b\x1bP+q544e\x1b\\X", want: "X"},
	{name: "the outer ST after a pending inner ESC", in: "\x1bPtmux;\x1b\x1bP+q544e\x1b\x1b\x1b\\X", want: "X"},
	{name: "a cancel after a pending inner ESC", in: "\x1bPtmux;\x1b\x1bP+q544e\x1b\x1b\x18X", want: "\x1b\x18X"},
	// A first inner sequence that starts a wrapper is held while it matches,
	// as at the top, so one that ends abnormally there is dropped.
	{name: "a nested header ending in t, ended by an ESC", in: "\x1bPtmux;\x1b\x1bPtmu\x1b\x1b[6nX\x1b\\", want: "X\x1b\\"},
	// Found by the fuzz test: a held inner string that ends at its own ST,
	// raw ESC ESC \, ends cleanly in the decoded stream, so one that is no
	// query passes with the wrapper, though a DEC terminal ends it at the
	// first raw ESC.
	{name: "a wrapped DCS ending in t, ended by its own ST, passes", in: "\x1bPtmux;\x1b\x1bPtm\x1b\x1b\\", want: "\x1bPtmux;\x1b\x1bPtm\x1b\x1b\\"},
	{name: "a wrapped title ended by its own ST passes", in: "\x1bPtmux;\x1b\x1b]0;t\x1b\x1b\\\x1b\\X", want: "\x1bPtmux;\x1b\x1b]0;t\x1b\x1b\\\x1b\\X"},
	{name: "a wrapped graphics command ended by its own ST passes", in: "\x1bPtmux;\x1b\x1b_Ga=T\x1b\x1b\\\x1b\\X", want: "\x1bPtmux;\x1b\x1b_Ga=T\x1b\x1b\\\x1b\\X"},
	// Found by the fuzz test: a byte that ends what a wrapper holds is taken
	// as it would be within the bound, as at the top, so a cancel arriving
	// with the bound full still drops a wrapped string the ESC before it
	// ended.
	{name: "a cancel at a wrapper's bound", in: "\x1bPtmux;\x1b\x1b]0;" + strings.Repeat("0", 242) + "\x1b\x1b\x18X", want: "\x1b\x18X"},
	// Past its bound the hold goes out, and the wrapper passes byte for byte.
	{name: "an over-bound wrapper passes", in: "\x1bPtmux;\x1b\x1b]0;" + strings.Repeat("t", 300) + "\x1b\x1b\\\x1b\\X",
		want: "\x1bPtmux;\x1b\x1b]0;" + strings.Repeat("t", 300) + "\x1b\x1b\\\x1b\\X"},
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

	for _, q := range dcsQueryExamples {
		dcsCases = append(dcsCases, filterCase{name: fmt.Sprintf("query %q", q), in: "a" + q + "544e\x1b\\b", want: "ab"})
	}
	for _, c := range dcsPassExamples {
		dcsCases = append(dcsCases, filterCase{name: fmt.Sprintf("counter-case %q", c), in: c + "#0\x1b\\", want: c + "#0\x1b\\"})
	}
	filterCases = append(filterCases, dcsCases...)

	for _, q := range apcQueryExamples {
		apcCases = append(apcCases,
			filterCase{name: fmt.Sprintf("query %q", q), in: "a\x1b_G" + q + ";AAAA\x1b\\b", want: "ab"},
			filterCase{name: fmt.Sprintf("query %q at a BEL", q), in: "a\x1b_G" + q + "\x07X;AAAA\x1b\\b", want: "ab"})
	}
	for _, c := range apcPassExamples {
		apcCases = append(apcCases, filterCase{name: fmt.Sprintf("counter-case %q", c), in: "\x1b_G" + c + ";AAAA\x1b\\", want: "\x1b_G" + c + ";AAAA\x1b\\"})
	}
	filterCases = append(filterCases, apcCases...)
	filterCases = append(filterCases, wrapperCases...)
}

// A DCS whose header isn't a query streams: its payload goes out during the
// write that brings it, and nothing is held but an ESC that may begin ST, so
// a sixel of any size costs the filter nothing. A query's payload is dropped
// as it streams, and nothing is held but its header.
func TestTerminalQueryFilter_StreamsADCSPayload(t *testing.T) {
	const size, chunk = 64 << 10, 4 << 10
	body := strings.Repeat("#0;2;0;0;0#0!10~-", size/16)[:size-1]

	var out bytes.Buffer
	f := NewTerminalQueryFilter(&out)
	_, err := f.Write([]byte("\x1bPq"))
	require.NoError(t, err)
	require.Equal(t, "\x1bPq", out.String(), "a header that isn't a query goes out at its final byte")

	// The last write ends with ST's ESC, which is held until the '\'.
	sixel := body + "\x1b"
	for at := 0; at < len(sixel); at += chunk {
		w := sixel[at:min(at+chunk, len(sixel))]
		out.Reset()
		_, err := f.Write([]byte(w))
		require.NoError(t, err)
		require.Equal(t, strings.TrimSuffix(w, "\x1b"), out.String(), "the write at %d", at)
		require.LessOrEqual(t, len(f.Pending()), 1, "after the write at %d", at)
	}
	require.Equal(t, "\x1b", string(f.Pending()))
	out.Reset()
	_, err = f.Write([]byte("\\"))
	require.NoError(t, err)
	require.Equal(t, "\x1b\\", out.String())
	require.Empty(t, f.Pending())

	out.Reset()
	query := "\x1bP+q" + body + "\x1b\\"
	for at := 0; at < len(query); at += chunk {
		_, err := f.Write([]byte(query[at:min(at+chunk, len(query))]))
		require.NoError(t, err)
		require.LessOrEqual(t, len(f.Pending()), len("\x1bP+q\x1b"), "after the write at %d", at)
	}
	require.Zero(t, out.Len(), "a query of the same size is dropped whole")
	require.Empty(t, f.Pending())
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

// continuationCheck checks that a joiner at any boundary ends where the
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

// SettleDrop hands back exactly where a dropped string ends, for every
// resume point, at the top and in a wrapper: n into p, or the raw ESCs the
// filter carried from the last write, which the stream resumes from.
func TestTerminalQueryFilter_SettleDrop(t *testing.T) {
	const wrapped = "\x1bPtmux;\x1b\x1bP+q544e"
	for _, c := range []struct {
		before, p string
		n         int
		raw       string
		done      bool
	}{
		{"\x1bP+q54", "4e", 2, "", false},
		{"\x1bP+q544e", "\x1b\\hello", 2, "", true}, // ST: after the '\'
		{"\x1bP+q544e\x1b", "\\hello", 1, "", true},
		{"\x1bP+q544e", "\x18hello", 0, "", true}, // CAN: at it
		{"\x1bP+q544e", "\x1ahello", 0, "", true},
		{"\x1bP+q544e", "xy\x1bZhello", 2, "", true}, // an ESC that isn't ST: at it
		{"\x1bP+q544e\x1b", "Zhello", 0, "\x1b", true},
		{"\x1bP+q544e\x1b", "\x1b[6n", 0, "\x1b", true},
		{"\x1bP+q544e\x1b", "\x18hello", 0, "\x1b", true},
		{"\x1bPtmux;\x1b\x1b_Ga=q;AAAA", "\x1b\x1b\\\x1b\\hello", 3, "", true}, // an inner ST
		{"\x1bPtmux;\x1b\x1b_Ga=q;AAAA\x1b", "\x1b\\\x1b\\hello", 2, "", true},
		{"\x1bPtmux;\x1b\x1b_Ga=q;AAAA\x1b\x1b", "\\\x1b\\hello", 1, "", true},
		{wrapped, "\x18hello", 0, "", true}, // an inner CAN
		{wrapped + "\x1b\x1b", "\x18hello", 0, "\x1b", true},
		{wrapped, "\x1b\x1b[6n", 1, "", true}, // an inner ESC: at its pair's second raw ESC
		{wrapped + "\x1b", "\x1b[6n", 0, "", true},
		{wrapped + "\x1b\x1b", "[6nhello\x1b\\", 0, "\x1b", true},
		{wrapped, "\x1b\\X", 2, "", true}, // the outer ST
		{wrapped + "\x1b", "\\X", 1, "", true},
		{wrapped, "\x1b[6n", 0, "", true}, // a lone raw ESC x: at that ESC
		{wrapped + "\x1b", "[6n", 0, "\x1b", true},
		{wrapped + "\x1b", "\x18X", 0, "\x1b", true},
		{wrapped, "\x1b\x1b\x1b\x1b[6n", 1, "", true}, // an inner ESC after a pending one: at the pending one's
		{wrapped + "\x1b\x1b", "\x1b\x1b[6n", 0, "\x1b", true},
		{wrapped + "\x1b\x1b\x1b", "\x1b[6n", 0, "\x1b\x1b", true},
	} {
		var out bytes.Buffer
		f := NewTerminalQueryFilter(&out)
		_, _ = f.Write([]byte(c.before))
		require.True(t, f.Dropping(), "%q", c.before)
		n, raw, done := f.SettleDrop([]byte(c.p))
		require.Equal(t, c.n, n, "%q|%q", c.before, c.p)
		require.Equal(t, c.raw, string(raw), "%q|%q", c.before, c.p)
		require.Equal(t, c.done, done, "%q|%q", c.before, c.p)
		require.Equal(t, !c.done, f.Dropping(), "%q|%q", c.before, c.p)
		require.Zero(t, out.Len(), "nothing of a drop goes out: %q|%q", c.before, c.p)
	}
}

// At every boundary of every exact-bytes case where the filter is dropping,
// SettleDrop agrees with the filter's own drop: the stream it hands back,
// raw and then p from n, is the input from a raw point no later than p's
// start, and filtered from ground it gives what the filter gives for the
// input whole. So the resume point is neither inside the string nor past
// anything after it.
func TestTerminalQueryFilter_SettleDropResumesWhereTheFilterDoes(t *testing.T) {
	settled := 0
	for _, c := range filterCases {
		whole := filterAll(c.in)
		for k := 0; k <= len(c.in); k++ {
			var out bytes.Buffer
			f := NewTerminalQueryFilter(&out)
			_, _ = f.Write([]byte(c.in[:k]))
			if !f.Dropping() {
				continue
			}
			settled++
			emitted := out.Len()
			p := []byte(c.in[k:])
			n, raw, done := f.SettleDrop(p)
			require.Equal(t, emitted, out.Len(), "%s: SettleDrop emitted, split at %d", c.name, k)
			if !done {
				require.Equal(t, len(p), n, "%s: split at %d", c.name, k)
				require.Nil(t, raw, "%s: split at %d", c.name, k)
				require.Equal(t, whole, out.String(), "%s: the input ends in the drop, split at %d", c.name, k)
				continue
			}
			require.False(t, f.Dropping(), "%s: split at %d", c.name, k)
			if len(raw) > 0 {
				require.Zero(t, n, "%s: split at %d", c.name, k)
				require.LessOrEqual(t, len(raw), k, "%s: split at %d", c.name, k)
				require.Equal(t, c.in[k-len(raw):k], string(raw), "%s: raw is the input's own bytes, split at %d", c.name, k)
			}
			g := NewTerminalQueryFilter(&out)
			_, _ = g.Write(raw)
			_, _ = g.Write(p[n:])
			require.Equal(t, whole, out.String(), "%s: resumed from ground, split at %d", c.name, k)
		}
	}
	require.NotZero(t, settled)
}

// A row marked kitty is one whose output a kitty guest could read differently
// from a DEC one; under kitty's string ends it still asks nothing. The filter's
// output is parsed, not the row's want, so a filter that breaks the row fails
// here too.
func TestTerminalQueryFilter_KittyRowsAskNothing(t *testing.T) {
	for _, c := range filterCases {
		if !c.kitty {
			continue
		}
		out := filterAll(c.in)
		for _, ev := range refParse(refKitty, []byte(out)) {
			require.False(t, refQuery(refKitty, ev), "%s: %q asks %v under kitty", c.name, out, ev)
		}
	}
}

// Every exact-bytes case passes the oracle as it stands, the ones the fuzz
// domain leaves out included. A sequence past its bound passes unclassified,
// so a query there is a stated limit, but a non-query must still reach the
// terminal with the effect it had, and only these rows check that: the fuzz
// never takes a sequence past its bound. A row marked limit is left out: its
// input is past a stated limit where a query passes on purpose, such as one
// nested in a wrapper inside a wrapper.
func TestTerminalQueryFilter_CasesPassTheOracle(t *testing.T) {
	for _, c := range filterCases {
		if c.limit {
			continue
		}
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
