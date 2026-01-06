package io

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
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
			name:     "passes regular CSI sequences",
			input:    []byte("\x1b[2J"), // clear screen
			expected: []byte("\x1b[2J"),
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
			name:     "OSC 4 palette query (not 10/11/12, should pass)",
			input:    []byte("\x1b]4;1;?\x07"),
			expected: []byte("\x1b]4;1;?\x07"),
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
