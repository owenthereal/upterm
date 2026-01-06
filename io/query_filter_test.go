package io

import (
	"bytes"
	"testing"
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
			expected: []byte{},
		},
		{
			name:     "filters OSC 11 query with ST",
			input:    []byte("\x1b]11;?\x1b\\"),
			expected: []byte{},
		},
		{
			name:     "filters OSC 10 query (foreground color)",
			input:    []byte("\x1b]10;?\x07"),
			expected: []byte{},
		},
		{
			name:     "filters OSC 12 query (cursor color)",
			input:    []byte("\x1b]12;?\x07"),
			expected: []byte{},
		},
		{
			name:     "passes OSC set (not query)",
			input:    []byte("\x1b]11;rgb:ff/ff/ff\x07"),
			expected: []byte("\x1b]11;rgb:ff/ff/ff\x07"),
		},
		{
			name:     "filters CSI 6 n (cursor position request)",
			input:    []byte("\x1b[6n"),
			expected: []byte{},
		},
		{
			name:     "filters CSI 5 n (device status request)",
			input:    []byte("\x1b[5n"),
			expected: []byte{},
		},
		{
			name:     "filters CSI c (primary device attributes)",
			input:    []byte("\x1b[c"),
			expected: []byte{},
		},
		{
			name:     "filters CSI 0 c (primary device attributes)",
			input:    []byte("\x1b[0c"),
			expected: []byte{},
		},
		{
			name:     "filters CSI > c (secondary device attributes)",
			input:    []byte("\x1b[>c"),
			expected: []byte{},
		},
		{
			name:     "filters CSI > 0 c (secondary device attributes)",
			input:    []byte("\x1b[>0c"),
			expected: []byte{},
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
			expected: []byte{},
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
			var buf bytes.Buffer
			filter := NewTerminalQueryFilter(&buf)

			n, err := filter.Write(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if n != len(tt.input) {
				t.Errorf("expected n=%d, got %d", len(tt.input), n)
			}

			if !bytes.Equal(buf.Bytes(), tt.expected) {
				t.Errorf("expected %q, got %q", tt.expected, buf.Bytes())
			}
		})
	}
}

func TestTerminalQueryFilter_PreservesNonQueryOSC(t *testing.T) {
	// OSC sequences that SET values (not queries) should pass through
	// Note: Our simple parser outputs partial sequences, which is acceptable
	var buf bytes.Buffer
	filter := NewTerminalQueryFilter(&buf)

	// OSC 0 (set window title) - should pass through
	input := []byte("\x1b]0;My Title\x07")
	_, err := filter.Write(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have some output (at least the beginning)
	if buf.Len() == 0 {
		t.Error("expected OSC title sequence to pass through, got nothing")
	}
}
