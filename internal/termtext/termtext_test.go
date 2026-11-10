package termtext

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The text a terminal is given keeps its printable characters and its line
// feeds, a carriage return before each with crlf, and has every control
// character and every byte that isn't UTF-8 replaced, so nothing in it acts on
// the terminal. A U+FFFD already there is left as it is.
func TestSanitizeMatchesRestrictedText(t *testing.T) {
	const message = "work is not running (last seen unknown).\n"
	for _, tc := range []struct {
		name string
		in   string
		crlf bool
		want string
	}{
		{"plain", message, false, message},
		{"plain for a terminal", message, true, strings.ReplaceAll(message, "\n", "\r\n")},
		{"nothing that controls a terminal", "\x1b[31mwork\x1b]0;x\x07 is\r reconnecting\x9b\xff.\n", false, "�[31mwork�]0;x� is� reconnecting��.\n"},
		{"nothing that controls a terminal, for a terminal", "\x1b[31mwork\x1b]0;x\x07 is\r reconnecting\x9b\xff.\n", true, "�[31mwork�]0;x� is� reconnecting��.\r\n"},
		{"a carriage return before a line feed", "a\r\nb", true, "a�\r\nb"},
		{"lines kept", "line one\nline two\n\nend", false, "line one\nline two\n\nend"},
		{"every control character", "\x00\x01\x08\x09\x0b\x0c\x0d\x1f\x7f\u0080\u009f", false, strings.Repeat("�", 11)},
		{"invalid UTF-8", "a\xc3b\xe2\x82c\xed\xa0\x80d\xf8e", false, "a�b��c���d�e"},
		{"printable beyond ASCII", "café ✓ 日本", false, "café ✓ 日本"},
		{"a replacement character already there", "a�b", true, "a�b"},
		{"empty", "", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, string(Sanitize([]byte(tc.in), tc.crlf)))
		})
	}
}
