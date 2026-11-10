// Package termtext makes text someone else chose safe to write to a terminal,
// whole lines kept.
package termtext

import (
	"bytes"
	"unicode"
	"unicode/utf8"
)

// Sanitize is text as a terminal may be given it: its printable text and line
// feeds, with a carriage return before each line feed when crlf is set, and
// every other control character, and every byte that isn't UTF-8, replaced
// with U+FFFD, so that nothing in it can control the terminal.
func Sanitize(text []byte, crlf bool) []byte {
	var b bytes.Buffer
	for len(text) > 0 {
		r, size := utf8.DecodeRune(text)
		text = text[size:]
		switch {
		case r == '\n':
			if crlf {
				b.WriteByte('\r')
			}
			b.WriteByte('\n')
		case r == utf8.RuneError && size == 1, unicode.IsControl(r):
			b.WriteRune(utf8.RuneError)
		default:
			b.WriteRune(r)
		}
	}
	return b.Bytes()
}
