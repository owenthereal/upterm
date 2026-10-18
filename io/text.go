package io

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// PlainText is s as text a terminal draws and never acts on: every control
// character (0x00-0x1F, DEL and 0x80-0x9F) and every byte that isn't UTF-8
// comes out as '?'. It is for text someone else chose that is printed into a
// terminal, such as a guest's SSH version, which its client sends as it
// likes: written raw, an escape sequence in it would be the terminal's to
// act on.
func PlainText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}
