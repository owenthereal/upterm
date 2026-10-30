package attach

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestApprovalTerminalReplies(t *testing.T) {
	replies := []string{"\x1b[?1;2c", "\x1b[>0;10;1c", "\x1b[12;34R", "\x1b[?2004;1$y", "\x1b]10;rgb:ffff/0000/0000\a", "\x1b]52;c;ZyBBQkNE\x1b\\", "\x1bP1$r g ABCD\r\x1b\\", "\x1b_reply g ABCD\r\x1b\\"}
	for _, reply := range replies {
		for split := 0; split <= len(reply); split++ {
			var p approvalInput
			var keys, program []byte
			for _, chunk := range []string{reply[:split], reply[split:]} {
				out, k := p.feed([]byte(chunk))
				program = append(program, out...)
				keys = append(keys, k...)
			}
			require.Equal(t, reply, string(program))
			require.Empty(t, keys)
		}
	}
	for _, encoded := range []string{"\x1b[103u", "\x1b[103;1:1u", "\x1b[27;1;103~"} {
		for split := 0; split <= len(encoded); split++ {
			var p approvalInput
			_, a := p.feed([]byte(encoded[:split]))
			_, b := p.feed([]byte(encoded[split:]))
			require.Equal(t, "g", string(append(a, b...)))
		}
	}
	for _, ignored := range []string{"\x1b[103;1:3u", "\x1b[A", "\x1b[15~", "\x1bOP"} {
		var p approvalInput
		out, keys := p.feed([]byte(ignored))
		require.Empty(t, out)
		require.Empty(t, keys)
	}
}

func TestApprovalInputIsolation(t *testing.T) {
	paste := "\x1b[200~g ABCD\r\x1b[201~"
	for split := 0; split <= len(paste); split++ {
		var p approvalInput
		_, a := p.feed([]byte(paste[:split]))
		_, b := p.feed([]byte(paste[split:]))
		require.Empty(t, append(a, b...))
	}
	for _, marker := range []string{"\x1b]52;c;", "\x1bP", "\x1b_"} {
		var p approvalInput
		out, keys := p.feed([]byte(marker + strings.Repeat("x", 9000) + "g ABCD\r"))
		require.Empty(t, out)
		require.Empty(t, keys)
		require.LessOrEqual(t, len(p.sequence), 8192)
		out, keys = p.feed([]byte("\x1b\\"))
		require.Empty(t, out)
		require.Empty(t, keys)
		_, keys = p.feed([]byte("c ABCD\r"))
		require.Equal(t, "c ABCD\r", string(keys))
	}
}

func TestApprovalEscapeCompatibility(t *testing.T) {
	for _, esc := range []byte{'~', '!'} {
		for _, literal := range []bool{false, true} {
			input := string(esc) + "ag ABCD\r"
			want := ""
			action := EscapeApproval
			if literal {
				input = string(esc) + input
				want = string(esc) + "ag ABCD\r"
				action = EscapeNone
			}
			for split := 0; split <= len(input); split++ {
				f := NewEscapeFilter(esc, true, WithApproval())
				a, aa := f.Feed([]byte(input[:split]))
				b, bb := f.Feed([]byte(input[split:]))
				if aa == EscapeApproval {
					b = nil
				}
				require.Equal(t, want, string(append(a, b...)))
				if aa == EscapeNone {
					aa = bb
				}
				require.Equal(t, action, aa)
			}
		}
	}
	raw := []byte("~ag ABCD\r\x1b[200~")
	f := NewEscapeFilter(0, true, WithApproval())
	out, action := f.Feed(raw)
	require.Equal(t, raw, out)
	require.Equal(t, EscapeNone, action)
}

func TestApprovalEncodedConfirmation(t *testing.T) {
	for _, encoded := range []struct{ input, want string }{
		{"\x1b[97;2u", "A"}, {"\x1b[97:65;2:1u", "A"}, {"\x1b[122;5u", "\x1a"}, {"\x1b[27;5;122~", "\x1a"},
		{"\x1b[103u\x1b[32u\x1b[97;2u\x1b[98;2u\x1b[99;2u\x1b[100;2u\x1b[13u", "g ABCD\r"},
	} {
		for split := 0; split <= len(encoded.input); split++ {
			var p approvalInput
			_, a := p.feed([]byte(encoded.input[:split]))
			_, b := p.feed([]byte(encoded.input[split:]))
			require.Equal(t, encoded.want, string(append(a, b...)))
		}
	}
}
