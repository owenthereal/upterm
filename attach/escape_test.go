package attach

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEscapeFilter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     []string // fed one element per Feed, so state across writes is exercised
		out    string
		detach bool
	}{
		{name: "tilde dot at the very start detaches", in: []string{"~."}, out: "", detach: true},
		{name: "tilde dot after a newline detaches", in: []string{"ls\n~."}, out: "ls\n", detach: true},
		{name: "tilde dot after a carriage return detaches", in: []string{"ls\r~."}, out: "ls\r", detach: true},
		{name: "tilde dot mid-line passes through", in: []string{"echo ~."}, out: "echo ~.", detach: false},
		{name: "tilde tilde sends one tilde", in: []string{"\n~~"}, out: "\n~", detach: false},
		{name: "tilde then another byte sends both", in: []string{"\n~/bin"}, out: "\n~/bin", detach: false},
		{name: "split across writes", in: []string{"\n~", "."}, out: "\n", detach: true},
		{name: "split across writes, not an escape", in: []string{"\n~", "x"}, out: "\n~x", detach: false},
		{name: "bytes after the detach are dropped", in: []string{"\n~.rm -rf /"}, out: "\n", detach: true},
		{name: "a tilde after a tilde-x is not at line start", in: []string{"\n~x~."}, out: "\n~x~.", detach: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := NewEscapeFilter('~')
			var out []byte
			var detached bool
			for _, chunk := range tc.in {
				o, d := f.Feed([]byte(chunk))
				out = append(out, o...)
				if d {
					detached = true
					break
				}
			}
			require.Equal(t, tc.out, string(out))
			require.Equal(t, tc.detach, detached)
		})
	}
}

func TestEscapeFilterFlushReleasesAPendingEscape(t *testing.T) {
	f := NewEscapeFilter('~')
	out, detach := f.Feed([]byte("\n~"))
	require.Equal(t, "\n", string(out))
	require.False(t, detach)
	require.Equal(t, "~", string(f.Flush()), "a held escape byte is real input if nothing follows it")
	require.Empty(t, f.Flush())
}

func TestEscapeFilterDisabled(t *testing.T) {
	f := NewEscapeFilter(0)
	out, detach := f.Feed([]byte("\n~."))
	require.Equal(t, "\n~.", string(out))
	require.False(t, detach)
}
