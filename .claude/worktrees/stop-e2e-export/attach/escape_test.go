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
			f := NewEscapeFilter('~', true)
			var out []byte
			var detached bool
			for _, chunk := range tc.in {
				o, action := f.Feed([]byte(chunk))
				out = append(out, o...)
				if action == EscapeDetach {
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
	f := NewEscapeFilter('~', true)
	out, action := f.Feed([]byte("\n~"))
	require.Equal(t, "\n", string(out))
	require.Equal(t, EscapeNone, action)
	require.Equal(t, "~", string(f.Flush()), "a held escape byte is real input if nothing follows it")
	require.Empty(t, f.Flush())
}

func TestEscapeFilterDisabled(t *testing.T) {
	f := NewEscapeFilter(0, true)
	out, action := f.Feed([]byte("\n~."))
	require.Equal(t, "\n~.", string(out))
	require.Equal(t, EscapeNone, action)
}

func TestEscapeFilter_SuspendAtLineStart(t *testing.T) {
	f := NewEscapeFilter('~', true)
	out, action := f.Feed([]byte("hi\r~\x1a"))
	require.Equal(t, EscapeSuspend, action)
	require.Equal(t, "hi\r", string(out))

	// Back at a line start afterwards: the suspend consumed the sequence and
	// did not leave the filter mid-line, so ~. works immediately on resume.
	out, action = f.Feed([]byte("~."))
	require.Equal(t, EscapeDetach, action)
	require.Empty(t, string(out))
}

func TestEscapeFilter_SuspendDisabledPassesBothBytes(t *testing.T) {
	f := NewEscapeFilter('~', false)
	out, action := f.Feed([]byte("\r~\x1a"))
	require.Equal(t, EscapeNone, action)
	require.Equal(t, "\r~\x1a", string(out))
}

func TestEscapeFilter_SuspendKeepsProcessingTheRestOfTheRead(t *testing.T) {
	// Bytes typed after the sequence, in the same read, are still the
	// session's. They are queued before the process stops and delivered when
	// it resumes, which is the same thing from the session's side.
	f := NewEscapeFilter('~', true)
	out, action := f.Feed([]byte("\r~\x1als\r"))
	require.Equal(t, EscapeSuspend, action)
	require.Equal(t, "\rls\r", string(out))
}

func TestEscapeFilter_DetachWinsOverAnEarlierSuspendInTheSameRead(t *testing.T) {
	// Documented precedence, not a preference: a detach returns at once
	// because bytes after it belong to nobody, and that return is what drops
	// the suspend. Two escape sequences in one 4096-byte read do not come
	// from a keyboard.
	f := NewEscapeFilter('~', true)
	out, action := f.Feed([]byte("\r~\x1a\r~."))
	require.Equal(t, EscapeDetach, action)
	require.Equal(t, "\r\r", string(out))
}
