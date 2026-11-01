//go:build !windows

package command

import (
	"io"
	"os"
	"testing"

	ptylib "github.com/creack/pty"
	"github.com/stretchr/testify/require"
)

// The prompt draws on stdout and reads its answer from stdin, so the guard has
// to look at both. One pty pair and one pipe pair cover every case: the slave
// end of the pty is what a shell hands a foreground process, and a pipe end is
// what a redirect or a CI runner hands it.
func Test_confirmationTerminalError(t *testing.T) {
	ptmx, tty, err := ptylib.Open()
	require.NoError(t, err)
	t.Cleanup(func() { _ = ptmx.Close(); _ = tty.Close() })

	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = pr.Close(); _ = pw.Close() })

	const (
		refused         = "upterm host needs a terminal to ask before starting; pass --accept to start without asking"
		refusedDetached = "--detach needs --accept when there is no terminal to ask in (it also lets guests transfer files without asking)"
	)
	cases := []struct {
		name           string
		accept, detach bool
		stdin          *os.File
		stdout         *os.File
		want           string
	}{
		{name: "pipe stdin with pty stdout", stdin: pr, stdout: tty, want: refused},
		{name: "pty stdin with pipe stdout", stdin: tty, stdout: pw, want: refused},
		{name: "pty on both", stdin: tty, stdout: tty},
		{name: "accept with pipes on both", accept: true, stdin: pr, stdout: pw},
		{name: "detach with pty on both", detach: true, stdin: tty, stdout: tty},
		{name: "detach with pipe stdin", detach: true, stdin: pr, stdout: tty, want: refusedDetached},
		{name: "detach with pipe stdout", detach: true, stdin: tty, stdout: pw, want: refusedDetached},
		{name: "detach and accept with pipes on both", accept: true, detach: true, stdin: pr, stdout: pw},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := confirmationTerminalError(c.accept, c.detach, c.stdin, c.stdout)
			if c.want == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, c.want)
		})
	}
}

// The key hint is for whoever is at the keyboard, so it goes to whichever of
// stderr and stdout is the terminal, stderr first; with neither a terminal
// there is nobody at one to tell.
func TestHintGoesToTheTerminalWhenStderrIsAFile(t *testing.T) {
	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr")
	require.NoError(t, err)
	t.Cleanup(func() { _ = stderrFile.Close() })
	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout")
	require.NoError(t, err)
	t.Cleanup(func() { _ = stdoutFile.Close() })
	_, tty := openPty(t)

	require.Equal(t, io.Writer(tty), hintOut(stderrFile, tty))
	require.Equal(t, io.Writer(tty), hintOut(tty, stderrFile))
	require.Equal(t, io.Discard, hintOut(stderrFile, stdoutFile))
}
