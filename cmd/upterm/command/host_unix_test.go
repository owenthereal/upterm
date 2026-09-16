//go:build !windows

package command

import (
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

	cases := []struct {
		name    string
		accept  bool
		stdin   *os.File
		stdout  *os.File
		refused bool
	}{
		{name: "pipe stdin with pty stdout", stdin: pr, stdout: tty, refused: true},
		{name: "pty stdin with pipe stdout", stdin: tty, stdout: pw, refused: true},
		{name: "pty on both", stdin: tty, stdout: tty},
		{name: "accept with pipes on both", accept: true, stdin: pr, stdout: pw},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := confirmationTerminalError(c.accept, c.stdin, c.stdout)
			if !c.refused {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, "interactive confirmation requires a terminal on stdin and stdout")
		})
	}
}
