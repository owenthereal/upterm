//go:build !windows

package command

import (
	"io"
	"testing"
	"time"

	ptylib "github.com/creack/pty"
	"github.com/stretchr/testify/require"
)

// On a terminal the cursor is hidden for the download's progress bar, and
// shown again afterwards.
func TestCursorIsHiddenOnATerminalAndShownAgain(t *testing.T) {
	ptmx, tty, err := ptylib.Open()
	require.NoError(t, err)
	t.Cleanup(func() { _ = ptmx.Close(); _ = tty.Close() })

	show := hideCursorIfTerminal(tty)
	show()

	const want = "\033[?25l\033[?25h"
	got := make([]byte, len(want))
	read := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(ptmx, got)
		read <- err
	}()

	select {
	case err := <-read:
		require.NoError(t, err)
		require.Equal(t, want, string(got))
	case <-time.After(5 * time.Second):
		t.Fatal("the terminal was sent no cursor escapes")
	}
}

func TestProgressBarOnATerminal(t *testing.T) {
	ptmx, tty, err := ptylib.Open()
	require.NoError(t, err)
	t.Cleanup(func() { _ = ptmx.Close(); _ = tty.Close() })

	require.NotNil(t, downloadProxy(tty))
}
