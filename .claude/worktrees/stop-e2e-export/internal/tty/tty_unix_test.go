//go:build !windows

package tty

import (
	"testing"

	ptylib "github.com/creack/pty"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/require"
)

// An in-process pty pair is a terminal, has a size, and is the controlling
// terminal of no session: Size answers, Owned does not, and the pgrp query
// fails rather than lying. The foreground case is observable only in a real
// session, which is what internal/e2e is for.
func TestSizeAndOwnershipOnAPtyPair(t *testing.T) {
	ptmx, tty, err := ptylib.Open()
	require.NoError(t, err)
	defer func() { _ = ptmx.Close(); _ = tty.Close() }()
	require.NoError(t, ptylib.Setsize(ptmx, &ptylib.Winsize{Rows: 43, Cols: 132}))

	size, err := Size(tty)
	require.NoError(t, err)
	require.Equal(t, termsize.Size{Cols: 132, Rows: 43}, size)

	require.False(t, Owned(tty))
	_, err = ForegroundProcessGroup(int(tty.Fd()))
	require.Error(t, err, "TIOCGPGRP on a terminal that is nobody's controlling terminal fails with ENOTTY")
}
