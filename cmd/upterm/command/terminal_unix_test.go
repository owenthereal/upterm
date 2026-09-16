//go:build !windows

package command

import (
	"context"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"

	ptylib "github.com/creack/pty"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

// Test_Command_RestoresTheTerminalOnlyWhenStillOwned covers the end of the
// terminal's life rather than the start of it. withRawTerminal puts a
// terminal it owns into raw mode and arms the restore in the same breath,
// but by the time fn returns the host may have been backgrounded -- ^Z then
// bg, or a shell that moved on -- and SIGTTOU is ignored, so the restoring
// tcsetattr succeeds against whatever holds the terminal now, writing this
// session's stale termios over theirs.
//
// Ownership is injected because job control cannot be staged in-process: a
// pty pair opened here is the controlling terminal of no session, so the
// real ownsTerminal answers false for it either way and the transition the
// rule is about never happens.
func Test_Command_RestoresTheTerminalOnlyWhenStillOwned(t *testing.T) {
	for _, tc := range []struct {
		name string
		// owns decides, at the point withRawTerminal asks on the way out,
		// whether this process still owns the terminal.
		owns        func() func(*os.File) bool
		wantRestore bool
	}{
		{
			name:        "the host is still in the foreground",
			owns:        func() func(*os.File) bool { return func(*os.File) bool { return true } },
			wantRestore: true,
		},
		{
			name:        "the host lost the foreground while the command ran",
			owns:        func() func(*os.File) bool { return func(*os.File) bool { return false } },
			wantRestore: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ptmx, tty, err := ptylib.Open()
			require.NoError(t, err)
			defer func() { _ = ptmx.Close() }()
			defer func() { _ = tty.Close() }()

			fd := int(tty.Fd())
			original, err := term.GetState(fd)
			require.NoError(t, err)

			// What raw looks like on this pty, taken from MakeRaw itself and
			// then undone. Hard-coding termios flags here would be asserting
			// against a copy of golang.org/x/term rather than against the fact
			// under test, which is only "raw was applied and then left alone".
			previous, err := term.MakeRaw(fd)
			require.NoError(t, err)
			raw, err := term.GetState(fd)
			require.NoError(t, err)
			require.NoError(t, term.Restore(fd, previous))

			require.NoError(t, withRawTerminal(tty, tc.owns(), func() error { return nil }))

			got, err := term.GetState(fd)
			require.NoError(t, err)

			if tc.wantRestore {
				require.True(t, reflect.DeepEqual(original, got),
					"a terminal we still own must be handed back the way we found it")
				return
			}
			require.True(t, reflect.DeepEqual(raw, got),
				"a terminal we no longer own must be left to whoever holds it now")
		})
	}
}

func TestClassifyTerminalOnAPty(t *testing.T) {
	ptmx, tty, err := ptylib.Open()
	require.NoError(t, err)
	defer func() { _ = ptmx.Close(); _ = tty.Close() }()
	require.NoError(t, ptylib.Setsize(ptmx, &ptylib.Winsize{Rows: 43, Cols: 132}))

	// stdout is a terminal, stdin is one we own (injected): fully interactive.
	lt := classifyTerminal(tty, tty, func(*os.File) bool { return true }, "xterm-256color")
	require.NotNil(t, lt.pty)
	require.Equal(t, "xterm-256color", lt.pty.Term)
	require.Equal(t, termsize.Size{Cols: 132, Rows: 43}, lt.pty.Size)
	require.NotNil(t, lt.stdin)
	require.True(t, lt.rawMode)
	require.Equal(t, tty, lt.sizeOf)

	// stdout is a terminal, stdin is not ours: `upterm host … &`. A pty
	// viewer that follows the terminal's size and reads nothing.
	lt = classifyTerminal(tty, tty, func(*os.File) bool { return false }, "xterm")
	require.NotNil(t, lt.pty)
	require.Nil(t, lt.stdin)
	require.False(t, lt.rawMode)
	require.Equal(t, tty, lt.sizeOf)
}

func TestWatchResizeReportsSIGWINCH(t *testing.T) {
	ptmx, tty, err := ptylib.Open()
	require.NoError(t, err)
	defer func() { _ = ptmx.Close(); _ = tty.Close() }()
	require.NoError(t, ptylib.Setsize(ptmx, &ptylib.Winsize{Rows: 24, Cols: 80}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sizes := watchResize(ctx, tty)

	require.NoError(t, ptylib.Setsize(ptmx, &ptylib.Winsize{Rows: 30, Cols: 100}))
	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGWINCH))
	select {
	case size := <-sizes:
		require.Equal(t, termsize.Size{Cols: 100, Rows: 30}, size)
	case <-time.After(5 * time.Second):
		t.Fatal("SIGWINCH did not produce a size")
	}
}
