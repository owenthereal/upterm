//go:build !windows

package command

import (
	"os"
	"testing"

	ptylib "github.com/creack/pty"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func openPty(t *testing.T) (ptmx, tty *os.File) {
	t.Helper()
	ptmx, tty, err := ptylib.Open()
	require.NoError(t, err)
	t.Cleanup(func() { _ = ptmx.Close(); _ = tty.Close() })
	return ptmx, tty
}

// takeTerminalFor is the command's TakeTerminal on f. owned is always true:
// a pty pair is nobody's foreground, and what is under test is the flush.
func takeTerminalFor(f *os.File) func() error {
	raw := &rawTerminal{f: f, owned: func(*os.File) bool { return true }}
	return func() error { return takeTerminal(raw) }
}

func TestTakeTerminalFlushesTypedAheadInput(t *testing.T) { // Review Focus 5, D6
	ptmx, tty := openPty(t)
	_, _ = ptmx.Write([]byte("typed-before-join\n"))
	take := takeTerminalFor(tty) // raw.enter + flush
	require.NoError(t, take())
	readable := make(chan int, 1)
	go func() { b := make([]byte, 64); n, _ := tty.Read(b); readable <- n }()
	_, _ = ptmx.Write([]byte("x"))
	require.Equal(t, 1, <-readable) // only what was typed after the flush
}

// The passphrase prompt turns echo off and nothing else, and its restore
// puts the terminal back as it was.
func TestEchoOffClearsEchoAndRestoresIt(t *testing.T) {
	_, tty := openPty(t)
	fd := int(tty.Fd())
	before, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	require.NoError(t, err)
	require.NotZero(t, before.Lflag&unix.ECHO, "a new pty echoes")

	restore, err := echoOff(tty)()
	require.NoError(t, err)
	during, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	require.NoError(t, err)
	require.Zero(t, during.Lflag&unix.ECHO)
	require.NotZero(t, during.Lflag&unix.ICANON, "the line is still read whole")
	require.NotZero(t, during.Lflag&unix.ISIG, "Ctrl-C is still SIGINT")

	restore()
	after, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	require.NoError(t, err)
	require.Equal(t, *before, *after)
}
