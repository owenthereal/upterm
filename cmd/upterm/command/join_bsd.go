//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package command

import (
	"os"

	"golang.org/x/sys/unix"
)

// The termios requests, as golang.org/x/term names them for these systems.
const (
	ioctlReadTermios  = unix.TIOCGETA
	ioctlWriteTermios = unix.TIOCSETA
)

// fread is FREAD from <sys/fcntl.h>, which golang.org/x/sys doesn't name:
// given to TIOCFLUSH, it selects the input queue.
const fread = 1

// flushInput drops what was typed at the terminal f and not yet read.
func flushInput(f *os.File) error {
	return unix.IoctlSetPointerInt(int(f.Fd()), unix.TIOCFLUSH, fread)
}
