package command

import (
	"os"

	"golang.org/x/sys/unix"
)

// The termios requests, as golang.org/x/term names them for Linux.
const (
	ioctlReadTermios  = unix.TCGETS
	ioctlWriteTermios = unix.TCSETS
)

// flushInput drops what was typed at the terminal f and not yet read.
func flushInput(f *os.File) error {
	return unix.IoctlSetInt(int(f.Fd()), unix.TCFLSH, unix.TCIFLUSH)
}
