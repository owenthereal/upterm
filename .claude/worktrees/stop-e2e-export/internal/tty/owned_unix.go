//go:build !windows

package tty

import (
	"os"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Owned reports whether f is a terminal this process is in the foreground of.
//
// Reading or reconfiguring a terminal we are not in the foreground of is what
// SIGTTIN and SIGTTOU exist to prevent, and since a host ignores both, nothing
// else would stop it: `upterm host … &` would put the foreground shell's
// terminal into raw mode and then race it for input.
func Owned(f *os.File) bool {
	if f == nil || !term.IsTerminal(int(f.Fd())) {
		return false
	}
	pgrp, err := ForegroundProcessGroup(int(f.Fd()))
	if err != nil {
		return false
	}
	return pgrp == unix.Getpgrp()
}
