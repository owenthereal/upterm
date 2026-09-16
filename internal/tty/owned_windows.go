//go:build windows

package tty

import (
	"os"

	"golang.org/x/term"
)

// Owned reports whether f is a terminal this process may touch. Windows has
// no process groups in this sense and no SIGTTIN, so there is nothing to be
// in the foreground of: being a terminal is the whole of the question.
func Owned(f *os.File) bool {
	return f != nil && term.IsTerminal(int(f.Fd()))
}
