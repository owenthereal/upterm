//go:build !windows

package command

import (
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// signalName is signal n's name, "SIGTERM", as this system numbers signals,
// or, for a number it has no name for, the number itself, "40": the lines
// already say "signal" before it.
func signalName(n int) string {
	if name := unix.SignalName(syscall.Signal(n)); name != "" {
		return name
	}
	return strconv.Itoa(n)
}
