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

// signalNumber is the number of the signal this system describes as
// description, the way syscall.Signal's String does ("terminated"): all that
// a record written before records carried the number says of its signal.
// false when no signal here is described that way. Every number a wait
// status can hold is asked, since it keeps a signal's number in seven bits.
func signalNumber(description string) (int, bool) {
	for n := 1; n <= 0x7f; n++ {
		if syscall.Signal(n).String() == description {
			return n, true
		}
	}
	return 0, false
}
