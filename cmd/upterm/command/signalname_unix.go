//go:build !windows

package command

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// signalName is signal n's name, "SIGTERM", as this system numbers signals,
// or "signal N" for a number it has no name for.
func signalName(n int) string {
	if name := unix.SignalName(syscall.Signal(n)); name != "" {
		return name
	}
	return fmt.Sprintf("signal %d", n)
}
