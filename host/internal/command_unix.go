//go:build !windows

package internal

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// signalOutcome names the signal that killed a command, given the error from
// Wait. Empty when the command was not signalled.
//
// Here rather than beside recordResult because syscall.WaitStatus is
// Unix-shaped: it has no Signaled() on Windows, where a process is terminated
// with a status rather than signalled.
func signalOutcome(err error) (string, *int) {
	var execErr *exec.ExitError
	if errors.As(err, &execErr) {
		if ws, ok := execErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			n := int(ws.Signal())
			return ws.Signal().String(), &n
		}
	}
	return "", nil
}

// sshSignalName is sig's name as SSH spells it, without "SIG": "TERM".
func sshSignalName(sig syscall.Signal) string {
	return strings.TrimPrefix(unix.SignalName(sig), "SIG")
}
