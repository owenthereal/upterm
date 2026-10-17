//go:build windows

package internal

import "syscall"

// signalOutcome has no answer on Windows: a process there is terminated with a
// status rather than signalled, so the wait carries no signal to name. The
// empty string is the honest result, not a placeholder.
func signalOutcome(err error) (string, *int) {
	return "", nil
}

// sshSignalName is sig's name as SSH spells it, without "SIG". On Windows the
// daemon is only ever signalled with SIGINT or SIGTERM, so those are the only
// names it needs.
func sshSignalName(sig syscall.Signal) string {
	switch sig {
	case syscall.SIGINT:
		return "INT"
	case syscall.SIGTERM:
		return "TERM"
	}
	return ""
}
