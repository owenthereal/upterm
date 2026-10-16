package command

import (
	"fmt"
	"syscall"
)

// signalName is signal n's name, "SIGTERM", or "signal N" for a number with
// none. Windows has no signal-name table to ask. A record written there names
// only a signal the daemon itself was sent (a command is terminated with a
// status, not signalled), and these cover those.
func signalName(n int) string {
	switch syscall.Signal(n) {
	case syscall.SIGHUP:
		return "SIGHUP"
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGKILL:
		return "SIGKILL"
	case syscall.SIGTERM:
		return "SIGTERM"
	}
	return fmt.Sprintf("signal %d", n)
}
