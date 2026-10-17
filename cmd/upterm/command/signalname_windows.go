package command

import (
	"strconv"
	"syscall"
)

// signalName is signal n's name, "SIGTERM", or, for a number with none, the
// number itself, "40": the lines already say "signal" before it. Windows has
// no signal-name table to ask. A record written there names only a signal the
// daemon itself was sent (a command is terminated with a status, not
// signalled), and these cover those.
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
	return strconv.Itoa(n)
}

// signalNumber is the number of the signal described as description, the way
// syscall.Signal's String does ("terminated"): all that a record written
// before records carried the number says of its signal. false for any other
// description. The signals asked are the ones signalName names, which cover
// every signal a record written here can name.
func signalNumber(description string) (int, bool) {
	for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGKILL, syscall.SIGTERM} {
		if sig.String() == description {
			return int(sig), true
		}
	}
	return 0, false
}
