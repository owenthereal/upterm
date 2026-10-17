package host

import (
	"context"
	"errors"

	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/host/sessiondir"
)

// isShutdown reports whether err, the run group's winner, is a shutdown: a
// stop, a signal the daemon received, the join timeout, or a cancellation.
// They are the causes the session's handlers tell their clients of, and are
// told by what err wraps, as the handlers tell them. Anything else -- the
// server's own return, which is the session ending as its command did, a
// session nobody attached to, readiness that couldn't be published -- is not
// one.
func isShutdown(err error) bool {
	var sig internal.ShutdownSignal
	return errors.Is(err, errSessionStopped) || errors.As(err, &sig) || errors.Is(err, errJoinTimeout) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// runOutcome is how a run ended, as its record says: the reason, and the
// detail that reason carries.
type runOutcome struct {
	reason       string
	exitCode     *int
	signal       string
	signalNumber *int
}

// classifyRun is how a run ended, from err, the run group's winner, and res,
// the shared command's result. abandonedBeforeStart is whether the process
// that started the session went away before the command started.
//
// The command's own outcome, and the cause that initiated teardown, are two
// different questions. Precedence is explicit because the wait status cannot
// answer the second: our own teardown kills the command, so a requested
// shutdown surfaces as a signal on Unix and as an ordinary non-zero exit on
// Windows.
//
// A shared command that ended on its own before any shutdown was published
// is the exception. The session ended because it did, and its clients were
// sent its own status; a shutdown that won the group after that changed
// nothing, and the record says what the clients were told.
func classifyRun(err error, res internal.CommandResult, abandonedBeforeStart bool) runOutcome {
	if isShutdown(err) && res.EndedOnItsOwn() {
		err = nil
	}
	var hostSignal hostSignalError
	switch {
	case errors.Is(err, errJoinTimeout):
		// The group winner alone identifies why teardown happened.
		return runOutcome{reason: sessiondir.ReasonJoinTimeout}
	case errors.Is(err, errSessionStopped):
		return runOutcome{reason: sessiondir.ReasonStopped}
	case errors.As(err, &hostSignal):
		n := int(hostSignal.signal)
		return runOutcome{reason: sessiondir.ReasonSignaled, signal: hostSignal.signal.String(), signalNumber: &n}
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		if abandonedBeforeStart {
			return runOutcome{reason: sessiondir.ReasonStartupAbandoned}
		}
		return runOutcome{reason: sessiondir.ReasonCanceled}
	case errors.Is(err, internal.ErrNoInitialClient):
		// Nobody attached, so nothing ran and nothing failed: the session
		// was abandoned before its command started.
		return runOutcome{reason: sessiondir.ReasonStartupAbandoned}
	case errors.Is(err, errReadyUnpublished):
		// Ahead of the command's result, which here says only what teardown
		// did to it.
		return runOutcome{reason: sessiondir.ReasonStartupFailed}
	case res.Exited:
		code := res.Code
		return runOutcome{reason: sessiondir.ReasonExited, exitCode: &code}
	case res.Signal != "":
		return runOutcome{reason: sessiondir.ReasonSignaled, signal: res.Signal, signalNumber: res.SignalNumber}
	}
	return runOutcome{reason: sessiondir.ReasonStartupFailed}
}
