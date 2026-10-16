package command

import (
	"context"
	"fmt"
	"time"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
)

// ended is how a session ended, in the terms its lines are written in. It
// comes from the session's record (endedFromRecord) or from what the daemon
// told an attached terminal (endedFromResult), so that the lines read the
// same whichever of the two a command has.
type ended struct {
	Reason       string // a sessiondir.Reason*
	Status       *int   // the exit status, when exited
	SignalNumber *int   // when signalled, from the record
	SSHSignal    string // when signalled, from an attach.Cause ("TERM")
	LogPath      string // the session's log, for a startup that failed
}

func endedFromRecord(rec *sessiondir.Record) ended {
	return ended{
		Reason:       rec.Reason,
		Status:       rec.ExitCode,
		SignalNumber: rec.SignalNumber,
		LogPath:      rec.LogPath,
	}
}

// endedFromResult reads the daemon's cause ahead of the status, which alone
// can't say: a stop and a signal both give 1, and a join timeout gives 0. No
// cause, from an older daemon, is an exit with the status it sent.
func endedFromResult(res attach.Result) ended {
	switch res.Cause.Kind {
	case attach.CauseStopped:
		return ended{Reason: sessiondir.ReasonStopped}
	case attach.CauseSignaled:
		return ended{Reason: sessiondir.ReasonSignaled, SSHSignal: res.Cause.Signal}
	case attach.CauseCanceled:
		return ended{Reason: sessiondir.ReasonCanceled}
	case attach.CauseJoinTimeout:
		return ended{Reason: sessiondir.ReasonJoinTimeout}
	}
	status := res.Status
	return ended{Reason: sessiondir.ReasonExited, Status: &status}
}

// outcome is the one way an ended session is told: its reason, with the
// detail that reason needs. Anything without that detail — an exit with no
// status, a signal with neither name nor number, a reason with no words of
// its own — is told as unrecorded, so no line guesses.
type outcome int

const (
	outcomeUnrecorded outcome = iota
	outcomeExited
	outcomeStopped
	outcomeSignaled
	outcomeJoinTimeout
	outcomeStartupFailed
)

func (e ended) outcome() outcome {
	switch e.Reason {
	case sessiondir.ReasonExited:
		if e.Status != nil {
			return outcomeExited
		}
	case sessiondir.ReasonStopped:
		return outcomeStopped
	case sessiondir.ReasonSignaled:
		if e.signal() != "" {
			return outcomeSignaled
		}
	case sessiondir.ReasonJoinTimeout:
		return outcomeJoinTimeout
	case sessiondir.ReasonStartupFailed:
		return outcomeStartupFailed
	}
	return outcomeUnrecorded
}

// signal is the signal's name ("SIGTERM"), or its number ("40") for one this
// system has no name for, to follow "signal" in the lines; "" when neither
// source gave one.
func (e ended) signal() string {
	switch {
	case e.SignalNumber != nil:
		return signalName(*e.SignalNumber)
	case e.SSHSignal != "":
		return "SIG" + e.SSHSignal
	}
	return ""
}

// failedToStart is a startup failure's words, which every column shares.
func (e ended) failedToStart() string {
	return "failed to start" + seeLog(" (see %s)", e.LogPath)
}

// waitLine is `session wait`'s line for a session it saw end. The status is
// the command's exit code to carry, so the line never repeats it.
func waitLine(name string, e ended) string {
	var how string
	switch e.outcome() {
	case outcomeExited:
		how = "ended"
	case outcomeStopped:
		how = "was stopped"
	case outcomeSignaled:
		how = "ended by signal " + e.signal()
	case outcomeJoinTimeout:
		how = "ended: no guest joined within the join timeout"
	case outcomeStartupFailed:
		how = e.failedToStart()
	default:
		how = "ended for a reason upterm didn't record"
	}
	return "session " + name + " " + how
}

// alreadyEndedLine is what `session stop` and `session set` say about a
// session that had ended before they reached it.
func alreadyEndedLine(name string, e ended) string {
	return "session " + name + " " + alreadyEnded(e)
}

// refusalLine is `upterm attach`'s refusal of a session that has ended:
// alreadyEndedLine with the name quoted. Without the "upterm: " prefix, which
// Exit puts on the error it is returned as.
func refusalLine(name string, e ended) string {
	return fmt.Sprintf("session %q %s", name, alreadyEnded(e))
}

func alreadyEnded(e ended) string {
	switch e.outcome() {
	case outcomeExited:
		if *e.Status == 0 {
			return "has already ended"
		}
		return fmt.Sprintf("has already ended with status %d", *e.Status)
	case outcomeStopped:
		return "was already stopped"
	case outcomeSignaled:
		return "has already ended by signal " + e.signal()
	case outcomeJoinTimeout:
		return "has already ended: no guest joined within the join timeout"
	case outcomeStartupFailed:
		return e.failedToStart()
	}
	return "has already ended for a reason upterm didn't record"
}

// endLine is the last line of the terminal that was attached as the session
// ended: upterm host's own, or upterm attach's when attach is true. No name:
// a name goes in these lines only as the argument to a next step, and an
// ended session has none. "" when there is nothing to add: a join timeout,
// which the daemon's notice in the stream already told, and, for upterm
// host, an exit of 0.
func endLine(e ended, attach bool) string {
	switch e.outcome() {
	case outcomeExited:
		if *e.Status != 0 {
			return fmt.Sprintf("upterm: the session ended with status %d", *e.Status)
		}
		if attach {
			return "upterm: the session ended"
		}
		return ""
	case outcomeStopped:
		return "upterm: the session was stopped"
	case outcomeSignaled:
		return "upterm: the session ended by signal " + e.signal()
	case outcomeJoinTimeout:
		return ""
	}
	return "upterm: the session ended for a reason upterm didn't record"
}

// afterDisconnect is what became of the launch a terminal was attached to,
// once it was disconnected (exit 254). The zero value is unchecked, so
// nothing claims more than was found.
type afterDisconnect int

const (
	// unchecked: the record couldn't be read in time, or says nothing about
	// the launch.
	unchecked afterDisconnect = iota
	// stillRunning: the launch holds its name and is attachable.
	stillRunning
	// ending: the launch holds its name and is ending.
	ending
	// endedNow: the launch has given its name up and nobody has taken it.
	endedNow
	// replaced: another launch has the name now.
	replaced
)

// disconnectCheckTimeout bounds checkAfterDisconnect: it runs as the terminal
// is handed back, and a line late by more than this helps nobody.
const disconnectCheckTimeout = time.Second

// checkAfterDisconnect finds what became of launchID, the launch a terminal
// attached to under name. The launch, not the name: a session can end and
// another take its name while the terminal is attached, and advice to
// reattach by name would then send the operator into somebody else's
// session.
func checkAfterDisconnect(ctx context.Context, name, launchID string) afterDisconnect {
	if launchID == "" {
		// Nothing to tell this launch's record from another's.
		return unchecked
	}
	ctx, cancel := context.WithTimeout(ctx, disconnectCheckTimeout)
	defer cancel()
	rec, held, err := sessiondir.Inspect(ctx, utils.UptermStateDir(), name)
	switch {
	case err != nil, rec == nil:
		// No record at all is not another session using the name: upterm
		// hasn't seen one.
		return unchecked
	case rec.LaunchID != launchID:
		return replaced
	case !held:
		return endedNow
	}
	switch rec.Status {
	case sessiondir.StatusEnding:
		return ending
	case sessiondir.StatusStarting, sessiondir.StatusReady, sessiondir.StatusReconnecting, sessiondir.StatusDisconnected:
		return stillRunning
	}
	return unchecked
}

// disconnectLine is the line for a terminal the session disconnected (exit
// 254): the log has why, when there is one (logPath isn't ""), and what the
// check found decides what to do next. Only a session still running is one
// to reattach to.
func disconnectLine(name, logPath string, s afterDisconnect) string {
	see := seeLog(" (see %s)", logPath)
	switch s {
	case stillRunning:
		return "upterm: this terminal was disconnected" + see + "; the session is still running. Reattach with upterm attach " + name
	case ending:
		return "upterm: this terminal was disconnected" + see + "; the session is ending"
	case endedNow:
		return "upterm: this terminal was disconnected, and the session has ended" + see + "; upterm session info " + name + " shows how"
	case replaced:
		return "upterm: this terminal was disconnected, and the session has ended" + see + "; another session now uses the name " + name
	}
	return "upterm: this terminal was disconnected" + see + "; upterm couldn't check the session. upterm session list shows what's running"
}

// attachDetachedLine is what upterm attach says when its terminal detaches.
const attachDetachedLine = "upterm: detached; the session continues"

// detachedLine is what upterm host says when its own terminal detaches: the
// session it started goes on without a terminal, so how to get back to it,
// or end it, goes with it.
func detachedLine(name string) string {
	return attachDetachedLine + ". Reattach with upterm attach " + name + ", or stop it with upterm session stop " + name
}
