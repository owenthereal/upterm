package host

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/stretchr/testify/require"
)

// stopWinner is the group's winner for a `session stop`: the signal actor's
// join of its context's error and cause.
var stopWinner = errors.Join(context.Canceled, errSessionStopped)

// What is published to the session's clients is decided by the winner's
// error, not by which actor returned first: a stop can win the group as the
// command ends on its own, and the server has then returned before its
// interrupt runs. Anything that isn't a shutdown is left to the handlers'
// reading of the cancellation.
func TestOnlyAShutdownIsPublished(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"a stop", stopWinner, true},
		{"a signal", hostSignalError{signal: syscall.SIGTERM}, true},
		{"the join timeout", errJoinTimeout, true},
		{"a cancellation", errors.Join(context.Canceled, context.Canceled), true},
		{"a deadline", errors.Join(context.DeadlineExceeded, context.DeadlineExceeded), true},
		{"the server's own return", nil, false},
		{"the command's own failure", errors.New("exit status 3"), false},
		{"nobody attached", internal.ErrNoInitialClient, false},
		{"readiness unpublished", fmt.Errorf("%w: %w", errReadyUnpublished, errors.New("disk full")), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, isShutdown(tc.err))
		})
	}
}

// A run is recorded as its clients were told it ended. A shared command that
// ended on its own before any shutdown was published ended the session: its
// clients were sent its own status, and the record says what it did, whichever
// shutdown then won the group. One that ended after the shutdown was torn down
// by it, and what that made of it is not its own outcome: the shutdown is
// recorded.
func TestARunIsRecordedAsItsClientsWereTold(t *testing.T) {
	number := func(n int) *int { return &n }
	exited := func(code int) internal.CommandResult {
		return internal.CommandResult{Exited: true, Code: code}
	}
	killed := func(sig syscall.Signal) internal.CommandResult {
		return internal.CommandResult{Signal: sig.String(), SignalNumber: number(int(sig))}
	}
	afterShutdown := func(r internal.CommandResult) internal.CommandResult {
		r.EndedAfterShutdown = true
		return r
	}
	signalWinner := hostSignalError{signal: syscall.SIGTERM}
	cancelWinner := errors.Join(context.Canceled, context.Canceled)
	readyUnpublished := fmt.Errorf("%w: %w", errReadyUnpublished, errors.New("disk full"))

	stopped := runOutcome{reason: sessiondir.ReasonStopped}
	signaled := runOutcome{reason: sessiondir.ReasonSignaled, signal: syscall.SIGTERM.String(), signalNumber: number(int(syscall.SIGTERM))}
	exitedWith := func(code int) runOutcome {
		return runOutcome{reason: sessiondir.ReasonExited, exitCode: number(code)}
	}

	for _, tc := range []struct {
		name      string
		err       error
		res       internal.CommandResult
		abandoned bool
		want      runOutcome
	}{
		// The command ended on its own before the shutdown.
		{name: "a stop, the command exited 7 before it", err: stopWinner, res: exited(7), want: exitedWith(7)},
		{name: "a signal, the command exited 0 before it", err: signalWinner, res: exited(0), want: exitedWith(0)},
		{name: "the join timeout, the command exited 3 before it", err: errJoinTimeout, res: exited(3), want: exitedWith(3)},
		{name: "a cancellation, the command exited 5 before it", err: cancelWinner, res: exited(5), want: exitedWith(5)},
		{name: "a stop, the command killed by a signal before it", err: stopWinner, res: killed(syscall.SIGKILL),
			want: runOutcome{reason: sessiondir.ReasonSignaled, signal: syscall.SIGKILL.String(), signalNumber: number(int(syscall.SIGKILL))}},

		// The command was torn down by the shutdown: killed by its hangup,
		// or, on Windows or with the hangup trapped, exited.
		{name: "a stop, the command ended after it", err: stopWinner, res: afterShutdown(killed(syscall.SIGHUP)), want: stopped},
		{name: "a stop, the command exited 0 after it", err: stopWinner, res: afterShutdown(exited(0)), want: stopped},
		{name: "a signal, the command ended after it", err: signalWinner, res: afterShutdown(killed(syscall.SIGHUP)), want: signaled},
		{name: "the join timeout, the command killed by the teardown", err: errJoinTimeout, res: afterShutdown(killed(syscall.SIGHUP)),
			want: runOutcome{reason: sessiondir.ReasonJoinTimeout}},
		{name: "a cancellation, the command exited 1 after it", err: cancelWinner, res: afterShutdown(exited(1)),
			want: runOutcome{reason: sessiondir.ReasonCanceled}},

		// The rest are as they were.
		{name: "a stop, the command never confirmed ended", err: stopWinner, want: stopped},
		{name: "a signal, the command never confirmed ended", err: signalWinner, want: signaled},
		{name: "a cancellation by the starter going away, before the command started", err: cancelWinner, abandoned: true,
			want: runOutcome{reason: sessiondir.ReasonStartupAbandoned}},
		{name: "nobody attached", err: internal.ErrNoInitialClient, want: runOutcome{reason: sessiondir.ReasonStartupAbandoned}},
		{name: "readiness unpublished", err: readyUnpublished, res: afterShutdown(killed(syscall.SIGHUP)),
			want: runOutcome{reason: sessiondir.ReasonStartupFailed}},
		{name: "readiness unpublished, the command exited before", err: readyUnpublished, res: exited(0),
			want: runOutcome{reason: sessiondir.ReasonStartupFailed}},
		{name: "the command exited 3", res: exited(3), want: exitedWith(3)},
		{name: "the command killed by a signal", res: killed(syscall.SIGKILL),
			want: runOutcome{reason: sessiondir.ReasonSignaled, signal: syscall.SIGKILL.String(), signalNumber: number(int(syscall.SIGKILL))}},
		{name: "nothing ran", want: runOutcome{reason: sessiondir.ReasonStartupFailed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, classifyRun(tc.err, tc.res, tc.abandoned))
		})
	}
}
