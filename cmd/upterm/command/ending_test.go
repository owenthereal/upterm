package command

import (
	"context"
	"testing"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
)

// ptr returns a pointer to v (test helper).
func ptr(v int) *int { return &v }

func TestPhraseTable(t *testing.T) {
	three, nine := 3, 9
	for _, tc := range []struct {
		e                  ended
		wait, already, end string
	}{
		{ended{Reason: "exited", Status: ptr(0)}, "session s ended", "session s has already ended", ""},
		{ended{Reason: "exited", Status: &three}, "session s ended", "session s has already ended with status 3", "upterm: the session ended with status 3"},
		{ended{Reason: "stopped"}, "session s was stopped", "session s was already stopped", "upterm: the session was stopped"},
		{ended{Reason: "signaled", SignalNumber: &nine}, "session s ended by signal SIGKILL", "session s has already ended by signal SIGKILL", "upterm: the session ended by signal SIGKILL"},
		{ended{Reason: "join_timeout"}, "session s ended: no guest joined within the join timeout", "session s has already ended: no guest joined within the join timeout", ""},
		{ended{Reason: "unknown"}, "session s ended for a reason upterm didn't record", "session s has already ended for a reason upterm didn't record", "upterm: the session ended for a reason upterm didn't record"},
	} {
		require.Equal(t, tc.wait, waitLine("s", tc.e))
		require.Equal(t, tc.already, alreadyEndedLine("s", tc.e))
		require.Equal(t, tc.end, endLine(tc.e, false))
	}
}

// The rows the table above leaves out: a startup that failed, the reasons
// upterm has no words for beyond "didn't record", and the outcomes a record
// can hold without the detail its reason needs. None of them may guess.
func TestPhraseTableTheOtherReasons(t *testing.T) {
	unrecorded := []string{
		"session s ended for a reason upterm didn't record",
		"session s has already ended for a reason upterm didn't record",
	}
	for _, tc := range []struct {
		name          string
		e             ended
		wait, already string
	}{
		{"startup failed", ended{Reason: sessiondir.ReasonStartupFailed, LogPath: "/var/log/upterm.log"},
			"session s failed to start (see /var/log/upterm.log)", "session s failed to start (see /var/log/upterm.log)"},
		{"startup failed, no log recorded", ended{Reason: sessiondir.ReasonStartupFailed},
			"session s failed to start", "session s failed to start"},
		{"startup abandoned", ended{Reason: sessiondir.ReasonStartupAbandoned}, unrecorded[0], unrecorded[1]},
		{"canceled", ended{Reason: sessiondir.ReasonCanceled}, unrecorded[0], unrecorded[1]},
		{"a reason this upterm does not know", ended{Reason: "eaten_by_a_grue"}, unrecorded[0], unrecorded[1]},
		{"exited with no status", ended{Reason: sessiondir.ReasonExited}, unrecorded[0], unrecorded[1]},
		{"signalled with no signal", ended{Reason: sessiondir.ReasonSignaled}, unrecorded[0], unrecorded[1]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.wait, waitLine("s", tc.e))
			require.Equal(t, tc.already, alreadyEndedLine("s", tc.e))
		})
	}
}

// attach refusing an ended session says what stop and set say, with the
// name quoted. The "upterm: " prefix is Exit's, which prints the error.
func TestRefusalLineIsTheAlreadyEndedLineQuoted(t *testing.T) {
	for _, tc := range []struct {
		e    ended
		want string
	}{
		{ended{Reason: sessiondir.ReasonExited, Status: ptr(0)}, `session "build" has already ended`},
		{ended{Reason: sessiondir.ReasonExited, Status: ptr(3)}, `session "build" has already ended with status 3`},
		{ended{Reason: sessiondir.ReasonStopped}, `session "build" was already stopped`},
		{ended{Reason: sessiondir.ReasonSignaled, SignalNumber: ptr(15)}, `session "build" has already ended by signal SIGTERM`},
		{ended{Reason: sessiondir.ReasonJoinTimeout}, `session "build" has already ended: no guest joined within the join timeout`},
		{ended{Reason: sessiondir.ReasonStartupFailed, LogPath: "/l"}, `session "build" failed to start (see /l)`},
		{ended{Reason: sessiondir.ReasonUnknown}, `session "build" has already ended for a reason upterm didn't record`},
	} {
		require.Equal(t, tc.want, refusalLine("build", tc.e))
	}
}

func TestEndLineFromAnAttachResult(t *testing.T) {
	jt := attach.Result{Reason: attach.Exited, Status: 0, Cause: attach.Cause{Kind: attach.CauseJoinTimeout}}
	require.Empty(t, endLine(endedFromResult(jt), true))
	old := attach.Result{Reason: attach.Exited, Status: 0} // an older daemon: no cause
	require.Equal(t, "upterm: the session ended", endLine(endedFromResult(old), true))
	stopped := attach.Result{Reason: attach.Exited, Status: 1, Cause: attach.Cause{Kind: attach.CauseStopped}}
	require.Equal(t, "upterm: the session was stopped", endLine(endedFromResult(stopped), false))

	for _, tc := range []struct {
		name       string
		res        attach.Result
		host, atch string
	}{
		{"exited 0", attach.Result{Reason: attach.Exited, Cause: attach.Cause{Kind: attach.CauseExited}},
			"", "upterm: the session ended"},
		{"exited 3", attach.Result{Reason: attach.Exited, Status: 3, Cause: attach.Cause{Kind: attach.CauseExited}},
			"upterm: the session ended with status 3", "upterm: the session ended with status 3"},
		{"an older daemon's 3", attach.Result{Reason: attach.Exited, Status: 3},
			"upterm: the session ended with status 3", "upterm: the session ended with status 3"},
		{"signalled", attach.Result{Reason: attach.Exited, Status: 1, Cause: attach.Cause{Kind: attach.CauseSignaled, Signal: "TERM"}},
			"upterm: the session ended by signal SIGTERM", "upterm: the session ended by signal SIGTERM"},
		{"signalled, no name", attach.Result{Reason: attach.Exited, Status: 1, Cause: attach.Cause{Kind: attach.CauseSignaled}},
			"upterm: the session ended for a reason upterm didn't record", "upterm: the session ended for a reason upterm didn't record"},
		{"canceled", attach.Result{Reason: attach.Exited, Status: 1, Cause: attach.Cause{Kind: attach.CauseCanceled}},
			"upterm: the session ended for a reason upterm didn't record", "upterm: the session ended for a reason upterm didn't record"},
		{"stopped", attach.Result{Reason: attach.Exited, Status: 1, Cause: attach.Cause{Kind: attach.CauseStopped}},
			"upterm: the session was stopped", "upterm: the session was stopped"},
		{"join timeout", attach.Result{Reason: attach.Exited, Cause: attach.Cause{Kind: attach.CauseJoinTimeout}},
			"", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := endedFromResult(tc.res)
			require.Equal(t, tc.host, endLine(e, false), "host")
			require.Equal(t, tc.atch, endLine(e, true), "attach")
		})
	}
}

func TestSignalName(t *testing.T) {
	require.Equal(t, "SIGHUP", signalName(1))
	require.Equal(t, "SIGINT", signalName(2))
	require.Equal(t, "SIGKILL", signalName(9))
	require.Equal(t, "SIGTERM", signalName(15))
	require.Equal(t, "signal 200", signalName(200), "a number with no name is still told")
}

func TestDisconnectNeverSendsYouToAnotherSession(t *testing.T) {
	setupSessionRoots(t)
	dir := claimSession(t, "s") // launch A, held
	launchA := dir.LaunchID()
	require.Equal(t, stillRunning, checkAfterDisconnect(context.Background(), "s", launchA))

	require.NoError(t, dir.Release(context.Background())) // launch A ends
	require.Equal(t, endedNow, checkAfterDisconnect(context.Background(), "s", launchA))

	other := claimSession(t, "s") // launch B takes the name
	releaseAtEnd(t, other)
	require.Equal(t, replaced, checkAfterDisconnect(context.Background(), "s", launchA))
	require.NotContains(t, disconnectLine("s", "/l", replaced), "upterm attach")
}

func TestDisconnectWhileEndingSaysSo(t *testing.T) {
	setupSessionRoots(t)
	dir := claimSession(t, "s")
	releaseAtEnd(t, dir)
	require.NoError(t, dir.Update(func(r *sessiondir.Record) { r.Status = sessiondir.StatusEnding }))
	require.Equal(t, ending, checkAfterDisconnect(context.Background(), "s", dir.LaunchID()))
}

// Every status a held session is attachable in is still running: the
// command is alive whatever the tunnel is doing.
func TestDisconnectFromALiveSessionSaysItIsStillRunning(t *testing.T) {
	setupSessionRoots(t)
	dir := claimSession(t, "s")
	releaseAtEnd(t, dir)
	for _, status := range []string{sessiondir.StatusStarting, sessiondir.StatusReady, sessiondir.StatusReconnecting, sessiondir.StatusDisconnected} {
		require.NoError(t, dir.Update(func(r *sessiondir.Record) { r.Status = status }))
		require.Equal(t, stillRunning, checkAfterDisconnect(context.Background(), "s", dir.LaunchID()), status)
	}
}

// What upterm couldn't confirm it doesn't claim. No record at all is not
// another session using the name, and a record that can't be read, or a
// launch nobody named, is no answer either.
func TestDisconnectWithoutAnAnswerIsUnchecked(t *testing.T) {
	setupSessionRoots(t)
	require.Equal(t, unchecked, checkAfterDisconnect(context.Background(), "s", "launch-a"),
		"no record: nothing says another session has the name")

	seedCorruptSessionRecord(t, utils.UptermStateDir(), "corrupt")
	require.Equal(t, unchecked, checkAfterDisconnect(context.Background(), "corrupt", "launch-a"))

	dir := claimSession(t, "held")
	releaseAtEnd(t, dir)
	require.Equal(t, unchecked, checkAfterDisconnect(context.Background(), "held", ""),
		"with no launch to compare, a live record could be anybody's")
}

// The terminal's own lines, word for word: how an exit-254 reads for each
// thing the check can find, and both detach lines. The log is pointed at
// only when there is one.
func TestDisconnectAndDetachLines(t *testing.T) {
	for _, logPath := range []string{"/l", ""} {
		see := ""
		if logPath != "" {
			see = " (see /l)"
		}
		for _, tc := range []struct {
			after afterDisconnect
			want  string
		}{
			{stillRunning, "upterm: this terminal was disconnected" + see + "; the session is still running. Reattach with upterm attach s"},
			{ending, "upterm: this terminal was disconnected" + see + "; the session is ending"},
			{endedNow, "upterm: this terminal was disconnected, and the session has ended" + see + "; upterm session info s shows how"},
			{replaced, "upterm: this terminal was disconnected, and the session has ended" + see + "; another session now uses the name s"},
			{unchecked, "upterm: this terminal was disconnected" + see + "; upterm couldn't check the session. upterm session list shows what's running"},
		} {
			require.Equal(t, tc.want, disconnectLine("s", logPath, tc.after), "log %q", logPath)
			require.Equal(t, tc.want, attachEndLine("s", logPath, attach.Result{Reason: attach.Disconnected}, tc.after),
				"attach says what the host says, log %q", logPath)
		}
	}
	require.Equal(t, "upterm: detached; the session continues. Reattach with upterm attach s, or stop it with upterm session stop s", detachedLine("s"))
	require.Equal(t, "upterm: detached; the session continues", attachEndLine("s", "/l", attach.Result{Reason: attach.Detached}, unchecked))
}
