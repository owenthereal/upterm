package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestAttachTarget(t *testing.T) {
	setupSessionRoots(t)
	buildStarting(t, "starting")
	buildReady(t, "ready")
	buildDisconnected(t, "gone")
	buildEndedAfterExit(t, "ended")

	for _, name := range []string{"starting", "ready", "gone"} {
		got, err := attachTarget(context.Background(), resolved{Name: name})
		require.NoError(t, err, name)
		rec, err := sessiondir.ReadRecord(utils.UptermStateDir(), name)
		require.NoError(t, err)
		require.Equal(t, rec.AttachSocket, got.Socket, "the record's path, not one rebuilt under this runtime root")
		require.Equal(t, rec.Status, got.Status, "and the status that explains a failed dial")
		require.Equal(t, rec.LaunchID, got.LaunchID, "and the launch, which a disconnect is checked against")
		require.Equal(t, rec.AdminSocket, got.AdminSocket)
		require.Len(t, got.Keys, len(rec.HostKeys), "the record's keys, parsed")
		for i, key := range got.Keys {
			require.Equal(t, rec.HostKeys[i], strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n"),
				"key %d is the one the record names, not merely a key", i)
		}
	}

	_, err := attachTarget(context.Background(), resolved{Name: "ended"})
	require.EqualError(t, err, `session "ended" has already ended with status 3`, "the record's outcome is the explanation")

	_, err = attachTarget(context.Background(), resolved{Name: "never-existed"})
	require.ErrorContains(t, err, "no session named")
}

// TestAttachTargetExplainsHowAnEndedSessionEnded covers the two outcomes no
// exit code reaches: a session killed before it could publish an outcome, and
// one that published a signal.
func TestAttachTargetExplainsHowAnEndedSessionEnded(t *testing.T) {
	setupSessionRoots(t)

	// Nothing got the chance to write a reason, and the refusal says so
	// rather than guessing one.
	buildEndedAfterKill(t, "killed")
	_, err := attachTarget(context.Background(), resolved{Name: "killed"})
	require.EqualError(t, err, `session "killed" has already ended for a reason upterm didn't record`,
		"a session that ended without saying how still says that much")

	d := claimSession(t, "signaled")
	rec, path := d.Record(), d.RecordPath()
	require.NoError(t, d.Release(context.Background()))
	rec.Status = sessiondir.StatusEnding
	rec.Reason = sessiondir.ReasonSignaled
	rec.Signal = "terminated"
	rec.SignalNumber = ptr(15)
	writeRecordRaw(t, path, rec)

	_, err = attachTarget(context.Background(), resolved{Name: "signaled"})
	require.EqualError(t, err, `session "signaled" has already ended by signal SIGTERM`,
		"a signalled session names the signal, since there is no exit code to name")
}

// The refusal is one line, prefixed once, and exits 255 like every other
// attachment that could not be made.
func TestAttachRefusesAnEndedSessionInOneLine(t *testing.T) {
	setupSessionRoots(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	buildEndedAfterExit(t, "build")

	stdout, stderr, code := runCLI(t, "attach", "build")
	require.Equal(t, exitAttachFailed, code)
	require.Empty(t, stdout)
	require.Equal(t, "upterm: session \"build\" has already ended with status 3\n", stderr)
}

// attach points its lines at the log only when the run has one: a log the
// root's pre-run could not open has nothing of this run in it.
func TestAttachLogPathIsEmptyWhenLoggingIsOff(t *testing.T) {
	setupSessionRoots(t)
	warning := &logWarning{w: io.Discard}
	ctx := context.WithValue(context.Background(), logWarningKey{}, warning)
	require.Equal(t, utils.UptermLogFilePath(), attachLogPath(ctx))

	warning.warn(utils.UptermLogFilePath(), errors.New("permission denied"))
	require.Empty(t, attachLogPath(ctx))
}

// TestAttachFailure pins which dial failures are worth rewording. A record
// names its attach socket from the moment the name is claimed, and the daemon
// binds that socket only once the tunnel is up, so a dial in that window fails
// against a path the user never typed.
func TestAttachFailure(t *testing.T) {
	dialErr := errors.New("dial unix /run/u/t1/attach.sock: connect: no such file or directory")

	err := attachFailure("t1", sessiondir.StatusStarting, dialErr)
	require.ErrorContains(t, err, "t1")
	require.ErrorContains(t, err, "still starting")
	require.NotErrorIs(t, err, dialErr, "the dialer's account of an early attach is not the user's answer")

	for _, status := range []string{sessiondir.StatusReady, sessiondir.StatusDisconnected} {
		require.ErrorIs(t, attachFailure("t1", status, dialErr), dialErr,
			"%s: a session that is up describes its own failure better than this could", status)
	}

	// The one failure the starting window must not swallow: something
	// answered the socket and it was not the session. "Try again in a
	// moment" would send the user back to it.
	mismatch := fmt.Errorf("ssh: handshake failed: %w", attach.ErrHostKeyMismatch)
	err = attachFailure("t1", sessiondir.StatusStarting, mismatch)
	require.ErrorIs(t, err, attach.ErrHostKeyMismatch)
	require.NotContains(t, err.Error(), "still starting")
}

func TestAttachTargetRefusesARecordWithoutAnAttachSocket(t *testing.T) {
	setupSessionRoots(t)
	d := claimSession(t, "old")
	releaseAtEnd(t, d)
	// A record from before attach sockets existed: rewrite it without one.
	rec := d.Record()
	rec.AttachSocket = ""
	writeRecordRaw(t, d.RecordPath(), rec)

	_, err := attachTarget(context.Background(), resolved{Name: "old"})
	require.ErrorContains(t, err, "attach")
}

// TestAttachTargetRefusesARecordWithoutHostKeys is
// TestAttachTargetRefusesARecordWithoutAnAttachSocket's neighbour: a record
// that never had a key published is the same class of failure as one from
// before attach sockets existed. Unlike AttachSocket, HostKeys is not forced
// on Update, so an ordinary Update that says nothing about it leaves it out
// without needing writeRecordRaw.
func TestAttachTargetRefusesARecordWithoutHostKeys(t *testing.T) {
	setupSessionRoots(t)
	d := claimSession(t, "no-host-key")
	releaseAtEnd(t, d)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
	}))

	_, err := attachTarget(context.Background(), resolved{Name: "no-host-key"})
	require.ErrorContains(t, err, "attach")
}

// A session that has not published its keys yet is still starting, not one
// that cannot be attached to: the daemon publishes them as its attach door
// starts listening, so a record without them names a socket that is not
// dialable either. Telling the user to restart would throw away a session
// that was about to be attachable.
func TestAttachTargetTellsAStartingSessionApartFromAnOldOne(t *testing.T) {
	setupSessionRoots(t)
	d := claimSession(t, "still-starting")
	releaseAtEnd(t, d)

	_, err := attachTarget(context.Background(), resolved{Name: "still-starting"})
	require.ErrorContains(t, err, "still starting")
	require.NotContains(t, err.Error(), "restart", "waiting is the advice, not restarting")
}

// TestAttachTargetRefusesARecordWithAnUnparsableHostKey covers the other way
// HostKeys can fail to name a usable key: present, but not one
// ssh.ParseAuthorizedKey accepts.
func TestAttachTargetRefusesARecordWithAnUnparsableHostKey(t *testing.T) {
	setupSessionRoots(t)
	d := claimSession(t, "bad-host-key")
	releaseAtEnd(t, d)
	require.NoError(t, d.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
		r.HostKeys = []string{"not a real key"}
	}))

	_, err := attachTarget(context.Background(), resolved{Name: "bad-host-key"})
	require.ErrorContains(t, err, "attach")
}

func TestResolveAttachName(t *testing.T) {
	setupSessionRoots(t)
	_, err := resolveAttachName(context.Background(), "")
	require.ErrorContains(t, err, "no running session")

	buildReady(t, "only")
	r, err := resolveAttachName(context.Background(), "")
	require.NoError(t, err)
	require.Equal(t, resolved{Name: "only"}, r, "the only session is a name, with no launch pinned")

	buildReady(t, "another")
	_, err = resolveAttachName(context.Background(), "")
	require.ErrorContains(t, err, "another")
	require.ErrorContains(t, err, "only")

	r, err = resolveAttachName(context.Background(), "explicit")
	require.NoError(t, err)
	require.Equal(t, resolved{Name: "explicit"}, r)
}

// A session ID attaches to the session it names, to the same socket, with the
// same keys, as its name does.
func TestAttachTargetByID(t *testing.T) {
	setupSessionRoots(t)
	buildReady(t, "ready") // session ID sid-1

	r, err := resolveAttachName(context.Background(), "sid-1")
	require.NoError(t, err)
	byID, err := attachTarget(context.Background(), r)
	require.NoError(t, err)
	byName, err := attachTarget(context.Background(), resolved{Name: "ready"})
	require.NoError(t, err)
	require.Equal(t, byName, byID)
	require.Equal(t, "ready", r.Name)
}

// An ended session given by ID is refused as it is by name, in the words of
// its record.
func TestAttachRefusesAnEndedSessionGivenByIDInOneLine(t *testing.T) {
	setupSessionRoots(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	endHeld(t, readyHeld(t, "build", "sid-1"))

	stdout, stderr, code := runCLI(t, "attach", "sid-1")
	require.Equal(t, exitAttachFailed, code)
	require.Empty(t, stdout)
	require.Equal(t, "upterm: session \"build\" has already ended with status 3\n", stderr)
}

// The session given by ID has ended and its name is another's: attach does
// not dial the other session's socket, which the record found would name.
func TestAttachTargetByIDRefusesWhenTheNameWasReused(t *testing.T) {
	setupSessionRoots(t)
	a := readyHeld(t, "build", "sid-1")
	require.NoError(t, a.Update(func(r *sessiondir.Record) { r.HostKeys = []string{testHostKeyLine(t)} }))
	r, err := resolveAttachName(context.Background(), "sid-1")
	require.NoError(t, err)

	endHeld(t, a)
	b := readyHeld(t, "build", "sid-2")
	require.NoError(t, b.Update(func(r *sessiondir.Record) { r.HostKeys = []string{testHostKeyLine(t)} }))

	got, err := attachTarget(context.Background(), r)
	require.EqualError(t, err, `session "build" has already ended for a reason upterm didn't record`)
	require.Empty(t, got.Socket, "nothing to dial")

	// Whereas the name, which never pinned a launch, attaches to what holds it.
	got, err = attachTarget(context.Background(), resolved{Name: "build"})
	require.NoError(t, err)
	require.Equal(t, b.LaunchID(), got.LaunchID)
}

// ~? looks the session up by name, so an attachment made by ID reports on it
// under the name the ID resolved to.
func TestAttachStatusForASessionGivenByIDFindsIt(t *testing.T) {
	setupSessionRoots(t)
	buildReady(t, "ready") // session ID sid-1

	r, err := resolveAttachName(context.Background(), "sid-1")
	require.NoError(t, err)
	tgt, err := attachTarget(context.Background(), r)
	require.NoError(t, err)

	src := attachStatusSource(r, tgt)
	require.Equal(t, "ready", src.Name)
	src.Escape = '~'
	lines := statusLines(context.Background(), src, nil)
	require.NotEmpty(t, lines)
	require.Equal(t, "upterm: session ready: 0 guests; the relay is connected", lines[0])
}

func TestAttachExitError(t *testing.T) {
	require.NoError(t, attachExitError("s", attach.Result{Reason: attach.Detached}))
	require.NoError(t, attachExitError("s", attach.Result{Reason: attach.Exited, Status: 0}))

	var ec ExitCodeError
	require.ErrorAs(t, attachExitError("s", attach.Result{Reason: attach.Exited, Status: 3}), &ec)
	require.Equal(t, 3, ec.Code)
	require.ErrorAs(t, attachExitError("s", attach.Result{Reason: attach.Disconnected}), &ec)
	require.Equal(t, exitDisconnected, ec.Code)
}

// An attachment ends with one line, or none when the daemon's own notice
// already said it. Unlike upterm host, attach has a line for a 0.
func TestAttachEndLine(t *testing.T) {
	require.Equal(t, "upterm: detached; the session continues", attachEndLine("s", "/l", attach.Result{Reason: attach.Detached}, unchecked))
	require.Equal(t, "upterm: the session ended", attachEndLine("s", "/l", attach.Result{Reason: attach.Exited}, unchecked))
	require.Equal(t, "upterm: the session ended with status 3", attachEndLine("s", "/l", attach.Result{Reason: attach.Exited, Status: 3}, unchecked))
	require.Equal(t, "upterm: the session was stopped", attachEndLine("s", "/l",
		attach.Result{Reason: attach.Exited, Status: 1, Cause: attach.Cause{Kind: attach.CauseStopped}}, unchecked))
	require.Empty(t, attachEndLine("s", "/l",
		attach.Result{Reason: attach.Exited, Cause: attach.Cause{Kind: attach.CauseJoinTimeout}}, unchecked),
		"the daemon's notice said it")
}

// TestAttachRunERejectsABadEscapeCharAsACouldNotAttach pins the exit code and
// the shape of the complaint, which parseEscapeChar's own test cannot: the
// flag parsed, so this is not a usage error, and a script gets 255 like every
// other way an attachment fails to happen. It stops before anything a real
// terminal is needed for, because the escape character is read first.
func TestAttachRunERejectsABadEscapeCharAsACouldNotAttach(t *testing.T) {
	cmd := attachCmd()
	t.Cleanup(func() { flagEscapeChar = "~" })
	require.NoError(t, cmd.Flags().Set("escape-char", "ab"))

	var ec ExitCodeError
	require.ErrorAs(t, attachRunE(cmd, nil), &ec)
	require.Equal(t, exitAttachFailed, ec.Code)
	require.ErrorContains(t, ec, "single ASCII character", "and says what would have worked")
}

func TestParseEscapeChar(t *testing.T) {
	b, err := parseEscapeChar("~")
	require.NoError(t, err)
	require.Equal(t, byte('~'), b)
	b, err = parseEscapeChar("none")
	require.NoError(t, err)
	require.Zero(t, b)
	_, err = parseEscapeChar("ab")
	require.Error(t, err)
	_, err = parseEscapeChar("é")
	require.Error(t, err, "one byte, not one rune")
}
