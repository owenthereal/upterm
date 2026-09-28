package command

import (
	"context"
	"errors"
	"fmt"
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
		sock, keys, status, err := attachTarget(context.Background(), name)
		require.NoError(t, err, name)
		rec, err := sessiondir.ReadRecord(utils.UptermStateDir(), name)
		require.NoError(t, err)
		require.Equal(t, rec.AttachSocket, sock, "the record's path, not one rebuilt under this runtime root")
		require.Equal(t, rec.Status, status, "and the status that explains a failed dial")
		require.Len(t, keys, len(rec.HostKeys), "the record's keys, parsed")
		for i, key := range keys {
			require.Equal(t, rec.HostKeys[i], strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n"),
				"key %d is the one the record names, not merely a key", i)
		}
	}

	_, _, _, err := attachTarget(context.Background(), "ended")
	require.ErrorContains(t, err, "ended")
	require.ErrorContains(t, err, "exited", "the record's reason is the explanation")

	_, _, _, err = attachTarget(context.Background(), "never-existed")
	require.ErrorContains(t, err, "no session named")
}

// TestAttachTargetExplainsHowAnEndedSessionEnded covers describeOutcome's two
// branches that no exit code reaches: a session killed before it could publish
// an outcome, and one that published a signal.
func TestAttachTargetExplainsHowAnEndedSessionEnded(t *testing.T) {
	setupSessionRoots(t)

	// Nothing got the chance to write a reason, so "unknown" is the whole
	// explanation and must still be given.
	buildEndedAfterKill(t, "killed")
	_, _, _, err := attachTarget(context.Background(), "killed")
	require.ErrorContains(t, err, sessiondir.ReasonUnknown,
		"a session that ended without saying how still says that much")

	d := claimSession(t, "signaled")
	rec, path := d.Record(), d.RecordPath()
	require.NoError(t, d.Release(context.Background()))
	rec.Status = sessiondir.StatusEnding
	rec.Reason = sessiondir.ReasonSignaled
	rec.Signal = "SIGTERM"
	writeRecordRaw(t, path, rec)

	_, _, _, err = attachTarget(context.Background(), "signaled")
	require.ErrorContains(t, err, "signaled by SIGTERM",
		"a signalled session names the signal, since there is no exit code to name")
}

// TestAttachFailure pins which dial failures are worth rewording. A record
// names its attach socket from the moment the name is claimed, and the daemon
// binds that socket only once the tunnel is up, so a dial in that window fails
// against a path the user never typed.
func TestAttachFailure(t *testing.T) {
	dialErr := errors.New("attach: dial unix /run/u/t1/attach.sock: connect: no such file or directory")

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
	mismatch := fmt.Errorf("attach: ssh: handshake failed: %w", attach.ErrHostKeyMismatch)
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

	_, _, _, err := attachTarget(context.Background(), "old")
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

	_, _, _, err := attachTarget(context.Background(), "no-host-key")
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

	_, _, _, err := attachTarget(context.Background(), "still-starting")
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

	_, _, _, err := attachTarget(context.Background(), "bad-host-key")
	require.ErrorContains(t, err, "attach")
}

func TestResolveAttachName(t *testing.T) {
	setupSessionRoots(t)
	_, err := resolveAttachName(context.Background(), "")
	require.ErrorContains(t, err, "no running session")

	buildReady(t, "only")
	name, err := resolveAttachName(context.Background(), "")
	require.NoError(t, err)
	require.Equal(t, "only", name)

	buildReady(t, "another")
	_, err = resolveAttachName(context.Background(), "")
	require.ErrorContains(t, err, "another")
	require.ErrorContains(t, err, "only")

	name, err = resolveAttachName(context.Background(), "explicit")
	require.NoError(t, err)
	require.Equal(t, "explicit", name)
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
	require.True(t, cmd.SilenceUsage, "a value the flag accepted is not a usage error")
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
