package ftests

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// outcomeTimeout bounds one host run. It is a hang detector, not a
// measurement: every command these tests host exits or is cancelled in
// milliseconds, so the budget costs nothing when the run behaves and turns a
// wedged run.Group into a failure with a stack instead of a dead suite.
const outcomeTimeout = 60 * time.Second

// outcomePollInterval is how often the never-ready tests sample the record.
// Fast enough that a "ready" published and immediately overwritten would still
// be caught, which is the whole point of sampling rather than reading once.
const outcomePollInterval = 2 * time.Millisecond

// shortXDGDir returns a directory short enough to hold a session's sockets.
//
// A session's admin socket is <runtime>/upterm/sessions/<name>/admin.sock, and
// macOS caps a unix socket path at 104 bytes. t.TempDir() hands out
// /var/folders/<hash>/T/<TestName>/001, which overflows that before the
// session's own path components are appended.
//
// Windows has no /tmp, and t.TempDir() there is a per-test path long enough to
// hit the same limit, so the temp root is used directly instead.
func shortXDGDir(t *testing.T) string {
	t.Helper()

	root := "/tmp"
	if runtime.GOOS == "windows" {
		root = ""
	}

	dir, err := os.MkdirTemp(root, "up")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// skipWithoutPOSIXShell skips a case whose command is a shell script.
//
// Two reasons, both about the command rather than the guarantee: Windows has
// no POSIX shell to run it, and no signals for it to die from — a terminated
// process there is reported as an ordinary exit status, so "signalled" is not
// a distinction the platform can make. Kept in the harness so the cases
// themselves stay as written.
func skipWithoutPOSIXShell(t *testing.T, command []string) {
	t.Helper()

	if runtime.GOOS == "windows" && len(command) > 0 && command[0] == "sh" {
		t.Skip("the command under test is a POSIX shell script")
	}
}

// uniqueSessionName keeps concurrent tests from claiming the same name. They
// have separate roots, so this is belt and braces — but a name collision would
// surface as ErrNameInUse from an unrelated test, which is a bad hour.
func uniqueSessionName(t *testing.T) string {
	t.Helper()

	b := make([]byte, 4)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return "outcome-" + hex.EncodeToString(b)
}

// outcomeRun is one host run against its own relay, with its own session
// directory roots.
type outcomeRun struct {
	host      *host.Host
	name      string
	stateRoot string

	// relay is the server the host tunnels through, kept so a case can take it
	// away mid-session. Shutting it down is the only honest way to produce a
	// lost tunnel: anything the host could be told to do instead would be
	// testing the instruction rather than the failure.
	relay TestServer

	// stdout is the read end of the host's stdout. The host's sink for a
	// non-terminal stdout is asynchronous and bounded, so a test that does not
	// read it loses output rather than blocking the host.
	stdout *os.File

	// closeWriters releases the pipe ends the host wrote to, so a reader of
	// stdout sees EOF. Called once Run has returned.
	closeWriters func()
}

// newOutcomeRun builds a Host that claims a session directory for real.
//
// Deliberately not the ftests.Host wrapper: that requires an AdminSocketFile,
// and supplying one is exactly what makes Host.Run skip the claim these tests
// are about.
func newOutcomeRun(t *testing.T, command []string) *outcomeRun {
	t.Helper()

	skipWithoutPOSIXShell(t, command)

	dir := shortXDGDir(t)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("XDG_STATE_HOME", dir)

	ts, err := NewServerWithMode(ServerPrivateKeyContent, routing.ModeEmbedded)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ts.Shutdown() })

	signers, err := utils.CreateSigners([][]byte{[]byte(HostPrivateKeyContent)})
	require.NoError(t, err)

	// Never written to: ownsTerminal reports false for a pipe, so the host
	// does not forward stdin and nothing here has to feed it.
	stdinr, stdinw, err := os.Pipe()
	require.NoError(t, err)

	stdoutr, stdoutw, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = stdoutr.Close() })

	name := uniqueSessionName(t)

	return &outcomeRun{
		host: &host.Host{
			Host:              "ssh://" + ts.SSHAddr(),
			Name:              name,
			Command:           command,
			Signers:           signers,
			HostKeyCallback:   ssh.InsecureIgnoreHostKey(),
			KeepAliveDuration: keepAliveDuration,
			Logger:            testLogger,
			Stdin:             stdinr,
			Stdout:            stdoutw,
		},
		name:      name,
		stateRoot: utils.UptermStateDir(),
		relay:     ts,
		stdout:    stdoutr,
		closeWriters: func() {
			_ = stdoutw.Close()
			_ = stdinw.Close()
			_ = stdinr.Close()
		},
	}
}

// record reads what the run published. It works after Release, which is the
// point: the runtime directory is gone by then and only the record is left.
func (r *outcomeRun) record(t *testing.T) *sessiondir.Record {
	t.Helper()

	rec, err := sessiondir.ReadRecord(r.stateRoot, r.name)
	require.NoError(t, err)
	require.NotNil(t, rec)
	return rec
}

// runHostForOutcome runs a host to completion and returns the record it left.
// Run's own error is not the assertion: a command that exits non-zero fails
// the group, and that is the case under test rather than a test failure.
func runHostForOutcome(t *testing.T, command []string) *sessiondir.Record {
	t.Helper()

	run := newOutcomeRun(t, command)

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = io.Copy(io.Discard, run.stdout)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()

	err := run.host.Run(ctx)
	run.closeWriters()
	<-drained
	t.Logf("host run returned: %v", err)

	return run.record(t)
}

// runHostUntilCancelled starts a host, waits for marker on its stdout, then
// cancels the context it was given and waits for Run to return.
func runHostUntilCancelled(t *testing.T, command []string, marker string) *sessiondir.Record {
	t.Helper()

	run := newOutcomeRun(t, command)

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- run.host.Run(ctx) }()

	// The marker proves the command is running and its output has reached us,
	// so the cancellation below is a shutdown of a working session rather than
	// a race with its startup.
	awaitMarker(t, run.stdout, marker)
	cancel()

	select {
	case err := <-done:
		t.Logf("host run returned: %v", err)
	case <-time.After(outcomeTimeout):
		t.Fatalf("host did not return within %s of cancellation", outcomeTimeout)
	}
	run.closeWriters()

	return run.record(t)
}

// awaitMarker reads r until marker appears, failing if it never does.
func awaitMarker(t *testing.T, r io.Reader, marker string) {
	t.Helper()

	found := make(chan bool, 1)
	go func() {
		var seen strings.Builder
		buf := make([]byte, 512)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				seen.Write(buf[:n])
				if strings.Contains(seen.String(), marker) {
					found <- true
					return
				}
			}
			if err != nil {
				found <- false
				return
			}
		}
	}()

	select {
	case ok := <-found:
		if !ok {
			t.Fatalf("host stdout ended without carrying %q", marker)
		}
	case <-time.After(outcomeTimeout):
		t.Fatalf("host stdout did not carry %q within %s", marker, outcomeTimeout)
	}
}

// watchStatuses records every distinct status the record carries until done is
// closed. Reading the record once at the end could not tell a run that briefly
// claimed to be ready from one that never did, and "never ready" is the
// guarantee under test.
func watchStatuses(stateRoot, name string, done <-chan struct{}) <-chan []string {
	out := make(chan []string, 1)

	go func() {
		var seen []string
		record := func() {
			rec, err := sessiondir.ReadRecord(stateRoot, name)
			if err != nil || rec == nil {
				return
			}
			if len(seen) == 0 || seen[len(seen)-1] != rec.Status {
				seen = append(seen, rec.Status)
			}
		}

		tick := time.NewTicker(outcomePollInterval)
		defer tick.Stop()

		for {
			select {
			case <-done:
				record()
				out <- seen
				return
			case <-tick.C:
				record()
			}
		}
	}()

	return out
}

func Test_Host_PublishesNonZeroExit(t *testing.T) {
	res := runHostForOutcome(t, []string{"sh", "-c", "exit 42"})
	require.Equal(t, sessiondir.ReasonExited, res.Reason)
	require.NotNil(t, res.ExitCode)
	require.Equal(t, 42, *res.ExitCode)
}

func Test_Host_PublishesZeroExit(t *testing.T) {
	res := runHostForOutcome(t, []string{"sh", "-c", "exit 0"})
	require.Equal(t, sessiondir.ReasonExited, res.Reason)
	require.NotNil(t, res.ExitCode)
	require.Equal(t, 0, *res.ExitCode)
}

func Test_Host_PublishesSignalTermination(t *testing.T) {
	res := runHostForOutcome(t, []string{"sh", "-c", "kill -TERM $$"})
	require.Equal(t, sessiondir.ReasonSignaled, res.Reason,
		"a signalled command must not be reported as exited -1")
	require.Nil(t, res.ExitCode)
}

func Test_Host_PublishesStartupFailure(t *testing.T) {
	// A command that cannot be started at all.
	res := runHostForOutcome(t, []string{"/nonexistent/definitely-not-a-command"})
	require.Equal(t, sessiondir.ReasonStartupFailed, res.Reason)
	require.Nil(t, res.ExitCode)
}

func Test_Host_PublishesStoppedOnCancellation(t *testing.T) {
	// Review fix: this was skipped, and a skipped test guards nothing. It is
	// also the one case the wait status cannot answer on its own — our own
	// teardown kills the command, so without the shutdownRequested flag this
	// reports "signaled" on Unix and a non-zero "exited" on Windows.
	res := runHostUntilCancelled(t, []string{"sh", "-c", "echo READY; sleep 300"}, "READY")

	require.Equal(t, sessiondir.ReasonStopped, res.Reason,
		"a shutdown we initiated must not be reported as the signal it produced")
	require.Nil(t, res.ExitCode,
		"the exit code of a process we killed is not the command's own outcome")
	require.Empty(t, res.Signal)
}

// Test_Host_PublishesReadyOnceBothSidesAcknowledge is the positive control for
// the two tests below it. "Never publishes ready" is satisfied just as well by
// a host that never publishes ready at all, so one of these has to show that a
// working session does.
func Test_Host_PublishesReadyOnceBothSidesAcknowledge(t *testing.T) {
	run := newOutcomeRun(t, []string{"sh", "-c", "echo READY; sleep 300"})

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- run.host.Run(ctx) }()

	awaitMarker(t, run.stdout, "READY")

	// Waits rather than samples: the marker proves the command started, and
	// the admin socket may bind a moment either side of that. The session
	// stays ready until it is cancelled, so waiting is not a race.
	require.Eventually(t, func() bool {
		rec, err := sessiondir.ReadRecord(run.stateRoot, run.name)
		return err == nil && rec != nil && rec.Status == sessiondir.StatusReady && rec.SessionID != ""
	}, outcomeTimeout, outcomePollInterval,
		"a live session must be published as ready, carrying the session ID a reader would connect with")

	cancel()
	select {
	case err := <-done:
		t.Logf("host run returned: %v", err)
	case <-time.After(outcomeTimeout):
		t.Fatalf("host did not return within %s of cancellation", outcomeTimeout)
	}
	run.closeWriters()

	require.Equal(t, sessiondir.StatusEnding, run.record(t).Status)
}

// Test_Host_GivesTheCommandTheSessionName covers wiring rather than an
// outcome: the host puts the claimed name in the command's environment so that
// a script inside the session can name itself to `upterm session info`. A typo
// in the variable would be invisible everywhere else.
//
// The environment it runs in already carries both session variables, which is
// what a host started inside another session sees. They have to lose to this
// session's own, so the assertion below is about precedence as much as wiring.
func Test_Host_GivesTheCommandTheSessionName(t *testing.T) {
	t.Setenv(upterm.HostSessionNameEnvVar, "outer-session")
	t.Setenv(upterm.HostAdminSocketEnvVar, "/outer/admin.sock")

	run := newOutcomeRun(t, []string{"sh", "-c", "echo NAME=$" + upterm.HostSessionNameEnvVar})

	collected := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(run.stdout)
		collected <- string(b)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()

	err := run.host.Run(ctx)
	// The host's stdout sink is flushed as Run returns, so closing the write
	// ends here is what turns the read above into an EOF rather than a hang.
	run.closeWriters()
	t.Logf("host run returned: %v", err)

	select {
	case out := <-collected:
		require.Contains(t, out, "NAME="+run.name,
			"the command must be able to find out which session it is running in")
	case <-time.After(outcomeTimeout):
		t.Fatalf("host stdout did not reach EOF within %s", outcomeTimeout)
	}
}

// Test_Host_LostTunnelIsAStateNotAnOutcome is the Host-level counterpart to
// the internal tunnel tests: the relay is taken away under a live session, and
// the command has to survive it. A lost tunnel drops the guests and publishes
// "disconnected"; the session still ends for the reason it is eventually
// stopped for, not for the network.
func Test_Host_LostTunnelIsAStateNotAnOutcome(t *testing.T) {
	run := newOutcomeRun(t, []string{"sh", "-c", "echo READY; sleep 300"})

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = io.Copy(io.Discard, run.stdout)
	}()

	done := make(chan error, 1)
	go func() { done <- run.host.Run(ctx) }()

	require.Eventually(t, func() bool {
		rec, err := sessiondir.ReadRecord(run.stateRoot, run.name)
		return err == nil && rec != nil && rec.Status == sessiondir.StatusReady
	}, outcomeTimeout, outcomePollInterval,
		"the session must be ready before the tunnel can be lost from under it")

	require.NoError(t, run.relay.Shutdown())

	require.Eventually(t, func() bool {
		rec, err := sessiondir.ReadRecord(run.stateRoot, run.name)
		return err == nil && rec != nil && rec.Status == sessiondir.StatusDisconnected
	}, 20*time.Second, outcomePollInterval,
		"a host that lost its tunnel must publish disconnected, and must not have exited")

	// Still running, which is the whole claim: the command outlived the
	// network. Now end it the way an operator would.
	cancel()
	select {
	case err := <-done:
		t.Logf("host run returned: %v", err)
	case <-time.After(outcomeTimeout):
		t.Fatalf("host did not return within %s of cancellation", outcomeTimeout)
	}
	run.closeWriters()
	<-drained

	rec := run.record(t)
	require.Equal(t, sessiondir.StatusEnding, rec.Status)
	require.Equal(t, sessiondir.ReasonStopped, rec.Reason,
		"a session stopped by its operator must not be reported as the network's fault")
	require.Nil(t, rec.ExitCode)
}

func Test_Host_NeverPublishesReadyWhenClaimRefusesTheSocketPath(t *testing.T) {
	run := newOutcomeRun(t, []string{"sh", "-c", "sleep 300"})

	// A runtime root deep enough that <root>/upterm/sessions/<name>/admin.sock
	// is longer than a unix socket path may be. Claim refuses it up front, so
	// the run never reaches the tunnel — which is the point of checking there:
	// this used to fail in net.Listen with the name already claimed, the
	// record already published, and the classification racing the command.
	deep := filepath.Join(shortXDGDir(t), strings.Repeat("d", 120))
	require.NoError(t, os.MkdirAll(deep, 0700))
	t.Setenv("XDG_RUNTIME_DIR", deep)

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = io.Copy(io.Discard, run.stdout)
	}()

	done := make(chan struct{})
	statuses := watchStatuses(run.stateRoot, run.name, done)

	err := run.host.Run(ctx)
	close(done)
	run.closeWriters()
	<-drained
	t.Logf("host run returned: %v", err)
	require.ErrorIs(t, err, sessiondir.ErrSocketPathTooLong,
		"a name whose admin socket cannot be bound must be refused, not attempted")

	seen := <-statuses
	require.NotContains(t, seen, sessiondir.StatusReady,
		"a session that never bound its admin socket must never have been published as ready")

	// The claim failed, so this run published nothing at all: the record under
	// the short state root is the one the *previous* claim in newOutcomeRun
	// would have left, and there is none. Reading it must say "no such
	// session" rather than report an outcome.
	_, readErr := sessiondir.ReadRecord(run.stateRoot, run.name)
	require.True(t, os.IsNotExist(readErr),
		"a refused claim must leave no record behind, got %v", readErr)
}

func Test_Host_NeverPublishesReadyWhenCommandCannotStart(t *testing.T) {
	run := newOutcomeRun(t, []string{"/nonexistent/definitely-not-a-command"})

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = io.Copy(io.Discard, run.stdout)
	}()

	done := make(chan struct{})
	statuses := watchStatuses(run.stateRoot, run.name, done)

	err := run.host.Run(ctx)
	close(done)
	run.closeWriters()
	<-drained
	t.Logf("host run returned: %v", err)
	require.Error(t, err, "a host whose command cannot start must not report success")

	seen := <-statuses
	require.NotContains(t, seen, sessiondir.StatusReady,
		"a session whose command never started must never have been published as ready")

	rec := run.record(t)
	require.Equal(t, sessiondir.StatusEnding, rec.Status)
	require.Equal(t, sessiondir.ReasonStartupFailed, rec.Reason,
		"a command that never started is a startup failure, not an outcome of its own")
	require.Nil(t, rec.ExitCode)
}
