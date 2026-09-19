package ftests

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
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

// shellCommand picks this platform's spelling of a case's command.
//
// What these cases are about is what a host publishes, not what shell ran:
// Windows has no POSIX shell, which is a fact about the command rather than
// about the guarantee, so each case names the same work twice and runs
// whichever spelling this platform can.
//
// A nil Windows spelling means the case has none. That is the signal case:
// Windows reports a terminated process as an ordinary exit status, so
// "signalled" is not a distinction the platform can make, and there is no
// command that would make it one.
func shellCommand(t *testing.T, posix, windows []string) []string {
	t.Helper()

	if runtime.GOOS != "windows" {
		return posix
	}
	if windows == nil {
		t.Skip("Windows reports a terminated process as an ordinary exit status, so there is no signalled outcome to publish")
	}
	return windows
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

	// attachSocket carries the path the daemon bound its local door at, so a
	// case can attach a client to the session it is watching.
	attachSocket chan string

	// Set by options before the host and relay are built.
	signers        []ssh.Signer
	sessionCreated func(context.Context, *api.GetSessionResponse) error
	relayOptions   []func(*Server)
}

// outcomeOption adjusts the host a case runs, for the things that are not the
// command it hosts.
type outcomeOption func(*outcomeRun)

// withSessionCreatedCallback stands in for the interactive confirmation: the
// CLI asks the operator there, and it is the only hook that can refuse a
// session after the relay has created it but before the command exists.
func withSessionCreatedCallback(cb func(context.Context, *api.GetSessionResponse) error) outcomeOption {
	return func(r *outcomeRun) { r.sessionCreated = cb }
}

// withSigners replaces the host's identity.
func withSigners(signers []ssh.Signer) outcomeOption {
	return func(r *outcomeRun) { r.signers = signers }
}

// withRelayAuthorizedKeys runs the relay with an allowlist of host identities.
func withRelayAuthorizedKeys(path string) outcomeOption {
	return func(r *outcomeRun) {
		r.relayOptions = append(r.relayOptions, func(s *Server) {
			s.authorizedKeysFiles = append(s.authorizedKeysFiles, path)
		})
	}
}

// newOutcomeRun builds a Host that claims a session directory for real.
//
// Deliberately not the ftests.Host wrapper: that requires an AdminSocketFile,
// and supplying one is exactly what makes Host.Run skip the claim these tests
// are about.
func newOutcomeRun(t *testing.T, command []string, opts ...outcomeOption) *outcomeRun {
	t.Helper()

	dir := shortXDGDir(t)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("XDG_STATE_HOME", dir)

	name := uniqueSessionName(t)

	// Buffered for two runs: Test_Host_CanRunTwice runs the same Host twice,
	// and a callback nobody is receiving must not block the second startup.
	attachSocket := make(chan string, 2)

	run := &outcomeRun{
		name:         name,
		stateRoot:    utils.UptermStateDir(),
		attachSocket: attachSocket,
	}
	for _, opt := range opts {
		opt(run)
	}

	ts, err := NewServerWithOptions(ServerPrivateKeyContent, routing.ModeEmbedded, run.relayOptions...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ts.Shutdown() })
	run.relay = ts

	signers := run.signers
	if signers == nil {
		signers, err = utils.CreateSigners([][]byte{[]byte(HostPrivateKeyContent)})
		require.NoError(t, err)
	}

	run.host = &host.Host{
		Host:                    "ssh://" + ts.SSHAddr(),
		Name:                    name,
		Command:                 command,
		Signers:                 signers,
		HostKeyCallback:         ssh.InsecureIgnoreHostKey(),
		KeepAliveDuration:       keepAliveDuration,
		Logger:                  testLogger,
		SessionCreatedCallback:  run.sessionCreated,
		AttachListeningCallback: func(s string) { attachSocket <- s },
	}

	return run
}

// awaitAttachSocket returns the path the daemon bound its attach door at.
func (r *outcomeRun) awaitAttachSocket(t *testing.T) string {
	t.Helper()
	select {
	case s := <-r.attachSocket:
		return s
	case <-time.After(outcomeTimeout):
		t.Fatal("the daemon never bound its attach socket")
		return ""
	}
}

// attachViewer attaches an output-only client and returns its output. The
// keys it pins come from the session record the daemon already published,
// the same source `upterm attach` reads them from.
func (r *outcomeRun) attachViewer(t *testing.T, ctx context.Context, socket string) io.Reader {
	t.Helper()
	rec := r.record(t)
	keys := make([]ssh.PublicKey, 0, len(rec.HostKeys))
	for _, k := range rec.HostKeys {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
		require.NoError(t, err)
		keys = append(keys, key)
	}
	pr, pw := io.Pipe()
	client := &attach.Client{Socket: socket, HostKeys: keys, Stdout: pw, Logger: testLogger}
	go func() {
		_, err := client.Run(ctx)
		_ = pw.CloseWithError(err)
	}()
	return pr
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
func runHostForOutcome(t *testing.T, command []string, opts ...outcomeOption) *sessiondir.Record {
	t.Helper()

	run := newOutcomeRun(t, command, opts...)

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()

	// Nothing to drain: the daemon has no stdout of its own, and no client is
	// attached, so the fan-out's only consumer is its replay ring.
	err := run.host.Run(ctx)
	t.Logf("host run returned: %v", err)

	return run.record(t)
}

// runHostUntilCancelled starts a host, attaches a viewer, waits for marker on
// what it receives, then cancels the context the host was given and waits for
// Run to return.
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
	awaitMarker(t, run.attachViewer(t, ctx, run.awaitAttachSocket(t)), marker)
	cancel()

	select {
	case err := <-done:
		t.Logf("host run returned: %v", err)
	case <-time.After(outcomeTimeout):
		t.Fatalf("host did not return within %s of cancellation", outcomeTimeout)
	}

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
	res := runHostForOutcome(t, shellCommand(t,
		[]string{"sh", "-c", "exit 42"},
		[]string{"cmd", "/c", "exit", "42"}))
	require.Equal(t, sessiondir.ReasonExited, res.Reason)
	require.NotNil(t, res.ExitCode)
	require.Equal(t, 42, *res.ExitCode)
}

func Test_Host_PublishesZeroExit(t *testing.T) {
	res := runHostForOutcome(t, shellCommand(t,
		[]string{"sh", "-c", "exit 0"},
		[]string{"cmd", "/c", "exit", "0"}))
	require.Equal(t, sessiondir.ReasonExited, res.Reason)
	require.NotNil(t, res.ExitCode)
	require.Equal(t, 0, *res.ExitCode)
}

// Test_Host_CanRunTwice pins that running a Host does not consume it. A
// supervisor that restarts a session, and a test that reuses its fixture,
// both call Run again on the same value — and the bookkeeping Run leaves
// behind used to make the second run publish into the first run's released
// directory, which by then may belong to somebody else entirely.
func Test_Host_CanRunTwice(t *testing.T) {
	run := newOutcomeRun(t, shellCommand(t,
		[]string{"sh", "-c", "exit 0"},
		[]string{"cmd", "/c", "exit", "0"}))

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()

	t.Logf("first host run returned: %v", run.host.Run(ctx))
	first := run.record(t)

	t.Logf("second host run returned: %v", run.host.Run(ctx))
	second := run.record(t)

	require.NotEqual(t, first.LaunchID, second.LaunchID,
		"the second run must claim the name for itself rather than inherit the first run's claim")
	// Per run means per run: a Host run twice generates a key each time.
	require.Len(t, first.HostKeys, 1)
	require.Len(t, second.HostKeys, 1)
	require.NotEqual(t, first.HostKeys[0], second.HostKeys[0],
		"the second run must present a key of its own, not the first run's")
	for i, rec := range []*sessiondir.Record{first, second} {
		require.Equal(t, sessiondir.StatusEnding, rec.Status, "run %d", i+1)
		require.Equal(t, sessiondir.ReasonExited, rec.Reason, "run %d", i+1)
		require.NotNil(t, rec.ExitCode, "run %d", i+1)
		require.Equal(t, 0, *rec.ExitCode, "run %d", i+1)
	}

	// The same state root newOutcomeRun pointed the host at, by way of the
	// environment it set. Ownership lives beside the record, so that root is
	// the whole of what this asks about.
	_, held, err := sessiondir.Inspect(ctx, run.stateRoot, run.name)
	require.NoError(t, err)
	require.False(t, held,
		"a host that has returned must leave its name free, however many times it has run")
}

func Test_Host_PublishesSignalTermination(t *testing.T) {
	res := runHostForOutcome(t, shellCommand(t,
		[]string{"sh", "-c", "kill -TERM $$"},
		nil))
	require.Equal(t, sessiondir.ReasonSignaled, res.Reason,
		"a signalled command must not be reported as exited -1")
	require.Nil(t, res.ExitCode)
}

// Test_Host_PublishesStartupAbandonedWhenTheCallbackDeclines separates a
// session nobody wanted from one that broke. The interactive confirmation
// runs in SessionCreatedCallback, after the relay has created the session and
// before the command exists, so declining it returns an error from a place
// where every error used to be a startup failure — and `upterm session info`
// then reported a fault for an operator who simply said no.
//
// The plain-error case is the control: without it, "abandoned" could be what
// this path reports for everything.
func Test_Host_PublishesStartupAbandonedWhenTheCallbackDeclines(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{
			name: "the operator declined the session",
			err:  fmt.Errorf("declined: %w", host.ErrSessionAbandoned),
			want: sessiondir.ReasonStartupAbandoned,
		},
		{
			name: "the callback could not do its job",
			err:  errors.New("no terminal to ask on"),
			want: sessiondir.ReasonStartupFailed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := runHostForOutcome(t,
				shellCommand(t,
					[]string{"sh", "-c", "exit 0"},
					[]string{"cmd", "/c", "exit", "0"}),
				withSessionCreatedCallback(func(context.Context, *api.GetSessionResponse) error {
					return tc.err
				}))

			require.Equal(t, sessiondir.StatusEnding, rec.Status)
			require.Equal(t, tc.want, rec.Reason)
			require.Nil(t, rec.ExitCode,
				"the command never started, so there is no exit code to report")
		})
	}
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
	res := runHostUntilCancelled(t, shellCommand(t,
		[]string{"sh", "-c", "echo READY; sleep 300"},
		[]string{"cmd", "/c", "echo READY & ping -n 400 127.0.0.1 >nul"}), "READY")

	require.Equal(t, sessiondir.ReasonStopped, res.Reason,
		"a shutdown we initiated must not be reported as the signal it produced")
	require.Nil(t, res.ExitCode,
		"the exit code of a process we killed is not the command's own outcome")
	require.Empty(t, res.Signal)
}

// Test_Host_PublishesStoppedWhenCancelledBeforeTheCommandStarts is the
// cancellation the signal actor cannot answer for: it is registered only
// after SessionCreatedCallback returns, so a caller that cancels while the
// callback is waiting -- or during Establish, before it -- gets ctx.Err()
// back through a path where every error used to be a startup failure, and
// the record said the session broke when it had been told to stop. The
// callback here waits on the context the way the interactive confirmation
// does, and the test cancels once it is known to be waiting.
func Test_Host_PublishesStoppedWhenCancelledBeforeTheCommandStarts(t *testing.T) {
	entered := make(chan struct{})
	run := newOutcomeRun(t,
		shellCommand(t,
			[]string{"sh", "-c", "exit 0"},
			[]string{"cmd", "/c", "exit", "0"}),
		withSessionCreatedCallback(func(ctx context.Context, _ *api.GetSessionResponse) error {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		}))

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- run.host.Run(ctx) }()

	// A cancellation that lands before the callback is entered would end
	// the run somewhere else; waiting for the channel pins it to this path.
	select {
	case <-entered:
	case <-time.After(outcomeTimeout):
		t.Fatalf("the callback was not entered within %s", outcomeTimeout)
	}
	cancel()

	select {
	case err := <-done:
		t.Logf("host run returned: %v", err)
	case <-time.After(outcomeTimeout):
		t.Fatalf("host did not return within %s of cancellation", outcomeTimeout)
	}

	rec := run.record(t)
	require.Equal(t, sessiondir.StatusEnding, rec.Status)
	require.Equal(t, sessiondir.ReasonStopped, rec.Reason,
		"a session cancelled before its command started was told to stop; nothing failed")
	require.Nil(t, rec.ExitCode,
		"the command never started, so there is no exit code to report")
	require.Empty(t, rec.Signal)
}

// Test_Host_PublishesReadyOnceBothSidesAcknowledge is the positive control for
// the two tests below it. "Never publishes ready" is satisfied just as well by
// a host that never publishes ready at all, so one of these has to show that a
// working session does.
func Test_Host_PublishesReadyOnceBothSidesAcknowledge(t *testing.T) {
	run := newOutcomeRun(t, shellCommand(t,
		[]string{"sh", "-c", "echo READY; sleep 300"},
		[]string{"cmd", "/c", "echo READY & ping -n 400 127.0.0.1 >nul"}))

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- run.host.Run(ctx) }()

	awaitMarker(t, run.attachViewer(t, ctx, run.awaitAttachSocket(t)), "READY")

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

	run := newOutcomeRun(t, shellCommand(t,
		[]string{"sh", "-c", "echo NAME=$" + upterm.HostSessionNameEnvVar},
		[]string{"cmd", "/c", "echo", "NAME=%" + upterm.HostSessionNameEnvVar + "%"}))
	// The command prints once and exits, so the client has to be attached
	// before it starts: that is what a viewer of an immediate-exit command
	// needs, and what upterm host asks for.
	run.host.AwaitInitialClient = true

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- run.host.Run(ctx) }()

	out := run.attachViewer(t, ctx, run.awaitAttachSocket(t))
	awaitMarker(t, out, "NAME="+run.name)

	select {
	case err := <-done:
		t.Logf("host run returned: %v", err)
	case <-time.After(outcomeTimeout):
		t.Fatalf("host did not return within %s", outcomeTimeout)
	}
}

// Test_Host_LostTunnelIsAStateNotAnOutcome is the Host-level counterpart to
// the internal tunnel tests: the relay is taken away under a live session, and
// the command has to survive it. A lost tunnel drops the guests and publishes
// "disconnected"; the session still ends for the reason it is eventually
// stopped for, not for the network.
func Test_Host_LostTunnelIsAStateNotAnOutcome(t *testing.T) {
	// A marker a second, so that "still running" can be shown by what the
	// command produces rather than only by what the record says. ping prints
	// one reply per second, which is the same shape on the platform with no
	// shell loop.
	tick := "TICK"
	if runtime.GOOS == "windows" {
		tick = "Reply from"
	}
	run := newOutcomeRun(t, shellCommand(t,
		[]string{"sh", "-c", "echo READY; while :; do sleep 1; echo TICK; done"},
		[]string{"cmd", "/c", "echo READY & ping -n 400 127.0.0.1"}))

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- run.host.Run(ctx) }()

	// A viewer attached before the loss, counting the markers it receives.
	// Design item 6: the command and the local client both survive a tunnel
	// that goes away.
	//
	// The socket is awaited here rather than inside the goroutine below:
	// awaitAttachSocket calls t.Fatal, which from a goroutine that is not the
	// test's stops only that goroutine, so a daemon that never bound would
	// hang to the package timeout instead of failing.
	out := run.attachViewer(t, ctx, run.awaitAttachSocket(t))
	var ticks atomic.Int64
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if strings.Contains(sc.Text(), tick) {
				ticks.Add(1)
			}
		}
	}()

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

	// Two more markers, not one: a single one could have been in flight when
	// the relay went away, and what is being shown is output produced after
	// it did.
	before := ticks.Load()
	require.Eventually(t, func() bool { return ticks.Load() > before+1 }, 20*time.Second, 50*time.Millisecond,
		"the command kept running, and the local client kept receiving it, after the tunnel was lost")

	// And it stays disconnected while the session runs on. Nothing may talk
	// the record back into "ready" once the tunnel that ready describes is
	// gone: a reader of `upterm session list` would be offered a session
	// nobody can reach.
	require.Never(t, func() bool {
		rec, err := sessiondir.ReadRecord(run.stateRoot, run.name)
		return err != nil || rec == nil || rec.Status != sessiondir.StatusDisconnected
	}, time.Second, outcomePollInterval,
		"a session whose tunnel is gone must not be published as ready again")

	// Still running, which is the whole claim: the command outlived the
	// network. Now end it the way an operator would.
	cancel()
	select {
	case err := <-done:
		t.Logf("host run returned: %v", err)
	case <-time.After(outcomeTimeout):
		t.Fatalf("host did not return within %s of cancellation", outcomeTimeout)
	}

	rec := run.record(t)
	require.Equal(t, sessiondir.StatusEnding, rec.Status)
	require.Equal(t, sessiondir.ReasonStopped, rec.Reason,
		"a session stopped by its operator must not be reported as the network's fault")
	require.Nil(t, rec.ExitCode)
}

func Test_Host_NeverPublishesReadyWhenClaimRefusesTheSocketPath(t *testing.T) {
	run := newOutcomeRun(t, shellCommand(t,
		[]string{"sh", "-c", "sleep 300"},
		[]string{"cmd", "/c", "ping -n 400 127.0.0.1 >nul"}))

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

	done := make(chan struct{})
	statuses := watchStatuses(run.stateRoot, run.name, done)

	err := run.host.Run(ctx)
	close(done)
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

	done := make(chan struct{})
	statuses := watchStatuses(run.stateRoot, run.name, done)

	err := run.host.Run(ctx)
	close(done)
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

func Test_Host_PublishesStartupAbandonedWhenNoClientAttaches(t *testing.T) {
	run := newOutcomeRun(t, shellCommand(t, []string{"sh", "-c", "exit 0"}, []string{"cmd", "/c", "exit", "0"}))
	run.host.AwaitInitialClient = true
	run.host.InitialClientTimeout = 300 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()
	// Nothing attaches, so there is nothing to drain: the daemon gives up on
	// its own and the record is the whole of what it left behind.
	err := run.host.Run(ctx)
	require.ErrorIs(t, err, host.ErrNoInitialClient)

	rec := run.record(t)
	require.Equal(t, sessiondir.ReasonStartupAbandoned, rec.Reason)
	require.Equal(t, sessiondir.StatusEnding, rec.Status)
	require.Nil(t, rec.ExitCode)
}

func Test_Host_PublishesTheAttachSocketAndServesIt(t *testing.T) {
	run := newOutcomeRun(t, shellCommand(t,
		[]string{"sh", "-c", "echo ATTACHED; sleep 30"},
		[]string{"cmd", "/c", "echo ATTACHED & ping -n 30 127.0.0.1 > NUL"}))
	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run.host.Run(ctx) }()

	sock := run.awaitAttachSocket(t)
	rec, err := sessiondir.ReadRecord(run.stateRoot, run.name)
	require.NoError(t, err)
	require.Equal(t, sock, rec.AttachSocket, "the record names the socket the daemon bound")

	out := run.attachViewer(t, ctx, sock)
	awaitMarker(t, out, "ATTACHED")
	cancel()
	<-done
}
