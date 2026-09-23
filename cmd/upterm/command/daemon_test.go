package command

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// daemonTestRoots points the session directories at a socket-safe temp root,
// and flagKnownHostsFilename at a file under it. Production always reaches
// buildDaemonHost through hostCmd(), whose flag registration gives that
// global a real default; a unit test that calls runDaemonProcess directly
// never runs that registration; without this, newHostKeyCallback's
// createFileIfNotExist("") fails every case here with "open : no such file
// or directory".
//
// It also resets suppliedFlags: a real daemon is a fresh process, whose own
// Root().Execute() populates that package var from its own os.Args before
// shareRunE ever runs. These tests call runDaemonProcess directly, bypassing
// Root() entirely, so nothing here ever sets it — it is whatever the last
// cobra command executed in this test binary left behind. At -count=1 that
// is always the zero value, since daemon_test.go sorts before host_test.go
// and nothing runs first; at -count=2 or higher, a later iteration
// otherwise inherits Test_hostCmd_*'s leftover flags and authorizationRequested
// spuriously refuses every one of these sessions.
func daemonTestRoots(t *testing.T) {
	t.Helper()
	root := "/tmp"
	if runtime.GOOS == "windows" {
		root = ""
	}
	dir, err := os.MkdirTemp(root, "up")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("XDG_STATE_HOME", dir)

	origKnownHosts := flagKnownHostsFilename
	flagKnownHostsFilename = filepath.Join(dir, "known_hosts")
	t.Cleanup(func() { flagKnownHostsFilename = origKnownHosts })

	origSupplied := suppliedFlags
	suppliedFlags = map[string]bool{}
	t.Cleanup(func() { suppliedFlags = origSupplied })
}

// readyPublishGap is how long fakeRun leaves between the command starting
// and the record saying ready.
//
// The real Host has that gap for real: the command's start is one of the two
// facts readiness is made of, and the readiness actor writes the record only
// once it has both. Modelled here rather than left to chance so that
// TestRunDaemonProcessSpeaksTheExchange pins the order of the two rather
// than which goroutine happened to run first — a daemon that told its parent
// "started" from CommandStartedCallback would still be caught by the record
// read, and be caught every time.
const readyPublishGap = 100 * time.Millisecond

// fakeRun stands in for Host.Run: it drives the callbacks the exchange is
// wired to, in the order Run calls them, against a directory it claims for
// real so SessionClaimedCallback has something to report — including the
// ready record, which the readiness actor writes before it calls back and
// which is therefore part of the order.
//
// It runs on runDaemonProcess's own goroutine, not the test's, so a failed
// require here would call t.FailNow off the test goroutine and hang the
// test on <-done instead of failing it; assert.NoError plus an explicit
// return surfaces the failure through runDaemonProcess's own return value.
func fakeRun(t *testing.T, sessionID string, result error) func(context.Context, *host.Host) error {
	return func(ctx context.Context, h *host.Host) error {
		if errors.Is(result, sessiondir.ErrNameInUse) {
			return result
		}
		dir, err := sessiondir.Claim(ctx, sessiondir.ClaimOptions{
			RuntimeRoot: utils.UptermRuntimeDir(), StateRoot: utils.UptermStateDir(),
			Name: h.Name, Command: h.Command,
		})
		assert.NoError(t, err)
		if err != nil {
			return err
		}
		defer func() { _ = dir.Release(context.Background()) }()
		if h.SessionClaimedCallback != nil {
			h.SessionClaimedCallback(dir)
		}
		if h.SessionCreatedCallback != nil {
			if err := h.SessionCreatedCallback(ctx, &api.GetSessionResponse{SessionId: sessionID, Host: "ssh://127.0.0.1:2222", NodeAddr: "127.0.0.1:2222", Command: h.Command}); err != nil {
				return err
			}
		}
		if h.AttachListeningCallback != nil {
			h.AttachListeningCallback(dir.AttachSocket())
		}
		if result != nil {
			return result
		}
		if h.CommandStartedCallback != nil {
			h.CommandStartedCallback()
		}
		time.Sleep(readyPublishGap)
		// The status is read back out of the record rather than assumed, as
		// the readiness actor reads it back out of the mutation it ran: what
		// the callback carries is what a reader would find.
		published := ""
		err = dir.Update(func(r *sessiondir.Record) {
			r.SessionID = sessionID
			r.Status = sessiondir.StatusReady
			published = r.Status
		})
		assert.NoError(t, err)
		if err != nil {
			return err
		}
		if h.SessionReadyCallback != nil {
			h.SessionReadyCallback(published)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
			return nil
		}
	}
}

func testHostOptions() hostOptions {
	return hostOptions{command: []string{"sh"}, term: "xterm"}
}

func TestRunDaemonProcessSpeaksTheExchange(t *testing.T) {
	daemonTestRoots(t)
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	parent := bootstrap.NewParent(b, nil, io.Discard, nil)

	var claimed *api.Claimed
	var listening *api.Listening
	var doorKey ssh.PublicKey
	run := fakeRun(t, "sid-1", nil)
	done := make(chan error, 1)
	go func() {
		done <- runDaemonProcess(context.Background(), discardLogger(), testHostOptions(), a, "daemon-1",
			func(ctx context.Context, h *host.Host) error {
				// What the embedded sshd will present on the attach door.
				if h.HostKey != nil {
					doorKey = h.HostKey.PublicKey()
				}
				return run(ctx, h)
			})
	}()
	out, err := parent.Run(context.Background(), bootstrap.Handlers{
		Claimed:   func(c *api.Claimed) { claimed = c },
		Listening: func(l *api.Listening) { listening = l },
	})
	require.NoError(t, err)

	// Read here, before the daemon is waited for, because this is the record
	// as it stood at the moment the parent was told the session had started
	// -- which is the moment `upterm host --detach -o json` prints "status":
	// "ready" and exits, and the moment the script it printed to runs
	// `upterm session info`. Told started off the command alone, the daemon
	// would be answering for a record that still said starting.
	atStarted, err := sessiondir.ReadRecord(utils.UptermStateDir(), "daemon-1")
	require.NoError(t, err)
	require.NotNil(t, atStarted)
	require.Equal(t, sessiondir.StatusReady, atStarted.Status,
		"the parent is told started only once the record it will be read against says ready")
	require.Equal(t, "sid-1", atStarted.SessionID,
		"and carries the session ID, which is published by the same write")

	require.NoError(t, <-done)
	require.NotNil(t, out.Started)
	require.Equal(t, "sid-1", out.Started.SessionId)
	require.Equal(t, atStarted.Status, out.Started.Status,
		"the parent is told the status the record carries, which is what it prints")
	require.NotNil(t, claimed)
	require.Equal(t, "daemon-1", claimed.Name)
	require.NotEmpty(t, claimed.LaunchId)
	require.Equal(t, int32(os.Getpid()), claimed.Pid)
	require.Equal(t, utils.UptermLogFilePath(), claimed.LogPath)
	require.NotNil(t, listening)
	require.Equal(t, claimed.AttachSocket, listening.AttachSocket)
	// Not merely non-empty: the parent pins whatever this names, and the
	// door presents the session host key — never the --private-key signers,
	// which authenticate the tunnel and nothing else. Reporting the signers
	// leaves the parent unable to attach to its own session.
	require.NotNil(t, doorKey, "the daemon must set the host key it reports")
	require.Equal(t,
		[]string{strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(doorKey)), "\n")},
		listening.HostKeys,
		"the parent pins the door's session host key")

	rec, err := sessiondir.ReadRecord(utils.UptermStateDir(), "daemon-1")
	require.NoError(t, err)
	require.Equal(t, utils.UptermLogFilePath(), rec.LogPath, "published for readers under another state root")
}

func TestRunDaemonProcessReportsANameInUse(t *testing.T) {
	daemonTestRoots(t)
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	parent := bootstrap.NewParent(b, nil, io.Discard, nil)
	done := make(chan error, 1)
	go func() {
		done <- runDaemonProcess(context.Background(), discardLogger(), testHostOptions(), a, "taken", fakeRun(t, "", sessiondir.ErrNameInUse))
	}()
	out, err := parent.Run(context.Background(), bootstrap.Handlers{})
	require.NoError(t, err)
	require.ErrorIs(t, <-done, sessiondir.ErrNameInUse)
	require.NotNil(t, out.Failed)
	require.True(t, out.Failed.NameInUse)
}

// TestRunDaemonReportsAnArgumentItCannotParse pins the one failure that used
// to be silent. A daemon whose own argv does not parse never reached
// runDaemonProcess, so nothing was ever sent, and the parent saw its end of
// the channel close and reported the daemon as gone rather than the reason.
// Unreachable in practice -- the parent parsed the same argv before it
// spawned anything -- but a failure shape that only holds while a caller
// stays correct is not a shape.
func TestRunDaemonReportsAnArgumentItCannotParse(t *testing.T) {
	daemonTestRoots(t)

	// Two characters where parseEscapeChar wants one, which is the cheapest
	// way to make parseHostOptions fail without touching the arguments the
	// session would run.
	orig := flagHostEscapeChar
	flagHostEscapeChar = "xy"
	t.Cleanup(func() { flagHostEscapeChar = orig })
	// parseHostOptions reads this one first, so a bad URL left behind by
	// another test would fail the daemon on an error this case is not about.
	// The assertion below names --escape-char and would catch it, but loudly
	// failing for the wrong reason is still a worse test than not being able
	// to.
	origProxy := flagProxy
	flagProxy = ""
	t.Cleanup(func() { flagProxy = origProxy })

	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	parent := bootstrap.NewParent(b, nil, io.Discard, nil)
	done := make(chan error, 1)
	go func() {
		err := runDaemon(context.Background(), discardLogger(), []string{"sh"}, a, "bad-args")
		// A real daemon's process exits here, and that is what closes its end
		// of the channel. net.Pipe has to be told, and it matters: without
		// it, a daemon that sent nothing leaves the parent waiting on a
		// message that will never come, so the regression this test guards
		// would hang the package instead of failing it.
		_ = a.Close()
		done <- err
	}()
	out, err := parent.Run(context.Background(), bootstrap.Handlers{})
	require.NoError(t, err, "the parent read the reason, not the end of the connection")

	daemonErr := <-done
	require.ErrorContains(t, daemonErr, "--escape-char")
	require.NotNil(t, out.Failed, "the parent has to be told why, not left to read EOF as the daemon going away")
	require.Equal(t, daemonErr.Error(), out.Failed.Error,
		"the message the parent prints is the daemon's own reason, unaltered")
	require.False(t, out.Failed.NameInUse)
	require.False(t, out.Failed.Abandoned)
}

func TestRunDaemonProcessMapsTheDecision(t *testing.T) {
	for _, tc := range []struct {
		dec   api.Accept_Decision
		check func(*testing.T, error)
	}{
		{api.Accept_DECLINED, func(t *testing.T, err error) {
			var want UserDiscardedError
			require.ErrorAs(t, err, &want)
		}},
		{api.Accept_INTERRUPTED, func(t *testing.T, err error) {
			var want UserInterruptedError
			require.ErrorAs(t, err, &want)
		}},
	} {
		t.Run(tc.dec.String(), func(t *testing.T) {
			daemonTestRoots(t)
			a, b := net.Pipe()
			defer func() { _ = a.Close() }()
			parent := bootstrap.NewParent(b, nil, io.Discard, nil)
			done := make(chan error, 1)
			go func() {
				done <- runDaemonProcess(context.Background(), discardLogger(), testHostOptions(), a, "d", fakeRun(t, "sid", nil))
			}()
			out, err := parent.Run(context.Background(), bootstrap.Handlers{
				SessionCreated: func(*api.GetSessionResponse) api.Accept_Decision { return tc.dec },
			})
			require.NoError(t, err)
			runErr := <-done
			tc.check(t, runErr)
			require.ErrorIs(t, runErr, host.ErrSessionAbandoned)
			require.NotNil(t, out.Failed)
			require.True(t, out.Failed.Abandoned)
		})
	}
}

func TestRunDaemonProcessAbandonsWhenTheParentLeavesEarly(t *testing.T) {
	daemonTestRoots(t)
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	var runCtx context.Context
	entered := make(chan struct{})
	run := func(ctx context.Context, h *host.Host) error {
		runCtx = ctx
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}
	done := make(chan error, 1)
	go func() {
		done <- runDaemonProcess(context.Background(), discardLogger(), testHostOptions(), a, "d", run)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("run was never called; buildDaemonHost likely failed")
	}
	require.NoError(t, b.Close())
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the daemon did not stop when its parent left")
	}
	require.ErrorIs(t, context.Cause(runCtx), host.ErrSessionAbandoned)
}

// TestRunDaemonProcessIgnoresTheParentLeavingAfterStart pins that Disarm
// beats the parent's departure. It closes the parent's end the instant
// parent.Run reports Started — with no wait for the daemon's own
// SessionReadyCallback to have returned, since a real parent process has
// no way to wait for that either — so a Disarm that ran after Started
// (rather than before) would race this close and show up here, at least
// intermittently.
//
// cause is read from inside run, at the instant it decides not to abandon,
// rather than from outside after runDaemonProcess has returned: its own
// deferred cancel(nil) cancels the context on the way out regardless of
// outcome (context.CancelCauseFunc treats a nil cause as context.Canceled),
// so a check made after <-done would see that cleanup cancellation and not
// the abandonment question this test asks.
func TestRunDaemonProcessIgnoresTheParentLeavingAfterStart(t *testing.T) {
	daemonTestRoots(t)
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	parent := bootstrap.NewParent(b, nil, io.Discard, nil)
	var cause error
	run := func(ctx context.Context, h *host.Host) error {
		inner := fakeRun(t, "sid", nil)
		_ = inner(ctx, h)
		select {
		case <-ctx.Done():
			cause = context.Cause(ctx)
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
			cause = context.Cause(ctx)
			return nil
		}
	}
	done := make(chan error, 1)
	go func() {
		done <- runDaemonProcess(context.Background(), discardLogger(), testHostOptions(), a, "d", run)
	}()
	out, err := parent.Run(context.Background(), bootstrap.Handlers{})
	require.NoError(t, err)
	require.NotNil(t, out.Started)
	require.NoError(t, parent.Close())
	require.NoError(t, <-done, "a parent leaving after the command started is not abandonment")
	require.NoError(t, cause, "the parent leaving after start must not be recorded as an abandonment cause")
}

func TestJoinTimeoutFlagReachesHostOptions(t *testing.T) {
	cmd := hostCmd()
	t.Cleanup(func() { flagJoinTimeout = 0 })
	require.NoError(t, cmd.PersistentFlags().Parse([]string{"--join-timeout", "9m"}))
	opts, err := parseHostOptions([]string{"sh"})
	require.NoError(t, err)
	require.Equal(t, 9*time.Minute, opts.joinTimeout)
}

func TestJoinTimeoutReachesTheDaemonHost(t *testing.T) {
	hostCmd()
	daemonTestRoots(t)
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	child := bootstrap.NewChild(a, nil)
	t.Cleanup(func() { _ = child.Close() })
	opts := testHostOptions()
	opts.joinTimeout = 7 * time.Minute
	h, err := buildDaemonHost(context.Background(), "n", opts, child, discardLogger())
	require.NoError(t, err)
	require.Equal(t, 7*time.Minute, h.JoinTimeout)
}

func TestJoinTimeoutFlagDefaultsToOff(t *testing.T) {
	f := hostCmd().PersistentFlags().Lookup("join-timeout")
	require.NotNil(t, f)
	require.Equal(t, "0s", f.DefValue)
}

func TestJoinTimeoutFlagRejectsNegative(t *testing.T) {
	cmd := hostCmd()
	t.Cleanup(func() { flagJoinTimeout = 0 })
	require.NoError(t, cmd.PersistentFlags().Parse([]string{"--join-timeout", "-5m"}))
	err := cmd.PreRunE(cmd, nil)
	require.ErrorContains(t, err, "--join-timeout cannot be negative")
}
