package command

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// fakeRun stands in for Host.Run: it drives the callbacks the exchange is
// wired to, in the order Run calls them, against a directory it claims for
// real so SessionClaimedCallback has something to report.
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
	done := make(chan error, 1)
	go func() {
		done <- runDaemonProcess(context.Background(), discardLogger(), testHostOptions(), a, "daemon-1", fakeRun(t, "sid-1", nil))
	}()
	out, err := parent.Run(context.Background(), bootstrap.Handlers{
		Claimed:   func(c *api.Claimed) { claimed = c },
		Listening: func(l *api.Listening) { listening = l },
	})
	require.NoError(t, err)
	require.NoError(t, <-done)
	require.NotNil(t, out.Started)
	require.Equal(t, "sid-1", out.Started.SessionId)
	require.NotNil(t, claimed)
	require.Equal(t, "daemon-1", claimed.Name)
	require.NotEmpty(t, claimed.LaunchId)
	require.Equal(t, int32(os.Getpid()), claimed.Pid)
	require.Equal(t, utils.UptermLogFilePath(), claimed.LogPath)
	require.NotNil(t, listening)
	require.Equal(t, claimed.AttachSocket, listening.AttachSocket)
	require.NotEmpty(t, listening.HostKeys, "the parent pins these")

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
// CommandStartedCallback to have returned, since a real parent process has
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
