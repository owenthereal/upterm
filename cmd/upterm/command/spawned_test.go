package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// scriptedDaemon is the far end of a spawn: a bootstrap.Child driven by a
// script, standing in for the daemon process.
type scriptedDaemon struct {
	child *bootstrap.Child
	ready chan struct{} // closed once spawn has built the child
	gone  chan struct{} // closed when the child's watcher fires (parent left while armed)
}

func newScriptedDaemon(t *testing.T) (spawnFunc, *scriptedDaemon) {
	t.Helper()
	d := &scriptedDaemon{ready: make(chan struct{}), gone: make(chan struct{})}
	spawn := func(opts spawnOptions) (net.Conn, *os.Process, error) {
		require.NotEmpty(t, opts.name)
		require.NotEmpty(t, opts.logPath)
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		d.child = bootstrap.NewChild(a, func() { close(d.gone) })
		close(d.ready)
		return b, nil, nil
	}
	return spawn, d
}

// await hands the script the child once spawn has built it. A channel rather
// than polling the field: spawn runs on run's goroutine and the script runs
// on its own, and an unsynchronised read of the field is a data race -race is
// right to report.
func (d *scriptedDaemon) await() *bootstrap.Child {
	select {
	case <-d.ready:
	case <-time.After(5 * time.Second):
		panic("the session never spawned a daemon")
	}
	return d.child
}

// startup runs the child's side up to and including started, on its own
// goroutine, reporting the decision it was given.
func (d *scriptedDaemon) startup(t *testing.T, name string) <-chan api.Accept_Decision {
	t.Helper()
	hostKey := testHostKeyLine(t)
	got := make(chan api.Accept_Decision, 1)
	go func() {
		child := d.await()
		_ = child.Claimed(&api.Claimed{Name: name, LaunchId: "launch-1", AdminSocket: "/run/a.sock", AttachSocket: "/run/t.sock", LogPath: "/var/log/upterm.log", Pid: 4242})
		dec, err := child.SessionCreated(&api.GetSessionResponse{SessionId: "sid-1", Host: "ssh://127.0.0.1:2222", NodeAddr: "127.0.0.1:2222", SshUser: "u", Command: []string{"bash"}})
		got <- dec
		if err != nil || dec != api.Accept_ACCEPTED {
			child.Failed("declined", false, true)
			return
		}
		_ = child.Listening("/run/t.sock", []string{hostKey})
	}()
	return got
}

func (d *scriptedDaemon) start() {
	child := d.await()
	child.Disarm()
	_ = child.Started("sid-1")
}

func newSession(t *testing.T, spawn spawnFunc, client clientFunc, stdout, stderr *bytes.Buffer) *spawnedSession {
	t.Helper()
	return &spawnedSession{
		name:         "s",
		logPath:      "/var/log/upterm.log",
		stdout:       stdout,
		stderr:       stderr,
		spawn:        spawn,
		display:      func(context.Context, *api.GetSessionResponse, string) error { return nil },
		attachClient: client,
		logger:       discardLogger(),
	}
}

func TestSpawnedSessionDetachPrintsJSON(t *testing.T) {
	spawn, d := newScriptedDaemon(t)
	var stdout, stderr bytes.Buffer
	s := newSession(t, spawn, nil, &stdout, &stderr)
	s.detach, s.jsonOut = true, true
	dec := d.startup(t, "s")
	go func() { <-dec; d.start() }()

	require.NoError(t, s.run(context.Background()))

	var info sessionInfo
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &info))
	require.Equal(t, "s", info.Name)
	require.Equal(t, "launch-1", info.LaunchID)
	require.Equal(t, sessiondir.StatusReady, info.Status)
	require.Equal(t, "sid-1", info.SessionID)
	require.Equal(t, "/run/a.sock", info.AdminSocket)
	require.Equal(t, "/run/t.sock", info.AttachSocket)
	require.Equal(t, "/var/log/upterm.log", info.LogPath)
	require.Equal(t, 4242, info.Pid)
	require.Equal(t, "ssh u@127.0.0.1 -p 2222", info.SSHCommand)
	require.Equal(t, sessiondir.ReasonUnknown, info.Reason,
		"reason is a key `session info -o json` always publishes; this shape has to match it")
	require.Empty(t, stderr.String())

	// The parent left after started; the daemon's watcher stays quiet.
	select {
	case <-d.gone:
		t.Fatal("a parent that exits after started must not be read as abandonment")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSpawnedSessionDetachPrintsHowToAttach(t *testing.T) {
	spawn, d := newScriptedDaemon(t)
	var stdout, stderr bytes.Buffer
	s := newSession(t, spawn, nil, &stdout, &stderr)
	s.detach = true
	dec := d.startup(t, "s")
	go func() { <-dec; d.start() }()
	require.NoError(t, s.run(context.Background()))
	require.Contains(t, stdout.String(), "upterm attach s")
	require.Contains(t, stdout.String(), "upterm session stop s")
}

// fakeClient attaches on cue and ends how it is told.
func fakeClient(attached chan<- string, result <-chan attach.Result) clientFunc {
	return func(ctx context.Context, socket string, keys []ssh.PublicKey) (attach.Result, error) {
		if len(keys) == 0 {
			return attach.Result{}, errors.New("no keys")
		}
		attached <- socket
		select {
		case r := <-result:
			return r, nil
		case <-ctx.Done():
			return attach.Result{Reason: attach.Detached}, nil
		}
	}
}

func TestSpawnedSessionForegroundExitStatuses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		res   attach.Result
		check func(*testing.T, error, string)
	}{
		{"detached", attach.Result{Reason: attach.Detached}, func(t *testing.T, err error, stderr string) {
			require.NoError(t, err)
			require.Contains(t, stderr, "detached from session s")
			require.Contains(t, stderr, "upterm session stop s")
		}},
		{"exited 0", attach.Result{Reason: attach.Exited, Status: 0}, func(t *testing.T, err error, _ string) {
			require.NoError(t, err)
		}},
		{"exited 7", attach.Result{Reason: attach.Exited, Status: 7}, func(t *testing.T, err error, stderr string) {
			var ec ExitCodeError
			require.ErrorAs(t, err, &ec)
			require.Equal(t, 7, ec.Code)
			// The sentence is the account, exactly as `upterm attach`
			// gives it; the nil Err is what makes host.go silence cobra
			// so nothing else is printed after it.
			require.Contains(t, stderr, "upterm: session s ended: command exited (status 7)")
			require.NoError(t, ec.Err)
		}},
		{"disconnected", attach.Result{Reason: attach.Disconnected}, func(t *testing.T, err error, stderr string) {
			var ec ExitCodeError
			require.ErrorAs(t, err, &ec)
			require.Equal(t, exitDisconnected, ec.Code)
			require.Contains(t, stderr, "upterm attach s")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spawn, d := newScriptedDaemon(t)
			attached := make(chan string, 1)
			result := make(chan attach.Result, 1)
			var stdout, stderr bytes.Buffer
			s := newSession(t, spawn, fakeClient(attached, result), &stdout, &stderr)
			d.startup(t, "s")
			go func() {
				// assert, not require: a require here would Goexit this
				// goroutine, leaving the test hung on a daemon that never
				// starts rather than failed on the mismatch.
				assert.Equal(t, "/run/t.sock", <-attached)
				d.start()
				result <- tc.res
			}()
			tc.check(t, s.run(context.Background()), stderr.String())
		})
	}
}

func TestSpawnedSessionRedrawsATakenName(t *testing.T) {
	spawn, d := newScriptedDaemon(t)
	var stdout, stderr bytes.Buffer
	s := newSession(t, spawn, nil, &stdout, &stderr)
	s.detach = true
	go func() { d.await().Failed("name in use: s", true, false) }()
	err := s.run(context.Background())
	require.ErrorIs(t, err, sessiondir.ErrNameInUse, "runWithGeneratedNameRetry redraws on exactly this error")
}

func TestSpawnedSessionDeclineIsNotAnError(t *testing.T) {
	spawn, d := newScriptedDaemon(t)
	var stdout, stderr bytes.Buffer
	s := newSession(t, spawn, nil, &stdout, &stderr)
	s.display = func(context.Context, *api.GetSessionResponse, string) error { return UserDiscardedError{} }
	dec := d.startup(t, "s")
	err := s.run(context.Background())
	require.Equal(t, api.Accept_DECLINED, <-dec)
	var discarded UserDiscardedError
	require.ErrorAs(t, err, &discarded, "shareRunE maps this to exit 0, as it did in-process")
}

func TestSpawnedSessionReportsADaemonThatDied(t *testing.T) {
	spawn, d := newScriptedDaemon(t)
	var stdout, stderr bytes.Buffer
	s := newSession(t, spawn, nil, &stdout, &stderr)
	s.detach = true
	go func() { _ = d.await().Close() }()
	err := s.run(context.Background())
	require.ErrorIs(t, err, bootstrap.ErrDaemonGone)
	require.ErrorContains(t, err, "/var/log/upterm.log", "the log is where the answer is")
}

// A terminal that never attached leaves the daemon with a gate nobody will
// open; the parent closes its end at once so the daemon abandons now rather
// than after its own timeout.
func TestSpawnedSessionAbandonsWhenItsTerminalCannotAttach(t *testing.T) {
	spawn, d := newScriptedDaemon(t)
	var stdout, stderr bytes.Buffer
	client := func(context.Context, string, []ssh.PublicKey) (attach.Result, error) {
		return attach.Result{}, errors.New("dial unix /run/t.sock: connection refused")
	}
	s := newSession(t, spawn, client, &stdout, &stderr)
	d.startup(t, "s")
	err := s.run(context.Background())
	require.ErrorContains(t, err, "could not attach the local terminal to session s")
	select {
	case <-d.gone:
	case <-time.After(2 * time.Second):
		t.Fatal("the daemon was not told")
	}
}

// TestSpawnedSessionWaitsForItsTerminalWhenTheSessionFails pins that a parent
// about to report a failed startup still waits for the client that holds the
// terminal.
//
// attachLocalTerminal restores raw mode only when its own callback returns,
// so returning here while the client is still inside it exits with the
// operator's terminal raw — and a command that cannot be exec'd is the
// ordinary way in: the terminal attaches, the gate opens, the exec fails, and
// the daemon reports failed microseconds later.
func TestSpawnedSessionWaitsForItsTerminalWhenTheSessionFails(t *testing.T) {
	oldDrain := localClientDrainTimeout
	localClientDrainTimeout = 100 * time.Millisecond
	t.Cleanup(func() { localClientDrainTimeout = oldDrain })

	spawn, d := newScriptedDaemon(t)
	attached := make(chan string, 1)
	var clientReturned, clientSawCancel atomic.Bool
	// A client only a cancellation gets back, which is what a terminal
	// holding raw mode with nothing left to read looks like.
	client := func(ctx context.Context, socket string, keys []ssh.PublicKey) (attach.Result, error) {
		attached <- socket
		<-ctx.Done()
		clientSawCancel.Store(ctx.Err() != nil)
		clientReturned.Store(true)
		return attach.Result{Reason: attach.Detached}, nil
	}
	var stdout, stderr bytes.Buffer
	s := newSession(t, spawn, client, &stdout, &stderr)
	d.startup(t, "s")
	go func() {
		<-attached
		d.await().Failed("exec: no such file", false, false)
	}()

	err := s.run(context.Background())
	require.ErrorContains(t, err, "session s could not start: exec: no such file")
	require.True(t, clientReturned.Load(), "run returned while its terminal was still in raw mode")
	require.True(t, clientSawCancel.Load(), "the client was never cancelled, so nothing would have got it back")
}

// A terminal that attached and left before the command started waits for the
// daemon's verdict, bounded, and never guesses.
func TestSpawnedSessionWaitsForTheVerdictAfterAnEarlyDetach(t *testing.T) {
	old := startedWaitTimeout
	startedWaitTimeout = 300 * time.Millisecond
	t.Cleanup(func() { startedWaitTimeout = old })

	t.Run("started arrives", func(t *testing.T) {
		spawn, d := newScriptedDaemon(t)
		attached := make(chan string, 1)
		result := make(chan attach.Result, 1)
		var stdout, stderr bytes.Buffer
		s := newSession(t, spawn, fakeClient(attached, result), &stdout, &stderr)
		d.startup(t, "s")
		go func() {
			<-attached
			result <- attach.Result{Reason: attach.Detached} // gone before started
			time.Sleep(100 * time.Millisecond)
			d.start()
		}()
		require.NoError(t, s.run(context.Background()))
		require.Contains(t, stderr.String(), "the session continues")
		select {
		case <-d.gone:
			t.Fatal("the parent closed its end before the daemon disarmed")
		default:
		}
	})
	t.Run("nothing arrives", func(t *testing.T) {
		spawn, d := newScriptedDaemon(t)
		attached := make(chan string, 1)
		result := make(chan attach.Result, 1)
		var stdout, stderr bytes.Buffer
		s := newSession(t, spawn, fakeClient(attached, result), &stdout, &stderr)
		d.startup(t, "s")
		go func() {
			<-attached
			result <- attach.Result{Reason: attach.Detached}
		}()
		started := time.Now()
		err := s.run(context.Background())
		require.Error(t, err)
		require.ErrorContains(t, err, "did not report")
		require.Less(t, time.Since(started), 2*time.Second)
		require.NotContains(t, stderr.String(), "the session continues", "never claimed on the strength of the client's result")
	})
}
