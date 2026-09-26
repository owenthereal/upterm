package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
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
	d.startWith(sessiondir.StatusReady)
}

// startWith is start for a case about the status the daemon publishes: the
// record's status travels in Started and the parent prints what it is given.
// The join state is a real daemon's with no timeout set.
func (d *scriptedDaemon) startWith(status string) {
	d.startWithJoinState(status, &api.JoinState{})
}

// startWithJoinState is start for a case about the join state the daemon
// holds as it reports readiness.
func (d *scriptedDaemon) startWithJoinState(status string, js *api.JoinState) {
	child := d.await()
	child.Disarm()
	_ = child.Started("sid-1", status, js)
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

// TestSpawnedSessionNamesTheLogWhenTheSpawnFails pins that a failure to spawn
// the daemon names the log only when the spawn got far enough to have opened
// one. spawn_unix.go and spawn_windows.go each os.OpenFile the log
// themselves, so a failure before that point (nonce, bootstrap directory,
// listener) has no log to point at, and naming one that is not there would
// mislead.
func TestSpawnedSessionNamesTheLogWhenTheSpawnFails(t *testing.T) {
	t.Run("log exists", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "upterm.log")
		require.NoError(t, os.WriteFile(logPath, nil, 0o600))
		spawn := func(spawnOptions) (net.Conn, *os.Process, error) {
			return nil, nil, errors.New("boom")
		}
		var stdout, stderr bytes.Buffer
		s := newSession(t, spawn, nil, &stdout, &stderr)
		s.logPath = logPath

		err := s.run(context.Background())
		require.ErrorContains(t, err, "boom")
		require.ErrorContains(t, err, "(see "+logPath+")")
	})
	t.Run("no log yet", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "upterm.log") // never created
		spawn := func(spawnOptions) (net.Conn, *os.Process, error) {
			return nil, nil, errors.New("boom")
		}
		var stdout, stderr bytes.Buffer
		s := newSession(t, spawn, nil, &stdout, &stderr)
		s.logPath = logPath

		err := s.run(context.Background())
		require.ErrorContains(t, err, "boom")
		require.NotContains(t, err.Error(), "(see")
	})
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
	require.Equal(t, sessiondir.StatusReady, info.Status,
		"the status the daemon published, which for a healthy session is ready")
	require.Equal(t, "sid-1", info.SessionID)
	require.Equal(t, "/run/a.sock", info.AdminSocket)
	require.Equal(t, "/run/t.sock", info.AttachSocket)
	require.Equal(t, "/var/log/upterm.log", info.LogPath)
	require.Equal(t, 4242, info.Pid)
	require.Equal(t, "ssh u@127.0.0.1 -p 2222", info.SSHCommand)
	require.Equal(t, sessiondir.ReasonUnknown, info.Reason,
		"reason is a key `session info -o json` always publishes; this shape has to match it")
	require.Equal(t, joinStateFromDaemon, info.JoinStateSource,
		"joinStateSource is a key `session info -o json` always publishes; this shape has to match it too, "+
			"and a daemon that reported its join state is the source even when there is no timeout")
	require.Empty(t, stderr.String())

	// The parent left after started; the daemon's watcher stays quiet.
	select {
	case <-d.gone:
		t.Fatal("a parent that exits after started must not be read as abandonment")
	case <-time.After(100 * time.Millisecond):
	}
}

// TestSpawnedSessionDetachPrintsJoinTimeout pins that a session started with
// --join-timeout reports it as the daemon holds it: Started carries the
// daemon's snapshot, taken once the timeout is counting, so the JSON has the
// deadline a `session info` run a moment later would show, not an inference
// from the flag.
func TestSpawnedSessionDetachPrintsJoinTimeout(t *testing.T) {
	spawn, d := newScriptedDaemon(t)
	var stdout, stderr bytes.Buffer
	s := newSession(t, spawn, nil, &stdout, &stderr)
	s.detach, s.jsonOut = true, true
	deadline := time.Date(2026, 9, 25, 12, 10, 0, 0, time.UTC)
	dec := d.startup(t, "s")
	go func() {
		<-dec
		d.startWithJoinState(sessiondir.StatusReady,
			&api.JoinState{TimeoutNanos: int64(10 * time.Minute), DeadlineUnixNano: deadline.UnixNano()})
	}()

	require.NoError(t, s.run(context.Background()))

	require.Contains(t, stdout.String(), `"joinTimeout": "10m"`)
	require.Contains(t, stdout.String(), `"joinDeadline": "2026-09-25T12:10:00Z"`)
	require.Contains(t, stdout.String(), `"joinStateSource": "daemon"`)
	require.Empty(t, stderr.String())
}

// TestSpawnedSessionDetachPrintsTheStatusItWasGiven: the JSON's status is the
// daemon's report, not this process's assumption. The record is written by the
// daemon and can say something other than ready by the time readiness is
// published -- a tunnel lost in that moment leaves "disconnected" standing,
// since a status never moves backwards -- and `upterm session info` would then
// answer disconnected for the launch this JSON describes.
func TestSpawnedSessionDetachPrintsTheStatusItWasGiven(t *testing.T) {
	spawn, d := newScriptedDaemon(t)
	var stdout, stderr bytes.Buffer
	s := newSession(t, spawn, nil, &stdout, &stderr)
	s.detach, s.jsonOut = true, true
	dec := d.startup(t, "s")
	go func() { <-dec; d.startWith(sessiondir.StatusDisconnected) }()

	require.NoError(t, s.run(context.Background()))

	var info sessionInfo
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &info))
	require.Equal(t, sessiondir.StatusDisconnected, info.Status,
		"the parent prints the status the record carried, not ready by assumption")
	require.Equal(t, "sid-1", info.SessionID, "the session is up; only its tunnel is not")
}

// TestSpawnedSessionDetachRefusesAStatuslessReport: no daemon that speaks this
// exchange sends an empty status, and the exchange is unreleased, so one is a
// bug in this binary rather than an older daemon to accommodate. Refused
// rather than printed, because `"status": ""` is a value no script can branch
// on -- the same hole as printing a status nobody vouched for.
func TestSpawnedSessionDetachRefusesAStatuslessReport(t *testing.T) {
	spawn, d := newScriptedDaemon(t)
	var stdout, stderr bytes.Buffer
	s := newSession(t, spawn, nil, &stdout, &stderr)
	s.detach, s.jsonOut = true, true
	dec := d.startup(t, "s")
	go func() { <-dec; d.startWith("") }()

	err := s.run(context.Background())
	require.ErrorContains(t, err, "reported no status")
	require.ErrorContains(t, err, "/var/log/upterm.log", "the log is where the reason will be")
	require.Empty(t, stdout.String(), "nothing may be printed for a report that cannot be trusted")
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
			// Foreground host preserves its command-exit sentence; attach
			// uses a generic session status. The nil Err makes host.go
			// silence cobra so nothing else is printed after it.
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
	require.ErrorAs(t, err, &discarded, "shareRunE maps this to exit 0")
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

// TestSpawnedSessionRefusesAnUnreadableHostKey pins that the parent refuses a
// host key it cannot parse, without ever starting the attach client on it,
// and tells the daemon at once rather than leaving it to its own timeout.
//
// run is driven from a goroutine with its own bounded wait, rather than
// called inline: the path this pins is what closes the parent's end of the
// connection at all, so a regression that drops that close leaves nothing to
// unblock parent.Run's Recv, and the test must fail on its own timeout
// instead of hanging until the package's.
func TestSpawnedSessionRefusesAnUnreadableHostKey(t *testing.T) {
	spawn, d := newScriptedDaemon(t)
	var stdout, stderr bytes.Buffer
	client := func(context.Context, string, []ssh.PublicKey) (attach.Result, error) {
		t.Error("the client must not be started with keys that did not parse")
		return attach.Result{}, nil
	}
	s := newSession(t, spawn, client, &stdout, &stderr)
	go func() {
		child := d.await()
		_ = child.Claimed(&api.Claimed{Name: "s", LaunchId: "l", AttachSocket: "/run/t.sock"})
		if dec, err := child.SessionCreated(&api.GetSessionResponse{SessionId: "sid", Host: "ssh://127.0.0.1:2222", NodeAddr: "127.0.0.1:2222", SshUser: "u"}); err != nil || dec != api.Accept_ACCEPTED {
			return
		}
		_ = child.Listening("/run/t.sock", []string{"not a key"})
	}()
	runDone := make(chan error, 1)
	go func() { runDone <- s.run(context.Background()) }()
	select {
	case err := <-runDone:
		require.ErrorContains(t, err, "cannot be read")
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return for an unreadable host key; the parent must close its end rather than wait")
	}
	select {
	case <-d.gone:
	case <-time.After(2 * time.Second):
		t.Fatal("the daemon was not told")
	}
}

// TestSpawnedSessionReportsAnAbandonmentItDidNotCause pins that an
// abandonment the operator did not cause -- the daemon reporting no initial
// client rather than this process's own decline or interrupt -- is reported
// as the session never having started, not folded into the generic
// could-not-start case.
func TestSpawnedSessionReportsAnAbandonmentItDidNotCause(t *testing.T) {
	spawn, d := newScriptedDaemon(t)
	var stdout, stderr bytes.Buffer
	s := newSession(t, spawn, nil, &stdout, &stderr)
	s.detach = true
	go func() { d.await().Failed("no initial client", false, true) }()
	err := s.run(context.Background())
	require.EqualError(t, err, "session s was not started: no initial client")
}

// TestSpawnedSessionSendsInterruptedForADisplayFailure pins that a display
// error which is not a decline (UserDiscardedError) is answered as
// INTERRUPTED, not DECLINED -- the two put the daemon through different
// abandonment paths, and only DECLINED is the operator saying no.
func TestSpawnedSessionSendsInterruptedForADisplayFailure(t *testing.T) {
	spawn, d := newScriptedDaemon(t)
	var stdout, stderr bytes.Buffer
	s := newSession(t, spawn, nil, &stdout, &stderr)
	s.detach = true
	s.display = func(context.Context, *api.GetSessionResponse, string) error { return errors.New("terminal went away") }
	dec := d.startup(t, "s")
	_ = s.run(context.Background())
	require.Equal(t, api.Accept_INTERRUPTED, <-dec)
}

// TestSpawnedSessionDetachRefusesAMissingClaim pins that --detach refuses to
// print a session whose claim never arrived, rather than printing a report
// built on a nil Claimed.
func TestSpawnedSessionDetachRefusesAMissingClaim(t *testing.T) {
	spawn, d := newScriptedDaemon(t)
	var stdout, stderr bytes.Buffer
	s := newSession(t, spawn, nil, &stdout, &stderr)
	s.detach = true
	s.jsonOut = true
	go func() {
		child := d.await()
		// No Claimed.
		if dec, err := child.SessionCreated(&api.GetSessionResponse{SessionId: "sid", Host: "ssh://127.0.0.1:2222", NodeAddr: "127.0.0.1:2222", SshUser: "u"}); err != nil || dec != api.Accept_ACCEPTED {
			return
		}
		child.Disarm()
		_ = child.Started("sid", sessiondir.StatusReady, &api.JoinState{})
	}()
	err := s.run(context.Background())
	require.ErrorContains(t, err, "never reported its claim")
	require.Empty(t, stdout.String(), "nothing a script would parse is printed")
}
