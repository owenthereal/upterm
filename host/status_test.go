package host

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/stretchr/testify/require"
)

// claimTestDir claims a real session directory in a temp root, released when
// the test ends. The root is short because the directory's sockets are unix
// sockets, whose paths have a length limit that t.TempDir() can exceed.
func claimTestDir(t *testing.T) *sessiondir.Dir {
	t.Helper()

	base := "/tmp"
	if runtime.GOOS == "windows" {
		base = ""
	}
	root, err := os.MkdirTemp(base, "up-status-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	runtimeRoot := filepath.Join(root, "run")
	stateRoot := filepath.Join(root, "state")
	require.NoError(t, os.MkdirAll(runtimeRoot, 0700))
	require.NoError(t, os.MkdirAll(stateRoot, 0700))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dir, err := sessiondir.Claim(ctx, sessiondir.ClaimOptions{
		RuntimeRoot: runtimeRoot,
		StateRoot:   stateRoot,
		Name:        "status",
		Command:     []string{"sh"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = dir.Release(context.Background()) })
	return dir
}

func TestDeriveStatusCoversEveryCombination(t *testing.T) {
	for _, tc := range []struct {
		p    phase
		tun  tunnelState
		want string
	}{
		{phaseStarting, tunnelUp, sessiondir.StatusStarting},
		{phaseStarting, tunnelReconnecting, sessiondir.StatusStarting},
		{phaseStarting, tunnelLost, sessiondir.StatusStarting},
		{phaseRunning, tunnelUp, sessiondir.StatusReady},
		{phaseRunning, tunnelReconnecting, sessiondir.StatusReconnecting},
		{phaseRunning, tunnelLost, sessiondir.StatusDisconnected},
		{phaseEnding, tunnelUp, sessiondir.StatusEnding},
		{phaseEnding, tunnelReconnecting, sessiondir.StatusEnding},
		{phaseEnding, tunnelLost, sessiondir.StatusEnding},
	} {
		require.Equal(t, tc.want, deriveStatus(tc.p, tc.tun))
	}
}

// A tunnel lost during startup and the ready write have no order between
// them, and the record must say reconnecting whichever writes last.
func TestStartupRaceGivesReconnectingInEitherOrder(t *testing.T) {
	for _, tunnelFirst := range []bool{true, false} {
		dir := claimTestDir(t) // a real sessiondir.Dir in a temp root
		var s sessionState
		write := func() { require.NoError(t, dir.Update(s.apply)) }
		lose := func() {
			s.tunnelReconnecting(time.Now(), sessiondir.TunnelReasonNetwork, "EOF", time.Now().Add(time.Second))
			write()
		}
		ready := func() { s.setPhase(phaseRunning); write() }
		if tunnelFirst {
			lose()
			ready()
		} else {
			ready()
			lose()
		}
		require.Equal(t, sessiondir.StatusReconnecting, dir.Record().Status)
	}
}

func TestZeroSessionStateIsStartingWithTheTunnelUp(t *testing.T) {
	var s sessionState
	require.Equal(t, phaseStarting, s.phase)
	require.Equal(t, tunnelUp, s.tunnel)
	require.Equal(t, sessiondir.StatusStarting, s.status())
}

func TestPhaseNeverMovesBackwards(t *testing.T) {
	phases := []phase{phaseStarting, phaseRunning, phaseEnding}
	for _, from := range phases {
		for _, to := range phases {
			var s sessionState
			s.setPhase(from)
			s.setPhase(to)
			want := max(from, to)
			require.Equal(t, want, s.phase, "from %d to %d", from, to)
		}
	}

	// And in the status it gives, which is what a reader sees: a session
	// that has begun ending is not made ready again by a late ready write.
	var s sessionState
	s.setPhase(phaseEnding)
	s.setPhase(phaseRunning)
	require.Equal(t, sessiondir.StatusEnding, s.status())
}

func TestTunnelStateWritesLeaveThePhaseAlone(t *testing.T) {
	var s sessionState
	s.tunnelReconnecting(time.Now(), sessiondir.TunnelReasonNetwork, "EOF", time.Now())
	require.Equal(t, sessiondir.StatusStarting, s.status())
	s.tunnelLost(time.Now(), "EOF")
	require.Equal(t, sessiondir.StatusStarting, s.status())
	s.tunnelUp()
	require.Equal(t, sessiondir.StatusStarting, s.status())
}

func TestStatusFollowsTheTunnelWhileRunning(t *testing.T) {
	var s sessionState
	s.setPhase(phaseRunning)
	require.Equal(t, sessiondir.StatusReady, s.status())

	s.tunnelReconnecting(time.Now(), sessiondir.TunnelReasonNetwork, "EOF", time.Now().Add(time.Second))
	require.Equal(t, sessiondir.StatusReconnecting, s.status())

	// The status is not an order: a tunnel that comes back makes the session
	// ready again, and one that is lost for good makes it disconnected.
	s.tunnelUp()
	require.Equal(t, sessiondir.StatusReady, s.status())
	s.tunnelLost(time.Now(), "EOF")
	require.Equal(t, sessiondir.StatusDisconnected, s.status())
	s.tunnelUp()
	require.Equal(t, sessiondir.StatusReady, s.status())
}

func TestSetReconnect(t *testing.T) {
	var s sessionState
	var r sessiondir.Record

	s.apply(&r)
	require.Empty(t, r.Reconnect, "nothing is known before the first connection")

	s.setReconnect(true)
	s.apply(&r)
	require.Equal(t, sessiondir.ReconnectSupported, r.Reconnect)

	s.setReconnect(false)
	s.apply(&r)
	require.Equal(t, sessiondir.ReconnectUnsupported, r.Reconnect)
}

func TestTunnelReconnectingIsPublishedWithItsOutage(t *testing.T) {
	lostAt := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	nextAt := lostAt.Add(2 * time.Second)

	var s sessionState
	s.setPhase(phaseRunning)
	s.tunnelReconnecting(lostAt, sessiondir.TunnelReasonRelayError, "relay said no", nextAt)

	var r sessiondir.Record
	s.apply(&r)
	require.Equal(t, sessiondir.StatusReconnecting, r.Status)
	require.Equal(t, lostAt, r.TunnelLostAt)
	require.Equal(t, sessiondir.TunnelReasonRelayError, r.TunnelReason)
	require.Equal(t, "relay said no", r.TunnelError)
	require.Equal(t, nextAt, r.NextAttemptAt)
}

func TestTunnelLostSaysWhyThereIsNoNextAttempt(t *testing.T) {
	lostAt := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

	var s sessionState
	s.setPhase(phaseRunning)
	// The schedule of the attempt before it does not outlive it: a tunnel
	// that is lost has no next attempt.
	s.tunnelReconnecting(lostAt, sessiondir.TunnelReasonNetwork, "first", lostAt.Add(time.Second))
	s.tunnelLost(lostAt, "EOF")

	var r sessiondir.Record
	s.apply(&r)
	require.Equal(t, sessiondir.StatusDisconnected, r.Status)
	require.Equal(t, lostAt, r.TunnelLostAt)
	require.Equal(t, sessiondir.TunnelReasonReconnectUnsupported, r.TunnelReason)
	require.Equal(t, "EOF", r.TunnelError)
	require.True(t, r.NextAttemptAt.IsZero())
}

func TestTunnelUpClearsTheOutage(t *testing.T) {
	var s sessionState
	s.setPhase(phaseRunning)
	s.setReconnect(true)
	now := time.Now()
	s.tunnelReconnecting(now, sessiondir.TunnelReasonNetwork, "EOF", now.Add(time.Second))

	var r sessiondir.Record
	s.apply(&r)
	require.False(t, r.TunnelLostAt.IsZero())
	require.NotEmpty(t, r.TunnelReason)
	require.NotEmpty(t, r.TunnelError)
	require.False(t, r.NextAttemptAt.IsZero())

	// Applied onto the same record, so a field left standing would show.
	s.tunnelUp()
	s.apply(&r)
	require.Equal(t, sessiondir.StatusReady, r.Status)
	require.True(t, r.TunnelLostAt.IsZero())
	require.Empty(t, r.TunnelReason)
	require.Empty(t, r.TunnelError)
	require.True(t, r.NextAttemptAt.IsZero())
	require.Equal(t, sessiondir.ReconnectSupported, r.Reconnect,
		"whether the relay derives session IDs is a property of the relay, not of the outage")
}

func TestEndingKeepsTheOutage(t *testing.T) {
	lostAt := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	nextAt := lostAt.Add(time.Second)

	var s sessionState
	s.setPhase(phaseRunning)
	s.setReconnect(true)
	s.tunnelReconnecting(lostAt, sessiondir.TunnelReasonNetwork, "EOF", nextAt)
	s.setPhase(phaseEnding)

	var r sessiondir.Record
	s.apply(&r)
	require.Equal(t, sessiondir.StatusEnding, r.Status)
	require.Equal(t, lostAt, r.TunnelLostAt)
	require.Equal(t, sessiondir.TunnelReasonNetwork, r.TunnelReason)
	require.Equal(t, "EOF", r.TunnelError)
	require.Equal(t, nextAt, r.NextAttemptAt)
	require.Equal(t, sessiondir.ReconnectSupported, r.Reconnect)
}

// The previous status is not an input: a record that says disconnected is
// made ready by a write whose state says the tunnel is up.
func TestApplyIgnoresTheStatusTheRecordHad(t *testing.T) {
	for _, had := range []string{
		"", sessiondir.StatusStarting, sessiondir.StatusReady, sessiondir.StatusReconnecting,
		sessiondir.StatusDisconnected, sessiondir.StatusEnding, "from-a-version-we-do-not-know",
	} {
		var s sessionState
		s.setPhase(phaseRunning)
		r := sessiondir.Record{Status: had}
		s.apply(&r)
		require.Equal(t, sessiondir.StatusReady, r.Status, "record had %q", had)
	}
}

// apply takes one snapshot of every field under the state's lock: a record
// that says reconnecting carries a whole outage, and a ready one carries none,
// however the applies interleave with the supervisor's writes.
func TestApplyTakesOneSnapshotWhileTheTunnelChanges(t *testing.T) {
	var s sessionState
	s.setPhase(phaseRunning)

	const rounds = 20000
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for range rounds {
			now := time.Now()
			s.tunnelReconnecting(now, sessiondir.TunnelReasonNetwork, "EOF", now.Add(time.Second))
			s.tunnelUp()
		}
	}()

	close(start)
	var torn int
	for range rounds {
		var r sessiondir.Record
		s.apply(&r)
		reconnecting := r.Status == sessiondir.StatusReconnecting
		if reconnecting != (r.TunnelReason != "") || reconnecting != !r.TunnelLostAt.IsZero() ||
			reconnecting != (r.TunnelError != "") || reconnecting != !r.NextAttemptAt.IsZero() {
			torn++
		}
	}
	wg.Wait()

	require.Zero(t, torn, "records carried a status and an outage that disagree")
}

// The callback carries what the record says, not what the ready actor asked
// for. A tunnel that is down by the time of the ready write makes the record
// say reconnecting, and a callback that announced ready for it would be the
// disagreement the callback exists to rule out. The tunnel is taken down from
// the barrier that runs just before the write, so the ordering is made rather
// than raced.
func TestReadyCallbackReportsTheDerivedStatus(t *testing.T) {
	f := newJoinTimeoutHost(t)
	lostAt := time.Now().UTC()
	f.h.beforeReadyPublish = func(s *sessionState) {
		s.tunnelReconnecting(lostAt, sessiondir.TunnelReasonNetwork, "EOF", lostAt.Add(time.Minute))
	}
	called := make(chan string, 1)
	f.h.SessionReadyCallback = func(status string) { called <- status }
	f.start(t)

	var status string
	select {
	case status = <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("the readiness callback was not called")
	}

	rec := f.record(t)
	require.Equal(t, sessiondir.StatusReconnecting, status)
	require.Equal(t, sessiondir.StatusReconnecting, rec.Status,
		"the record a reader would consult says what the callback was given")
	require.NotEmpty(t, rec.SessionID, "published by the same write")
	require.Equal(t, sessiondir.TunnelReasonNetwork, rec.TunnelReason)
	require.Equal(t, "EOF", rec.TunnelError)
	require.True(t, rec.TunnelLostAt.Equal(lostAt))
	require.True(t, rec.NextAttemptAt.Equal(lostAt.Add(time.Minute)))
}
