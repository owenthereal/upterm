package liveness

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// lateWake is how late a woken goroutine may run on a loaded CI runner under
// -race. It is the tolerance server/lease_test.go uses for the same question.
const lateWake = 150 * time.Millisecond

// clock is a lastRead a test moves by hand.
type clock struct{ last atomic.Int64 }

var testBase = time.Now()

func (c *clock) touch()          { c.last.Store(int64(time.Since(testBase))) }
func (c *clock) read() time.Time { return testBase.Add(time.Duration(c.last.Load())) }

// A reply that sits behind queued output on a slow uplink never arrives in
// time, but the output does: the connection is alive. Bytes arrive every
// 100 ms, past Interval, so a probe goes out and stays unanswered while
// they keep coming: what's under test is that they, not its reply, keep the
// connection.
func TestWatchKeepsAConnectionWhoseBytesArrive(t *testing.T) {
	timing := Timing{Interval: 50 * time.Millisecond, Bound: 400 * time.Millisecond}
	var c clock
	c.touch()
	never := make(chan struct{})
	t.Cleanup(func() { close(never) })
	var probes atomic.Int32
	dead := make(chan error, 2)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		defer close(done)
		Watch(ctx, timing, c.read, func() error { probes.Add(1); <-never; return nil }, func(err error) { dead <- err })
	}()

	for end := time.Now().Add(800 * time.Millisecond); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		c.touch()
	}
	require.Equal(t, int32(1), probes.Load(), "one probe, unanswered, the whole time")
	require.Empty(t, dead, "closed while bytes were arriving")

	lastByte := c.read()
	deadline := lastByte.Add(timing.Interval + timing.Bound)
	select {
	case err := <-dead:
		late := time.Since(deadline)
		require.ErrorIs(t, err, ErrSilent)
		require.GreaterOrEqual(t, late, time.Duration(0), "closed before Interval+Bound of silence")
		require.LessOrEqual(t, late, lateWake, "closed long after Interval+Bound of silence")
	case <-time.After(2 * time.Second):
		t.Fatal("a silent connection was never given up on")
	}

	// Watch returns right after onDead, so once it has, nothing is left that
	// could report a second time.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Watch didn't return after giving up")
	}
	require.Empty(t, dead, "reported twice")
}

// The deadline is when Interval+Bound of silence is up, not the first wake
// after it. A Watch that slept a whole Interval between looks is never more
// than an Interval late, so only an Interval wider than lateWake can tell: here
// the next wake after the probe would be 300 ms on, 200 ms past the deadline.
func TestWatchGivesUpAtTheDeadlineNotTheNextWake(t *testing.T) {
	timing := Timing{Interval: 300 * time.Millisecond, Bound: 100 * time.Millisecond}
	var c clock
	c.touch()
	deadline := c.read().Add(timing.Interval + timing.Bound)
	never := make(chan struct{})
	t.Cleanup(func() { close(never) })
	dead := make(chan error, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Watch(ctx, timing, c.read, func() error { <-never; return nil }, func(err error) { dead <- err })

	select {
	case err := <-dead:
		late := time.Since(deadline)
		require.ErrorIs(t, err, ErrSilent)
		require.GreaterOrEqual(t, late, time.Duration(0), "closed before Interval+Bound of silence")
		require.LessOrEqual(t, late, lateWake, "closed long after Interval+Bound of silence")
	case <-time.After(5 * time.Second):
		t.Fatal("a silent connection was never given up on")
	}
}

// The port of Test_KeepAlive_DoesNotReportADeadRelayWhenStopped.
func TestWatchReportsNothingWhenStopped(t *testing.T) {
	var c clock
	c.touch()
	ctx, cancel := context.WithCancel(context.Background())
	started, release := make(chan struct{}, 1), make(chan struct{})
	dead := make(chan error, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// A long Bound: only the probe can end this watch.
		Watch(ctx, Timing{Interval: 20 * time.Millisecond, Bound: time.Hour}, c.read,
			func() error { started <- struct{}{}; <-release; return errors.New("ssh: EOF") },
			func(err error) { dead <- err })
	}()
	<-started
	cancel()
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Watch didn't return once its context ended")
	}
	require.Empty(t, dead)
}

// x/crypto serialises want-reply requests, so a second probe behind an
// unanswered one would only queue. Nothing here moves the clock and Bound is
// far off, so the one probe stays the only one however many wakes pass.
//
// The first probe is also the one that must not go out early: a connection
// that has been quiet for less than Interval has not earned a probe.
func TestWatchSendsOneProbeAtATime(t *testing.T) {
	timing := Timing{Interval: 20 * time.Millisecond, Bound: time.Hour}
	var c clock
	c.touch()
	touched := c.read()
	started, release := make(chan time.Time, 2), make(chan struct{})
	t.Cleanup(func() { close(release) })
	var probes atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Watch(ctx, timing, c.read,
		func() error { probes.Add(1); started <- time.Now(); <-release; return nil },
		func(error) { t.Error("gave up on a connection that was silent for less than Bound") })

	select {
	case at := <-started:
		silence := at.Sub(touched)
		require.GreaterOrEqual(t, silence, timing.Interval, "probed a connection that had not been silent for Interval")
		require.LessOrEqual(t, silence, timing.Interval+lateWake, "probed long after Interval of silence")
	case <-time.After(5 * time.Second):
		t.Fatal("the probe never started")
	}
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, int32(1), probes.Load(), "an unanswered probe must not be piled on by the next wake")
}

// A reply moves lastRead, so a probe that returns nil leaves the next one an
// Interval away. One that returns nil with no bytes having arrived is a caller
// whose lastRead is not fed by the connection the probe goes over, and must
// cost one probe an Interval, not a probe per pass.
func TestWatchPacesProbesThatMoveNothing(t *testing.T) {
	timing := Timing{Interval: 50 * time.Millisecond, Bound: time.Second}
	var c clock
	c.touch()
	var mu sync.Mutex
	var starts []time.Time
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Watch(ctx, timing, c.read,
			func() error { mu.Lock(); starts = append(starts, time.Now()); mu.Unlock(); return nil },
			func(error) { t.Error("gave up on a connection that was silent for less than Bound") })
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Watch didn't return once its context ended")
	}

	mu.Lock()
	defer mu.Unlock()
	// One an Interval from the start, then one an Interval after each: eight
	// in 400 ms, give or take the one that lands on the deadline.
	require.GreaterOrEqual(t, len(starts), 2, "stopped probing")
	require.LessOrEqual(t, len(starts), 9, "probed a connection more than once an Interval")
	for i := 1; i < len(starts); i++ {
		// Each start is stamped by its own goroutine, a little after Watch
		// decided on it, so two can land a little closer than Interval. A
		// probe-per-pass loop lands them microseconds apart, nowhere near half.
		gap := starts[i].Sub(starts[i-1])
		require.GreaterOrEqual(t, gap, timing.Interval/2, "probes %d and %d were %s apart", i-1, i, gap)
	}
}

// The port of Test_KeepAlive_StopsAfterAFailedPing.
func TestWatchReportsAFailedProbeOnce(t *testing.T) {
	var c clock
	c.touch()
	wantErr := errors.New("ssh: write: broken pipe")
	var probes atomic.Int32
	dead := make(chan error, 2)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		defer close(done)
		Watch(ctx, Timing{Interval: 20 * time.Millisecond, Bound: time.Hour}, c.read,
			func() error { probes.Add(1); return wantErr },
			func(err error) { dead <- err })
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Watch went on probing a connection that had already failed")
	}

	require.Equal(t, int32(1), probes.Load(), "a connection that failed a probe will fail the next one too")
	select {
	case err := <-dead:
		require.ErrorIs(t, err, wantErr, "onDead gets the error that killed the connection")
	default:
		t.Fatal("Watch gave up without saying so")
	}
	require.Empty(t, dead, "a connection dies once")
}

// Only bytes count: a read that fails with none is a connection going quiet,
// not one that is alive.
func TestConnRecordsOnlyRealReads(t *testing.T) {
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	c := NewConn(local)
	t.Cleanup(func() { _ = c.Close() })

	created := c.LastRead()
	require.Contains(t, created.String(), "m=", "a wall-clock step must not change a silence, so LastRead keeps its monotonic reading")

	// An error with no bytes: a read that times out.
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, c.SetReadDeadline(time.Now().Add(-time.Second)))
	n, err := c.Read(make([]byte, 8))
	require.Zero(t, n)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Equal(t, created, c.LastRead(), "a read that returned no bytes moved LastRead")
	require.NoError(t, c.SetReadDeadline(time.Time{}))

	// Bytes.
	go func() { _, _ = peer.Write([]byte("hi")) }()
	n, err = c.Read(make([]byte, 8))
	require.NoError(t, err)
	require.Equal(t, 2, n)
	read := c.LastRead()
	require.True(t, read.After(created), "a read that returned bytes did not move LastRead")
	require.False(t, read.After(time.Now()))

	// An error with no bytes: the peer is gone.
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, peer.Close())
	n, err = c.Read(make([]byte, 8))
	require.Zero(t, n)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, read, c.LastRead(), "a read that returned no bytes moved LastRead")
}
