package liveness

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

// The Watch tests run in a synctest bubble, where time is fake: it moves only
// when every goroutine in the bubble is blocked, and a timer fires exactly at
// its deadline. synctest.Wait settles what is due now without moving the
// clock, so each deadline is checked on both sides, a nanosecond before it and
// at it.

// clock is a lastRead a test moves by hand.
type clock struct {
	base time.Time
	last atomic.Int64
}

// newClock makes a clock whose last read is now. Made inside a bubble, now is
// the bubble's time.
func newClock() *clock { return &clock{base: time.Now()} }

func (c *clock) touch()          { c.last.Store(int64(time.Since(c.base))) }
func (c *clock) read() time.Time { return c.base.Add(time.Duration(c.last.Load())) }

// newGate returns a gate and the func that opens it. The gate opens when the
// test ends, too, so that nothing parked on it outlives the test.
func newGate(t *testing.T) (gate <-chan struct{}, open func()) {
	c := make(chan struct{})
	open = sync.OnceFunc(func() { close(c) })
	t.Cleanup(open)
	return c, open
}

// reports records what Watch passes to onDead.
type reports struct {
	mu   sync.Mutex
	errs []error
}

func (r *reports) onDead(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, err)
}

func (r *reports) all() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.errs)
}

// maxPasses bounds how many times one Watch may look at its connection. Each
// pass reads lastRead once, and no test here needs more than a few dozen.
const maxPasses = 100

// startWatch runs Watch on a goroutine of its own, and returns a channel that
// is closed once Watch has returned.
//
// A broken Watch can loop at one fake instant, and fake time doesn't move
// while it does, so the test would hang rather than fail. So past maxPasses
// reads of lastRead, or on a second onDead, startWatch fails the test and
// parks that call until ctx ends. Parked, Watch is durably blocked, so the
// test's own assertions run and report; when ctx ends, Watch can return.
// Once the test's context is done, the test may have completed, and failing
// a completed test panics, so then the call only returns. Every test here
// derives ctx from that context, so ctx is done by then too.
func startWatch(t *testing.T, ctx context.Context, timing Timing, lastRead func() time.Time, probe func() error, onDead func(error)) <-chan struct{} {
	var passes, deaths atomic.Int32
	park := func(format string, args ...any) {
		if t.Context().Err() != nil {
			return
		}
		t.Errorf(format, args...)
		<-ctx.Done()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		Watch(ctx, timing,
			func() time.Time {
				if n := passes.Add(1); n > maxPasses {
					park("Watch read lastRead %d times, more than any test here needs: it is likely looping", n)
				}
				return lastRead()
			},
			probe,
			func(err error) {
				onDead(err)
				if n := deaths.Add(1); n > 1 {
					park("onDead called %d times, the last with: %v", n, err)
				}
			})
	}()
	return done
}

// returned reports whether Watch has returned, without waiting for it.
func returned(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// A reply that sits behind queued output on a slow uplink never arrives in
// time, but the output does: the connection is alive. Bytes arrive every
// 100 ms for 800 ms, and the probe that goes out after Interval stays
// unanswered: what's under test is that the bytes, not its reply, keep the
// connection, until Interval+Bound after the last of them.
//
// Interval (50 ms) < the touch period (100 ms) < Interval+Bound (450 ms) <
// the span (800 ms): the probe goes out inside the span, the bytes come often
// enough to keep a connection judged by them, and one judged by the probe
// would be given up on before they stop.
func TestWatchKeepsAConnectionWhoseBytesArrive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		timing := Timing{Interval: 50 * time.Millisecond, Bound: 400 * time.Millisecond}
		const touchEvery, span = 100 * time.Millisecond, 800 * time.Millisecond
		c := newClock()
		unanswered, _ := newGate(t)
		var probes atomic.Int32
		var dead reports
		done := startWatch(t, t.Context(), timing, c.read,
			func() error { probes.Add(1); <-unanswered; return nil },
			dead.onDead)

		for end := time.Now().Add(span); time.Now().Before(end); time.Sleep(touchEvery) {
			c.touch()
		}
		synctest.Wait() // every wake due in the span has run
		require.Equal(t, int32(1), probes.Load(), "one probe, unanswered, the whole time")
		require.Empty(t, dead.all(), "closed while bytes were arriving")

		deadline := c.read().Add(timing.Interval + timing.Bound)
		time.Sleep(time.Until(deadline) - time.Nanosecond)
		synctest.Wait() // every wake due before Interval+Bound of silence has run
		require.Empty(t, dead.all(), "closed before Interval+Bound of silence")
		time.Sleep(time.Nanosecond)
		synctest.Wait() // the wake at Interval+Bound of silence has run
		errs := dead.all()
		require.NotEmpty(t, errs, "a silent connection wasn't given up on at Interval+Bound of silence")
		require.ErrorIs(t, errs[0], ErrSilent)
		// Watch returns right after onDead, so once it has, nothing is left
		// that could report a second time.
		require.True(t, returned(done), "Watch didn't return after giving up")
		require.Len(t, errs, 1, "reported twice")
	})
}

// The deadline is when Interval+Bound of silence is up, not the first wake
// after it. Interval+Bound (400 ms) < 2*Interval (600 ms), the next wake for a
// Watch that slept a whole Interval between looks: it would probe on time and
// give up 200 ms late.
func TestWatchGivesUpAtTheDeadlineNotTheNextWake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		timing := Timing{Interval: 300 * time.Millisecond, Bound: 100 * time.Millisecond}
		c := newClock()
		unanswered, _ := newGate(t)
		var probes atomic.Int32
		var dead reports
		startWatch(t, t.Context(), timing, c.read,
			func() error { probes.Add(1); <-unanswered; return nil },
			dead.onDead)

		time.Sleep(timing.Interval - time.Nanosecond)
		synctest.Wait() // every wake due before Interval of silence has run
		require.Zero(t, probes.Load(), "probed before Interval of silence")
		time.Sleep(time.Nanosecond)
		synctest.Wait() // the wake at Interval of silence has run
		require.Equal(t, int32(1), probes.Load(), "didn't probe at Interval of silence")

		time.Sleep(timing.Bound - time.Nanosecond)
		synctest.Wait() // every wake due before Interval+Bound of silence has run
		require.Empty(t, dead.all(), "closed before Interval+Bound of silence")
		time.Sleep(time.Nanosecond)
		synctest.Wait() // the wake at Interval+Bound of silence has run
		errs := dead.all()
		require.NotEmpty(t, errs, "a silent connection wasn't given up on at Interval+Bound of silence")
		require.ErrorIs(t, errs[0], ErrSilent)
		require.Len(t, errs, 1, "reported twice")
	})
}

// A watcher that starts late has not been neglecting anything. On the relay a
// connection's lastRead is set at accept, but the first probe waits behind a
// registration that can take longer than Interval+Bound; the peer has been
// waiting for its reply the whole time, so it must still get the probe it was
// promised, and the full Bound to answer it, from when Watch starts. The
// probe never gets an answer.
//
// Interval+Bound (300 ms) < lastRead's age (an hour), by far: a Watch that
// measured the silence from lastRead alone would give up the moment it
// started.
func TestWatchGivesANewWatcherItsFullBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		timing := Timing{Interval: 100 * time.Millisecond, Bound: 200 * time.Millisecond}
		hourAgo := time.Now().Add(-time.Hour)
		unanswered, _ := newGate(t)
		var probes atomic.Int32
		var dead reports
		startWatch(t, t.Context(), timing, func() time.Time { return hourAgo },
			func() error { probes.Add(1); <-unanswered; return nil },
			dead.onDead)

		time.Sleep(timing.Interval - time.Nanosecond)
		synctest.Wait() // every wake due before Interval since Watch started has run
		require.Empty(t, dead.all(), "gave up on a new watcher without the probe it was due")
		require.Zero(t, probes.Load(), "probed before Interval had passed since Watch started")
		time.Sleep(time.Nanosecond)
		synctest.Wait() // the wake at Interval since Watch started has run
		require.Equal(t, int32(1), probes.Load(), "didn't probe at Interval since Watch started")

		time.Sleep(timing.Bound - time.Nanosecond)
		synctest.Wait() // every wake due before Interval+Bound since Watch started has run
		require.Empty(t, dead.all(), "closed before Interval+Bound had passed since Watch started")
		time.Sleep(time.Nanosecond)
		synctest.Wait() // the wake at Interval+Bound since Watch started has run
		errs := dead.all()
		require.NotEmpty(t, errs, "a silent connection wasn't given up on at Interval+Bound since Watch started")
		require.ErrorIs(t, errs[0], ErrSilent)
		require.Len(t, errs, 1, "reported twice")
	})
}

// The port of Test_KeepAlive_DoesNotReportADeadRelayWhenStopped. A ctx that
// ends is the caller's own teardown, so a probe that fails after it is no
// dead peer. The whole test (65 Intervals of fake time) < Bound (an hour), by
// far: silence can't end this watch.
func TestWatchReportsNothingWhenStopped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		timing := Timing{Interval: 20 * time.Millisecond, Bound: time.Hour}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		started := make(chan struct{}, 1)
		release, open := newGate(t)
		var dead reports
		done := startWatch(t, ctx, timing, newClock().read,
			func() error { started <- struct{}{}; <-release; return errors.New("ssh: EOF") },
			dead.onDead)

		time.Sleep(timing.Interval)
		synctest.Wait() // the probe due at Interval has started, and is blocked
		select {
		case <-started:
		default:
			t.Fatal("the probe never started")
		}

		cancel()
		synctest.Wait() // Watch has seen its context end
		require.True(t, returned(done), "Watch didn't return once its context ended")
		require.Empty(t, dead.all(), "reported a dead connection when its context ended")

		open()
		synctest.Wait() // the probe has failed, with no Watch left to hear it
		require.Empty(t, dead.all(), "reported a probe that failed after its context ended")

		// What follows is stress, not a deterministic check. The probe fails
		// as the context ends, while Watch may still be on its way to its
		// select. If both cases are ready by then and it picks the probe's
		// result, only its second look at ctx keeps the failure from being
		// reported. Nothing here controls when Watch selects, or which case it
		// picks, so the loop only runs whatever schedules it gets.
		for range 64 {
			ctx, cancel := context.WithCancel(t.Context())
			started := make(chan struct{}, 1)
			release, open := newGate(t)
			var dead reports
			done := startWatch(t, ctx, timing, newClock().read,
				func() error { started <- struct{}{}; <-release; return errors.New("ssh: EOF") },
				dead.onDead)
			select {
			case <-started:
			case <-time.After(10 * timing.Interval): // the probe is due an Interval after Watch starts
				t.Fatal("the probe never started")
			}
			cancel()
			open()
			synctest.Wait() // Watch has returned, by whichever case it took
			require.True(t, returned(done), "Watch didn't return once its context ended")
			require.Empty(t, dead.all(), "reported a probe that failed as its context ended")
		}
	})
}

// x/crypto serialises want-reply requests, so a second probe behind an
// unanswered one would only queue. The first probe goes out at Interval and
// stays blocked. Bytes then arrive, so the wake at the first deadline,
// Interval+Bound from the start, finds the connection silent for Bound, and
// Interval (20 ms) < Bound (an hour) < Interval+Bound: that wake is due a
// probe and not a death, and only the probe in flight keeps it from starting
// a second.
//
// The first probe is also the one that must not go out early: a connection
// that has been quiet for less than Interval has not earned a probe.
func TestWatchSendsOneProbeAtATime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		timing := Timing{Interval: 20 * time.Millisecond, Bound: time.Hour}
		c := newClock()
		firstDeadline := c.read().Add(timing.Interval + timing.Bound)
		unanswered, _ := newGate(t)
		var probes atomic.Int32
		var dead reports
		startWatch(t, t.Context(), timing, c.read,
			func() error { probes.Add(1); <-unanswered; return nil },
			dead.onDead)

		time.Sleep(timing.Interval - time.Nanosecond)
		synctest.Wait() // every wake due before Interval of silence has run
		require.Zero(t, probes.Load(), "probed a connection that had not been silent for Interval")
		time.Sleep(time.Nanosecond)
		synctest.Wait() // the probe due at Interval has started, and is blocked
		require.Equal(t, int32(1), probes.Load(), "didn't probe at Interval of silence")

		c.touch()
		time.Sleep(time.Until(firstDeadline) + time.Nanosecond)
		synctest.Wait() // the wake at the first deadline has run
		require.Empty(t, dead.all(), "gave up on a connection that was silent for less than Interval+Bound")
		require.Equal(t, int32(1), probes.Load(), "an unanswered probe must not be piled on by the next wake")
	})
}

// A reply moves lastRead, so a probe that returns nil leaves the next one an
// Interval away. One that returns nil with no bytes having arrived is a caller
// whose lastRead is not fed by the connection the probe goes over, and must
// cost one probe an Interval, not a probe per pass.
//
// The run (425 ms) < Interval+Bound (1050 ms): nothing ends the watch early,
// so only the pacing spaces the probes, eight of them, one each Interval. The
// run ends off the Interval grid so that its end doesn't tie with a probe. A
// probe per pass would spin at one instant, and fake time never moves while
// it does, so the fake probe makes Watch give up past maxProbes rather than
// leave the test hanging.
func TestWatchPacesProbesThatMoveNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		timing := Timing{Interval: 50 * time.Millisecond, Bound: time.Second}
		const run, maxProbes = 425 * time.Millisecond, 20
		start := time.Now()
		ctx, cancel := context.WithTimeout(t.Context(), run)
		defer cancel()
		var mu sync.Mutex
		var starts []time.Duration
		var dead reports
		done := startWatch(t, ctx, timing, newClock().read, func() error {
			mu.Lock()
			defer mu.Unlock()
			starts = append(starts, time.Since(start))
			if len(starts) > maxProbes {
				// A probe still running when Watch returns is abandoned, and
				// can outlive the test; failing a completed test panics.
				if t.Context().Err() == nil {
					t.Errorf("probe %d at %s: probed once a pass, not once an Interval", len(starts), time.Since(start))
				}
				return errors.New("probed too often to go on")
			}
			return nil
		}, dead.onDead)
		// Fake time stops once the test's cleanups have run, so a Watch that
		// returns only some time after its context ends is waited for here,
		// while time still moves.
		t.Cleanup(func() { <-done })
		select {
		case <-done:
		case <-time.After(2 * run): // Watch's context ends at run
			t.Fatal("Watch didn't return once its context ended")
		}

		var want []time.Duration
		for at := timing.Interval; at < run; at += timing.Interval {
			want = append(want, at)
		}
		mu.Lock()
		defer mu.Unlock()
		require.Equal(t, want, starts, "a probe that moves nothing must cost one probe an Interval")
		require.Empty(t, dead.all(), "gave up on a connection that was silent for less than Interval+Bound")
	})
}

// The port of Test_KeepAlive_StopsAfterAFailedPing. Interval (20 ms) < Bound
// (an hour): the probe's failure, not silence, ends this watch, and once it
// has, Watch stops rather than probe again.
func TestWatchReportsAFailedProbeOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		timing := Timing{Interval: 20 * time.Millisecond, Bound: time.Hour}
		wantErr := errors.New("ssh: write: broken pipe")
		var probes atomic.Int32
		var dead reports
		done := startWatch(t, t.Context(), timing, newClock().read,
			func() error { probes.Add(1); return wantErr },
			dead.onDead)

		time.Sleep(timing.Interval - time.Nanosecond)
		synctest.Wait() // every wake due before Interval of silence has run
		require.Zero(t, probes.Load(), "probed before Interval of silence")
		require.Empty(t, dead.all(), "gave up before the probe")
		time.Sleep(time.Nanosecond)
		synctest.Wait() // the probe due at Interval has failed, and Watch has heard it
		require.True(t, returned(done), "Watch went on watching a connection that had already failed")
		require.Equal(t, int32(1), probes.Load(), "a connection that failed a probe will fail the next one too")
		errs := dead.all()
		require.NotEmpty(t, errs, "Watch gave up without saying so")
		require.ErrorIs(t, errs[0], wantErr, "onDead gets the error that killed the connection")
		require.Len(t, errs, 1, "a connection dies once")
	})
}

// Only bytes count: a read that fails with none is a connection going quiet,
// not one that is alive.
//
// This stays on the real clock: it checks that LastRead keeps a monotonic
// reading, and inside a synctest bubble time.Now carries none.
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
