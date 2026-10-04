package host

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// atMost is a jitter that waits the whole bound, so a test sees the schedule's
// upper edge exactly.
func atMost(d time.Duration) time.Duration { return d }

func TestReconnectTimingOrDefault(t *testing.T) {
	want := ReconnectTiming{
		PingInterval:    15 * time.Second,
		PingBound:       15 * time.Second,
		AttemptDeadline: 30 * time.Second,
		FastBase:        time.Second,
		FastCap:         30 * time.Second,
		SlowWait:        5 * time.Minute,
		SlowJitter:      30 * time.Second,
		ResetAfter:      60 * time.Second,
	}
	require.Equal(t, want, ReconnectTiming{}.orDefault())

	negative := ReconnectTiming{
		PingInterval:    -1,
		PingBound:       -time.Second,
		AttemptDeadline: -time.Hour,
		FastBase:        -1,
		FastCap:         -1,
		SlowWait:        -1,
		SlowJitter:      -1,
		ResetAfter:      -1,
	}
	require.Equal(t, want, negative.orDefault(), "a negative field is as unset as a zero one")

	set := ReconnectTiming{FastBase: time.Millisecond, FastCap: 4 * time.Millisecond, ResetAfter: time.Second}
	got := set.orDefault()
	require.Equal(t, set.FastBase, got.FastBase)
	require.Equal(t, set.FastCap, got.FastCap)
	require.Equal(t, set.ResetAfter, got.ResetAfter)
	require.Equal(t, want.SlowWait, got.SlowWait, "a field left unset inherits while another is overridden")
}

func TestScheduleFastBounds(t *testing.T) {
	s := newSchedule(ReconnectTiming{}.orDefault(), atMost)
	for _, want := range []time.Duration{1, 2, 4, 8, 16, 30, 30} {
		require.Equal(t, want*time.Second, s.next(transient))
	}
}

func TestScheduleFastDoesNotOverflow(t *testing.T) {
	timing := ReconnectTiming{}.orDefault()
	s := newSchedule(timing, atMost)
	var last time.Duration
	for i := range 100 {
		last = s.next(transient)
		require.GreaterOrEqual(t, last, time.Duration(0), "wait %d", i)
		require.LessOrEqual(t, last, timing.FastCap, "wait %d", i)
	}
	require.Equal(t, timing.FastCap, last)
}

func TestScheduleFastDoesNotOverflowWithHugeBounds(t *testing.T) {
	huge := ReconnectTiming{FastBase: 1 << 61, FastCap: 1<<63 - 1}.orDefault()
	s := newSchedule(huge, atMost)
	require.Equal(t, huge.FastBase, s.next(transient))
	for i := range 10 {
		w := s.next(transient)
		require.Greater(t, w, time.Duration(0), "wait %d", i)
		require.LessOrEqual(t, w, huge.FastCap, "wait %d", i)
	}

	inverted := newSchedule(ReconnectTiming{FastBase: time.Minute, FastCap: time.Second}.orDefault(), atMost)
	require.Equal(t, time.Second, inverted.next(transient), "a cap below the base is the cap")
}

func TestScheduleFastJitterGetsTheBound(t *testing.T) {
	var got []time.Duration
	s := newSchedule(ReconnectTiming{}.orDefault(), func(max time.Duration) time.Duration {
		got = append(got, max)
		return 0
	})
	for range 3 {
		require.Equal(t, time.Duration(0), s.next(transient))
	}
	require.Equal(t, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}, got)
}

func TestScheduleBlockedThenTransient(t *testing.T) {
	timing := ReconnectTiming{}.orDefault()
	s := newSchedule(timing, atMost)
	require.Equal(t, time.Second, s.next(blocked), "the first blocked error is retried once on the fast schedule")
	for range 3 {
		w := s.next(blocked)
		require.GreaterOrEqual(t, w, 5*time.Minute)
		require.LessOrEqual(t, w, 5*time.Minute+30*time.Second)
	}
	require.LessOrEqual(t, s.next(transient), timing.FastCap, "a transient error returns to the fast schedule")
	low := newSchedule(timing, func(time.Duration) time.Duration { return 0 })
	low.next(blocked)
	require.Equal(t, 5*time.Minute, low.next(blocked), "never less than SlowWait")
}

func TestScheduleSlowJitterGetsSlowJitter(t *testing.T) {
	var got []time.Duration
	s := newSchedule(ReconnectTiming{}.orDefault(), func(max time.Duration) time.Duration {
		got = append(got, max)
		return max
	})
	s.next(blocked)
	require.Equal(t, 5*time.Minute+30*time.Second, s.next(blocked))
	require.Equal(t, []time.Duration{time.Second, 30 * time.Second}, got)
}

func TestScheduleFastCountContinuesAcrossBlocked(t *testing.T) {
	s := newSchedule(ReconnectTiming{}.orDefault(), atMost)
	require.Equal(t, time.Second, s.next(transient))
	require.Equal(t, 2*time.Second, s.next(blocked), "the one fast wait for a first blocked error continues n")
	s.next(blocked)
	s.next(blocked)
	require.Equal(t, 4*time.Second, s.next(transient), "slow waits don't advance n")
}

func TestScheduleTransientEndsABlockedStreak(t *testing.T) {
	s := newSchedule(ReconnectTiming{}.orDefault(), atMost)
	s.next(blocked)
	require.GreaterOrEqual(t, s.next(blocked), 5*time.Minute)
	s.next(transient)
	require.LessOrEqual(t, s.next(blocked), 30*time.Second, "a blocked error after a transient one is a first blocked error again")
	require.GreaterOrEqual(t, s.next(blocked), 5*time.Minute)
}

func TestScheduleReset(t *testing.T) {
	s := newSchedule(ReconnectTiming{}.orDefault(), atMost)
	for range 6 {
		s.next(transient)
	}
	s.reset()
	require.Equal(t, time.Second, s.next(transient), "reset starts the fast schedule over")

	s.next(blocked)
	require.GreaterOrEqual(t, s.next(blocked), 5*time.Minute)
	s.reset()
	require.Equal(t, time.Second, s.next(blocked), "reset forgets a blocked streak")
}

func TestScheduleDefaultsAnUnsetTiming(t *testing.T) {
	s := newSchedule(ReconnectTiming{}, atMost)
	require.Equal(t, time.Second, s.next(transient))
}

func TestUniformJitter(t *testing.T) {
	require.Equal(t, time.Duration(0), uniformJitter(0))
	require.Equal(t, time.Duration(0), uniformJitter(-time.Second))
	require.Equal(t, time.Duration(0), uniformJitter(-1<<63))
	for range 200 {
		w := uniformJitter(time.Second)
		require.GreaterOrEqual(t, w, time.Duration(0))
		require.LessOrEqual(t, w, time.Second)
	}
	require.NotPanics(t, func() { uniformJitter(1<<63 - 1) })
}

func TestScheduleNilJitterIsUniform(t *testing.T) {
	timing := ReconnectTiming{}.orDefault()
	s := newSchedule(timing, nil)
	for range 50 {
		w := s.next(transient)
		require.GreaterOrEqual(t, w, time.Duration(0))
		require.LessOrEqual(t, w, timing.FastCap)
	}
	s.next(blocked)
	for range 50 {
		w := s.next(blocked)
		require.GreaterOrEqual(t, w, timing.SlowWait)
		require.LessOrEqual(t, w, timing.SlowWait+timing.SlowJitter)
	}
}

func TestSleepCtxIsInterruptible(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	entering := make(chan struct{})
	done := make(chan bool, 1)
	go func() {
		close(entering)
		done <- sleepCtx(ctx, time.Hour)
	}()
	<-entering
	cancel()

	select {
	case slept := <-done:
		require.False(t, slept, "a sleep that the context cut short reports it")
	case <-time.After(50 * time.Millisecond):
		t.Fatal("sleepCtx did not return within 50 ms of the context ending")
	}
}

func TestSleepCtxReturnsAtOnceOnAnEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, d := range []time.Duration{time.Hour, time.Nanosecond, 0, -time.Second} {
		require.False(t, sleepCtx(ctx, d), "duration %v", d)
	}
}

func TestSleepCtxElapses(t *testing.T) {
	start := time.Now()
	require.True(t, sleepCtx(context.Background(), 20*time.Millisecond))
	require.GreaterOrEqual(t, time.Since(start), 20*time.Millisecond)
	require.True(t, sleepCtx(context.Background(), 0), "a zero wait on a live context is not an interruption")
	require.True(t, sleepCtx(context.Background(), -time.Second))
}
