package join

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/liveness"
	"github.com/stretchr/testify/require"
)

func TestFastTierDoublesToItsCap(t *testing.T) {
	s := newSchedule(Timing{Jitter: func(max time.Duration) time.Duration { return max }})
	var got []time.Duration
	for i := 0; i < 6; i++ {
		w, long := s.next(time.Duration(i) * time.Second)
		require.False(t, long)
		got = append(got, w)
	}
	require.Equal(t, []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second}, got)
}

func TestSlowTierAfterFiveMinutes(t *testing.T) {
	s := newSchedule(Timing{Jitter: func(max time.Duration) time.Duration { return max }})
	w, long := s.next(5 * time.Minute)
	require.True(t, long)
	require.Equal(t, 90*time.Second, w)
}

func TestAFlappingSessionBacksOff(t *testing.T) {
	s := newSchedule(Timing{Jitter: func(max time.Duration) time.Duration { return max }})
	var last time.Duration
	for i := 0; i < 10; i++ { // ready for 1 s, then dropped, ten times
		last, _ = s.next(0)
		s.ready(time.Second)
	}
	require.Equal(t, 10*time.Second, last)
	s.ready(time.Minute)
	first, _ := s.next(0)
	require.Equal(t, time.Second, first)
}

func TestZeroAndNegativeFieldsTakeTheirDefaults(t *testing.T) {
	got := Timing{FastBase: -time.Second, SlowWait: 7 * time.Second}.orDefault()

	require.Equal(t, time.Second, got.FastBase)
	require.Equal(t, 10*time.Second, got.FastCap)
	require.Equal(t, 5*time.Minute, got.LongAfter)
	require.Equal(t, 7*time.Second, got.SlowWait)
	require.Equal(t, 30*time.Second, got.SlowJitter)
	require.Equal(t, time.Minute, got.ResetAfter)
	require.Equal(t, 30*time.Second, got.FirstJoin)
	require.Equal(t, 30*time.Second, got.Attempt)
	require.Equal(t, liveness.DefaultTiming, got.Liveness)
	require.Equal(t, time.Second, got.WallCheck)
	require.NotNil(t, got.Jitter)
	require.NotNil(t, got.Wall)
}

func TestTheDefaultJitterStaysWithinItsBound(t *testing.T) {
	jitter := Timing{}.orDefault().Jitter
	require.Zero(t, jitter(0))
	require.Zero(t, jitter(-time.Second))

	var spread bool
	for i := 0; i < 1000; i++ {
		j := jitter(time.Second)
		require.GreaterOrEqual(t, j, time.Duration(0))
		require.LessOrEqual(t, j, time.Second)
		spread = spread || j != 0
	}
	require.True(t, spread, "a jitter that is always zero spreads nothing")
}

func TestTheDefaultWallClockCarriesNoMonotonicReading(t *testing.T) {
	// A reading would make the clock move with the monotonic one, which is the
	// clock that stops while the machine sleeps.
	now := Timing{}.orDefault().Wall()
	require.Equal(t, now, now.Round(0))
	require.WithinDuration(t, time.Now(), now, time.Minute)
}

func TestWaitAttemptsWhenTheWallClockJumps(t *testing.T) {
	var jumped atomic.Bool
	started := make(chan struct{})
	var once sync.Once
	base := time.Now().Round(0)
	tm := Timing{WallCheck: 20 * time.Millisecond, Wall: func() time.Time {
		now := base
		if jumped.Load() {
			now = base.Add(time.Hour)
		}
		// The wait has read the clock for its target once this closes, so
		// the jump below can only come after it.
		once.Do(func() { close(started) })
		return now
	}}.orDefault()
	done := make(chan error, 1)
	go func() { done <- waitFor(context.Background(), tm, 60*time.Second, nil) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the wait never read the wall clock")
	}
	jumped.Store(true) // the lid opened an hour later
	// The wait is a minute long; a ceiling well short of it is all that tells
	// a wait that looked at the wall clock from one that didn't.
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("a wait whose wall-clock target had passed kept sleeping")
	}
}

func TestWaitIsNotLengthenedByAClockSteppedBack(t *testing.T) {
	base := time.Now().Round(0)
	var calls atomic.Int32
	tm := Timing{WallCheck: 20 * time.Millisecond, Wall: func() time.Time {
		if calls.Add(1) == 1 {
			return base // when the wait starts
		}
		return base.Add(-time.Hour) // NTP stepped the clock back
	}}.orDefault()
	start := time.Now()
	require.NoError(t, waitFor(context.Background(), tm, 100*time.Millisecond, nil))
	// The delay, and nowhere near the hour the wall clock now says is left.
	took := time.Since(start)
	require.GreaterOrEqual(t, took, 100*time.Millisecond)
	require.Less(t, took, time.Second)
}

func TestWaitEndsEarlyWhenToldToRetry(t *testing.T) {
	retry := make(chan struct{}, 1)
	retry <- struct{}{}
	done := make(chan error, 1)
	go func() { done <- waitFor(context.Background(), Timing{}.orDefault(), time.Hour, retry) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("a retry did not end the wait")
	}
}

func TestWaitEndsWithTheErrorOfAContextThatEnds(t *testing.T) {
	// The deadline arrives while the wait is sleeping.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- waitFor(ctx, Timing{}.orDefault(), time.Hour, nil) }()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(5 * time.Second):
		t.Fatal("a context that ended did not end the wait")
	}

	// The context is over before the wait starts, whatever the delay is.
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	for _, delay := range []time.Duration{time.Hour, 0, -time.Second} {
		require.ErrorIs(t, waitFor(cancelled, Timing{}.orDefault(), delay, nil), context.Canceled, delay.String())
	}
}

func TestWaitWithNothingToWaitForReturnsAtOnce(t *testing.T) {
	for _, delay := range []time.Duration{0, -time.Second} {
		require.NoError(t, waitFor(context.Background(), Timing{}.orDefault(), delay, nil), delay.String())
	}
}
