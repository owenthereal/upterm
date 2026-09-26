package host

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeJoinTimer struct {
	d       time.Duration
	fire    func()
	stopped bool
}

// fakeJoinClock drives a joinState by hand: time moves when the test says,
// and a timer fires when the test calls fire, from the test's goroutine, which
// is how every ordering below is made deterministic.
type fakeJoinClock struct {
	now    time.Time
	timers []*fakeJoinTimer
}

func newTestJoinState(timeout time.Duration) (*joinState, *fakeJoinClock) {
	c := &fakeJoinClock{now: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)}
	s := newJoinState(timeout)
	s.now = func() time.Time { return c.now }
	s.afterFunc = func(d time.Duration, f func()) func() bool {
		t := &fakeJoinTimer{d: d, fire: f}
		c.timers = append(c.timers, t)
		return func() bool {
			was := !t.stopped
			t.stopped = true
			return was
		}
	}
	return s, c
}

func (c *fakeJoinClock) timer(t *testing.T) *fakeJoinTimer {
	t.Helper()
	require.NotEmpty(t, c.timers, "no timer was armed")
	return c.timers[len(c.timers)-1]
}

func hasFired(s *joinState) bool {
	select {
	case <-s.Fired():
		return true
	default:
		return false
	}
}

func TestJoinStateLaunchTimeoutIsPendingUntilReady(t *testing.T) {
	s, c := newTestJoinState(10 * time.Minute)
	require.Equal(t, joinSnapshot{Timeout: 10 * time.Minute}, s.snapshot(), "set, not counting yet")
	require.Empty(t, c.timers)

	c.now = c.now.Add(time.Hour)
	require.True(t, s.markReady())
	require.Equal(t, joinSnapshot{Timeout: 10 * time.Minute, Deadline: c.now.Add(10 * time.Minute)}, s.snapshot(),
		"the clock starts at readiness, not at launch")
	require.Equal(t, 10*time.Minute, c.timer(t).d)
}

func TestJoinStateWithoutATimeoutArmsNothing(t *testing.T) {
	s, c := newTestJoinState(0)
	require.False(t, s.markReady())
	require.Equal(t, joinSnapshot{}, s.snapshot())
	require.Empty(t, c.timers)
}

func TestJoinStateSetBeforeReadyIsPending(t *testing.T) {
	s, c := newTestJoinState(0)
	require.Equal(t, joinSnapshot{Outcome: joinPending, Timeout: 5 * time.Minute}, s.set(5*time.Minute))
	require.Empty(t, c.timers, "nothing counts before readiness")

	c.now = c.now.Add(time.Minute)
	require.True(t, s.markReady())
	require.Equal(t, c.now.Add(5*time.Minute), s.snapshot().Deadline)
}

func TestJoinStateEachSetRestartsTheWindow(t *testing.T) {
	s, c := newTestJoinState(time.Minute)
	s.markReady()
	first := c.timer(t)

	c.now = c.now.Add(50 * time.Second)
	got := s.set(time.Minute)
	require.Equal(t, joinCounting, got.Outcome)
	require.Equal(t, time.Minute, got.Timeout)
	require.Equal(t, c.now.Add(time.Minute), got.Deadline, "counted from the call, not from the first deadline")
	require.True(t, first.stopped, "the replaced deadline's timer is stopped")
	require.Len(t, c.timers, 2)
}

func TestJoinStateExpiryCommits(t *testing.T) {
	s, c := newTestJoinState(time.Minute)
	s.markReady()
	deadline := s.snapshot().Deadline

	c.timer(t).fire()
	require.True(t, hasFired(s))
	require.Equal(t, deadline, s.snapshot().Deadline, "an expired timeout keeps the deadline that fired")
}

func TestJoinStateJoinAfterCommitIsLate(t *testing.T) {
	s, c := newTestJoinState(time.Minute)
	s.markReady()
	c.timer(t).fire()

	joinedAt, late := s.join()
	require.True(t, late, "the session is already ending for want of a guest")
	require.True(t, joinedAt.IsZero())
	require.True(t, s.snapshot().JoinedAt.IsZero(), "a late join is never recorded")
}

func TestJoinStateJoinBeforeFireWins(t *testing.T) {
	s, c := newTestJoinState(time.Minute)
	s.markReady()
	timer := c.timer(t)

	joinedAt, late := s.join()
	require.False(t, late)
	require.Equal(t, c.now, joinedAt)
	require.True(t, timer.stopped)

	// The timer's own goroutine can already be on its way when the join
	// takes the lock; its expire must then change nothing.
	timer.fire()
	require.False(t, hasFired(s), "a fire that lost to a join is a no-op")
	require.Equal(t, joinSnapshot{JoinedAt: joinedAt}, s.snapshot(), "claimed: no timeout, no deadline")
}

func TestJoinStateStaleFireAfterReplaceIsNoOp(t *testing.T) {
	s, c := newTestJoinState(time.Minute)
	s.markReady()
	old := c.timer(t)
	s.set(time.Hour)
	current := c.timer(t)

	old.fire()
	require.False(t, hasFired(s), "the replaced deadline cannot end the session")
	current.fire()
	require.True(t, hasFired(s))
}

func TestJoinStateStaleFireAfterDisableIsNoOp(t *testing.T) {
	s, c := newTestJoinState(time.Minute)
	s.markReady()
	old := c.timer(t)

	require.Equal(t, joinSnapshot{Outcome: joinDisabled}, s.set(0))
	old.fire()
	require.False(t, hasFired(s))
	require.Equal(t, joinSnapshot{}, s.snapshot())
}

func TestJoinStateSetAfterJoinIsClaimed(t *testing.T) {
	s, c := newTestJoinState(0)
	s.markReady()
	joinedAt, _ := s.join()

	require.Equal(t, joinSnapshot{Outcome: joinClaimed, JoinedAt: joinedAt}, s.set(time.Minute))
	require.Empty(t, c.timers, "a claimed session is never armed")
}

func TestJoinStateLaterJoinsKeepTheFirstTime(t *testing.T) {
	s, c := newTestJoinState(0)
	first, _ := s.join()
	c.now = c.now.Add(time.Hour)

	again, late := s.join()
	require.False(t, late)
	require.Equal(t, first, again)
}

func TestJoinStateSetAfterExpiryAnswersEnding(t *testing.T) {
	s, c := newTestJoinState(time.Minute)
	s.markReady()
	c.timer(t).fire()

	require.Equal(t, joinSnapshot{Outcome: joinEnding}, s.set(time.Hour))
	require.Len(t, c.timers, 1, "nothing is re-armed")
}

func TestJoinStateTeardownStopsTheTimerAndRefusesChanges(t *testing.T) {
	s, c := newTestJoinState(time.Minute)
	s.markReady()
	timer := c.timer(t)

	s.close()
	require.True(t, timer.stopped)
	require.Equal(t, joinSnapshot{Outcome: joinEnding}, s.set(time.Hour))
	timer.fire()
	require.False(t, hasFired(s), "teardown for another reason is not a join timeout")
	_, late := s.join()
	require.False(t, late, "only a committed expiry makes a join late")
	require.False(t, s.markReady())
}

// With real timers and real goroutines, under -race in CI: whatever the
// interleaving, the timeout never both fires and records a join.
func TestJoinStateNeverFiresAndRecordsAJoin(t *testing.T) {
	for i := 0; i < 200; i++ {
		s := newJoinState(time.Millisecond)
		s.markReady()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); s.join() }()
		go func() { defer wg.Done(); s.set(time.Millisecond) }()
		wg.Wait()
		time.Sleep(3 * time.Millisecond)
		require.False(t, hasFired(s) && !s.snapshot().JoinedAt.IsZero(), "iteration %d fired and recorded a join", i)
	}
}
