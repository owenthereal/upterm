package host

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeJoinClock is a joinClock a test drives by hand: time moves when the
// test says, and a timer fires when the test calls fire, on the test's
// goroutine, which is how every ordering below is made deterministic.
//
// It is safe across goroutines, since a running Host calls it from several
// (see joinClock). One mutex covers the fake's now and every timer's state;
// a callback runs outside it, because the callback takes the joinState's
// mutex, which the joinState holds while it calls into the fake.
type fakeJoinClock struct {
	mu   sync.Mutex
	at   time.Time
	made []*fakeTimer
}

// fakeTimer is one timer a fakeJoinClock made. It stays the clock's once it
// is stopped or fired.
type fakeTimer struct {
	clock     *fakeJoinClock
	d         time.Duration
	f         func()
	isStopped bool
	isFired   bool
}

// newFakeJoinClock starts the fake now at a fixed instant, not the zero
// time: a join records now, and a zero join time reads as no join.
func newFakeJoinClock() *fakeJoinClock {
	return &fakeJoinClock{at: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)}
}

// clock fakes afterFunc; now stays real, so what the joinState publishes
// carries real times.
func (f *fakeJoinClock) clock() joinClock { return joinClock{afterFunc: f.afterFunc} }

// clockWithNow fakes both now and afterFunc.
func (f *fakeJoinClock) clockWithNow() joinClock {
	return joinClock{now: f.now, afterFunc: f.afterFunc}
}

// now is the fake now, which only clockWithNow hands out.
func (f *fakeJoinClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.at
}

// advance moves the fake now on by d. It fires nothing: a test fires each
// timer itself.
func (f *fakeJoinClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.at = f.at.Add(d)
}

func (f *fakeJoinClock) afterFunc(d time.Duration, fn func()) func() bool {
	t := &fakeTimer{clock: f, d: d, f: fn}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.made = append(f.made, t)
	return t.stop
}

// timers is every timer made, in order, stopped and fired ones included.
func (f *fakeJoinClock) timers() []*fakeTimer {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.made)
}

// live is the timers that are neither stopped nor fired, in order.
func (f *fakeJoinClock) live() []*fakeTimer {
	f.mu.Lock()
	defer f.mu.Unlock()
	var live []*fakeTimer
	for _, t := range f.made {
		if !t.isStopped && !t.isFired {
			live = append(live, t)
		}
	}
	return live
}

// timer is the latest timer made; it fails the test if none was.
func (f *fakeJoinClock) timer(t *testing.T) *fakeTimer {
	t.Helper()
	made := f.timers()
	require.NotEmpty(t, made, "no timer was armed")
	return made[len(made)-1]
}

// stop is the handle afterFunc returns. As time.Timer.Stop does, it reports
// true only if it stopped a timer that was neither stopped nor fired, and
// does nothing otherwise.
func (t *fakeTimer) stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if t.isStopped || t.isFired {
		return false
	}
	t.isStopped = true
	return true
}

func (t *fakeTimer) duration() time.Duration { return t.d }

// stopped reports whether a stop stopped the timer before it fired.
func (t *fakeTimer) stopped() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	return t.isStopped
}

// fire runs the callback on the caller's goroutine, even when the timer was
// stopped: a stopped timer firing is a callback that was already dispatched
// when Stop ran, which is the case expire's generation check exists for.
func (t *fakeTimer) fire() {
	t.clock.mu.Lock()
	t.isFired = true
	t.clock.mu.Unlock()
	t.f()
}

func newTestJoinState(timeout time.Duration) (*joinState, *fakeJoinClock) {
	c := newFakeJoinClock()
	return newJoinState(timeout, c.clockWithNow()), c
}

func hasFired(s *joinState) bool {
	select {
	case <-s.Fired():
		return true
	default:
		return false
	}
}

func TestFakeJoinClockIsSafeAcrossGoroutines(t *testing.T) {
	f := newFakeJoinClock()
	c := f.clock()
	var wg sync.WaitGroup
	stops := make(chan func() bool, 2)
	for range 2 {
		wg.Go(func() { stops <- c.afterFunc(time.Second, func() {}) })
	}
	wg.Wait()
	done := make(chan struct{})
	go func() { defer close(done); (<-stops)() }()
	for _, tm := range f.timers() {
		tm.fire()
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a stop racing the fires never returned")
	}
	require.Len(t, f.timers(), 2)
	require.Empty(t, f.live(), "every timer is fired or stopped")
}

func TestAStoppedTimerCanStillFire(t *testing.T) {
	f := newFakeJoinClock()
	ran := false
	stop := f.clock().afterFunc(time.Second, func() { ran = true })
	require.True(t, stop())
	require.False(t, stop(), "a second Stop reports false, as time.Timer's does")
	require.Len(t, f.timers(), 1, "a stopped timer is still the clock's")
	require.True(t, f.timers()[0].stopped())
	f.timers()[0].fire()
	require.True(t, ran, "a dispatched callback runs whatever Stop said")

	stopAfterFire := f.clock().afterFunc(time.Second, func() {})
	require.Len(t, f.timers(), 2)
	f.timers()[1].fire()
	require.False(t, stopAfterFire(), "a Stop after the timer fired reports false, as time.Timer's does")
	require.False(t, f.timers()[1].stopped(), "and it stopped nothing")
	require.Empty(t, f.live())
}

func TestJoinStateLaunchTimeoutIsPendingUntilReady(t *testing.T) {
	s, c := newTestJoinState(10 * time.Minute)
	require.Equal(t, joinSnapshot{Timeout: 10 * time.Minute}, s.snapshot(), "set, not counting yet")
	require.Empty(t, c.timers())

	c.advance(time.Hour)
	require.True(t, s.markReady())
	require.Equal(t, joinSnapshot{Timeout: 10 * time.Minute, Deadline: c.now().Add(10 * time.Minute)}, s.snapshot(),
		"the clock starts at readiness, not at launch")
	require.Equal(t, 10*time.Minute, c.timer(t).duration())
}

func TestJoinStateWithoutATimeoutArmsNothing(t *testing.T) {
	s, c := newTestJoinState(0)
	require.False(t, s.markReady())
	require.Equal(t, joinSnapshot{}, s.snapshot())
	require.Empty(t, c.timers())
}

func TestJoinStateSetBeforeReadyIsPending(t *testing.T) {
	s, c := newTestJoinState(0)
	require.Equal(t, joinSnapshot{Outcome: joinPending, Timeout: 5 * time.Minute}, s.set(5*time.Minute))
	require.Empty(t, c.timers(), "nothing counts before readiness")

	c.advance(time.Minute)
	require.True(t, s.markReady())
	require.Equal(t, c.now().Add(5*time.Minute), s.snapshot().Deadline)
}

func TestJoinStateEachSetRestartsTheWindow(t *testing.T) {
	s, c := newTestJoinState(time.Minute)
	s.markReady()
	first := c.timer(t)

	c.advance(50 * time.Second)
	got := s.set(time.Minute)
	require.Equal(t, joinCounting, got.Outcome)
	require.Equal(t, time.Minute, got.Timeout)
	require.Equal(t, c.now().Add(time.Minute), got.Deadline, "counted from the call, not from the first deadline")
	require.True(t, first.stopped(), "the replaced deadline's timer is stopped")
	require.Len(t, c.timers(), 2)
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
	require.Equal(t, c.now(), joinedAt)
	require.True(t, timer.stopped())

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
	require.True(t, old.stopped(), "disabling stops the timer that was counting")
	old.fire()
	require.False(t, hasFired(s))
	require.Equal(t, joinSnapshot{}, s.snapshot())
}

func TestJoinStateSetAfterJoinIsClaimed(t *testing.T) {
	s, c := newTestJoinState(0)
	s.markReady()
	joinedAt, _ := s.join()

	require.Equal(t, joinSnapshot{Outcome: joinClaimed, JoinedAt: joinedAt}, s.set(time.Minute))
	require.Empty(t, c.timers(), "a claimed session is never armed")
}

func TestJoinStateLaterJoinsKeepTheFirstTime(t *testing.T) {
	s, c := newTestJoinState(0)
	first, _ := s.join()
	c.advance(time.Hour)

	again, late := s.join()
	require.False(t, late)
	require.Equal(t, first, again)
}

func TestJoinStateSetAfterExpiryAnswersEnding(t *testing.T) {
	s, c := newTestJoinState(time.Minute)
	s.markReady()
	c.timer(t).fire()

	require.Equal(t, joinSnapshot{Outcome: joinEnding}, s.set(time.Hour))
	require.Len(t, c.timers(), 1, "nothing is re-armed")
}

func TestJoinStateTeardownStopsTheTimerAndRefusesChanges(t *testing.T) {
	s, c := newTestJoinState(time.Minute)
	s.markReady()
	timer := c.timer(t)

	s.close()
	require.True(t, timer.stopped())
	require.Equal(t, joinSnapshot{Outcome: joinEnding}, s.set(time.Hour))
	timer.fire()
	require.False(t, hasFired(s), "teardown for another reason is not a join timeout")
	_, late := s.join()
	require.False(t, late, "only a committed expiry makes a join late")
	require.False(t, s.markReady())
}

// Teardown that beats readiness: a session torn down before it was ready
// never starts counting.
func TestJoinStateCloseBeforeReadyArmsNothing(t *testing.T) {
	s, c := newTestJoinState(time.Minute)
	s.close()
	require.False(t, s.markReady())
	require.Empty(t, c.timers(), "no timer is armed after teardown")
	require.True(t, s.snapshot().Deadline.IsZero())
}

// A -race smoke test, with real timers and real goroutines: whatever the
// interleaving, the timeout never both fires and records a join. It proves
// nothing about ordering on its own; the deterministic tests above pin that.
func TestJoinStateNeverFiresAndRecordsAJoin(t *testing.T) {
	for i := 0; i < 200; i++ {
		s := newJoinState(time.Millisecond, joinClock{})
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
