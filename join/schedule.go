package join

import (
	"context"
	"math/rand/v2"
	"time"

	"github.com/owenthereal/upterm/internal/liveness"
)

// Timing is every duration the core runs by. A field left zero or negative
// takes its default, so that a caller, a test above all, can set one and
// inherit the rest.
type Timing struct {
	// FastBase and FastCap are the first wait of a run of attempts and the
	// most a wait can be while the guest is still in the fast tier. Each wait
	// doubles the bound of the one before until it reaches FastCap. 1 s, 10 s.
	FastBase, FastCap time.Duration

	// LongAfter is how long a wait has lasted when the slow tier begins, and
	// when Waiting says so. 5 min. The wait is measured on the monotonic
	// clock, as the deadlines are, and not on Wall: a wall clock that is
	// stepped, or that jumps when a laptop wakes, leaves it where it was.
	LongAfter time.Duration

	// SlowWait and SlowJitter are what separates attempts in the slow tier:
	// SlowWait plus up to SlowJitter more. 60 s, 30 s.
	SlowWait, SlowJitter time.Duration

	// ResetAfter is how long a session has to have been ready for the next
	// drop to start the schedule over. A session that drops sooner leaves the
	// schedule where it was, so that a host that keeps dropping a guest is
	// not rejoined every second. 60 s.
	ResetAfter time.Duration

	// FirstJoin is the deadline of a first join, from its first attempt. 30 s.
	FirstJoin time.Duration

	// Attempt is how long one attempt has to connect, from the dial to the
	// shell. 30 s.
	Attempt time.Duration

	// Liveness is when a connection that has gone quiet is probed and given
	// up on. The host's tunnel figures: 15 s and 15 s.
	Liveness liveness.Timing

	// WallCheck is the longest a wait goes without looking at the wall clock.
	// 1 s.
	WallCheck time.Duration

	// Jitter returns a duration chosen from [0, max]. Nil means uniform.
	Jitter func(max time.Duration) time.Duration

	// Wall tells the wall-clock time. Nil means time.Now with its monotonic
	// reading dropped, so that the time moves with the clock on the wall and
	// not with the one that stops while the machine sleeps.
	Wall func() time.Time
}

// orDefault fills in whichever field was left zero or negative, as
// liveness.Timing.OrDefault does for its own.
func (t Timing) orDefault() Timing {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&t.FastBase, time.Second)
	def(&t.FastCap, 10*time.Second)
	def(&t.LongAfter, 5*time.Minute)
	def(&t.SlowWait, 60*time.Second)
	def(&t.SlowJitter, 30*time.Second)
	def(&t.ResetAfter, 60*time.Second)
	def(&t.FirstJoin, 30*time.Second)
	def(&t.Attempt, 30*time.Second)
	def(&t.WallCheck, time.Second)
	t.Liveness = t.Liveness.OrDefault()
	if t.Jitter == nil {
		t.Jitter = uniformJitter
	}
	if t.Wall == nil {
		t.Wall = func() time.Time { return time.Now().Round(0) }
	}
	return t
}

// uniformJitter is a duration chosen evenly from [0, max]; nothing for a max
// that leaves no room.
func uniformJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(max) + 1))
}

// schedule decides how long to wait before each rejoin. It has no clock of
// its own: the caller says how long the wait has lasted and how long a session
// was ready, so the same figures drive it in a test and in a run.
type schedule struct {
	t Timing
	n int // the waits so far since the schedule last restarted
}

func newSchedule(t Timing) *schedule { return &schedule{t: t.orDefault()} }

// next is the wait before the next attempt, for a wait that has lasted elapsed
// so far; long reports that it has lasted long enough to be in the slow tier.
//
// In the fast tier the n-th wait is jittered below min(FastCap, FastBase·2ⁿ).
// n keeps counting once the bound has reached FastCap, so that a guest who
// connects and drops again comes back to a wait that is still at the cap.
func (s *schedule) next(elapsed time.Duration) (wait time.Duration, long bool) {
	if elapsed >= s.t.LongAfter {
		s.n++
		return s.t.SlowWait + s.t.Jitter(s.t.SlowJitter), true
	}
	bound := s.t.FastBase
	for i := 0; i < s.n && bound < s.t.FastCap; i++ {
		bound *= 2
	}
	s.n++
	return s.t.Jitter(min(bound, s.t.FastCap)), false
}

// ready says that a session ended after being ready for d. Only a session that
// stayed up for ResetAfter restarts the schedule. One that drops sooner leaves
// n where it was, so the bound of the wait after it is no lower than the last
// one's; the wait itself is jittered below its bound, and may be shorter.
func (s *schedule) ready(d time.Duration) {
	if d >= s.t.ResetAfter {
		s.n = 0
	}
}

// waitFor sleeps for delay and returns nil once it is over, or once retry
// delivers. It returns ctx.Err() if ctx ends first.
//
// The wait is over when the delay has passed on the monotonic clock or when
// the wall clock has passed the time it was due, whichever comes first. The
// monotonic clock stops while a laptop sleeps, so a timer armed before the lid
// closed would fire late after it opened. Hence the wake-ups at least every
// WallCheck, each of which looks at the wall clock. And hence the monotonic
// deadline too: a wall clock stepped backwards must not make the wait longer
// than the delay.
func waitFor(ctx context.Context, t Timing, delay time.Duration, retry <-chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if delay <= 0 {
		return nil
	}
	t = t.orDefault()
	wallDue := t.Wall().Add(delay)
	monoDue := time.Now().Add(delay)

	timer := time.NewTimer(min(t.WallCheck, delay))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-retry:
			return nil
		case <-timer.C:
		}
		if !time.Now().Before(monoDue) || !t.Wall().Before(wallDue) {
			return nil
		}
		timer.Reset(min(t.WallCheck, time.Until(monoDue)))
	}
}
