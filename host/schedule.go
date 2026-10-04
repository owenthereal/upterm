package host

import (
	"context"
	"math/rand/v2"
	"time"
)

// ReconnectTiming paces the tunnel's liveness and its redials. A field left
// zero or negative takes its default, so a caller can override one and inherit
// the rest.
type ReconnectTiming struct {
	// PingInterval is how long the tunnel may be silent before it is probed,
	// and PingBound how long a probe has to prompt any bytes at all. The
	// defaults are 15 s and 15 s.
	PingInterval, PingBound time.Duration
	// AttemptDeadline is how long one redial may take, from dialling to a
	// registered tunnel. The default is 30 s.
	AttemptDeadline time.Duration
	// FastBase and FastCap shape the fast schedule: the wait doubles from
	// FastBase up to FastCap. The defaults are 1 s and 30 s.
	FastBase, FastCap time.Duration
	// SlowWait is the least wait on the slow schedule, and SlowJitter the most
	// that is added to it. The defaults are 5 min and 30 s.
	SlowWait, SlowJitter time.Duration
	// ResetAfter is how long a tunnel must have been up before losing it starts
	// the schedule over, so a relay that keeps dropping the tunnel is not
	// redialled at the fast schedule's start each time. The default is 60 s.
	ResetAfter time.Duration
}

// orDefault fills in whichever field was left zero or negative. A negative
// duration is as much "not set" as zero: neither is a wait or a deadline
// anyone can honour.
func (t ReconnectTiming) orDefault() ReconnectTiming {
	fill := func(d *time.Duration, def time.Duration) {
		if *d <= 0 {
			*d = def
		}
	}
	fill(&t.PingInterval, 15*time.Second)
	fill(&t.PingBound, 15*time.Second)
	fill(&t.AttemptDeadline, 30*time.Second)
	fill(&t.FastBase, time.Second)
	fill(&t.FastCap, 30*time.Second)
	fill(&t.SlowWait, 5*time.Minute)
	fill(&t.SlowJitter, 30*time.Second)
	fill(&t.ResetAfter, 60*time.Second)
	return t
}

// schedule says how long to wait before the next redial. It has no attempt
// limit: a host keeps redialling for as long as its session lives, quickly
// while a failure is likely to be brief and slowly once only someone's action
// is likely to clear it. It is not safe for concurrent use.
type schedule struct {
	t ReconnectTiming
	// n counts the fast waits taken since the last reset. It sets the next
	// fast wait and keeps counting without bound; the wait it implies doesn't.
	n int
	// blocked counts the consecutive blocked errors, so that the first of a
	// run can be told from the rest.
	blocked int
	jitter  func(max time.Duration) time.Duration
}

// newSchedule starts a schedule from the first fast wait. jitter takes a bound
// and returns how much of it to wait, a duration in [0, max]; nil waits a
// uniformly random part of it. A field of t left zero or negative takes its
// default.
func newSchedule(t ReconnectTiming, jitter func(max time.Duration) time.Duration) *schedule {
	if jitter == nil {
		jitter = uniformJitter
	}
	return &schedule{t: t.orDefault(), jitter: jitter}
}

// next is the wait before the next redial, given why the last one failed.
//
// A transient error waits on the fast schedule: jittered below the smaller of
// FastCap and FastBase doubled once per earlier fast wait, so the first retry
// after a loss comes within FastBase.
//
// The first blocked error of a run gets one more fast wait, in case it came
// from one bad node. From the second on, the wait is SlowWait plus up to
// SlowJitter, and never less than SlowWait. A transient error ends the run, and
// the fast schedule resumes where it left off.
func (s *schedule) next(class retryClass) time.Duration {
	if class == blocked {
		s.blocked++
		if s.blocked > 1 {
			return s.t.SlowWait + s.jitter(s.t.SlowJitter)
		}
	} else {
		s.blocked = 0
	}
	return s.fast()
}

// fast takes one fast wait.
func (s *schedule) fast() time.Duration {
	// Double the bound until it reaches FastCap and then stop, rather than
	// computing FastBase<<n: a long outage takes n far enough that the shift
	// would wrap negative.
	bound := s.t.FastBase
	for i := 0; i < s.n && bound < s.t.FastCap; i++ {
		if bound > s.t.FastCap/2 {
			bound = s.t.FastCap
		} else {
			bound *= 2
		}
	}
	s.n++
	return s.jitter(min(bound, s.t.FastCap))
}

// reset starts the fast schedule over and forgets any run of blocked errors. A
// caller resets it once a tunnel it lost had been up for ResetAfter.
func (s *schedule) reset() {
	s.n = 0
	s.blocked = 0
}

// uniformJitter is a uniformly random duration in [0, max], or 0 when max is not
// positive.
func uniformJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Uint64N(uint64(max) + 1))
}

// sleepCtx waits d, and reports whether it waited the whole of it: false is
// returned at once when ctx ends, before or during the wait.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
