package host

import (
	"sync"
	"time"

	"github.com/owenthereal/upterm/host/api"
)

// joinOutcome is what a request to set the join timeout found.
type joinOutcome int

const (
	// joinCounting: the timeout is counting; Deadline says when it fires.
	joinCounting joinOutcome = iota + 1
	// joinPending: set before readiness; Timeout counts from readiness.
	joinPending
	// joinDisabled: no timeout is set.
	joinDisabled
	// joinClaimed: a guest had already joined, at JoinedAt, so nothing was
	// set. The first join claims the session for good.
	joinClaimed
	// joinEnding: the timeout already committed, or the session is tearing
	// down for another reason.
	joinEnding
)

// joinSnapshot is the join state at one instant. Outcome is only set on what
// set returns.
type joinSnapshot struct {
	Outcome  joinOutcome
	Timeout  time.Duration // set and not claimed; zero otherwise
	Deadline time.Time     // counting, or the deadline that fired; zero otherwise
	JoinedAt time.Time     // the first guest's join; zero until one does
}

// joinState is the single owner of a session's no-guest deadline.
//
// Every event that bears on it -- readiness, a guest joining, a caller
// setting the timeout, the timer firing, teardown -- takes one mutex, so the
// order in which they take it is the order in which they happened. The
// deadline actor used to decide with a select over a timer and a joined
// channel, re-checking before it won; Go chooses at random among ready
// cases, so that tie-breaking was best-effort and a join could land after
// the last check.
//
// The commit point is expire setting expired. A join that takes the mutex
// before it disarms the timeout for good; a join after it is late, and is
// not recorded, because the session is already ending for want of one. A
// set or a join bumps gen, which turns any expire already on its way for an
// older deadline into a no-op.
type joinState struct {
	now       func() time.Time
	afterFunc func(time.Duration, func()) (stop func() bool)

	mu        sync.Mutex
	timeout   time.Duration
	deadline  time.Time
	gen       uint64
	stopTimer func() bool
	ready     bool
	joinedAt  time.Time
	expired   bool
	closed    bool
	fired     chan struct{}
}

// newJoinState returns the join state for a session launched with timeout,
// which counts from readiness; zero sets none.
func newJoinState(timeout time.Duration) *joinState {
	return &joinState{
		now: time.Now,
		afterFunc: func(d time.Duration, f func()) func() bool {
			return time.AfterFunc(d, f).Stop
		},
		timeout: timeout,
		fired:   make(chan struct{}),
	}
}

// Fired is closed once the timeout has committed.
func (s *joinState) Fired() <-chan struct{} { return s.fired }

// markReady records readiness. A timeout already set starts counting from
// now; it reports whether one did.
func (s *joinState) markReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready || s.closed {
		return false
	}
	s.ready = true
	if s.timeout == 0 || !s.joinedAt.IsZero() {
		return false
	}
	s.startLocked()
	return true
}

// set replaces the timeout: counted from now, or from readiness if the
// session is not ready yet. Zero disables it.
func (s *joinState) set(timeout time.Duration) joinSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expired || s.closed {
		return joinSnapshot{Outcome: joinEnding}
	}
	if !s.joinedAt.IsZero() {
		return joinSnapshot{Outcome: joinClaimed, JoinedAt: s.joinedAt}
	}
	s.disarmLocked()
	s.timeout = timeout
	switch {
	case timeout == 0:
		return joinSnapshot{Outcome: joinDisabled}
	case !s.ready:
		return joinSnapshot{Outcome: joinPending, Timeout: timeout}
	}
	s.startLocked()
	return joinSnapshot{Outcome: joinCounting, Timeout: timeout, Deadline: s.deadline}
}

// join records a guest joining and reports when the first one did. late
// means the timeout had already committed: the session is ending for want of
// a guest, and this join must not be published.
func (s *joinState) join() (joinedAt time.Time, late bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expired {
		return time.Time{}, true
	}
	if s.joinedAt.IsZero() {
		s.joinedAt = s.now().UTC()
		s.disarmLocked()
		s.timeout = 0
	}
	return s.joinedAt, false
}

// expire is the timer's callback for generation gen: it commits the timeout
// unless something changed it since that timer was armed.
func (s *joinState) expire(gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen != s.gen || s.expired || s.closed || !s.joinedAt.IsZero() || s.deadline.IsZero() {
		return
	}
	s.expired = true
	s.stopTimer = nil
	close(s.fired)
}

// close marks teardown: the timer stops and later sets answer joinEnding.
// The state itself is kept, so the final record shows what was current.
func (s *joinState) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.stopTimer != nil {
		s.stopTimer()
		s.stopTimer = nil
	}
}

// snapshot is the state as it stands, for publication.
func (s *joinState) snapshot() joinSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return joinSnapshot{Timeout: s.timeout, Deadline: s.deadline, JoinedAt: s.joinedAt}
}

func (s *joinState) startLocked() {
	s.disarmLocked()
	gen := s.gen
	s.deadline = s.now().UTC().Add(s.timeout)
	s.stopTimer = s.afterFunc(s.timeout, func() { s.expire(gen) })
}

func (s *joinState) disarmLocked() {
	s.gen++
	if s.stopTimer != nil {
		s.stopTimer()
		s.stopTimer = nil
	}
	s.deadline = time.Time{}
}

// apiJoinState is s as the admin API carries it: a zero field is absent.
func apiJoinState(s joinSnapshot) *api.JoinState {
	st := &api.JoinState{TimeoutNanos: int64(s.Timeout)}
	if !s.Deadline.IsZero() {
		st.DeadlineUnixNano = s.Deadline.UnixNano()
	}
	if !s.JoinedAt.IsZero() {
		st.FirstGuestJoinedUnixNano = s.JoinedAt.UnixNano()
	}
	return st
}

// setJoinTimeoutResponse is set's result as the admin API carries it.
func setJoinTimeoutResponse(s joinSnapshot) *api.SetJoinTimeoutResponse {
	var outcome api.SetJoinTimeoutResponse_Outcome
	switch s.Outcome {
	case joinCounting:
		outcome = api.SetJoinTimeoutResponse_COUNTING
	case joinPending:
		outcome = api.SetJoinTimeoutResponse_PENDING
	case joinDisabled:
		outcome = api.SetJoinTimeoutResponse_DISABLED
	case joinClaimed:
		outcome = api.SetJoinTimeoutResponse_CLAIMED
	case joinEnding:
		outcome = api.SetJoinTimeoutResponse_ENDING
	}
	return &api.SetJoinTimeoutResponse{Outcome: outcome, State: apiJoinState(s)}
}
