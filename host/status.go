package host

import (
	"sync"
	"time"

	"github.com/owenthereal/upterm/host/sessiondir"
)

// phase is how far the host process has got. It only moves forward, and only
// Run writes it: running once the session is ready to serve, ending once Run
// is on its way out.
type phase int

// The zero value is the earliest phase, so a sessionState needs no setup.
const (
	phaseStarting phase = iota
	phaseRunning
	phaseEnding
)

// tunnelState is whether the relay tunnel is carrying guests. The tunnel's
// supervisor is its only writer. The zero value is up: until a connection is
// lost there is nothing to report.
type tunnelState int

const (
	tunnelUp tunnelState = iota
	tunnelReconnecting
	tunnelLost
)

// deriveStatus is the status a session's record carries, a function of the
// two facts and of nothing else, in particular not of the status the record
// had. Ending and starting belong to the process whatever the tunnel is
// doing; while the session is running the tunnel decides: up is ready, down
// and being redialled is reconnecting, and down for good is disconnected.
func deriveStatus(p phase, t tunnelState) string {
	switch p {
	case phaseEnding:
		return sessiondir.StatusEnding
	case phaseStarting:
		return sessiondir.StatusStarting
	}
	switch t {
	case tunnelReconnecting:
		return sessiondir.StatusReconnecting
	case tunnelLost:
		return sessiondir.StatusDisconnected
	}
	return sessiondir.StatusReady
}

// sessionState is the session's two facts, and what its record says about the
// tunnel. The publishers of those facts are concurrent and have no order
// between them: the supervisor learns the tunnel is down while the ready
// actor learns the session is up, in either order, and each publishes.
//
// Neither publisher says what the status is. Each records its own fact here
// and then writes the record through apply, inside the record's own update
// lock. The snapshot apply takes is therefore taken in write order: whichever
// write runs last carries the latest of both facts, and none can leave a
// stale status standing. The record's previous status is not an input.
//
// The zero value is a session that is starting with its tunnel up.
type sessionState struct {
	mu sync.Mutex

	phase  phase
	tunnel tunnelState

	// reconnect is sessiondir.ReconnectSupported or ReconnectUnsupported once
	// the first connection has shown whether the relay derives session IDs,
	// and empty before. It is a property of the relay, so it is never cleared.
	reconnect string

	// The current outage: when it began, why the latest attempt failed, that
	// attempt's raw error, and when the next attempt is due. All zero while
	// the tunnel is up.
	lostAt  time.Time
	reason  string
	lastErr string
	nextAt  time.Time
}

// setPhase moves the phase forward. A move backwards is ignored: a session
// that has begun ending does not run again.
func (s *sessionState) setPhase(p phase) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p > s.phase {
		s.phase = p
	}
}

// setReconnect records whether the relay derives session IDs, so a redial
// can be expected to find the session again.
func (s *sessionState) setReconnect(supported bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if supported {
		s.reconnect = sessiondir.ReconnectSupported
	} else {
		s.reconnect = sessiondir.ReconnectUnsupported
	}
}

// tunnelUp says the tunnel is carrying guests, and ends the outage: nothing
// of it is left to report.
func (s *sessionState) tunnelUp() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnel = tunnelUp
	s.lostAt, s.reason, s.lastErr, s.nextAt = time.Time{}, "", "", time.Time{}
}

// tunnelReconnecting says the tunnel is down and the host is redialling it:
// the outage began at lostAt, the latest attempt failed for reason (one of
// sessiondir's TunnelReason values) with lastErr, and the next attempt is due
// at nextAt. Called again after each failed attempt, with the same lostAt.
func (s *sessionState) tunnelReconnecting(lostAt time.Time, reason, lastErr string, nextAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnel = tunnelReconnecting
	s.lostAt, s.reason, s.lastErr, s.nextAt = lostAt, reason, lastErr, nextAt
}

// tunnelLost says the tunnel is down and will not come back: the relay does
// not derive session IDs, so a new connection would be a different session.
// There is no next attempt.
func (s *sessionState) tunnelLost(lostAt time.Time, lastErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnel = tunnelLost
	s.lostAt, s.reason, s.lastErr, s.nextAt = lostAt, sessiondir.TunnelReasonReconnectUnsupported, lastErr, time.Time{}
}

// status is the status the facts give now.
func (s *sessionState) status() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return deriveStatus(s.phase, s.tunnel)
}

// apply writes the status and the tunnel's fields onto r from one snapshot of
// the state. It is for dir.Update's closure, which is what makes the snapshot
// ordered with the record's other writers; called anywhere else it gives a
// record that may already be stale. It takes the state's lock inside the
// record's, so nothing may call into the record while holding the state's.
// An ended session's outage is left as it was, so its record still says it
// ended while reconnecting.
func (s *sessionState) apply(r *sessiondir.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.Status = deriveStatus(s.phase, s.tunnel)
	r.Reconnect = s.reconnect
	r.TunnelLostAt = s.lostAt
	r.TunnelReason = s.reason
	r.TunnelError = s.lastErr
	r.NextAttemptAt = s.nextAt
}
