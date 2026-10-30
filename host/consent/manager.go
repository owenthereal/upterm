package consent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"
)

type connectionGrant struct {
	connection string
	capability Capability
	tuple      string
}
type guestGrant struct {
	fingerprint string
	capability  Capability
}
type flightKey struct {
	guestGrant
	unidentifiedConnection string
	tuple                  string
}
type result struct {
	decision Decision
	err      error
}
type waiter struct {
	sequence  uint64
	ctx       context.Context
	deadline  time.Time
	operation Operation
	client    ClientInfo
	subjects  []string
	key       flightKey
	flight    *flight
	requestID string
	done      chan struct{}
	finished  bool
	result    result
}
type flight struct {
	key     flightKey
	origin  *waiter
	waiters map[*waiter]struct{}
	prompt  Prompt
	ctx     context.Context
	cancel  context.CancelFunc
}

// Manager owns grants and bounded in-flight reviews. All mutable state is
// protected by mu; prompt calls, notifications and logging run without it.
type Manager struct {
	mu          sync.Mutex
	prompter    Prompter
	logger      *slog.Logger
	closed      bool
	sequence    uint64
	flights     map[flightKey]*flight
	waiters     map[*waiter]struct{}
	connections map[string]int
	grants      map[connectionGrant]struct{}
	guests      map[guestGrant]struct{}
	workers     sync.WaitGroup
	workerCount int // Includes invalidated prompts until their workers finish cleanup.
}

var _ PermissionChecker = (*Manager)(nil)

// NewManager creates a policy manager. An absent prompter denies new requests.
func NewManager(prompter Prompter, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		prompter: prompter, logger: logger,
		flights: make(map[flightKey]*flight), waiters: make(map[*waiter]struct{}),
		connections: make(map[string]int), grants: make(map[connectionGrant]struct{}),
		guests: make(map[guestGrant]struct{}),
	}
}

// transitions defers external work until the state lock has been released.
type transitions struct {
	start  []*flight
	cancel []context.CancelFunc
	done   []*waiter
}

func (a transitions) run(m *Manager) {
	for _, cancel := range a.cancel {
		cancel()
	}
	for _, w := range a.done {
		close(w.done)
	}
	for _, f := range a.start {
		go m.review(f)
	}
}

// CheckPermission retains the caller's earlier deadline and applies a 60-second
// ceiling measured from entry, including scheduling and coalescing.
func (m *Manager) CheckPermission(ctx context.Context, op Operation, client ClientInfo, subjects ...string) (Decision, error) {
	deadline := time.Now().Add(PermissionTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	subjects = append([]string(nil), subjects...)
	decision, err, id := m.check(ctx, deadline, op, client, subjects)
	// Even a cached result must not escape cancellation at the policy boundary.
	if decision != Deny {
		if e := contextError(ctx, deadline, time.Now()); e != nil {
			decision, err = Deny, e
		}
	}
	m.log(op, client, subjects, id, decision, err)
	return decision, err
}

func (m *Manager) check(ctx context.Context, deadline time.Time, op Operation, client ClientInfo, subjects []string) (Decision, error, string) {
	capability := op.Capability()
	tuple := encodeTuple(subjects)
	key := flightKey{guestGrant: guestGrant{client.Fingerprint, capability}, tuple: tuple}
	if client.Fingerprint == "" {
		key.unidentifiedConnection = client.ConnectionID
	}
	var a transitions
	m.mu.Lock()
	m.expireLocked(&a)
	m.reconcileLocked(&a)
	var immediate result
	switch {
	case m.closed:
		immediate = result{Deny, ErrUnavailable}
	case capability == "":
		immediate = result{Deny, fmt.Errorf("%w: invalid operation %q", ErrDenied, op)}
	default:
		immediate.err = contextError(ctx, deadline, time.Now())
	}
	if immediate.err == nil {
		if client.Fingerprint != "" {
			if _, ok := m.guests[key.guestGrant]; ok {
				immediate.decision = AllowGuest
			}
		}
		if immediate.decision == Deny {
			if _, ok := m.grants[connectionGrant{client.ConnectionID, capability, tuple}]; ok {
				immediate.decision = AllowConnection
			}
		}
		if immediate.decision == Deny {
			bytes := 0
			for _, s := range subjects {
				bytes += len(s)
			}
			switch {
			case bytes > MaxSubjectBytes:
				immediate.err = fmt.Errorf("%w: complete subject tuple is %d bytes; maximum is %d", ErrSubjectTooLarge, bytes, MaxSubjectBytes)
			case m.prompter == nil:
				immediate.err = ErrUnavailable
			case len(m.waiters) >= MaxWaiters || m.connections[client.ConnectionID] >= MaxWaitersPerConnection:
				immediate.err = ErrOverloaded
			case m.flights[key] != nil && len(m.flights[key].waiters) >= MaxWaitersPerFlight:
				immediate.err = ErrOverloaded
			case m.flights[key] == nil && (m.pendingKeysLocked() >= MaxPending || m.workerCount >= MaxPending):
				immediate.err = ErrOverloaded
			}
		}
	}
	if immediate.err != nil || immediate.decision != Deny {
		m.reconcileLocked(&a)
		m.mu.Unlock()
		a.run(m)
		return immediate.decision, immediate.err, ""
	}
	m.sequence++
	w := &waiter{sequence: m.sequence, ctx: ctx, deadline: deadline, operation: op, client: client, subjects: subjects, key: key, done: make(chan struct{})}
	m.waiters[w] = struct{}{}
	m.connections[client.ConnectionID]++
	if f := m.flights[key]; f != nil {
		w.flight = f
		w.requestID = f.prompt.ID
		f.waiters[w] = struct{}{}
	}
	m.reconcileLocked(&a)
	m.mu.Unlock()
	a.run(m)
	select {
	case <-w.done:
	case <-ctx.Done():
	}
	a = transitions{}
	m.mu.Lock()
	m.expireLocked(&a)
	m.reconcileLocked(&a)
	answer, id := w.result, w.requestID
	m.mu.Unlock()
	a.run(m)
	return answer.decision, answer.err, id
}

// Length prefixes preserve every tuple element, including NULs and delimiters.
func encodeTuple(subjects []string) string {
	var encoded []byte
	for _, s := range subjects {
		encoded = binary.AppendUvarint(encoded, uint64(len(s)))
		encoded = append(encoded, s...)
	}
	return string(encoded)
}

func contextError(ctx context.Context, deadline, timeNow time.Time) error {
	err := ctx.Err()
	if errors.Is(err, context.DeadlineExceeded) || !timeNow.Before(deadline) {
		return errors.Join(ErrTimeout, context.DeadlineExceeded)
	}
	if err != nil {
		return errors.Join(ErrCanceled, err)
	}
	return nil
}

// expireLocked also runs when answers arrive, so a late answer cannot win just
// because its originating CheckPermission goroutine has not yet been scheduled.
func (m *Manager) expireLocked(a *transitions) {
	now := time.Now()
	for w := range m.waiters {
		if err := contextError(w.ctx, w.deadline, now); err != nil {
			m.finishLocked(w, result{Deny, err}, a)
		}
	}
}

func (m *Manager) finishLocked(w *waiter, answer result, a *transitions) {
	if w.finished {
		return
	}
	w.finished = true
	w.result = answer
	delete(m.waiters, w)
	m.connections[w.client.ConnectionID]--
	if m.connections[w.client.ConnectionID] == 0 {
		delete(m.connections, w.client.ConnectionID)
	}
	a.done = append(a.done, w)
	f := w.flight
	if f == nil {
		return
	}
	delete(f.waiters, w)
	w.flight = nil
	if f.origin == w {
		// Invalidate the request ID under the same lock used to commit approvals.
		delete(m.flights, f.key)
		a.cancel = append(a.cancel, f.cancel)
		for other := range f.waiters {
			other.flight = nil
		}
		clear(f.waiters)
	}
}

// Count orphaned groups too: origin expiry must not bypass the flight bound.
func (m *Manager) pendingKeysLocked() int {
	keys := make(map[flightKey]struct{})
	for w := range m.waiters {
		keys[w.key] = struct{}{}
	}
	return len(keys)
}

// Re-form orphaned flights with their oldest remaining waiter and unchanged
// deadlines. A new ID prevents a stale confirmation from approving the survivor.
func (m *Manager) reconcileLocked(a *transitions) {
	if m.closed {
		return
	}
	origins := make(map[flightKey]*waiter)
	for w := range m.waiters {
		if w.flight != nil {
			continue
		}
		if origin := origins[w.key]; origin == nil || w.sequence < origin.sequence {
			origins[w.key] = w
		}
	}
	for key, origin := range origins {
		// Invalidated prompts retain their reservations through worker exit. A
		// surviving group cannot create unbounded replacement cleanup work.
		if m.workerCount >= MaxPending {
			for w := range m.waiters {
				if w.key == key {
					m.finishLocked(w, result{Deny, ErrOverloaded}, a)
				}
			}
			continue
		}
		m.sequence++
		ctx, cancel := context.WithCancel(origin.ctx)
		f := &flight{key: key, origin: origin, waiters: make(map[*waiter]struct{}), ctx: ctx, cancel: cancel,
			prompt: Prompt{ID: strconv.FormatUint(m.sequence, 10), Operation: origin.operation, Client: origin.client, Subjects: append([]string(nil), origin.subjects...), Deadline: origin.deadline}}
		m.flights[key] = f
		for w := range m.waiters {
			if w.key == key {
				w.flight = f
				w.requestID = f.prompt.ID
				f.waiters[w] = struct{}{}
			}
		}
		m.workerCount++
		m.workers.Add(1)
		a.start = append(a.start, f)
	}
}

func normalizeError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{ErrUnavailable, ErrDenied, ErrTimeout, ErrCanceled, ErrOverloaded, ErrSubjectTooLarge, ErrStale} {
		if errors.Is(err, known) {
			return err
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrTimeout, err)
	}
	if errors.Is(err, context.Canceled) {
		return errors.Join(ErrCanceled, err)
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

func (m *Manager) review(f *flight) {
	// Release the reservation last, after prompt cleanup, result delivery and
	// any stale-answer logging, rather than when its flight is invalidated.
	defer func() {
		m.mu.Lock()
		m.workerCount--
		m.mu.Unlock()
		m.workers.Done()
	}()
	decision, err := m.prompter.Prompt(f.ctx, f.prompt)
	err = normalizeError(err)
	var a transitions
	m.mu.Lock()
	m.expireLocked(&a)
	// Recheck the origin at the approval linearization point: cancellation
	// can occur while other waiters are being expired above.
	if m.flights[f.key] != f || f.origin.finished || contextError(f.origin.ctx, f.origin.deadline, time.Now()) != nil {
		m.expireLocked(&a)
		m.reconcileLocked(&a)
		m.mu.Unlock()
		a.run(m)
		m.log(f.prompt.Operation, f.prompt.Client, f.origin.subjects, f.prompt.ID, Deny, ErrStale)
		return
	}
	if err != nil {
		decision = Deny
	}
	if decision != Deny && decision != AllowConnection && decision != AllowGuest {
		decision, err = Deny, fmt.Errorf("%w: invalid decision %d", ErrDenied, decision)
	}
	if decision == Deny && err == nil {
		err = ErrDenied
	}
	// An unknown identity may never acquire authority beyond this connection.
	if decision == AllowGuest && f.origin.client.Fingerprint == "" {
		decision = AllowConnection
	}
	switch decision {
	case AllowGuest:
		m.guests[f.key.guestGrant] = struct{}{}
		for w := range m.waiters {
			if w.key.guestGrant == f.key.guestGrant {
				m.finishLocked(w, result{AllowGuest, nil}, &a)
			}
		}
	case AllowConnection:
		connection := f.origin.client.ConnectionID
		m.grants[connectionGrant{connection, f.key.capability, f.key.tuple}] = struct{}{}
		for w := range m.waiters {
			if w.key == f.key && w.client.ConnectionID == connection {
				m.finishLocked(w, result{AllowConnection, nil}, &a)
			}
		}
	default:
		for w := range m.waiters {
			if w.key == f.key {
				m.finishLocked(w, result{Deny, err}, &a)
			}
		}
	}
	m.reconcileLocked(&a)
	m.mu.Unlock()
	a.run(m)
}

// ClearConnection cancels only this connection's waiters and plain grants.
// Guest-wide grants intentionally survive connection teardown.
func (m *Manager) ClearConnection(connection string) {
	var a transitions
	m.mu.Lock()
	m.expireLocked(&a)
	for grant := range m.grants {
		if grant.connection == connection {
			delete(m.grants, grant)
		}
	}
	for w := range m.waiters {
		if w.client.ConnectionID == connection {
			m.finishLocked(w, result{Deny, ErrCanceled}, &a)
		}
	}
	m.reconcileLocked(&a)
	m.mu.Unlock()
	a.run(m)
}

// Close denies pending and future checks, drops all grants and joins prompt
// workers. Prompters must honor cancellation so those workers can terminate.
func (m *Manager) Close() {
	var a transitions
	m.mu.Lock()
	m.closed = true
	clear(m.grants)
	clear(m.guests)
	for w := range m.waiters {
		m.finishLocked(w, result{Deny, ErrUnavailable}, &a)
	}
	m.mu.Unlock()
	a.run(m)
	m.workers.Wait()
}

func (m *Manager) log(op Operation, client ClientInfo, subjects []string, id string, decision Decision, err error) {
	outcome := "denied"
	if err != nil {
		switch {
		case errors.Is(err, ErrUnavailable):
			outcome = "unavailable"
		case errors.Is(err, ErrDenied):
			outcome = "denied"
		case errors.Is(err, ErrTimeout):
			outcome = "timeout"
		case errors.Is(err, ErrCanceled):
			outcome = "canceled"
		case errors.Is(err, ErrOverloaded):
			outcome = "overloaded"
		case errors.Is(err, ErrSubjectTooLarge):
			outcome = "subject_too_large"
		case errors.Is(err, ErrStale):
			outcome = "stale"
		}
	} else if decision == AllowGuest {
		outcome = "allow_guest"
	} else if decision == AllowConnection {
		outcome = "allow_connection"
	}
	m.logger.Info("consent decision", "outcome", outcome, "capability", op.Capability(), "operation", op,
		"subjects", subjects, "fingerprint", client.Fingerprint, "connection_id", client.ConnectionID, "request_id", id, "error", err)
}
