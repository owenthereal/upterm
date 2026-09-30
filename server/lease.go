package server

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// leaseTiming paces a lease keeper's retries, and bounds how long a capable
// registration's rebuild may take.
type leaseTiming struct {
	retryBase, retryMax time.Duration
	// rebuildBound is how long after a known loss a capable registration's
	// connection is closed if the lease hasn't been rebuilt, so that its host
	// redials rather than holding a session guests can't find.
	rebuildBound time.Duration
}

var defaultLeaseTiming = leaseTiming{time.Second, 10 * time.Second, 60 * time.Second}

// leaseMargin is how long before its lease could expire a capable
// registration's connection is closed when renewals keep failing. The close
// then comes before the entry can vanish, unless the keeper's timer runs more
// than the margin late, and the host redials while it still stands.
func leaseMargin(ttl time.Duration) time.Duration {
	return min(ttl/10, time.Minute)
}

// leaseKeeper keeps one adopted registration's entry alive for as long as its
// connection lives. It renews the lease at half its TTL, retrying failures,
// and rebuilds it under a new lease once the store says it's lost.
//
// A capable registration's host can redial, so when its lease can't be kept in
// time the keeper closes the connection and the host registers afresh: when
// renewals fail until the lease might expire, or a rebuild hasn't succeeded
// rebuildBound after the loss. Those deadlines are absolute, and no store call
// holds them up, whether or not it honours its context. A legacy host can't
// redial, so the keeper never closes its connection for the lease; its calls
// are retried for as long as the connection lives.
type leaseKeeper struct {
	sm        *SessionManager
	ttl       time.Duration
	timing    leaseTiming
	closeConn func()
	replace   func(next *Registration) bool // false: the registration has ended
	logger    *slog.Logger
}

// run keeps reg's lease until ctx ends, the registration is superseded, or a
// deadline closes its connection. Each rebuild hands it a new handle for reg.
func (k *leaseKeeper) run(ctx context.Context, reg *Registration) {
	confirmed := reg.ConfirmedAt
	for {
		if !sleep(ctx, time.Until(confirmed.Add(k.ttl/2))) {
			return
		}
		sent, lost, ok := k.renew(ctx, reg, confirmed)
		if !ok {
			return
		}
		if !lost {
			confirmed = sent
			continue
		}
		if reg, ok = k.rebuild(ctx, reg, time.Now()); !ok {
			return
		}
		confirmed = reg.ConfirmedAt
	}
}

// renew renews reg until a renewal succeeds, and returns that renewal's send
// time: the lease's TTL can't have restarted before it. lost: the store says
// reg no longer holds its entry. ok false: the keeper is done, because ctx
// ended, or because the expiry budget ran out and the connection is closed.
func (k *leaseKeeper) renew(ctx context.Context, reg *Registration, confirmed time.Time) (sent time.Time, lost, ok bool) {
	var deadline time.Time
	if reg.Capable() {
		deadline = confirmed.Add(k.ttl - leaseMargin(k.ttl))
	}
	bctx, cancel := withDeadline(ctx, deadline)
	defer cancel()

	for delay := k.timing.retryBase; ; delay = min(2*delay, k.timing.retryMax) {
		sent = time.Now()
		_, err := k.call(bctx, reg, func(ctx context.Context) (*Registration, error) {
			return nil, k.sm.Renew(ctx, reg)
		})
		if k.over(ctx, deadline, "the session lease's expiry budget ran out") {
			return sent, false, false
		}
		if err == nil {
			return sent, false, true
		}
		if errors.Is(err, ErrLeaseLost) {
			k.logger.Warn("session lease lost; rebuilding it", "error", err)
			return sent, true, true
		}
		k.logger.Warn("failed to renew the session lease", "error", err, "retry-in", delay)
		if !sleep(bctx, delay) {
			k.over(ctx, deadline, "the session lease's expiry budget ran out")
			return sent, false, false
		}
	}
}

// rebuild stores reg again under a new lease after a loss that became known
// at lostAt, retrying until it succeeds, and returns the new handle, which
// this node now serves in reg's place. false: the keeper is done.
func (k *leaseKeeper) rebuild(ctx context.Context, reg *Registration, lostAt time.Time) (*Registration, bool) {
	var deadline time.Time
	if reg.Capable() {
		deadline = lostAt.Add(k.timing.rebuildBound)
	}
	bctx, cancel := withDeadline(ctx, deadline)
	defer cancel()

	for delay := k.timing.retryBase; ; delay = min(2*delay, k.timing.retryMax) {
		next, err := k.call(bctx, reg, func(ctx context.Context) (*Registration, error) {
			return k.sm.Reregister(ctx, reg)
		})
		if k.over(ctx, deadline, "the lost session lease wasn't rebuilt in time") {
			// The deadline has closed the connection, or the registration has
			// ended: either way, a success arriving now is no one's.
			if next != nil {
				k.release(next)
			}
			return nil, false
		}
		switch {
		case err == nil:
			if !k.replace(next) {
				// The registration ended, or was replaced, while it was being
				// rebuilt.
				k.release(next)
				return nil, false
			}
			// The lost lease holds nothing now. In memory there is no lease,
			// and releasing reg would delete the entry just rebuilt.
			if reg.lease != "" && reg.lease != next.lease {
				k.release(reg)
			}
			k.logger.Info("rebuilt the lost session lease")
			return next, true
		case errors.Is(err, ErrSuperseded):
			k.logger.Warn("closing the host connection", "reason", "superseded while rebuilding its lost lease", "error", err)
			k.closeConn()
			return nil, false
		}
		k.logger.Warn("failed to rebuild the session lease", "error", err, "retry-in", delay)
		if !sleep(bctx, delay) {
			k.over(ctx, deadline, "the lost session lease wasn't rebuilt in time")
			return nil, false
		}
	}
}

// call makes one store call under ctx. A capable registration's call runs on
// a goroutine of its own, and call returns when ctx ends whether the call has
// or not: a deadline has to hold against a call that ignores its context, as a
// stuck HTTP request does, and against Register's own cleanup, which can
// outlast it. The abandoned call finishes in the background, and a
// registration it returns then is released. A legacy registration has no
// deadline to hold, so its calls are made inline.
func (k *leaseKeeper) call(ctx context.Context, reg *Registration, fn func(context.Context) (*Registration, error)) (*Registration, error) {
	if !reg.Capable() {
		return fn(ctx)
	}
	type result struct {
		reg *Registration
		err error
	}
	done := make(chan result, 1)
	go func() {
		next, err := fn(ctx)
		done <- result{next, err}
	}()
	select {
	case r := <-done:
		return r.reg, r.err
	case <-ctx.Done():
		go func() {
			if r := <-done; r.reg != nil {
				k.release(r.reg)
			}
		}()
		return nil, ctx.Err()
	}
}

// over reports whether the keeper is done: ctx ended, or the deadline, if
// there is one, has passed. At the deadline it closes the connection first,
// so the host redials.
func (k *leaseKeeper) over(ctx context.Context, deadline time.Time, why string) bool {
	if ctx.Err() != nil {
		return true
	}
	if deadline.IsZero() || time.Now().Before(deadline) {
		return false
	}
	k.logger.Warn("closing the host connection", "reason", why)
	k.closeConn()
	return true
}

// release gives up a handle the keeper won't keep. It runs on a fresh
// context, since the keeper's may be what ended, and for a capable
// registration in the background, so no deadline waits on it. The store only
// removes an entry the handle still holds.
func (k *leaseKeeper) release(reg *Registration) {
	release := func() {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultConsulTimeout)
		defer cancel()
		if err := k.sm.Release(ctx, reg); err != nil {
			k.logger.Warn("failed to release a session lease", "error", err)
		}
	}
	if reg.Capable() {
		go release()
		return
	}
	release()
}

// withDeadline bounds ctx by deadline; a zero deadline leaves it unbounded.
func withDeadline(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	if deadline.IsZero() {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, deadline)
}

// sleep waits for d, and reports false if ctx ends first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
