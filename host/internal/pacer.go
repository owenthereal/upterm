package internal

import (
	"context"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	uio "github.com/owenthereal/upterm/io"
)

// The pacing guest's low mark and its stall bound; vars so a test can shorten
// the bound.
var (
	// pacingLowWater keeps the pacer's host-side queue to about one drain
	// chunk plus one pty write, so how far the command runs ahead of the
	// guest is set by the SSH windows between them, as it is over plain ssh.
	pacingLowWater = 64 << 10
	// pacingStallTimeout is the primary's bound, measured from the last piece
	// the pacer delivered rather than from when a write began to wait: a
	// pacer working steadily through a large backlog is never dropped for how
	// long the backlog takes, only for delivering nothing.
	pacingStallTimeout = 5 * time.Second
)

// pacedSink is what the pacer needs of a guest's sink. *uio.AsyncWriter is
// the one production uses.
type pacedSink interface {
	Backlog() uio.Backlog
	AbortIfNoProgress(since uint64, err error) bool
}

// guestPacer paces the command by a guest when the session has no primary.
//
// A primary host client paces the command by being written synchronously
// inside the fan-out. Without one, nothing does: every guest is a bounded
// AsyncWriter, so the copy reads the pty as fast as the kernel hands it over,
// and any guest slower than that — every remote guest of a detached session —
// is dropped by the first burst larger than its slack. Over plain ssh the
// same burst takes as long as the link needs and disconnects nobody.
//
// The earliest registered guest that is still live paces; the others follow.
// A later guest faster than the pacer is held to its rate, and one slower
// overflows and is dropped, as a guest slower than a primary is. Not the
// fastest guest: host-side backlog is all there is to judge by, and a
// newcomer starts with megabytes of fresh SSH window across the two legs, so
// even one that never reads looks fastest for long enough to overflow the
// guest it displaced. Earliest protects whoever is already watching from
// whoever joins next.
//
// It stands in front of MultiWriter.Write, so a write waits here, outside
// writeMu: an attach or a detach never queues behind a slow guest, as it does
// behind a parked primary.
type guestPacer struct {
	w   io.Writer
	ctx context.Context

	// attachMu makes a guest's registration and its Append one transaction,
	// serialised across guests; see attach. Nothing on the write path takes
	// it, so pacing never waits on a join.
	attachMu sync.Mutex

	mu       sync.Mutex
	guests   []pacedSink // registration order
	primary  bool
	released bool
	// changed is closed and replaced whenever any of the above changes, which
	// is how a held write hears of it without polling.
	changed chan struct{}

	// waiting counts the writes held right now and holds every write ever
	// held, so a test can observe backpressure rather than sleep on it.
	waiting atomic.Int32
	holds   atomic.Int64
}

// newGuestPacer returns a pacer writing to w. Pacing stops for good once ctx
// ends: a session being stopped must not wait on a slow guest.
func newGuestPacer(ctx context.Context, w io.Writer) *guestPacer {
	return &guestPacer{w: w, ctx: ctx, changed: make(chan struct{})}
}

// Write waits until the pacing guest's backlog is below the low mark, then
// writes b through.
func (p *guestPacer) Write(b []byte) (int, error) {
	p.wait()
	return p.w.Write(b)
}

// attach registers s, then runs appendFn, which attaches s to the fan-out,
// and unregisters s if that fails.
//
// Registering first is what bounds a new guest's exposure. Append publishes
// the sink to the fan-out before it returns, so registering afterwards would
// leave a window, as long as the handler is descheduled, in which a session
// with no other guest writes to it unpaced. Registered first, the only write
// that can reach it unseen is one that had passed the gate already: one pty
// write. A first guest registered but not yet appended is the pacer with an
// empty queue, so a write can pass on its behalf; it either goes out ahead of
// Append, and so into the replay, or waits on writeMu, which Append holds,
// and lands after it.
//
// attachMu is what keeps that true when guests join together. Without it, a
// guest registered but descheduled before its Append would be the pacer with
// an empty queue, holding the gate open while a later guest attached and took
// output unpaced until it overflowed. With it, registration order is
// attachment order, and no guest attaches ahead of an earlier registered one.
func (p *guestPacer) attach(s pacedSink, appendFn func() error) error {
	p.attachMu.Lock()
	defer p.attachMu.Unlock()
	p.mu.Lock()
	p.guests = append(p.guests, s)
	p.changedLocked()
	p.mu.Unlock()
	if err := appendFn(); err != nil {
		p.remove(s)
		return err
	}
	return nil
}

// remove unregisters s. A sink not registered, or already removed, changes
// nothing, so this is safe on every way out.
func (p *guestPacer) remove(s pacedSink) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if i := slices.Index(p.guests, s); i >= 0 {
		p.guests = slices.Delete(p.guests, i, i+1)
		p.changedLocked()
	}
}

// setPrimary records whether the session has a primary, which paces the
// command itself; with one, writes pass straight through. It never blocks,
// so it can be called under the host clients' own lock, which is what keeps
// reports in the order the primary changed.
func (p *guestPacer) setPrimary(primary bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.primary != primary {
		p.primary = primary
		p.changedLocked()
	}
}

// release turns pacing off for good. The command's exit calls it before it
// waits for output to go quiet, so a held write cannot pass for idleness and
// a slow guest cannot hold the host's exit open.
func (p *guestPacer) release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.released {
		p.released = true
		p.changedLocked()
	}
}

// changedLocked wakes every held write to look again. Callers must hold p.mu.
func (p *guestPacer) changedLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

// current returns the pacing guest and its backlog, or nil when writes pass
// through, with the signal for the next change to any of it.
func (p *guestPacer) current() (pacedSink, uio.Backlog, <-chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.primary || p.released || p.ctx.Err() != nil {
		return nil, uio.Backlog{}, p.changed
	}
	for _, g := range p.guests {
		if b := g.Backlog(); b.Live {
			return g, b, p.changed
		}
	}
	return nil, uio.Backlog{}, p.changed
}

// wait returns once the write may go: the pacing guest's backlog is below the
// low mark, or nothing paces.
//
// The deadline is armed against one sink and the Delivered it last showed,
// and armed afresh whenever either changes, so it measures time without
// progress rather than time spent waiting. When it expires, the pacing guest
// alone is aborted, and the next-earliest paces from whatever backlog it has.
// A follower that stalls is never judged here: it overflows and is dropped by
// its own sink, without freezing anyone.
//
// Reset needs no drain of the timer's channel: since Go 1.23 a stopped or
// reset timer never delivers a stale expiry.
func (p *guestPacer) wait() {
	var (
		timer   *time.Timer
		armed   pacedSink
		since   uint64
		counted bool
	)
	defer func() {
		if timer != nil {
			timer.Stop()
		}
		if counted {
			p.waiting.Add(-1)
		}
	}()
	for {
		s, b, changed := p.current()
		if s == nil || b.Bytes < pacingLowWater {
			return
		}
		if !counted {
			counted = true
			p.waiting.Add(1)
			p.holds.Add(1)
		}
		if s != armed || b.Delivered != since {
			armed, since = s, b.Delivered
			if timer == nil {
				timer = time.NewTimer(pacingStallTimeout)
			} else {
				timer.Reset(pacingStallTimeout)
			}
		}
		select {
		case <-b.Progress:
		case <-changed:
		case <-p.ctx.Done():
			return
		case <-timer.C:
			armed = nil // whatever follows, the deadline is armed afresh
			// The deadline and a delivered piece can be ready together, and a
			// primary can have arrived: look again before acting...
			if s2, b2, _ := p.current(); s2 != s || b2.Delivered != since || b2.Bytes < pacingLowWater {
				continue
			}
			// ...and decide against the recorded count under the sink's own
			// lock, so a piece delivered after that look still wins.
			s.AbortIfNoProgress(since, uio.ErrStalled)
		}
	}
}
