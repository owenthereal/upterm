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
	// pacingStallTimeout is the primary's bound. Its deadline is armed when
	// a write starts waiting and restarted by every piece the pacer delivers,
	// so it bounds time without progress, not time spent waiting: a pacer
	// working steadily through a large backlog is never dropped for how long
	// the backlog takes, only for delivering nothing.
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
// While the pacing guest is still being attached, the command waits for it as
// it does for a backlog: the join may be reconstructing its screen, and has to
// catch up on whatever the command writes meanwhile before it can hand over.
// A command that outran the reconstruction would leave the join no handoff it
// could reach in time, or evict from the ring the output the handoff needs,
// and the guest would be handed the raw ring instead. A follower being
// attached holds nothing.
//
// It stands in front of MultiWriter.Write, so a write waits here, outside
// writeMu: an attach or a detach never queues behind a slow guest, as it does
// behind a parked primary.
type guestPacer struct {
	w   io.Writer
	ctx context.Context

	// attachSlot makes a guest's registration and its Append one transaction,
	// serialised across guests; see attach. A one-slot channel rather than a
	// mutex, so that a guest waiting its turn stops waiting when it leaves:
	// the Append can be a join reconstructing the screen, which holds the
	// slot for as long as its budget allows. Nothing on the write path takes
	// it: a write waits on a join only through pending, and only on the
	// pacing guest's own.
	attachSlot chan struct{}

	mu     sync.Mutex
	guests []pacedSink // registration order
	// pending is the guest whose attach is running: registered, and not yet
	// handed its replay. attachSlot keeps it to one.
	pending  pacedSink
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
	return &guestPacer{w: w, ctx: ctx, attachSlot: make(chan struct{}, 1), changed: make(chan struct{})}
}

// Write waits until the pacing guest's backlog is below the low mark, then
// writes b through.
func (p *guestPacer) Write(b []byte) (int, error) {
	p.wait()
	return p.w.Write(b)
}

// attach registers s, then runs appendFn, which attaches s to the fan-out,
// and unregisters s if that fails. It waits its turn on ctx, the joiner's:
// a guest that leaves while another attaches is refused with ctx's error,
// registered nowhere, and its sink is the caller's to release.
//
// Registering first is what bounds a new guest's exposure. Append publishes
// the sink to the fan-out before it returns, so registering afterwards would
// leave a window, as long as the handler is descheduled, in which a session
// with no other guest writes to it unpaced. Registered first, the only write
// that can reach it unseen is one that had passed the gate already: one pty
// write, which either goes out ahead of Append, and so into the replay, or
// waits on writeMu, which Append holds, and lands after it.
//
// While appendFn runs, s is pending, and a pending guest that paces holds
// every write although its queue is empty: appendFn may be reconstructing
// its screen, which has to catch up on whatever the command writes meanwhile.
// However appendFn ends, attached, refused, failed or panicking, s stops
// being pending, which wakes every held write to look again; it stays
// registered only if attached.
//
// That hold can't deadlock the join it waits for, since nothing appendFn
// waits on needs the command to write. The join's capture and its handoff
// take writeMu, which a held write doesn't hold. Its emulation waits its turn
// behind other joins' emulations, each bounded by that join's deadline. Its
// handoff waits for a resize's outcome, which the pty reports as its ioctl
// returns, writing nothing. Only a resize inside a sequence or a character
// the ring ends in the middle of has the handoff wait for more output, and
// that join falls back to the raw ring at its deadline. So the hold lasts
// until the join attaches or falls back, at the latest its deadline.
//
// attachSlot keeps attaches one at a time, so that one guest at most is
// pending, and registration order is attachment order: no guest attaches
// ahead of one registered before it.
func (p *guestPacer) attach(ctx context.Context, s pacedSink, appendFn func() error) error {
	// Asked first: with the slot free, the select below would pick between
	// the two at random, and attach a guest that has already left.
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case p.attachSlot <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-p.attachSlot }()
	p.mu.Lock()
	p.guests = append(p.guests, s)
	p.pending = s
	p.changedLocked()
	p.mu.Unlock()
	attached := false
	// Deferred, so that a panic in appendFn ends the hold too.
	defer func() { p.settle(s, attached) }()
	if err := appendFn(); err != nil {
		return err
	}
	attached = true
	return nil
}

// settle ends s's attach: s is no longer pending, and unless it was attached
// it is unregistered as well.
func (p *guestPacer) settle(s pacedSink, attached bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending = nil
	if i := slices.Index(p.guests, s); i >= 0 && !attached {
		p.guests = slices.Delete(p.guests, i, i+1)
	}
	p.changedLocked()
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

// current returns the pacing guest, its backlog and whether it is pending, or
// nil when writes pass through, with the signal for the next change to any of
// it.
func (p *guestPacer) current() (pacedSink, uio.Backlog, bool, <-chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.primary || p.released || p.ctx.Err() != nil {
		return nil, uio.Backlog{}, false, p.changed
	}
	for _, g := range p.guests {
		if b := g.Backlog(); b.Live {
			return g, b, g == p.pending, p.changed
		}
	}
	return nil, uio.Backlog{}, false, p.changed
}

// wait returns once the write may go: the pacing guest's backlog is below the
// low mark and it isn't pending, or nothing paces.
//
// A pending pacer is waited for without a deadline. The deadline judges a
// guest by what it delivers, and one still being attached has been handed
// nothing to deliver; its attach ends by the join's deadline, and the hold
// with it.
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
		s, b, pending, changed := p.current()
		if s == nil || (!pending && b.Bytes < pacingLowWater) {
			return
		}
		if !counted {
			counted = true
			p.waiting.Add(1)
			p.holds.Add(1)
		}
		if pending {
			if timer != nil {
				timer.Stop()
			}
			armed = nil // armed afresh once the guest is attached
			select {
			case <-b.Progress: // the sink failing or closing ends its turn
			case <-changed:
			case <-p.ctx.Done():
				return
			}
			continue
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
			if s2, b2, _, _ := p.current(); s2 != s || b2.Delivered != since || b2.Bytes < pacingLowWater {
				continue
			}
			// ...and decide against the recorded count under the sink's own
			// lock, so a piece delivered after that look still wins.
			s.AbortIfNoProgress(since, uio.ErrStalled)
		}
	}
}
