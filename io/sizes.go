package io

import (
	"errors"
	"slices"
	"sync"

	"github.com/owenthereal/upterm/internal/termsize"
)

// ErrReplayCoverage is why a join can't emulate the ring: the size log can't
// name the size some of its bytes were written at, and no size is ever
// assumed.
var ErrReplayCoverage = errors.New("multiwriter: the ring's sizes aren't all known")

const (
	// sizeQueueMax bounds the resizes reported between two holds of writeMu.
	// A Write, a capture or a release drains them, so only a pty that is
	// resized 64 times while nothing is written reaches it.
	sizeQueueMax = 64

	// sizeLogMax bounds the events the log keeps. It keeps the one in effect
	// at the ring's start and every one after, so this is reached only by
	// 1,024 resizes within one ring of output.
	sizeLogMax = 1024
)

// SizeEvent is a resize of the pty, placed in the stream.
type SizeEvent struct {
	Seq    uint64 // ordinal: several events can share an offset
	Offset uint64 // applies before the byte at Offset
	Size   termsize.Size
}

// sizeLog records which size the pty was at for each byte of the ring, so
// that a joiner's emulation of the ring can be resized where the terminal
// was, and knows which of the ring's bytes it can vouch for.
//
// It is in two halves, under two locks, because its two writers can't share
// one. The pty reports a resize from Setsize, under terminalWindows' lock or
// sharedPTY.mu, neither of which may wait on the fan-out: writeMu is held for
// as long as a synchronous primary writer takes, which for a stopped terminal
// is indefinitely. So a report only queues, under mu, which nothing holds
// across anything else. The log is the fan-out's, guarded by writeMu, and
// apply moves the queue into it at the start of every hold that reads it.
//
// A report is two steps, ResizeBegin before the ioctl and ResizeEnd after it,
// because the command can repaint before the ioctl returns, and that repaint
// must already count at the new size. So the event is placed, tentatively, by
// the first apply after it begins, and is only committed, or deleted, by its
// outcome. A failed ioctl sends no SIGWINCH and changes no layout, so a
// deleted event leaves the bytes stamped after it to the event before, as
// they were.
type sizeLog struct {
	// mu guards the report side, down to pin: what ResizeBegin, ResizeEnd and
	// Pinned record, and apply drains.
	mu      sync.Mutex
	lastSeq uint64          // the last Seq handed out; the first is 1
	queue   []queuedSize    // reported, not yet in the log, in Seq order
	ended   map[uint64]bool // outcomes not yet applied, by Seq: applied or not
	// open holds every event still waiting for its outcome, each with the
	// channel wait hands out, closed when the outcome is recorded.
	open map[uint64]chan struct{}
	// dropped counts the reports the queue had no room for since the last
	// apply, the first of which was droppedSeq. Every report after the
	// first is dropped too, until apply empties the queue.
	dropped, droppedSeq uint64
	pin                 bool

	// The log, guarded by the fan-out's writeMu.
	events []loggedSize // in Seq order, which is offset order
	loss   uint64       // the newest loss's Seq, while a known size hasn't closed it; see lose
	lost   uint64       // every report or event ever lost; see losses
	heard  uint64       // the last event the fan-out's tracker has heard; see hear
}

type queuedSize struct {
	SizeEvent
	stamped bool // Offset is set already; only Pinned's is
}

type loggedSize struct {
	SizeEvent
	tentative bool // logged before its outcome, which apply hasn't had yet
}

// closedWait is what wait hands out for an event with no outcome to wait for.
var closedWait = func() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}()

// ResizeBegin records a tentative resize to size, before the pty's ioctl.
// It never waits on writeMu. It returns the event's Seq.
//
// It returns 0 once the pty is Pinned, and a Seq that ResizeEnd ignores when
// the queue had no room for the report, which then counts as a loss.
func (t *MultiWriter) ResizeBegin(size termsize.Size) uint64 {
	l := &t.sizes
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pin {
		return 0
	}
	return l.report(size)
}

// ResizeEnd records the outcome: applied commits the event, !applied
// deletes it. It never waits on writeMu.
//
// The outcome reaches the log at the next hold of writeMu, which every
// capture and release begins by applying. Until then the event stays
// tentative, which is what keeps a capture from using it either way.
func (t *MultiWriter) ResizeEnd(seq uint64, applied bool) {
	l := &t.sizes
	l.mu.Lock()
	defer l.mu.Unlock()

	done, ok := l.open[seq]
	if !ok {
		// 0 from a pinned pty, a report the log lost, or a second outcome.
		return
	}
	delete(l.open, seq)
	close(done)
	if l.ended == nil {
		l.ended = make(map[uint64]bool)
	}
	l.ended[seq] = applied
}

// Pinned records that the pty keeps size for good. Called once, at start,
// instead of any resize report.
//
// Its event is placed at offset 0, before any byte, rather than wherever the
// next apply happens to find the ring. A second call changes nothing.
func (t *MultiWriter) Pinned(size termsize.Size) {
	l := &t.sizes
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pin {
		return
	}
	l.pin = true

	// Queued past the bound, which is for a resize storm: this is a pinned
	// pty's only report, and losing it would leave its every byte at an
	// unknown size for good.
	l.lastSeq++
	l.queue = append(l.queue, queuedSize{SizeEvent: SizeEvent{Seq: l.lastSeq, Offset: 0, Size: size}, stamped: true})
	if l.ended == nil {
		l.ended = make(map[uint64]bool)
	}
	l.ended[l.lastSeq] = true
}

// applyResize brings the size log up to date with what was reported since
// the last hold of writeMu, placing new events before the next byte the ring
// takes, and has the tracker hear every event in effect at the ring's start.
// Called with writeMu held, at the start of every capture and release, so
// each sees the pty's size as of the hold. Write does the same in two halves,
// around the ring's eviction; see bound.
func (t *MultiWriter) applyResize() {
	t.sizes.apply(t.buffer.End(), t.modes)
	// Eviction hears each event as the ring's start reaches it, but an event
	// placed while the ring was empty is at its start already, and a capture
	// clones the tracker as of there.
	t.sizes.hear(t.modes, t.buffer.Start(), nil)
	t.sizes.bound()
}

// report queues a tentative resize to size under the next Seq, or drops it
// when the queue is full. Called with mu held.
func (l *sizeLog) report(size termsize.Size) uint64 {
	l.lastSeq++
	seq := l.lastSeq
	if len(l.queue) == sizeQueueMax {
		if l.dropped == 0 {
			l.droppedSeq = seq
		}
		l.dropped++
		return seq
	}

	l.queue = append(l.queue, queuedSize{SizeEvent: SizeEvent{Seq: seq, Size: size}})
	if l.open == nil {
		l.open = make(map[uint64]chan struct{})
	}
	l.open[seq] = make(chan struct{})
	return seq
}

// wait returns a channel closed once ResizeEnd records seq's outcome, either
// way. It is closed already when there is none to wait for: seq is decided,
// was lost, or is 0. Waiting needs no lock but this one, so a join can wait
// outside writeMu.
func (l *sizeLog) wait(seq uint64) <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	if done, ok := l.open[seq]; ok {
		return done
	}
	return closedWait
}

// apply moves the queued reports into the log, stamping each not yet stamped
// at end, and applies the outcomes recorded since the last apply: a committed
// event becomes one, and a deleted one goes, wherever it is. Events keep
// their Seq order, and none is coalesced: 80 → 45 → 80 with no output between
// truncates the screen at 45, which 80 alone doesn't.
//
// An event the tracker m has already heard, eviction having crossed it before
// its outcome, has its outcome passed on, to select among the candidates m
// kept for it (spec A22). Called with writeMu held.
func (l *sizeLog) apply(end uint64, m *ModeTracker) {
	l.mu.Lock()
	queue, ended := l.queue, l.ended
	dropped, droppedSeq := l.dropped, l.droppedSeq
	if len(queue) == 0 && len(ended) == 0 && dropped == 0 {
		l.mu.Unlock()
		return
	}
	// Replaced, not reused: what was drained is read below, outside mu,
	// while ResizeBegin and ResizeEnd may record again.
	l.queue, l.ended, l.dropped, l.droppedSeq = nil, nil, 0, 0
	l.mu.Unlock()

	// Outcomes first, so that a deleted event frees its room before the
	// queue needs it.
	if len(ended) > 0 {
		kept := l.events[:0]
		for _, e := range l.events {
			if applied, ok := ended[e.Seq]; ok && e.tentative {
				if e.Seq <= l.heard {
					m.resolve(e.Seq, applied)
				}
				if !applied {
					continue
				}
				e.tentative = false
			}
			kept = append(kept, e)
		}
		l.events = kept
	}
	for _, q := range queue {
		applied, decided := ended[q.Seq]
		if decided && !applied {
			continue
		}
		if !q.stamped {
			q.Offset = end
		}
		l.events = append(l.events, loggedSize{SizeEvent: q.SizeEvent, tentative: !decided})
	}
	if dropped > 0 {
		// The reports dropped would have been placed here, after everything
		// the queue held.
		l.lose(dropped, droppedSeq)
	}
}

// bound drops events past the log's bound: the oldest committed event goes,
// while tentative ones are kept for their outcome, which a capture waits on.
// Only 1,024 resizes begun and never ended leave none committed, and then the
// oldest goes anyway, so the log stays bounded whatever the pty does.
//
// A Write calls it after prune, not with apply: an event its own eviction lets
// prune forget is superseded, not lost, and counted lost it would fail every
// join that captured before it. Called with writeMu held.
func (l *sizeLog) bound() {
	var gone []uint64
	for len(l.events) > sizeLogMax {
		i := slices.IndexFunc(l.events, func(e loggedSize) bool { return !e.tentative })
		i = max(i, 0)
		e := l.events[i]
		l.events = slices.Delete(l.events, i, i+1)
		l.lose(1, e.Seq)
		if e.tentative {
			gone = append(gone, e.Seq)
		}
	}
	if len(gone) > 0 {
		// Nobody is left to apply their outcomes, so whoever waits on them
		// wakes now, to find the loss.
		l.mu.Lock()
		for _, seq := range gone {
			if done, ok := l.open[seq]; ok {
				delete(l.open, seq)
				close(done)
			}
		}
		l.mu.Unlock()
	}
}

// lose counts n reports or events lost and records where, by Seq: the first
// report dropped, or the event dropped. The size from there on, between the
// events before seq and those after it, is unknown until a committed, valid
// event after it closes the loss. Only the newest loss is kept: the event that
// closes it closes every older one too, and any start an older loss fails
// coverage for, the newest fails as well. A loss of 0 is none. Called with
// writeMu held.
func (l *sizeLog) lose(n, seq uint64) {
	l.lost += n
	if seq > l.loss {
		l.loss = seq
	}
}

// hear feeds m the bytes p, which begin at stream offset offset, with each
// logged event at or before their end that m hasn't heard yet placed where it
// falls among them, in Seq order (spec E3): a committed one through
// resizeHeard, which skips one of the size the terminal already has, and a
// tentative one through crossTentative, its outcome to follow through apply.
// One exactly at their end is heard too, since it is in effect at the byte
// after them, the ring's first once they have left. A deleted event is no
// longer logged, so it is never heard.
//
// The log's own entry says whether an event is tentative: it is exactly while
// apply hasn't applied an outcome to it, and an outcome ResizeEnd records
// later reaches m through apply, like any other. Called with writeMu held.
func (l *sizeLog) hear(m *ModeTracker, offset uint64, p []byte) {
	end := offset + uint64(len(p))
	for _, e := range l.events {
		if e.Seq <= l.heard {
			continue
		}
		if e.Offset > end {
			break
		}
		if e.Offset > offset {
			n := e.Offset - offset
			_, _ = m.Write(p[:n])
			p, offset = p[n:], e.Offset
		}
		if e.tentative {
			m.crossTentative(e.Seq, e.Size)
		} else {
			m.resizeHeard(e.Size)
		}
		l.heard = e.Seq
	}
	_, _ = m.Write(p)
}

// covering returns the committed event in effect at start, the last with
// Offset <= start, and every committed event after it, in Seq order: every
// size the ring was written at, from start on. It fails with
// ErrReplayCoverage when one of those sizes is unknown:
//   - there is no event in effect at start;
//   - a loss lies after it, so a size from there on is missing;
//   - an event from it on has an invalid size, which no reconstruction fits;
//   - a tentative event lies at or before start, since its outcome decides
//     the size the emulation starts at.
//
// A tentative event after start is no failure and isn't returned: a capture
// stops short of it. The events are a copy. Called with writeMu held.
func (l *sizeLog) covering(start uint64) ([]SizeEvent, error) {
	from := -1
	for i, e := range l.events {
		if e.Offset > start {
			break
		}
		if e.tentative {
			return nil, ErrReplayCoverage
		}
		from = i
	}
	if from < 0 || l.loss > l.events[from].Seq {
		return nil, ErrReplayCoverage
	}

	var events []SizeEvent
	for _, e := range l.events[from:] {
		if e.tentative {
			continue
		}
		if !e.Size.Valid() {
			return nil, ErrReplayCoverage
		}
		events = append(events, e.SizeEvent)
	}
	return events, nil
}

// after returns the committed events after seq, in Seq order, as a copy.
// Unknown ones are included: whoever offers them decides what one means.
// Called with writeMu held.
func (l *sizeLog) after(seq uint64) []SizeEvent {
	var events []SizeEvent
	for _, e := range l.events {
		if !e.tentative && e.Seq > seq {
			events = append(events, e.SizeEvent)
		}
	}
	return events
}

// firstUnresolved returns the oldest logged event still waiting for its
// outcome. Called with writeMu held.
func (l *sizeLog) firstUnresolved() (offset uint64, seq uint64, ok bool) {
	for _, e := range l.events {
		if e.tentative {
			return e.Offset, e.Seq, true
		}
	}
	return 0, 0, false
}

// prune forgets what the ring no longer needs, now that it starts at start.
// A committed event is forgotten once a later committed event at or before
// start supersedes it.
//
// A loss is an open interval of unknown size, which only a later committed,
// valid event closes. So it is forgotten only once that event is at or before
// start, however far the ring has evicted past the loss itself: forgotten
// sooner, it would let covering pick the size logged before it, which the pty
// had left.
//
// Tentative events are never pruned: their outcome is still to come. Called
// with writeMu held, after the ring is fed.
func (l *sizeLog) prune(start uint64) {
	if l.loss != 0 {
		for _, e := range l.events {
			if e.Seq > l.loss && !e.tentative && e.Size.Valid() {
				if e.Offset <= start {
					l.loss = 0
				}
				break
			}
		}
	}

	in := -1
	for i, e := range l.events {
		if e.Offset > start {
			break
		}
		if !e.tentative {
			in = i
		}
	}
	if in <= 0 {
		return
	}
	kept := l.events[:0]
	for i, e := range l.events {
		if i < in && !e.tentative {
			continue
		}
		kept = append(kept, e)
	}
	l.events = kept
}

// pinned reports whether the pty's size is pinned, and so never changes.
func (l *sizeLog) pinned() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pin
}

// losses counts every report or event the log has lost, to a full queue or a
// full log, ever. A capture records it; a change by a later handoff means
// coverage broke meanwhile, even if a known size has closed the loss since.
// Called with writeMu held.
func (l *sizeLog) losses() uint64 {
	return l.lost
}
