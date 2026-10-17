package io

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime/debug"
	"sync"
	"time"

	"github.com/owenthereal/upterm/internal/termsize"
)

// Replayer reconstructs the screen the ring's bytes drew, for a joining
// terminal, so the joiner is handed that screen rather than the raw ring.
// io has no emulator of its own; the host installs one with SetReplayer.
type Replayer interface {
	// Start emulates c for a joiner whose terminal is size. The Emulation it
	// returns stops, within the emulator's meter interval, once ctx is done
	// or the deadline passes, in Start and in every later call.
	Start(ctx context.Context, deadline time.Time, c *Capture, size termsize.Size) (Emulation, error)
}

// Emulation is one joiner's reconstruction, in progress.
type Emulation interface {
	// Feed continues the emulation over more of the stream: chunks run on
	// from the end of everything offered so far, and sizes are the committed
	// events after the last one offered.
	Feed(chunks [][]byte, sizes []SizeEvent) error
	// Handoff is the point the render reconstructs: the stream offset of the
	// end of what the emulator consumed, where both it and the tracker clone
	// are outside every sequence, and the Seq of the last event it has
	// passed, applied or skipped as the size it already had. Bytes offered
	// after offset were never consumed, nor the events among them.
	Handoff() (offset, lastSeq uint64)
	// Render is the reconstruction as of Handoff.
	Render() ([]byte, error)
}

// Capture is what a join takes of the fan-out, under one hold of writeMu, to
// emulate outside it.
type Capture struct {
	Modes      *ModeTracker // a clone: the state as of the ring's first byte
	Chunks     [][]byte     // the stream from Start to End, immutable once handed out
	Sizes      []SizeEvent  // the committed events covering Chunks, in Seq order, the first in effect at Start
	Start, End uint64       // stream offsets of Chunks
	Pinned     bool         // the pty keeps its size for good
}

// ReplayBudget is how long a join may spend reconstructing the screen before
// it falls back to the raw ring: the doors take a join's deadline this far
// from when it begins. A var for tests.
var ReplayBudget = time.Second

// ReplayPanic is a panic recovered from a Replayer, reported as an error.
type ReplayPanic struct {
	Value any
	Stack []byte
}

func (p *ReplayPanic) Error() string {
	return fmt.Sprintf("multiwriter: the replay panicked: %v", p.Value)
}

// Why a join that could have been emulated fell back to the raw ring, besides
// ErrReplayCoverage and whatever the replayer itself reports. ErrReplayDeadline
// is the emulation running out of time; a join that ran out of time waiting
// for something else reports it wrapped, with what it waited for.
var (
	ErrReplayGapEvicted       = errors.New("multiwriter: the output since the handoff was evicted")
	ErrReplayMarginsUncertain = errors.New("multiwriter: the tracker's margins are uncertain")
	ErrReplayDeadline         = errors.New("multiwriter: the replay ran out of time")
)

// What a join that ran out of time was waiting for, when it wasn't the
// emulation: an unresolved resize, which comes when the pty's ioctl returns;
// output that ends the character or the sequence an offered resize fell
// inside, which the emulation can't pass the resize before; or the permit,
// which another join's emulation holds.
var (
	errDeadlineAtAResize   = fmt.Errorf("%w waiting for a resize's outcome", ErrReplayDeadline)
	errDeadlineInASequence = fmt.Errorf("%w waiting for the rest of a character or a sequence a resize fell inside", ErrReplayDeadline)
	errDeadlineAtThePermit = fmt.Errorf("%w waiting for another join's emulation", ErrReplayDeadline)
)

// errRenderTooLong keeps one delivery bounded in io itself, whatever the
// replayer does: the render, at most DefaultReplayBytes, then the gap, at
// most the ring, then Pending, together well under DefaultGuestBufferSize.
var errRenderTooLong = errors.New("multiwriter: the render is longer than DefaultReplayBytes")

// errHandoffOutOfRange keeps every byte reaching the joiner once whatever the
// replayer reports: a handoff point past the end of what it was offered would
// leave the bytes before it in neither the render nor the gap, and a last
// event past the last offered would attach the joiner past a resize it was
// never fed.
var errHandoffOutOfRange = errors.New("multiwriter: the replay's handoff is past what it was offered")

// SetReplayer installs r, and fallback, which is told why each join that
// fell back did (never called with the fan-out's locks held). Once, before
// any join.
func (t *MultiWriter) SetReplayer(r Replayer, fallback func(error)) {
	t.replayer, t.fallback = r, fallback
}

// AppendSized attaches w, a joiner whose terminal is size, handing it a
// reconstruction of the screen the ring drew rather than the ring itself,
// once the deadline allows and a replayer is installed. A viewer keeps
// Append's raw ring, and so does a join with no replayer, no time, or nothing
// in the ring to reconstruct.
//
// The emulation runs outside every fan-out lock, so a Write never waits on
// it, and only the capture and the handoff hold writeMu. The capture takes
// the ring, a clone of the tracker and the sizes the ring was written at;
// while the emulation runs, the stream moves on. The handoff, under one hold
// of writeMu, then writes the render, the ring from the emulation's handoff
// point on, which it never consumed, and Pending, and attaches w: every byte
// written since the capture reaches w once. Until a hold finds the
// emulation has reached every resize logged, the join catches it up on what
// it missed, or waits outside the lock for what it is still missing.
//
// A join that can't be emulated, for any of the reasons fallback is told,
// is attached by Append's path instead, and AppendSized returns nil. It
// returns ErrClosed once Shutdown has run, and ctx's error once the joiner
// has left, and then attaches nothing: on every path, the raw ones included,
// the hold of writeMu that would attach w is the one that finds ctx done. The
// check waits for nothing, so a joiner with nothing to emulate is attached as
// promptly as Append would.
func (t *MultiWriter) AppendSized(ctx context.Context, deadline time.Time, size termsize.Size, w io.Writer) error {
	if err := checkRemovable(w); err != nil {
		return err
	}
	if !size.Valid() || t.replayer == nil || !time.Now().Before(deadline) {
		return t.appendRaw(ctx, w)
	}

	j := &join{t: t, ctx: ctx, deadline: deadline, size: size, w: w}
	c, done, err := j.capture()
	if done {
		return err
	}
	// One emulation at a time, the permit held from Start to the handoff's
	// outcome and released on every one, so a guest rejoining in a loop
	// costs the host one core, not one per join.
	switch err := t.acquire(ctx, deadline); {
	case errors.Is(err, ErrReplayDeadline):
		j.err = err
	case err != nil:
		return err
	default:
		defer t.release()
		j.start(c)
	}
	return j.handoff()
}

// join is one AppendSized past its fast paths.
type join struct {
	t        *MultiWriter
	ctx      context.Context
	deadline time.Time
	size     termsize.Size
	w        io.Writer

	// What the emulation has been offered: the stream up to offeredEnd, and
	// the events up to offeredSeq. losses is the size log's count at the
	// capture: a change means coverage broke since.
	offeredEnd, offeredSeq uint64
	losses                 uint64
	// heldBack is set while bytes the capture stopped short of, behind a resize
	// whose outcome wasn't known yet, have yet to be offered: the handoff
	// offers them once it is known, with the event if it committed and without
	// it if not.
	heldBack bool

	em  Emulation
	err error // why the replay failed, once it has
	// render is the render as of h and lastSeq, the emulation's handoff, or
	// nil while the emulation has yet to pass a resize it was offered.
	render []byte
	h      uint64
	// lastSeq is the last event the emulation has passed.
	lastSeq uint64
}

// capture takes what the emulation starts from, under one hold of writeMu.
// done is set when the join ended there instead: refused, or attached by
// Append's path, which an empty ring takes, and a ring that can't be
// emulated falls back to.
func (j *join) capture() (c *Capture, done bool, err error) {
	t := j.t
	var fellBack error
	defer func() { t.reportFallback(fellBack) }()
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	t.applyResize()
	if t.closed {
		return nil, true, ErrClosed
	}
	// A joiner that has left is attached by none of the paths below, raw or
	// emulated, and is no fallback to report.
	if err := j.ctx.Err(); err != nil {
		return nil, true, err
	}
	start, end := t.buffer.Start(), t.buffer.End()
	if start == end {
		// Nothing to reconstruct: Append's path, which is no fallback.
		return nil, true, t.attachRaw(j.w)
	}
	if t.modes.uncertain() {
		fellBack = ErrReplayMarginsUncertain
		return nil, true, t.attachRaw(j.w)
	}
	sizes, err := t.sizes.covering(start)
	if err != nil {
		fellBack = err
		return nil, true, t.attachRaw(j.w)
	}

	// Nothing past a resize whose outcome isn't known: the bytes after it were
	// laid out at a size the emulation can't know yet, and feeding the event
	// afterwards can't repair them. Nor any committed event after it by Seq,
	// even one at its offset: it takes effect after the unresolved resize, so
	// the emulation can't be given it before that one's outcome is known.
	e0, below := end, uint64(math.MaxUint64)
	if offset, seq, ok := t.sizes.firstUnresolved(); ok {
		e0, below = min(end, offset), seq
	}
	sizes = upTo(sizes, e0, below)
	chunks, _ := t.buffer.Range(start, e0)
	j.offeredEnd, j.offeredSeq = e0, sizes[len(sizes)-1].Seq
	j.losses = t.sizes.losses()
	j.heldBack = e0 < end
	return &Capture{
		Modes:  t.modes.Clone(),
		Chunks: chunks,
		Sizes:  sizes,
		Start:  start,
		End:    e0,
		Pinned: t.sizes.pinned(),
	}, false, nil
}

// start runs the emulation's Start, outside every lock, and renders it if it
// has passed every resize it was offered (see rerender).
func (j *join) start(c *Capture) {
	if !time.Now().Before(j.deadline) {
		// The permit came as the deadline passed.
		j.err = errDeadlineAtThePermit
		return
	}
	j.err = guard(func() (err error) {
		j.em, err = j.t.replayer.Start(j.ctx, j.deadline, c, j.size)
		return err
	})
	if j.err == nil {
		j.err = j.rerender()
	}
}

// feed offers the emulation more of the stream, outside every lock, and
// renders it again once it has passed every resize offered so far.
func (j *join) feed(chunks [][]byte, sizes []SizeEvent) {
	j.err = guard(func() error { return j.em.Feed(chunks, sizes) })
	if j.err == nil {
		j.err = j.rerender()
	}
}

// rerender reads the handoff point the emulation has reached, and renders
// it once the emulation has passed every resize it was offered. Until then
// the emulation is at a size older than the stream's, which the joiner, sized
// to the newest, may not hold: a resize inside a character or a sequence the
// stream so far ends in the middle of waits in the emulation's tail for the
// rest of it. So there is no render yet, and the handoff waits for the output
// that lets the emulation pass the resize, or falls back at the deadline.
func (j *join) rerender() error {
	return guard(func() error {
		h, lastSeq := j.em.Handoff()
		if h > j.offeredEnd || lastSeq > j.offeredSeq {
			return errHandoffOutOfRange
		}
		j.h, j.lastSeq = h, lastSeq
		if lastSeq < j.offeredSeq {
			// Nor is an older render kept: one as of an earlier point is
			// never to be handed over.
			j.render = nil
			return nil
		}
		render, err := j.em.Render()
		if err != nil {
			return err
		}
		if len(render) > DefaultReplayBytes {
			return errRenderTooLong
		}
		j.render = render
		return nil
	})
}

// guard runs f, a call into the replayer, and turns a panic in it into a
// *ReplayPanic. The replayer runs on bytes a guest can influence, and a panic
// left to unwind would take the host's whole process with it.
func guard(f func() error) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = &ReplayPanic{Value: v, Stack: debug.Stack()}
		}
	}()
	return f()
}

// handoff ends the join under one hold of writeMu: it attaches w with the
// render, falls back, or is refused. Between holds it catches the emulation
// up, or waits for what it is missing, outside every lock.
func (j *join) handoff() error {
	for {
		// Taken before the hold, so a Write or a ResizeEnd after it wakes the
		// wait for one even if it comes before the wait begins.
		changed := j.t.changed.wait()
		s := j.hold()
		switch {
		case s.done:
			return s.err
		case s.resolved != nil:
			j.wait(waitResize, s.resolved)
		case len(s.chunks) == 0 && len(s.sizes) == 0:
			// Nothing new to offer: what the emulation lacks to hand off,
			// the rest of a sequence or a resize, can only come with more
			// output or another resize.
			j.wait(waitOutput, changed)
		default:
			j.feed(s.chunks, s.sizes)
		}
	}
}

// step is what one hold of writeMu at the handoff decided.
type step struct {
	done     bool
	err      error           // what AppendSized returns, once done
	resolved <-chan struct{} // closed with an unresolved resize's outcome, to wait for
	chunks   [][]byte        // what to feed the emulation, if neither of those
	sizes    []SizeEvent
}

// hold is one hold of writeMu at the handoff: every resize reported before it
// is in the reconstruction, or the join waits for it or catches up on it, and
// every one after it reaches the joiner as a live resize.
func (j *join) hold() step {
	t := j.t
	var fellBack error
	defer func() { t.reportFallback(fellBack) }()
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	t.applyResize()
	if t.closed {
		return step{done: true, err: ErrClosed}
	}
	if err := j.ctx.Err(); err != nil {
		return step{done: true, err: err}
	}
	if fellBack = j.failed(); fellBack != nil {
		return step{done: true, err: t.attachRaw(j.w)}
	}
	if _, seq, ok := t.sizes.firstUnresolved(); ok {
		// The emulation was offered nothing past it, and its outcome comes
		// when the pty's ioctl returns.
		return step{resolved: t.sizes.wait(seq)}
	}
	// A committed event the emulation hasn't passed: bytes after it were
	// laid out at a size the reconstruction doesn't have. Events are
	// compared by Seq, never by offset, because several can share one.
	if j.heldBack || len(t.sizes.after(j.lastSeq)) > 0 {
		chunks, sizes, err := j.offer()
		if err != nil {
			fellBack = err
			return step{done: true, err: t.attachRaw(j.w)}
		}
		return step{chunks: chunks, sizes: sizes}
	}
	gap, ok := t.buffer.Range(j.h, t.buffer.End())
	if !ok {
		fellBack = ErrReplayGapEvicted
		return step{done: true, err: t.attachRaw(j.w)}
	}
	return step{done: true, err: j.attach(gap)}
}

// failed says why the handoff can't use the emulation, if it can't. Called
// with writeMu held.
func (j *join) failed() error {
	t := j.t
	start := t.buffer.Start()
	switch {
	case j.err != nil:
		return j.err
	case t.sizes.losses() != j.losses:
		// A report or an event was lost since the capture, so some size the
		// emulation would be offered is unknown, even if a known one has
		// closed the loss since.
		return ErrReplayCoverage
	case start > j.h:
		return ErrReplayGapEvicted
	case start == j.h && j.unofferedAt(start):
		// prune keeps only the last committed event at the ring's start, so
		// events there the emulation hasn't been offered may be gone: an 80
		// → 45 → 80 at the handoff would lose the 45's truncation.
		return ErrReplayGapEvicted
	case !time.Now().Before(j.deadline):
		return j.overtime()
	}
	return nil
}

// overtime says what held the handoff back when the join's deadline passed:
// a resize whose outcome isn't known yet, or an offered resize the emulation
// can't pass before the rest of the character or the sequence it fell inside;
// or else nothing outside the emulation, which the time went into, catching
// up included. Called with writeMu held.
func (j *join) overtime() error {
	if _, _, ok := j.t.sizes.firstUnresolved(); ok {
		return errDeadlineAtAResize
	}
	if j.lastSeq < j.offeredSeq {
		return errDeadlineInASequence
	}
	return ErrReplayDeadline
}

// unofferedAt reports a committed event at offset that the emulation hasn't
// been offered. Called with writeMu held.
func (j *join) unofferedAt(offset uint64) bool {
	for _, e := range j.t.sizes.after(j.offeredSeq) {
		if e.Offset == offset {
			return true
		}
	}
	return false
}

// offer takes what the emulation hasn't been offered of the stream: the bytes
// since offeredEnd, and the committed events after offeredSeq, the last offered
// rather than the last passed, so an event still in the emulation's tail is
// never offered twice. hold runs it only once no event is unresolved, so it
// offers everything to End: the bound at the first unresolved event, by offset
// and by Seq, is the capture's to decide. An unknown size among the events is
// the end of the emulation: the size the bytes after it were laid out at isn't
// known, so offer returns ErrReplayCoverage. Called with writeMu held.
func (j *join) offer() (chunks [][]byte, sizes []SizeEvent, err error) {
	t := j.t
	sizes = t.sizes.after(j.offeredSeq)
	for _, e := range sizes {
		if !e.Size.Valid() {
			return nil, nil, ErrReplayCoverage
		}
	}
	end := t.buffer.End()
	chunks, ok := t.buffer.Range(j.offeredEnd, end)
	if !ok {
		return nil, nil, ErrReplayGapEvicted
	}
	j.offeredEnd, j.heldBack = end, false
	if len(sizes) > 0 {
		j.offeredSeq = sizes[len(sizes)-1].Seq
	}
	return chunks, sizes, nil
}

// attach hands w the render, then gap, the ring from the handoff point on,
// which the emulation never consumed, then the sequence the filter holds, and
// attaches w. The sequence is read now and never at the capture: the filter
// holds the start of what follows the ring's end, and the ring has grown since
// the capture. Called with writeMu held, the same hold that found the
// emulation had passed every event logged.
func (j *join) attach(gap [][]byte) error {
	t := j.t
	if len(j.render) > 0 {
		if _, err := j.w.Write(j.render); err != nil {
			return err
		}
	}
	for _, d := range gap {
		if _, err := j.w.Write(d); err != nil {
			return err
		}
	}
	if err := t.writePending(j.w); err != nil {
		return err
	}
	t.attach(j.w)
	return nil
}

// wait waits outside writeMu for ch, the join's ctx, Shutdown or its
// deadline, whichever comes first; the next hold decides what it means.
func (j *join) wait(what joinWait, ch <-chan struct{}) {
	if testHookJoinWaits != nil {
		testHookJoinWaits(what)
	}
	timer := time.NewTimer(time.Until(j.deadline))
	defer timer.Stop()
	select {
	case <-ch:
	case <-j.ctx.Done():
	case <-j.t.closing:
	case <-timer.C:
	}
}

// upTo returns the leading events of sizes, which are in Seq order, at or
// before end and below Seq below.
func upTo(sizes []SizeEvent, end, below uint64) []SizeEvent {
	for i, e := range sizes {
		if e.Offset > end || e.Seq >= below {
			return sizes[:i]
		}
	}
	return sizes
}

// acquire takes the emulation permit: ErrClosed once Shutdown runs, ctx's
// error once ctx is done, or ErrReplayDeadline, wrapped, once the deadline
// passes, while it waits.
func (t *MultiWriter) acquire(ctx context.Context, deadline time.Time) error {
	if err := t.take(ctx, deadline); err != nil {
		return err
	}
	// Whichever way the permit came, it comes with no word on Shutdown or on
	// the joiner: the fast path never looks, and a select with several cases
	// ready picks one at random. A join begun after Shutdown, or for a joiner
	// already gone, is refused here, with the permit freed for the next join,
	// not left to hold it through an emulation nobody needs.
	select {
	case <-t.closing:
		t.release()
		return ErrClosed
	default:
	}
	if err := ctx.Err(); err != nil {
		t.release()
		return err
	}
	return nil
}

// take is acquire's wait for the permit.
func (t *MultiWriter) take(ctx context.Context, deadline time.Time) error {
	select {
	case t.permit <- struct{}{}:
		return nil
	default:
	}
	if testHookJoinWaits != nil {
		testHookJoinWaits(waitPermit)
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case t.permit <- struct{}{}:
		return nil
	case <-t.closing:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errDeadlineAtThePermit
	}
}

func (t *MultiWriter) release() { <-t.permit }

// reportFallback tells the installed fallback why a join fell back, if one
// did. Called with no fan-out lock held.
func (t *MultiWriter) reportFallback(err error) {
	if err != nil && t.fallback != nil {
		t.fallback(err)
	}
}

// broadcast wakes whoever waits for the next of something: wait hands out a
// channel, and notify closes it.
type broadcast struct {
	mu sync.Mutex
	ch chan struct{}
}

func (b *broadcast) wait() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ch == nil {
		b.ch = make(chan struct{})
	}
	return b.ch
}

func (b *broadcast) notify() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ch != nil {
		close(b.ch)
		b.ch = nil
	}
}

// joinWait is what a join waits for outside writeMu.
type joinWait int

const (
	waitPermit joinWait = iota // another join's emulation to end
	waitResize                 // an unresolved resize's outcome
	waitOutput                 // more output or a resize, with nothing new to offer
)

// testHookJoinWaits, when a test sets it, is called each time a join is about
// to wait, with what for, so that the test can act once the join is parked
// rather than guess when it is. Nil outside tests.
var testHookJoinWaits func(joinWait)
