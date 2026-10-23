package io

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/owenthereal/upterm/internal/termsize"
)

// fakeReplayer is a Replayer whose emulation consumes what it is offered as
// it is offered, but for the events it is told to leave in its tail, and
// renders "<" + the bytes it consumed + ">", so that a joiner's bytes show
// where the render ends and the raw gap begins. Its hooks gate and steer it,
// and it records every call.
type fakeReplayer struct {
	// Each hook, when set, runs first in its call, with the call's index
	// among the replayer's calls of that kind; an error it returns is the
	// call's.
	start   func(n int, ctx context.Context, deadline time.Time, c *Capture) error
	feed    func(n int, chunks [][]byte, sizes []SizeEvent) error
	handoff func()
	// skew, when set, moves the handoff point Handoff reports, but not the
	// one Render is as of: a replayer at odds with itself.
	skew func(h, lastSeq uint64) (uint64, uint64)
	// render, when set, makes the render from the handoff point and the
	// bytes consumed up to it.
	render func(h uint64, consumed []byte) ([]byte, error)
	// discard has the emulation count the bytes it is offered rather than
	// keep them, for a stream too long to keep.
	discard bool

	mu       sync.Mutex
	captures []*Capture
	fed      []fedCall
	renders  int
	tail     map[uint64]bool // the events left in the tail, by Seq
}

// fedCall is one Feed's arguments, the chunks joined.
type fedCall struct {
	chunks string
	sizes  []SizeEvent
}

func (r *fakeReplayer) Start(ctx context.Context, deadline time.Time, c *Capture, _ termsize.Size) (Emulation, error) {
	r.mu.Lock()
	n := len(r.captures)
	r.captures = append(r.captures, c)
	r.mu.Unlock()
	if r.start != nil {
		if err := r.start(n, ctx, deadline, c); err != nil {
			return nil, err
		}
	}
	e := &fakeEmulation{r: r, start: c.Start, end: c.Start}
	e.offer(c.Chunks, c.Sizes)
	return e, nil
}

// leaveInTail has the emulation leave event seq unconsumed, and every byte
// from its offset on, or stop doing so.
func (r *fakeReplayer) leaveInTail(seq uint64, leave bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tail == nil {
		r.tail = map[uint64]bool{}
	}
	r.tail[seq] = leave
}

func (r *fakeReplayer) starts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.captures)
}

func (r *fakeReplayer) feeds() []fedCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.fed)
}

func (r *fakeReplayer) renderCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.renders
}

type fakeEmulation struct {
	r          *fakeReplayer
	start, end uint64      // the stream offsets of what was offered
	stream     []byte      // and its bytes, unless discarded
	sizes      []SizeEvent // every event offered, in order
}

func (e *fakeEmulation) offer(chunks [][]byte, sizes []SizeEvent) {
	for _, c := range chunks {
		e.end += uint64(len(c))
		if !e.r.discard {
			e.stream = append(e.stream, c...)
		}
	}
	e.sizes = append(e.sizes, sizes...)
}

func (e *fakeEmulation) Feed(chunks [][]byte, sizes []SizeEvent) error {
	r := e.r
	call := fedCall{sizes: slices.Clone(sizes)}
	if !r.discard {
		call.chunks = string(bytes.Join(chunks, nil))
	}
	r.mu.Lock()
	n := len(r.fed)
	r.fed = append(r.fed, call)
	r.mu.Unlock()
	if r.feed != nil {
		if err := r.feed(n, chunks, sizes); err != nil {
			return err
		}
	}
	e.offer(chunks, sizes)
	return nil
}

func (e *fakeEmulation) Handoff() (uint64, uint64) {
	if e.r.handoff != nil {
		e.r.handoff()
	}
	if e.r.skew != nil {
		return e.r.skew(e.point())
	}
	return e.point()
}

// point is the end of what was offered, or the offset of the first event
// left in the tail, with the Seq of the last event before it.
func (e *fakeEmulation) point() (h, lastSeq uint64) {
	e.r.mu.Lock()
	defer e.r.mu.Unlock()
	h = e.end
	for _, s := range e.sizes {
		if e.r.tail[s.Seq] {
			return min(h, s.Offset), lastSeq
		}
		lastSeq = s.Seq
	}
	return h, lastSeq
}

func (e *fakeEmulation) Render() ([]byte, error) {
	e.r.mu.Lock()
	e.r.renders++
	e.r.mu.Unlock()
	h, _ := e.point()
	var consumed []byte
	if !e.r.discard {
		consumed = e.stream[:h-e.start]
	}
	if e.r.render != nil {
		return e.r.render(h, consumed)
	}
	return []byte("<" + string(consumed) + ">"), nil
}

// fallbackLog collects what a fan-out reports of the joins that fell back,
// and notes a report made with one of its locks held.
type fallbackLog struct {
	w *MultiWriter

	mu     sync.Mutex
	errs   []error
	locked bool
}

func (f *fallbackLog) report(err error) {
	free := f.w.writeMu.TryLock()
	if free {
		f.w.writeMu.Unlock()
	}
	if f.w.membersMu.TryLock() {
		f.w.membersMu.Unlock()
	} else {
		free = false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs = append(f.errs, err)
	f.locked = f.locked || !free
}

func (f *fallbackLog) all() []error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.errs)
}

// joinable is a fan-out with r installed.
func joinable(replayBytes int, r Replayer) (*MultiWriter, *fallbackLog) {
	w := NewMultiWriter(replayBytes)
	f := &fallbackLog{w: w}
	w.SetReplayer(r, f.report)
	return w, f
}

// far is a deadline no test reaches.
func far() time.Time { return time.Now().Add(time.Minute) }

// joinAsync joins sink at 80x24 on a goroutine of its own.
func joinAsync(w *MultiWriter, ctx context.Context, deadline time.Time, sink io.Writer) <-chan error {
	done := make(chan error, 1)
	go func() { done <- w.AppendSized(ctx, deadline, at80x24, sink) }()
	return done
}

// within receives from ch, failing the test if nothing comes in a bound no
// healthy run comes near.
func within[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

// settledReplay receives an immediate consequence after all bubble work settles.
// Unlike within, it cannot advance fake time to hide a delayed wakeup.
func settledReplay[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	synctest.Wait()
	select {
	case v := <-ch:
		return v
	default:
		t.Fatalf("%s did not complete after settling", what)
		var zero T
		return zero
	}
}

func pendingReplay[T any](t *testing.T, ch <-chan T, what string) {
	t.Helper()
	synctest.Wait()
	select {
	case v := <-ch:
		t.Fatalf("%s completed early: %v", what, v)
	default:
	}
}

// parkedStart is a start hook that hands entered each capture and then parks
// until gate closes or the join's ctx is done.
func parkedStart(entered chan<- *Capture, gate <-chan struct{}) func(int, context.Context, time.Time, *Capture) error {
	return func(_ int, ctx context.Context, _ time.Time, c *Capture) error {
		entered <- c
		select {
		case <-gate:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// joinWaits has every join report each wait it begins, until the test ends.
func joinWaits(t *testing.T, writer *MultiWriter) <-chan joinWait {
	waits := make(chan joinWait, 16)
	writer.onJoinWait = func(w joinWait) {
		select {
		case waits <- w:
		default:
		}
	}
	return waits
}

// attachedTimes counts sink among the fan-out's members.
func attachedTimes(w *MultiWriter, sink io.Writer) int {
	w.membersMu.Lock()
	defer w.membersMu.Unlock()
	n := 0
	for _, m := range w.writers {
		if m == sink {
			n++
		}
	}
	return n
}

func joined(chunks [][]byte) string { return string(bytes.Join(chunks, nil)) }

// The fake's Start blocks on a gate. Meanwhile "B" is written: an attached
// recorder receives "B" as work settles (Write never waits on the emulation).
// Then the gate opens: the joiner receives the fake's render, then "B",
// once each, then live writes.
func TestAppendSizedSendsTheRenderThenWhatItMissed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancelJoin := context.WithCancel(t.Context())
		t.Cleanup(cancelJoin)
		entered, gate := make(chan *Capture, 1), make(chan struct{})
		releaseGate := sync.OnceFunc(func() { close(gate) })
		t.Cleanup(releaseGate)
		r := &fakeReplayer{start: parkedStart(entered, gate)}
		w, fallbacks := joinable(DefaultReplayBytes, r)
		w.Pinned(at80x24)
		var live recordingWriter
		require.NoError(t, w.Append(&live))
		writeString(w, "A")

		var joiner recordingWriter
		done := joinAsync(w, ctx, far(), &joiner)
		c := settledReplay(t, entered, "Start")
		require.True(t, c.Pinned)
		require.NotSame(t, w.modes, c.Modes, "the capture's tracker is a clone")

		wrote := make(chan struct{})
		go func() { defer close(wrote); writeString(w, "B") }()
		settledReplay(t, wrote, "a Write while the emulation is parked")
		require.Equal(t, "AB", string(live.bytes()))
		require.Empty(t, joiner.bytes(), "attached before the handoff")

		releaseGate()
		require.NoError(t, settledReplay(t, done, "the join"))
		writeString(w, "C")
		require.Equal(t, "<A>BC", string(joiner.bytes()), "the render, what it missed, then live output, once each")
		require.Empty(t, fallbacks.all())
	})
}

// While the fake is gated, ResizeBegin+ResizeEnd(true) and a write: Feed is
// called with the event and the write's bytes before the attach. Events are
// told apart by Seq, never by offset: two at one offset are each fed, and so
// is one sharing the offset of an event the capture took.
func TestAppendSizedCatchesUpOnAResizeInTheGap(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, gated func(w *MultiWriter)
		captured, fed []SizeEvent
	}{
		{
			name:     "one resize",
			gated:    func(w *MultiWriter) { resize(w, at45x30) },
			captured: []SizeEvent{{Seq: 1, Offset: 0, Size: at80x24}},
			fed:      []SizeEvent{{Seq: 2, Offset: 1, Size: at45x30}},
		},
		{
			// 80 → 45 → 80 with no output between truncates the screen at
			// 45, which 80 alone doesn't.
			name:     "two at one offset",
			gated:    func(w *MultiWriter) { resize(w, at45x30); resize(w, at80x24) },
			captured: []SizeEvent{{Seq: 1, Offset: 0, Size: at80x24}},
			fed:      []SizeEvent{{Seq: 2, Offset: 1, Size: at45x30}, {Seq: 3, Offset: 1, Size: at80x24}},
		},
		{
			name:     "one at the capture's end, and one after it there",
			before:   func(w *MultiWriter) { resize(w, at45x30) },
			gated:    func(w *MultiWriter) { resize(w, at80x24) },
			captured: []SizeEvent{{Seq: 1, Offset: 0, Size: at80x24}, {Seq: 2, Offset: 1, Size: at45x30}},
			fed:      []SizeEvent{{Seq: 3, Offset: 1, Size: at80x24}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered, gate := make(chan *Capture, 1), make(chan struct{})
			var joiner recordingWriter
			var early atomic.Bool
			r := &fakeReplayer{
				start: parkedStart(entered, gate),
				feed: func(int, [][]byte, []SizeEvent) error {
					early.Store(len(joiner.bytes()) > 0)
					return nil
				},
			}
			w, fallbacks := joinable(DefaultReplayBytes, r)
			resize(w, at80x24)
			writeString(w, "A")
			if tc.before != nil {
				tc.before(w)
			}

			// A deadline a join that missed an event falls back at, before
			// the test stops waiting for it.
			done := joinAsync(w, t.Context(), time.Now().Add(2*time.Second), &joiner)
			require.Equal(t, tc.captured, within(t, entered, "Start").Sizes)
			tc.gated(w)
			writeString(w, "X")
			close(gate)

			require.NoError(t, within(t, done, "the join"))
			require.Equal(t, []fedCall{{chunks: "X", sizes: tc.fed}}, r.feeds())
			require.False(t, early.Load(), "attached before the catch-up")
			require.Equal(t, "<AX>", string(joiner.bytes()))
			require.Empty(t, fallbacks.all())
		})
	}
}

// captureStopsAtATentativeResize is the race between a join's capture and a
// resize whose outcome isn't known yet: ResizeBegin(45x30) without its end, a
// write of "X", then the capture, which ends at the event's offset, without
// "X". Then the outcome: the handoff feeds "X", after the event if it
// committed.
func captureStopsAtATentativeResize(t *testing.T, applied bool) {
	entered, gate := make(chan *Capture, 1), make(chan struct{})
	r := &fakeReplayer{start: parkedStart(entered, gate)}
	w, fallbacks := joinable(DefaultReplayBytes, r)
	resize(w, at80x24)
	writeString(w, "A")
	seq := w.ResizeBegin(at45x30)
	writeString(w, "X") // the event is stamped at 1, before "X"

	var joiner recordingWriter
	done := joinAsync(w, t.Context(), far(), &joiner)
	c := within(t, entered, "Start")
	require.Equal(t, uint64(0), c.Start)
	require.Equal(t, uint64(1), c.End, "the capture stops at the unresolved resize")
	require.Equal(t, "A", joined(c.Chunks))
	require.Equal(t, []SizeEvent{{Seq: 1, Offset: 0, Size: at80x24}}, c.Sizes)

	w.ResizeEnd(seq, applied)
	close(gate)
	require.NoError(t, within(t, done, "the join"))
	want := fedCall{chunks: "X"}
	if applied {
		want.sizes = []SizeEvent{{Seq: seq, Offset: 1, Size: at45x30}}
	}
	require.Equal(t, []fedCall{want}, r.feeds())
	require.Equal(t, "<AX>", string(joiner.bytes()), "X once")
	require.Empty(t, fallbacks.all())
}

// ResizeBegin(45x30) without its end, a write of "X", then the capture:
// Capture.End is the event's offset and "X" isn't in Chunks. Then
// ResizeEnd(true): the handoff feeds the event and then "X", in that order,
// and the joiner gets "X" once.
func TestCaptureStopsAtATentativeResize(t *testing.T) { captureStopsAtATentativeResize(t, true) }

// The same with ResizeEnd(false): "X" is fed with no event.
func TestCaptureStopsAtADeletedResizeToo(t *testing.T) { captureStopsAtATentativeResize(t, false) }

// A tentative event at the handoff: no attach until its ResizeEnd.
func TestHandoffWaitsForATentativeResize(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancelJoin := context.WithCancel(t.Context())
		t.Cleanup(cancelJoin)
		entered, gate := make(chan *Capture, 1), make(chan struct{})
		releaseGate := sync.OnceFunc(func() { close(gate) })
		t.Cleanup(releaseGate)
		r := &fakeReplayer{start: parkedStart(entered, gate)}
		w, fallbacks := joinable(DefaultReplayBytes, r)
		waits := joinWaits(t, w)
		resize(w, at80x24)
		writeString(w, "A")

		var joiner recordingWriter
		done := joinAsync(w, ctx, far(), &joiner)
		settledReplay(t, entered, "Start")
		seq := w.ResizeBegin(at45x30)
		releaseGate()

		require.Equal(t, waitResize, settledReplay(t, waits, "the resize wait"))
		require.Empty(t, joiner.bytes())
		require.Zero(t, attachedTimes(w, &joiner))

		w.ResizeEnd(seq, true)
		require.NoError(t, settledReplay(t, done, "the join"))
		require.Equal(t, []fedCall{{sizes: []SizeEvent{{Seq: seq, Offset: 1, Size: at45x30}}}}, r.feeds())
		require.Equal(t, "<A>", string(joiner.bytes()))
		require.Empty(t, fallbacks.all())
	})
}

// More than the ring written while gated: the fallback, ErrReplayGapEvicted
// reported, the joiner gets today's replay.
func TestAppendSizedFallsBackWhenTheGapIsEvicted(t *testing.T) {
	entered, gate := make(chan *Capture, 1), make(chan struct{})
	r := &fakeReplayer{start: parkedStart(entered, gate)}
	w, fallbacks := joinable(16, r)
	resize(w, at80x24)
	writeString(w, "0123456789abcdef")

	var joiner recordingWriter
	done := joinAsync(w, t.Context(), far(), &joiner)
	within(t, entered, "Start")
	writeString(w, "ghijklmnopqrstuvw") // 17 bytes: the ring starts past the handoff
	close(gate)

	require.NoError(t, within(t, done, "the join"))
	require.Equal(t, []error{ErrReplayGapEvicted}, fallbacks.all())
	writeString(w, "Z")
	require.Equal(t, "hijklmnopqrstuvwZ", string(joiner.bytes()), "today's replay, then live output")
}

// prune keeps only the last committed event at the ring's start, so with
// the ring starting at the handoff, events there that the emulation hasn't
// been offered may be gone: an 80 → 45 → 80 at the handoff loses the 45's
// truncation. That is a gap too. With the ring starting a byte before the
// handoff, both events are still logged, and fed.
func TestAppendSizedFallsBackOnEventsEvictedAtTheHandoff(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after int // bytes written after the events: the ring's start, past the handoff's 16
		want  []error
	}{
		{"the ring starts at the handoff", 16, []error{ErrReplayGapEvicted}},
		{"the ring starts before it", 15, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered, gate := make(chan *Capture, 1), make(chan struct{})
			r := &fakeReplayer{start: parkedStart(entered, gate)}
			w, fallbacks := joinable(16, r)
			resize(w, at80x24)
			write(w, 16)

			var joiner recordingWriter
			done := joinAsync(w, t.Context(), far(), &joiner)
			require.Equal(t, uint64(16), within(t, entered, "Start").End)
			resize(w, at45x30)
			resize(w, at80x24)
			write(w, tc.after)
			close(gate)

			require.NoError(t, within(t, done, "the join"))
			require.Equal(t, tc.want, fallbacks.all())
			if tc.want != nil {
				require.Empty(t, r.feeds())
				require.Equal(t, strings.Repeat("x", 16), string(joiner.bytes()), "today's replay")
				return
			}
			require.Equal(t, []fedCall{{
				chunks: strings.Repeat("x", tc.after),
				sizes:  []SizeEvent{{Seq: 2, Offset: 16, Size: at45x30}, {Seq: 3, Offset: 16, Size: at80x24}},
			}}, r.feeds())
			require.Equal(t, "<"+strings.Repeat("x", 16+tc.after)+">", string(joiner.bytes()))
		})
	}
}

// Start returns an error; Render panics: the fallback each time, the
// panic as *ReplayPanic with a stack; the process survives. So with a
// panic in each of the replayer's other calls: every call is guarded.
func TestAppendSizedFallsBackOnAnErrorOrAPanic(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name   string
		steer  func(r *fakeReplayer, w *MultiWriter)
		panics bool
	}{
		{"Start errs", func(r *fakeReplayer, _ *MultiWriter) {
			r.start = func(int, context.Context, time.Time, *Capture) error { return boom }
		}, false},
		{"Start panics", func(r *fakeReplayer, _ *MultiWriter) {
			r.start = func(int, context.Context, time.Time, *Capture) error { panic("boom") }
		}, true},
		{"Render panics", func(r *fakeReplayer, _ *MultiWriter) {
			r.render = func(uint64, []byte) ([]byte, error) { panic("boom") }
		}, true},
		{"Handoff panics", func(r *fakeReplayer, _ *MultiWriter) {
			r.handoff = func() { panic("boom") }
		}, true},
		{"Feed panics", func(r *fakeReplayer, w *MultiWriter) {
			// A resize during Start for the handoff to catch up on.
			r.start = func(int, context.Context, time.Time, *Capture) error { resize(w, at45x30); return nil }
			r.feed = func(int, [][]byte, []SizeEvent) error { panic("boom") }
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeReplayer{}
			w, fallbacks := joinable(DefaultReplayBytes, r)
			tc.steer(r, w)
			resize(w, at80x24)
			writeString(w, "A")

			var joiner recordingWriter
			require.NoError(t, w.AppendSized(t.Context(), far(), at80x24, &joiner))
			errs := fallbacks.all()
			require.Len(t, errs, 1)
			if tc.panics {
				var p *ReplayPanic
				require.ErrorAs(t, errs[0], &p)
				require.Equal(t, "boom", p.Value)
				require.Contains(t, string(p.Stack), "replay_test.go", "the stack is the panic's")
			} else {
				require.ErrorIs(t, errs[0], boom)
			}
			require.False(t, fallbacks.locked, "the fallback was reported with a lock held")
			writeString(w, "B")
			require.Equal(t, "AB", string(joiner.bytes()), "today's replay, then live output")
			require.Equal(t, 1, attachedTimes(w, &joiner))
		})
	}
}

// Shutdown while gated: ErrClosed, nothing attached, no fallback report.
func TestAppendSizedRefusesAfterShutdown(t *testing.T) {
	entered, gate := make(chan *Capture, 1), make(chan struct{})
	r := &fakeReplayer{start: parkedStart(entered, gate)}
	w, fallbacks := joinable(DefaultReplayBytes, r)
	resize(w, at80x24)
	writeString(w, "A")

	var joiner recordingWriter
	done := joinAsync(w, t.Context(), far(), &joiner)
	within(t, entered, "Start")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, w.Shutdown(ctx))
	close(gate)

	require.ErrorIs(t, within(t, done, "the join"), ErrClosed)
	require.Empty(t, joiner.bytes())
	require.Zero(t, attachedTimes(w, &joiner))
	require.Empty(t, fallbacks.all())
}

// The joiner's ctx cancelled while gated: ctx.Err(), nothing attached. So
// too while the handoff waits for a resize's outcome.
func TestAppendSizedAttachesNothingOnceTheJoinerLeft(t *testing.T) {
	for _, tc := range []struct {
		name string
		// park steers the join to where it waits, and returns what waits
		// for it to get there.
		park func(t *testing.T, r *fakeReplayer, w *MultiWriter) (parked func())
	}{
		{"in Start", func(t *testing.T, r *fakeReplayer, _ *MultiWriter) func() {
			entered := make(chan *Capture, 1)
			r.start = parkedStart(entered, nil) // no gate: only the cancel ends Start
			return func() { settledReplay(t, entered, "Start") }
		}},
		{"waiting on a resize", func(t *testing.T, r *fakeReplayer, w *MultiWriter) func() {
			waits := joinWaits(t, w)
			r.start = func(int, context.Context, time.Time, *Capture) error {
				w.ResizeBegin(at45x30) // never ended
				return nil
			}
			return func() { require.Equal(t, waitResize, settledReplay(t, waits, "the wait")) }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := &fakeReplayer{}
				w, fallbacks := joinable(DefaultReplayBytes, r)
				parked := tc.park(t, r, w)
				resize(w, at80x24)
				writeString(w, "A")

				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var joiner recordingWriter
				done := joinAsync(w, ctx, far(), &joiner)
				parked()
				cancel()

				require.ErrorIs(t, settledReplay(t, done, "the join"), context.Canceled)
				require.Empty(t, joiner.bytes())
				require.Zero(t, attachedTimes(w, &joiner))
				require.Empty(t, fallbacks.all())
			})
		})
	}
}

// A joiner whose ctx is done when the join takes its hold is refused on every
// path that would attach it raw too, not only the ones that emulate: ctx's
// error, nothing handed over, nothing attached, no fallback reported (a
// joiner that left is no fallback), and no Start.
func TestAppendSizedRawPathsAttachNothingOnceTheJoinerLeft(t *testing.T) {
	// The tracker holds ?2004h, the ring 16 bytes, and the filter "\x1b[".
	stream := func(w *MultiWriter) {
		writeString(w, "\x1b[?2004h")
		write(w, 16)
		writeString(w, "\x1b[")
	}
	for _, tc := range []struct {
		name     string
		replayer bool
		size     termsize.Size
		deadline func() time.Time
		stream   func(w *MultiWriter)
	}{
		{"no replayer", false, at80x24, far, stream},
		{"a viewer", true, termsize.Size{}, far, stream},
		{"a passed deadline", true, at80x24, time.Now, stream},
		{"an empty ring", true, at80x24, far, func(w *MultiWriter) { writeString(w, "\x1b[") }},
		{"a 0x0 event in the ring", true, at80x24, far, func(w *MultiWriter) {
			write(w, 1)
			resize(w, termsize.Size{})
			write(w, 1)
		}},
		{"margins uncertain", true, at80x24, far, func(w *MultiWriter) {
			resize(w, rows(8))
			writeString(w, "\x1b[2;5r")
			w.ResizeBegin(rows(4))
			writeString(w, "\x1b[2;6r")
			write(w, 16)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeReplayer{}
			w := NewMultiWriter(16)
			fallbacks := &fallbackLog{w: w}
			if tc.replayer {
				w.SetReplayer(r, fallbacks.report)
			}
			resize(w, at80x24)
			tc.stream(w)

			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			var joiner recordingWriter
			require.ErrorIs(t, w.AppendSized(ctx, tc.deadline(), tc.size, &joiner), context.Canceled)
			writeString(w, "z")
			require.Empty(t, joiner.bytes(), "a joiner that had left was handed output")
			require.Zero(t, attachedTimes(w, &joiner), "a joiner that had left was attached")
			require.Zero(t, r.starts())
			require.Empty(t, fallbacks.all())
		})
	}
}

// Shutdown before a join reaches the permit: acquire refuses, however select
// breaks a tie between the permit and the fan-out closing, and the permit is
// left free. With it free, the fast path takes it; held until the join begins
// to wait, then freed, both cases of the wait are ready at once. A coin flip
// picks one, so the attempts repeat.
func TestAcquireRefusesOnceShutdown(t *testing.T) {
	const attempts = 200
	for _, tc := range []struct {
		name string
		// held fills the permit before each attempt and frees it as the join
		// begins to wait for it.
		held bool
	}{
		{"the permit is free", false},
		{"the permit frees as the join begins to wait", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := NewMultiWriter(DefaultReplayBytes)
				require.NoError(t, w.Shutdown(t.Context()))
				if tc.held {
					w.onJoinWait = func(joinWait) { <-w.permit }
				}
				for i := range attempts {
					if tc.held {
						w.permit <- struct{}{}
					}
					require.ErrorIs(t, w.acquire(t.Context(), far()), ErrClosed, "attempt %d", i)
					require.Empty(t, w.permit, "attempt %d left the permit taken", i)
				}
			})
		})
	}
}

// A joiner gone before its join reaches the permit: acquire refuses with its
// ctx's error, however select breaks a tie between the permit and ctx, and
// the permit is left free for the next join, as with Shutdown above.
func TestAcquireRefusesAJoinerThatHasLeft(t *testing.T) {
	const attempts = 200
	for _, tc := range []struct {
		name string
		held bool
	}{
		{"the permit is free", false},
		{"the permit frees as the join begins to wait", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := NewMultiWriter(DefaultReplayBytes)
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				if tc.held {
					w.onJoinWait = func(joinWait) { <-w.permit }
				}
				for i := range attempts {
					if tc.held {
						w.permit <- struct{}{}
					}
					require.ErrorIs(t, w.acquire(ctx, far()), context.Canceled, "attempt %d", i)
					require.Empty(t, w.permit, "attempt %d left the permit taken", i)
				}
			})
		})
	}
}

// The same through AppendSized: a join waiting for the permit while another's
// emulation holds it, Shutdown, then the permit freed. The waiting join is
// refused and its Start never called, whichever way select breaks the tie
// between the permit and the fan-out closing, so the join repeats.
func TestAppendSizedStartsNoEmulationOnceShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const attempts = 200
		for i := range attempts {
			func() {
				entered, gate := make(chan *Capture, 1), make(chan struct{})
				releaseGate := sync.OnceFunc(func() { close(gate) })
				t.Cleanup(releaseGate)
				r := &fakeReplayer{start: parkedStart(entered, gate)}
				w, fallbacks := joinable(DefaultReplayBytes, r)
				resize(w, at80x24)
				writeString(w, "A")

				var a, b recordingWriter
				var doneA <-chan error
				// Installed before either join starts. Only B waits for A's permit.
				// Once it does, end the session and A's emulation, and let A return.
				var errA error
				w.onJoinWait = func(what joinWait) {
					if what != waitPermit {
						return
					}
					_ = w.Shutdown(t.Context())
					releaseGate()
					errA = <-doneA
				}
				doneA = joinAsync(w, t.Context(), far(), &a)
				settledReplay(t, entered, "A's Start")
				doneB := joinAsync(w, t.Context(), far(), &b)

				require.ErrorIs(t, settledReplay(t, doneB, "B"), ErrClosed, "attempt %d", i)
				require.ErrorIs(t, errA, ErrClosed, "attempt %d", i)
				require.Equal(t, 1, r.starts(), "attempt %d: a join began an emulation after Shutdown", i)
				require.Empty(t, b.bytes())
				require.Zero(t, attachedTimes(w, &b))
				require.Empty(t, fallbacks.all())
			}()
		}
	})
}

// A viewer size, no replayer, a passed deadline, an empty ring: Start is
// never called and the joiner gets Append's bytes.
func TestAppendSizedTakesTheFastPath(t *testing.T) {
	// The tracker holds ?2004h, the ring 16 bytes, and the filter "\x1b[":
	// every part of Append's replay.
	stream := func(w *MultiWriter) {
		writeString(w, "\x1b[?2004h")
		write(w, 16)
		writeString(w, "\x1b[")
	}
	full := "\x1b[?2004h" + strings.Repeat("x", 16) + "\x1b["
	for _, tc := range []struct {
		name     string
		replayer bool
		size     termsize.Size
		deadline func() time.Time
		stream   func(w *MultiWriter)
		want     string
	}{
		{"a viewer", true, termsize.Size{}, far, stream, full},
		{"no replayer", false, at80x24, far, stream, full},
		{"a passed deadline", true, at80x24, time.Now, stream, full},
		{"an empty ring", true, at80x24, far, func(w *MultiWriter) { writeString(w, "\x1b[") }, "\x1b["},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeReplayer{}
			w := NewMultiWriter(16)
			fallbacks := &fallbackLog{w: w}
			if tc.replayer {
				w.SetReplayer(r, fallbacks.report)
			}
			resize(w, at80x24)
			tc.stream(w)

			var joiner, appended recordingWriter
			require.NoError(t, w.AppendSized(t.Context(), tc.deadline(), tc.size, &joiner))
			require.NoError(t, w.Append(&appended))
			require.Equal(t, tc.want, string(joiner.bytes()))
			require.Equal(t, string(appended.bytes()), string(joiner.bytes()))
			require.Zero(t, r.starts())
			require.Empty(t, fallbacks.all())
			require.Equal(t, 1, attachedTimes(w, &joiner))
		})
	}
}

// Two joins: the second's Start begins only after the first's semaphore is
// released; a second join whose ctx ends while waiting returns at once.
func TestAppendSizedEmulatesOneAtATime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancelJoin := context.WithCancel(t.Context())
		t.Cleanup(cancelJoin)
		entered, gate := make(chan *Capture, 1), make(chan struct{})
		releaseGate := sync.OnceFunc(func() { close(gate) })
		t.Cleanup(releaseGate)
		started := make(chan int, 4)
		var a recordingWriter
		var early atomic.Bool
		park := parkedStart(entered, gate)
		r := &fakeReplayer{start: func(n int, ctx context.Context, deadline time.Time, c *Capture) error {
			if n == 0 {
				return park(n, ctx, deadline, c)
			}
			early.Store(len(a.bytes()) == 0)
			started <- n
			return nil
		}}
		w, fallbacks := joinable(DefaultReplayBytes, r)
		waits := joinWaits(t, w)
		resize(w, at80x24)
		writeString(w, "A")
		doneA := joinAsync(w, ctx, far(), &a)
		settledReplay(t, entered, "A's Start")

		// B leaves while it waits for the permit A holds.
		ctxB, cancel := context.WithCancel(ctx)
		var b recordingWriter
		doneB := joinAsync(w, ctxB, far(), &b)
		t.Cleanup(cancel)
		require.Equal(t, waitPermit, settledReplay(t, waits, "B's permit wait"))
		pendingReplay(t, doneB, "B while A holds the permit")
		cancel()
		require.ErrorIs(t, settledReplay(t, doneB, "B after cancellation"), context.Canceled)
		require.Equal(t, 1, r.starts(), "B never started")
		for len(waits) > 0 {
			<-waits
		}

		// C waits for it too, and starts once A has attached and released it.
		var c recordingWriter
		doneC := joinAsync(w, ctx, far(), &c)
		require.Equal(t, waitPermit, settledReplay(t, waits, "C's permit wait"))
		pendingReplay(t, started, "C while A holds the permit")
		releaseGate()
		require.NoError(t, settledReplay(t, doneA, "A"))
		require.NoError(t, settledReplay(t, doneC, "C"))
		require.Equal(t, 1, settledReplay(t, started, "C's Start"))
		require.False(t, early.Load(), "C started before A had attached")
		require.Equal(t, "<A>", string(a.bytes()))
		require.Equal(t, "<A>", string(c.bytes()))
		require.Empty(t, b.bytes())
		require.Empty(t, fallbacks.all())
	})
}

// A CSI split by the filter at the capture ("\x1b[3" pending): it completes
// while gated; the joiner receives it once, in the gap.
func TestAppendSizedReadsPendingAtRelease(t *testing.T) {
	entered, gate := make(chan *Capture, 1), make(chan struct{})
	r := &fakeReplayer{start: parkedStart(entered, gate)}
	w, fallbacks := joinable(DefaultReplayBytes, r)
	resize(w, at80x24)
	writeString(w, "A\x1b[3")

	var joiner recordingWriter
	done := joinAsync(w, t.Context(), far(), &joiner)
	require.Equal(t, "A", joined(within(t, entered, "Start").Chunks))
	writeString(w, "1mB")
	close(gate)

	require.NoError(t, within(t, done, "the join"))
	require.Equal(t, "<A>\x1b[31mB", string(joiner.bytes()))
	require.Empty(t, fallbacks.all())
}

// The tracker uncertain at capture: the fallback, ErrReplayMarginsUncertain.
func TestAppendSizedFallsBackWhenMarginsAreUncertain(t *testing.T) {
	r := &fakeReplayer{}
	w, fallbacks := joinable(16, r)
	resize(w, rows(8))
	writeString(w, "\x1b[2;5r")
	w.ResizeBegin(rows(4))
	writeString(w, "\x1b[2;6r")
	write(w, 16) // 2;6 at 8 rows, 2;4 at 4

	var joiner recordingWriter
	require.NoError(t, w.AppendSized(t.Context(), far(), at80x24, &joiner))
	require.Equal(t, []error{ErrReplayMarginsUncertain}, fallbacks.all())
	require.Zero(t, r.starts())
	require.Equal(t, "\x1b[2;4r"+strings.Repeat("x", 16), string(joiner.bytes()), "today's replay")
}

// Coverage is decided at the capture: a queue overflow before it, and a 0x0
// event inside the ring, each fall back with ErrReplayCoverage; Start is never
// called.
func TestAppendSizedFallsBackOnIncompleteCoverage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream func(w *MultiWriter)
	}{
		{"a queue overflow", func(w *MultiWriter) {
			write(w, 1)
			for i := range sizeQueueMax + 1 {
				resize(w, rows(10+i))
			}
			write(w, 1)
		}},
		{"a 0x0 event in the ring", func(w *MultiWriter) {
			write(w, 1)
			resize(w, termsize.Size{})
			write(w, 1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeReplayer{}
			w, fallbacks := joinable(DefaultReplayBytes, r)
			resize(w, at80x24)
			tc.stream(w)

			var joiner recordingWriter
			require.NoError(t, w.AppendSized(t.Context(), far(), at80x24, &joiner))
			require.Equal(t, []error{ErrReplayCoverage}, fallbacks.all())
			require.Zero(t, r.starts())
			require.Equal(t, "xx", string(joiner.bytes()), "today's replay")
		})
	}
}

// While the fake's Start is gated, 65 ResizeBegin+ResizeEnd pairs with no write
// between (a queue overflow); then a write and the gate opens: the handoff
// falls back with ErrReplayCoverage; Feed is never offered the events that
// survived.
func TestAppendSizedFallsBackWhenCoverageBreaksWhileEmulating(t *testing.T) {
	entered, gate := make(chan *Capture, 1), make(chan struct{})
	r := &fakeReplayer{start: parkedStart(entered, gate)}
	w, fallbacks := joinable(DefaultReplayBytes, r)
	resize(w, at80x24)
	writeString(w, "A")

	var joiner recordingWriter
	done := joinAsync(w, t.Context(), far(), &joiner)
	within(t, entered, "Start")
	for i := range sizeQueueMax + 1 {
		resize(w, rows(10+i))
	}
	writeString(w, "X")
	close(gate)

	require.NoError(t, within(t, done, "the join"))
	require.Equal(t, []error{ErrReplayCoverage}, fallbacks.all())
	require.Empty(t, r.feeds())
	require.Equal(t, "AX", string(joiner.bytes()), "today's replay")
}

// The same with a committed 0x0 event after the capture: the catch-up
// falls back with ErrReplayCoverage before calling Feed.
func TestAppendSizedFallsBackOnAnUnknownSizeAfterTheCapture(t *testing.T) {
	entered, gate := make(chan *Capture, 1), make(chan struct{})
	r := &fakeReplayer{start: parkedStart(entered, gate)}
	w, fallbacks := joinable(DefaultReplayBytes, r)
	resize(w, at80x24)
	writeString(w, "A")

	var joiner recordingWriter
	done := joinAsync(w, t.Context(), far(), &joiner)
	within(t, entered, "Start")
	resize(w, termsize.Size{})
	writeString(w, "X")
	close(gate)

	require.NoError(t, within(t, done, "the join"))
	require.Equal(t, []error{ErrReplayCoverage}, fallbacks.all())
	require.Empty(t, r.feeds())
	require.Equal(t, "AX", string(joiner.bytes()), "today's replay")
}

// The permit is held through the catch-up: join A's catch-up Feed is gated;
// join B arrives: B's Start does not begin until A has attached; then it runs.
func TestAppendSizedHoldsThePermitThroughCatchUp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancelJoin := context.WithCancel(t.Context())
		t.Cleanup(cancelJoin)
		fedA, gate := make(chan struct{}), make(chan struct{})
		releaseGate := sync.OnceFunc(func() { close(gate) })
		t.Cleanup(releaseGate)
		started := make(chan int, 4)
		var a, b recordingWriter
		var early atomic.Bool
		r := &fakeReplayer{}
		w, fallbacks := joinable(DefaultReplayBytes, r)
		waits := joinWaits(t, w)
		r.start = func(n int, _ context.Context, _ time.Time, _ *Capture) error {
			if n == 0 {
				// Something for A's handoff to catch up on.
				resize(w, at45x30)
				writeString(w, "X")
				return nil
			}
			early.Store(len(a.bytes()) == 0)
			started <- n
			return nil
		}
		r.feed = func(n int, _ [][]byte, _ []SizeEvent) error {
			if n == 0 {
				close(fedA)
				<-gate
			}
			return nil
		}
		resize(w, at80x24)
		writeString(w, "A")

		doneA := joinAsync(w, ctx, far(), &a)
		settledReplay(t, fedA, "A's catch-up")
		doneB := joinAsync(w, ctx, far(), &b)
		require.Equal(t, waitPermit, settledReplay(t, waits, "B's permit wait"))
		pendingReplay(t, started, "B during A's catch-up")
		pendingReplay(t, doneA, "A during catch-up")
		releaseGate()

		require.NoError(t, settledReplay(t, doneA, "A"))
		require.NoError(t, settledReplay(t, doneB, "B"))
		require.Equal(t, 1, settledReplay(t, started, "B's Start"))
		require.False(t, early.Load(), "B started before A had attached")
		require.Equal(t, "<AX>", string(a.bytes()))
		require.Equal(t, "<AX>", string(b.bytes()))
		require.Empty(t, fallbacks.all())
	})
}

// The fake defers an offered event (its Handoff's lastSeq stays before it);
// two more catch-ups follow: the fake is offered each Seq exactly once.
func TestCatchUpNeverOffersAnEventTwice(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancelJoin := context.WithCancel(t.Context())
		t.Cleanup(cancelJoin)
		entered, gate := make(chan *Capture, 1), make(chan struct{})
		releaseGate := sync.OnceFunc(func() { close(gate) })
		t.Cleanup(releaseGate)
		fed, proceed := make(chan int), make(chan struct{})
		r := &fakeReplayer{
			start: parkedStart(entered, gate),
			feed: func(n int, _ [][]byte, _ []SizeEvent) error {
				select {
				case fed <- n:
				case <-ctx.Done():
					return ctx.Err()
				}
				select {
				case <-proceed:
				case <-ctx.Done():
					return ctx.Err()
				}
				return nil
			},
		}
		w, fallbacks := joinable(DefaultReplayBytes, r)
		resize(w, at80x24)
		writeString(w, "A")

		var joiner recordingWriter
		done := joinAsync(w, ctx, far(), &joiner)
		settledReplay(t, entered, "Start")
		seq := w.ResizeBegin(at45x30)
		w.ResizeEnd(seq, true)
		r.leaveInTail(seq, true)
		writeString(w, "a")
		releaseGate()

		// Each catch-up finds the event still unapplied, and more output.
		require.Equal(t, 0, settledReplay(t, fed, "the first catch-up"))
		writeString(w, "b")
		proceed <- struct{}{}
		require.Equal(t, 1, settledReplay(t, fed, "the second"))
		writeString(w, "c")
		proceed <- struct{}{}
		require.Equal(t, 2, settledReplay(t, fed, "the third"))
		r.leaveInTail(seq, false)
		proceed <- struct{}{}

		require.NoError(t, settledReplay(t, done, "the join"))
		feeds := r.feeds()
		require.Equal(t, []fedCall{
			{chunks: "a", sizes: []SizeEvent{{Seq: seq, Offset: 1, Size: at45x30}}},
			{chunks: "b"},
			{chunks: "c"},
		}, feeds)
		offered := map[uint64]int{}
		for _, e := range r.captures[0].Sizes {
			offered[e.Seq]++
		}
		for _, f := range feeds {
			for _, e := range f.sizes {
				offered[e.Seq]++
			}
		}
		require.Equal(t, map[uint64]int{1: 1, seq: 1}, offered)
		require.Equal(t, "<Aabc>", string(joiner.bytes()))
		require.Empty(t, fallbacks.all())
	})
}

// When a catch-up would offer the emulation nothing new, the join waits for
// more output, the deadline or ctx, rather than feeding and rendering again
// in a loop: a quiet stream with an event left in the replayer's tail
// renders once, at Start, before handing off or falling back. The catch-up
// that leaves the event in the tail renders nothing.
func TestCatchUpWaitsWhenThereIsNothingNewToOffer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancelJoin := context.WithCancel(t.Context())
		t.Cleanup(cancelJoin)
		entered, gate := make(chan *Capture, 1), make(chan struct{})
		releaseGate := sync.OnceFunc(func() { close(gate) })
		t.Cleanup(releaseGate)
		r := &fakeReplayer{start: parkedStart(entered, gate)}
		w, fallbacks := joinable(DefaultReplayBytes, r)
		waits := joinWaits(t, w)
		resize(w, at80x24)
		writeString(w, "A")

		var joiner recordingWriter
		const wait = 300 * time.Millisecond
		done := joinAsync(w, ctx, time.Now().Add(wait), &joiner)
		settledReplay(t, entered, "Start")
		seq := w.ResizeBegin(at45x30)
		w.ResizeEnd(seq, true)
		r.leaveInTail(seq, true)
		writeString(w, "a")
		releaseGate()

		require.Equal(t, waitOutput, settledReplay(t, waits, "the output wait"))
		time.Sleep(wait - time.Nanosecond)
		pendingReplay(t, done, "the catch-up deadline")
		require.Len(t, r.feeds(), 1)
		time.Sleep(time.Nanosecond)
		require.NoError(t, settledReplay(t, done, "the join"))
		require.Equal(t, []error{errDeadlineInASequence}, fallbacks.all())
		require.Equal(t, 1, r.renderCount(), "Start's render, and none while the event is in the tail")
		require.Len(t, r.feeds(), 1)
		require.Equal(t, "Aa", string(joiner.bytes()), "today's replay")
	})
}

// A join that runs out of time says what it was doing: emulating, which is
// ErrReplayDeadline itself, or waiting, for a resize's outcome, for the rest
// of a character or a sequence a resize fell inside, or for another join's
// emulation, each ErrReplayDeadline wrapped with what it waited for.
func TestAppendSizedSaysWhatTheDeadlineCaughtTheJoinDoing(t *testing.T) {
	for _, tc := range []struct {
		name                string
		size                termsize.Size
		waitFor             joinWait
		steer               func(t *testing.T, r *fakeReplayer, w *MultiWriter)
		beforeStart         bool
		startBeforeDeadline bool
		want                error
		raw                 string
	}{
		{
			name: "emulating", size: at80x24,
			steer: func(_ *testing.T, r *fakeReplayer, _ *MultiWriter) {
				r.start = func(_ int, _ context.Context, deadline time.Time, _ *Capture) error {
					time.Sleep(time.Until(deadline))
					return nil
				}
			},
			want: ErrReplayDeadline, raw: "A",
		},
		{
			name: "waiting for a resize's outcome", size: at80x24, waitFor: waitResize,
			steer: func(t *testing.T, r *fakeReplayer, w *MultiWriter) {
				r.start = func(int, context.Context, time.Time, *Capture) error {
					seq := w.ResizeBegin(at45x30)
					t.Cleanup(func() { w.ResizeEnd(seq, true) })
					return nil
				}
			},
			want: errDeadlineAtAResize, raw: "A",
		},
		{
			name: "waiting for the rest of a sequence", size: at45x30, waitFor: waitOutput,
			steer: func(_ *testing.T, r *fakeReplayer, w *MultiWriter) {
				seq := w.ResizeBegin(at45x30)
				w.ResizeEnd(seq, true)
				r.leaveInTail(seq, true)
				writeString(w, "\x1b[3")
			},
			want: errDeadlineInASequence, raw: "A\x1b[3",
		},
		{
			name: "waiting for another join's emulation", size: at80x24, waitFor: waitPermit,
			steer: func(t *testing.T, _ *fakeReplayer, w *MultiWriter) {
				require.NoError(t, w.acquire(t.Context(), far()))
				t.Cleanup(w.release)
			},
			want: errDeadlineAtThePermit, raw: "A",
		},
		{name: "before Start", size: at80x24, beforeStart: true, want: errDeadlineBeforeStart, raw: "A"},
		{name: "before Start just before deadline", size: at80x24, beforeStart: true, startBeforeDeadline: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const wait = 200 * time.Millisecond
				deadline := time.Now().Add(wait)
				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)
				r := &fakeReplayer{}
				w, fallbacks := joinable(DefaultReplayBytes, r)
				waits := joinWaits(t, w)
				resize(w, at80x24)
				writeString(w, "A")
				if tc.steer != nil {
					tc.steer(t, r, w)
				}
				var sink recordingWriter
				var done <-chan error
				var start func()
				if tc.beforeStart {
					// Exercise the internal stages: AppendSized has no pause
					// between acquiring the permit and checking Start's deadline.
					j := &join{t: w, ctx: ctx, deadline: deadline, size: tc.size, w: &sink}
					c, complete, err := j.capture()
					require.NoError(t, err)
					require.False(t, complete)
					require.NoError(t, w.acquire(ctx, deadline))
					t.Cleanup(w.release)
					result := make(chan error, 1)
					done = result
					start = func() { j.start(c); result <- j.handoff() }
				} else {
					result := make(chan error, 1)
					go func() { result <- w.AppendSized(ctx, deadline, tc.size, &sink) }()
					done = result
					if tc.want != ErrReplayDeadline {
						require.Equal(t, tc.waitFor, settledReplay(t, waits, "the deadline wait"))
					}
				}
				time.Sleep(wait - time.Nanosecond)
				pendingReplay(t, done, "the join before its deadline")
				require.Empty(t, sink.bytes())
				require.Empty(t, fallbacks.all())
				if !tc.startBeforeDeadline {
					time.Sleep(time.Nanosecond)
				}
				if start != nil {
					start()
				}
				require.NoError(t, settledReplay(t, done, "the join at its deadline"))
				if tc.startBeforeDeadline {
					require.Equal(t, 1, r.starts(), "Start is allowed one nanosecond before the deadline")
					require.Equal(t, "<A>", string(sink.bytes()))
					require.Empty(t, fallbacks.all())
					return
				}
				errs := fallbacks.all()
				require.Equal(t, []error{tc.want}, errs)
				require.ErrorIs(t, errs[0], ErrReplayDeadline)
				require.Equal(t, tc.raw, string(sink.bytes()), "exact raw replay at the deadline")
				if tc.beforeStart {
					require.Zero(t, r.starts(), "Start must not run at the deadline")
				}
			})
		})
	}
}

// The emulation renders only once it has passed every resize it was
// offered. Until then it is at a size older than the stream's, which a joiner
// sized to the newest may not hold. Here the joiner's own resize is in the
// capture but stays in the emulation's tail, as a resize inside a character
// the ring ends in the middle of does: Start renders nothing, the join waits
// for output, and the output that lets the emulation pass the resize brings
// the one render, which the join hands over.
func TestAppendSizedRendersNothingBeforeTheNewestOfferedResize(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancelJoin := context.WithCancel(t.Context())
		t.Cleanup(cancelJoin)
		r := &fakeReplayer{}
		var seq uint64
		var early atomic.Bool // a render made with the resize in the tail
		r.render = func(_ uint64, consumed []byte) ([]byte, error) {
			r.mu.Lock()
			inTail := r.tail[seq]
			r.mu.Unlock()
			if inTail {
				early.Store(true)
			}
			return []byte("<" + string(consumed) + ">"), nil
		}
		r.feed = func(int, [][]byte, []SizeEvent) error {
			// The rest of the character, which lets the emulation pass the resize.
			r.leaveInTail(seq, false)
			return nil
		}
		w, fallbacks := joinable(DefaultReplayBytes, r)
		waits := joinWaits(t, w)
		resize(w, at80x24)
		writeString(w, "A")
		seq = w.ResizeBegin(at45x30)
		w.ResizeEnd(seq, true)
		r.leaveInTail(seq, true)

		var joiner recordingWriter
		done := joinAsync(w, ctx, far(), &joiner)
		require.Equal(t, waitOutput, settledReplay(t, waits, "the wait for output"))
		require.Zero(t, r.renderCount(), "a render was made at a size older than the joiner's resize")

		writeString(w, "B")
		require.NoError(t, settledReplay(t, done, "the join"))
		require.False(t, early.Load(), "a render was made with the joiner's resize in the emulation's tail")
		require.Equal(t, 1, r.renderCount())
		require.Equal(t, "<AB>", string(joiner.bytes()))
		require.Empty(t, fallbacks.all())
	})
}

// io falls back when a render is longer than DefaultReplayBytes, so one
// delivery stays bounded whatever the replayer does.
func TestAppendSizedFallsBackOnAnOverlongRender(t *testing.T) {
	for _, n := range []int{DefaultReplayBytes, DefaultReplayBytes + 1} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			render := bytes.Repeat([]byte("r"), n)
			r := &fakeReplayer{render: func(uint64, []byte) ([]byte, error) { return render, nil }}
			w, fallbacks := joinable(DefaultReplayBytes, r)
			resize(w, at80x24)
			writeString(w, "A")

			var joiner recordingWriter
			require.NoError(t, w.AppendSized(t.Context(), far(), at80x24, &joiner))
			if n <= DefaultReplayBytes {
				require.Empty(t, fallbacks.all())
				require.Equal(t, string(render), string(joiner.bytes()))
				return
			}
			require.Equal(t, []error{errRenderTooLong}, fallbacks.all())
			require.Equal(t, "A", string(joiner.bytes()), "today's replay")
		})
	}
}

// Exactly once is io's guarantee whatever the replayer does. A handoff point
// past what the emulation was offered would leave bytes in neither the
// render nor the gap, and a last event past the last offered would attach
// the joiner past a resize never fed. Either falls back.
func TestAppendSizedFallsBackOnAHandoffPastWhatWasOffered(t *testing.T) {
	for _, tc := range []struct {
		name  string
		gated func(w *MultiWriter)
		skew  func(h, lastSeq uint64) (uint64, uint64)
		raw   string
	}{
		{
			name:  "a byte past the offered end",
			gated: func(w *MultiWriter) { writeString(w, "BC") },
			skew:  func(h, lastSeq uint64) (uint64, uint64) { return h + 1, lastSeq },
			raw:   "ABC",
		},
		{
			name:  "an event past the last offered",
			gated: func(w *MultiWriter) { resize(w, at45x30); writeString(w, "X") },
			skew:  func(h, lastSeq uint64) (uint64, uint64) { return h, lastSeq + 1 },
			raw:   "AX",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered, gate := make(chan *Capture, 1), make(chan struct{})
			r := &fakeReplayer{start: parkedStart(entered, gate), skew: tc.skew}
			w, fallbacks := joinable(DefaultReplayBytes, r)
			resize(w, at80x24)
			writeString(w, "A")

			var joiner recordingWriter
			done := joinAsync(w, t.Context(), far(), &joiner)
			within(t, entered, "Start")
			tc.gated(w)
			close(gate)

			require.NoError(t, within(t, done, "the join"))
			require.Equal(t, []error{errHandoffOutOfRange}, fallbacks.all())
			require.Equal(t, tc.raw, string(joiner.bytes()), "today's replay")
		})
	}
}

// Shutdown wakes a join parked outside writeMu, whatever it waits for: it
// returns ErrClosed at once and attaches nothing, rather than sleeping out
// its deadline holding the permit, or waking to a Start that can only end
// in ErrClosed.
func TestShutdownWakesAParkedJoin(t *testing.T) {
	shutdown := func(t *testing.T, w *MultiWriter) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		require.NoError(t, w.Shutdown(ctx))
	}
	closedAtOnce := func(t *testing.T, done <-chan error) {
		require.ErrorIs(t, settledReplay(t, done, "the parked join after Shutdown"), ErrClosed)
	}

	for _, tc := range []struct {
		name  string
		wait  joinWait
		steer func(r *fakeReplayer, w *MultiWriter)
	}{
		{"waiting on a resize", waitResize, func(r *fakeReplayer, w *MultiWriter) {
			r.start = func(int, context.Context, time.Time, *Capture) error {
				w.ResizeBegin(at45x30) // never ended
				return nil
			}
		}},
		{"waiting for output", waitOutput, func(r *fakeReplayer, w *MultiWriter) {
			r.start = func(int, context.Context, time.Time, *Capture) error {
				seq := w.ResizeBegin(at45x30)
				w.ResizeEnd(seq, true)
				r.leaveInTail(seq, true)
				return nil
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := &fakeReplayer{}
				w, fallbacks := joinable(DefaultReplayBytes, r)
				waits := joinWaits(t, w)
				tc.steer(r, w)
				resize(w, at80x24)
				writeString(w, "A")

				var joiner recordingWriter
				done := joinAsync(w, t.Context(), far(), &joiner)
				require.Equal(t, tc.wait, settledReplay(t, waits, "the wait"))
				shutdown(t, w)
				closedAtOnce(t, done)
				require.Empty(t, joiner.bytes())
				require.Zero(t, attachedTimes(w, &joiner))
				require.Empty(t, fallbacks.all())
				require.Zero(t, len(w.permit), "the permit was given back")
			})
		})
	}

	t.Run("waiting for the permit", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			entered, gate := make(chan *Capture, 1), make(chan struct{})
			releaseGate := sync.OnceFunc(func() { close(gate) })
			t.Cleanup(releaseGate)
			r := &fakeReplayer{start: parkedStart(entered, gate)}
			w, fallbacks := joinable(DefaultReplayBytes, r)
			waits := joinWaits(t, w)
			resize(w, at80x24)
			writeString(w, "A")

			var a, b recordingWriter
			doneA := joinAsync(w, t.Context(), far(), &a)
			settledReplay(t, entered, "A's Start")
			doneB := joinAsync(w, t.Context(), far(), &b)
			require.Equal(t, waitPermit, settledReplay(t, waits, "B's wait"))
			shutdown(t, w)
			closedAtOnce(t, doneB)
			require.Equal(t, 1, r.starts(), "B never started")

			releaseGate()
			require.ErrorIs(t, settledReplay(t, doneA, "A"), ErrClosed)
			require.Zero(t, len(w.permit), "the permit was given back")
			require.Empty(t, a.bytes())
			require.Empty(t, b.bytes())
			require.Zero(t, attachedTimes(w, &a)+attachedTimes(w, &b))
			require.Empty(t, fallbacks.all())
		})
	})
}

// The capture takes only committed events below the first unresolved one's Seq,
// whatever their offsets. A resize begun and committed while an earlier one
// waits for its ioctl lands at the same offset, after it, and is offered only
// once the earlier one's outcome is known, after it if it committed.
func TestCaptureTakesNoEventPastAnUnresolvedOne(t *testing.T) {
	for _, applied := range []bool{true, false} {
		t.Run(fmt.Sprintf("applied=%t", applied), func(t *testing.T) {
			entered, gate := make(chan *Capture, 1), make(chan struct{})
			r := &fakeReplayer{start: parkedStart(entered, gate)}
			w, fallbacks := joinable(DefaultReplayBytes, r)
			resize(w, at80x24)
			writeString(w, "A")
			first := w.ResizeBegin(at45x30)
			resize(w, at100x40)
			writeString(w, "X") // both at 1, the first unresolved

			var joiner recordingWriter
			done := joinAsync(w, t.Context(), far(), &joiner)
			c := within(t, entered, "Start")
			require.Equal(t, uint64(1), c.End)
			require.Equal(t, []SizeEvent{{Seq: 1, Offset: 0, Size: at80x24}}, c.Sizes, "nothing after the unresolved event")

			w.ResizeEnd(first, applied)
			close(gate)
			require.NoError(t, within(t, done, "the join"))
			fed := []SizeEvent{{Seq: first + 1, Offset: 1, Size: at100x40}}
			if applied {
				fed = append([]SizeEvent{{Seq: first, Offset: 1, Size: at45x30}}, fed...)
			}
			require.Equal(t, []fedCall{{chunks: "X", sizes: fed}}, r.feeds())
			require.Equal(t, "<AX>", string(joiner.bytes()))
			require.Empty(t, fallbacks.all())
		})
	}
}

// streamChunk is the k'th of a stream's 4 KiB pieces, numbered, so that a
// joiner's copy shows any byte of it missing or repeated.
func streamChunk(k uint64) []byte {
	p := bytes.Repeat([]byte("."), 4096)
	copy(p, fmt.Sprintf("%010d", k))
	p[len(p)-1] = '\n'
	return p
}

// streamBytes is the stream of numbered pieces from offset from to to.
func streamBytes(from, to uint64) []byte {
	var out []byte
	for k := from / 4096; k*4096 < to; k++ {
		lo, hi := uint64(0), uint64(4096)
		if k*4096 < from {
			lo = from - k*4096
		}
		if (k+1)*4096 > to {
			hi = to - k*4096
		}
		out = append(out, streamChunk(k)[lo:hi]...)
	}
	return out
}

// A goroutine writes 4 KiB chunks continuously; the fake's Feed takes 5 ms;
// the join either attaches with every byte once (checked by sequence numbers
// in the chunks) or falls back at the deadline, within deadline + 50 ms.
//
// The bound is on the decision, the sink's first byte: the release's own
// hold, writing up to the whole ring into the sink, is outside the deadline.
func TestAppendSizedUnderStreamingOutput(t *testing.T) {
	for _, tc := range []struct {
		name string
		// tail has the emulation leave the resize in its tail for good, so
		// it can never hand off.
		tail bool
	}{{"the emulation keeps up", false}, {"the emulation never passes the resize", true}} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeReplayer{
				discard: true,
				feed: func(int, [][]byte, []SizeEvent) error {
					time.Sleep(5 * time.Millisecond) // the emulation's work
					return nil
				},
				render: func(h uint64, _ []byte) ([]byte, error) { return fmt.Appendf(nil, "<%d>", h), nil },
			}
			w, fallbacks := joinable(16<<20, r)
			resize(w, at80x24)
			_, _ = w.Write(streamChunk(0))
			r.start = func(int, context.Context, time.Time, *Capture) error {
				// A resize for the handoff to catch up on, mid-stream.
				seq := w.ResizeBegin(at45x30)
				w.ResizeEnd(seq, true)
				r.leaveInTail(seq, tc.tail)
				return nil
			}

			// The join begins once a ring's worth has streamed, and the stream
			// runs on through it.
			streaming, stop, total := make(chan struct{}), make(chan struct{}), make(chan uint64, 1)
			go func() {
				for k := uint64(1); ; k++ {
					select {
					case <-stop:
						total <- k * 4096
						return
					default:
					}
					_, _ = w.Write(streamChunk(k))
					if k == DefaultReplayBytes/4096 {
						close(streaming)
					}
				}
			}()
			within(t, streaming, "the stream")

			deadline := time.Now().Add(300 * time.Millisecond)
			var joiner firstWriteSink
			err := w.AppendSized(t.Context(), deadline, at80x24, &joiner)
			close(stop)
			end := <-total
			require.NoError(t, err)
			decided := joiner.firstWrite()
			require.False(t, decided.After(deadline.Add(50*time.Millisecond)),
				"decided %v after the deadline", decided.Sub(deadline))

			got := joiner.bytes()
			errs := fallbacks.all()
			t.Logf("fell back: %v; %d catch-ups; %d KiB streamed; decided %v after the deadline", errs, len(r.feeds()), end>>10, decided.Sub(deadline))
			if len(errs) == 0 {
				require.False(t, tc.tail, "attached with the resize never applied")
				require.NotEmpty(t, r.feeds(), "attached without catching up on the resize")
				i := bytes.IndexByte(got, '>')
				require.Positive(t, i)
				h, perr := strconv.ParseUint(string(got[1:i]), 10, 64)
				require.NoError(t, perr)
				require.True(t, bytes.Equal(streamBytes(h, end), got[i+1:]), "the gap and live output, from the handoff, once each")
				return
			}
			require.Len(t, errs, 1)
			require.True(t, errors.Is(errs[0], ErrReplayDeadline) || errors.Is(errs[0], ErrReplayGapEvicted), "%v", errs[0])
			require.True(t, bytes.Equal(streamBytes(end-uint64(len(got)), end), got), "today's replay, then live output, once each")
		})
	}
}

// firstWriteSink records when it is first written to: when a join's outcome
// was decided, before the release's own writes.
type firstWriteSink struct {
	recordingWriter
	mu    sync.Mutex
	first time.Time
}

func (s *firstWriteSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.first.IsZero() {
		s.first = time.Now()
	}
	s.mu.Unlock()
	return s.recordingWriter.Write(p)
}

func (s *firstWriteSink) firstWrite() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.first
}

// stormSink is a joiner's terminal in the rejoin storm. Its first bytes are
// its join's outcome, so they end the emulation its join ran, if it ran one.
type stormSink struct {
	recordingWriter
	active  *atomic.Int32
	started atomic.Bool
	once    sync.Once
}

func (s *stormSink) Write(p []byte) (int, error) {
	s.once.Do(func() {
		if s.started.Load() {
			s.active.Add(-1)
		}
	})
	return s.recordingWriter.Write(p)
}

// A rejoin storm: 20 joins at once, a fake that takes 200 ms with a 1 s
// deadline: they run one at a time; those past their deadline fall back;
// an attached recorder sees every write within 50 ms; each joiner is
// attached exactly once.
func TestAppendSizedRejoinStorm(t *testing.T) {
	const joins = 20
	type joinKey struct{}
	var active, overlaps atomic.Int32
	sinks := make([]*stormSink, joins)
	for i := range sinks {
		sinks[i] = &stormSink{active: &active}
	}
	r := &fakeReplayer{start: func(_ int, ctx context.Context, deadline time.Time, _ *Capture) error {
		sinks[ctx.Value(joinKey{}).(int)].started.Store(true)
		if active.Add(1) > 1 {
			overlaps.Add(1)
		}
		// 200 ms of work, which stops at the deadline, as a replayer's does.
		timer := time.NewTimer(min(200*time.Millisecond, time.Until(deadline)))
		defer timer.Stop()
		<-timer.C
		if !time.Now().Before(deadline) {
			return ErrReplayDeadline
		}
		return nil
	}}
	w, fallbacks := joinable(DefaultReplayBytes, r)
	resize(w, at80x24)
	var live recordingWriter
	require.NoError(t, w.Append(&live))
	writeString(w, "A")

	// The session's output flows through the storm, each Write timed.
	stop := make(chan struct{})
	type written struct {
		lines   int
		slowest time.Duration
	}
	result := make(chan written, 1)
	go func() {
		var out written
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				result <- out
				return
			case <-tick.C:
			}
			begin := time.Now()
			writeString(w, fmt.Sprintf("line %d\n", out.lines))
			out.slowest = max(out.slowest, time.Since(begin))
			out.lines++
		}
	}()

	var wg sync.WaitGroup
	deadlines, returned := make([]time.Time, joins), make([]time.Time, joins)
	errs := make([]error, joins)
	for i := range joins {
		wg.Go(func() {
			ctx := context.WithValue(t.Context(), joinKey{}, i)
			deadlines[i] = time.Now().Add(time.Second)
			errs[i] = w.AppendSized(ctx, deadlines[i], at80x24, sinks[i])
			returned[i] = time.Now()
		})
	}
	wg.Wait()
	close(stop)
	out := <-result
	require.LessOrEqual(t, out.slowest, 50*time.Millisecond, "a Write waited on the joins")
	require.Zero(t, overlaps.Load(), "two emulations ran at once")

	stream := live.bytes()
	var lines strings.Builder
	lines.WriteString("A")
	for i := range out.lines {
		fmt.Fprintf(&lines, "line %d\n", i)
	}
	require.Equal(t, lines.String(), string(stream), "the recorder saw every write")

	rendered := 0
	for i, s := range sinks {
		require.NoError(t, errs[i], "join %d", i)
		require.False(t, returned[i].After(deadlines[i].Add(50*time.Millisecond)),
			"join %d returned %v after its deadline", i, returned[i].Sub(deadlines[i]))
		require.Equal(t, 1, attachedTimes(w, s), "join %d", i)
		got := s.bytes()
		if len(got) > 0 && got[0] == '<' {
			rendered++
			end := bytes.IndexByte(got, '>')
			h := end - 1 // the render is "<" + the stream up to the handoff + ">"
			require.Equal(t, string(stream[:h]), string(got[1:end]), "join %d", i)
			require.Equal(t, string(stream[h:]), string(got[end+1:]), "join %d: the gap, then live output", i)
			continue
		}
		require.Equal(t, string(stream), string(got), "join %d: today's replay, then live output", i)
	}
	reasons := fallbacks.all()
	require.Len(t, reasons, joins-rendered)
	for _, err := range reasons {
		require.ErrorIs(t, err, ErrReplayDeadline)
	}
	require.GreaterOrEqual(t, rendered, 1)
	require.LessOrEqual(t, rendered, 5, "five 200 ms emulations fill the 1 s deadline")
	t.Logf("%d joins attached by render, %d fell back; %d lines; slowest write %v", rendered, len(reasons), out.lines, out.slowest)
}

// Through the real fallback and the real Restore: candidates {none: 8, e1: 4,
// e2: 12} by eviction, CSI 2;6r evicted, ResizeEnd(e1, true) with e2 still
// tentative ("none" gone; 2;4 and 2;6 remain). A join falls back
// (ErrReplayMarginsUncertain); the joiner's first bytes are Snapshot with CSI
// 2;6r (the newest surviving candidate, e2's), then the ring. Then Shutdown:
// the guest's reset contains ESC[r.
func TestRawFallbackAfterAPartialCommitment(t *testing.T) {
	r := &fakeReplayer{}
	w, fallbacks := joinable(16, r)
	resize(w, rows(8))
	write(w, 1)
	e1 := w.ResizeBegin(rows(4))
	write(w, 1)
	w.ResizeBegin(rows(12))
	writeString(w, "\x1b[2;6r")
	write(w, 16)
	w.ResizeEnd(e1, true)

	guest := resetBuffer{&bytes.Buffer{}}
	require.NoError(t, w.AppendSized(t.Context(), far(), at80x24, guest))
	require.Equal(t, []error{ErrReplayMarginsUncertain}, fallbacks.all())
	require.Zero(t, r.starts())
	require.Equal(t, "\x1b[2;6r"+strings.Repeat("x", 16), guest.String())

	before := guest.Len()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, w.Shutdown(ctx))
	require.Contains(t, guest.String()[before:], "\x1b[r")
}

// The same after an overflow: 17 tentative events crossed, then CSI 2;6r at
// the fallback's height (the 17th's): the joiner's Snapshot carries the
// fallback's region, and Shutdown's reset contains ESC[r. Every event then
// commits, so the size log covers the ring and only the tracker's overflow
// decides the fallback.
func TestRawFallbackAfterAnOverflow(t *testing.T) {
	r := &fakeReplayer{}
	w, fallbacks := joinable(16, r)
	resize(w, rows(8))
	var seqs []uint64
	for i := range maxUnresolvedResizes + 1 {
		write(w, 1)
		seqs = append(seqs, w.ResizeBegin(rows(10+i)))
	}
	writeString(w, "\x1b[2;6r") // 2;6 at the 17th's 26 rows
	write(w, 16)
	for _, seq := range seqs {
		w.ResizeEnd(seq, true)
	}
	_, err := coverageAtStart(w)
	require.NoError(t, err)

	guest := resetBuffer{&bytes.Buffer{}}
	require.NoError(t, w.AppendSized(t.Context(), far(), at80x24, guest))
	require.Equal(t, []error{ErrReplayMarginsUncertain}, fallbacks.all())
	require.Zero(t, r.starts())
	require.Equal(t, "\x1b[2;6r"+strings.Repeat("x", 16), guest.String())

	before := guest.Len()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, w.Shutdown(ctx))
	require.Contains(t, guest.String()[before:], "\x1b[r")
}

// Both wait sites must dispatch to the writer whose join is waiting. A hook
// installed on a different writer must never receive its permit/resize/output.
func TestJoinWaitHookBelongsToItsWriter(t *testing.T) {
	for _, what := range []joinWait{waitPermit, waitResize, waitOutput} {
		t.Run(fmt.Sprint(what), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := NewMultiWriter(1), NewMultiWriter(1)
				aWaits, bWaits := joinWaits(t, a), joinWaits(t, b)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan struct{})
				t.Cleanup(func() { cancel(); <-done })
				if what == waitPermit {
					a.permit <- struct{}{}
				}
				go func() {
					defer close(done)
					if what == waitPermit {
						_ = a.take(ctx, time.Now().Add(time.Second))
						return
					}
					j := join{t: a, ctx: ctx, deadline: time.Now().Add(time.Second)}
					j.wait(what, make(chan struct{}))
				}()
				require.Equal(t, what, settledReplay(t, aWaits, "writer A's wait"))
				require.Empty(t, bWaits, "writer B must not observe writer A's wait")
				cancel()
			})
		})
	}
}
