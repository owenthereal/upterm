package io

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/owenthereal/upterm/internal/termsize"
)

var (
	at80x24  = termsize.Size{Cols: 80, Rows: 24}
	at45x30  = termsize.Size{Cols: 45, Rows: 30}
	at100x40 = termsize.Size{Cols: 100, Rows: 40}
)

// resize reports a resize whose ioctl succeeded, as the pty does.
func resize(w *MultiWriter, size termsize.Size) {
	w.ResizeEnd(w.ResizeBegin(size), true)
}

// write writes n bytes of plain text, whose content no size test cares about.
func write(w *MultiWriter, n int) {
	_, _ = w.Write([]byte(strings.Repeat("x", n)))
}

// withLog runs f on w's size log with writeMu held, once what was reported
// since the last hold is applied: how every capture and release reads it.
func withLog(w *MultiWriter, f func(l *sizeLog, start uint64)) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	w.applyResize()
	f(&w.sizes, w.buffer.Start())
}

func coverageAt(w *MultiWriter, start uint64) (events []SizeEvent, err error) {
	withLog(w, func(l *sizeLog, _ uint64) { events, err = l.covering(start) })
	return events, err
}

func coverageAtStart(w *MultiWriter) (events []SizeEvent, err error) {
	withLog(w, func(l *sizeLog, start uint64) { events, err = l.covering(start) })
	return events, err
}

func loggedAfter(w *MultiWriter, seq uint64) (events []SizeEvent) {
	withLog(w, func(l *sizeLog, _ uint64) { events = l.after(seq) })
	return events
}

func lossCount(w *MultiWriter) (n uint64) {
	withLog(w, func(l *sizeLog, _ uint64) { n = l.losses() })
	return n
}

func unresolved(w *MultiWriter) (offset, seq uint64, ok bool) {
	withLog(w, func(l *sizeLog, _ uint64) { offset, seq, ok = l.firstUnresolved() })
	return offset, seq, ok
}

func requireOpen(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
		t.Fatal("closed before the event's outcome was recorded")
	default:
	}
}

func requireClosed(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	default:
		t.Fatal("still open")
	}
}

// ResizeBegin(45x30), a Write, ResizeEnd(false): no event; covering(0) is
// the 80x24 event alone, so the write counts at 80x24.
func TestAFailedResizeIsNoEvent(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	resize(w, at80x24)

	seq := w.ResizeBegin(at45x30)
	write(w, 5)
	w.ResizeEnd(seq, false)

	want := []SizeEvent{{Seq: 1, Offset: 0, Size: at80x24}}
	events, err := coverageAt(w, 0)
	require.NoError(t, err)
	require.Equal(t, want, events)
	require.Equal(t, want, loggedAfter(w, 0))
	_, _, ok := unresolved(w)
	require.False(t, ok)
}

// 80 → 45 → 80 before any write: three committed events at one offset,
// in Seq order.
func TestEventsKeepTheirOrderAtOneOffset(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	resize(w, at80x24)
	resize(w, at45x30)
	resize(w, at80x24)

	// Applied as a capture applies them, before any write.
	require.Equal(t, []SizeEvent{
		{Seq: 1, Offset: 0, Size: at80x24},
		{Seq: 2, Offset: 0, Size: at45x30},
		{Seq: 3, Offset: 0, Size: at80x24},
	}, loggedAfter(w, 0))

	// The one in effect at 0 is the last of them.
	events, err := coverageAt(w, 0)
	require.NoError(t, err)
	require.Equal(t, []SizeEvent{{Seq: 3, Offset: 0, Size: at80x24}}, events)

	// Inside the ring, where an emulation has a screen for 45 to truncate,
	// the Write that places them keeps all three too.
	write(w, 1)
	resize(w, at45x30)
	resize(w, at80x24)
	resize(w, at45x30)
	write(w, 1)
	require.Equal(t, []SizeEvent{
		{Seq: 3, Offset: 0, Size: at80x24},
		{Seq: 4, Offset: 1, Size: at45x30},
		{Seq: 5, Offset: 1, Size: at80x24},
		{Seq: 6, Offset: 1, Size: at45x30},
	}, loggedAfter(w, 0))
}

// A writer parked inside Write (a gated sink) holds writeMu; ResizeBegin
// and ResizeEnd both return within 50 ms.
func TestResizeReportsNeverWaitOnWriteMu(t *testing.T) {
	stuck := newBlockingWriter()
	w := NewMultiWriter(DefaultReplayBytes)
	resize(w, at80x24)
	require.NoError(t, w.Append(stuck))

	wrote := make(chan struct{})
	go func() { defer close(wrote); _, _ = w.Write([]byte("output")) }()
	<-stuck.entered

	begun, ended := make(chan uint64, 1), make(chan struct{})
	go func() {
		defer close(ended)
		seq := w.ResizeBegin(at45x30)
		begun <- seq
		w.ResizeEnd(seq, true)
	}()

	var seq uint64
	select {
	case seq = <-begun:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("ResizeBegin waited on a Write parked in a stopped writer")
	}
	select {
	case <-ended:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("ResizeEnd waited on a Write parked in a stopped writer")
	}
	select {
	case <-wrote:
		t.Fatal("the Write was not parked, so writeMu was never held")
	default:
	}

	close(stuck.release)
	<-wrote

	// The parked Write had taken its bytes before the report, so the event
	// lands after them.
	require.Equal(t, []SizeEvent{
		{Seq: 1, Offset: 0, Size: at80x24},
		{Seq: seq, Offset: uint64(len("output")), Size: at45x30},
	}, loggedAfter(w, 0))
}

// ResizeBegin, a Write (the event is stamped at the write's offset), then
// ResizeEnd(true): the event's offset is where the write began.
func TestATentativeEventIsStampedAtTheNextWrite(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	resize(w, at80x24)
	write(w, 3)

	seq := w.ResizeBegin(at45x30)
	write(w, 4)

	// Logged, but not offered to anyone until it is decided.
	offset, first, ok := unresolved(w)
	require.True(t, ok)
	require.Equal(t, uint64(3), offset)
	require.Equal(t, seq, first)
	require.Equal(t, []SizeEvent{{Seq: 1, Offset: 0, Size: at80x24}}, loggedAfter(w, 0))

	w.ResizeEnd(seq, true)
	require.Equal(t, []SizeEvent{
		{Seq: 1, Offset: 0, Size: at80x24},
		{Seq: seq, Offset: 3, Size: at45x30},
	}, loggedAfter(w, 0))
	_, _, ok = unresolved(w)
	require.False(t, ok)
}

// 65 reports with no Write between: covering fails until a later committed
// event and the ring evicting past the loss.
func TestAQueueOverflowMakesCoverageIncomplete(t *testing.T) {
	w := NewMultiWriter(16)
	resize(w, at80x24)
	write(w, 1)

	// 64 fit, which is the queue's bound, not one fewer.
	for i := range 64 {
		resize(w, []termsize.Size{at45x30, at80x24}[i%2])
	}
	write(w, 1)
	require.Zero(t, lossCount(w))
	_, err := coverageAtStart(w)
	require.NoError(t, err)

	for i := range 65 {
		resize(w, []termsize.Size{at45x30, at80x24}[i%2])
	}
	write(w, 1)
	require.Equal(t, uint64(1), lossCount(w))
	_, err = coverageAtStart(w)
	require.ErrorIs(t, err, ErrReplayCoverage)

	// The ring evicting past the loss alone is not enough.
	write(w, 32)
	_, err = coverageAtStart(w)
	require.ErrorIs(t, err, ErrReplayCoverage)

	resize(w, at100x40)
	write(w, 1)
	_, err = coverageAtStart(w)
	require.ErrorIs(t, err, ErrReplayCoverage, "the ring still starts before the event that closes the loss")

	write(w, 32)
	events, err := coverageAtStart(w)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, at100x40, events[0].Size)
	require.Equal(t, uint64(1), lossCount(w), "losses counts what was lost, ever")
}

// A 0x0 resize committed: covering across it fails; a valid one after it
// restores coverage from there.
func TestAnInvalidSizeIsUnknown(t *testing.T) {
	for _, unknown := range []termsize.Size{{}, {Cols: 0, Rows: 24}, {Cols: 80, Rows: 0}} {
		t.Run(unknown.String(), func(t *testing.T) {
			w := NewMultiWriter(DefaultReplayBytes)
			resize(w, at80x24)
			write(w, 4)
			resize(w, unknown)
			write(w, 4)

			for _, start := range []uint64{0, 4, 6} {
				_, err := coverageAt(w, start)
				require.ErrorIs(t, err, ErrReplayCoverage, "start %d", start)
			}

			resize(w, at45x30)
			write(w, 4)
			_, err := coverageAt(w, 0)
			require.ErrorIs(t, err, ErrReplayCoverage, "across the unknown event")
			events, err := coverageAt(w, 8)
			require.NoError(t, err)
			require.Equal(t, []SizeEvent{{Seq: 3, Offset: 8, Size: at45x30}}, events)
		})
	}
}

// The last logged size is 80x24; a committed resize to 45x30 is
// lost (queue overflow); no resize follows; the ring evicts far past the
// loss: covering(Start) still fails (it must not pick 80x24). Then a
// committed 45x30 event and the ring evicting past it: covering succeeds.
func TestALossStaysOpenUntilAKnownSizeFollows(t *testing.T) {
	w := NewMultiWriter(16)
	resize(w, at80x24)
	write(w, 1)

	// Failed resizes fill the queue and are never logged, so 80x24 stays the
	// last size logged, and the committed 45x30 after them has no room.
	for range 64 {
		w.ResizeEnd(w.ResizeBegin(at45x30), false)
	}
	resize(w, at45x30)
	write(w, 1)
	require.Equal(t, uint64(1), lossCount(w))
	require.Equal(t, []SizeEvent{{Seq: 1, Offset: 0, Size: at80x24}}, loggedAfter(w, 0))

	write(w, 1000)
	_, err := coverageAtStart(w)
	require.ErrorIs(t, err, ErrReplayCoverage, "the pty was at 45x30, not 80x24")

	resize(w, at45x30)
	write(w, 1)
	_, err = coverageAtStart(w)
	require.ErrorIs(t, err, ErrReplayCoverage)

	write(w, 16)
	want := []SizeEvent{{Seq: 67, Offset: 1002, Size: at45x30}}
	events, err := coverageAtStart(w)
	require.NoError(t, err)
	require.Equal(t, want, events)
	require.Equal(t, want, loggedAfter(w, 0), "80x24 is superseded, so forgotten")
}

// Pinned(80x24): one event; later reports are ignored.
func TestPinnedRecordsOneEvent(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	withLog(w, func(l *sizeLog, _ uint64) { require.False(t, l.pinned()) })

	w.Pinned(at80x24)
	seq := w.ResizeBegin(at45x30)
	require.Zero(t, seq)
	requireClosed(t, w.sizes.wait(seq))
	w.ResizeEnd(seq, true)
	write(w, 3)
	resize(w, at45x30)
	w.Pinned(at45x30)
	write(w, 3)

	want := []SizeEvent{{Seq: 1, Offset: 0, Size: at80x24}}
	require.Equal(t, want, loggedAfter(w, 0))
	events, err := coverageAt(w, 0)
	require.NoError(t, err)
	require.Equal(t, want, events)
	events, err = coverageAtStart(w)
	require.NoError(t, err)
	require.Equal(t, want, events)
	_, _, ok := unresolved(w)
	require.False(t, ok)
	withLog(w, func(l *sizeLog, _ uint64) { require.True(t, l.pinned()) })
}

// A tentative event, then enough output that the ring evicts past
// it: covering(Start) fails until its ResizeEnd; then it succeeds, from
// the committed size or the one before, by the outcome.
func TestCoveringFailsWhileATentativeEventPrecedesStart(t *testing.T) {
	for _, applied := range []bool{true, false} {
		t.Run(fmt.Sprintf("applied=%t", applied), func(t *testing.T) {
			w := NewMultiWriter(16)
			resize(w, at80x24)
			write(w, 1)
			seq := w.ResizeBegin(at45x30)
			write(w, 1)

			// Past the ring's start, it decides nothing yet, and is not offered.
			events, err := coverageAtStart(w)
			require.NoError(t, err)
			require.Equal(t, []SizeEvent{{Seq: 1, Offset: 0, Size: at80x24}}, events)

			write(w, 32)
			_, err = coverageAtStart(w)
			require.ErrorIs(t, err, ErrReplayCoverage)

			w.ResizeEnd(seq, applied)
			want := []SizeEvent{{Seq: 1, Offset: 0, Size: at80x24}}
			if applied {
				want = []SizeEvent{{Seq: seq, Offset: 1, Size: at45x30}}
			}
			events, err = coverageAtStart(w)
			require.NoError(t, err)
			require.Equal(t, want, events)
		})
	}
}

// A join waits on a tentative event outside writeMu, so the channel has to
// close on the outcome itself, whichever it is and wherever the event is.
func TestWaitClosesOnEitherOutcome(t *testing.T) {
	for _, applied := range []bool{true, false} {
		for _, logged := range []bool{true, false} {
			t.Run(fmt.Sprintf("applied=%t,logged=%t", applied, logged), func(t *testing.T) {
				w := NewMultiWriter(DefaultReplayBytes)
				seq := w.ResizeBegin(at45x30)
				done := w.sizes.wait(seq)
				requireOpen(t, done)
				if logged {
					write(w, 1)
					requireOpen(t, done)
					requireOpen(t, w.sizes.wait(seq))
				}

				w.ResizeEnd(seq, applied)
				requireClosed(t, done)
				requireClosed(t, w.sizes.wait(seq))
			})
		}
	}

	t.Run("nothing to wait for", func(t *testing.T) {
		w := NewMultiWriter(DefaultReplayBytes)
		for range 64 {
			w.ResizeBegin(at45x30)
		}
		lost := w.ResizeBegin(at45x30)
		requireClosed(t, w.sizes.wait(lost))
		requireClosed(t, w.sizes.wait(0))
		requireClosed(t, w.sizes.wait(lost+1))
		requireOpen(t, w.sizes.wait(lost-1))
	})
}

// The log's own bound: past 1,024 events it drops the oldest committed one,
// and coverage before the event after it is lost with it.
func TestALogOverflowDropsTheOldestCommittedEvent(t *testing.T) {
	sizeAt := func(i int) termsize.Size { return termsize.Size{Cols: 10 + i%100, Rows: 24} }

	t.Run("committed", func(t *testing.T) {
		w := NewMultiWriter(DefaultReplayBytes)
		for i := range 1025 {
			resize(w, sizeAt(i))
			write(w, 1)
		}
		require.Equal(t, uint64(1), lossCount(w))

		events := loggedAfter(w, 0)
		require.Len(t, events, 1024)
		require.Equal(t, SizeEvent{Seq: 2, Offset: 1, Size: sizeAt(1)}, events[0])
		_, err := coverageAt(w, 0)
		require.ErrorIs(t, err, ErrReplayCoverage)
		events, err = coverageAt(w, 1)
		require.NoError(t, err)
		require.Len(t, events, 1024)
	})

	t.Run("a tentative event is kept over a committed one", func(t *testing.T) {
		w := NewMultiWriter(DefaultReplayBytes)
		seq := w.ResizeBegin(at80x24)
		write(w, 1)
		for i := range 1024 {
			resize(w, sizeAt(i))
			write(w, 1)
		}
		require.Equal(t, uint64(1), lossCount(w))

		offset, first, ok := unresolved(w)
		require.True(t, ok)
		require.Equal(t, uint64(0), offset)
		require.Equal(t, seq, first)
		events := loggedAfter(w, 0)
		require.Len(t, events, 1023)
		require.Equal(t, uint64(3), events[0].Seq)
	})

	t.Run("with none committed, the oldest goes, and its wait with it", func(t *testing.T) {
		w := NewMultiWriter(DefaultReplayBytes)
		var seqs []uint64
		var waiting <-chan struct{}
		for i := range 1025 {
			seqs = append(seqs, w.ResizeBegin(at45x30))
			if i == 0 {
				waiting = w.sizes.wait(seqs[0])
			}
			write(w, 1)
		}
		require.Equal(t, uint64(1), lossCount(w))
		requireClosed(t, waiting)
		requireClosed(t, w.sizes.wait(seqs[0]))
		requireOpen(t, w.sizes.wait(seqs[1]))

		offset, first, ok := unresolved(w)
		require.True(t, ok)
		require.Equal(t, uint64(1), offset)
		require.Equal(t, seqs[1], first)

		// Its outcome, arriving after, finds nothing to apply.
		w.ResizeEnd(seqs[0], true)
		require.Empty(t, loggedAfter(w, 0))
	})
}

// resolved is the outcome as ResizeEnd recorded it, before apply has applied
// it, for an eviction that reaches the event in between.
func TestResolvedReportsTheRecordedOutcome(t *testing.T) {
	w := NewMultiWriter(DefaultReplayBytes)
	resolvedNow := func(seq uint64) (committed, deleted bool) {
		w.writeMu.Lock()
		defer w.writeMu.Unlock()
		return w.sizes.resolved(seq)
	}
	type outcome struct{ committed, deleted bool }
	requireOutcome := func(want outcome, seq uint64, msg string) {
		t.Helper()
		committed, deleted := resolvedNow(seq)
		require.Equal(t, want, outcome{committed, deleted}, msg)
	}

	kept, failed := w.ResizeBegin(at80x24), w.ResizeBegin(at45x30)
	write(w, 1)
	requireOutcome(outcome{}, kept, "tentative")
	requireOutcome(outcome{}, failed, "tentative")

	w.ResizeEnd(kept, true)
	w.ResizeEnd(failed, false)
	requireOutcome(outcome{committed: true}, kept, "recorded, not yet applied")
	requireOutcome(outcome{deleted: true}, failed, "recorded, not yet applied")

	write(w, 1)
	requireOutcome(outcome{committed: true}, kept, "applied")
	requireOutcome(outcome{}, failed, "applied, so no longer held")

	queued := w.ResizeBegin(at45x30)
	requireOutcome(outcome{}, queued, "queued")
	w.ResizeEnd(queued, true)
	requireOutcome(outcome{committed: true}, queued, "queued, recorded")
}
