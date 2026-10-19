package io

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

// The AsyncWriter tests run in a synctest bubble, where time is fake: it moves
// only when every goroutine in the bubble is blocked. synctest.Wait returns
// once the drain, and every other goroutine the test started, has done all it
// can without the clock moving. So what the drain does in answer to a call is
// asserted right after a Wait, and so is what it must not do.

// recordingWriter accumulates what it is given. The drain runs on its own
// goroutine, so every field is read under the mutex.
type recordingWriter struct {
	mu      sync.Mutex
	written []byte
	sizes   []int
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.written = append(r.written, p...)
	r.sizes = append(r.sizes, len(p))
	return len(p), nil
}

func (r *recordingWriter) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.written)
}

func (r *recordingWriter) writeSizes() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.sizes)
}

// gateWriter models a guest whose SSH channel window has filled: every Write
// blocks until the test releases it. entered closes on the first Write so a
// test can wait for the drain to actually be inside the writer rather than for
// its goroutine to be scheduled.
type gateWriter struct {
	recordingWriter
	once    sync.Once
	entered chan struct{}
	release chan struct{}
	opened  sync.Once
}

func newGateWriter() *gateWriter {
	return &gateWriter{entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *gateWriter) Write(p []byte) (int, error) {
	g.once.Do(func() { close(g.entered) })
	<-g.release
	return g.recordingWriter.Write(p)
}

// open releases every Write, held or still to come. A test in a bubble also
// passes it to startAsyncWriter, which opens it when the test ends, so a
// failed assertion doesn't leave the drain parked in Write and synctest.Test
// waiting for it; opening twice is fine.
func (g *gateWriter) open() { g.opened.Do(func() { close(g.release) }) }

// pieceGate counts Write entries and parks only on the first one, so a test
// can observe that no second piece ever started while the first is still
// parked. Counting entries rather than completions is what makes that
// observable: a gate that counted completions could not tell "one write,
// still in flight" from "one write, already returned".
type pieceGate struct {
	recordingWriter
	entries int32
	entered chan struct{}
	release chan struct{}
	opened  sync.Once
}

func newPieceGate() *pieceGate {
	return &pieceGate{entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *pieceGate) Write(p []byte) (int, error) {
	if atomic.AddInt32(&g.entries, 1) == 1 {
		close(g.entered)
		<-g.release
	}
	return g.recordingWriter.Write(p)
}

// open releases the first Write, as gateWriter's open does; opening twice is
// fine.
func (g *pieceGate) open() { g.opened.Do(func() { close(g.release) }) }

// maxWrites is how many writes one test's drain may make before the test
// fails. The most any test here needs is fifty, one per byte written.
const maxWrites = 100

// startAsyncWriter starts an AsyncWriter delivering to w. When the test ends,
// it calls each release, which opens a fake writer the drain may be parked
// in, and then closes the writer.
//
// A broken drain can write in a loop at one fake instant, and fake time
// doesn't move while it does, so the test would hang rather than fail. So past
// maxWrites writes, the sink fails the test and parks the write until the test
// ends, then fails the write. Parked, the drain is durably blocked, so the
// test's own assertions run and report; failed, the write ends the drain.
// Once the test's context is done, the test may have completed, and failing a
// completed test panics, so then the write only fails.
//
// The teardown is ordered so that the drain can still exit when Close is
// broken in either of two ways; otherwise synctest.Test would find the bubble
// deadlocked and panic, which stops the whole test binary. The releases come
// before Close, so a Close that waits for the drain, as it must not, still
// returns. And Close is what wakes an idle drain to exit; should it not,
// nothing else would, so the teardown wakes the drain as well.
func startAsyncWriter(t *testing.T, w io.Writer, max int, onDrop func(error), releases ...func()) *AsyncWriter {
	a := NewAsyncWriter(&cappedWriter{t: t, w: w}, max, onDrop)
	t.Cleanup(func() {
		for _, release := range releases {
			release()
		}
		_ = a.Close()
		a.mu.Lock()
		a.cond.Broadcast()
		a.mu.Unlock()
	})
	return a
}

// cappedWriter passes up to maxWrites writes through to w.
type cappedWriter struct {
	t      *testing.T
	w      io.Writer
	writes atomic.Int32
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	n := c.writes.Add(1)
	if n <= maxWrites {
		return c.w.Write(p)
	}
	if err := c.t.Context().Err(); err != nil {
		return 0, err
	}
	if n == maxWrites+1 {
		c.t.Errorf("the drain made %d writes, more than any test here needs: it is likely looping", n)
	}
	<-c.t.Context().Done()
	return 0, errors.New("the drain made too many writes")
}

// fired reports whether ch has been closed, without waiting for it.
func fired(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// requireEntered settles the bubble and requires the drain to be parked inside
// the writer that entered belongs to. Receiving from entered instead would
// deadlock the bubble if the drain never got there, and the deadlock panic
// would stop the whole test binary, not only fail this test.
func requireEntered(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	synctest.Wait() // the drain has reached the writer and is parked in it
	require.True(t, fired(entered), "the drain never reached the writer")
}

// closeWithoutWaiting closes a while the test holds its drain in a write, and
// requires Close to return without waiting for the drain, which is what
// TestAsyncWriterCloseDoesNotWaitAndStopsTheDrain asserts, and without an
// error, which msgAndArgs describe. Closing on the test's goroutine instead, a
// Close that waited would deadlock the bubble, and the deadlock panic would
// stop the whole test binary, not only fail this test.
func closeWithoutWaiting(t *testing.T, a *AsyncWriter, msgAndArgs ...any) {
	t.Helper()
	closed := make(chan error, 1)
	go func() { closed <- a.Close() }()
	synctest.Wait() // Close has returned, or is waiting for the drain
	select {
	case err := <-closed:
		require.NoError(t, err, msgAndArgs...)
	default:
		t.Fatal("Close waited for a drain held in a write")
	}
}

// The property the whole change rests on: the fan-out hands off instead of
// waiting for a guest that has stopped reading.
func TestAsyncWriterWriteDoesNotBlockOnStuckWriter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, nil, gate.open)

		_, err := a.Write([]byte("first"))
		require.NoError(t, err)
		requireEntered(t, gate.entered) // the drain is now blocked inside the writer

		done := make(chan struct{})
		go func() {
			defer close(done)
			for range 100 {
				_, _ = a.Write([]byte("more output"))
			}
		}()

		synctest.Wait() // the writes have returned, or are blocked behind the writer
		require.True(t, fired(done), "Write blocked behind a stuck writer")
	})
}

func TestAsyncWriterDeliversInOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rec := &recordingWriter{}
		a := startAsyncWriter(t, rec, DefaultGuestBufferSize, nil)

		var want []byte
		for i := range 50 {
			p := []byte{byte('a' + i%26)}
			want = append(want, p...)
			_, err := a.Write(p)
			require.NoError(t, err)
		}

		synctest.Wait() // the drain has delivered everything and is idle
		require.Equal(t, want, rec.bytes(), "bytes should arrive in order and intact")
	})
}

// io.Copy reuses its buffer, so a sink that retained p would corrupt output for
// every attached guest the moment the copy looped.
func TestAsyncWriterCopiesTheCallersBuffer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, nil, gate.open)

		buf := []byte("original")
		_, err := a.Write(buf)
		require.NoError(t, err)
		copy(buf, "OVERWRIT")

		gate.open()
		synctest.Wait() // the drain has delivered the write and is idle
		require.Equal(t, "original", string(gate.bytes()), "the sink must not alias the caller's buffer")
	})
}

func TestAsyncWriterOverflowDropsOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		drops := make(chan error, 4)
		a := startAsyncWriter(t, gate, 16, func(err error) { drops <- err }, gate.open)

		_, err := a.Write([]byte("12345678"))
		require.NoError(t, err)
		requireEntered(t, gate.entered)

		// The first 8 bytes are in flight, so the cap applies to what follows.
		_, err = a.Write([]byte("12345678"))
		require.NoError(t, err)
		_, err = a.Write([]byte("123456789"))
		require.ErrorIs(t, err, ErrOverflow, "writing past the cap must fail")

		synctest.Wait() // onDrop has run
		select {
		case err := <-drops:
			require.ErrorIs(t, err, ErrOverflow)
		default:
			t.Fatal("onDrop never fired")
		}

		_, err = a.Write([]byte("x"))
		require.ErrorIs(t, err, ErrOverflow, "the error must be sticky")

		synctest.Wait() // a second onDrop, had the sticky error started one, has run
		select {
		case err := <-drops:
			t.Fatalf("onDrop fired more than once: %v", err)
		default:
		}
	})
}

// Flush reports nil for a sink that has already failed, so a caller that needs
// to know whether what it wrote was delivered has to ask Err as well.
func TestAsyncWriterErrReportsTheTerminalError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		a := startAsyncWriter(t, gate, 16, nil, gate.open)
		require.NoError(t, a.Err(), "a healthy sink has no error")

		_, err := a.Write([]byte("12345678"))
		require.NoError(t, err)
		requireEntered(t, gate.entered)
		require.NoError(t, a.Err(), "in flight is not failed")

		_, err = a.Write([]byte("past the cap and then some"))
		require.ErrorIs(t, err, ErrOverflow)
		require.ErrorIs(t, a.Err(), ErrOverflow)

		// And Flush still says nothing is coming, which is the whole point.
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		require.NoError(t, a.Flush(ctx))
	})
}

// onDrop runs on the pty copy's behalf, so it must never be able to hold it up.
func TestAsyncWriterSlowDropCallbackDoesNotBlockWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		blocked := make(chan struct{})
		t.Cleanup(func() { close(blocked) })
		a := startAsyncWriter(t, gate, 8, func(error) { <-blocked }, gate.open)

		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = a.Write([]byte("0123456789"))
		}()

		synctest.Wait() // the write has returned, or is blocked behind onDrop
		require.True(t, fired(done), "Write blocked behind onDrop")
	})
}

func TestAsyncWriterUnderlyingErrorIsTreatedAsADrop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		drops := make(chan error, 1)
		a := startAsyncWriter(t, &failingWriter{}, DefaultGuestBufferSize, func(err error) { drops <- err })

		_, err := a.Write([]byte("output"))
		require.NoError(t, err, "the failure surfaces on the drain, not this write")

		synctest.Wait() // the drain has failed on the write, and onDrop has run
		select {
		case err := <-drops:
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrOverflow)
		default:
			t.Fatal("onDrop never fired for an underlying write error")
		}

		_, err = a.Write([]byte("more"))
		require.Error(t, err, "later writes must fail once the sink is dead")
	})
}

// MultiWriter treats a short write as a failed writer, and wrapping the guest
// in a sink must not quietly give that up: a writer that reports n < len(p)
// with no error would otherwise truncate the stream and stay attached.
func TestAsyncWriterShortWriteIsADrop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		drops := make(chan error, 1)
		a := startAsyncWriter(t, shortWriter{}, DefaultGuestBufferSize, func(err error) { drops <- err })

		_, err := a.Write([]byte("output"))
		require.NoError(t, err)

		synctest.Wait() // the drain has made the short write, and any onDrop has run
		select {
		case err := <-drops:
			require.ErrorIs(t, err, io.ErrShortWrite)
		default:
			t.Fatal("a short write was accepted as complete delivery")
		}
	})
}

// shortWriter accepts everything but the last byte, without reporting an error.
type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

// An idle drain has no I/O to fail, so Close is the only thing that can ever
// release it. This is the refused-attach path: the sink is built, the attach is
// rejected, and nothing was ever written.
//
// The drain parks on its cond before Close: had Close landed first, the drain
// would see it before parking and exit, and the test would pass even if Close
// never woke a parked drain.
func TestAsyncWriterCloseStopsAnIdleDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := startAsyncWriter(t, &recordingWriter{}, DefaultGuestBufferSize, nil)
		require.False(t, a.Closed())
		synctest.Wait() // the drain is parked on its cond, waiting for output
		require.False(t, a.stopped(), "the drain exited with nothing to stop it")

		require.NoError(t, a.Close())
		require.True(t, a.Closed(), "and it says so, since Flush will not")
		synctest.Wait() // the drain has woken, seen Close and returned
		require.True(t, a.stopped(), "an idle drain must exit on Close")
	})
}

// Close must not wait for the goroutine: in the case this whole change exists
// for, that goroutine is blocked in a write that only session teardown releases.
func TestAsyncWriterCloseDoesNotWaitAndStopsTheDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, nil, gate.open)

		_, err := a.Write([]byte("first"))
		require.NoError(t, err)
		requireEntered(t, gate.entered)

		done := make(chan struct{})
		go func() { defer close(done); _ = a.Close() }()
		synctest.Wait() // Close has returned, or is waiting for the drain
		require.True(t, fired(done), "Close waited for a goroutine blocked in a write")

		_, err = a.Write([]byte("after close"))
		require.ErrorIs(t, err, ErrWriterClosed)
		closeWithoutWaiting(t, a, "Close must be repeatable")

		gate.open()     // release the in-flight write
		synctest.Wait() // the write has returned, and the drain has seen Close
		require.True(t, a.stopped(), "the drain goroutine must exit")
	})
}

func TestAsyncWriterCoalescesUpToTheChunkCap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, nil, gate.open)

		_, err := a.Write([]byte("first"))
		require.NoError(t, err)
		requireEntered(t, gate.entered) // the drain holds "first"; everything below queues behind it

		// 32 KiB blocks would arrive one by one whether or not the drain coalesced
		// them, now that pieces are themselves capped at maxDrainWrite (32 KiB), so
		// 1 KiB blocks are what makes coalescing into fewer, larger writes
		// observable here.
		block := bytes.Repeat([]byte("y"), 1<<10)
		const blocks = 256 // 256 KiB, four chunks' worth
		for range blocks {
			_, err := a.Write(block)
			require.NoError(t, err)
		}

		gate.open()
		synctest.Wait() // the drain has delivered everything queued and is idle
		wantLen := len("first") + blocks*len(block)
		require.Equal(t, wantLen, len(gate.bytes()), "everything queued must be delivered")

		sizes := gate.writeSizes()
		require.Less(t, len(sizes), blocks/8, "queued writes should coalesce, not arrive one by one")
		for _, n := range sizes {
			require.LessOrEqual(t, n, maxDrainWrite, "no write may exceed the piece cap")
		}
	})
}

// The property piece delivery rests on: a chunk larger than maxDrainWrite must
// still reach the writer as multiple bounded pieces rather than one large one.
func TestAsyncWriterWritesInPiecesOfAtMostMaxDrainWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, nil, gate.open)

		_, err := a.Write([]byte("first"))
		require.NoError(t, err)
		requireEntered(t, gate.entered) // the drain holds "first"; everything below queues behind it

		const total = 256 << 10
		block := bytes.Repeat([]byte("p"), 32<<10)
		for written := 0; written < total; written += len(block) {
			_, err := a.Write(block)
			require.NoError(t, err)
		}

		gate.open()
		synctest.Wait() // the drain has delivered everything queued and is idle
		wantLen := len("first") + total
		require.Equal(t, wantLen, len(gate.bytes()), "everything queued must be delivered")

		sizes := gate.writeSizes()
		for _, n := range sizes {
			require.LessOrEqual(t, n, maxDrainWrite, "no write may exceed the piece cap")
		}
		// More than one write per chunk (256 KiB / maxDrainChunk chunks, plus the
		// initial "first") is what shows chunks are actually split into pieces,
		// rather than merely bounded at the existing chunk cap.
		require.Greater(t, len(sizes), 1+total/maxDrainChunk,
			"a chunk must be split into more than one piece")
	})
}

// Close's promise is that the drain exits when its in-flight write returns:
// once closed, no second piece of the chunk already being delivered may start.
func TestAsyncWriterStopsBetweenPiecesWhenClosed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newPieceGate()
		onDrop := make(chan error, 1)
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, func(err error) { onDrop <- err }, gate.open)

		// One chunk, exactly two pieces: the first parks in the gate.
		_, err := a.Write(bytes.Repeat([]byte("q"), maxDrainChunk))
		require.NoError(t, err)
		requireEntered(t, gate.entered)

		closeWithoutWaiting(t, a)
		gate.open()

		synctest.Wait() // the first piece has returned, the drain has seen Close, and any onDrop has run
		require.True(t, a.stopped(), "the drain must exit once its in-flight piece returns")
		require.EqualValues(t, 1, atomic.LoadInt32(&gate.entries),
			"a second piece must never start once Close has happened")

		select {
		case err := <-onDrop:
			t.Fatalf("Close must never invoke onDrop: %v", err)
		default:
		}
	})
}

// AbortIfNoProgress fails the writer exactly as an overflow or a write error
// does: the drain must not start another piece of the chunk in flight.
func TestAsyncWriterStopsBetweenPiecesWhenAborted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newPieceGate()
		onDrop := make(chan error, 1)
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, func(err error) { onDrop <- err }, gate.open)

		_, err := a.Write(bytes.Repeat([]byte("q"), maxDrainChunk))
		require.NoError(t, err)
		requireEntered(t, gate.entered)

		require.True(t, a.AbortIfNoProgress(0, ErrStalled))
		gate.open()

		synctest.Wait() // the first piece has returned, the drain has seen the abort, and onDrop has run
		require.True(t, a.stopped(), "the drain must exit once its in-flight piece returns")
		require.EqualValues(t, 1, atomic.LoadInt32(&gate.entries),
			"a second piece must never start once aborted")

		select {
		case err := <-onDrop:
			require.ErrorIs(t, err, ErrStalled)
		default:
			t.Fatal("onDrop never fired")
		}
	})
}

// Backlog.Bytes counts the undelivered rest of the chunk in flight, not just
// pending: a caller pacing on this writer needs to know about output that has
// already left pending but has not yet reached the underlying writer.
func TestAsyncWriterBacklogCountsTheUndeliveredChunk(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		step := newStepWriter()
		a := startAsyncWriter(t, step, DefaultGuestBufferSize, nil, step.open)

		const total = 100 << 10
		_, err := a.Write(bytes.Repeat([]byte("d"), total))
		require.NoError(t, err)

		backlog := a.Backlog()
		require.Equal(t, total, backlog.Bytes)
		require.EqualValues(t, 0, backlog.Delivered)
		require.True(t, backlog.Live)

		// stepWriter.release settles the bubble after the write lands, so deliver
		// has already counted the piece, and closed the Progress channel taken
		// before releasing, by the time it returns.
		progress := backlog.Progress
		step.release(t)
		require.True(t, fired(progress), "Progress never closed after a piece was delivered")

		backlog = a.Backlog()
		require.EqualValues(t, maxDrainWrite, backlog.Delivered)
		require.Equal(t, total-maxDrainWrite, backlog.Bytes)
	})
}

// A caller waiting on Progress must be released whether the writer stops by
// Close or by abort, and a Backlog taken afterwards must report dead rather
// than hand out a channel nothing will ever signal again.
func TestAsyncWriterBacklogReleasesWaitersWhenItStops(t *testing.T) {
	for _, tc := range []struct {
		name string
		stop func(t *testing.T, a *AsyncWriter)
	}{
		{"close", func(t *testing.T, a *AsyncWriter) { closeWithoutWaiting(t, a) }},
		{"abort", func(_ *testing.T, a *AsyncWriter) { a.AbortIfNoProgress(0, ErrStalled) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				gate := newGateWriter()
				a := startAsyncWriter(t, gate, DefaultGuestBufferSize, nil, gate.open)

				_, err := a.Write([]byte("first"))
				require.NoError(t, err)
				requireEntered(t, gate.entered)

				progress := a.Backlog().Progress
				tc.stop(t, a)

				synctest.Wait() // whatever the stop releases has been released
				require.True(t, fired(progress), "a waiter on Progress was never released")

				require.False(t, a.Backlog().Live)
				require.True(t, fired(a.Backlog().Progress), "a dead writer must hand out an already-closed Progress")
			})
		})
	}
}

// AbortIfNoProgress must only fail the writer when Delivered has not moved
// since the caller's snapshot, and must never invoke onDrop a second time.
//
// The case that matters is a piece landing after the snapshot was taken: the
// abort must be refused even though since is not "stale" in the sense of
// being ahead of Delivered. The condition is "Delivered == since", not "since
// is not greater than Delivered" — an implementation that refused only when
// since > delivered would still abort a guest that made progress after the
// pacer's last look.
func TestAsyncWriterAbortIfNoProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		step := newStepWriter()
		drops := make(chan error, 4)
		a := startAsyncWriter(t, step, DefaultGuestBufferSize, func(err error) { drops <- err }, step.open)

		// More than maxDrainWrite, so a piece can land while the chunk still has a
		// piece left in flight.
		_, err := a.Write(bytes.Repeat([]byte("d"), 100<<10))
		require.NoError(t, err)

		before := a.Backlog()
		require.EqualValues(t, 0, before.Delivered)

		require.False(t, a.AbortIfNoProgress(1, ErrStalled), "a since ahead of Delivered must not abort")
		require.True(t, a.Backlog().Live, "a refused abort must leave the writer live")

		// stepWriter.release settles the bubble after the write lands, so deliver
		// has already counted the piece, and closed the Progress channel taken
		// before releasing, by the time it returns.
		step.release(t)
		require.True(t, fired(before.Progress), "Progress never closed after a piece was delivered")

		require.False(t, a.AbortIfNoProgress(before.Delivered, ErrStalled),
			"a piece delivered after the snapshot must refuse the abort")
		require.True(t, a.Backlog().Live, "a refused abort must leave the writer live")

		require.True(t, a.AbortIfNoProgress(a.Backlog().Delivered, ErrStalled), "the current Delivered count must abort")

		synctest.Wait() // onDrop has run
		select {
		case err := <-drops:
			require.ErrorIs(t, err, ErrStalled)
		default:
			t.Fatal("onDrop never fired")
		}

		_, err = a.Write([]byte("more"))
		require.ErrorIs(t, err, ErrStalled, "writes after an abort must fail with its error")

		require.False(t, a.AbortIfNoProgress(0, ErrStalled), "a second call on a dead writer must not abort again")
		synctest.Wait() // a second onDrop, had that call started one, has run
		select {
		case err := <-drops:
			t.Fatalf("onDrop fired a second time: %v", err)
		default:
		}
	})
}

// An abort with a nil error must still end the writer. A writer counts as
// failed only once it holds a non-nil error, so passing nil through would
// discard the queue and spend onDrop while leaving the writer live, accepting
// writes, and its drain still running.
func TestAsyncWriterAbortIfNoProgressTreatsANilErrorAsStalled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		drops := make(chan error, 2)
		a := startAsyncWriter(t, &recordingWriter{}, DefaultGuestBufferSize, func(err error) { drops <- err })

		require.True(t, a.AbortIfNoProgress(a.Backlog().Delivered, nil))
		require.False(t, a.Backlog().Live, "an abort with a nil error left the writer live")
		require.ErrorIs(t, a.Err(), ErrStalled)

		_, err := a.Write([]byte("more"))
		require.ErrorIs(t, err, ErrStalled, "writes after the abort must fail with its error")

		synctest.Wait() // onDrop has run, and the drain has seen the abort
		select {
		case err := <-drops:
			require.ErrorIs(t, err, ErrStalled)
		default:
			t.Fatal("onDrop never fired")
		}
		require.True(t, a.stopped(), "the drain outlived the abort")
	})
}

// A burst that has been fully delivered must not leave its backing array behind
// for the rest of the session.
//
// The assertion is that pending is nil, not that its capacity is small, because
// capacity is not what holds the memory. Advancing past the bytes taken shrinks
// length and capacity but leaves the slice pointing inside the array append
// grew, and Go frees an allocation only as a whole. Under this burst, written
// the way io.Copy writes it, re-slicing alone ends at 72 KiB of capacity with
// 589 KiB still resident; dropping the slice returns all but 5 KiB. A nil slice
// holds no pointer, so nil is the release.
func TestAsyncWriterReleasesPendingBufferWhenItCatchesUp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, nil, gate.open)

		_, err := a.Write([]byte("first"))
		require.NoError(t, err)
		requireEntered(t, gate.entered) // the drain is parked in the writer, so the burst piles up behind it

		// Written at io.Copy's chunk size rather than in one call: growing by
		// repeated append is what leaves pending owning an array far larger than the
		// bytes it still owes.
		block := bytes.Repeat([]byte("z"), 32<<10)
		for written := 0; written < 512<<10; written += len(block) {
			_, err = a.Write(block)
			require.NoError(t, err)
		}

		gate.open()
		synctest.Wait() // the drain has delivered the burst and is idle
		a.mu.Lock()
		released := a.pending == nil
		a.mu.Unlock()
		require.True(t, released, "a one-off burst must not be retained for the session")
	})
}

// Close discards what it never delivered, and discarding means releasing: a
// sink closed mid-burst that stayed reachable — through a deferred Close, or a
// caller still holding it — would otherwise pin the whole buffer.
func TestAsyncWriterCloseReleasesUndeliveredOutput(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, nil, gate.open)

		_, err := a.Write([]byte("first"))
		require.NoError(t, err)
		requireEntered(t, gate.entered) // the drain is parked, so nothing below is delivered

		_, err = a.Write(bytes.Repeat([]byte("z"), 512<<10))
		require.NoError(t, err)

		closeWithoutWaiting(t, a)

		a.mu.Lock()
		defer a.mu.Unlock()
		// Compared rather than passed to require.Nil: the failure is a held buffer,
		// and require.Nil would render every byte of it.
		require.True(t, a.pending == nil, "Close must release the output it discards")
	})
}

// The drain's chunk must stay a bounded buffer of its own rather than a window
// into pending: `a.chunk = a.pending[:n]` would keep the guest's whole grown
// array — up to max — reachable for as long as the write is in flight, which is
// the memory term the 64 KiB cap exists to bound.
//
// This pins memory, not content. Delivered bytes cannot be rewritten under the
// writer either way: pending only ever advances past the bytes taken, so every
// later append lands beyond the range a window would cover. A content
// comparison therefore cannot tell a copy from a window — capacity can.
func TestAsyncWriterChunkStaysABoundedBuffer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, nil, gate.open)

		// A burst far larger than one chunk, so a windowing takeChunk would inherit
		// a correspondingly large capacity.
		const burst = 512 << 10
		_, err := a.Write(bytes.Repeat([]byte("a"), burst))
		require.NoError(t, err)
		requireEntered(t, gate.entered) // the drain is inside Write, holding the first chunk

		a.mu.Lock()
		chunkCap := cap(a.chunk)
		a.mu.Unlock()
		require.Equal(t, maxDrainChunk, chunkCap,
			"the chunk must not inherit pending's backing array")

		gate.open()
		synctest.Wait() // the drain has delivered the burst and is idle
		require.Equal(t, burst, len(gate.bytes()), "all bytes delivered")
	})
}

func TestAsyncWriterFlushReturnsWhenIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := startAsyncWriter(t, &recordingWriter{}, DefaultGuestBufferSize, nil)

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		require.NoError(t, a.Flush(ctx), "an idle sink flushes immediately")
	})
}

func TestAsyncWriterFlushWaitsForDelivery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, nil, gate.open)

		_, err := a.Write([]byte("tail of the session"))
		require.NoError(t, err)
		requireEntered(t, gate.entered)

		ctx := t.Context()
		flushed := make(chan error, 1)
		go func() { flushed <- a.Flush(ctx) }()

		synctest.Wait() // Flush is parked, waiting for the drain to catch up
		select {
		case err := <-flushed:
			t.Fatalf("Flush returned before delivery completed: %v", err)
		default:
		}

		gate.open()
		synctest.Wait() // the write has landed, the drain has caught up, and Flush has returned
		select {
		case err := <-flushed:
			require.NoError(t, err)
			require.Equal(t, "tail of the session", string(gate.bytes()))
		default:
			t.Fatal("Flush never returned after delivery")
		}
	})
}

// A stuck guest must not hold up shutdown: Flush gives up at its context's
// deadline, and not before it. The relationship: the 100 ms deadline < when
// the sink drains, which is never while the test runs, since its write is held
// until the test ends.
func TestAsyncWriterFlushGivesUpOnAStuckSink(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, nil, gate.open)

		_, err := a.Write([]byte("never delivered"))
		require.NoError(t, err)
		requireEntered(t, gate.entered)

		const deadline = 100 * time.Millisecond
		ctx, cancel := context.WithTimeout(t.Context(), deadline)
		defer cancel()
		flushed := make(chan error, 1)
		go func() { flushed <- a.Flush(ctx) }()

		time.Sleep(deadline - time.Nanosecond)
		synctest.Wait() // everything due before the deadline has run
		select {
		case err := <-flushed:
			t.Fatalf("Flush gave up before its deadline: %v", err)
		default:
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait() // the deadline has passed, and Flush has seen it
		select {
		case err := <-flushed:
			require.ErrorIs(t, err, context.DeadlineExceeded, "a stuck guest must not hold up shutdown")
		default:
			t.Fatal("Flush didn't give up at its deadline: a stuck guest would hold up shutdown")
		}
	})
}

// stepWriter delivers one write per token, so a test can park the drain at a
// chosen point in a backlog and observe what has and has not been delivered
// while it is standing still.
type stepWriter struct {
	recordingWriter
	step      chan struct{}
	unblocked chan struct{}
	opened    sync.Once
}

func newStepWriter() *stepWriter {
	return &stepWriter{step: make(chan struct{}), unblocked: make(chan struct{})}
}

func (s *stepWriter) Write(p []byte) (int, error) {
	select {
	case <-s.step:
	case <-s.unblocked:
	}
	return s.recordingWriter.Write(p)
}

// open lets every write through from then on, so a drain parked mid-backlog
// can finish and exit. A test passes it to startAsyncWriter, which opens it
// when the test ends; opening twice is fine.
func (s *stepWriter) open() { s.opened.Do(func() { close(s.unblocked) }) }

// release lets exactly one write through and reports the running total once it
// has landed. It settles the bubble on both sides: before, so the drain is
// parked at its next write; after, so the write has landed, deliver has
// counted it, and the drain is parked again or idle. It reports what landed
// rather than checking an expected size: the drain coalesces whatever is
// pending when it takes a chunk, so how the backlog divides into writes is not
// fixed.
func (s *stepWriter) release(t *testing.T) int {
	t.Helper()
	before := len(s.bytes())
	synctest.Wait() // the drain is parked at its next write, if it has one
	select {
	case s.step <- struct{}{}:
	default:
		t.Fatal("the drain never reached its next write")
	}
	synctest.Wait() // the write has landed, and the drain is parked at its next one or idle
	after := len(s.bytes())
	require.Greater(t, after, before, "the released write never landed")
	return after
}

// Flush must not return until a whole backlog has been delivered, not merely
// until the write that was in flight when it was called returns.
//
// The observation point is the whole test. Releasing the backlog all at once
// proves nothing: the drain finishes it before the bubble settles, so a Flush
// that returned far too early still looks correct by the time an assertion
// runs. Stepping one write at a time and asserting while the drain is parked
// is what makes an early return observable.
//
// Two mechanisms hold the contract up: the drain publishes idle only on the
// pass that finds pending empty, and Flush re-checks the condition rather than
// trusting a single wake-up. Either alone is sufficient, so no single mutation
// fails this — it guards the contract, not one of its two supports.
func TestAsyncWriterFlushSpansAMultiChunkBacklog(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		step := newStepWriter()
		a := startAsyncWriter(t, step, DefaultGuestBufferSize, nil, step.open)

		// One small write to park the drain, then four chunks' worth behind it at
		// io.Copy's write size, so delivery provably takes more than one pass.
		const blocks = 8
		block := bytes.Repeat([]byte("x"), 32<<10)
		_, err := a.Write([]byte("first"))
		require.NoError(t, err)
		for range blocks {
			_, err := a.Write(block)
			require.NoError(t, err)
		}
		total := len("first") + blocks*len(block)

		ctx := t.Context()
		flushed := make(chan error, 1)
		go func() { flushed <- a.Flush(ctx) }()

		// Step the backlog through one write at a time, and after every write that
		// leaves something owed, require that Flush is still waiting. Checking only
		// once would not do it: an early return can come at the end of any pass
		// through the backlog, and a single check looks at only one of them.
		// Each release settles the bubble, Flush included, before it returns.
		delivered := step.release(t)
		require.Less(t, delivered, total, "the backlog must not fit in one write")
		for delivered < total {
			select {
			case err := <-flushed:
				t.Fatalf("Flush returned with %d of %d bytes delivered: %v", delivered, total, err)
			default:
			}
			delivered = step.release(t)
		}

		select {
		case err := <-flushed:
			require.NoError(t, err)
		default:
			t.Fatal("Flush never returned after the backlog drained")
		}

		// Compared as a count: the failure is a short delivery, and asserting on the
		// bytes themselves would render a quarter of a megabyte.
		require.Equal(t, total, len(step.bytes()),
			"Flush returned with part of the backlog still undelivered")
		require.Greater(t, len(step.writeSizes()), 1,
			"the backlog must have taken more than one pass, or this proves nothing")
	})
}

func TestAsyncWriterFlushAfterCloseReturnsImmediately(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, nil, gate.open)

		_, err := a.Write([]byte("discarded"))
		require.NoError(t, err)
		requireEntered(t, gate.entered)
		closeWithoutWaiting(t, a)

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		require.NoError(t, a.Flush(ctx))
	})
}

// Drained is the news that Flush waits for, and it has to arrive whether
// delivery caught up or gave up: the host's elector watches a client that was
// too far behind to be promoted, and a client that is never coming back has to
// wake it too, or the wait is a goroutine held to the end of the session.
func TestAsyncWriterDrainedReportsCatchingUp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, nil, gate.open)

		_, err := a.Write([]byte("queued"))
		require.NoError(t, err)
		requireEntered(t, gate.entered)

		drained, ok := a.Drained()
		require.True(t, ok, "a live writer reports a signal to wait on")
		synctest.Wait() // the drain is still parked in the write
		require.False(t, fired(drained), "reported drained while a write was still in flight")

		gate.open()
		synctest.Wait() // the write has landed and the drain has caught up
		require.True(t, fired(drained), "never reported drained after delivery completed")
	})
}

func TestAsyncWriterDrainedWakesOnClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := newGateWriter()
		a := startAsyncWriter(t, gate, DefaultGuestBufferSize, nil, gate.open)

		_, err := a.Write([]byte("never delivered"))
		require.NoError(t, err)
		requireEntered(t, gate.entered)

		drained, ok := a.Drained()
		require.True(t, ok)
		closeWithoutWaiting(t, a)
		synctest.Wait() // whatever Close releases has been released
		require.True(t, fired(drained), "a closed writer left a waiter with nothing to wake it")

		// And afterwards there is no signal left to hand out: the channel the
		// close published is spent, and the one that replaced it is closed by
		// nothing.
		_, ok = a.Drained()
		require.False(t, ok, "a closed writer must not hand out a signal that never fires")
	})
}

func TestAsyncWriterDrainedWakesOnFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := startAsyncWriter(t, &failingWriter{}, DefaultGuestBufferSize, nil)

		drained, ok := a.Drained()
		require.True(t, ok)

		_, err := a.Write([]byte("undeliverable"))
		require.NoError(t, err, "the failure is the delivery's, not the caller's")
		synctest.Wait() // the drain has failed on the write
		require.True(t, fired(drained), "a failed writer left a waiter with nothing to wake it")

		_, ok = a.Drained()
		require.False(t, ok, "a failed writer must not hand out a signal that never fires")
	})
}
