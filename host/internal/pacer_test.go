package internal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/owenthereal/upterm/host/internal/replay"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/require"
)

// ptyWriteSize is io.Copy's buffer, so the largest write the pty copy makes,
// and also the largest piece a guest's sink hands its link. The tests produce
// in it.
const ptyWriteSize = 32 << 10

// meteredWriter takes every to deliver each write and counts what it was
// given: a link draining steadily at a known rate.
type meteredWriter struct {
	every   time.Duration
	release chan struct{}
	n       atomic.Int64
}

func newMeteredWriter(t *testing.T, every time.Duration) *meteredWriter {
	t.Helper()
	m := &meteredWriter{every: every, release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(m.release) })
	t.Cleanup(release)
	return m
}

func (m *meteredWriter) Write(p []byte) (int, error) {
	timer := time.NewTimer(m.every)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-m.release:
	}
	m.n.Add(int64(len(p)))
	return len(p), nil
}

// steppedLink delivers exactly one piece per releasePiece. entered reports a
// link write waiting for permission; releaseAll also frees a failing test.
type steppedLink struct {
	entered  <-chan struct{}
	entering chan struct{}
	piece    chan struct{}
	all      chan struct{}
	once     sync.Once
	n        atomic.Int64
}

func newSteppedLink(t *testing.T) *steppedLink {
	t.Helper()
	entered := make(chan struct{}, 1)
	l := &steppedLink{entered: entered, entering: entered, piece: make(chan struct{}, 1), all: make(chan struct{})}
	t.Cleanup(l.releaseAll)
	return l
}

func (l *steppedLink) Write(b []byte) (int, error) {
	select {
	case l.entering <- struct{}{}:
	case <-l.all:
	}
	select {
	case <-l.piece:
	case <-l.all:
	}
	l.n.Add(int64(len(b)))
	return len(b), nil
}

func (l *steppedLink) releasePiece() bool {
	select {
	case <-l.entered:
		l.piece <- struct{}{}
		return true
	default:
		return false
	}
}

func (l *steppedLink) releaseAll() { l.once.Do(func() { close(l.all) }) }

// windowWriter accepts budget bytes at once and then blocks until release is
// closed: a newcomer's fresh SSH windows, followed by never reading. Only the
// sink's drain writes to it, so budget needs no lock.
type windowWriter struct {
	budget  int
	release chan struct{}
}

func (w *windowWriter) Write(p []byte) (int, error) {
	if w.budget <= 0 {
		<-w.release
	}
	w.budget -= len(p)
	return len(p), nil
}

// stuckSink is a guest's sink over a link that delivers nothing until the test
// ends.
func stuckSink(t *testing.T, onDrop func(error)) *uio.AsyncWriter {
	t.Helper()
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	var sink *uio.AsyncWriter
	t.Cleanup(func() {
		if sink != nil {
			_ = sink.Close()
		}
		release()
	})
	sink = uio.NewAsyncWriter(&gatedWriter{gate: gate, rec: &recordingWriter{}}, uio.DefaultGuestBufferSize, onDrop)
	return sink
}

// newTestPacer returns a pacer over a fresh fan-out with the stall timeout set
// to stall.
func newTestPacer(t *testing.T, stall time.Duration) (*guestPacer, *uio.MultiWriter) {
	t.Helper()
	return newTestPacerWithContext(t, t.Context(), stall)
}

// newTestPacerWithContext is newTestPacer for a test that ends the pacer's
// context itself.
func newTestPacerWithContext(t *testing.T, ctx context.Context, stall time.Duration) (*guestPacer, *uio.MultiWriter) {
	t.Helper()
	writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
	return newGuestPacer(ctx, writers, stall), writers
}

// attachPaced attaches sink as HandleSession does: registered with the pacer
// and appended to the fan-out in one transaction, and taken out of both on the
// way out.
func attachPaced(t *testing.T, p *guestPacer, writers *uio.MultiWriter, sink *uio.AsyncWriter) {
	t.Helper()
	require.NoError(t, p.attach(t.Context(), sink, func() error { return attachGuestOutput(t.Context(), time.Time{}, writers, sink, termsize.Size{}) }))
	t.Cleanup(func() {
		writers.Remove(sink)
		p.remove(sink)
		_ = sink.Close()
	})
}

// attachStuck attaches a guest that delivers nothing and puts it past the low
// mark, so the pacer holds the next write for as long as that guest paces.
func attachStuck(t *testing.T, p *guestPacer, writers *uio.MultiWriter) *uio.AsyncWriter {
	t.Helper()
	sink := stuckSink(t, nil)
	attachPaced(t, p, writers, sink)
	_, err := writers.Write(make([]byte, 2*pacingLowWater))
	require.NoError(t, err)
	return sink
}

// goWrite runs writes on a goroutine of its own and returns a channel closed
// when it returns. Its cleanup releases the pacer and joins the goroutine, so
// a test that fails part-way still has nothing writing by the time its
// cleanups restore what the pacer reads.
func goWrite(t *testing.T, p *guestPacer, writes func()) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() {
		p.release()
		<-done
	})
	go func() {
		defer close(done)
		writes()
	}()
	return done
}

// produce writes n bytes through p in pty-sized writes.
func produce(p *guestPacer, n int) {
	piece := make([]byte, ptyWriteSize)
	for ; n > 0; n -= len(piece) {
		_, _ = p.Write(piece)
	}
}

// requireHeld settles a bubble and checks both observable backpressure and
// the producer still being pending.
func requireHeld(t *testing.T, p *guestPacer, done <-chan struct{}) {
	t.Helper()
	synctest.Wait()
	require.Positive(t, p.waiting.Load(), "the write was never held")
	requirePending(t, done, "the write returned instead of being held")
}

// requireReturns fails, rather than hangs, if what is behind done has not
// returned within d.
func requireReturns(t *testing.T, done <-chan struct{}, d time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("still waiting after %v", d)
	}
}

// requireCompleted checks an immediate consequence without advancing time.
func requireCompleted(t *testing.T, done <-chan struct{}) {
	t.Helper()
	synctest.Wait()
	select {
	case <-done:
	default:
		t.Fatal("the write did not return")
	}
}

func requirePending(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
		t.Fatal(what)
	default:
	}
}

// awaitErr settles a bubble and requires the attach to have returned.
func awaitErr(t *testing.T, ch <-chan error) error {
	t.Helper()
	synctest.Wait()
	select {
	case err := <-ch:
		return err
	default:
		t.Fatal("the attach did not return")
		return nil
	}
}

// registered is how many guests the pacer holds in its order.
func registered(p *guestPacer) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.guests)
}

// fakePaced is a pacing sink whose every abort loses to a piece that landed
// first: AbortIfNoProgress delivers a piece, signals it and refuses. A real
// sink loses that race only by chance; this one loses it on demand.
type fakePaced struct {
	mu        sync.Mutex
	bytes     int
	delivered uint64
	progress  chan struct{}
	refused   int
}

func newFakePaced(bytes int) *fakePaced {
	return &fakePaced{bytes: bytes, progress: make(chan struct{})}
}

func (f *fakePaced) Backlog() uio.Backlog {
	f.mu.Lock()
	defer f.mu.Unlock()
	return uio.Backlog{Bytes: f.bytes, Delivered: f.delivered, Progress: f.progress, Live: true}
}

func (f *fakePaced) AbortIfNoProgress(uint64, error) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refused++
	f.delivered++
	f.signal()
	return false
}

// drain empties the backlog, which is what lets a held write go.
func (f *fakePaced) drain() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bytes = 0
	f.signal()
}

func (f *fakePaced) refusals() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refused
}

// signal must be called with f.mu held.
func (f *fakePaced) signal() {
	close(f.progress)
	f.progress = make(chan struct{})
}

// With nothing to pace on — no guest, a primary, a release, or an ended
// context — a write goes straight through, even with a stuck guest attached.
// The control shows that the same stuck guest holds it otherwise, so the
// others pass for the reason they name.
func TestGuestPacerPassesThroughWhenNothingPaces(t *testing.T) {
	t.Run("control", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			piece := make([]byte, ptyWriteSize)
			p, writers := newTestPacer(t, time.Minute)
			attachStuck(t, p, writers)
			done := goWrite(t, p, func() { _, _ = p.Write(piece) })
			requireHeld(t, p, done)
			p.release()
			requireCompleted(t, done)
		})
	})
	t.Run("no guests", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			piece := make([]byte, ptyWriteSize)
			p, _ := newTestPacer(t, time.Minute)
			done := goWrite(t, p, func() { _, _ = p.Write(piece) })
			requireCompleted(t, done)
		})
	})
	t.Run("primary", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			piece := make([]byte, ptyWriteSize)
			p, writers := newTestPacer(t, time.Minute)
			attachStuck(t, p, writers)
			p.setPrimary(true)
			done := goWrite(t, p, func() { _, _ = p.Write(piece) })
			requireCompleted(t, done)
		})
	})
	t.Run("released", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			piece := make([]byte, ptyWriteSize)
			p, writers := newTestPacer(t, time.Minute)
			attachStuck(t, p, writers)
			p.release()
			done := goWrite(t, p, func() { _, _ = p.Write(piece) })
			requireCompleted(t, done)
		})
	})
	t.Run("context cancelled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			piece := make([]byte, ptyWriteSize)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			p, writers := newTestPacerWithContext(t, ctx, time.Minute)
			attachStuck(t, p, writers)
			cancel()
			done := goWrite(t, p, func() { _, _ = p.Write(piece) })
			requireCompleted(t, done)
		})
	})
}

// The earliest guest sets the rate and a faster one follows it. At one 32 KiB
// piece per 10 ms, the first guest has to deliver all of 2 MiB but the low
// mark and a write before the last write goes out: about 60 pieces, 600 ms.
// Unpaced, or paced by the faster guest, the same 2 MiB goes by in a fraction
// of the 500 ms asserted below and overflows the first guest's 1 MiB on the
// way.
func TestGuestPacerHoldsOutputToTheEarliestGuest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, writers := newTestPacer(t, time.Minute)
		first := uio.NewAsyncWriter(newMeteredWriter(t, 10*time.Millisecond), uio.DefaultGuestBufferSize, nil)
		attachPaced(t, p, writers, first)
		second := uio.NewAsyncWriter(io.Discard, uio.DefaultGuestBufferSize, nil)
		attachPaced(t, p, writers, second)
		done := goWrite(t, p, func() { produce(p, 2<<20) })
		requireHeld(t, p, done)
		// About 60 pieces at 10 ms: the 2 MiB burst cannot finish in 500 ms.
		time.Sleep(500*time.Millisecond - time.Nanosecond)
		requireHeld(t, p, done)
		time.Sleep(200*time.Millisecond + time.Nanosecond)
		requireCompleted(t, done)
		require.Positive(t, p.holds.Load(), "no write was ever held")
		require.True(t, first.Backlog().Live, "the pacing guest was dropped")
		require.True(t, second.Backlog().Live, "the following guest was dropped")
	})
}

// The failure that decided the policy. A guest joining under backpressure
// starts with fresh SSH windows, megabytes of them, so for its first few
// megabytes it takes output faster than any guest already reading — even when
// it never reads at all. Were the fastest guest to pace, the newcomer would
// take over, the output would run at its windows' speed, and the established
// guest would overflow. The earliest paces instead: the newcomer overflows,
// and the established guest receives every byte.
//
// Backpressure is observed before the newcomer joins, not assumed: joined
// together at the start, both guests would begin with fresh windows and the
// two policies would look alike.
//
// The established link delivers a piece only after the test observes a held
// producer. If a newcomer takes over, no further established pieces are
// released, so the finite burst overflows the guest that should have paced.
func TestGuestPacerANonReadingNewcomerCannotDisplaceThePacer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, writers := newTestPacer(t, time.Minute)
		link := newSteppedLink(t)
		established := uio.NewAsyncWriter(link, uio.DefaultGuestBufferSize, nil)
		attachPaced(t, p, writers, established)
		backpressure := goWrite(t, p, func() { produce(p, 2<<20) })
		requireHeld(t, p, backpressure)
		// Delivery happens only while the established guest observably holds output.
		drainHeld := func(done <-chan struct{}) {
			for {
				synctest.Wait()
				select {
				case <-done:
					return
				default:
				}
				require.Positive(t, p.waiting.Load(), "the write was never held")
				requirePending(t, done, "the write returned instead of being held")
				require.True(t, established.Backlog().Live, "the newcomer displaced the established guest")
				require.True(t, link.releasePiece(), "the established link had no piece to deliver")
			}
		}
		drainHeld(backpressure)
		require.GreaterOrEqual(t, p.holds.Load(), int64(8), "the established guest did not hold output back")
		newcomerLink := &windowWriter{budget: 4 << 20, release: make(chan struct{})}
		t.Cleanup(func() { close(newcomerLink.release) })
		newcomer := uio.NewAsyncWriter(newcomerLink, uio.DefaultGuestBufferSize, nil)
		attachPaced(t, p, writers, newcomer)
		// The 8 MiB burst exceeds the newcomer's 4 MiB windows plus its queue.
		burst := goWrite(t, p, func() { produce(p, 8<<20) })
		drainHeld(burst)
		require.True(t, established.Backlog().Live, "the newcomer displaced the established guest")
		require.False(t, newcomer.Backlog().Live, "a newcomer that never reads outlasted its windows and its cap")
		require.ErrorIs(t, newcomer.Err(), uio.ErrOverflow)
		link.releaseAll()
		flush(t, established)
		require.Equal(t, int64(10<<20), link.n.Load(), "the established guest missed output")
	})
}

// A pacer that inherits a backlog — here from a primary that left while it
// was behind — is dropped only for delivering nothing, never for how long the
// backlog takes. 768 KiB at one piece per 100 ms is more than two seconds,
// ten stall timeouts, with a piece landing every half a timeout.
func TestGuestPacerLetsAPacerWorkThroughAnInheritedBacklog(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, writers := newTestPacer(t, 200*time.Millisecond)
		guest := uio.NewAsyncWriter(newMeteredWriter(t, 100*time.Millisecond), uio.DefaultGuestBufferSize, nil)
		attachPaced(t, p, writers, guest)
		p.setPrimary(true)
		_, err := p.Write(make([]byte, 768<<10))
		require.NoError(t, err)
		p.setPrimary(false)
		start := time.Now()
		done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
		requireHeld(t, p, done)
		// 768 KiB needs 23 pieces to get below 64 KiB: 2.3 s > ten 200 ms stalls.
		// Every 100 ms piece is progress within half a stall interval.
		for step := 1; step <= 23; step++ {
			time.Sleep(100 * time.Millisecond)
			synctest.Wait()
			require.True(t, guest.Backlog().Live, "a pacer delivering steadily was dropped as stalled at step %d", step)
			if step < 23 {
				requireHeld(t, p, done)
			}
		}
		requireCompleted(t, done)
		require.Greater(t, time.Since(start), 2*time.Second, "the write did not wait for the inherited backlog")
		time.Sleep(200 * time.Millisecond)
		flush(t, guest)
	})
}

// A pacer delivering nothing drops at 200 ms, and its successor must still
// drain the inherited 256 KiB below the low mark before output resumes.
func TestGuestPacerDropsAPacerThatDeliversNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, writers := newTestPacer(t, 200*time.Millisecond)
		dropped := make(chan error, 1)
		stuck := stuckSink(t, func(err error) { dropped <- err })
		attachPaced(t, p, writers, stuck)
		link := newSteppedLink(t)
		next := uio.NewAsyncWriter(link, uio.DefaultGuestBufferSize, nil)
		attachPaced(t, p, writers, next)
		_, err := p.Write(make([]byte, 256<<10))
		require.NoError(t, err)
		start := time.Now()
		done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
		requireHeld(t, p, done)
		// No progress: live at 200 ms-1 ns, dropped exactly at 200 ms.
		time.Sleep(200*time.Millisecond - time.Nanosecond)
		synctest.Wait()
		require.True(t, stuck.Backlog().Live, "the pacer was dropped before its stall deadline")
		requireHeld(t, p, done)
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		require.False(t, stuck.Backlog().Live, "the pacer was not dropped at its stall deadline")
		select {
		case err := <-dropped:
			require.ErrorIs(t, err, uio.ErrStalled)
		default:
			t.Fatal("the stuck guest was never dropped")
		}
		// The successor inherits all 256 KiB; the departure cannot open the gate.
		requireHeld(t, p, done)
		// At 100 ms per piece, draining the successor must still take at least 400 ms.
		for step := 1; step <= 7; step++ {
			time.Sleep(100 * time.Millisecond)
			require.True(t, link.releasePiece(), "the successor had no piece to deliver")
			synctest.Wait()
			require.True(t, next.Backlog().Live, "the next guest was dropped")
			if step < 7 {
				requireHeld(t, p, done)
			}
		}
		requireCompleted(t, done)
		require.GreaterOrEqual(t, time.Since(start), 400*time.Millisecond, "the write went out ahead of the next guest's inherited backlog")
	})
}

// When the pacer leaves, the next guest paces from its own backlog; the
// departure does not open the gate.
func TestGuestPacerHandsOverWhenThePacerLeaves(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, writers := newTestPacer(t, time.Minute)
		stuck := stuckSink(t, nil)
		attachPaced(t, p, writers, stuck)
		link := newSteppedLink(t)
		next := uio.NewAsyncWriter(link, uio.DefaultGuestBufferSize, nil)
		attachPaced(t, p, writers, next)
		_, err := p.Write(make([]byte, 256<<10))
		require.NoError(t, err)
		start := time.Now()
		done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
		requireHeld(t, p, done)
		p.remove(stuck)
		requireHeld(t, p, done)
		// Seven 32 KiB deliveries are needed to get the inherited 256 KiB below 64 KiB.
		// At 100 ms per piece, draining the successor must still take at least 400 ms.
		for step := 1; step <= 7; step++ {
			time.Sleep(100 * time.Millisecond)
			require.True(t, link.releasePiece(), "the successor had no piece to deliver")
			synctest.Wait()
			require.True(t, next.Backlog().Live, "the next guest was dropped")
			if step < 7 {
				requireHeld(t, p, done)
			}
		}
		requireCompleted(t, done)
		require.GreaterOrEqual(t, time.Since(start), 400*time.Millisecond, "the write went out ahead of the next guest's inherited backlog")
	})
}

// The deadline and a delivered piece can be ready together. The abort is
// decided against the count the pacer recorded, under the sink's own lock, so
// a piece that lands in between wins: the sink refuses, nobody is dropped, the
// write stays held and the deadline is armed again. Two refusals rather than
// one are what show the re-arming: the second deadline exists only if the
// pacer armed it after the first.
func TestGuestPacerProgressAtTheDeadlineCancelsTheAbort(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, _ := newTestPacer(t, 50*time.Millisecond)
		fake := newFakePaced(2 * pacingLowWater)
		require.NoError(t, p.attach(t.Context(), fake, func() error { return nil }))
		done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
		requireHeld(t, p, done)
		// Each 50 ms deadline loses to progress under the sink lock and rearms.
		for attempt := 1; attempt <= 2; attempt++ {
			time.Sleep(50*time.Millisecond - time.Nanosecond)
			synctest.Wait()
			require.Equal(t, attempt-1, fake.refusals(), "an abort was attempted before its deadline")
			requireHeld(t, p, done)
			time.Sleep(time.Nanosecond)
			synctest.Wait()
			require.Equal(t, attempt, fake.refusals(), "the pacer did not rearm its deadline")
			requireHeld(t, p, done)
		}
		fake.drain()
		requireCompleted(t, done)
	})
}

// Registration must precede publication: the ring is preloaded, appendFn is
// held after publishing the sink, and only then does a finite producer start.
// While attach is held, replay plus the low mark and one in-flight write bound
// the guest's exposure, even if the handler makes no further progress.
func TestGuestPacerRegistersAGuestBeforeItCanReceiveOutput(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, writers := newTestPacer(t, time.Minute)
		_, err := writers.Write(make([]byte, uio.DefaultReplayBytes))
		require.NoError(t, err)
		sink := stuckSink(t, nil)
		published, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		attached := make(chan error, 1)
		t.Cleanup(func() {
			once.Do(func() { close(release) })
			p.release()
			require.NoError(t, <-attached, "the attach failed once it was let finish")
			writers.Remove(sink)
			p.remove(sink)
			_ = sink.Close()
		})
		go func() {
			attached <- p.attach(t.Context(), sink, func() error {
				if err := attachGuestOutput(t.Context(), time.Time{}, writers, sink, termsize.Size{}); err != nil {
					return err
				}
				close(published)
				<-release
				return nil
			})
		}()
		awaitClosed(t, published, "the attach never published its sink")
		// Finite even if registration moves after append: 2 MiB can expose overflow.
		done := goWrite(t, p, func() { produce(p, 2<<20) })
		synctest.Wait()
		b := sink.Backlog()
		require.True(t, b.Live, "the guest overflowed while it was being attached")
		require.LessOrEqual(t, b.Bytes, uio.DefaultReplayBytes+pacingLowWater+2*ptyWriteSize, "the guest took output unpaced while it was being attached")
		requireHeld(t, p, done)
		once.Do(func() { close(release) })
		synctest.Wait()
		// End pacing explicitly: this sink intentionally delivers nothing.
		p.release()
		requireCompleted(t, done)
	})
}

// Attachments are one transaction each, serialised: B cannot attach while A is
// registered but not yet appended, so one guest at a time is being attached.
// And registration order is attachment order, so A, attached first, paces.
func TestGuestPacerSerialisesAttachments(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, writers := newTestPacer(t, time.Minute)
		a := stuckSink(t, nil)
		b := uio.NewAsyncWriter(io.Discard, uio.DefaultGuestBufferSize, nil)

		resume := make(chan struct{})
		var (
			resumeOnce sync.Once
			wg         sync.WaitGroup
		)
		t.Cleanup(func() {
			resumeOnce.Do(func() { close(resume) })
			wg.Wait()
			writers.Remove(a, b)
			p.remove(a)
			p.remove(b)
			_ = b.Close()
		})

		aErr := make(chan error, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			aErr <- p.attach(t.Context(), a, func() error {
				<-resume
				return attachGuestOutput(t.Context(), time.Time{}, writers, a, termsize.Size{})
			})
		}()
		synctest.Wait()
		require.Equal(t, 1, registered(p), "A was never registered")

		bErr := make(chan error, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			bErr <- p.attach(t.Context(), b, func() error { return attachGuestOutput(t.Context(), time.Time{}, writers, b, termsize.Size{}) })
		}()
		synctest.Wait()
		select {
		case err := <-bErr:
			t.Fatalf("B's attach returned (%v) while A was registered but not yet attached", err)
		default:
		}

		resumeOnce.Do(func() { close(resume) })
		require.NoError(t, awaitErr(t, aErr))
		require.NoError(t, awaitErr(t, bErr))

		_, err := writers.Write(make([]byte, 2*pacingLowWater))
		require.NoError(t, err)
		done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
		requireHeld(t, p, done)
		p.release()
		requireCompleted(t, done)
	})
}

// A guest waiting at the gate for another's attach stops waiting when it
// leaves: refused with its context's error, registered nowhere, its Append
// never run. The attach ahead of it keeps the gate, and the next one waits
// for it as before. An attach can hold the gate for a join's whole budget,
// emulating, and a guest that left behind it would otherwise wait it out.
func TestGuestPacerGateWaitsOnTheJoinersContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, writers := newTestPacer(t, time.Minute)
		a := uio.NewAsyncWriter(io.Discard, uio.DefaultGuestBufferSize, nil)
		b := uio.NewAsyncWriter(io.Discard, uio.DefaultGuestBufferSize, nil)
		c := uio.NewAsyncWriter(io.Discard, uio.DefaultGuestBufferSize, nil)
		t.Cleanup(func() {
			writers.Remove(a, c)
			p.remove(a)
			p.remove(c)
			_ = a.Close()
			_ = b.Close()
			_ = c.Close()
		})

		inside, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
		aErr := make(chan error, 1)
		go func() {
			aErr <- p.attach(t.Context(), a, func() error {
				close(inside)
				<-release
				return attachGuestOutput(t.Context(), time.Time{}, writers, a, termsize.Size{})
			})
		}()
		synctest.Wait()
		select {
		case <-inside:
		default:
			t.Fatal("A never took the gate")
		}

		left, leave := context.WithCancel(t.Context())
		var bRan atomic.Bool
		bErr := make(chan error, 1)
		go func() {
			bErr <- p.attach(left, b, func() error {
				bRan.Store(true)
				return nil
			})
		}()
		synctest.Wait()
		select {
		case err := <-bErr:
			t.Fatalf("B's attach returned (%v) while A held the gate", err)
		default:
		}
		leave()
		require.ErrorIs(t, awaitErr(t, bErr), context.Canceled, "B kept waiting after it left")
		require.False(t, bRan.Load(), "B attached after it left")
		require.Equal(t, 1, registered(p), "B was registered after it left")

		cErr := make(chan error, 1)
		go func() {
			cErr <- p.attach(t.Context(), c, func() error { return attachGuestOutput(t.Context(), time.Time{}, writers, c, termsize.Size{}) })
		}()
		synctest.Wait()
		select {
		case err := <-cErr:
			t.Fatalf("C's attach returned (%v) while A held the gate", err)
		default:
		}
		releaseOnce.Do(func() { close(release) })
		require.NoError(t, awaitErr(t, aErr))
		require.NoError(t, awaitErr(t, cErr))
		require.Equal(t, 2, registered(p))
	})
}

// A guest that has already left is refused even with the slot free: it is
// never registered and its Append never runs. Two hundred times, because a
// select between a free slot and a done context picks either at random, and
// a refusal that depended on it would pass by chance about half the time.
func TestGuestPacerRefusesAGuestThatHasAlreadyLeft(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, _ := newTestPacer(t, time.Minute)
		left, leave := context.WithCancel(t.Context())
		leave()
		for i := range 200 {
			sink := uio.NewAsyncWriter(io.Discard, uio.DefaultGuestBufferSize, nil)
			ran := false
			err := p.attach(left, sink, func() error {
				ran = true
				return nil
			})
			p.remove(sink)
			_ = sink.Close()
			require.ErrorIs(t, err, context.Canceled, "attempt %d", i)
			require.False(t, ran, "attempt %d: a guest that had left was attached", i)
		}
	})
}

// A failed Append takes its registration back out, or a guest that never
// joined would pace the session from then on. The sink is refused without
// being closed, unlike attachGuestOutput's refusal: a closed sink is skipped
// as dead anyway, which would hide a registration left behind.
func TestGuestPacerRollsBackAFailedAttach(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, _ := newTestPacer(t, time.Minute)
		sink := stuckSink(t, nil)
		_, err := sink.Write(make([]byte, 2*pacingLowWater))
		require.NoError(t, err)

		refuse := func() error { return uio.ErrClosed }
		require.ErrorIs(t, p.attach(t.Context(), sink, refuse), uio.ErrClosed)
		require.Zero(t, registered(p), "a failed attach left its guest registered")

		done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
		requireCompleted(t, done)

		// And the transaction's lock went with it.
		again := make(chan error, 1)
		go func() { again <- p.attach(t.Context(), sink, refuse) }()
		require.ErrorIs(t, awaitErr(t, again), uio.ErrClosed)
	})
}

// A held write wakes for anything that ends its reason to wait, not only for
// the pacer's progress.
func TestGuestPacerWakesAWaitingWrite(t *testing.T) {
	for _, tc := range []struct {
		name string
		wake func(p *guestPacer, pacer *uio.AsyncWriter, cancel context.CancelFunc)
	}{
		{"primary elected", func(p *guestPacer, _ *uio.AsyncWriter, _ context.CancelFunc) { p.setPrimary(true) }},
		{"pacer leaves", func(p *guestPacer, pacer *uio.AsyncWriter, _ context.CancelFunc) { p.remove(pacer) }},
		{"context cancelled", func(_ *guestPacer, _ *uio.AsyncWriter, cancel context.CancelFunc) { cancel() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				p, writers := newTestPacerWithContext(t, ctx, time.Minute)
				pacer := attachStuck(t, p, writers)

				done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
				requireHeld(t, p, done)
				tc.wake(p, pacer, cancel)
				requireCompleted(t, done)
			})
		})
	}
}

// The wait is outside the fan-out's lock and never takes the attach lock, so
// a guest can join while a write is held — and joins behind the pacer, so the
// write stays held.
func TestGuestPacerDoesNotHoldAnAttachBehindAGatedWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, writers := newTestPacer(t, time.Minute)
		attachStuck(t, p, writers)
		done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
		requireHeld(t, p, done)

		joiner := uio.NewAsyncWriter(io.Discard, uio.DefaultGuestBufferSize, nil)
		t.Cleanup(func() {
			writers.Remove(joiner)
			p.remove(joiner)
			_ = joiner.Close()
		})
		attached := make(chan error, 1)
		go func() {
			attached <- p.attach(t.Context(), joiner, func() error { return attachGuestOutput(t.Context(), time.Time{}, writers, joiner, termsize.Size{}) })
		}()
		require.NoError(t, awaitErr(t, attached), "a guest's attach failed while a write was held")
		requireHeld(t, p, done)

		p.release()
		requireCompleted(t, done)
	})
}

// renderMark heads every render a heldReplayer's emulation makes, so that a
// guest's bytes say whether it was handed a reconstruction.
const renderMark = "<render>"

// ringBytes is what an emulatingPacer's ring holds before anyone joins.
const ringBytes = "before"

// heldReplayer is a Replayer a test holds inside Start: each Start reports
// its capture on started, then waits for release, or for the join's ctx,
// whose error it returns. Its emulation consumes all it is offered and hands
// off at the end of it, and renders renderMark and the bytes it consumed.
//
// stuck, set before a join starts, has the emulation take nothing a Feed
// offers it, as an emulation can't pass a resize inside a sequence the ring
// ends in the middle of: until the rest of the sequence arrives, the resize
// and everything after it wait in its tail.
type heldReplayer struct {
	started chan *uio.Capture
	release chan struct{}
	stuck   bool

	mu  sync.Mutex
	fed []uio.SizeEvent // every event a Feed offered, in order
}

func (r *heldReplayer) Start(ctx context.Context, _ time.Time, c *uio.Capture, _ termsize.Size) (uio.Emulation, error) {
	r.started <- c
	select {
	case <-r.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	e := &heldEmulation{r: r, h: c.Start}
	e.consume(c.Chunks, c.Sizes)
	return e, nil
}

// fedEvents is every event a Feed offered, in order.
func (r *heldReplayer) fedEvents() []uio.SizeEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uio.SizeEvent(nil), r.fed...)
}

type heldEmulation struct {
	r          *heldReplayer
	consumed   []byte
	h, lastSeq uint64
}

func (e *heldEmulation) consume(chunks [][]byte, sizes []uio.SizeEvent) {
	for _, c := range chunks {
		e.consumed = append(e.consumed, c...)
		e.h += uint64(len(c))
	}
	if len(sizes) > 0 {
		e.lastSeq = sizes[len(sizes)-1].Seq
	}
}

func (e *heldEmulation) Feed(chunks [][]byte, sizes []uio.SizeEvent) error {
	e.r.mu.Lock()
	e.r.fed = append(e.r.fed, sizes...)
	e.r.mu.Unlock()
	if !e.r.stuck {
		e.consume(chunks, sizes)
	}
	return nil
}

func (e *heldEmulation) Handoff() (uint64, uint64) { return e.h, e.lastSeq }

func (e *heldEmulation) Render() ([]byte, error) {
	return append([]byte(renderMark), e.consumed...), nil
}

// emulatingPacer is a pacer whose fan-out reconstructs a joining terminal's
// screen with a heldReplayer. The ring holds ringBytes, written at 80x24, and
// passed is every write the pacer has let through to the fan-out.
type emulatingPacer struct {
	p           *guestPacer
	writers     *uio.MultiWriter
	r           *heldReplayer
	passed      *recordingWriter
	fellBack    chan error // why each join that fell back did
	releaseOnce sync.Once
}

func newEmulatingPacer(t *testing.T, stall time.Duration) *emulatingPacer {
	t.Helper()

	e := &emulatingPacer{
		writers:  uio.NewMultiWriter(uio.DefaultReplayBytes),
		r:        &heldReplayer{started: make(chan *uio.Capture, 4), release: make(chan struct{})},
		passed:   &recordingWriter{},
		fellBack: make(chan error, 4),
	}
	t.Cleanup(func() {
		if e.p != nil {
			e.p.release()
		}
		e.release()
	})
	e.writers.SetReplayer(e.r, func(err error) { e.fellBack <- err })
	// The size the ring is written at, which a join's emulation starts from.
	e.writers.ResizeEnd(e.writers.ResizeBegin(termsize.Default), true)
	e.p = newGuestPacer(t.Context(), io.MultiWriter(e.passed, e.writers), stall)
	_, err := e.p.Write([]byte(ringBytes))
	require.NoError(t, err)
	return e
}

func (e *emulatingPacer) release() { e.releaseOnce.Do(func() { close(e.r.release) }) }

// join attaches sink through the pacer as the guest door does, with its
// screen reconstructed for an 80x24 terminal by deadline, on a goroutine of
// its own, and returns what the attach returns.
func (e *emulatingPacer) join(t *testing.T, ctx context.Context, sink *uio.AsyncWriter, deadline time.Time) <-chan error {
	t.Helper()
	attached := make(chan error, 1)
	t.Cleanup(func() {
		e.writers.Remove(sink)
		e.p.remove(sink)
		_ = sink.Close()
	})
	go func() {
		attached <- e.p.attach(ctx, sink, func() error { return attachGuestOutput(ctx, deadline, e.writers, sink, termsize.Default) })
	}()
	return attached
}

// awaitStart waits for a join's emulation to start, which is after its
// capture and inside its attach: its guest is registered and its replay is
// being made.
func (e *emulatingPacer) awaitStart(t *testing.T) {
	t.Helper()
	synctest.Wait()
	select {
	case <-e.r.started:
	default:
		t.Fatal("no join reached the replayer")
	}
}

// requireNoFallback fails if any join fell back to the raw ring.
func (e *emulatingPacer) requireNoFallback(t *testing.T) {
	t.Helper()
	select {
	case err := <-e.fellBack:
		t.Fatalf("a join fell back to the raw ring: %v", err)
	default:
	}
}

// flush waits until sink has delivered everything written to it.
func flush(t *testing.T, sink *uio.AsyncWriter) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, sink.Flush(ctx))
}

// awaitClosed settles a bubble and requires the operation to have completed.
func awaitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	synctest.Wait()
	select {
	case <-ch:
	default:
		t.Fatal(what)
	}
}

// pieces returns n writes of ptyWriteSize bytes, each of a byte of its own,
// so that what a guest was handed shows which of them it got, and in what
// order.
func pieces(n int) [][]byte {
	ps := make([][]byte, n)
	for i := range ps {
		ps[i] = bytes.Repeat([]byte{'a' + byte(i)}, ptyWriteSize)
	}
	return ps
}

// writeAll writes each of ps through p, in order.
func writeAll(p *guestPacer, ps [][]byte) {
	for _, b := range ps {
		_, _ = p.Write(b)
	}
}

// requirePassedWhilePending checks what the pacer let through since the ring
// was written, all of it while the guest was pending: up to the low mark, and
// past it by one write at most.
func (e *emulatingPacer) requirePassedWhilePending(t *testing.T) {
	t.Helper()
	passed := len(e.passed.bytes()) - len(ringBytes)
	require.GreaterOrEqual(t, passed, pacingLowWater, "the command was held before the low mark")
	require.LessOrEqual(t, passed, pacingLowWater+ptyWriteSize,
		"more than the low mark and one write passed while the guest was replayed")
}

// requireSent checks that sink delivered exactly want, without printing a
// stream of hundreds of kilobytes.
func requireSent(t *testing.T, got *recordingWriter, want string, msg string) {
	t.Helper()
	if sent := string(got.bytes()); sent != want {
		t.Fatalf("%s: sent %s, want %s", msg, ends(sent), ends(want))
	}
}

// ends is what a failure shows of a long stream: its length and its two ends.
func ends(s string) string {
	const n = 32
	if len(s) <= 2*n {
		return fmt.Sprintf("%d bytes %q", len(s), s)
	}
	return fmt.Sprintf("%d bytes %q...%q", len(s), s[:n], s[len(s)-n:])
}

// While the guest that paces is still being attached, its screen being
// reconstructed, the command is held to it as to a backlog: what passes on
// its behalf is what the join will hand it as the gap, and the command waits
// once that reaches the low mark. A command that outran the reconstruction
// would have the join fall back to the raw ring and lose output a paced guest
// is otherwise guaranteed, and the low mark's worth lets through the end of a
// sequence the ring stops inside, which the join may need to hand over. So
// at most the low mark and one write pass until the replay is released; then
// the guest has the render and every byte written after its capture, once,
// and nothing fell back.
func TestGuestPacerHoldsTheCommandWhileItsGuestIsReplayed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEmulatingPacer(t, time.Minute)
		got := &recordingWriter{}
		sink := uio.NewAsyncWriter(got, uio.DefaultGuestBufferSize, nil)
		attached := e.join(t, t.Context(), sink, time.Now().Add(time.Minute))
		e.awaitStart(t)

		ps := pieces(4)
		done := goWrite(t, e.p, func() { writeAll(e.p, ps) })
		requireHeld(t, e.p, done)
		e.requirePassedWhilePending(t)

		e.release()
		require.NoError(t, awaitErr(t, attached))
		requireCompleted(t, done)

		flush(t, sink)
		requireSent(t, got, renderMark+ringBytes+string(bytes.Join(ps, nil)),
			"the guest missed or repeated output written after its capture")
		e.requireNoFallback(t)
	})
}

// A guest attached and caught up paces, and a second guest being replayed
// behind it holds nothing. It is a follower, and its join catches up on what
// the command writes meanwhile; only the pacer's attach holds the command.
func TestGuestPacerAFollowerBeingReplayedHoldsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEmulatingPacer(t, time.Minute)
		first := uio.NewAsyncWriter(io.Discard, uio.DefaultGuestBufferSize, nil)
		attachPaced(t, e.p, e.writers, first)
		flush(t, first)

		got := &recordingWriter{}
		second := uio.NewAsyncWriter(got, uio.DefaultGuestBufferSize, nil)
		attached := e.join(t, t.Context(), second, time.Now().Add(time.Minute))
		e.awaitStart(t)

		done := goWrite(t, e.p, func() { _, _ = e.p.Write([]byte("during")) })
		requireCompleted(t, done)
		require.Zero(t, e.p.holds.Load(), "a guest being replayed behind the pacer held the command")

		e.release()
		require.NoError(t, awaitErr(t, attached))
		flush(t, second)
		require.Equal(t, renderMark+ringBytes+"during", string(got.bytes()),
			"the follower missed or repeated output written while it was replayed")
		e.requireNoFallback(t)
	})
}

// A guest that leaves while it is replayed ends the hold it put on the
// command: its join is refused with its context's error, its registration
// goes with it, and the write held for it goes through.
func TestGuestPacerAGuestThatLeavesWhileReplayedReleasesTheCommand(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEmulatingPacer(t, time.Minute)
		ctx, leave := context.WithCancel(t.Context())
		defer leave()
		sink := uio.NewAsyncWriter(io.Discard, uio.DefaultGuestBufferSize, nil)
		attached := e.join(t, ctx, sink, time.Now().Add(time.Minute))
		e.awaitStart(t)

		done := goWrite(t, e.p, func() { writeAll(e.p, pieces(3)) })
		requireHeld(t, e.p, done)

		leave()
		require.ErrorIs(t, awaitErr(t, attached), context.Canceled)
		requireCompleted(t, done)
		require.Zero(t, registered(e.p), "a guest that left while it was replayed is still registered")
		e.requireNoFallback(t)
	})
}

// However an attach ends, the hold it put on the command ends with it:
// attached (by the replay, or by the raw ring it falls back to: both return
// nil), refused (as after Shutdown), failed (as a sink the replay overflows),
// or a panic. A hold that outlived its attach would leave the command waiting
// on a guest with nothing coming. Only an attached guest stays registered.
func TestGuestPacerEndsTheHoldHoweverTheAttachEnds(t *testing.T) {
	for _, tc := range []struct {
		name     string
		end      func() error
		attached bool
	}{
		{name: "attached", end: func() error { return nil }, attached: true},
		{name: "refused", end: func() error { return uio.ErrClosed }},
		{name: "failed", end: func() error { return uio.ErrOverflow }},
		{name: "panicked", end: func() error { panic("the attach panics") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, _ := newTestPacer(t, time.Minute)
				inside, finish, over := make(chan struct{}), make(chan struct{}), make(chan struct{})
				t.Cleanup(func() {
					select {
					case <-finish:
					default:
						close(finish)
					}
					<-over
				})
				go func() {
					defer close(over)
					// The test's own panic, which the attach must not swallow.
					defer func() { _ = recover() }()
					_ = p.attach(t.Context(), newFakePaced(0), func() error {
						close(inside)
						<-finish
						return tc.end()
					})
				}()

				awaitClosed(t, inside, "the attach never ran")

				done := goWrite(t, p, func() { produce(p, 3*ptyWriteSize) })
				requireHeld(t, p, done)
				close(finish)
				awaitClosed(t, over, "the attach never returned")
				requireCompleted(t, done)
				want := 0
				if tc.attached {
					want = 1
				}
				require.Equal(t, want, registered(p))
			})
		})
	}
}

// The session stopping ends a hold for a guest still being attached, as it
// ends any other, without waiting for the attach: the pacer's context ending,
// as the command's does when the session is stopped, or the command exiting.
// The attach here never returns, so nothing else can end the hold.
func TestGuestPacerAPendingHoldEndsWithTheSession(t *testing.T) {
	for _, tc := range []struct {
		name string
		stop func(p *guestPacer, cancel context.CancelFunc)
	}{
		{"the session's context ends", func(_ *guestPacer, cancel context.CancelFunc) { cancel() }},
		{"the command exits", func(p *guestPacer, _ context.CancelFunc) { p.release() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				p, _ := newTestPacerWithContext(t, ctx, time.Minute)
				inside, finish := make(chan struct{}), make(chan struct{})
				attached := make(chan error, 1)
				t.Cleanup(func() {
					close(finish)
					require.NoError(t, <-attached, "the attach failed once it was let finish")
				})
				go func() {
					attached <- p.attach(t.Context(), newFakePaced(0), func() error {
						close(inside)
						<-finish
						return nil
					})
				}()

				awaitClosed(t, inside, "the attach never ran")

				done := goWrite(t, p, func() { produce(p, 3*ptyWriteSize) })
				requireHeld(t, p, done)
				tc.stop(p, cancel)
				requireCompleted(t, done)
			})
		})
	}
}

// The stall deadline judges a pacing guest by what it delivers, and a guest
// still being attached has been handed nothing to deliver. Held for its
// attach through five stall deadlines, it is never judged stalled, and once
// attached and caught up the write goes.
func TestGuestPacerNeverJudgesAGuestStalledWhileItIsAttached(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const stall = 20 * time.Millisecond
		p, _ := newTestPacer(t, stall)
		fake := newFakePaced(0)
		inside, finish := make(chan struct{}), make(chan struct{})
		attached := make(chan error, 1)
		t.Cleanup(func() {
			select {
			case <-finish:
			default:
				close(finish)
			}
		})
		go func() {
			attached <- p.attach(t.Context(), fake, func() error {
				close(inside)
				<-finish
				return nil
			})
		}()

		awaitClosed(t, inside, "the attach never ran")

		done := goWrite(t, p, func() { produce(p, 3*ptyWriteSize) })
		requireHeld(t, p, done)
		// Pending at all five 20 ms stall boundaries: no delivery is due yet.
		for range 5 {
			time.Sleep(stall)
			synctest.Wait()
			require.Zero(t, fake.refusals(), "a guest being attached was judged stalled")
			requireHeld(t, p, done)
		}

		close(finish)
		require.NoError(t, awaitErr(t, attached))
		requireCompleted(t, done)
	})
}

// The hold can't deadlock the join it waits for, because the handoff waits
// for nothing the command has to write. With the command held throughout, a
// resize committed while the guest's screen is being reconstructed is caught
// up on, and one whose outcome comes after the reconstruction is released is
// either waited for or caught up on, depending on which comes first: the pty
// reports an outcome as its ioctl returns, writing nothing. The join's
// deadline is a minute off. Once the resize resolves, settlement must finish
// the attach immediately; needing more command output would leave it pending.
func TestGuestPacerHoldNeedsNoWriteToEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEmulatingPacer(t, time.Minute)
		sink := uio.NewAsyncWriter(io.Discard, uio.DefaultGuestBufferSize, nil)
		attached := e.join(t, t.Context(), sink, time.Now().Add(time.Minute))
		e.awaitStart(t)
		done := goWrite(t, e.p, func() { writeAll(e.p, pieces(3)) })
		requireHeld(t, e.p, done)
		e.requirePassedWhilePending(t)

		committed, unresolved := termsize.Size{Cols: 45, Rows: 24}, termsize.Size{Cols: 40, Rows: 20}
		e.writers.ResizeEnd(e.writers.ResizeBegin(committed), true)
		seq := e.writers.ResizeBegin(unresolved)
		t.Cleanup(func() { e.writers.ResizeEnd(seq, false) })
		e.release()
		e.writers.ResizeEnd(seq, true)

		require.NoError(t, awaitErr(t, attached), "the attach waited on the command it holds")
		requireCompleted(t, done)
		var fed []termsize.Size
		for _, ev := range e.r.fedEvents() {
			fed = append(fed, ev.Size)
		}
		require.Equal(t, []termsize.Size{committed, unresolved}, fed, "the join didn't catch up on the resizes")
		e.requireNoFallback(t)
	})
}

// One handoff waits on the command: an emulation that can't pass a resize
// until a sequence the ring ends inside is complete, when the rest of it
// doesn't come within the low mark's worth the pacer lets through. Held past
// that, the rest never comes, and the join falls back to the raw ring at its
// deadline, which ends the hold. So the join's deadline bounds any hold an
// attach puts on the command.
func TestGuestPacerHoldEndsByTheJoinsDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEmulatingPacer(t, time.Minute)
		e.r.stuck = true
		got := &recordingWriter{}
		sink := uio.NewAsyncWriter(got, uio.DefaultGuestBufferSize, nil)
		deadline := time.Now().Add(300 * time.Millisecond)
		attached := e.join(t, t.Context(), sink, deadline)
		e.awaitStart(t)
		ps := pieces(3)
		done := goWrite(t, e.p, func() { writeAll(e.p, ps) })
		requireHeld(t, e.p, done)

		// The guest's own resize, which the emulation can't pass without more
		// output.
		e.writers.ResizeEnd(e.writers.ResizeBegin(termsize.Size{Cols: 45, Rows: 24}), true)
		e.release()

		// The 300 ms join budget bounds the pending hold exactly.
		synctest.Wait()
		time.Sleep(time.Until(deadline) - time.Nanosecond)
		synctest.Wait()
		requireHeld(t, e.p, done)
		select {
		case err := <-attached:
			t.Fatalf("the join ended before its deadline: %v", err)
		default:
		}
		time.Sleep(time.Nanosecond)
		requireCompleted(t, done)
		require.NoError(t, awaitErr(t, attached), "a join that falls back is attached")
		select {
		case err := <-e.fellBack:
			require.ErrorIs(t, err, uio.ErrReplayDeadline)
		default:
			t.Fatal("the join didn't fall back")
		}
		flush(t, sink)
		sent := string(got.bytes())
		require.NotContains(t, sent, renderMark, "a join that fell back was handed a render")
		requireSent(t, got, ringBytes+string(bytes.Join(ps, nil)), "the guest missed or repeated output")
	})
}

// startSignal is a Replayer that says as each Start begins, which is inside
// its join's attach: the guest is registered, and pending.
type startSignal struct {
	uio.Replayer
	started chan struct{}
}

func (r startSignal) Start(ctx context.Context, deadline time.Time, c *uio.Capture, size termsize.Size) (uio.Emulation, error) {
	r.started <- struct{}{}
	return r.Replayer.Start(ctx, deadline, c, size)
}

// splitCharacter is a fan-out with the session's own replayer whose ring, at
// 80x24, ends inside a character, as a pty read can split one: after two of
// ✳'s three bytes. rest is the command's next write, which completes it.
// Each Start is announced on started, and each fallback's reason on fellBack.
type splitCharacter struct {
	writers  *uio.MultiWriter
	started  chan struct{}
	fellBack chan error
}

const splitCharacterRest = "\xb3 done\r\n"

func newSplitCharacter(t *testing.T) *splitCharacter {
	t.Helper()
	c := &splitCharacter{
		writers:  uio.NewMultiWriter(uio.DefaultReplayBytes),
		started:  make(chan struct{}, 1),
		fellBack: make(chan error, 4),
	}
	c.writers.SetReplayer(startSignal{replay.New(), c.started}, func(err error) { c.fellBack <- err })
	c.writers.ResizeEnd(c.writers.ResizeBegin(termsize.Default), true)
	_, err := c.writers.Write([]byte("prompt\r\n\xe2\x9c"))
	require.NoError(t, err)
	return c
}

// join resizes the pty to joiner's terminal, so that the resize lands inside
// the split character, then attaches sink with join, on a goroutine of its
// own, and returns once the join's emulation has started.
func (c *splitCharacter) join(t *testing.T, joiner termsize.Size, sink *uio.AsyncWriter, join func() error) <-chan error {
	t.Helper()
	c.writers.ResizeEnd(c.writers.ResizeBegin(joiner), true)
	t.Cleanup(func() {
		c.writers.Remove(sink)
		_ = sink.Close()
	})
	attached := make(chan error, 1)
	go func() { attached <- join() }()
	synctest.Wait()
	select {
	case <-c.started:
	default:
		t.Fatal("no join reached the replayer")
	}
	return attached
}

// requireNoFallback fails if the join fell back.
func (c *splitCharacter) requireNoFallback(t *testing.T) {
	t.Helper()
	select {
	case err := <-c.fellBack:
		t.Fatalf("the join fell back to the raw ring: %v", err)
	default:
	}
}

// requireReconstructed checks that sink was handed the screen, completed
// character and all, rather than the raw ring.
func requireReconstructed(t *testing.T, sink *uio.AsyncWriter, got *recordingWriter) {
	t.Helper()
	flush(t, sink)
	sent := string(got.bytes())
	require.False(t, strings.HasPrefix(sent, "prompt"), "the guest was handed the raw ring")
	require.Contains(t, sent, "\u2733 done", "the screen lost the character")
}

// A joiner's resize that lands inside a split character can't be passed by
// the emulation until the character's third byte arrives, in the command's
// next write. That write is under the low mark, so the pacer lets it through
// on behalf of the guest being replayed, and the join hands over at once,
// emulated, rather than waiting out its deadline, a minute off, to fall back.
func TestGuestPacerLetsAJoinFinishACharacterTheRingEndsInside(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newSplitCharacter(t)
		p := newGuestPacer(t.Context(), c.writers, 0)
		joiner := termsize.Size{Cols: 100, Rows: 40}
		got := &recordingWriter{}
		sink := uio.NewAsyncWriter(got, uio.DefaultGuestBufferSize, nil)
		t.Cleanup(func() { p.remove(sink) })
		attached := c.join(t, joiner, sink, func() error {
			return p.attach(t.Context(), sink, func() error {
				return attachGuestOutput(t.Context(), time.Now().Add(time.Minute), c.writers, sink, joiner)
			})
		})

		done := goWrite(t, p, func() { _, _ = p.Write([]byte(splitCharacterRest)) })
		requireCompleted(t, done)
		require.NoError(t, awaitErr(t, attached), "the join waited for its deadline")
		c.requireNoFallback(t)
		requireReconstructed(t, sink, got)
	})
}

// A joiner smaller than the pty is not held by the screen at the pty's old
// size, and until the emulation has passed the joiner's own resize that is
// the only size it has. So it renders nothing until then: the join waits for
// the character's third byte, which lets the emulation pass the resize, and
// hands over the screen at the joiner's size. Through the pacer, for a guest
// that paces, and with no pacer, for a session with a primary.
func TestAJoinWhoseResizeLandsInsideACharacterHandsOverAtItsSize(t *testing.T) {
	t.Run("a guest that paces, no primary", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			joiner := termsize.Size{Cols: 45, Rows: 24}
			c := newSplitCharacter(t)
			p := newGuestPacer(t.Context(), c.writers, 0)
			got := &recordingWriter{}
			sink := uio.NewAsyncWriter(got, uio.DefaultGuestBufferSize, nil)
			t.Cleanup(func() { p.remove(sink) })
			attached := c.join(t, joiner, sink, func() error {
				return p.attach(t.Context(), sink, func() error {
					return attachGuestOutput(t.Context(), time.Now().Add(time.Minute), c.writers, sink, joiner)
				})
			})

			done := goWrite(t, p, func() { _, _ = p.Write([]byte(splitCharacterRest)) })
			requireCompleted(t, done)
			require.NoError(t, awaitErr(t, attached), "the join waited for its deadline")
			c.requireNoFallback(t)
			requireReconstructed(t, sink, got)
		})
	})
	t.Run("a primary, no pacer", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			joiner := termsize.Size{Cols: 45, Rows: 24}
			c := newSplitCharacter(t)
			// The primary is written synchronously, inside the fan-out.
			primary := &recordingWriter{}
			require.NoError(t, c.writers.Append(primary))
			got := &recordingWriter{}
			sink := uio.NewAsyncWriter(got, uio.DefaultGuestBufferSize, nil)
			attached := c.join(t, joiner, sink, func() error {
				return attachGuestOutput(t.Context(), time.Now().Add(time.Minute), c.writers, sink, joiner)
			})

			_, err := c.writers.Write([]byte(splitCharacterRest))
			require.NoError(t, err)
			require.NoError(t, awaitErr(t, attached), "the join waited for its deadline")
			c.requireNoFallback(t)
			requireReconstructed(t, sink, got)
		})
	})
}

// The same joiner, with the character's third byte never coming: the join
// falls back to the raw ring at its deadline, for running out of time, and
// not at once for a render at the pty's old size, which it never makes.
func TestAJoinWhoseResizeLandsInsideACharacterFallsBackAtItsDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newSplitCharacter(t)
		joiner := termsize.Size{Cols: 45, Rows: 24}
		got := &recordingWriter{}
		sink := uio.NewAsyncWriter(got, uio.DefaultGuestBufferSize, nil)
		deadline := time.Now().Add(300 * time.Millisecond)
		attached := c.join(t, joiner, sink, func() error {
			return attachGuestOutput(t.Context(), deadline, c.writers, sink, joiner)
		})

		// The 300 ms deadline is pending at -1 ns and completes at the boundary.
		synctest.Wait()
		time.Sleep(time.Until(deadline) - time.Nanosecond)
		synctest.Wait()
		select {
		case err := <-attached:
			t.Fatalf("the join ended before its deadline: %v", err)
		default:
		}
		time.Sleep(time.Nanosecond)
		require.NoError(t, awaitErr(t, attached), "a join that falls back is attached")
		require.Equal(t, deadline, time.Now(), "the join did not end at its deadline")
		select {
		case err := <-c.fellBack:
			require.ErrorIs(t, err, uio.ErrReplayDeadline)
		default:
			t.Fatal("the join didn't fall back")
		}
		flush(t, sink)
		requireSent(t, got, "prompt\r\n\xe2\x9c", "the guest missed or repeated the raw ring")
	})
}
