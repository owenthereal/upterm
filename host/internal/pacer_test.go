package internal

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	every time.Duration
	n     atomic.Int64
}

func (m *meteredWriter) Write(p []byte) (int, error) {
	time.Sleep(m.every)
	m.n.Add(int64(len(p)))
	return len(p), nil
}

// heldLink is a meteredWriter that takes a piece only while the pacer is
// holding a write, so the guest behind it is slower than the producer by
// construction, however fast the producer runs. Setting free lets it run
// without waiting, so a flush can complete and a failing test never leaves the
// sink's drain parked here.
type heldLink struct {
	meteredWriter
	p    *guestPacer
	free atomic.Bool
}

func (l *heldLink) Write(b []byte) (int, error) {
	for !l.free.Load() && l.p.waiting.Load() == 0 {
		time.Sleep(100 * time.Microsecond)
	}
	return l.meteredWriter.Write(b)
}

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
	sink := uio.NewAsyncWriter(&gatedWriter{gate: gate, rec: &recordingWriter{}}, uio.DefaultGuestBufferSize, onDrop)
	t.Cleanup(func() {
		_ = sink.Close()
		close(gate)
	})
	return sink
}

// newTestPacer returns a pacer over a fresh fan-out with the stall timeout set
// to stall. Called first in a test, its restore is the first cleanup
// registered and so the last to run: after every cleanup that joins a
// goroutine reading the timeout.
func newTestPacer(t *testing.T, stall time.Duration) (*guestPacer, *uio.MultiWriter) {
	t.Helper()
	return newTestPacerWithContext(t, t.Context(), stall)
}

// newTestPacerWithContext is newTestPacer for a test that ends the pacer's
// context itself.
func newTestPacerWithContext(t *testing.T, ctx context.Context, stall time.Duration) (*guestPacer, *uio.MultiWriter) {
	t.Helper()
	orig := pacingStallTimeout
	pacingStallTimeout = stall
	t.Cleanup(func() { pacingStallTimeout = orig })
	writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
	return newGuestPacer(ctx, writers), writers
}

// attachPaced attaches sink as HandleSession does: registered with the pacer
// and appended to the fan-out in one transaction, and taken out of both on the
// way out.
func attachPaced(t *testing.T, p *guestPacer, writers *uio.MultiWriter, sink *uio.AsyncWriter) {
	t.Helper()
	require.NoError(t, p.attach(sink, func() error { return attachGuestOutput(writers, sink) }))
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
	go func() {
		defer close(done)
		writes()
	}()
	t.Cleanup(func() {
		p.release()
		<-done
	})
	return done
}

// produce writes n bytes through p in pty-sized writes.
func produce(p *guestPacer, n int) {
	piece := make([]byte, ptyWriteSize)
	for ; n > 0; n -= len(piece) {
		_, _ = p.Write(piece)
	}
}

// requireHeld waits until the pacer is holding a write, then requires that the
// write behind done has not returned.
func requireHeld(t *testing.T, p *guestPacer, done <-chan struct{}) {
	t.Helper()
	require.Eventually(t, func() bool { return p.waiting.Load() > 0 }, 2*time.Second, time.Millisecond,
		"the write was never held")
	select {
	case <-done:
		t.Fatal("the write returned instead of being held")
	default:
	}
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

// awaitErr returns what an attach running on another goroutine returned,
// failing if it has not returned within 2 s.
func awaitErr(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(2 * time.Second):
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
	piece := make([]byte, ptyWriteSize)

	t.Run("control", func(t *testing.T) {
		p, writers := newTestPacer(t, time.Minute)
		attachStuck(t, p, writers)
		done := goWrite(t, p, func() { _, _ = p.Write(piece) })
		requireHeld(t, p, done)
		p.release()
		requireReturns(t, done, 2*time.Second)
	})
	t.Run("no guests", func(t *testing.T) {
		p, _ := newTestPacer(t, time.Minute)
		done := goWrite(t, p, func() { _, _ = p.Write(piece) })
		requireReturns(t, done, 2*time.Second)
	})
	t.Run("primary", func(t *testing.T) {
		p, writers := newTestPacer(t, time.Minute)
		attachStuck(t, p, writers)
		p.setPrimary(true)
		done := goWrite(t, p, func() { _, _ = p.Write(piece) })
		requireReturns(t, done, 2*time.Second)
	})
	t.Run("released", func(t *testing.T) {
		p, writers := newTestPacer(t, time.Minute)
		attachStuck(t, p, writers)
		p.release()
		done := goWrite(t, p, func() { _, _ = p.Write(piece) })
		requireReturns(t, done, 2*time.Second)
	})
	t.Run("context cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		p, writers := newTestPacerWithContext(t, ctx, time.Minute)
		attachStuck(t, p, writers)
		cancel()
		done := goWrite(t, p, func() { _, _ = p.Write(piece) })
		requireReturns(t, done, 2*time.Second)
	})
}

// The earliest guest sets the rate and a faster one follows it. At one 32 KiB
// piece per 10 ms, the first guest has to deliver all of 2 MiB but the low
// mark and a write before the last write goes out: about 60 pieces, 600 ms.
// Unpaced, or paced by the faster guest, the same 2 MiB goes by in a few
// milliseconds and overflows the first guest's 1 MiB on the way.
func TestGuestPacerHoldsOutputToTheEarliestGuest(t *testing.T) {
	p, writers := newTestPacer(t, time.Minute)
	first := uio.NewAsyncWriter(&meteredWriter{every: 10 * time.Millisecond}, uio.DefaultGuestBufferSize, nil)
	attachPaced(t, p, writers, first)
	second := uio.NewAsyncWriter(io.Discard, uio.DefaultGuestBufferSize, nil)
	attachPaced(t, p, writers, second)

	start := time.Now()
	done := goWrite(t, p, func() { produce(p, 2<<20) })
	requireReturns(t, done, 10*time.Second)

	require.GreaterOrEqual(t, time.Since(start), 500*time.Millisecond, "output outran the first guest")
	require.Positive(t, p.holds.Load(), "no write was ever held")
	require.True(t, first.Backlog().Live, "the pacing guest was dropped")
	require.True(t, second.Backlog().Live, "the following guest was dropped")
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
// The established guest's link takes a piece only while the pacer is holding
// the producer. The producer's own speed varies by an order of magnitude
// between race and non-race builds, so no fixed rate can guarantee that the
// established guest is what holds it back; draining only while held makes it
// the bottleneck by construction. The same link drains nothing while a
// newcomer is letting output through, which is how the fastest rule would
// overflow it.
func TestGuestPacerANonReadingNewcomerCannotDisplaceThePacer(t *testing.T) {
	p, writers := newTestPacer(t, time.Minute)
	link := &heldLink{meteredWriter: meteredWriter{every: 2 * time.Millisecond}, p: p}
	t.Cleanup(func() { link.free.Store(true) })
	established := uio.NewAsyncWriter(link, uio.DefaultGuestBufferSize, nil)
	attachPaced(t, p, writers, established)

	var produced int
	backpressure := goWrite(t, p, func() {
		piece := make([]byte, ptyWriteSize)
		for p.holds.Load() < 8 && produced < 64<<20 {
			_, _ = p.Write(piece)
			produced += len(piece)
		}
	})
	requireReturns(t, backpressure, 10*time.Second)
	require.GreaterOrEqual(t, p.holds.Load(), int64(8),
		"64 MiB went by without the established guest holding output back")

	newcomerLink := &windowWriter{budget: 4 << 20, release: make(chan struct{})}
	t.Cleanup(func() { close(newcomerLink.release) })
	newcomer := uio.NewAsyncWriter(newcomerLink, uio.DefaultGuestBufferSize, nil)
	attachPaced(t, p, writers, newcomer)

	burst := goWrite(t, p, func() {
		piece := make([]byte, ptyWriteSize)
		// Cut short only once the established guest is gone, which fails the
		// test below anyway; otherwise all 8 MiB go through.
		for n := 0; n < 8<<20 && established.Backlog().Live; n += len(piece) {
			_, _ = p.Write(piece)
			produced += len(piece)
		}
	})
	requireReturns(t, burst, 20*time.Second)
	// Nothing is held any more, so the link would never take the rest.
	link.free.Store(true)

	require.True(t, established.Backlog().Live, "the newcomer displaced the established guest")
	require.False(t, newcomer.Backlog().Live, "a newcomer that never reads outlasted its windows and its cap")
	require.ErrorIs(t, newcomer.Err(), uio.ErrOverflow)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	require.NoError(t, established.Flush(ctx))
	require.Equal(t, int64(produced), link.n.Load(), "the established guest missed output")
}

// A pacer that inherits a backlog — here from a primary that left while it
// was behind — is dropped only for delivering nothing, never for how long the
// backlog takes. 768 KiB at one piece per 100 ms is more than two seconds,
// ten stall timeouts, with a piece landing every half a timeout.
func TestGuestPacerLetsAPacerWorkThroughAnInheritedBacklog(t *testing.T) {
	p, writers := newTestPacer(t, 200*time.Millisecond)
	guest := uio.NewAsyncWriter(&meteredWriter{every: 100 * time.Millisecond}, uio.DefaultGuestBufferSize, nil)
	attachPaced(t, p, writers, guest)

	p.setPrimary(true)
	_, err := p.Write(make([]byte, 768<<10))
	require.NoError(t, err)
	p.setPrimary(false)

	start := time.Now()
	done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
	requireReturns(t, done, 10*time.Second)

	require.GreaterOrEqual(t, time.Since(start), time.Second, "the write did not wait for the inherited backlog")
	require.True(t, guest.Backlog().Live, "a pacer delivering steadily was dropped as stalled")
}

// A pacer that delivers nothing is dropped after the stall timeout, and the
// next guest paces from the backlog it built up as a follower rather than
// from empty. The lower bound is what tells those apart: the drop alone comes
// at 200 ms, and the next guest needs about 700 ms to bring 256 KiB under the
// low mark.
func TestGuestPacerDropsAPacerThatDeliversNothing(t *testing.T) {
	p, writers := newTestPacer(t, 200*time.Millisecond)
	dropped := make(chan error, 1)
	stuck := stuckSink(t, func(err error) { dropped <- err })
	attachPaced(t, p, writers, stuck)
	next := uio.NewAsyncWriter(&meteredWriter{every: 100 * time.Millisecond}, uio.DefaultGuestBufferSize, nil)
	attachPaced(t, p, writers, next)

	// Both guests are empty, so this passes and leaves each 256 KiB behind.
	_, err := p.Write(make([]byte, 256<<10))
	require.NoError(t, err)

	start := time.Now()
	done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
	requireReturns(t, done, 10*time.Second)
	require.GreaterOrEqual(t, time.Since(start), 400*time.Millisecond,
		"the write went out when the stuck guest was dropped, ahead of the next guest's backlog")

	select {
	case err := <-dropped:
		require.ErrorIs(t, err, uio.ErrStalled)
	case <-time.After(2 * time.Second):
		t.Fatal("the stuck guest was never dropped")
	}
	require.True(t, next.Backlog().Live, "the next guest was dropped")
}

// When the pacer leaves, the next guest paces from its own backlog; the
// departure does not open the gate.
func TestGuestPacerHandsOverWhenThePacerLeaves(t *testing.T) {
	p, writers := newTestPacer(t, time.Minute)
	stuck := stuckSink(t, nil)
	attachPaced(t, p, writers, stuck)
	next := uio.NewAsyncWriter(&meteredWriter{every: 100 * time.Millisecond}, uio.DefaultGuestBufferSize, nil)
	attachPaced(t, p, writers, next)

	_, err := p.Write(make([]byte, 256<<10))
	require.NoError(t, err)

	start := time.Now()
	done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
	requireHeld(t, p, done)
	p.remove(stuck)
	requireReturns(t, done, 10*time.Second)
	require.GreaterOrEqual(t, time.Since(start), 400*time.Millisecond,
		"the write went out when the pacer left, ahead of the next guest's backlog")
}

// The deadline and a delivered piece can be ready together. The abort is
// decided against the count the pacer recorded, under the sink's own lock, so
// a piece that lands in between wins: the sink refuses, nobody is dropped, the
// write stays held and the deadline is armed again. Two refusals rather than
// one are what show the re-arming: the second deadline exists only if the
// pacer armed it after the first.
func TestGuestPacerProgressAtTheDeadlineCancelsTheAbort(t *testing.T) {
	p, _ := newTestPacer(t, 50*time.Millisecond)
	fake := newFakePaced(2 * pacingLowWater)
	require.NoError(t, p.attach(fake, func() error { return nil }))

	done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
	requireHeld(t, p, done)
	require.Eventually(t, func() bool { return fake.refusals() >= 2 }, 2*time.Second, time.Millisecond,
		"the pacer did not keep trying the abort as its deadlines passed")
	requireHeld(t, p, done)

	fake.drain()
	requireReturns(t, done, 2*time.Second)
}

// A guest is registered before Append publishes it to the fan-out. Registered
// afterwards, a session with no other guest would write to it unpaced for as
// long as its handler was descheduled — here the 100 ms appendFn sleeps once
// attachGuestOutput has returned — and a producer running flat out overflows
// 1 MiB in far less. Registered first, what reaches it before the pacer sees
// it is its replay and at most one pty write that had already passed the gate.
func TestGuestPacerRegistersAGuestBeforeItCanReceiveOutput(t *testing.T) {
	p, writers := newTestPacer(t, time.Minute)

	var (
		stop     atomic.Bool
		produced atomic.Int64
		wg       sync.WaitGroup
	)
	t.Cleanup(func() {
		stop.Store(true)
		p.release()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		piece := make([]byte, ptyWriteSize)
		for !stop.Load() {
			_, _ = p.Write(piece)
			produced.Add(int64(len(piece)))
		}
	}()
	// With nobody to pace on the producer runs flat out; this also fills the
	// replay.
	require.Eventually(t, func() bool { return produced.Load() >= uio.DefaultReplayBytes }, 2*time.Second, time.Millisecond,
		"the producer never got going")

	sink := stuckSink(t, nil)
	require.NoError(t, p.attach(sink, func() error {
		if err := attachGuestOutput(writers, sink); err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
		return nil
	}))
	t.Cleanup(func() {
		writers.Remove(sink)
		p.remove(sink)
		_ = sink.Close()
	})

	b := sink.Backlog()
	require.True(t, b.Live, "the guest overflowed while it was being attached")
	require.LessOrEqual(t, b.Bytes, uio.DefaultReplayBytes+pacingLowWater+2*ptyWriteSize,
		"the guest took output unpaced while it was being attached")
}

// Attachments are one transaction each, serialised: B cannot attach while A is
// registered but not yet appended. Were it able to, A would be the pacer with
// an empty queue, holding the gate open while B took output unpaced. And
// registration order is attachment order, so A, attached first, paces.
func TestGuestPacerSerialisesAttachments(t *testing.T) {
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
		aErr <- p.attach(a, func() error {
			<-resume
			return attachGuestOutput(writers, a)
		})
	}()
	require.Eventually(t, func() bool { return registered(p) == 1 }, 2*time.Second, time.Millisecond,
		"A was never registered")

	bErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		bErr <- p.attach(b, func() error { return attachGuestOutput(writers, b) })
	}()
	select {
	case err := <-bErr:
		t.Fatalf("B's attach returned (%v) while A was registered but not yet attached", err)
	case <-time.After(100 * time.Millisecond):
	}

	resumeOnce.Do(func() { close(resume) })
	require.NoError(t, awaitErr(t, aErr))
	require.NoError(t, awaitErr(t, bErr))

	_, err := writers.Write(make([]byte, 2*pacingLowWater))
	require.NoError(t, err)
	done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
	requireHeld(t, p, done)
	p.release()
	requireReturns(t, done, 2*time.Second)
}

// A failed Append takes its registration back out, or a guest that never
// joined would pace the session from then on. The sink is refused without
// being closed, unlike attachGuestOutput's refusal: a closed sink is skipped
// as dead anyway, which would hide a registration left behind.
func TestGuestPacerRollsBackAFailedAttach(t *testing.T) {
	p, _ := newTestPacer(t, time.Minute)
	sink := stuckSink(t, nil)
	_, err := sink.Write(make([]byte, 2*pacingLowWater))
	require.NoError(t, err)

	refuse := func() error { return uio.ErrClosed }
	require.ErrorIs(t, p.attach(sink, refuse), uio.ErrClosed)
	require.Zero(t, registered(p), "a failed attach left its guest registered")

	done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
	requireReturns(t, done, 2*time.Second)

	// And the transaction's lock went with it.
	again := make(chan error, 1)
	go func() { again <- p.attach(sink, refuse) }()
	require.ErrorIs(t, awaitErr(t, again), uio.ErrClosed)
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
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			p, writers := newTestPacerWithContext(t, ctx, time.Minute)
			pacer := attachStuck(t, p, writers)

			done := goWrite(t, p, func() { _, _ = p.Write(make([]byte, ptyWriteSize)) })
			requireHeld(t, p, done)
			tc.wake(p, pacer, cancel)
			requireReturns(t, done, 2*time.Second)
		})
	}
}

// The wait is outside the fan-out's lock and never takes the attach lock, so
// a guest can join while a write is held — and joins behind the pacer, so the
// write stays held.
func TestGuestPacerDoesNotHoldAnAttachBehindAGatedWrite(t *testing.T) {
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
	go func() { attached <- p.attach(joiner, func() error { return attachGuestOutput(writers, joiner) }) }()
	require.NoError(t, awaitErr(t, attached), "a guest's attach failed while a write was held")
	requireHeld(t, p, done)

	p.release()
	requireReturns(t, done, 2*time.Second)
}
