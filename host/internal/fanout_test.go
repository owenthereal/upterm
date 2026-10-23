package internal

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// recordingWriter accumulates what it is given. The drain runs on its own
// goroutine, so every field is read under the mutex.
type recordingWriter struct {
	mu      sync.Mutex
	written []byte
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.written = append(r.written, p...)
	return len(p), nil
}

func (r *recordingWriter) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.written)
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testSigners(t *testing.T) []ssh.Signer {
	t.Helper()
	signers, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	return signers
}

// A guest that reaches the door after the fan-out has quiesced is refused, and
// the sink built for it must not outlive the attempt.
//
// The assertion is on the sink, not on the error: checking only ErrClosed would
// pass just as happily with the release deleted. A closed sink refuses writes,
// which is the observable consequence of its goroutine being released.
func TestAttachGuestOutputReleasesTheSinkWhenRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		require.NoError(t, writers.Shutdown(ctx))

		var out recordingWriter
		sink := uio.NewAsyncWriter(&out, uio.DefaultGuestBufferSize, nil)
		defer func() { _ = sink.Close() }()

		require.ErrorIs(t, attachGuestOutput(t.Context(), time.Time{}, writers, sink, termsize.Size{}), uio.ErrClosed)

		_, err := sink.Write([]byte("output"))
		require.ErrorIs(t, err, uio.ErrWriterClosed,
			"a refused attach must release the sink it was given")
	})
}

// delayedWriter always takes longer to deliver than the copy takes to finish,
// so output is provably still pending when the producer stops. Without the
// flush, Run returns before this writer has been given anything at all.
type delayedWriter struct {
	delay   time.Duration
	rec     *recordingWriter
	release <-chan struct{}
}

func newDelayedWriter(t *testing.T, delay time.Duration, rec *recordingWriter) *delayedWriter {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(sync.OnceFunc(func() { close(release) }))
	return &delayedWriter{delay: delay, rec: rec, release: release}
}

func (d *delayedWriter) Write(p []byte) (int, error) {
	timer := time.NewTimer(d.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-d.release:
	}
	return d.rec.Write(p)
}

// The barrier: by the time Run returns, everything the fan-out accepted has
// reached the asynchronous guest.
//
// Ordering is the whole point. waitIdle returns after 100ms of quiet or its 1s
// deadline, in both cases with the copy still running, so a flush placed in the
// interrupt races the producer. Placing it where the copy returns is what makes
// it a barrier — and asserting *immediately after Run returns*, rather than
// eventually, is what makes this test notice if it moves back.
func TestCommandRunFlushesAcceptedOutputBeforeReturning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const lastLine = "written just before exit"

		var guestOut recordingWriter
		// 200ms: longer than the copy takes to drain the pty, and well inside
		// guestFlushTimeout, so the flush both has work to do and can finish it.
		guest := uio.NewAsyncWriter(newDelayedWriter(t, 200*time.Millisecond, &guestOut),
			uio.DefaultGuestBufferSize, nil)
		defer func() { _ = guest.Close() }()

		writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
		require.NoError(t, writers.Append(guest))

		cmd := &command{
			logger:  discardLogger(),
			writers: writers,
			ctx:     t.Context(),
			ptmx:    newExitedPTY(t, [][]byte{[]byte("first chunk\r\n"), []byte(lastLine + "\r\n")}, 20*time.Millisecond),
		}

		patientExitDrain(cmd)
		require.NoError(t, cmd.Run())

		// No Eventually: the guarantee is that this has already happened.
		require.Contains(t, string(guestOut.bytes()), lastLine,
			"Run returned with output still queued for an attached guest")
	})
}

// A guest too stuck to receive its tail must leave a trace.
//
// The flush is best-effort by design: the deadline expires, the host exits, and
// there is nothing to be done about it here. That is exactly why the error was
// easy to discard — and why discarding it is wrong. Without a line, a guest
// whose last screenful never arrived looks from the outside like output the
// command never produced.
func TestCommandRunLogsAGuestThatNeverReceivedItsTail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Never released, so the flush can only end at its deadline.
		gate := make(chan struct{})
		defer close(gate)
		guest := uio.NewAsyncWriter(&gatedWriter{gate: gate, rec: &recordingWriter{}},
			uio.DefaultGuestBufferSize, nil)
		defer func() { _ = guest.Close() }()

		writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
		require.NoError(t, writers.Append(guest))

		// The handler is slow but working, and the bound is far above its delay.
		// With the default 100ms bound, a CI runner starved of CPU could fail to
		// schedule the logging goroutine in time and Run returned before the line
		// landed. A slow handler also makes a fire-and-forget regression fail every
		// time instead of only when the goroutine happens to lose the race.
		var logs recordingWriter
		cmd := &command{
			logger:                    slog.New(slog.NewTextHandler(newDelayedWriter(t, 200*time.Millisecond, &logs), nil)),
			writers:                   writers,
			ctx:                       t.Context(),
			ptmx:                      newExitedPTY(t, [][]byte{[]byte("never delivered\r\n")}, 20*time.Millisecond),
			flushLogTimeoutForTesting: 30 * time.Second,
		}

		patientExitDrain(cmd)
		require.NoError(t, cmd.Run())

		// No Eventually, deliberately. The line is written off the actor's return
		// path so a blocked handler cannot hang the exit, but it is waited for
		// under a bound, so with a working handler it has landed by the time Run
		// returns. Asserting immediately is what pins that: a fire-and-forget
		// version passes under Eventually and still loses the line at process
		// exit, which is the whole failure being guarded against.
		require.Contains(t, string(logs.bytes()), "gave up delivering final output to a guest",
			"a guest that lost its tail left no trace in the host log")
	})
}

// The other half of that bound: a handler that never returns must not hold the
// host open. Exit waits for the warning, so the wait needs its own ceiling, or
// guestFlushTimeout would bound the flush and then the logger would hang the
// process anyway — with stdout redirected and stderr on a stopped terminal,
// which is exactly the shape of session this whole change exists for.
func TestCommandRunDoesNotHangOnABlockedLogger(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		guestGate, logGate := make(chan struct{}), make(chan struct{})
		defer close(guestGate)
		defer close(logGate)
		guestStarted, logStarted := make(chan struct{}), make(chan struct{})
		guest := uio.NewAsyncWriter(&gatedWriter{gate: guestGate, rec: &recordingWriter{}, started: guestStarted}, uio.DefaultGuestBufferSize, nil)
		defer func() { _ = guest.Close() }()
		writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
		require.NoError(t, writers.Append(guest))
		cmd := &command{
			logger:  slog.New(slog.NewTextHandler(&gatedWriter{gate: logGate, rec: &recordingWriter{}, started: logStarted}, nil)),
			writers: writers, ctx: t.Context(),
			ptmx: newExitedPTY(t, [][]byte{[]byte("never delivered\r\n")}, 20*time.Millisecond),
		}
		defer func() { _ = cmd.ptmx.Close() }()
		done := make(chan struct{})
		var runErr error
		go func() { defer close(done); runErr = cmd.Run() }()
		synctest.Wait()
		time.Sleep(20 * time.Millisecond)
		requireCompleted(t, guestStarted)
		// The second read reports EOF at 40ms and starts the 1s flush.
		time.Sleep(20 * time.Millisecond)
		synctest.Wait()
		time.Sleep(time.Second - time.Nanosecond)
		synctest.Wait()
		requirePending(t, logStarted, "warning started before the flush deadline")
		requirePending(t, done, "Run returned before the flush deadline")
		time.Sleep(time.Nanosecond)
		requireCompleted(t, logStarted)
		requirePending(t, done, "Run skipped the logger's bound")
		time.Sleep(100*time.Millisecond - time.Nanosecond)
		synctest.Wait()
		requirePending(t, done, "Run returned before the logger deadline")
		time.Sleep(time.Nanosecond)
		requireCompleted(t, done)
		require.NoError(t, runErr)
	})
}

// The shutdown barrier: waitIdle can return while the producer is still going,
// and anything produced after that must not be lost.
//
// waitIdle has two ways to give up: 100ms of quiet, or its own 1s outer bound
// regardless of quiet. The idle path cannot leave anything already accepted
// for this test to check, because the interrupt starts watching from the
// moment the mock pty's Wait returns -- immediately -- so a gap wide enough
// to read as quiet is also wide enough to swallow the first chunk before it
// ever arrives. So the test widens the quiet window past the deadline:
// waitIdle never sees quiet at all; it is only cut off by the 1s deadline,
// with the pty still holding chunks the copy never got to. That is the other
// half of "waitIdle does not establish nothing more can be produced": even
// its own deadline leaves the copy still running when the interrupt cancels
// it. The comparison is against a synchronous writer attached to the same
// fan-out, which by definition has everything the fan-out accepted.
func TestCommandRunLosesNothingWhenTheProducerOutlivesWaitIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var accepted recordingWriter // synchronous: the reference for what got in
		var guestOut recordingWriter
		guest := uio.NewAsyncWriter(newDelayedWriter(t, 200*time.Millisecond, &guestOut),
			uio.DefaultGuestBufferSize, nil)
		defer func() { _ = guest.Close() }()

		writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
		require.NoError(t, writers.Append(&accepted))
		require.NoError(t, writers.Append(guest))

		// 75 reads at 20ms take 1.5s: output outlives the 1s hard
		// drain bound, while the 5s quiet window cannot end it first.
		var pending [][]byte
		for i := range 75 {
			pending = append(pending, []byte{byte('a' + i%26)})
		}
		cmd := &command{timing: serverTiming{outputIdle: 5 * time.Second},
			logger:  discardLogger(),
			writers: writers,
			ctx:     t.Context(),
			ptmx:    newExitedPTY(t, pending, 20*time.Millisecond),
		}

		require.NoError(t, cmd.Run())

		require.NotEmpty(t, accepted.bytes())
		require.Equal(t, string(accepted.bytes()), string(guestOut.bytes()),
			"output accepted by the fan-out was lost at teardown")
	})
}

// A write the pacer is holding is not activity, so waitIdle would read a gated
// pty as quiet, and the cancel after it would cut the command's tail off. The
// interrupt releases pacing before it waits.
//
// What the test pins is that order. The guest delivers nothing, so two 32 KiB
// writes would put it at the low mark — one in flight on its link, one
// queued — and hold tail-1. Released before waitIdle, as here, every tail
// arrives: the fake's Wait returns at once, so the release precedes the
// first read and nothing is ever held. Released after it, tail-1 is held past
// the idle wait and tail-2 is cut off by the cancel that follows; never
// released, Run hangs. exitedPTY hands out one chunk per Read and drops
// whatever does not fit io.Copy's buffer, hence chunks of exactly that size.
// The synchronous recorder on the fan-out is the reference for what got past
// the pacer.
func TestCommandRunReleasesPacingBeforeWaitingForIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, writers := newTestPacer(t, time.Minute)
		var accepted recordingWriter
		require.NoError(t, writers.Append(&accepted))
		attachPaced(t, p, writers, stuckSink(t, nil))

		cmd := &command{
			logger:  discardLogger(),
			writers: writers,
			pacer:   p,
			ctx:     t.Context(),
			ptmx: newExitedPTY(t, [][]byte{
				make([]byte, ptyWriteSize), make([]byte, ptyWriteSize), []byte("tail-1\r\n"), []byte("tail-2\r\n"),
			}, 20*time.Millisecond),
		}

		var runErr error
		patientExitDrain(cmd)
		done := goWrite(t, p, func() { runErr = cmd.Run() })
		defer func() { _ = cmd.ptmx.Close() }()
		synctest.Wait()
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		require.Contains(t, string(accepted.bytes()), "tail-2",
			"pacing was not released before the idle wait")
		// Delivery is deliberately blocked; shutdown waits the 1s flush bound.
		time.Sleep(time.Second)
		requireCompleted(t, done)
		require.NoError(t, runErr)
		got := string(accepted.bytes())
		require.Contains(t, got, "tail-1", "a write held by the pacer was lost at exit")
		require.Contains(t, got, "tail-2", "the pty's tail was cut off behind a held write")
	})
}

// Under parent cancellation the command and the session handlers would
// otherwise be released together, so a guest's channel could close while the
// flush was still delivering into it. Sessions therefore do not inherit the
// parent's cancellation; only the SSH server actor's interrupt releases them,
// after giving the command a bounded chance to finish.
func TestSessionContextSurvivesParentCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		parent, cancelParent := context.WithCancel(context.Background())
		sessCtx, cancelSessions := context.WithCancel(sessionContext(parent))
		defer cancelSessions()

		cancelParent()
		synctest.Wait()
		requirePending(t, sessCtx.Done(), "sessions were released by the parent, ahead of the fan-out")
		cancelSessions()
		requireCompleted(t, sessCtx.Done())
	})
}

func TestWaitClosedReturnsOnCloseAndOnTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		closed, immediate := make(chan struct{}), make(chan struct{})
		close(closed)
		go func() { defer close(immediate); waitClosed(closed, time.Minute) }()
		requireCompleted(t, immediate)
		pending, returned := make(chan struct{}), make(chan struct{})
		defer close(pending)
		go func() { defer close(returned); waitClosed(pending, 50*time.Millisecond) }()
		synctest.Wait()
		time.Sleep(50*time.Millisecond - time.Nanosecond)
		synctest.Wait()
		requirePending(t, returned, "waitClosed returned before its deadline")
		time.Sleep(time.Nanosecond)
		requireCompleted(t, returned)
	})
}

// Cancellation-led shutdown: the sessions must not be released until the
// fan-out has finished delivering into them.
//
// This is the ordering ServeWithContext's last interrupt establishes, tested
// without the SSH stack because what matters is the sequence, not the
// transport. It is deterministic because the sink is gated: delivery is
// provably outstanding when the release is attempted, which a functional test
// cannot arrange — there, whether anything is still queued depends on window
// and socket sizes that differ per platform.
func TestReleaseSessionsWaitsForTheFanOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		release := sync.OnceFunc(func() { close(gate) })
		defer release()
		var guestOut recordingWriter
		guest := uio.NewAsyncWriter(&gatedWriter{gate: gate, rec: &guestOut},
			uio.DefaultGuestBufferSize, nil)
		defer func() { _ = guest.Close() }()

		writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
		require.NoError(t, writers.Append(guest))
		_, _ = writers.Write([]byte("tail of the session"))

		released := make(chan struct{})
		cmdDone := make(chan struct{})
		go func() {
			defer close(cmdDone)
			flushCtx, cancel := context.WithTimeout(context.Background(), guestFlushTimeout)
			defer cancel()
			_ = writers.Shutdown(flushCtx)
		}()
		go func() {
			defer close(released)
			releaseSessions(cmdDone, outputDrainTimeout+guestFlushTimeout, func() {})
		}()

		synctest.Wait()
		requirePending(t, released, "sessions were released while output was still being delivered")
		release()
		requireCompleted(t, released)
		require.Equal(t, "tail of the session", string(guestOut.bytes()))
	})
}

// gatedWriter delivers nothing until its gate is closed.
type gatedWriter struct {
	gate    <-chan struct{}
	rec     *recordingWriter
	started chan struct{}
	once    sync.Once
}

func (g *gatedWriter) Write(p []byte) (int, error) {
	if g.started != nil {
		g.once.Do(func() { close(g.started) })
	}
	<-g.gate
	return g.rec.Write(p)
}
