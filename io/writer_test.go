package io

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_MultiWriter(t *testing.T) {
	assert := assert.New(t)

	w1 := bytes.NewBuffer(nil)
	w := NewMultiWriter(1, w1)

	r := bytes.NewBufferString("hello1")
	_, _ = io.Copy(w, r)

	assert.Equal("hello1", w1.String())

	// append w2
	r = bytes.NewBufferString("hello2")
	w2 := bytes.NewBuffer(nil)
	_ = w.Append(w2)
	_, _ = io.Copy(w, r)

	assert.Equal("hello1hello2", w1.String())
	assert.Equal("hello1hello2", w2.String())

	// append w3
	r = bytes.NewBufferString("hello3")
	w3 := bytes.NewBuffer(nil)
	_ = w.Append(w3)
	_, _ = io.Copy(w, r)

	assert.Equal("hello1hello2hello3", w1.String())
	assert.Equal("hello1hello2hello3", w2.String())
	assert.Equal("hello2hello3", w3.String())

	// remove w2
	r = bytes.NewBufferString("hello4")
	w.Remove(w2)
	_, _ = io.Copy(w, r)

	assert.Equal("hello1hello2hello3hello4", w1.String())
	assert.Equal("hello1hello2hello3", w2.String())
	assert.Equal("hello2hello3hello4", w3.String())
}

// blockingWriter models a guest whose SSH channel window has filled because it
// stopped reading: Write blocks until released. It closes entered first, so a
// test can wait for the fan-out to actually reach a writer rather than for the
// goroutine that will eventually call Write to be scheduled.
type blockingWriter struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (b *blockingWriter) Write(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return len(p), nil
}

type failingWriter struct{ writes int }

func (f *failingWriter) Write(p []byte) (int, error) {
	f.writes++
	return 0, errors.New("guest went away")
}

// A stuck writer must not stop the session being modified around it.
//
// MultiWriter used to hold its lock across every write, so a guest that stopped
// reading blocked Remove. The host removes its writer as HandleSession returns,
// so HandleSession never returned and never emitted the client-left event that
// is deferred behind it.
func TestMultiWriterStuckWriterDoesNotBlockRemove(t *testing.T) {
	stuck := newBlockingWriter()
	defer close(stuck.release)

	w := NewMultiWriter(1)
	require.NoError(t, w.Append(stuck))

	go func() { _, _ = w.Write([]byte("shell output")) }()

	// Wait for the fan-out to be inside the stuck writer, not merely for the
	// writing goroutine to have started. Signalling from the caller side let
	// Remove win the race and pass without ever exercising the bug.
	<-stuck.entered

	done := make(chan struct{})
	go func() { defer close(done); w.Remove(stuck) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Remove blocked behind a stuck writer")
	}
}

// Concurrent producers must not reach the same writer at once.
//
// Most attached writers are not concurrency safe, and even one that is would
// end up with two writes interleaved. Run under -race, two goroutines writing
// into a shared bytes.Buffer report a data race if the fan-out is unserialized.
func TestMultiWriterConcurrentWritesAreSerialized(t *testing.T) {
	var shared bytes.Buffer

	w := NewMultiWriter(1)
	require.NoError(t, w.Append(&shared))

	const (
		producers = 4
		writes    = 200
	)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range producers {
		wg.Go(func() {
			<-start
			for range writes {
				_, _ = w.Write([]byte("chunk"))
			}
		})
	}
	close(start)
	wg.Wait()

	assert.Equal(t, producers*writes*len("chunk"), shared.Len(), "every write should land intact")
}

// sliceWriter is a legal io.Writer whose dynamic type cannot be compared, so
// `t.writers[i] == v` inside Remove would panic on it.
type sliceWriter []byte

func (s sliceWriter) Write(p []byte) (int, error) { return len(p), nil }

type funcWriter func(p []byte) (int, error)

func (f funcWriter) Write(p []byte) (int, error) { return f(p) }

// wrappedWriter hides the problem one level down. Its type is comparable --
// a struct with an interface field is -- so a check that asks the type says
// yes, and the comparison inside Remove panics anyway when the writers it
// holds are funcs. Decorators shaped exactly like this are ordinary: the host
// attaches one, TerminalQueryFilter, and it is only safe because it is
// attached by pointer.
type wrappedWriter struct{ io.Writer }

// Append refuses a writer Remove could never match.
//
// Write removes the writers that failed it, so a non-comparable writer turns
// an ordinary guest disconnect into a panic in the host's pty copy, which
// takes the process down. Reporting it from Append keeps the failure at the
// call that can still do something about it.
func TestMultiWriterAppendRejectsUnremovableWriters(t *testing.T) {
	discard := funcWriter(func(p []byte) (int, error) { return len(p), nil })

	tests := []struct {
		name   string
		writer io.Writer
	}{
		{name: "nil", writer: nil},
		{name: "slice", writer: sliceWriter(nil)},
		{name: "func", writer: discard},
		{name: "struct wrapping a func writer", writer: wrappedWriter{discard}},
		{name: "struct wrapping a slice writer", writer: wrappedWriter{sliceWriter(nil)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Error(t, NewMultiWriter(1).Append(tt.writer))
		})
	}
}

// The check is on the value, so it must not turn away a writer that is
// perfectly removable. A decorator holding a pointer is the shape the host
// actually attaches, and rejecting it would stop guests joining at all.
func TestMultiWriterAppendAcceptsComparableWrappers(t *testing.T) {
	var inner bytes.Buffer
	wrapped := wrappedWriter{&inner}

	w := NewMultiWriter(1)
	require.NoError(t, w.Append(wrapped))

	_, err := w.Write([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, "hello", inner.String())

	// Removal is where an unremovable writer would have panicked, and Write
	// does it unprompted for any writer that fails, so this is the half of
	// the invariant that keeps the panic out of the host's pty copy.
	w.Remove(wrapped)
	_, err = w.Write([]byte("gone"))
	require.NoError(t, err)
	assert.Equal(t, "hello", inner.String(), "the wrapper should have been removable by identity")
}

// A writer that fails must not fail the producer.
//
// The producer is the host's pty copy. Returning an error aborted it, which
// ended the command and tore the session down, so one guest disconnecting at
// the wrong moment killed everyone's session.
func TestMultiWriterFailingWriterIsDroppedNotPropagated(t *testing.T) {
	bad := &failingWriter{}
	var good bytes.Buffer

	w := NewMultiWriter(1)
	require.NoError(t, w.Append(bad))
	require.NoError(t, w.Append(&good))

	n, err := w.Write([]byte("first"))
	require.NoError(t, err, "a broken guest must not fail the host's output copy")
	assert.Equal(t, len("first"), n)
	assert.Equal(t, "first", good.String(), "a broken guest must not silence the writers after it")

	_, err = w.Write([]byte("second"))
	require.NoError(t, err)
	assert.Equal(t, "firstsecond", good.String())
	assert.Equal(t, 1, bad.writes, "a writer that failed should be dropped, not retried")
}

// Remove used to count down to index 1, so whatever sat at index 0 was stuck
// there for the life of the session.
func TestMultiWriterRemoveFirstWriter(t *testing.T) {
	var first, second bytes.Buffer

	w := NewMultiWriter(1)
	require.NoError(t, w.Append(&first))
	require.NoError(t, w.Append(&second))

	w.Remove(&first)
	_, err := w.Write([]byte("hello"))
	require.NoError(t, err)

	assert.Empty(t, first.String(), "the writer at index 0 should have been removed")
	assert.Equal(t, "hello", second.String())
}

// A writer joining a live session must see a contiguous stream: no byte
// delivered twice, none missing. Append replays the buffer and joins the member
// list as two separate steps today, with no lock spanning them, so a concurrent
// Write lands either side of the gap.
func TestMultiWriterAppendIsAtomicWithTheFanOut(t *testing.T) {
	for attempt := range 50 {
		w := NewMultiWriter(5)

		produced := make(chan string, 1)
		stop := make(chan struct{})
		go func() {
			var sent []byte
			for i := 0; ; i++ {
				select {
				case <-stop:
					produced <- string(sent)
					return
				default:
				}
				p := []byte{byte('a' + i%26)}
				sent = append(sent, p...)
				_, _ = w.Write(p)
			}
		}()

		time.Sleep(time.Duration(attempt%5) * time.Millisecond)
		var joined bytes.Buffer
		require.NoError(t, w.Append(&joined))
		time.Sleep(time.Millisecond)
		close(stop)
		all := <-produced

		got := joined.String()
		require.NotEmpty(t, got, "a joining writer should receive the replay buffer")
		require.Contains(t, all, got,
			"attempt %d: a joining writer saw bytes that were duplicated or skipped", attempt)
	}
}

// Data built its result with make([][]byte, len(queue)) and then appended, so it
// returned N nil entries before the N real ones and every newly attached writer
// received N zero-length writes.
func TestMultiWriterReplayHasNoEmptyWrites(t *testing.T) {
	w := NewMultiWriter(3)
	_, _ = w.Write([]byte("one"))
	_, _ = w.Write([]byte("two"))

	var rec recordingWriter
	require.NoError(t, w.Append(&rec))

	require.Equal(t, []int{3, 3}, rec.writeSizes(), "replay must not emit empty writes")
	require.Equal(t, "onetwo", string(rec.bytes()))
}

func TestMultiWriterZeroSizedReplayBufferDoesNotPanic(t *testing.T) {
	w := NewMultiWriter(0)
	var rec recordingWriter
	require.NoError(t, w.Append(&rec))
	require.NotPanics(t, func() { _, _ = w.Write([]byte("output")) })
	require.Equal(t, "output", string(rec.bytes()))
}

func TestMultiWriterShutdownFlushesAsyncMembers(t *testing.T) {
	gate := newGateWriter()
	sink := NewAsyncWriter(gate, DefaultGuestBufferSize, nil)
	defer func() { _ = sink.Close() }()

	w := NewMultiWriter(5)
	require.NoError(t, w.Append(sink))
	_, _ = w.Write([]byte("last line of the session"))
	<-gate.entered

	shutdown := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdown <- w.Shutdown(ctx)
	}()

	select {
	case <-shutdown:
		t.Fatal("Shutdown returned before the sink drained")
	case <-time.After(100 * time.Millisecond):
	}

	close(gate.release)
	select {
	case err := <-shutdown:
		require.NoError(t, err)
		require.Equal(t, "last line of the session", string(gate.bytes()))
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown never returned")
	}
}

// The SSH server keeps serving while the flush runs. Without the quiesce, a
// guest attaching after the snapshot has its replay queued into a sink nobody
// will flush, and teardown closes it before delivery: an empty screen and a
// disconnect.
func TestMultiWriterShutdownRefusesLaterAppends(t *testing.T) {
	w := NewMultiWriter(5)
	var before bytes.Buffer
	require.NoError(t, w.Append(&before))

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, w.Shutdown(ctx))

	var after bytes.Buffer
	require.ErrorIs(t, w.Append(&after), ErrClosed)
}

// The sequential case above proves the door is shut; this proves there is no
// gap in front of it. An attach racing the quiesce must land on one side or
// the other — attached and therefore flushed, or refused — never attached to a
// snapshot that has already been taken, which is the outcome that leaves a
// guest with a queued replay nobody will deliver.
func TestMultiWriterAppendRacingShutdownHasOnlyTwoOutcomes(t *testing.T) {
	for attempt := range 50 {
		w := NewMultiWriter(5)
		_, _ = w.Write([]byte("output"))

		var out recordingWriter
		sink := NewAsyncWriter(&out, DefaultGuestBufferSize, nil)

		var (
			wg        sync.WaitGroup
			appendErr error
		)
		wg.Add(2)
		go func() { defer wg.Done(); appendErr = w.Append(sink) }()
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = w.Shutdown(ctx)
		}()
		wg.Wait()

		if appendErr == nil {
			require.Equal(t, "output", string(out.bytes()),
				"attempt %d: an attach that succeeded must have been flushed", attempt)
		} else {
			require.ErrorIs(t, appendErr, ErrClosed, "attempt %d", attempt)
			require.Empty(t, out.bytes(), "attempt %d: a refused attach must receive nothing", attempt)
		}
		_ = sink.Close()
	}
}

func TestMultiWriterShutdownIgnoresPlainWriters(t *testing.T) {
	w := NewMultiWriter(5)
	var plain bytes.Buffer
	require.NoError(t, w.Append(&plain))
	_, _ = w.Write([]byte("output"))

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, w.Shutdown(ctx), "a synchronous writer is delivered by definition")
}

func TestMultiWriterShutdownGivesUpOnAStuckSink(t *testing.T) {
	gate := newGateWriter()
	defer close(gate.release)
	sink := NewAsyncWriter(gate, DefaultGuestBufferSize, nil)
	defer func() { _ = sink.Close() }()

	w := NewMultiWriter(5)
	require.NoError(t, w.Append(sink))
	_, _ = w.Write([]byte("never delivered"))
	<-gate.entered

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, w.Shutdown(ctx), context.DeadlineExceeded)
}

// The issue, end to end at the fan-out level: one guest that has stopped
// reading must not stall the host's terminal or any other guest, and must
// itself be dropped rather than tolerated.
//
// Before per-guest buffering, the stuck writer held the serial fan-out inside
// its Write and nothing after it in the slice received anything at all.
func TestMultiWriterSlowGuestDoesNotStallTheSession(t *testing.T) {
	const sinkCap = 4 << 10

	var hostStdout recordingWriter // attached unwrapped, as the host's own is

	healthyOut := &recordingWriter{}
	healthy := NewAsyncWriter(healthyOut, DefaultGuestBufferSize, nil)
	defer func() { _ = healthy.Close() }()

	stuckOut := newGateWriter()
	defer close(stuckOut.release)
	dropped := make(chan error, 1)
	stuck := NewAsyncWriter(stuckOut, sinkCap, func(err error) { dropped <- err })
	defer func() { _ = stuck.Close() }()

	w := NewMultiWriter(5)
	require.NoError(t, w.Append(&hostStdout))
	require.NoError(t, w.Append(stuck))
	require.NoError(t, w.Append(healthy))

	// Fill the stuck guest's buffer and keep going, as a `cat` of a large file
	// would. Run on its own goroutine and race it against a timeout, the same
	// way TestAsyncWriterWriteDoesNotBlockOnStuckWriter does: nothing here
	// bounds an individual w.Write call, so a regression that reintroduces
	// blocking would otherwise hang this goroutine until the package's
	// -timeout killed the whole binary instead of failing just this test.
	line := bytes.Repeat([]byte("x"), 1<<10)
	var (
		want     []byte
		writeErr error
		writeN   int
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 64 {
			want = append(want, line...)
			writeN, writeErr = w.Write(line)
			if writeErr != nil || writeN != len(line) {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the fan-out blocked on a stuck guest")
	}
	// require.FailNow, which these call on failure, must only run on the test
	// goroutine, so the checks are made here rather than inside the goroutine
	// above.
	require.NoError(t, writeErr, "the fan-out never reports a guest's failure")
	require.Equal(t, len(line), writeN)

	select {
	case err := <-dropped:
		require.ErrorIs(t, err, ErrOverflow)
	case <-time.After(5 * time.Second):
		t.Fatal("the stuck guest was never dropped")
	}

	require.Equal(t, want, hostStdout.bytes(), "the host's terminal must see everything")
	require.Eventually(t, func() bool { return bytes.Equal(healthyOut.bytes(), want) },
		5*time.Second, time.Millisecond, "a healthy guest must see everything")

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, w.Shutdown(ctx), "a dropped guest must not fail shutdown")
}
