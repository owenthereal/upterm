package io

import (
	"bytes"
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
