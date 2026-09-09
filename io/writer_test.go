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

// Append refuses a writer Remove could never match.
//
// Write removes the writers that failed it, so a non-comparable writer turns
// an ordinary guest disconnect into a panic in the host's pty copy, which
// takes the process down. Reporting it from Append keeps the failure at the
// call that can still do something about it.
func TestMultiWriterAppendRejectsUnremovableWriters(t *testing.T) {
	w := NewMultiWriter(1)

	require.Error(t, w.Append(sliceWriter(nil)), "a non-comparable writer should be refused")
	require.Error(t, w.Append(nil), "a nil writer should be refused")

	var good bytes.Buffer
	require.NoError(t, w.Append(&good))

	_, err := w.Write([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, "hello", good.String(), "a refused writer should not have been attached")
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
