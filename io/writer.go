package io

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
)

type buffer struct {
	mu sync.Mutex

	queue [][]byte
	size  int
}

func (c *buffer) Append(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// remove first element if queue is full
	if len(c.queue) >= c.size {
		c.queue = c.queue[1:]
	}

	pp := make([]byte, len(p))
	copy(pp, p)

	c.queue = append(c.queue, pp)
}

func (c *buffer) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.queue)
}

func (c *buffer) Data() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	result := make([][]byte, len(c.queue))
	return append(result, c.queue...)
}

func NewMultiWriter(bufferSize int, writers ...io.Writer) *MultiWriter {
	return &MultiWriter{
		writers: writers,
		buffer:  &buffer{size: bufferSize},
	}
}

// MultiWriter is a concurrent safe writer that allows appending/removing writers.
// Newly appended writers get the last write to preserve last output.
//
// Attached writers are tracked by identity, so they must be comparable; see
// checkRemovable, which is how Append enforces it. NewMultiWriter does not,
// because it cannot report the error, so prefer Append.
type MultiWriter struct {
	// writeMu serializes the fan-out. Two producers must not write to the
	// same attached writer at once: many writers are not concurrency safe,
	// and even those that are would interleave halves of two writes.
	writeMu sync.Mutex

	// membersMu guards writers. It is deliberately not writeMu: it is never
	// held while writing to an attached writer, so Append and Remove never
	// wait on one. See Write for why that matters.
	membersMu sync.Mutex
	writers   []io.Writer

	buffer *buffer
}

func (t *MultiWriter) Append(writers ...io.Writer) error {
	// Reject anything Remove could not later take back out, before it is
	// attached and before it is written to.
	for _, w := range writers {
		if err := checkRemovable(w); err != nil {
			return err
		}
	}

	// write last buffer to new writers
	if t.buffer.Size() > 0 {
		for _, w := range writers {
			for _, d := range t.buffer.Data() {
				_, err := w.Write(d)
				if err != nil {
					return err
				}
			}
		}
	}

	t.membersMu.Lock()
	defer t.membersMu.Unlock()
	t.writers = append(t.writers, writers...)

	return nil
}

// checkRemovable rejects a writer that Remove could not match.
//
// Writers are tracked by identity, so Remove compares interface values, and
// comparing two interface values that hold the same non-comparable dynamic
// type -- a slice, map, or func with a value receiver -- panics at run time.
// Write removes the writers that failed it, so that panic would land in the
// host's pty copy and take the whole process down. Refusing the writer at the
// door reports the mistake to the caller that made it, at the one point where
// it is still fixable.
//
// The question has to be asked of the value, not the type. A struct wrapping
// an io.Writer is a comparable type, because an interface field is one, yet
// comparing two of them still panics if the writers inside are funcs.
// reflect.Value.Comparable walks into the interface and answers for what is
// actually there, and promises the comparison will not panic when it says yes.
//
// This is checked once per attached writer, on a path that runs when a guest
// joins, so the reflection costs nothing that matters.
func checkRemovable(w io.Writer) error {
	if w == nil {
		return errors.New("multiwriter: writer is nil")
	}
	if !reflect.ValueOf(w).Comparable() {
		return fmt.Errorf("multiwriter: writer of type %T is not comparable, so it could never be removed", w)
	}
	return nil
}

func (t *MultiWriter) Remove(writers ...io.Writer) {
	t.membersMu.Lock()
	defer t.membersMu.Unlock()

	// Counts down to zero: the loop used to stop at 1, so whichever writer sat
	// at index 0 could never be removed.
	for i := len(t.writers) - 1; i >= 0; i-- {
		for _, v := range writers {
			if t.writers[i] == v {
				t.writers = append(t.writers[:i], t.writers[i+1:]...)
				break
			}
		}
	}
}

// Write fans p out to every attached writer. It always reports success.
//
// Two things here are deliberate, and both were bugs.
//
// The membership lock is released before any writer is written to. Holding one
// lock for both jobs made Append and Remove wait on whatever the slowest
// attached writer was doing, and a guest that stops reading its SSH channel
// blocks in Write indefinitely once the channel window fills. That wedged the
// host: HandleSession removes its writer on the way out, so Remove blocked,
// HandleSession never returned, and the client-left event it emits on the way
// out was never sent. Writes are still serialized among themselves, by
// writeMu, because concurrent producers must not interleave in a writer or
// race one that is not concurrency safe.
//
// A failing writer is dropped rather than reported. This is a broadcast to
// whoever is attached, and the producer is the host's pty: returning an error
// aborted the io.Copy feeding it, which ended the command and tore down the
// whole session. One guest losing its connection at the wrong moment must not
// take the session with it. Errors used to abandon the rest of the slice too,
// so a broken guest silenced everyone attached after it.
//
// A writer removed between the snapshot and the write still receives this one
// write. That is harmless: it is a session on its way out.
//
// Still outstanding: the writes are serial, so a guest that has stopped reading
// holds up the fan-out for everyone until its write returns. Fixing that needs
// per-writer buffering, so that a guest which cannot keep up is dropped rather
// than allowed to slow the session down. Tracked in owenthereal/upterm#524.
func (t *MultiWriter) Write(p []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	t.buffer.Append(p)

	t.membersMu.Lock()
	writers := make([]io.Writer, len(t.writers))
	copy(writers, t.writers)
	t.membersMu.Unlock()

	var failed []io.Writer
	for _, w := range writers {
		n, err := w.Write(p)
		if err != nil || n != len(p) {
			failed = append(failed, w)
		}
	}

	// Drop what broke, so the next write does not retry it.
	if len(failed) > 0 {
		t.Remove(failed...)
	}

	return len(p), nil
}
