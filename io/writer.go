package io

import (
	"io"
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
type MultiWriter struct {
	writeMu sync.Mutex
	writers []io.Writer

	buffer *buffer
}

func (t *MultiWriter) Append(writers ...io.Writer) error {
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

	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.writers = append(t.writers, writers...)

	return nil
}

func (t *MultiWriter) Remove(writers ...io.Writer) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

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
// The writers are snapshotted under the lock and written to with the lock
// released. Holding it across the writes made Append and Remove wait on
// whatever the slowest attached writer was doing, and a guest that stops
// reading its SSH channel blocks in Write indefinitely once the channel window
// fills. That wedged the host: HandleSession removes its writer on the way out,
// so Remove blocked, HandleSession never returned, and the client-left event it
// emits on the way out was never sent. It also meant one stuck guest stopped
// output reaching every other guest and the host's own terminal.
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
	t.buffer.Append(p)

	t.writeMu.Lock()
	writers := make([]io.Writer, len(t.writers))
	copy(writers, t.writers)
	t.writeMu.Unlock()

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
