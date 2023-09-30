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

	for i := len(t.writers) - 1; i > 0; i-- {
		for _, v := range writers {
			if t.writers[i] == v {
				t.writers = append(t.writers[:i], t.writers[i+1:]...)
				break
			}
		}
	}
}

func (t *MultiWriter) Write(p []byte) (n int, err error) {
	t.buffer.Append(p)

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	for _, w := range t.writers {
		n, err = w.Write(p)
		if err != nil {
			return
		}
		if n != len(p) {
			err = io.ErrShortWrite
			return
		}
	}

	return len(p), nil
}
