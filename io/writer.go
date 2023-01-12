package io

import (
	"bytes"
	"io"
	"sync"
)

func NewMultiWriter(writers ...io.Writer) *MultiWriter {
	return &MultiWriter{writers: writers, cache: bytes.NewBuffer(nil)}
}

// MultiWriter is a concurrent safe writer that allows appending/removing writers.
// Newly appended writers get the last write to preserve last output.
type MultiWriter struct {
	mu      sync.Mutex
	writers []io.Writer
	cache   *bytes.Buffer
}

func (t *MultiWriter) Append(writers ...io.Writer) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// write last cache to new writers
	b := t.cache.Bytes()
	if len(b) > 0 {
		for _, w := range writers {
			_, err := w.Write(b)
			if err != nil {
				return err
			}
		}
	}

	t.writers = append(t.writers, writers...)

	return nil
}

func (t *MultiWriter) Remove(writers ...io.Writer) {
	t.mu.Lock()
	defer t.mu.Unlock()

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
	t.mu.Lock()
	defer t.mu.Unlock()

	// reset cache
	t.cache.Reset()

	// cache last write
	n, err = t.cache.Write(p)
	if err != nil {
		return n, err
	}

	// return a new copy
	// and write to all writers
	b := t.cache.Bytes()

	for _, w := range t.writers {
		n, err = w.Write(b)
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
