package io

import (
	"io"
	"sync"
)

func NewMultiWriter(writers ...io.Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

// MultiWriter is a concurrent safe writer that allows appending/removing writers.
// Newly appended writers get the last write to preserve last output.
type MultiWriter struct {
	mu      sync.Mutex
	writers []io.Writer
	cache   []byte
}

func (t *MultiWriter) Append(writers ...io.Writer) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// write last cache to new writers
	if len(t.cache) > 0 {
		for _, w := range writers {
			_, err := w.Write(t.cache)
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
	t.cache = make([]byte, len(p))
	copy(t.cache, p)

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
