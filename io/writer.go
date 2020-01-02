package io

import (
	"bytes"
	"io"
	"sync"
)

func NewMultiWriter(writers ...io.Writer) *MultiWriter {
	cache := bytes.NewBuffer(nil)
	writers = append(writers, cache)

	w := make([]io.Writer, len(writers))
	copy(w, append(writers, cache))

	return &MultiWriter{writers: w, cache: cache}
}

// MultiWriter is a concurrent safe writer that allows appending/removing writers.
// Newly appended writers get the last write to preserve last output.
type MultiWriter struct {
	writers []io.Writer
	mu      sync.Mutex
	cache   *bytes.Buffer
}

func (t *MultiWriter) Append(writers ...io.Writer) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.writers = append(t.writers, writers...)

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
