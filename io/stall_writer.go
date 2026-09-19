package io

import (
	"io"
	"sync"
	"time"
)

// StallWriter writes synchronously to w in chunks, stamping progress after
// each one, and calls onStall once if a write has been outstanding with no
// chunk completed for timeout.
//
// It exists for the primary client's pacing. The primary's writer is attached
// to the fan-out synchronously, so the command cannot outrun the terminal, and
// MultiWriter.Write holds writeMu across it: a primary that stops reading its
// SSH channel therefore blocks every other writer and every new attach. The
// bound has to measure progress rather than duration — "a write took 5 s" and
// "no chunk has completed for 5 s" treat a slow-but-working terminal
// differently, and only the second is worth acting on — and it has to be
// armed only while a write is outstanding, or a healthy shell at a prompt
// would be judged stalled for producing nothing.
//
// A single blocking Write is unobservable from outside, which is why the
// writer chunks: the chunk is the unit of progress. The progress clock starts
// with each write, so the first chunk after a quiet period is not judged
// against a stale stamp.
//
// onStall runs on the watchdog's goroutine and must not take writeMu: the lock
// is held by the write it is there to release. Closing the client's SSH
// connection is what it is for; see host/internal.
type StallWriter struct {
	w       io.Writer
	chunk   int
	timeout time.Duration
	onStall func()

	mu          sync.Mutex
	outstanding bool
	progress    time.Time

	stallOnce sync.Once
	closeOnce sync.Once
	closed    chan struct{}
}

// NewStallWriter starts the watchdog. chunk bounds the bytes handed to w per
// call; onStall may be nil.
func NewStallWriter(w io.Writer, chunk int, timeout time.Duration, onStall func()) *StallWriter {
	if chunk <= 0 {
		chunk = 4096
	}
	s := &StallWriter{w: w, chunk: chunk, timeout: timeout, onStall: onStall, closed: make(chan struct{})}
	go s.watch()
	return s
}

// Write hands p to w in chunks and reports a short write from w as an error,
// the way MultiWriter would refuse it.
func (s *StallWriter) Write(p []byte) (int, error) {
	s.arm()
	defer s.disarm()

	written := 0
	for written < len(p) {
		end := min(written+s.chunk, len(p))
		n, err := s.w.Write(p[written:end])
		written += n
		s.stamp()
		if err != nil {
			return written, err
		}
		if n != end-(written-n) {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

// Close stops the watchdog. It does not close w and does not release a write
// already blocked in it; only onStall's action can do that.
func (s *StallWriter) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (s *StallWriter) arm() {
	s.mu.Lock()
	s.outstanding = true
	s.progress = time.Now()
	s.mu.Unlock()
}

func (s *StallWriter) disarm() {
	s.mu.Lock()
	s.outstanding = false
	s.mu.Unlock()
}

func (s *StallWriter) stamp() {
	s.mu.Lock()
	s.progress = time.Now()
	s.mu.Unlock()
}

// watch polls at a quarter of the timeout. Polling rather than a timer per
// write keeps the write path to two mutex operations per chunk.
func (s *StallWriter) watch() {
	interval := s.timeout / 4
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
			s.mu.Lock()
			stalled := s.outstanding && time.Since(s.progress) > s.timeout
			s.mu.Unlock()
			if stalled {
				s.stallOnce.Do(func() {
					if s.onStall != nil {
						s.onStall()
					}
				})
				return
			}
		}
	}
}
