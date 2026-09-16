package internal

import (
	"errors"
	"sync"

	"github.com/owenthereal/upterm/internal/termsize"
)

// errNoPty is what a shared handle answers once it is known that no pty
// will ever be set: the gate timed out or the command failed to start.
var errNoPty = errors.New("session ended before its command started")

// sharedPTY is the command's pty as the doors see it.
//
// It exists because the host door serves before the command starts: the
// first host client's subscription is what the command's start waits for,
// so that client's input and resize requests can arrive before there is a
// pty to deliver them to. Writes wait for the pty; the first geometry offered
// before it exists is what the pty is opened with. Everything else delegates.
type sharedPTY struct {
	ready chan struct{}
	done  chan struct{}

	mu      sync.Mutex
	ptmx    PTY
	initial termsize.Size
	once    sync.Once
}

func newSharedPTY() *sharedPTY {
	return &sharedPTY{ready: make(chan struct{}), done: make(chan struct{})}
}

// set publishes the pty. Once.
func (s *sharedPTY) set(p PTY) {
	s.once.Do(func() {
		s.mu.Lock()
		s.ptmx = p
		s.mu.Unlock()
		close(s.ready)
	})
}

// abandon says no pty is coming, releasing every waiter with errNoPty.
func (s *sharedPTY) abandon() {
	s.once.Do(func() { close(s.done) })
}

// offerSize records the first valid geometry seen before the pty exists.
func (s *sharedPTY) offerSize(size termsize.Size) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ptmx == nil && !s.initial.Valid() && size.Valid() {
		s.initial = size
	}
}

func (s *sharedPTY) initialSize() termsize.Size {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initial
}

// wait blocks until the pty exists or never will.
func (s *sharedPTY) wait() (PTY, error) {
	select {
	case <-s.ready:
	case <-s.done:
		return nil, errNoPty
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ptmx, nil
}

func (s *sharedPTY) Write(p []byte) (int, error) {
	ptmx, err := s.wait()
	if err != nil {
		return 0, err
	}
	return ptmx.Write(p)
}

func (s *sharedPTY) Read(p []byte) (int, error) {
	ptmx, err := s.wait()
	if err != nil {
		return 0, err
	}
	return ptmx.Read(p)
}

// Setsize before the pty exists records the geometry it will open with, and
// reports success: the resize will have happened, at open.
func (s *sharedPTY) Setsize(h, w int) error {
	select {
	case <-s.ready:
	default:
		s.offerSize(termsize.Size{Cols: w, Rows: h})
		return nil
	}
	s.mu.Lock()
	ptmx := s.ptmx
	s.mu.Unlock()
	return ptmx.Setsize(h, w)
}

// Redraw before the pty exists is a no-op: there is no process to nudge, and
// the client that arrived early has nothing to repaint — the command's first
// output is still ahead of it. Never waits, unlike Write: the nudge runs on
// the attaching client's handler, which must reach its actors.
func (s *sharedPTY) Redraw() error {
	select {
	case <-s.ready:
	default:
		return nil
	}
	s.mu.Lock()
	ptmx := s.ptmx
	s.mu.Unlock()
	return ptmx.Redraw()
}

func (s *sharedPTY) Close() error {
	ptmx, err := s.wait()
	if err != nil {
		return nil
	}
	return ptmx.Close()
}

func (s *sharedPTY) Wait() error {
	ptmx, err := s.wait()
	if err != nil {
		return err
	}
	return ptmx.Wait()
}

func (s *sharedPTY) Kill() error {
	ptmx, err := s.wait()
	if err != nil {
		return err
	}
	return ptmx.Kill()
}
