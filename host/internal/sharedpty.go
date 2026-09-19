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
// pty to deliver them to. Writes wait for the pty; the last geometry offered
// before it exists is what the pty is opened with -- each offer is already
// the minimum across the terminals attached so far, computed by
// resizeWindow, so the most recent one is the current answer. Everything
// else delegates.
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
//
// If a size was recorded while the pty did not exist, it is applied here
// before ready closes -- the gap Setsize's fast path otherwise leaves open:
// cmd.Start reads initialSize once, before this runs, so a size offered
// between that read and this call would otherwise be recorded and then
// never looked at again.
//
// Applied under mu, not after releasing it. Between publishing s.ptmx and
// applying the recorded size, a concurrent Setsize would take the delegating
// branch and set the pty to the size it was actually asked for — and then
// this call would put the older recorded size back over it, which is the
// very thing this handle exists to prevent. The ioctl costs microseconds;
// correctness of the last-writer is worth holding the lock for it.
//
// A pinned session (--pty-size) is not a special case: its Setsize already
// reports success without moving anything. The error is dropped because
// there is nothing here to tell — no logger, and no caller that could act
// on it — and the size is reasserted by the next resize either way.
func (s *sharedPTY) set(p PTY) {
	s.once.Do(func() {
		s.mu.Lock()
		s.ptmx = p
		if s.initial.Valid() {
			_ = p.Setsize(s.initial.Rows, s.initial.Cols)
		}
		s.mu.Unlock()
		close(s.ready)
	})
}

// abandon says no pty is coming, releasing every waiter with errNoPty.
func (s *sharedPTY) abandon() {
	s.once.Do(func() { close(s.done) })
}

// offerSize records the latest valid geometry seen before the pty exists.
func (s *sharedPTY) offerSize(size termsize.Size) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ptmx == nil && size.Valid() {
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
// reports success: the resize will have happened, at open. Once the pty
// exists it delegates.
//
// The decision -- record or delegate -- is made under mu in one step rather
// than by consulting the ready channel and then separately locking: the
// latter left a window between the two where a resize could land after
// ready closed but before the lock was taken, and fall through recorded
// nowhere. offerSize is not reused for the recording half, because reaching
// it would mean unlocking and relocking, reopening exactly that window.
func (s *sharedPTY) Setsize(h, w int) error {
	s.mu.Lock()
	if s.ptmx == nil {
		if size := (termsize.Size{Cols: w, Rows: h}); size.Valid() {
			s.initial = size
		}
		s.mu.Unlock()
		return nil
	}
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
