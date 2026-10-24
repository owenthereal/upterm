package internal

import (
	"sync"
	"time"
)

// ptyCloser owns the single asynchronous Close and its completion. Close may
// block on platform I/O, so neither starting it nor escalating waits for it.
type ptyCloser struct {
	ptmx PTY
	once sync.Once
	done chan struct{}
	// The termination actor sets until before the group's final cleanup joins.
	until time.Time
}

func newPTYCloser(ptmx PTY) *ptyCloser { return &ptyCloser{ptmx: ptmx, done: make(chan struct{})} }
func (c *ptyCloser) start() {
	c.once.Do(func() { go func() { defer close(c.done); _ = c.ptmx.Close() }() })
}
func (c *ptyCloser) wait(until time.Time) bool {
	if !c.until.IsZero() && c.until.Before(until) {
		until = c.until
	}
	select {
	case <-c.done:
		return true
	default:
	}
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-c.done:
		return true
	case <-timer.C:
		return false
	}
}
