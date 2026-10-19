package host

import (
	"testing"
	"time"
)

// wakeups turns a hook into a wait. The hook pokes; the waiter re-reads the
// state it waits on after each poke, and accepts only what it reads. A poke
// is a wakeup, not a history: pokes coalesce in a one-slot channel, so all a
// waiter learns is that something may have changed since it last looked.
// One waiter at a time, since a second would take the first's wakeup.
type wakeups struct {
	notify chan struct{}
}

func newWakeups() *wakeups {
	return &wakeups{notify: make(chan struct{}, 1)}
}

// poke wakes the waiter, or leaves a wakeup for the next wait. It never
// blocks and never touches a test, so it can be a hook on any goroutine,
// including one still running after its test has ended.
func (w *wakeups) poke() {
	select {
	case w.notify <- struct{}{}:
	default: // a wakeup is already pending, and the re-read it brings will see this change
	}
}

// poked is poke with onRecord's signature.
func (w *wakeups) poked(string) { w.poke() }

// until returns once cond holds, reading it at the start and again after
// each wakeup. A change made after a read pokes after it is made, so a
// re-read always follows it. within only bounds a wait that has already
// failed, which describe then accounts for.
func (w *wakeups) until(t *testing.T, within time.Duration, cond func() bool, describe func() string) {
	t.Helper()
	if cond() {
		return
	}
	w.untilNotified(t, within, cond, describe)
}

// untilNotified is until without the read at the start: it accepts cond
// only on a re-read that follows a wakeup received since newWakeups, so its
// returning proves a notification arrived. The waiter has to be armed before
// the act.
func (w *wakeups) untilNotified(t *testing.T, within time.Duration, cond func() bool, describe func() string) {
	t.Helper()
	timeout := time.NewTimer(within)
	defer timeout.Stop()
	woken := 0
	for {
		select {
		case <-w.notify:
			woken++
			if cond() {
				return
			}
		case <-timeout.C:
			t.Fatalf("%s (after %s and %d wakeups)", describe(), within, woken)
		}
	}
}
