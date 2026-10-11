package join

import (
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/require"
)

// A size queued while no session was running never reaches the session that
// starts next, even with no Size to measure with, when a change carries its
// own size. Which of the queued change and the start a resizer takes first is
// up to its select, so the case runs on many resizers. end is taken only
// after whatever the resizer was doing, so once it returns, anything the
// session was going to get is on its channel.
func TestASizeQueuedBetweenSessionsNeverReachesTheNext(t *testing.T) {
	stale := termsize.Size{Rows: 24, Cols: 80}
	for range 100 {
		changes := make(chan termsize.Size, 1)
		f := newResizer(changes, nil)
		changes <- stale // queued while no session runs

		to := make(chan termsize.Size, 1)
		f.begin(to, false)
		f.end()
		f.stop()
		require.Empty(t, to, "the session got a size from before it started")
	}
}

// A change sent once a session has begun is the session's.
func TestAChangeAfterASessionBeginsReachesIt(t *testing.T) {
	fresh := termsize.Size{Rows: 43, Cols: 132}
	changes := make(chan termsize.Size, 1)
	f := newResizer(changes, nil)
	defer f.stop()

	to := make(chan termsize.Size, 1)
	f.begin(to, false)
	changes <- fresh
	select {
	case got := <-to:
		require.Equal(t, fresh, got)
	case <-time.After(testTimeout):
		t.Fatal("a change sent once the session had begun never reached it")
	}
}
