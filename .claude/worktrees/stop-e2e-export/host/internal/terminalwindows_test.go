package internal

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// resizeWindow takes the minimum across attached terminals, so a smaller one
// leaving has to be recomputed rather than merely deleted: otherwise the pty
// stays at the departed terminal's size until a survivor happens to resize
// on its own. Pre-existing on master; this branch makes it ordinary rather
// than rare, because every attached terminal is now one of these entries.
//
// A unit test on terminalWindows, driving it directly so that detached's own
// logic — delete, then recompute if any terminal remains — is what is under
// test, with no session, no door and no window-change channel in the way. Its
// end-to-end twin, TestASmallerTerminalLeavingRestoresTheSizeOverTheDoor,
// covers the same claim through two real clients.
//
// Writing that twin is how the separate defect it names was found: the pty
// actor's loop read charm's window-change channel without checking for
// closure, and a closed channel yields the zero Window immediately and
// forever, so a departing client announced 0x0 resizes on its way out. One
// landing after its own detach re-added a terminal nothing would remove,
// pinning this minimum to nothing for the rest of the session — the
// survivor read "0 0" in seven of fifteen runs. Fixed in the same commit as
// this test.
func TestASmallerTerminalLeavingRestoresTheSize(t *testing.T) {
	tw := newTerminalWindows(discardLogger())
	pty := &exitedPTY{}

	tw.changed(pty, "a", 100, 30, nil)
	rows, cols := pty.lastSize()
	require.Equal(t, [2]int{30, 100}, [2]int{rows, cols}, "the only terminal's size was not applied")

	tw.changed(pty, "b", 80, 24, nil)
	rows, cols = pty.lastSize()
	require.Equal(t, [2]int{24, 80}, [2]int{rows, cols}, "the minimum of the two terminals was not applied")

	tw.detached(pty, "b")
	rows, cols = pty.lastSize()
	require.Equal(t, [2]int{30, 100}, [2]int{rows, cols}, "a's own size was not restored once b left")
}

// Every update lands, however many arrive at once.
//
// These used to be events, delivered to a handler goroutine through an
// emitter subscribed with emitter.Skip, which drops an event whenever the
// listener's one-deep channel is still full from the last one. A burst of
// departures — which is what a door sees when a session ends, or when a
// pane of terminals closes together — therefore lost most of itself, and
// every lost departure left a terminal that is gone constraining the
// minimum for the rest of the session. Thirty-two at once is well past what
// a one-deep channel could hold; the exact size at the end is what says
// none of them was dropped. Also a race-detector test for the map.
func TestEveryTerminalDepartureIsApplied(t *testing.T) {
	tw := newTerminalWindows(discardLogger())
	pty := &exitedPTY{}

	tw.changed(pty, "survivor", 120, 40, nil)

	var wg sync.WaitGroup
	for i := range 32 {
		id := fmt.Sprintf("leaving-%d", i)
		// Smaller than the survivor in both directions, so a departure that
		// goes missing is visible in the size at the end.
		tw.changed(pty, id, 20+i, 10+i, nil)
		wg.Add(1)
		go func() {
			defer wg.Done()
			tw.detached(pty, id)
		}()
	}
	wg.Wait()

	rows, cols := pty.lastSize()
	require.Equal(t, [2]int{40, 120}, [2]int{rows, cols}, "the session did not go back to the surviving terminal's size")
}

// A resize that was already on its way when its terminal left does not bring
// that terminal back.
//
// charm's window-change channel is one deep, so a client's last resize can
// still be in it when the client hangs up, and the handler reads it after the
// connection actor has taken that client out of the size calculation. Adding
// it back there is permanent: the actor's removal has already run, and the
// pty actor's runs only when the handler returns — which an input write
// parked in ptmx.Write can defer for as long as the session lives.
//
// So the liveness check cannot be at the call site, where it is a decision
// made before the lock and acted on after it. This test puts a resize in
// exactly that position: it is inside changed, waiting for the lock, at the
// moment its terminal goes away. A check made outside would have said "still
// here"; the one inside sees what is true when the map is actually written.
func TestAResizeInFlightWhenItsTerminalLeavesIsDropped(t *testing.T) {
	tw := newTerminalWindows(discardLogger())
	pty := &exitedPTY{}

	var gone atomic.Bool
	alive := func() bool { return !gone.Load() }

	tw.changed(pty, "survivor", 120, 40, alive)
	tw.changed(pty, "leaving", 70, 20, alive)
	tw.detached(pty, "leaving")

	// The resize is issued while its terminal is still there and blocks on
	// the lock, which this test holds.
	tw.mu.Lock()
	resized := make(chan struct{})
	go func() {
		defer close(resized)
		tw.changed(pty, "leaving", 70, 20, alive)
	}()
	// Long enough for that goroutine to be inside changed and waiting: it has
	// nothing else to do, and the assertion below is what would catch it if
	// it were not.
	time.Sleep(50 * time.Millisecond)

	// The terminal goes away while the resize is in flight.
	gone.Store(true)
	tw.mu.Unlock()
	<-resized

	rows, cols := pty.lastSize()
	require.Equal(t, [2]int{40, 120}, [2]int{rows, cols},
		"a terminal that had already left was put back into the minimum by its own last resize")
}

// The size of a terminal that has left is not a constraint on anything, and
// the last one leaving takes the whole session's geometry with it: computing a
// minimum across nothing asks for 0x0, which is a size no terminal wants and
// the pty would take.
//
// The repeat is the other half: a client's departure reaches detached twice,
// from the connection actor and from the pty actor's interrupt, and the second
// must do nothing rather than resize the session to nothing.
func TestTheLastTerminalLeavingDoesNotResizeThePtyToNothing(t *testing.T) {
	tw := newTerminalWindows(discardLogger())
	pty := &exitedPTY{}

	tw.changed(pty, "a", 100, 30, nil)
	tw.detached(pty, "a")
	tw.detached(pty, "a")

	rows, cols := pty.lastSize()
	require.Equal(t, [2]int{30, 100}, [2]int{rows, cols}, "the pty was resized after its last terminal left")
}
