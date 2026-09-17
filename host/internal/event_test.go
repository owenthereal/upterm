package internal

import (
	"context"
	"testing"
	"time"

	"github.com/olebedev/emitter"
	"github.com/stretchr/testify/require"
)

// resizeWindow takes the minimum across attached terminals, so a smaller one
// leaving has to be recomputed rather than merely deleted: otherwise the pty
// stays at the departed terminal's size until a survivor happens to resize
// on its own. Pre-existing on master; this branch makes it ordinary rather
// than rare, because every attached terminal is now one of these entries.
//
// A unit test on terminalEventHandler, driving it directly so that
// handleTerminalDetached's own logic — delete, then recompute if any
// terminal remains — is what is under test, with no session, no door and no
// window-change channel in the way. Its end-to-end twin,
// TestASmallerTerminalLeavingRestoresTheSizeOverTheDoor, covers the same
// claim through two real clients.
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
	h := terminalEventHandler{eventEmitter: emitter.New(1), logger: discardLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.Handle(ctx)
	}()
	// LIFO: cancel Handle's context first, then wait for it to actually
	// return, so this goroutine never leaks past the test.
	defer func() { <-done }()
	defer cancel()

	pty := &exitedPTY{}
	tee := terminalEventEmitter{h.eventEmitter}

	// Re-emitting on every attempt, not just checking, because Handle's own
	// listener registration races this goroutine's launch: an emit issued
	// before Handle reaches its .On calls has nothing to deliver to. Both
	// handlers are idempotent against a repeat of the same geometry.
	require.Eventually(t, func() bool {
		tee.TerminalWindowChanged("a", pty, 100, 30)
		tee.TerminalWindowChanged("b", pty, 80, 24)
		rows, cols := pty.lastSize()
		return rows == 24 && cols == 80
	}, time.Second, time.Millisecond, "the minimum of the two terminals was never applied")

	require.Eventually(t, func() bool {
		tee.TerminalDetached("b", pty)
		rows, cols := pty.lastSize()
		return rows == 30 && cols == 100
	}, time.Second, time.Millisecond, "a's own size was never restored once b left")
}
