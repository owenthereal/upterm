package internal

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Every waiter on a shared handle is parked in a blocking call, so abandoning
// it is the only thing that can release them: the gate that timed out and the
// command that failed to start both leave clients holding this handle with no
// pty behind it, and a waiter nobody releases is a session that never ends.
func TestSharedPTYAbandonReleasesEveryWaiter(t *testing.T) {
	s := newSharedPTY()

	errs := make(chan error, 3)
	go func() { _, err := s.Write([]byte("x")); errs <- err }()
	go func() { _, err := s.Read(make([]byte, 1)); errs <- err }()
	go func() { errs <- s.Wait() }()

	// Parked, not merely started: a Write that had already returned would make
	// this pass without abandon doing anything.
	select {
	case err := <-errs:
		t.Fatalf("a waiter returned before the handle was abandoned: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	s.abandon()

	for i := 0; i < 3; i++ {
		select {
		case err := <-errs:
			require.ErrorIs(t, err, errNoPty)
		case <-time.After(time.Second):
			t.Fatal("a waiter was still parked a second after the handle was abandoned")
		}
	}
}

// set and abandon are the same decision made twice, so whichever lands first
// has to stand: a pty published and then abandoned is still the session's pty,
// and a handle abandoned and then handed a pty is still abandoned.
func TestSharedPTYSetPublishesOnce(t *testing.T) {
	p := &exitedPTY{}

	set := newSharedPTY()
	set.set(p)
	set.abandon()
	got, err := set.wait()
	require.NoError(t, err)
	require.Same(t, p, got)

	abandoned := newSharedPTY()
	abandoned.abandon()
	abandoned.set(p)
	got, err = abandoned.wait()
	require.ErrorIs(t, err, errNoPty)
	require.Nil(t, got)
}

// Setsize before the pty exists has to either record the geometry or
// delegate to the real pty, and never both or neither: consulting the ready
// channel and then locking separately left a window between the two where a
// resize could land and fall through unrecorded. Recording and delegating
// both have to happen under the same lock as the pty being published, so
// this also covers set applying the latest recorded size to the pty it
// hands out, and a later Setsize reaching that pty directly.
//
// This is also what stands in for the end-to-end version of the same claim
// (gate opens on attach at 80x24, a resize to 100x30 lands before the
// command starts, the pty ends up at 100x30): driving that through a real
// SSH session races the window-change request against the marker byte meant
// to prove it landed first, on two independent queues (charm's own
// handleRequests loop versus this handler's own input actor) with no cross
// synchronization -- measured at roughly 1 failure in 20 runs. That is the
// window the brief names as possibly unreachable reliably; this unit test is
// the fallback it names for it.
func TestSharedPtySetsizeRecordsOrDelegatesAtomically(t *testing.T) {
	s := newSharedPTY()

	require.NoError(t, s.Setsize(24, 80))
	require.NoError(t, s.Setsize(30, 100))

	p := &exitedPTY{}
	s.set(p)

	h, w := p.lastSize()
	require.Equal(t, 30, h)
	require.Equal(t, 100, w)

	require.NoError(t, s.Setsize(43, 132))
	h, w = p.lastSize()
	require.Equal(t, 43, h)
	require.Equal(t, 132, w)
}
