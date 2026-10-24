package internal

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

// Noncancelable waiters on a shared handle need abandonment to release
// them: the gate that timed out and the
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
// window that cannot be reached reliably end to end; this unit test is the
// fallback for it.
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

func TestSharedPTYInputCancellationBeforePublication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSharedPTY()
		t.Cleanup(s.abandon)
		writer, ok := any(s).(interface {
			WriteContext(context.Context, []byte) (int, error)
		})
		require.True(t, ok, "shared PTY must support cancelable input publication")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := writer.WriteContext(ctx, []byte("lost")); done <- err }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		default:
			t.Fatal("canceled input still waits for publication")
		}
		later := make(chan inputTestResult, 1)
		go func() {
			n, err := writer.WriteContext(context.Background(), []byte("later"))
			later <- inputTestResult{n, err}
		}()
		synctest.Wait()
		select {
		case <-later:
			t.Fatal("unpublished successor returned before publication")
		default:
		}
		p := &readFromInputPTY{exitedPTY: &exitedPTY{}}
		s.set(p)
		synctest.Wait()
		result := <-later
		require.NoError(t, result.err)
		require.Equal(t, 5, result.n)
		require.Equal(t, "later", p.got.String())
		require.Equal(t, 1, p.contextCalls)
	})
}
