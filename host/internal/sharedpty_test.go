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
