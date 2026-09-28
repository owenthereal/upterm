package host

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// readinessAttempts is how many times each already-decided case below is
// asked. The question is what happens when a select has two ready cases, and
// Go answers that at random: one pass would prove nothing about a rule whose
// whole content is "never the coin". At this many, a version that let the
// scheduler decide survives with probability 2^-200.
const readinessAttempts = 200

// closedChan is a channel that has already been closed — a fact that was
// established before anyone looked.
func closedChan() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// Test_readinessEstablished_PrefersTheFactsOverTheTeardown pins the rule the
// readiness actor is built on, in the state that makes it matter: every
// channel already closed.
//
// That state is not contrived. `upterm host --detach -- true` reaches it on
// every run: the command starts, closes cmdReady, exits, the group unwinds
// and closes ready, all before the readiness actor is scheduled again. The
// admin socket bound before the group existed, so adminReady was closed the
// whole time.
func Test_readinessEstablished_PrefersTheFactsOverTheTeardown(t *testing.T) {
	t.Run("both facts and a teardown, all already true", func(t *testing.T) {
		for range readinessAttempts {
			require.True(t, readinessEstablished(closedChan(), closedChan(), closedChan()),
				"a command that started and then exited did start; the parent must be told so every time, not half the time")
		}
	})

	t.Run("the command never started", func(t *testing.T) {
		for range readinessAttempts {
			require.False(t, readinessEstablished(closedChan(), make(chan struct{}), closedChan()),
				"nothing may be published for a command that never ran")
		}
	})

	t.Run("the admin socket never bound", func(t *testing.T) {
		for range readinessAttempts {
			require.False(t, readinessEstablished(make(chan struct{}), closedChan(), closedChan()),
				"a caller told ready must be able to connect, which an unbound socket cannot answer")
		}
	})

	t.Run("neither fact", func(t *testing.T) {
		for range readinessAttempts {
			require.False(t, readinessEstablished(make(chan struct{}), make(chan struct{}), closedChan()))
		}
	})
}

// Test_readinessEstablished_WaitsForFactsStillComing is the other half: with
// no teardown in sight it blocks until both facts report, which is the
// ordinary case and the reason this is a wait at all rather than a poll.
func Test_readinessEstablished_WaitsForFactsStillComing(t *testing.T) {
	adminReady, cmdReady := make(chan struct{}), make(chan struct{})
	ready := make(chan struct{})

	got := make(chan bool, 1)
	go func() { got <- readinessEstablished(adminReady, cmdReady, ready) }()

	select {
	case <-got:
		t.Fatal("readiness was declared before either fact reported")
	case <-time.After(20 * time.Millisecond):
	}

	close(adminReady)
	select {
	case <-got:
		t.Fatal("readiness was declared on the socket alone, with no command running")
	case <-time.After(20 * time.Millisecond):
	}

	close(cmdReady)
	select {
	case ok := <-got:
		require.True(t, ok)
	case <-time.After(5 * time.Second):
		t.Fatal("readiness was never declared, with both facts established")
	}
}

// Test_readinessEstablished_TeardownAloneIsANo pins that the wait ends when
// the run does: an actor parked here forever would hang run.Group, which
// waits for every actor it started.
func Test_readinessEstablished_TeardownAloneIsANo(t *testing.T) {
	adminReady, cmdReady := make(chan struct{}), make(chan struct{})
	ready := make(chan struct{})

	got := make(chan bool, 1)
	go func() { got <- readinessEstablished(adminReady, cmdReady, ready) }()

	close(ready)
	select {
	case ok := <-got:
		require.False(t, ok, "a run torn down before either fact reported was never ready")
	case <-time.After(5 * time.Second):
		t.Fatal("the readiness wait did not end with the run")
	}
}
