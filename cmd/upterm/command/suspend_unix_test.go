//go:build !windows

package command

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSuspendAvailableWithholdsTheHookWhenSIGTSTPIsIgnored pins the guard's
// wiring: the hook is offered exactly when the probe says SIGTSTP is not
// ignored. It swaps the probe rather than the process's real disposition,
// because signal.Ignore is one-way — signal.Reset does not restore a handler
// sigignore has already cleared — so ignoring for real would leave SIGTSTP
// SIG_IGN for every test that runs after this one in the binary.
//
// The disposition this guard cannot see, an inherited SIG_IGN, is not
// testable here at all: signal.Ignored never reports it (see
// suspendAvailable). That case is covered downstream, by the bound
// TestStopSelfReturnsWhenTheStopNeverLands pins.
func TestSuspendAvailableWithholdsTheHookWhenSIGTSTPIsIgnored(t *testing.T) {
	// Not parallel: the probe is a package var.
	prev := tstpIgnored
	t.Cleanup(func() { tstpIgnored = prev })

	tstpIgnored = func() bool { return false }
	require.True(t, suspendAvailable(), "a SIGTSTP that is not ignored stops the process, so the hook is offered")

	tstpIgnored = func() bool { return true }
	require.False(t, suspendAvailable(), "an ignored SIGTSTP cannot stop the process, so the hook is withheld")
}

// TestStopSelfReturnsWhenTheStopNeverLands pins the bound on the wait for the
// continue. A SIGTSTP that os/signal is watching does not take its default
// action, so the raise here stops nothing while kill(2) still reports
// success — the same position a client is in when its process group is
// orphaned (ssh -t, docker run -it, a terminal emulator's -e) or when it
// inherited SIGTSTP ignored. Unbounded, stopSelf parked here forever with the
// terminal already restored and the client's input actor gone; the goroutine
// and the outer deadline are what make a regression fail this test rather
// than hang it.
//
// signal.Notify, not signal.Ignore: os/signal cannot undo an Ignore —
// signal.Reset does not restore a handler sigignore has already cleared — so
// ignoring for real would leak SIGTSTP SIG_IGN into every later test in this
// binary. signal.Stop undoes a Notify cleanly.
func TestStopSelfReturnsWhenTheStopNeverLands(t *testing.T) {
	// Not parallel: signal dispositions and suspendContWait are process-wide.
	tstp := make(chan os.Signal, 1)
	signal.Notify(tstp, syscall.SIGTSTP)
	t.Cleanup(func() { signal.Stop(tstp) })

	prev := suspendContWait
	suspendContWait = 100 * time.Millisecond
	t.Cleanup(func() { suspendContWait = prev })

	done := make(chan bool, 1)
	go func() { done <- stopSelf(nil) }()

	select {
	case continued := <-done:
		require.False(t, continued, "a stop that is discarded is never continued, and reporting one would have a backgrounded client stop again for nothing")
	case <-time.After(5 * time.Second):
		t.Fatal("stopSelf never returned from a stop that did not land, which leaves the client in cooked mode with no way out but SIGKILL")
	}
}

// A process stopped for longer than suspendContWait comes back with the
// bound expired and the continue on its way through os/signal at the same
// instant, and it was continued all the same: reported as a stop that never
// landed, a client continued by bg would give up on stopping again and
// detach. The continue is sent here well after the bound, from a process
// that was never stopped, so a stopSelf that trusts the timer alone reports
// the wrong one every time rather than on the scheduler's whim.
func TestStopSelfReportsAContinueThatArrivesAfterTheBound(t *testing.T) {
	// Not parallel: signal dispositions and the bounds are process-wide.
	tstp := make(chan os.Signal, 1)
	signal.Notify(tstp, syscall.SIGTSTP)
	t.Cleanup(func() { signal.Stop(tstp) })

	prevWait, prevGrace := suspendContWait, suspendContGrace
	suspendContWait, suspendContGrace = 10*time.Millisecond, 5*time.Second
	t.Cleanup(func() { suspendContWait, suspendContGrace = prevWait, prevGrace })

	done := make(chan bool, 1)
	go func() { done <- stopSelf(nil) }()
	// stopSelf raises SIGTSTP only once it is watching SIGCONT, so the raise
	// arriving is what makes it safe to send the continue.
	select {
	case <-tstp:
	case <-time.After(5 * time.Second):
		t.Fatal("stopSelf never raised SIGTSTP")
	}
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGCONT))

	select {
	case continued := <-done:
		require.True(t, continued, "a continue that arrived after the bound is still a continue")
	case <-time.After(5 * time.Second):
		t.Fatal("stopSelf never returned")
	}
}

// unless is how a stop again after bg avoids stopping a job that fg has
// already put back in the foreground: asked just before the raise, and when
// it holds, nothing is raised — a foreground job stopped for nothing needs a
// second fg — and a continue is reported, there being nothing to wait for.
func TestStopSelfRaisesNothingWhenUnlessHolds(t *testing.T) {
	// Not parallel: signal dispositions and the bounds are process-wide.
	tstp := make(chan os.Signal, 1)
	signal.Notify(tstp, syscall.SIGTSTP)
	t.Cleanup(func() { signal.Stop(tstp) })

	// A raise would stop nothing here, and leave stopSelf waiting out the
	// whole bound for a continue that never comes.
	prev := suspendContWait
	suspendContWait = 5 * time.Second
	t.Cleanup(func() { suspendContWait = prev })

	done := make(chan bool, 1)
	go func() { done <- stopSelf(func() bool { return true }) }()

	select {
	case continued := <-done:
		require.True(t, continued, "nothing to wait for is not a stop that never landed")
	case <-time.After(time.Second):
		t.Fatal("stopSelf raised the stop, or waited for a continue, although unless held")
	}
	select {
	case <-tstp:
		t.Fatal("SIGTSTP was raised although unless held")
	case <-time.After(100 * time.Millisecond):
	}
}
