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

	done := make(chan error, 1)
	go func() { done <- stopSelf() }()

	select {
	case err := <-done:
		require.NoError(t, err, "a stop that is discarded is not an error: the suspend simply did not happen")
	case <-time.After(5 * time.Second):
		t.Fatal("stopSelf never returned from a stop that did not land, which leaves the client in cooked mode with no way out but SIGKILL")
	}
}
