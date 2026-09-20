//go:build !windows

package command

import (
	"os/signal"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSuspendAvailableFollowsTheInheritedDisposition pins the guard that
// keeps stopSelf from waiting forever: a process that inherited SIGTSTP
// ignored — a child of a non-interactive shell — cannot stop itself, so the
// ~^Z hook must not be installed at all.
func TestSuspendAvailableFollowsTheInheritedDisposition(t *testing.T) {
	// Not parallel: the disposition is process-wide.
	t.Cleanup(func() { signal.Reset(syscall.SIGTSTP) })

	signal.Reset(syscall.SIGTSTP)
	require.True(t, suspendAvailable(), "the default disposition stops the process, so the hook is offered")

	signal.Ignore(syscall.SIGTSTP)
	require.False(t, suspendAvailable(), "an ignored SIGTSTP cannot stop the process, so the hook is withheld")
}
