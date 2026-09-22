//go:build !windows

package command

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignalNumberMatchesThisRuntime(t *testing.T) {
	// Checks current-runtime consistency only: the map and this loop both
	// call s.String(), so it is circular with respect to compatibility. It
	// catches a signal missing from the map, not a renamed string.
	//
	// Compatibility with records already on disk is guarded by the literal
	// fixtures in TestWaitExitCodeForReason ("terminated", "killed", ...),
	// which is where a rename would actually surface. Do not delete those in
	// favour of generated ones.
	for _, s := range []syscall.Signal{
		syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT,
		syscall.SIGABRT, syscall.SIGKILL, syscall.SIGSEGV,
		syscall.SIGPIPE, syscall.SIGALRM, syscall.SIGTERM,
	} {
		require.Equal(t, int(s), signalNumber(s.String()),
			"signalNumber must accept exactly what signalName writes")
	}
}
