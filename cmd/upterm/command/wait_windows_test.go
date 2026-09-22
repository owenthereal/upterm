//go:build windows

package command

import (
	"testing"

	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/stretchr/testify/require"
)

func TestWaitExitCodeForWindowsSignalIsUnavailable(t *testing.T) {
	// Windows records exit statuses, not Unix signals. Even a recognized
	// Unix spelling in a retained record has no signal mapping here.
	for _, signal := range []string{
		"terminated", "killed", "hangup", "interrupt", "segmentation fault",
		"aborted", "abort trap", "illegal instruction", "floating point exception",
		"bus error", "user defined signal 1", "user defined signal 2",
		"signal 34", "signal 64", "nope", "",
	} {
		t.Run(signal, func(t *testing.T) {
			rec := sessiondir.Record{Reason: sessiondir.ReasonSignaled, Signal: signal}
			require.Equal(t, 125, waitExitCode(&rec))
		})
	}
}
