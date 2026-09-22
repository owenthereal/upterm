//go:build !windows

package command

import (
	"syscall"
	"testing"

	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/stretchr/testify/require"
)

func TestSignalNumberMatchesThisRuntime(t *testing.T) {
	// Checks current-runtime consistency only: the map and this loop both
	// call s.String(), so it is circular with respect to compatibility. It
	// catches a signal missing from the map, not a renamed string.
	//
	// Compatibility with records already on disk is guarded by the literal
	// fixtures in TestWaitExitCodeForUnixSignal ("terminated", "killed", ...),
	// which is where a rename would actually surface. Do not delete those in
	// favour of generated ones.
	for _, s := range []syscall.Signal{
		syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT,
		syscall.SIGABRT, syscall.SIGKILL, syscall.SIGSEGV,
		syscall.SIGPIPE, syscall.SIGALRM, syscall.SIGTERM,
		syscall.SIGILL, syscall.SIGTRAP, syscall.SIGFPE, syscall.SIGBUS,
		syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGSYS,
		syscall.SIGXCPU, syscall.SIGXFSZ, syscall.SIGVTALRM, syscall.SIGPROF,
	} {
		require.Equal(t, int(s), signalNumber(s.String()),
			"signalNumber must accept exactly what signalName writes")
	}
}

func TestWaitExitCodeForUnixSignal(t *testing.T) {
	// Literal persisted spellings protect compatibility independently of
	// syscall.Signal.String(), including Linux and Darwin's SIGABRT names.
	for _, tc := range []struct {
		signal string
		want   int
	}{
		{"terminated", 143},
		{"killed", 137},
		{"hangup", 129},
		{"interrupt", 130},
		{"segmentation fault", 139},
		{"aborted", 134},
		{"abort trap", 134},
		{"illegal instruction", 132},
		{"floating point exception", 136},
		{"bus error", 128 + int(syscall.SIGBUS)},
		{"user defined signal 1", 128 + int(syscall.SIGUSR1)},
		{"user defined signal 2", 128 + int(syscall.SIGUSR2)},
		// Linux records real-time signals using syscall's numeric fallback.
		{"signal 34", 162},
		{"signal 64", 192},
		{"", 125},
		{"nope", 125},
		{"SIGILL", 125},
		{"signal 0", 125},
		{"signal 127", 125},
		{"signal 128", 125},
		{"signal -1", 125},
	} {
		t.Run(tc.signal, func(t *testing.T) {
			rec := sessiondir.Record{Reason: sessiondir.ReasonSignaled, Signal: tc.signal}
			require.Equal(t, tc.want, waitExitCode(&rec))
		})
	}
}
