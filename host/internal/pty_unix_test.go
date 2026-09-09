//go:build !windows

package internal

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A process stopped by a signal has no status to report.
//
// exec returns -1 for it, and that is what happens when a session is torn down
// and the pty closes underneath a command that is still running. SSH marshals
// exit-status as a uint32, so passing -1 through would tell the guest the
// command exited 4294967295.
func TestExitCodeSignalledProcess(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	require.NoError(t, cmd.Start())
	require.NoError(t, cmd.Process.Kill())

	err := cmd.Wait()
	require.Error(t, err)

	code, exited := exitCode(err)
	assert.False(t, exited, "a signalled process did not exit under its own control")
	assert.Negative(t, code)
}

// An ordinary non-zero exit is reported as itself.
func TestExitCodeExecExitStatus(t *testing.T) {
	err := exec.Command("sh", "-c", "exit 7").Run()
	require.Error(t, err)

	code, exited := exitCode(err)
	assert.True(t, exited)
	assert.Equal(t, 7, code)
}
