//go:build !windows

package internal

import (
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/termsize"
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

// Kill must remain independent of the PTY mutex, including platforms where a
// parked Read and a queued Close can hold it throughout termination.
func TestPtyKillDoesNotWaitOnTheLock(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	ptmx, err := startPty(cmd, termsize.Size{}, false, nil)
	require.NoError(t, err)
	p := ptmx.(*pty)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = p.Close()
	})

	p.Lock()
	release := sync.OnceFunc(p.Unlock)
	t.Cleanup(release) // Release the mutex before process/file cleanup on Fatal.
	killed := make(chan error, 1)
	go func() { killed <- p.Kill() }()
	select {
	case err := <-killed:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Kill waited on the pty's lock")
	}
	release()

	var exitErr *exec.ExitError
	require.ErrorAs(t, cmd.Wait(), &exitErr)
	ws, ok := exitErr.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.True(t, ws.Signaled())
	require.Equal(t, syscall.SIGKILL, ws.Signal())
}
