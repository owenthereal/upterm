//go:build !windows

package internal

import (
	"os/exec"
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

// TestPtyKillDoesNotWaitOnTheLock pins R23's guard: Kill must not take the
// pty's RWMutex. terminate can reach Kill while its own close is still
// pending, queued for the write lock behind a Read parked on the master, and
// Go's sync.RWMutex holds every new reader behind a pending writer -- so a
// Kill that took either lock would wait on a read that only the command's
// exit ends, which is what Kill is there to cause.
//
// TestCommandRunSurvivesAParkedReaderDuringClose cannot tell: terminate sends
// the group SIGKILL through Signal before it calls Kill, and that alone ends
// the command and frees the lock, so a Kill that took it there is late, not
// stuck. Here nothing but Kill is sent.
func TestPtyKillDoesNotWaitOnTheLock(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	ptmx, err := startPty(cmd, termsize.Size{}, false)
	require.NoError(t, err)
	p := ptmx.(*pty)

	readDone := make(chan struct{})
	var closeDone chan struct{} // made only once the Close goroutine starts
	t.Cleanup(func() {
		// Only the command's exit releases the parked Read, and with it the
		// lock: end it directly, never through the pty, in case Kill did not.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		<-readDone
		if closeDone != nil {
			<-closeDone
		}
	})

	// sleep writes nothing, so this Read holds the read lock until the
	// command exits. It has the lock once a write lock cannot be had.
	go func() {
		defer close(readDone)
		_, _ = p.Read(make([]byte, 1))
	}()
	require.Eventually(t, func() bool {
		if p.TryLock() {
			p.Unlock()
			return false
		}
		return true
	}, time.Second, time.Millisecond, "Read never took the read lock")

	// Close queues for the write lock behind that Read; once it has, not
	// even a read lock can be had.
	closeDone = make(chan struct{})
	go func() {
		defer close(closeDone)
		_ = p.Close()
	}()
	require.Eventually(t, func() bool {
		if p.TryRLock() {
			p.RUnlock()
			return false
		}
		return true
	}, time.Second, time.Millisecond, "Close never queued for the write lock")

	killed := make(chan error, 1)
	go func() { killed <- p.Kill() }()
	select {
	case err := <-killed:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Kill waited on the pty's lock, held by a parked Read with a Close queued behind it")
	}

	// And Kill alone is what ended the command: the Read and the Close are
	// both still parked until it exits.
	var exitErr *exec.ExitError
	require.ErrorAs(t, cmd.Wait(), &exitErr)
	ws, ok := exitErr.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.True(t, ws.Signaled())
	require.Equal(t, syscall.SIGKILL, ws.Signal())
}
