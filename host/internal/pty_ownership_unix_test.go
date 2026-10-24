//go:build !windows

package internal

import (
	"bytes"
	"io"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/require"
)

// Process exit must release every operation on a full raw terminal. Linux's
// pollable Close can release the I/O earlier; other Unix systems need the
// slave's exit before their blocked Close can finish.
func TestPTYProcessExitReleasesOwnedIO(t *testing.T) {
	cmd := exec.Command("sh", "-c", "trap '' HUP; stty raw -echo; printf READY; exec sleep 60")
	p, err := startPty(cmd, termsize.Size{}, false, nil)
	require.NoError(t, err)
	waited, readyDone, readDone, writeDone, closeDone := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var started, closeStarted bool
	t.Cleanup(func() {
		_ = p.Signal(syscall.SIGKILL)
		_ = p.Kill()
		if !started {
			go func() { defer close(waited); _ = p.Wait() }()
			close(readDone)
			close(writeDone)
		}
		if !closeStarted {
			go func() { defer close(closeDone); _ = p.Close() }()
		}
		until := time.Now().Add(2 * time.Second)
		joined := true
		for name, ch := range map[string]<-chan struct{}{"wait": waited, "ready": readyDone, "read": readDone, "write": writeDone, "close": closeDone} {
			timer := time.NewTimer(time.Until(until))
			select {
			case <-ch:
			case <-timer.C:
				joined = false
				t.Errorf("cleanup could not join owned PTY %s", name)
			}
			timer.Stop()
		}
		if joined {
			t.Log("cleanup joined owned PTY readiness reader, process wait and I/O")
		}
	})
	ready := make([]byte, 5)
	var readyErr error
	go func() { defer close(readyDone); _, readyErr = io.ReadFull(p, ready) }()
	readiness := time.NewTimer(time.Second)
	defer readiness.Stop()
	select {
	case <-readyDone:
		require.NoError(t, readyErr)
		require.Equal(t, "READY", string(ready))
	case <-readiness.C:
		t.Fatal("PTY readiness timed out after 1s waiting for READY")
	}
	started = true
	go func() { defer close(waited); _ = p.Wait() }()
	go func() { defer close(readDone); _, _ = p.Read(make([]byte, 1)) }()
	go func() { defer close(writeDone); _, _ = p.Write(bytes.Repeat([]byte("x"), 4<<20)) }()
	// This real-resource observation gives the kernel both full-queue operations
	// time to park; all completion assertions below have a separate wall guard.
	time.Sleep(200 * time.Millisecond)
	pending := func(ch <-chan struct{}) bool {
		select {
		case <-ch:
			return false
		default:
			return true
		}
	}
	require.True(t, pending(readDone), "read did not park before Close")
	require.True(t, pending(writeDone), "write did not park before Close")
	closeStarted = true
	go func() { defer close(closeDone); _ = p.Close() }()
	require.NoError(t, p.Signal(syscall.SIGKILL))
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not reap leader after group SIGKILL")
	}
	probe := syscall.Kill(-cmd.Process.Pid, 0)
	require.ErrorIs(t, probe, syscall.ESRCH, "the command's process group must be gone")
	t.Logf("platform=%s leader reaped=%s group_probe=%v", runtime.GOOS, cmd.ProcessState, probe)
	until := time.Now().Add(time.Second)
	for name, ch := range map[string]<-chan struct{}{"read": readDone, "write": writeDone, "close": closeDone} {
		timer := time.NewTimer(time.Until(until))
		select {
		case <-ch:
		case <-timer.C:
			t.Errorf("owned PTY %s remains after process group exit", name)
		}
		timer.Stop()
	}
}
