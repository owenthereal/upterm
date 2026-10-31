//go:build windows

package internal

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"

	gssh "charm.land/ssh"
	"golang.org/x/sys/windows"
)

func startGuestPipeCommand(cmd *exec.Cmd) (func(), error) {
	return startGuestPipeCommandWithJob(cmd, createJobObject)
}

// Retain the kill-on-close job until the runner finishes draining. A failed
// assignment still owns a started child and must kill and reap it locally.
func startGuestPipeCommandWithJob(cmd *exec.Cmd, assign func(syscall.Handle) (syscall.Handle, error)) (func(), error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	var job syscall.Handle
	if err == nil {
		job, err = assign(syscall.Handle(handle))
		_ = windows.CloseHandle(handle)
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("assign guest job: %w", err)
	}
	var once sync.Once
	return func() { once.Do(func() { _ = syscall.CloseHandle(job) }) }, nil
}
func (p *guestPipes) Signal(syscall.Signal) error    { return errors.ErrUnsupported }
func guestSignal(gssh.Signal) (syscall.Signal, bool) { return 0, false }
