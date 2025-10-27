//go:build !windows
// +build !windows

package internal

import (
	"os"
	"os/exec"
	"sync"
	"syscall"

	ptylib "github.com/creack/pty"
)

func startPty(c *exec.Cmd) (*pty, error) {
	f, err := ptylib.Start(c)
	if err != nil {
		return nil, err
	}

	return wrapPty(f), nil
}

// Linux kernel return EIO when attempting to read from a master pseudo
// terminal which no longer has an open slave. So ignore error here.
// See https://github.com/creack/pty/issues/21
func ptyError(err error) error {
	if pathErr, ok := err.(*os.PathError); !ok || pathErr.Err != syscall.EIO {
		return err
	}

	return nil
}

func getPtysize(f *os.File) (h, w int, err error) {
	return ptylib.Getsize(f)
}

func wrapPty(f *os.File) *pty {
	return &pty{File: f}
}

// Pty is a wrapper of the pty *os.File that provides a read/write mutex.
// This is to prevent data race that might happen for reszing, reading and closing.
// See ftests failure:
// * https://travis-ci.org/owenthereal/upterm/jobs/632489866
// * https://travis-ci.org/owenthereal/upterm/jobs/632458125
type pty struct {
	*os.File
	sync.RWMutex
}

func (pty *pty) Setsize(h, w int) error {
	pty.RLock()
	defer pty.RUnlock()

	size := &ptylib.Winsize{
		Rows: uint16(h),
		Cols: uint16(w),
	}
	return ptylib.Setsize(pty.File, size)
}

func (pty *pty) Read(p []byte) (n int, err error) {
	pty.RLock()
	defer pty.RUnlock()

	return pty.File.Read(p)
}

func (pty *pty) Close() error {
	pty.Lock()
	defer pty.Unlock()

	return pty.File.Close()
}

// Wait is a no-op on Unix - the exec.Cmd.Wait() handles process waiting
func (pty *pty) Wait() error {
	return nil
}

// Kill is a no-op on Unix - the exec.Cmd.Process.Kill() handles process killing
func (pty *pty) Kill() error {
	return nil
}

// waitForCommand waits for a command started via pty to exit.
// On Unix, we use cmd.Wait() since the command was started via ptylib.Start()
// which properly calls cmd.Start().
func waitForCommand(cmd *exec.Cmd, ptmx *pty) error {
	return cmd.Wait()
}
