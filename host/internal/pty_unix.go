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

func startPty(c *exec.Cmd, stdin *os.File) (PTY, error) {
	// Create PTY with kernel defaults first
	f, err := ptylib.Start(c)
	if err != nil {
		return nil, err
	}

	// Set the initial size from stdin if available
	if stdin != nil {
		h, w, err := getPtysize(stdin)
		if err == nil && w > 0 && h > 0 {
			// Set the PTY size before returning
			// Ignore error - process is already running, will use kernel defaults if this fails
			_ = ptylib.Setsize(f, &ptylib.Winsize{
				Rows: uint16(h),
				Cols: uint16(w),
			})
		}
	}

	return wrapPty(f, c), nil
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

func wrapPty(f *os.File, cmd *exec.Cmd) *pty {
	return &pty{File: f, cmd: cmd}
}

// Pty is a wrapper of the pty *os.File that provides a read/write mutex.
// This is to prevent data race that might happen for reszing, reading and closing.
// See ftests failure:
// * https://travis-ci.org/owenthereal/upterm/jobs/632489866
// * https://travis-ci.org/owenthereal/upterm/jobs/632458125
type pty struct {
	*os.File
	cmd *exec.Cmd // Process started with this PTY
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

// Wait waits for the process to exit
func (pty *pty) Wait() error {
	if pty.cmd == nil {
		return nil // No process to wait for
	}
	return pty.cmd.Wait()
}

// Kill terminates the process
func (pty *pty) Kill() error {
	if pty.cmd == nil || pty.cmd.Process == nil {
		return nil // No process to kill
	}
	return pty.cmd.Process.Kill()
}
