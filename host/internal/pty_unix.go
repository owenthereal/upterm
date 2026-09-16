//go:build !windows

package internal

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"

	ptylib "github.com/creack/pty"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/internal/tty"
	"golang.org/x/sys/unix"
)

func startPty(c *exec.Cmd, size termsize.Size, pinned bool) (PTY, error) {
	if !size.Valid() {
		size = termsize.Default
	}

	// StartWithSize, not Start-then-Setsize: a child can read its window size
	// before a follow-up ioctl lands, and a full-screen program that does so
	// draws its first frame at the kernel default.
	f, err := ptylib.StartWithSize(c, &ptylib.Winsize{
		Rows: uint16(size.Rows),
		Cols: uint16(size.Cols),
	})
	if err != nil {
		return nil, err
	}

	return wrapPty(f, c, pinned), nil
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

func wrapPty(f *os.File, cmd *exec.Cmd, pinned bool) *pty {
	return &pty{File: f, cmd: cmd, pinned: pinned}
}

// Pty is a wrapper of the pty *os.File that provides a read/write mutex.
// This is to prevent data race that might happen for reszing, reading and closing.
// See ftests failure:
// * https://travis-ci.org/owenthereal/upterm/jobs/632489866
// * https://travis-ci.org/owenthereal/upterm/jobs/632458125
type pty struct {
	*os.File
	cmd    *exec.Cmd // Process started with this PTY
	pinned bool
	sync.RWMutex
}

func (pty *pty) Setsize(h, w int) error {
	pty.RLock()
	defer pty.RUnlock()

	// --pty-size promises the geometry will not move. Every resize in the
	// process funnels through here — the host's SIGWINCH handler and a guest's
	// window-change request both reach it via event.go — so this is the only
	// place the promise has to be kept. Reporting success is deliberate: a
	// client asking to resize a pinned session has done nothing wrong.
	if pty.pinned {
		return nil
	}

	return ptylib.Setsize(pty.File, &ptylib.Winsize{Rows: uint16(h), Cols: uint16(w)})
}

// Redraw nudges the foreground process group with SIGWINCH, the signal a
// full-screen program repaints on. Nothing about the geometry changes, so a
// pinned session is nudged like any other.
func (pty *pty) Redraw() error {
	pty.RLock()
	defer pty.RUnlock()

	pgrp, err := tty.ForegroundProcessGroup(int(pty.Fd()))
	if err != nil {
		return err
	}
	if pgrp <= 0 {
		// kill(0, …) would signal our own process group.
		return errors.New("pty has no foreground process group")
	}
	return unix.Kill(-pgrp, unix.SIGWINCH)
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
	pty.RLock()
	cmd := pty.cmd
	pty.RUnlock()

	if cmd == nil {
		return nil // No process to wait for
	}
	return cmd.Wait()
}

// Kill terminates the process
func (pty *pty) Kill() error {
	pty.RLock()
	cmd := pty.cmd
	pty.RUnlock()

	if cmd == nil || cmd.Process == nil {
		return nil // No process to kill
	}
	return cmd.Process.Kill()
}
