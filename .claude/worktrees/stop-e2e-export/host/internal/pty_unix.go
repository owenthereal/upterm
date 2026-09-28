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
	// Snapshotted once, here, rather than read from cmd through the RWMutex
	// below every time Signal or Kill needs them: see Signal's and Kill's
	// own comments for why.
	var pid int
	var process *os.Process
	if cmd.Process != nil {
		pid = cmd.Process.Pid
		process = cmd.Process
	}
	return &pty{File: f, cmd: cmd, pinned: pinned, pid: pid, process: process}
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
	// pid and process are cmd.Process.Pid and cmd.Process, fixed at
	// construction (see wrapPty) and never touched again. Signal and Kill
	// read them without the RWMutex below; nothing else does.
	pid     int
	process *os.Process
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

	err := pty.control(func(fd uintptr) error {
		return unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ,
			&unix.Winsize{Row: uint16(h), Col: uint16(w)})
	})
	if errors.Is(err, os.ErrClosed) {
		// A resize that lost the race with the end of the session is nothing
		// to anyone, and the Windows pty says nothing about one on a closed
		// pty either (pty_windows.go's Setsize).
		return nil
	}
	return err
}

// Redraw nudges the foreground process group with SIGWINCH, the signal a
// full-screen program repaints on. Nothing about the geometry changes, so a
// pinned session is nudged like any other.
func (pty *pty) Redraw() error {
	pty.RLock()
	defer pty.RUnlock()

	var pgrp int
	err := pty.control(func(fd uintptr) (err error) {
		pgrp, err = tty.ForegroundProcessGroup(int(fd))
		return err
	})
	if errors.Is(err, os.ErrClosed) {
		// A nudge that lost the race with the end of the session is nothing
		// to anyone, and the Windows pty says nothing about one on a closed
		// pty either (pty_windows.go's Redraw).
		return nil
	}
	if err != nil {
		return err
	}
	if pgrp <= 0 {
		// kill(0, …) would signal our own process group.
		return errors.New("pty has no foreground process group")
	}
	return unix.Kill(-pgrp, unix.SIGWINCH)
}

// control runs f with the master's descriptor while holding a reference on
// the file, so a Close racing it cannot destroy the file under the ioctl and
// the number can never be one the process has reused. Fd() takes no
// reference: it reads the number bare, and the write path — unlocked,
// parked in the kernel while the command is not reading — is what finishes
// the close when that write finally returns; on Linux a write whose command
// has exited never does, and the descriptor lives until the process exits.
// control reports a closed file as os.ErrClosed and leaves what to do about
// it to the caller. Blocking mode is unaffected: StartWithSize already
// applied the initial size through Fd(), which put the master in blocking
// mode before the first write.
func (pty *pty) control(f func(fd uintptr) error) error {
	rc, err := pty.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) { ferr = f(fd) }); err != nil {
		// Control's only failure here is the file being closed or closing
		// (os/rawconn.go's checkValid, then poll.FD.RawControl's incref).
		// The callback's own error (ferr) still comes back below, distinct
		// from this one.
		return os.ErrClosed
	}
	return ferr
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

// Kill terminates the process.
//
// Deliberately not behind the RWMutex above, for the same reason as Signal:
// process is fixed at construction and never changes, so reading it needs
// no lock -- and taking one would let a pending close's write lock starve
// the kill step exactly the way it used to starve Signal. terminate's own
// close now runs on its own goroutine and can still be pending, its write
// lock queued, when the escalation reaches Kill; a kill step that blocked
// on that would mean SIGKILL is never sent, the give-up warning never
// logs, and terminate never returns.
func (pty *pty) Kill() error {
	if pty.process == nil {
		return nil // No process to kill
	}
	return pty.process.Kill()
}

// Signal sends sig to the command's process group. The command is a session
// leader — creack/pty starts it with Setsid — so its group is its pid, and
// this reaches every process that has not left the group on purpose.
//
// Deliberately not behind the RWMutex above: pid is fixed at construction
// (wrapPty) and never changes, so nothing here needs the lock to read it
// safely -- and taking it anyway would let a write lock queued by Close
// starve every signal behind it. That starvation is exactly what used to
// make terminate's own hangup impossible to send: Close (the write lock)
// queued ahead of Signal (a read lock) whenever it ran concurrently, and
// Go's sync.RWMutex blocks new readers behind a pending writer. terminate
// now closes the pty master itself, mid-escalation, so a signal must never
// depend on that close having finished first.
func (pty *pty) Signal(sig syscall.Signal) error {
	if pty.pid == 0 {
		return nil
	}
	return unix.Kill(-pty.pid, sig)
}
