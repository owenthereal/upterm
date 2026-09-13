//go:build !windows

package internal

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// signalName names the signal that killed a command, given the error from
// Wait. Empty when the command was not signalled.
//
// Here rather than beside recordResult because syscall.WaitStatus is
// Unix-shaped: it has no Signaled() on Windows, where a process is terminated
// with a status rather than signalled.
func signalName(err error) string {
	var execErr *exec.ExitError
	if errors.As(err, &execErr) {
		if ws, ok := execErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return ws.Signal().String()
		}
	}
	return ""
}

// tcgetpgrp returns the foreground process group of the terminal on fd.
//
// Not unix.IoctlGetInt: that reads into a Go int, and the kernel writes a
// 4-byte pid_t. On a big-endian 64-bit target (s390x is a release
// architecture) the value lands in the high half and the comparison in
// ownsTerminal can never succeed.
func tcgetpgrp(fd int) (int, error) {
	var pgrp int32
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TIOCGPGRP), uintptr(unsafe.Pointer(&pgrp)))
	if errno != 0 {
		return 0, errno
	}
	return int(pgrp), nil
}

// ownsTerminal reports whether f is a terminal this process is in the
// foreground of.
//
// Reading or reconfiguring a terminal we are not in the foreground of is what
// SIGTTIN and SIGTTOU exist to prevent, and since we ignore both, nothing else
// would stop us: `upterm host … &` would put the foreground shell's terminal
// into raw mode and then race it for input.
func ownsTerminal(f *os.File) bool {
	if f == nil || !term.IsTerminal(int(f.Fd())) {
		return false
	}
	pgrp, err := tcgetpgrp(int(f.Fd()))
	if err != nil {
		return false
	}
	return pgrp == unix.Getpgrp()
}

// setupTerminalResize sets up terminal resize handling for Unix systems using SIGWINCH
func (c *command) setupTerminalResize(g *run.Group, stdin *os.File, ptmx PTY, eventEmitter *emitter.Emitter) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	// Note: Initial size is already set in startPty, so we only handle resize events here
	ctx, cancel := context.WithCancel(c.ctx)
	tee := terminalEventEmitter{eventEmitter}
	g.Add(func() error {
		for {
			select {
			case <-ctx.Done():
				close(ch)
				return ctx.Err()
			case <-ch:
				h, w, err := getPtysize(stdin)
				if err != nil {
					return err
				}
				tee.TerminalWindowChanged("local", ptmx, w, h)
			}
		}
	}, func(err error) {
		tee.TerminalDetached("local", ptmx)
		cancel()
	})
}
