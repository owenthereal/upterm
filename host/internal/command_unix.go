//go:build !windows

package internal

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

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
	pgrp, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCGPGRP)
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
