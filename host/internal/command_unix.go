//go:build !windows

package internal

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/internal/tty"
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

// ownsTerminal reports whether f is a terminal this process is in the
// foreground of.
func ownsTerminal(f *os.File) bool {
	return tty.Owned(f)
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
