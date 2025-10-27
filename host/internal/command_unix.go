//go:build !windows
// +build !windows

package internal

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
)

// setupTerminalResize sets up terminal resize handling for Unix systems using SIGWINCH
func (c *command) setupTerminalResize(g *run.Group, stdin *os.File, ptmx *pty, eventEmitter *emitter.Emitter) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	ch <- syscall.SIGWINCH // Initial resize.
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

// waitForProcess waits for the process to exit on Unix
func (c *command) waitForProcess() error {
	// On Unix, use exec.Cmd.Wait() since it knows about the process
	return c.cmd.Wait()
}

// killProcess kills the process on Unix
func (c *command) killProcess() error {
	if c.cmd.Process != nil {
		return c.cmd.Process.Kill()
	}
	return nil
}
