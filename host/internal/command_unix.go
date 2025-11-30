//go:build !windows

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
