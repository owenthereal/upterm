//go:build windows

package internal

import (
	"context"
	"os"
	"time"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
)

// setupTerminalResize polls for terminal size changes on Windows
// Windows doesn't have SIGWINCH signals like Unix, so we poll for terminal size changes
// Note: Initial size is already set in startPty
func (c *command) setupTerminalResize(g *run.Group, stdin *os.File, ptmx PTY, eventEmitter *emitter.Emitter) {
	// Get the initial size to track changes
	h, w, err := getPtysize(stdin)
	if err != nil {
		// If we can't get the size, skip resize monitoring
		return
	}

	tee := terminalEventEmitter{eventEmitter}
	// Track the last known size for comparison
	lastH, lastW := h, w

	// Poll for terminal size changes
	ctx, cancel := context.WithCancel(c.ctx)
	g.Add(func() error {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				h, w, err := getPtysize(stdin)
				if err != nil {
					// Can't get size, skip this check
					continue
				}

				// Only notify if size actually changed
				if h != lastH || w != lastW {
					lastH, lastW = h, w
					tee.TerminalWindowChanged("local", ptmx, w, h)
				}
			}
		}
	}, func(err error) {
		tee.TerminalDetached("local", ptmx)
		cancel()
	})
}
