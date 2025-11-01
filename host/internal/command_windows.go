//go:build windows
// +build windows

package internal

import (
	"os"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
)

// setupTerminalResize is a no-op on Windows since ConPTY handles resize internally
// Windows doesn't have SIGWINCH, and ConPTY manages terminal resizing automatically
func (c *command) setupTerminalResize(g *run.Group, stdin *os.File, ptmx *pty, eventEmitter *emitter.Emitter) {
	// No-op on Windows - ConPTY handles this automatically
	// Terminal resize events are managed by the Windows Console system
}

// waitForProcess waits for the process to exit on Windows
func (c *command) waitForProcess() error {
	// On Windows, ConPTY spawned the process, so use pty.Wait()
	return c.ptmx.Wait()
}

// killProcess kills the process on Windows
func (c *command) killProcess() error {
	// On Windows, kill via the pty handle
	return c.ptmx.Kill()
}
