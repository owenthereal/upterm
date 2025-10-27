package internal

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	"golang.org/x/term"
)

func newCommand(
	name string,
	args []string,
	env []string,
	stdin *os.File,
	stdout *os.File,
	eventEmitter *emitter.Emitter,
	writers *uio.MultiWriter,
	forceForwardingInputForTesting bool,
) *command {
	return &command{
		name:                           name,
		args:                           args,
		env:                            env,
		stdin:                          stdin,
		stdout:                         stdout,
		eventEmitter:                   eventEmitter,
		writers:                        writers,
		forceForwardingInputForTesting: forceForwardingInputForTesting,
	}
}

type command struct {
	name string
	args []string
	env  []string

	cmd  *exec.Cmd
	ptmx *pty

	stdin  *os.File
	stdout *os.File

	writers *uio.MultiWriter

	eventEmitter *emitter.Emitter

	ctx context.Context

	// ForceForwardingInputForTesting forces stdin forwarding even when stdin is not a TTY.
	// This is used in tests where stdin is a pipe but we still want to forward test data.
	forceForwardingInputForTesting bool
}

func (c *command) Start(ctx context.Context) (*pty, error) {
	c.ctx = ctx
	c.cmd = exec.CommandContext(ctx, c.name, c.args...)
	c.cmd.Env = append(c.env, os.Environ()...)

	var err error
	c.ptmx, err = startPty(c.cmd)
	if err != nil {
		return nil, fmt.Errorf("unable to start pty: %w", err)
	}

	return c.ptmx, nil
}

func (c *command) Run() error {
	// Set stdin in raw mode.
	isTty := term.IsTerminal(int(c.stdin.Fd()))

	if isTty {
		oldState, err := term.MakeRaw(int(c.stdin.Fd()))
		if err != nil {
			return fmt.Errorf("unable to set terminal to raw mode: %w", err)
		}
		defer func() { _ = term.Restore(int(c.stdin.Fd()), oldState) }()
	}

	var g run.Group
	if isTty {
		// Setup terminal resize handling (platform-specific)
		c.setupTerminalResize(&g, c.stdin, c.ptmx, c.eventEmitter)
	}

	// Forward stdin if it's a TTY or if forced for testing.
	// Do not forward stdin if it's not a TTY to avoid blocking indefinitely on io.Copy,
	// since non-TTY stdin (pipes, redirects) may never receive EOF in daemon-like scenarios.
	if isTty || c.forceForwardingInputForTesting {
		// input - forward stdin to PTY
		ctx, cancel := context.WithCancel(c.ctx)
		g.Add(func() error {
			_, err := io.Copy(c.ptmx, uio.NewContextReader(ctx, c.stdin))
			return err
		}, func(err error) {
			cancel()
		})
	}
	{
		// output
		if err := c.writers.Append(c.stdout); err != nil {
			return err
		}
		ctx, cancel := context.WithCancel(c.ctx)
		g.Add(func() error {
			_, err := io.Copy(c.writers, uio.NewContextReader(ctx, c.ptmx))
			return ptyError(err)
		}, func(err error) {
			c.writers.Remove(os.Stdout)
			cancel()
		})
	}
	{
		ctx, cancel := context.WithCancel(c.ctx)
		g.Add(func() error {
			done := make(chan error, 1)
			go func() {
				done <- c.waitForProcess()
			}()

			select {
			case err := <-done:
				return err
			case <-ctx.Done():
				// Context cancelled, kill the process and wait for it to exit
				_ = c.killProcess()
				<-done // Wait for the process to actually exit
				return ctx.Err()
			}
		}, func(err error) {
			_ = c.ptmx.Close()
			cancel()
		})
	}

	return g.Run()
}
