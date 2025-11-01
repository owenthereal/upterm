package internal

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"

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
) *command {
	return &command{
		name:         name,
		args:         args,
		env:          env,
		stdin:        stdin,
		stdout:       stdout,
		eventEmitter: eventEmitter,
		writers:      writers,
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
		// pty
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGWINCH)
		ch <- syscall.SIGWINCH // Initial resize.
		ctx, cancel := context.WithCancel(c.ctx)
		tee := terminalEventEmitter{c.eventEmitter}
		g.Add(func() error {
			for {
				select {
				case <-ctx.Done():
					close(ch)
					return ctx.Err()
				case <-ch:
					h, w, err := getPtysize(c.stdin)
					if err != nil {
						return err
					}
					tee.TerminalWindowChanged("local", c.ptmx, w, h)
				}
			}
		}, func(err error) {
			tee.TerminalDetached("local", c.ptmx)
			cancel()
		})
	}

	if isTty || testing.Testing() {
		// input - forward stdin to PTY
		// TTY mode: stdin is an active terminal, we need to forward user input to the PTY.
		// Test mode: stdin is mocked by the test, we need to forward test data to the PTY.
		// Both cases require the input actor to be coordinated with the run group.
		// Non-TTY non-test mode: stdin is already closed (spawned from non-interactive env),
		// so we skip it to avoid unnecessary operations.
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
				done <- c.cmd.Wait()
			}()

			select {
			case err := <-done:
				return err
			case <-ctx.Done():
				// Context cancelled, kill the process and wait for it to exit
				if c.cmd.Process != nil {
					_ = c.cmd.Process.Kill()
				}
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
