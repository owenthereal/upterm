package internal

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

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

	{
		// input
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
		g.Add(func() error {
			return c.cmd.Wait()
		}, func(err error) {
			c.ptmx.Close()
		})
	}

	return g.Run()
}
