package internal

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/creack/pty"
	uio "github.com/jingweno/upterm/io"
	"github.com/oklog/run"
	"golang.org/x/crypto/ssh/terminal"
)

func NewCommand(
	name string,
	args []string,
	env []string,
	stdin *os.File,
	stdout *os.File,
	em *EventManager,
	writers *uio.MultiWriter,
) *Command {
	return &Command{
		name:    name,
		args:    args,
		env:     env,
		stdin:   stdin,
		stdout:  stdout,
		em:      em,
		writers: writers,
	}
}

type Command struct {
	name string
	args []string
	env  []string

	cmd  *exec.Cmd
	ptmx *Pty

	stdin  *os.File
	stdout *os.File

	em      *EventManager
	writers *uio.MultiWriter

	ctx context.Context
}

func (c *Command) Start(ctx context.Context) (*Pty, error) {
	c.ctx = ctx
	c.cmd = exec.CommandContext(ctx, c.name, c.args...)
	c.cmd.Env = append(c.env, os.Environ()...)

	ptmx, err := pty.Start(c.cmd)
	if err != nil {
		return nil, fmt.Errorf("unable to start pty: %w", err)
	}
	c.ptmx = WrapPty(ptmx)

	return c.ptmx, nil
}

func (c *Command) Run() error {
	// Set stdin in raw mode.
	isTty := terminal.IsTerminal(int(c.stdin.Fd()))

	if isTty {
		oldState, err := terminal.MakeRaw(int(c.stdin.Fd()))
		if err != nil {
			return fmt.Errorf("unable to set terminal to raw mode: %w", err)
		}
		defer func() { _ = terminal.Restore(int(c.stdin.Fd()), oldState) }()
	}

	var g run.Group
	if isTty {
		// pty
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGWINCH)
		ch <- syscall.SIGWINCH // Initial resize.
		te := c.em.TerminalEvent("local", c.ptmx)
		ctx, cancel := context.WithCancel(c.ctx)
		g.Add(func() error {
			for {
				select {
				case <-ctx.Done():
					close(ch)
					return ctx.Err()
				case <-ch:
					h, w, err := pty.Getsize(c.stdin)
					if err != nil {
						return err
					}

					te.TerminalWindowChanged(w, h)
				}
			}
		}, func(err error) {
			te.TerminalDetached()
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
			return err
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
