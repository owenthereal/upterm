package client

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/creack/pty"
	"github.com/jingweno/upterm"
	"github.com/oklog/run"
	"golang.org/x/crypto/ssh/terminal"
)

func NewCommand(name string, args []string, em *EventManager, writers *upterm.MultiWriter) *Command {
	return &Command{
		name:    name,
		args:    args,
		em:      em,
		writers: writers,
	}
}

type Command struct {
	name string
	args []string

	cmd  *exec.Cmd
	ptmx *os.File

	em      *EventManager
	writers *upterm.MultiWriter

	ctx context.Context
}

func (c *Command) Start(ctx context.Context) (*os.File, error) {
	var err error

	c.ctx = ctx
	c.cmd = exec.CommandContext(ctx, c.name, c.args...)
	c.ptmx, err = pty.Start(c.cmd)
	if err != nil {
		return nil, fmt.Errorf("unable to start pty: %w", err)
	}

	return c.ptmx, nil
}

func (c *Command) Run() error {
	// Set stdin in raw mode.
	oldState, err := terminal.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("unable to set terminal to raw mode: %w", err)
	}
	defer func() { _ = terminal.Restore(int(os.Stdin.Fd()), oldState) }()

	var g run.Group
	{
		// pty
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGWINCH)
		ch <- syscall.SIGWINCH // Initial resize.
		te := c.em.TerminalEvent("local", c.ptmx)
		g.Add(func() error {
			for range ch {
				h, w, err := pty.Getsize(os.Stdin)
				if err != nil {
					return err
				}

				te.TerminalWindowChanged(w, h)
			}

			return nil
		}, func(err error) {
			close(ch)
			te.TerminalDetached()
		})
	}
	{
		// input
		ctx, cancel := context.WithCancel(c.ctx)
		g.Add(func() error {
			_, err := io.Copy(c.ptmx, upterm.NewContextReader(ctx, os.Stdin))
			return err
		}, func(err error) {
			cancel()
		})
	}
	{
		// output
		c.writers.Append(os.Stdout)
		g.Add(func() error {
			_, err := io.Copy(c.writers, c.ptmx)
			return err
		}, func(err error) {
			c.writers.Remove(os.Stdout)
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
