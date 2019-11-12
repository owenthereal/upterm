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
	"github.com/jingweno/upterm/client/internal"
	"github.com/oklog/run"
	"golang.org/x/crypto/ssh/terminal"
)

func newCommand(name string, args []string, em *internal.EventManager, writers *upterm.MultiWriter) *command {
	return &command{
		name:    name,
		args:    args,
		em:      em,
		writers: writers,
	}
}

type command struct {
	name string
	args []string

	cmd  *exec.Cmd
	ptmx *os.File

	em      *internal.EventManager
	writers *upterm.MultiWriter

	ctx context.Context
}

func (c *command) Start(ctx context.Context) (*os.File, error) {
	var err error

	c.ctx = ctx
	c.cmd = exec.CommandContext(ctx, c.name, c.args...)
	c.ptmx, err = pty.Start(c.cmd)
	if err != nil {
		return nil, fmt.Errorf("unable to start pty: %w", err)
	}

	return c.ptmx, nil
}

func (c *command) Run() error {
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
		ctx, cancel := context.WithCancel(c.ctx)
		g.Add(func() error {
			for {
				select {
				case <-ctx.Done():
					close(ch)
					return ctx.Err()
				case <-ch:
					h, w, err := pty.Getsize(os.Stdin)
					if err != nil {
						return err
					}

					te.TerminalWindowChanged(w, h)
				}
			}
			return nil
		}, func(err error) {
			cancel()
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
		ctx, cancel := context.WithCancel(c.ctx)
		c.writers.Append(os.Stdout)
		g.Add(func() error {
			_, err := io.Copy(c.writers, upterm.NewContextReader(ctx, c.ptmx))
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
