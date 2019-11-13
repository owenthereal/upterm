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
	"github.com/jingweno/upterm/client/internal"
	uio "github.com/jingweno/upterm/io"
	"github.com/oklog/run"
	"golang.org/x/crypto/ssh/terminal"
)

func newCommand(
	name string,
	args []string,
	stdin *os.File,
	stdout *os.File,
	em *internal.EventManager,
	writers *uio.MultiWriter,
) *command {
	return &command{
		name:    name,
		args:    args,
		stdin:   stdin,
		stdout:  stdout,
		em:      em,
		writers: writers,
	}
}

type command struct {
	name string
	args []string

	cmd  *exec.Cmd
	ptmx *os.File

	stdin  *os.File
	stdout *os.File

	em      *internal.EventManager
	writers *uio.MultiWriter

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
			_, err := io.Copy(c.ptmx, uio.NewContextReader(ctx, c.stdin))
			return err
		}, func(err error) {
			cancel()
		})
	}
	{
		// output
		ctx, cancel := context.WithCancel(c.ctx)
		c.writers.Append(c.stdout)
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
