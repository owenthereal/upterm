package internal

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	"golang.org/x/term"
)

const (
	// outputIdleTimeout is how long output may stay quiet after the process
	// exits before the pty is considered drained.
	outputIdleTimeout = 100 * time.Millisecond
	// outputDrainTimeout bounds the total time spent draining after exit.
	outputDrainTimeout = time.Second
)

// activityWriter records when it last wrote, so a drain can stop once output
// has gone idle.
type activityWriter struct {
	io.Writer
	last atomic.Int64 // unix nanoseconds of the last write
}

func (w *activityWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	w.last.Store(time.Now().UnixNano())
	return n, err
}

// waitIdle returns when done is closed, when no write has happened for idle,
// or after max. The idle window is measured from now, not from the last
// write, so output that has not yet been read still gets its chance.
func (w *activityWriter) waitIdle(done <-chan struct{}, idle, max time.Duration) {
	start := time.Now()
	deadline := time.NewTimer(max)
	defer deadline.Stop()
	tick := time.NewTicker(idle / 4)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-deadline.C:
			return
		case <-tick.C:
			last := time.Unix(0, w.last.Load())
			if last.Before(start) {
				last = start
			}
			if time.Since(last) >= idle {
				return
			}
		}
	}
}

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
	ptmx PTY

	stdin  *os.File
	stdout *os.File

	writers *uio.MultiWriter

	eventEmitter *emitter.Emitter

	ctx context.Context

	// ForceForwardingInputForTesting forces stdin forwarding even when stdin is not a TTY.
	// This is used in tests where stdin is a pipe but we still want to forward test data.
	forceForwardingInputForTesting bool
}

// setupCommand creates an exec.Cmd with the given context, name, and args.
// No special platform-specific handling is needed - signal handling is done
// at the application level in host/host_*.go files.
func setupCommand(ctx context.Context, name string, args []string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

func (c *command) Start(ctx context.Context) (PTY, error) {
	c.ctx = ctx
	c.cmd = setupCommand(ctx, c.name, c.args)
	c.cmd.Env = append(c.env, os.Environ()...)

	var err error
	// Pass stdin so startPty can get the initial terminal size
	c.ptmx, err = startPty(c.cmd, c.stdin)
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
		output := &activityWriter{Writer: c.writers}
		done := make(chan struct{})
		g.Add(func() error {
			defer close(done)
			_, err := io.Copy(output, uio.NewContextReader(ctx, c.ptmx))
			return ptyError(err)
		}, func(err error) {
			// The process may have exited with output still buffered in the
			// pty. Cancelling the copy here would drop it, so let the copy
			// run until the read ends or output goes idle. On Unix the read
			// ends by itself once the slave side closes; ConPTY never signals
			// EOF until closed, and a background child can keep a Unix pty
			// open, so the wait is bounded.
			output.waitIdle(done, outputIdleTimeout, outputDrainTimeout)
			c.writers.Remove(c.stdout)
			cancel()
		})
	}
	{
		ctx, cancel := context.WithCancel(c.ctx)
		g.Add(func() error {
			done := make(chan error, 1)
			go func() {
				done <- c.ptmx.Wait()
			}()

			select {
			case err := <-done:
				return err
			case <-ctx.Done():
				// Context cancelled, kill the process and wait for it to exit
				_ = c.ptmx.Kill()
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
