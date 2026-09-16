package internal

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
)

const (
	// outputIdleTimeout is how long output may stay quiet after the process
	// exits before the pty is considered drained.
	outputIdleTimeout = 100 * time.Millisecond
	// outputDrainTimeout bounds the total time spent draining after exit.
	outputDrainTimeout = time.Second
	// guestFlushTimeout bounds how long the fan-out waits for asynchronous
	// guests to receive what it has already accepted, once the producer has
	// stopped. A guest still behind when it expires loses the remainder; it is
	// deliberately not dropped for that, because the session is ending and a
	// slow last second is not an overflow.
	guestFlushTimeout = time.Second
	// guestFlushLogTimeout bounds how long exit waits for the warning about
	// that flush to be written. Generous for any handler that is working, so
	// the line lands before the host tears down and stays in order with what
	// follows it; short enough that a handler blocked on a stopped terminal
	// cannot hold the exit open. Both halves matter — fire-and-forget loses the
	// line, waiting outright hangs the host.
	guestFlushLogTimeout = 100 * time.Millisecond
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
	ptySize termsize.Size,
	pinPtySize bool,
	term string,
	eventEmitter *emitter.Emitter,
	writers *uio.MultiWriter,
	logger *slog.Logger,
) *command {
	return &command{
		name:         name,
		args:         args,
		env:          env,
		ptySize:      ptySize,
		pinPtySize:   pinPtySize,
		term:         term,
		eventEmitter: eventEmitter,
		writers:      writers,
		logger:       logger,
	}
}

type command struct {
	name string
	args []string
	env  []string

	ptySize    termsize.Size
	pinPtySize bool
	term       string

	cmd  *exec.Cmd
	ptmx PTY

	writers *uio.MultiWriter

	eventEmitter *emitter.Emitter
	logger       *slog.Logger

	ctx context.Context

	// result is the command's own outcome, recorded by the actor that waits on
	// it. run.Group.Run returns whichever actor finished first, and the output
	// copy returns nil on pty EOF at the same instant the command exits, so
	// reading a status off Run is a coin toss. HandleSession learned this the
	// hard way; see HandleSession.
	resultMu sync.Mutex
	result   CommandResult

	// flushLogTimeoutForTesting, when non-zero, replaces guestFlushLogTimeout.
	// A test asserting the warning has landed when Run returns needs a bound
	// that a loaded CI scheduler cannot miss.
	flushLogTimeoutForTesting time.Duration
}

func (c *command) recordResult(err error) {
	code, exited := exitCode(err)

	res := CommandResult{Exited: exited, Code: code}
	if !exited {
		res.Signal = signalName(err)
	}

	c.resultMu.Lock()
	c.result = res
	c.resultMu.Unlock()
}

// Result returns the command's outcome. Safe after Run returns.
func (c *command) Result() CommandResult {
	c.resultMu.Lock()
	defer c.resultMu.Unlock()
	return c.result
}

// setupCommand creates an exec.Cmd with the given context, name, and args.
// No special platform-specific handling is needed - signal handling is done
// at the application level in host/host_*.go files.
func setupCommand(ctx context.Context, name string, args []string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

// Start opens the command's pty and starts it. initial is the geometry the
// initial client arrived with, used when nothing was asked for explicitly.
func (c *command) Start(ctx context.Context, initial termsize.Size) (PTY, error) {
	c.ctx = ctx
	c.cmd = setupCommand(ctx, c.name, c.args)
	// The session's own variables go last, and that is the whole rule for all
	// three of them. exec.Cmd keeps the last duplicate key, so appending is
	// what makes UPTERM_SESSION_NAME, UPTERM_ADMIN_SOCKET and TERM describe
	// *this* session rather than whatever the host inherited — and inheriting
	// them is the ordinary case, not an exotic one: a host started inside
	// another upterm session, or a multiplexer told to forward the variables,
	// hands us somebody else's session, and TERM comes from whichever terminal
	// launched the host. Prepended instead, --term would silently do nothing
	// and `upterm session info` inside the session would name the outer one.
	c.cmd.Env = append(os.Environ(), c.env...)
	if c.term != "" {
		c.cmd.Env = append(c.cmd.Env, fmt.Sprintf("TERM=%s", c.term))
	}

	want := c.ptySize
	if !want.Valid() {
		// The initial client's terminal, when there is one: the local
		// terminal used to be the host's stdin and now it is a client, and
		// the geometry it reports is the same one.
		want = initial
	}

	var err error
	// startPty falls back to termsize.Default for a size that is not one, so
	// a session nobody offered a geometry still opens at something usable.
	c.ptmx, err = startPty(c.cmd, want, c.pinPtySize)
	if err != nil {
		return nil, fmt.Errorf("unable to start pty: %w", err)
	}

	return c.ptmx, nil
}

func (c *command) Run() error {
	var g run.Group
	{
		// output: the pty into the fan-out. Every consumer — the local
		// terminal included — is a client of the fan-out now, so there is
		// nothing here to attach or pace: the primary client's synchronous
		// writer is what keeps the pty from running ahead of a terminal.
		ctx, cancel := context.WithCancel(c.ctx)
		output := &activityWriter{Writer: c.writers}
		done := make(chan struct{})
		g.Add(func() error {
			// Runs last, by LIFO. The copy has returned, so the producer has
			// provably stopped and nothing further can enter the fan-out: this
			// is the only point where a flush is a barrier rather than a guess.
			// Putting it in the interrupt instead would race the producer, and
			// waiting there for the copy would not even be bounded — cancelling
			// the reader cannot release a copy blocked in a synchronous write
			// to a client, and run.Group calls interrupts one after another, so
			// that wait would hold up the pty close behind it.
			defer func() {
				flushCtx, cancelFlush := context.WithTimeout(context.WithoutCancel(c.ctx), guestFlushTimeout)
				defer cancelFlush()
				if err := c.writers.Shutdown(flushCtx); err != nil {
					// Not a host failure, and nothing to do about it here: a
					// guest still stuck when the deadline expires loses its tail
					// by design, and a guest already gone flushes to nil. Worth
					// a line because otherwise the only evidence is a guest
					// whose last screenful never arrived, which looks from the
					// outside exactly like output the command never produced.
					//
					// Written off this goroutine but waited for, under a bound.
					//
					// This defer is the output actor's return path, and
					// run.Group cannot finish until it returns, so writing here
					// directly would let a handler blocked on a stopped
					// terminal hang the host's exit and leave guestFlushTimeout
					// bounding nothing. Not waiting at all trades that for a
					// quieter fault: Go abandons runnable goroutines at process
					// exit, so the one diagnostic this path produces could be
					// lost, or land after the shutdown lines it should precede,
					// with a perfectly healthy logger.
					//
					// Waiting under a bound is the only form with neither
					// failure. One goroutine per call of Run, which is once per
					// host process.
					logTimeout := guestFlushLogTimeout
					if c.flushLogTimeoutForTesting > 0 {
						logTimeout = c.flushLogTimeoutForTesting
					}
					logged := make(chan struct{})
					go func() {
						defer close(logged)
						c.logger.Warn("gave up delivering final output to a guest",
							"timeout", guestFlushTimeout, "error", err)
					}()
					select {
					case <-logged:
					case <-time.After(logTimeout):
					}
				}
			}()
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
				c.recordResult(err)
				return err
			case <-ctx.Done():
				// Context cancelled, kill the process and wait for it to exit
				_ = c.ptmx.Kill()
				c.recordResult(<-done) // Wait for the process to actually exit
				return ctx.Err()
			}
		}, func(err error) {
			_ = c.ptmx.Close()
			cancel()
		})
	}

	return g.Run()
}
