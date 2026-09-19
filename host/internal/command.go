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
	"syscall"
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

// DefaultStopGrace is how long each step of the teardown waits before the
// next: SIGHUP, then SIGTERM, then SIGKILL. Five seconds is long enough for
// a shell to hang up its jobs and a program to flush, and short enough that
// `session stop` against something that ignores both is a ten-second wait,
// not a minute.
const DefaultStopGrace = 5 * time.Second

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

	// stopGrace bounds each step of terminate's teardown; zero means
	// DefaultStopGrace. Set by the caller after construction, not a
	// newCommand parameter.
	stopGrace time.Duration
}

// grace is how long terminate waits at each step: the field if set, else
// DefaultStopGrace.
func (c *command) grace() time.Duration {
	if c.stopGrace > 0 {
		return c.stopGrace
	}
	return DefaultStopGrace
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
	// exec.Command, not CommandContext: Go's own cancellation kills the
	// process outright the instant the context ends, ahead of the hangup
	// the wait actor below sends first. The forced command keeps
	// CommandContext (see startForceCommand): its teardown is the guest's
	// channel closing, and a kill is the right end for it.
	c.cmd = exec.Command(c.name, c.args...)
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
		waitDone := make(chan struct{})
		g.Add(func() error {
			defer close(waitDone)

			exited := make(chan struct{})
			var waitErr error
			go func() {
				waitErr = c.ptmx.Wait()
				close(exited)
			}()

			select {
			case <-exited:
				c.recordResult(waitErr)
				return waitErr
			case <-ctx.Done():
				// The session is ending and the command is not: hang it up
				// the way a terminal going away would, and escalate only if
				// it stays.
				terminate(c.ptmx, exited, c.grace())
				c.recordResult(waitErr)
				return ctx.Err()
			}
		}, func(err error) {
			// cancel first: this actor's own execute is parked in the select
			// above on this same ctx, and run.Group's contract is that
			// execute returns once interrupt is invoked. When the output
			// actor returns first with c.ctx still live -- a command that
			// closes its pty slave but keeps running, so the master read
			// ends on its own while nothing has asked the session to stop --
			// nothing else would ever cancel this ctx, and waiting on
			// waitDone before that happened would block forever. Cancelling
			// first unblocks the select via ctx.Done, which sends terminate
			// on its way; in the cancellation flow this cancel is a no-op,
			// since ctx is already done.
			cancel()

			// Close takes the pty's write lock, which a pending writer
			// starves new readers behind (see terminate's doc comment on
			// why it never closes the pty itself). waitDone, closed only
			// once this actor's own execute returns, keeps Close from
			// running until terminate already has, so it can never queue
			// ahead of terminate's own Signal calls. Now that cancel runs
			// first, this wait is bounded by terminate's own grace/kill
			// sequence on every path, not just the one where c.ctx was
			// already done when we got here.
			//
			// That the output actor has already drained by the time this
			// runs is a separate guarantee, and not this gate's doing:
			// run.Group calls interrupts in the order actors were added, so
			// the output actor's own interrupt (above, waitIdle) always runs
			// to completion first, whichever actor returned first.
			<-waitDone
			_ = c.ptmx.Close()
		})
	}

	return g.Run()
}

// terminate ends a command that has been told to stop: SIGHUP to its
// process group, which a job-control shell forwards to every job; SIGTERM
// after grace; SIGKILL after another. Where signals are unsupported it
// kills at once. It returns once the process has exited.
//
// The pty master is deliberately not closed between the steps: Read holds
// the pty's read lock for the length of a blocking read and Close takes the
// write lock, so a close here would wait on a read that only the process's
// exit ends. The interrupt closes it only after this returns, which the
// wait actor's waitDone gate guarantees.
func terminate(ptmx PTY, exited <-chan struct{}, grace time.Duration) {
	for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGTERM} {
		select {
		case <-exited:
			// Already gone by the time this step was due: sending a signal
			// now would reach whatever pid the kernel has since reused,
			// not the command.
			return
		default:
		}
		if err := ptmx.Signal(sig); err != nil {
			break
		}
		timer := time.NewTimer(grace)
		select {
		case <-exited:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	_ = ptmx.Kill()
	<-exited
}
