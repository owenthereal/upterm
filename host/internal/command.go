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
// next, save the first: SIGHUP (bounded by hangupGrace instead), then close
// the pty master, then SIGTERM, then SIGKILL. Five seconds is long enough
// for a shell to hang up its jobs and a program to flush, and short enough
// that `session stop` against something that ignores everything is a worst
// case of about sixteen seconds -- hangupGrace plus three of these -- not a
// minute.
const DefaultStopGrace = 5 * time.Second

// hangupGrace bounds only the first step of terminate's teardown -- how
// long SIGHUP alone is given before the pty master closes -- and is
// shorter than stopGrace on purpose. An idle interactive shell (nothing
// typed into it yet, nothing running) ignores a bare SIGHUP for ten
// seconds or more, measured against a real bash; a shell that is going to
// act on it, forwarding it to its jobs, does so in tens of milliseconds.
// A full stopGrace here would buy the idle case nothing and would cost
// every freshly started, untouched session -- the common case for a
// `--detach`ed one -- several extra seconds on every stop. A var so a test
// can shrink it.
var hangupGrace = time.Second

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
				terminate(c.ptmx, exited, c.grace(), c.logger, c.name)
				// terminate's own final wait is bounded -- it may return
				// with the process still not confirmed exited, however
				// unlikely -- so waitErr may still be being written by the
				// goroutine above. Reading it here unconditionally would be
				// a data race; recording is safe only once exited has
				// actually closed, which happens-before this observes it.
				select {
				case <-exited:
					c.recordResult(waitErr)
				default:
				}
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

			// Fired, not waited on, same as terminate's own close (see its
			// doc comment for why a close here can never be relied on to
			// return): run.Group calls every actor's interrupt before it
			// waits for any execute to return, so an interrupt parked in a
			// blocking Close would hang Run's own return exactly the way a
			// synchronous close inside terminate would hang terminate's.
			// waitDone still keeps this from firing until terminate's own
			// execute has returned, but not from overlapping it: terminate's
			// own close runs on closeAsync's own goroutine, not the actor's,
			// and may still be in flight here. That overlap is harmless --
			// os.File.Close is safe to call twice, and the Windows pty
			// guards its own close the same way -- so which of the two
			// closes actually reaches the descriptor first does not matter:
			// whichever wins, wins, and the daemon's own process exit closes
			// it regardless of either.
			//
			// That the output actor has already drained by the time this
			// runs is a separate guarantee, and not this gate's doing:
			// run.Group calls interrupts in the order actors were added, so
			// the output actor's own interrupt (above, waitIdle) always runs
			// to completion first, whichever actor returned first.
			<-waitDone
			closeAsync(c.ptmx)
		})
	}

	return g.Run()
}

// closeAsync starts closing ptmx on its own goroutine and returns without
// waiting. See terminate's doc comment for why a close here can never be
// relied on to return, and why it is fired anyway.
func closeAsync(ptmx PTY) {
	go func() { _ = ptmx.Close() }()
}

// terminate ends a command that has been told to stop, the design's own
// sequence: SIGHUP to its process group, which a job-control shell forwards
// to every job; if it stays past hangupGrace, close the pty master --
// anything still holding the terminal open fails its reads and writes,
// which collects processes that ignored the hangup, and is also what frees
// a session leader a platform will otherwise block inside exit() while its
// controlling terminal still holds output nobody has drained, since the
// reader that was going to drain it stopped issuing new reads the moment
// this session began ending; SIGTERM after another grace; SIGKILL to the
// group, then the leader, after a third -- the design's boundary is
// everything in the command's process group, plus everything that hangs up
// when the pty goes, and a leader-only kill would leave its own children
// behind exactly like the hangup and the term steps would if nothing
// forwarded them. Where signals are unsupported it kills at once. Every
// wait in here is bounded, including the one after the final kill --
// terminate must return, with or without proof the process has actually
// gone, because it runs on the actor's own execute and run.Group is
// waiting for that to return before anything else can. A command still not
// confirmed exited when terminate gives up is logged: Result() staying
// zero for it is fine, but it should not also be silent.
//
// The close is fired on its own goroutine rather than waited on, and this
// is load-bearing, not a style choice. Read holds the pty's read lock for
// the length of a blocking read and Close takes the write lock, so a
// synchronous close here would wait on a read that only the process's exit
// ends -- the very hang this step exists to break. Bypassing that lock does
// not fix it either: the master is opened in blocking mode with no poller
// registration, so the Go runtime itself defers the underlying close(2)
// behind whatever read is already in flight, independent of any lock this
// package takes. Firing it is still worth doing: once the reader is
// released -- the process's own exit, or the case this step exists for, a
// leader already stuck in exit() because its slave is already closed -- the
// close lands, and anything still holding the master open past that point
// fails its next read or write.
func terminate(ptmx PTY, exited <-chan struct{}, grace time.Duration, logger *slog.Logger, name string) {
	// gone reports whether exited has already closed, without blocking:
	// sending a signal after that would reach whatever pid the kernel has
	// since reused, not the command, and closing or killing an already-gone
	// process is only ever wasted work, not wrong -- so only the signals
	// check this.
	gone := func() bool {
		select {
		case <-exited:
			return true
		default:
			return false
		}
	}
	// wait blocks for up to d, reporting whether exited closed within it.
	// Every step below is followed by exactly one of these.
	wait := func(d time.Duration) bool {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-exited:
			return true
		case <-timer.C:
			return false
		}
	}
	// kill sends SIGKILL to the group -- the same non-blocking exited check
	// the other signal steps make first, since a group signal has the same
	// reused-pid risk they do -- and then kills the leader directly, the
	// way it always has: Signal alone cannot be trusted to reach a leader
	// that already left the group on purpose, and Kill (through
	// os.Process) is what returns ErrProcessDone once the leader is
	// already reaped, which a raw group signal has no way to know. Then it
	// waits at most one more grace for either to have taken -- the one
	// wait in this whole function that is not preceded by a signal this
	// function chose to send for its own sake, since it is also where
	// terminate lands when Signal itself reports the platform cannot take
	// a step it was asked for (Windows: the group SIGKILL above is then
	// simply a no-op, and this step is the Kill it already was). A command
	// still running when even this gives up is logged, so an abandoned
	// teardown leaves a trace.
	kill := func() {
		if !gone() {
			_ = ptmx.Signal(syscall.SIGKILL)
		}
		_ = ptmx.Kill()
		if !wait(grace) {
			logger.Warn("command did not exit after being killed; giving up on this teardown",
				"name", name, "bound", grace)
		}
	}

	if gone() {
		return
	}
	if err := ptmx.Signal(syscall.SIGHUP); err != nil {
		kill()
		return
	}
	if wait(hangupGrace) {
		return
	}

	closeAsync(ptmx)
	if wait(grace) {
		return
	}

	if gone() {
		return
	}
	if err := ptmx.Signal(syscall.SIGTERM); err != nil {
		kill()
		return
	}
	if wait(grace) {
		return
	}

	kill()
}
