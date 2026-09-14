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
	"golang.org/x/term"
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
	stdin *os.File,
	stdout *os.File,
	eventEmitter *emitter.Emitter,
	writers *uio.MultiWriter,
	logger *slog.Logger,
	forceForwardingInputForTesting bool,
) *command {
	return &command{
		name:                           name,
		args:                           args,
		env:                            env,
		ptySize:                        ptySize,
		pinPtySize:                     pinPtySize,
		term:                           term,
		stdin:                          stdin,
		stdout:                         stdout,
		eventEmitter:                   eventEmitter,
		writers:                        writers,
		logger:                         logger,
		forceForwardingInputForTesting: forceForwardingInputForTesting,
		ownsTerminal:                   ownsTerminal,
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

	stdin  *os.File
	stdout *os.File

	writers *uio.MultiWriter

	eventEmitter *emitter.Emitter
	logger       *slog.Logger

	// ownsTerminal is the package function of the same name, held in a field
	// so a test can take the terminal away mid-run. Losing the foreground is a
	// job-control event -- ^Z then bg -- that no in-process pty can be made to
	// produce, and the rule it is asked about is only interesting when the
	// answer changes between the start of Run and its end.
	ownsTerminal func(*os.File) bool

	ctx context.Context

	// result is the command's own outcome, recorded by the actor that waits on
	// it. run.Group.Run returns whichever actor finished first, and the output
	// copy returns nil on pty EOF at the same instant the command exits, so
	// reading a status off Run is a coin toss. HandleSession learned this the
	// hard way; see HandleSession.
	resultMu sync.Mutex
	result   CommandResult

	// ForceForwardingInputForTesting forces stdin forwarding even when stdin is not a TTY.
	// This is used in tests where stdin is a pipe but we still want to forward test data.
	forceForwardingInputForTesting bool

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

func (c *command) Start(ctx context.Context) (PTY, error) {
	c.ctx = ctx
	c.cmd = setupCommand(ctx, c.name, c.args)
	// The session's own variables go last, and that is the whole rule for all
	// three of them. exec.Cmd keeps the last duplicate key, so appending is
	// what makes UPTERM_SESSION_NAME, UPTERM_ADMIN_SOCKET and TERM describe
	// *this* session rather than whatever the host inherited -- and inheriting
	// them is the ordinary case, not an exotic one: a host started inside
	// another upterm session, or a multiplexer told to forward the variables,
	// hands us somebody else's session, and TERM comes from whichever terminal
	// launched the host. Prepended instead, --term would silently do nothing
	// and `upterm session info` inside the session would name the outer one.
	c.cmd.Env = append(os.Environ(), c.env...)
	if c.term != "" {
		c.cmd.Env = append(c.cmd.Env, fmt.Sprintf("TERM=%s", c.term))
	}

	var err error
	c.ptmx, err = startPty(c.cmd, ResolvePtySize(c.stdin, c.ptySize), c.pinPtySize)
	if err != nil {
		return nil, fmt.Errorf("unable to start pty: %w", err)
	}

	return c.ptmx, nil
}

// logInputEnded records that input forwarding stopped. It is not an error for
// the session, only the end of one of its inputs.
func (c *command) logInputEnded(err error) {
	if c.logger == nil {
		return
	}
	c.logger.Debug("stdin forwarding ended; session continues", "error", err)
}

func (c *command) Run() error {
	// Not "is stdin a terminal" but "is stdin a terminal we are entitled to
	// touch". Backgrounded, these are someone else's terminal's settings.
	owns := c.ownsTerminal(c.stdin)

	if owns {
		// Set stdin in raw mode.
		oldState, err := term.MakeRaw(int(c.stdin.Fd()))
		if err != nil {
			return fmt.Errorf("unable to set terminal to raw mode: %w", err)
		}
		defer func() {
			// Asked again rather than remembered, because the answer can
			// change while the command runs: ^Z then bg, or a shell that moved
			// on, leaves the host in the background of a terminal somebody
			// else is now using. SIGTTOU is ignored for the reasons in
			// host_unix.go, so nothing would stop this tcsetattr from
			// succeeding -- it would write this session's stale termios over
			// theirs, and the usual symptom is a shell that has lost its echo.
			//
			// The settings belong to whoever is in the foreground now. If we
			// are ever foregrounded again, the shell's job control puts ours
			// back as part of resuming us.
			if !c.ownsTerminal(c.stdin) {
				return
			}
			_ = term.Restore(int(c.stdin.Fd()), oldState)
		}()
	}

	var g run.Group
	if owns {
		// Setup terminal resize handling (platform-specific)
		c.setupTerminalResize(&g, c.stdin, c.ptmx, c.eventEmitter)
	}

	// Forward stdin only from a terminal we own, or when forced for testing.
	// A pipe or a redirect is nobody's terminal and may never see EOF, and a
	// terminal we are not in the foreground of is not ours to read.
	if owns || c.forceForwardingInputForTesting {
		// input - forward stdin to PTY
		ctx, cancel := context.WithCancel(c.ctx)
		g.Add(func() error {
			// The copy ending is not the session ending. stdin can die on its
			// own — a backgrounded process, a closed terminal, plain EOF —
			// while the command is perfectly healthy.
			//
			// Returning here would end the session either way: run.Group
			// interrupts every actor as soon as any one of them returns, and it
			// never looks at the error. Returning nil would be exactly as fatal
			// as returning the error. So park until the session is cancelled,
			// which the interrupt below does.
			_, err := io.Copy(c.ptmx, uio.NewContextReader(ctx, c.stdin))
			if err != nil {
				c.logInputEnded(err)
			}
			<-ctx.Done()
			return nil
		}, func(err error) {
			cancel()
		})
	}
	{
		// output
		//
		// A stdout that is a terminal stays synchronous: the pty should not run
		// ahead of the screen that owns it, and a human watching wants complete
		// output more than they want the command to finish sooner.
		//
		// A stdout that is not a terminal is a pipe, a file or a log. A pipe
		// nobody drains blocks forever, and MultiWriter.Write holds writeMu
		// across the fan-out, so that block stops every other writer and every
		// new attach: the session wedges. Bounding it makes the worst case "the
		// log loses output", which is what a log is for.
		//
		// c.stdout belongs to whoever constructed the Host. Nothing here closes
		// it, dups it, or changes its flags — and so nothing here can release a
		// drain goroutine already blocked writing to it. See the note below.
		hostOut := io.Writer(c.stdout)
		var hostSink *uio.AsyncWriter
		if !term.IsTerminal(int(c.stdout.Fd())) {
			// Capture the logger, not c. A closure over the command retains
			// the command, its pty and the whole fan-out for as long as the
			// parked writer lives, which makes the "bounded" claim below false
			// by a wide margin.
			logger := c.logger
			hostSink = uio.NewAsyncWriter(c.stdout, uio.DefaultGuestBufferSize, func(err error) {
				logger.Warn("host stdout dropped; session continues", "error", err)
			})
			hostOut = hostSink
		}

		// The bound, since the comment above promises one. A pipe nobody
		// drains parks this sink's drain goroutine in that write until the
		// process exits: Close cannot release it, and both ways to force the
		// write to return were rejected — a deadline, which Fd() has already
		// disabled, and a dup, which would set O_NONBLOCK on the caller's own
		// pipe. At most one such goroutine per Run. It retains the sink, its
		// in-flight chunk and the logger the drop callback closes over,
		// blocks nothing else, and ends when the pipe drains, the reader
		// closes it, or the process exits.

		if err := c.writers.Append(hostOut); err != nil {
			return err
		}
		ctx, cancel := context.WithCancel(c.ctx)
		output := &activityWriter{Writer: c.writers}
		done := make(chan struct{})
		g.Add(func() error {
			// Runs last, by LIFO. The copy has returned, so the producer has
			// provably stopped and nothing further can enter the fan-out: this
			// is the only point where a flush is a barrier rather than a guess.
			// Putting it in the interrupt instead would race the producer, and
			// waiting there for the copy would not even be bounded — cancelling
			// the reader cannot release a copy blocked in the synchronous write
			// to c.stdout, and run.Group calls interrupts one after another, so
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

				// Shutdown only flushes writers that are still attached, and
				// AsyncWriter.Close discards whatever is pending. So the order is
				// flush, then remove, then close. An earlier draft removed and
				// closed in the interrupt, which both skipped the flush and threw
				// away a slow stdout's tail.
				c.writers.Remove(hostOut)
				if hostSink != nil {
					_ = hostSink.Close()
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
