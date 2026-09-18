// Package attach is the local terminal's side of a session: an SSH client of
// the session's attach socket. upterm host, upterm attach and the functional
// tests all use it, so the local terminal is just another client in the code
// rather than in a design document.
package attach

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/run"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

// dialTimeout bounds the connect and handshake. The socket is local; anything
// slower than this is a daemon that is not answering.
const dialTimeout = 10 * time.Second

// outputDrainTimeout bounds how long Run waits, after the session has ended,
// for what the session sent to reach Stdout. A var so a test can shorten it.
var outputDrainTimeout = 5 * time.Second

// inputFlushTimeout bounds what a detach still owes the session — the Enter
// that preceded ~., or an escape byte held at EOF — so that a session no
// longer taking input cannot keep the detach from happening. A var so a test
// can shorten it.
var inputFlushTimeout = time.Second

// inputBacklogLimit bounds what may sit unwritten in forwardInput's queue
// while the session is not taking input. 1 MiB, the same figure as
// uio.DefaultGuestBufferSize: more than a terminal can be typed at, and
// small enough that a client holds no meaningful amount of what it will
// never deliver. A var so a test can shorten it.
var inputBacklogLimit = 1 << 20

// Pty is a pty request: the terminal type and geometry the client's own
// terminal has. A client that requests one is eligible to be the session's
// primary client; one that does not is a viewer.
type Pty struct {
	Term string
	Size termsize.Size
}

// Client attaches a pair of streams to a running session.
type Client struct {
	Socket  string
	Stdin   io.Reader
	Stdout  io.Writer
	Pty     *Pty
	Resizes <-chan termsize.Size
	Escape  byte
	Logger  *slog.Logger

	// HostKeys is the daemon's public keys, from the session record: one per
	// signer it holds, since a daemon started with several private keys may
	// present any of them. Run refuses to attach without at least one: a
	// client that accepted any key would hand its terminal to whatever bound
	// the socket.
	HostKeys []ssh.PublicKey

	// dial reaches the socket; nil is a unix dial. Tests hand over a
	// connection they can block, to stand in for a daemon that has stopped
	// reading its socket.
	dial func(ctx context.Context, socket string) (net.Conn, error)
}

// Reason says how an attachment ended.
type Reason int

const (
	// Detached: the client ended it — the escape key, EOF on Stdin, or ctx.
	Detached Reason = iota
	// Exited: the session sent the command's exit status and closed.
	Exited
	// Disconnected: the session closed the connection without an exit status.
	// The daemon's log says why: a stalled or overflowed client, or a daemon
	// that went away.
	Disconnected
)

func (r Reason) String() string {
	switch r {
	case Detached:
		return "detached"
	case Exited:
		return "exited"
	case Disconnected:
		return "disconnected"
	}
	return fmt.Sprintf("reason(%d)", int(r))
}

// Result is how an attachment ended. Status is meaningful only for Exited.
type Result struct {
	Reason Reason
	Status int
}

// Run attaches and returns when the attachment ends. An error means the client
// never attached; once attached, every ending is a Result.
func (c *Client) Run(ctx context.Context) (Result, error) {
	if c.Stdout == nil {
		return Result{}, errors.New("attach: Stdout is required")
	}
	if len(c.HostKeys) == 0 {
		return Result{}, errors.New("attach: HostKeys is required")
	}
	logger := c.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// A throwaway key per connection: nothing is written to disk and there is
	// nothing to rotate. The socket's permissions are the authentication; the
	// key only names this client in `session info`.
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Result{}, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return Result{}, err
	}

	// parent is the caller's context; ctx is the one internal cleanup
	// cancels. Told apart deliberately: see record below.
	parent := ctx
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	dialCtx, cancelDial := context.WithTimeout(ctx, dialTimeout)
	defer cancelDial()
	dial := c.dial
	if dial == nil {
		dial = func(ctx context.Context, socket string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}
	}
	raw, err := dial(dialCtx, c.Socket)
	if err != nil {
		return Result{}, fmt.Errorf("attach: %w", err)
	}
	// The deadline covers the handshake and every setup request after it —
	// a daemon that completed the handshake and then stopped answering
	// would otherwise hold NewSession, RequestPty or Shell forever. Cleared
	// only once the shell is running. Cancellation during the handshake
	// closes the socket the same way the AfterFunc below closes the client.
	_ = raw.SetDeadline(time.Now().Add(dialTimeout))
	stopRaw := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopRaw()
	conn, chans, reqs, err := ssh.NewClientConn(raw, c.Socket, &ssh.ClientConfig{
		User:            "host",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: c.checkHostKey,
		ClientVersion:   upterm.AttachSSHClientVersion,
	})
	if err != nil {
		_ = raw.Close()
		return Result{}, fmt.Errorf("attach: %w", err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer func() { _ = client.Close() }()

	// Local cancellation never waits on the peer. Closing the connection is
	// the one thing that fails a Wait on a session the daemon will never
	// close, an input write parked on an exhausted window, and a setup
	// request nobody answers: it ends mux.loop, which closes every channel
	// (x/crypto v0.57.0 ssh/mux.go:212-219). Bytes the channel has already
	// received stay readable after it, so the drain below loses nothing the
	// daemon actually sent.
	stopClosing := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stopClosing()

	sess, err := client.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("attach: %w", err)
	}
	defer func() { _ = sess.Close() }()

	if c.Pty != nil {
		size := c.Pty.Size
		if !size.Valid() {
			size = termsize.Default
		}
		if err := sess.RequestPty(c.Pty.Term, size.Rows, size.Cols, ssh.TerminalModes{}); err != nil {
			return Result{}, fmt.Errorf("attach: pty request: %w", err)
		}
		if c.Stdin != nil {
			// Interactive: this client displays on a terminal and forwards
			// its keystrokes, so it can answer the terminal queries a primary
			// is sent. Declared, because the daemon cannot tell a terminal
			// from a pipe on the far side of an SSH channel — and a pty viewer
			// that does not read its terminal would leave the terminal's
			// replies in the foreground shell as junk.
			if err := sess.Setenv(upterm.AttachInteractiveEnvVar, "1"); err != nil {
				return Result{}, fmt.Errorf("attach: %w", err)
			}
		}
	}
	// Always a pipe, even with no Stdin: leaving Session.Stdin nil makes
	// x/crypto copy from an empty reader and send EOF at once, which ends a
	// viewer's session the moment it starts. A pipe nobody writes to holds the
	// input open until the session ends.
	stdin, err := sess.StdinPipe()
	if err != nil {
		return Result{}, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return Result{}, err
	}
	if err := sess.Shell(); err != nil {
		return Result{}, fmt.Errorf("attach: %w", err)
	}
	_ = raw.SetDeadline(time.Time{})

	// The first cause recorded wins, and internal cleanup never records one.
	// run.Group interrupts every actor as soon as any one returns, so by the
	// time an interrupt runs "cancelled" says nothing about why: only the
	// actor that saw the cause may record it. And once the caller has left,
	// whatever is seen afterwards is a consequence of leaving: ctx is derived
	// from parent, so parent's end cancels ctx too, and Wait failing because
	// the connection was closed on the way out must read as the detach it is.
	var (
		mu     sync.Mutex
		result *Result
	)
	record := func(r Result) {
		if parent.Err() != nil {
			r = Result{Reason: Detached}
		}
		mu.Lock()
		defer mu.Unlock()
		if result == nil {
			result = &r
		}
	}

	// Output runs on its own goroutine, not as an actor: a Stdout that blocks
	// — a stopped terminal, a pipe nobody drains — must not keep Run from
	// returning once the session is gone. It owns Stdout only until
	// abandoned: a write already in flight cannot be interrupted without
	// owning the descriptor, but no later one is started. copyErr is a
	// failed write to Stdout; a read ending, however it ends, is nil, and
	// Wait says what it meant.
	var (
		abandoned atomic.Bool
		copied    = make(chan struct{})
		copyErr   error
		// What the session did to this terminal, watched on the way past so
		// it can be undone on the way out. Only for a terminal: a viewer
		// redirected into a pipe or a file is not left in any modes, and mode
		// sequences appended to a captured log are nothing but noise.
		modes *uio.ModeTracker
	)
	if c.Pty != nil {
		modes = uio.NewModeTracker()
	}
	go func() {
		defer close(copied)
		copyErr = c.copyOutput(stdout, modes, &abandoned)
	}()

	var g run.Group
	{
		// The session's end: an exit status, or a close without one. Cancel
		// first, then the courtesy close: run.Group runs interrupts one
		// after another, a channel close is a packet written to the socket,
		// and a daemon that has stopped reading its socket would park it —
		// before the interrupt that cancels, and so before the AfterFunc
		// that closes the connection and releases it. Cancelled first, the
		// close either completes or fails when the connection goes.
		g.Add(func() error {
			record(resultFromWait(sess.Wait()))
			return nil
		}, func(error) {
			cancel()
			_ = sess.Close()
		})
	}
	{
		// Stdout going away is this terminal detaching — EPIPE from a pipe
		// whose reader left, an error from a terminal that closed — and
		// nothing on the session's side would ever report it: with a quiet
		// command nothing else moves. On an ordinary EOF this parks; Wait
		// is what classifies the session's end.
		g.Add(func() error {
			select {
			case <-copied:
				if copyErr != nil {
					record(Result{Reason: Detached})
					return nil
				}
				<-ctx.Done()
			case <-ctx.Done():
			}
			return nil
		}, func(error) { cancel() })
	}
	if c.Stdin != nil {
		g.Add(func() error {
			if c.forwardInput(ctx, stdin, logger) {
				record(Result{Reason: Detached})
			}
			return nil
		}, func(error) { cancel() })
	}
	if c.Resizes != nil {
		g.Add(func() error {
			for {
				select {
				case size, ok := <-c.Resizes:
					if !ok {
						<-ctx.Done()
						return nil
					}
					if size.Valid() {
						if err := sess.WindowChange(size.Rows, size.Cols); err != nil {
							// Bounded: this fails when the connection has
							// gone, which is when the group is unwinding,
							// and a handler blocked on a stopped terminal
							// would park the unwind right here.
							logging.LogWithin(logger, slog.LevelDebug, logging.LogBound, "window change not delivered", "error", err)
						}
					}
				case <-ctx.Done():
					return nil
				}
			}
		}, func(error) { cancel() })
	}
	{
		// The caller leaving is a detach. This actor only triggers the
		// unwinding; record itself notices parent's end, so it does not
		// matter which of ctx and parent this select happens to pick.
		g.Add(func() error {
			<-ctx.Done()
			if parent.Err() != nil {
				record(Result{Reason: Detached})
			}
			return nil
		}, func(error) { cancel() })
	}
	_ = g.Run()

	// The tail. The channel's remaining bytes are readable after its close,
	// and Wait can return before the copy has read them.
	select {
	case <-copied:
		// Everything the session sent has been written, so the terminal is in
		// the modes the session left it in and this is the moment to take it
		// out of them: a full-screen program still running in the session
		// would otherwise leave this terminal's shell on the alternate
		// screen, cursor hidden, mouse reporting on. Restoring the termios
		// settings around this call says nothing about any of that.
		//
		// Here rather than in the copy goroutine because the tracker is that
		// goroutine's until it ends, and only this path has seen it end. On
		// the timeout below the copy may still be inside a write to a
		// terminal that is not taking bytes, which is the one case where
		// writing more is the wrong answer anyway.
		if modes != nil {
			if restore := modes.Restore(); len(restore) > 0 {
				if _, err := c.Stdout.Write(restore); err != nil {
					logger.Debug("could not restore the terminal's modes", "error", err)
				}
			}
		}
	case <-time.After(outputDrainTimeout):
		abandoned.Store(true)
		logging.WarnWithin(logger, logging.LogBound, "abandoning output still undelivered to the terminal", "timeout", outputDrainTimeout)
	}

	mu.Lock()
	defer mu.Unlock()
	if result == nil {
		// Every actor above records on its own ending; this is defensive.
		return Result{Reason: Disconnected}, nil
	}
	return *result, nil
}

// ErrHostKeyMismatch is what Run's error wraps when the door presented a key
// that is not the daemon's. It is exported so a caller can tell this apart
// from every other reason an attachment did not happen: those are worth
// retrying, and this one is worth stopping for — whatever answered the socket
// is not the session, and the terminal must not be handed to it. x/crypto
// returns the callback's error as it is and wraps it with %w, so errors.Is
// finds it through the handshake's own message.
var ErrHostKeyMismatch = errors.New("host key is not the daemon's")

// checkHostKey accepts key only if it matches one of HostKeys. The daemon may
// hold several signers and presents whichever the negotiated algorithm
// selects, so every pinned key is tried in turn; ssh.FixedHostKey does the
// actual comparison, since it is both the right byte comparison and the sink
// CodeQL recognises as safe.
func (c *Client) checkHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	for _, want := range c.HostKeys {
		if ssh.FixedHostKey(want)(hostname, remote, key) == nil {
			return nil
		}
	}
	// No "attach:" prefix: Run wraps the handshake's error with one already.
	return fmt.Errorf("%w (it presented %s)", ErrHostKeyMismatch, ssh.FingerprintSHA256(key))
}

// copyOutput copies the session's output into Stdout until the session's
// side ends or a write fails, checking abandoned before every write. It
// returns the write error — a short write is one, as io.Copy has it — and
// nil for every way the read can end.
//
// modes, when it is not nil, observes everything on its way to the terminal,
// so that the terminal can be put back afterwards. It is fed what was read
// rather than what was written: a write that fails has still reached the
// terminal as far as the modes in it are concerned, and the tracker is the
// record of what this terminal was asked to do, not of what arrived.
func (c *Client) copyOutput(r io.Reader, modes *uio.ModeTracker, abandoned *atomic.Bool) error {
	buf := make([]byte, 32<<10)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			if abandoned.Load() {
				return nil
			}
			if modes != nil {
				_, _ = modes.Write(buf[:n])
			}
			nw, werr := c.Stdout.Write(buf[:n])
			if werr != nil {
				return werr
			}
			if nw != n {
				return io.ErrShortWrite
			}
		}
		if rerr != nil {
			return nil
		}
	}
}

// forwardInput copies Stdin to the session through the escape filter. It
// reports true when the client is leaving of its own accord — the escape
// sequence completed, or Stdin ended, which from a terminal means the
// terminal went away — and false when it was unblocked by ctx, which is the
// session ending for some other reason that Wait will report.
//
// Reading and delivering are separate goroutines, because a session that has
// stopped taking input ends them differently. Its pty write is parked because
// the command is not reading, so the channel's window is exhausted, and the
// write that hits it returns only when the connection closes. Escape
// recognition lives in what has been read, so a client that read and wrote on
// one goroutine would stop reading exactly when the one escape that exists to
// get out of this is typed: the Enter before ~. parks, and the ~. is never
// seen. The reader therefore queues, and the writer parks.
//
// It does not close the session's input on the way out. That close is an
// EOF packet written to the socket, and a daemon that has stopped reading
// would park it here, before the caller has recorded the detach and before
// anything has cancelled: the attachment is ending either way, and the
// connection close that follows cancellation says so.
func (c *Client) forwardInput(ctx context.Context, stdin io.Writer, logger *slog.Logger) (detached bool) {
	filter := NewEscapeFilter(c.Escape)
	buf := make([]byte, 4096)
	r := uio.NewContextReader(ctx, c.Stdin)

	q := newInputQueue()
	// Closed on every path, including the ones that do not wait: it is what
	// the writer ends on, and a queue left open leaks it.
	defer q.close()
	go q.drainTo(stdin)

	// flush waits for what the session is still owed — the Enter before ~., a
	// held escape byte at EOF — under the same bound a single delivery used
	// to get, now applied to the queue. Past it the writer is abandoned where
	// it is parked, and the connection close that follows cancellation
	// releases it.
	flush := func() {
		q.close()
		q.waitDrained(inputFlushTimeout)
	}

	dropped := false
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out, detach := filter.Feed(buf[:n])
			if detach {
				// The bytes before the escape are the session's — the Enter
				// that preceded ~. — but a detach that has been detected
				// must reach the cancellation machinery whether or not the
				// session is still taking input, so they are queued and
				// waited for rather than written here. With the backlog
				// already full they are dropped like any other byte: the
				// policy does not change for the last read, and a session
				// that has taken nothing for a megabyte will not take this.
				q.append(out)
				flush()
				return true
			}
			if !q.append(out) && !dropped {
				// Dropped rather than waited on, deliberately: a session that
				// is not reading will never see these bytes, and blocking for
				// it is the defect this queue exists to fix — OpenSSH stops
				// reading the terminal here, which is no better. Once per
				// attachment, and bounded: this runs on the goroutine that
				// has to stay responsive.
				dropped = true
				logging.WarnWithin(logger, logging.LogBound, "dropping input: the session is not taking it",
					"backlog-bytes", inputBacklogLimit)
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			// Stdin ended: the terminal is gone. An escape byte held back
			// was real input; it is delivered under the same bound, for
			// the same reason.
			q.append(filter.Flush())
			flush()
			return true
		}
		if q.stopped() {
			// The session went away under us; Wait says how.
			return false
		}
	}
}

// inputQueue hands keystrokes from forwardInput's reader to its writer. The
// reader never blocks on it, which is the point; the writer parks in the
// session's Write for as long as the session is not taking input.
type inputQueue struct {
	mu     sync.Mutex
	more   *sync.Cond
	buf    []byte
	closed bool

	// done is closed by drainTo on its way out, which is the one thing that
	// says what was queued has been delivered — or that it never will be.
	done chan struct{}
}

func newInputQueue() *inputQueue {
	q := &inputQueue{done: make(chan struct{})}
	q.more = sync.NewCond(&q.mu)
	return q
}

// append queues p and reports whether it was taken. Beyond inputBacklogLimit
// it is not: the session has stopped reading and nothing queued for it is
// going anywhere.
func (q *inputQueue) append(p []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.buf)+len(p) > inputBacklogLimit {
		return false
	}
	q.buf = append(q.buf, p...)
	q.more.Broadcast()
	return true
}

// next blocks until there is something to write, or until the queue is closed
// and empty. What it returns is the caller's.
func (q *inputQueue) next() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.buf) == 0 && !q.closed {
		q.more.Wait()
	}
	if len(q.buf) == 0 {
		return nil, false
	}
	p := q.buf
	q.buf = nil
	return p, true
}

// close says no more keystrokes are coming. Idempotent: every way out of
// forwardInput reaches it, and two of them reach it twice.
func (q *inputQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.more.Broadcast()
}

// stopped reports that the writer has gone: either everything queued has been
// delivered and the queue is closed, or a write failed and nothing more will
// be delivered.
func (q *inputQueue) stopped() bool {
	select {
	case <-q.done:
		return true
	default:
		return false
	}
}

// waitDrained waits at most timeout for the writer to finish.
func (q *inputQueue) waitDrained(timeout time.Duration) {
	select {
	case <-q.done:
	case <-time.After(timeout):
	}
}

// drainTo writes what the reader queues into w until the queue is closed and
// empty, or a write fails.
func (q *inputQueue) drainTo(w io.Writer) {
	defer close(q.done)
	for {
		p, ok := q.next()
		if !ok {
			return
		}
		if _, err := w.Write(p); err != nil {
			// The session went away under us; the reader notices through
			// stopped and Wait says how.
			return
		}
	}
}

func resultFromWait(err error) Result {
	var exit *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case err == nil:
		return Result{Reason: Exited, Status: 0}
	case errors.As(err, &exit):
		return Result{Reason: Exited, Status: exit.ExitStatus()}
	case errors.As(err, &missing):
		return Result{Reason: Disconnected}
	default:
		// The connection went away under the session: no close message, no
		// status. What the daemon knows about it is in its log.
		return Result{Reason: Disconnected}
	}
}
