// Package attach is the local terminal's side of a session: an SSH client of
// the session's attach socket. upterm host, upterm attach and the functional
// tests all use it, so the local terminal is just another client in the code,
// not a special case beside it.
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
	"time"

	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

// dialTimeout bounds the connect and handshake. The socket is local; anything
// slower than this is a daemon that is not answering.
const dialTimeout = 10 * time.Second

// Client attaches a pair of streams to a running session.
type Client struct {
	Socket  string
	Stdin   io.Reader
	Stdout  io.Writer
	Pty     *Pty
	Resizes <-chan termsize.Size
	Escape  byte
	Logger  *slog.Logger

	// HostKeys is the daemon's public keys, from the session record: a record
	// from a current daemon carries exactly one entry, the session host key
	// it generated for that run; a record written by an older daemon may
	// carry several, which is why this is a slice. Run refuses to attach
	// without at least one: a client that accepted any key would hand its
	// terminal to whatever bound the socket.
	HostKeys []ssh.PublicKey

	// Suspend is the Terminal's: see Terminal.Suspend.
	Suspend func() (size termsize.Size, owned bool)

	// Status is the Terminal's: see Terminal.Status.
	Status func(ctx context.Context) []string

	// dial reaches the socket; nil is a unix dial. Tests hand over a
	// connection they can block, to stand in for a daemon that has stopped
	// reading its socket.
	dial func(ctx context.Context, socket string) (net.Conn, error)
}

// Seams for a test of the order the daemon's cause is read in; nil outside
// tests, and read by Run before the request loop starts. requestLoopHold runs
// on the loop's goroutine before it handles anything, and the loop goes on
// when it returns; sessionEndedHook runs in Run once the session's end is in
// hand, before the cause is taken.
var (
	requestLoopHold  func()
	sessionEndedHook func()
)

// Run attaches and returns when the attachment ends. An error means the client
// never attached; once attached, every ending is a Result.
func (c *Client) Run(ctx context.Context) (Result, error) {
	if c.Stdout == nil {
		return Result{}, errors.New("stdout is required")
	}
	if len(c.HostKeys) == 0 {
		return Result{}, errors.New("HostKeys is required")
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
		// Already "dial unix SOCKET: …".
		return Result{}, err
	}
	// One budget covers the handshake and every setup request after it — a
	// daemon that completed the handshake and then stopped answering would
	// otherwise hold NewSession, RequestPty or Shell forever. The socket's
	// deadline covers the handshake and is cleared after it; from there the
	// Terminal's setupBy, the same instant, covers the rest. Cancellation
	// during the handshake closes the socket the same way the Terminal closes
	// the client after it.
	setupBy := time.Now().Add(dialTimeout)
	_ = raw.SetDeadline(setupBy)
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
		// Already "ssh: handshake failed: …".
		return Result{}, err
	}
	_ = raw.SetDeadline(time.Time{})
	// The connection's global requests are read here, not by NewClient, which
	// would refuse every one of them: the daemon sends one that has to be
	// answered. NewClient is given a queue that is already closed, so its own
	// handler returns at once and this is the only reader of reqs.
	holdLoop, sessionEnded := requestLoopHold, sessionEndedHook
	ends := newEndReader(reqs)
	go ends.run(holdLoop)
	noRequests := make(chan *ssh.Request)
	close(noRequests)
	client := ssh.NewClient(conn, chans, noRequests)
	defer func() { _ = client.Close() }()

	res, err := (&Terminal{
		Stdin:   c.Stdin,
		Stdout:  c.Stdout,
		Pty:     c.Pty,
		Resizes: c.Resizes,
		Escape:  c.Escape,
		Suspend: c.Suspend,
		Status:  c.Status,
		// Interactive: this client displays on a terminal and forwards its
		// keystrokes.
		DeclareInteractive: c.Pty != nil && c.Stdin != nil,
		Logger:             c.Logger,
	}).Run(ctx, client, setupBy)
	if err != nil {
		return Result{}, err
	}
	if sessionEnded != nil {
		sessionEnded()
	}
	// A cause explains a status, so only an exit has one. A connection that
	// went away after the request but before any status is a disconnect, and
	// the cause the daemon sent is not what this client saw happen.
	var cause Cause
	if res.Reason == Exited {
		// The status can be here before the loop has handled the request that
		// came ahead of it: the daemon sends the status after waiting for the
		// reply only up to a bound. So the cause is taken only once every
		// request queued so far has been handled.
		ends.drain(endDrainTimeout)
		cause = ends.cause()
	}
	// One attachment is all a Client makes, so there is no next one to hand
	// Stdout over to: a write still in flight is left where it is, and a
	// restore the drain abandoned stays unwritten, as it always has.
	return Result{Reason: res.Reason, Status: res.Status, Cause: cause}, nil
}

// endDrainTimeout bounds the wait for the request loop to catch up once the
// session has ended. Handling a request is decoding it and writing a reply
// of a few bytes; this only matters when that write is parked on a daemon
// that has stopped reading its socket, which must not keep Run from
// returning with the status it already has.
const endDrainTimeout = time.Second

// endReader answers the connection's global requests and keeps the cause the
// daemon gives for ending the session.
type endReader struct {
	reqs <-chan *ssh.Request
	// asks is how drain gets the loop's attention, with a channel the loop
	// closes once it has caught up. Unbuffered: the loop takes one only
	// between requests, so a request being handled is finished first.
	asks chan chan struct{}
	done chan struct{} // closed when the loop has returned

	mu  sync.Mutex
	end *upterm.SessionEnd // the first one the daemon sent
}

func newEndReader(reqs <-chan *ssh.Request) *endReader {
	return &endReader{reqs: reqs, asks: make(chan chan struct{}), done: make(chan struct{})}
}

// run handles requests until the connection ends. hold, if not nil, is a
// test's: it runs before anything is handled.
func (e *endReader) run(hold func()) {
	defer close(e.done)
	if hold != nil {
		hold()
	}
	for {
		select {
		case req, ok := <-e.reqs:
			if !ok {
				return
			}
			e.handle(req)
		case caughtUp := <-e.asks:
			// What is queued when the ask is taken: everything that came in
			// before it was made is either handled already or in the queue,
			// and only this loop takes from the queue, so each of these
			// receives has a request waiting.
			for n := len(e.reqs); n > 0; n-- {
				if req, ok := <-e.reqs; ok {
					e.handle(req)
				}
			}
			close(caughtUp)
		}
	}
}

// handle keeps the daemon's session-end request and says so in its reply, and
// refuses everything else, as x/crypto's own handler would.
func (e *endReader) handle(req *ssh.Request) {
	if req.Type != upterm.SessionEndRequestType {
		_ = req.Reply(false, nil)
		return
	}
	var end sessionEnd
	if err := ssh.Unmarshal(req.Payload, &end); err != nil {
		// Not a payload this client knows, so the reply says it wasn't
		// read. The daemon still said why the session ended, so what is
		// kept is a session end with no cause this client knows, not
		// nothing: the status alone is not the whole story. Kept empty, not
		// as decoded, since a payload that fails part way leaves what came
		// before the failure behind.
		e.keep(upterm.SessionEnd{})
		_ = req.Reply(false, nil)
		return
	}
	e.keep(upterm.SessionEnd{Cause: end.Cause, Signal: end.Signal})
	_ = req.Reply(true, nil)
}

// keep holds end as the session's, unless the daemon sent one before it.
func (e *endReader) keep(end upterm.SessionEnd) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.end == nil {
		e.end = &end
	}
}

// sessionEnd is upterm.SessionEnd as this client reads it: the fields it
// knows, in the same order, and then whatever a later daemon has appended to
// them, which it ignores. x/crypto's Unmarshal refuses a payload with anything
// left over, so without Rest a field added later would cost this client the
// cause.
type sessionEnd struct {
	Cause  string
	Signal string
	Rest   []byte `ssh:"rest"`
}

// drain returns once the loop has handled every request that was queued when
// it was called, or the loop has ended -- the connection is gone and nothing
// more will be queued -- or bound has passed.
func (e *endReader) drain(bound time.Duration) {
	timeout := time.NewTimer(bound)
	defer timeout.Stop()
	caughtUp := make(chan struct{})
	select {
	case e.asks <- caughtUp:
	case <-e.done:
		return
	case <-timeout.C:
		return
	}
	select {
	case <-caughtUp:
	case <-e.done:
	case <-timeout.C:
	}
}

// cause is what the daemon said ended the session: CauseNone when it said
// nothing, and CauseUnknown when it gave a cause this client has no kind for,
// or one it couldn't read, which is never guessed at.
func (e *endReader) cause() Cause {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.end == nil {
		return Cause{}
	}
	switch e.end.Cause {
	case upterm.CauseExited:
		return Cause{Kind: CauseExited}
	case upterm.CauseStopped:
		return Cause{Kind: CauseStopped}
	case upterm.CauseSignaled:
		return Cause{Kind: CauseSignaled, Signal: e.end.Signal}
	case upterm.CauseCanceled:
		return Cause{Kind: CauseCanceled}
	case upterm.CauseJoinTimeout:
		return Cause{Kind: CauseJoinTimeout}
	}
	return Cause{Kind: CauseUnknown}
}

// ErrHostKeyMismatch is what Run's error wraps when the door presented a key
// that is not the daemon's. It is exported so a caller can tell this apart
// from every other reason an attachment did not happen: those are worth
// retrying, and this one is worth stopping for — whatever answered the socket
// is not the session, and the terminal must not be handed to it. x/crypto
// returns the callback's error as it is and wraps it with %w, so errors.Is
// finds it through the handshake's own message.
var ErrHostKeyMismatch = errors.New("host key is not the daemon's")

// checkHostKey accepts key only if it matches one of HostKeys. A current
// daemon presents one key, the session host key it generated for this run; a
// record from an older daemon may pin several, so every pinned key is tried
// in turn; ssh.FixedHostKey does the actual comparison, since it is both the
// right byte comparison and the sink CodeQL recognises as safe.
func (c *Client) checkHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	for _, want := range c.HostKeys {
		if ssh.FixedHostKey(want)(hostname, remote, key) == nil {
			return nil
		}
	}
	// No prefix: Run returns the handshake's error as it is, which x/crypto
	// already starts with "ssh: handshake failed:".
	return fmt.Errorf("%w (it presented %s)", ErrHostKeyMismatch, ssh.FingerprintSHA256(key))
}
