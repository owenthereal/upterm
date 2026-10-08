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

	// dial reaches the socket; nil is a unix dial. Tests hand over a
	// connection they can block, to stand in for a daemon that has stopped
	// reading its socket.
	dial func(ctx context.Context, socket string) (net.Conn, error)
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
		return Result{}, fmt.Errorf("attach: %w", err)
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
		return Result{}, fmt.Errorf("attach: %w", err)
	}
	_ = raw.SetDeadline(time.Time{})
	client := ssh.NewClient(conn, chans, reqs)
	defer func() { _ = client.Close() }()

	res, err := (&Terminal{
		Stdin:   c.Stdin,
		Stdout:  c.Stdout,
		Pty:     c.Pty,
		Resizes: c.Resizes,
		Escape:  c.Escape,
		Suspend: c.Suspend,
		// Interactive: this client displays on a terminal and forwards its
		// keystrokes.
		DeclareInteractive: c.Pty != nil && c.Stdin != nil,
		Logger:             c.Logger,
	}).Run(ctx, client, setupBy)
	if err != nil {
		return Result{}, err
	}
	// One attachment is all a Client makes, so there is no next one to hand
	// Stdout over to: a write still in flight is left where it is, and a
	// restore the drain abandoned stays unwritten, as it always has.
	return Result{Reason: res.Reason, Status: res.Status}, nil
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
	// No "attach:" prefix: Run wraps the handshake's error with one already.
	return fmt.Errorf("%w (it presented %s)", ErrHostKeyMismatch, ssh.FingerprintSHA256(key))
}
