package command

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
)

// Only the Windows transport calls into this file: Unix hands the daemon a
// socketpair and has nothing to authenticate, while a listener anything on
// the machine could in principle dial does. It carries no build tag anyway,
// because the trap it exists to avoid is a framing one, and a framing bug
// proved only by the Windows job is a framing bug found a round later.

// checkHelloNonce consumes the first message on rw and requires it to be a
// hello carrying nonce, leaving every byte after it unread.
//
// That last clause is the whole reason this is not two lines at the call
// site. The framing is bootstrap's, but the reader deliberately is not the
// one the exchange goes on to use: bootstrap.Conn reads through a bufio.
// Reader, and a buffered read of a twenty-byte hello takes whatever else has
// arrived on the socket with it — the daemon's claimed report is the very
// next thing it sends, and it would be decoded into a buffer that is then
// dropped on the floor. Reading a byte at a time cannot overshoot, so the
// connection handed back still has everything the child sent after the
// hello on it.
//
// The nonce is compared in constant time. The comparison leaks nothing an
// attacker could not already have — they would have to be able to open the
// socket to get this far — but a nonce checked with == is a habit, not a
// judgement call.
//
// The message's type is checked before its nonce, and that is not
// belt-and-braces: GetNonce() answers "" for every other message in the
// oneof, and ConstantTimeCompare of two empty slices returns 1. Without the
// type check this function would reject a print only because its caller
// happens to pass a non-empty nonce, which makes a security property of this
// file depend on a line in another one.
func checkHelloNonce(rw io.ReadWriteCloser, nonce string) error {
	m, err := bootstrap.NewConn(oneByteAtATime{rw}).Recv()
	if err != nil {
		return fmt.Errorf("bootstrap hello: %w", err)
	}
	if m.GetHello() == nil {
		return errNotOurDaemon
	}
	if subtle.ConstantTimeCompare([]byte(m.GetHello().GetNonce()), []byte(nonce)) != 1 {
		return errNotOurDaemon
	}
	return nil
}

// errNotOurDaemon says the same thing for a message that is not a hello and
// for a hello with the wrong nonce, because from here the fact is the same:
// whatever opened this connection did not come from the child this process
// started. Which of the two it was goes in the log the daemon writes, not in
// an error handed to whoever is on the far end.
var errNotOurDaemon = errors.New("the process that connected to the bootstrap socket is not the session daemon this one started")

// oneByteAtATime is an io.ReadWriteCloser whose reads never return more than
// a byte, so a bufio.Reader over it buffers nothing beyond the message being
// decoded. Writes and Close are the underlying stream's own.
//
// The cost is one read syscall per byte, which is nothing for the twenty-odd
// bytes of a hello and is bounded above by bootstrap's own frame limit: a
// length prefix over 1 MiB is refused before any of the body is read, so the
// worst case a same-user process that had already won the connect race could
// buy is a megabyte of one-byte reads inside the parent's read deadline.
type oneByteAtATime struct{ io.ReadWriteCloser }

func (o oneByteAtATime) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return o.ReadWriteCloser.Read(p)
}
