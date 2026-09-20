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
func checkHelloNonce(rw io.ReadWriteCloser, nonce string) error {
	m, err := bootstrap.NewConn(oneByteAtATime{rw}).Recv()
	if err != nil {
		return fmt.Errorf("bootstrap hello: %w", err)
	}
	got := m.GetHello().GetNonce()
	if subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return errors.New("the process that connected to the bootstrap socket is not the session daemon this one started")
	}
	return nil
}

// oneByteAtATime is an io.ReadWriteCloser whose reads never return more than
// a byte, so a bufio.Reader over it buffers nothing beyond the message being
// decoded. Writes and Close are the underlying stream's own.
type oneByteAtATime struct{ io.ReadWriteCloser }

func (o oneByteAtATime) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return o.ReadWriteCloser.Read(p)
}
