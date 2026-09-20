package command

import (
	"bytes"
	"io"
	"testing"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
	"github.com/owenthereal/upterm/host/api"
	"github.com/stretchr/testify/require"
)

// wire is a stream that hands over everything it holds in a single Read, the
// way a socket with two messages already in its receive buffer does. net.Pipe
// cannot stand in for it: it is unbuffered, so a Read there returns one
// Write's worth however large the caller's buffer is, and the over-read this
// file is about would never happen.
type wire struct {
	io.Reader
	io.Writer
}

func (wire) Close() error { return nil }

func newWire(t *testing.T, msgs ...*api.Startup) *wire {
	t.Helper()
	var buf bytes.Buffer
	c := bootstrap.NewConn(&wire{Writer: &buf})
	for _, m := range msgs {
		require.NoError(t, c.Send(m))
	}
	return &wire{Reader: bytes.NewReader(buf.Bytes()), Writer: io.Discard}
}

func helloMsg(nonce string) *api.Startup {
	return &api.Startup{Msg: &api.Startup_Hello{Hello: &api.Hello{Nonce: nonce}}}
}

// The message behind the hello has to survive being read past. On Windows the
// parent checks the nonce and then hands the same connection to
// bootstrap.NewParent, which starts its own reader: anything the hello check
// swallowed on the way through is a report the parent never sees — and the
// very next thing a daemon sends is claimed, the report carrying the session's
// name and paths.
func Test_checkHelloNonce_LeavesTheNextMessageOnTheWire(t *testing.T) {
	claimed := &api.Startup{Msg: &api.Startup_Claimed{Claimed: &api.Claimed{Name: "sepia-otter", Pid: 42}}}
	rw := newWire(t, helloMsg("n0nce"), claimed)

	require.NoError(t, checkHelloNonce(rw, "n0nce"))

	m, err := bootstrap.NewConn(rw).Recv()
	require.NoError(t, err, "the hello check read past its own message")
	require.Equal(t, "sepia-otter", m.GetClaimed().GetName())
}

func Test_checkHelloNonce_RefusesAnythingButItsOwnNonce(t *testing.T) {
	t.Run("wrong nonce", func(t *testing.T) {
		err := checkHelloNonce(newWire(t, helloMsg("theirs")), "ours")
		require.ErrorContains(t, err, "not the session daemon this one started")
	})
	t.Run("no nonce", func(t *testing.T) {
		err := checkHelloNonce(newWire(t, helloMsg("")), "ours")
		require.ErrorContains(t, err, "not the session daemon this one started")
	})
	t.Run("a prefix of the nonce", func(t *testing.T) {
		err := checkHelloNonce(newWire(t, helloMsg("our")), "ours")
		require.ErrorContains(t, err, "not the session daemon this one started")
	})
	t.Run("some other message", func(t *testing.T) {
		printMsg := &api.Startup{Msg: &api.Startup_Print{Print: &api.Print{Text: "ours"}}}
		err := checkHelloNonce(newWire(t, printMsg), "ours")
		require.ErrorContains(t, err, "not the session daemon this one started",
			"a message with no hello in it has no nonce, whatever else it carries")
	})
	t.Run("nothing at all", func(t *testing.T) {
		err := checkHelloNonce(newWire(t), "ours")
		require.ErrorContains(t, err, "bootstrap hello")
	})
}
