// Package bootstrap is the exchange between `upterm host` and the daemon it
// spawns, over the connection the daemon inherits. The child reports and
// asks; the parent shows, answers and, once the command has started, leaves.
package bootstrap

import (
	"bufio"
	"io"
	"sync"

	"github.com/owenthereal/upterm/host/api"
	"google.golang.org/protobuf/encoding/protodelim"
)

// maxMessageSize bounds one frame. The largest message is session_created,
// which carries the session's authorized keys; a megabyte is far past any
// real one and small enough that a corrupt length prefix cannot ask for the
// machine's memory.
const maxMessageSize = 1 << 20

// Conn frames Startup messages over a byte stream, one varint-delimited
// protobuf per message. Send is safe for concurrent use; Recv is for one
// goroutine.
type Conn struct {
	rw  io.ReadWriteCloser
	r   *bufio.Reader
	wmu sync.Mutex
}

func NewConn(rw io.ReadWriteCloser) *Conn {
	return &Conn{rw: rw, r: bufio.NewReader(rw)}
}

func (c *Conn) Send(m *api.Startup) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := protodelim.MarshalTo(c.rw, m)
	return err
}

func (c *Conn) Recv() (*api.Startup, error) {
	m := &api.Startup{}
	if err := (protodelim.UnmarshalOptions{MaxSize: maxMessageSize}).UnmarshalFrom(c.r, m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *Conn) Close() error { return c.rw.Close() }
