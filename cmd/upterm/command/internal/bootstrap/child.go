package bootstrap

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/owenthereal/upterm/host/api"
)

// ErrParentGone: the process that started this session closed its end of the
// channel, or never answered.
var ErrParentGone = errors.New("the process that started this session went away")

// NoAnswerError: the parent could not answer a read, and says why — no
// terminal for a secret, EOF on its stdin. Callers that wrap it in their own
// message (the host-key callback does) keep the reason.
type NoAnswerError struct{ Reason string }

func (e *NoAnswerError) Error() string { return "no answer from the terminal: " + e.Reason }

// Child is the daemon's half of the exchange.
//
// One goroutine reads the parent's messages for the Child's life. Replies go
// to whoever is waiting for one; the protocol is strictly request/reply, so
// at most one is ever outstanding. A read error — the parent closing its end,
// or dying — while the Child is armed calls onParentGone, once: that is
// parent-lifetime cancellation, and Disarm is what ends it.
type Child struct {
	conn         *Conn
	onParentGone func()
	replies      chan *api.Startup
	gone         chan struct{}
	armed        atomic.Bool
	started      atomic.Bool
	closeOnce    sync.Once
}

// NewChild starts reading rw. It is armed: the parent leaving is abandonment
// until Disarm is called.
func NewChild(rw io.ReadWriteCloser, onParentGone func()) *Child {
	c := &Child{
		conn:         NewConn(rw),
		onParentGone: onParentGone,
		replies:      make(chan *api.Startup, 4),
		gone:         make(chan struct{}),
	}
	c.armed.Store(true)
	go c.read()
	return c
}

func (c *Child) read() {
	defer close(c.gone)
	for {
		m, err := c.conn.Recv()
		if err != nil {
			if c.armed.Load() && c.onParentGone != nil {
				c.onParentGone()
			}
			return
		}
		select {
		case c.replies <- m:
		default:
			// A reply nobody asked for. The protocol has no such message;
			// dropping it keeps a misbehaving parent from parking the reader.
		}
	}
}

func (c *Child) await() (*api.Startup, error) {
	// A reply that already arrived wins even if the parent has also since
	// gone: read() puts it on c.replies before it can observe the close that
	// would close c.gone, but a plain two-case select doesn't know that and
	// could pick either ready case at random.
	select {
	case m := <-c.replies:
		return m, nil
	default:
	}
	select {
	case m := <-c.replies:
		return m, nil
	case <-c.gone:
		return nil, ErrParentGone
	}
}

func (c *Child) send(m *api.Startup) error {
	if err := c.conn.Send(m); err != nil {
		return ErrParentGone
	}
	return nil
}

// Print sends text for the parent's stderr. Best-effort: a parent that is
// gone will be noticed by the next thing that needs an answer.
func (c *Child) Print(text string) {
	_ = c.send(&api.Startup{Msg: &api.Startup_Print{Print: &api.Print{Text: text}}})
}

type printWriter struct{ c *Child }

func (w printWriter) Write(p []byte) (int, error) {
	w.c.Print(string(p))
	return len(p), nil
}

// Writer is an io.Writer whose every Write is a Print — what the host-key
// callback and the version warning write their prose to.
func (c *Child) Writer() io.Writer { return printWriter{c} }

func (c *Child) readLine(prompt string, secret bool) (string, error) {
	if err := c.send(&api.Startup{Msg: &api.Startup_Read{Read: &api.Read{Prompt: prompt, Secret: secret}}}); err != nil {
		return "", err
	}
	m, err := c.await()
	if err != nil {
		return "", err
	}
	switch v := m.Msg.(type) {
	case *api.Startup_Line:
		return v.Line.Text, nil
	case *api.Startup_ReadFailed:
		return "", &NoAnswerError{Reason: v.ReadFailed.Reason}
	}
	return "", fmt.Errorf("unexpected reply %T to a read", m.Msg)
}

// ReadSecret asks the parent's terminal for a line that must not echo.
func (c *Child) ReadSecret(prompt string) ([]byte, error) {
	s, err := c.readLine(prompt, true)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// lineReader turns reads into round trips, for the host-key callback, which
// reads its answer from an io.Reader with a bufio.Reader of its own. One
// round trip per line: the parent's line comes back with its newline
// restored, and bufio stops there.
type lineReader struct {
	c       *Child
	pending []byte
}

func (r *lineReader) Read(p []byte) (int, error) {
	if len(r.pending) == 0 {
		line, err := r.c.readLine("", false)
		if err != nil {
			return 0, err
		}
		r.pending = []byte(line + "\n")
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// Reader is the stdin the host-key callback reads its confirmation from.
func (c *Child) Reader() io.Reader { return &lineReader{c: c} }

func (c *Child) Claimed(m *api.Claimed) error {
	return c.send(&api.Startup{Msg: &api.Startup_Claimed{Claimed: m}})
}

// SessionCreated is gate 1 and 2 in one round trip: the parent shows the
// session and answers with the operator's decision.
func (c *Child) SessionCreated(sess *api.GetSessionResponse) (api.Accept_Decision, error) {
	if err := c.send(&api.Startup{Msg: &api.Startup_SessionCreated{SessionCreated: &api.SessionCreated{Session: sess}}}); err != nil {
		return 0, err
	}
	m, err := c.await()
	if err != nil {
		return 0, err
	}
	a, ok := m.Msg.(*api.Startup_Accept)
	if !ok {
		return 0, fmt.Errorf("unexpected reply %T to session_created", m.Msg)
	}
	return a.Accept.Decision, nil
}

func (c *Child) Listening(socket string, hostKeys []string) error {
	return c.send(&api.Startup{Msg: &api.Startup_Listening{Listening: &api.Listening{AttachSocket: socket, HostKeys: hostKeys}}})
}

// Disarm stops treating the parent's departure as abandonment. Call it the
// instant the command has started, before Started: a parent that exits the
// moment it is told the session is up must not be read as leaving it.
func (c *Child) Disarm() { c.armed.Store(false) }

// Started is gate 3. Disarm first.
//
// status is what the session's record says at this moment, and joinState the
// join timeout as the daemon holds it, both of which the parent reports
// rather than assuming: see the Started message in startup.proto.
func (c *Child) Started(sessionID, status string, joinState *api.JoinState) error {
	c.started.Store(true)
	return c.send(&api.Startup{Msg: &api.Startup_Started{Started: &api.Started{SessionId: sessionID, Status: status, JoinState: joinState}}})
}

// Failed reports that the session did not start. Nothing is sent after
// Started: the parent has gone by then, and a session that started and then
// ended is an outcome the record carries, not a startup failure.
func (c *Child) Failed(msg string, nameInUse, abandoned bool) {
	if c.started.Load() {
		return
	}
	_ = c.send(&api.Startup{Msg: &api.Startup_Failed{Failed: &api.Failed{Error: msg, NameInUse: nameInUse, Abandoned: abandoned}}})
}

// Close disarms and closes the connection. Disarming first: the close makes
// the reader return, and a return after Disarm is not abandonment.
func (c *Child) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.armed.Store(false)
		err = c.conn.Close()
	})
	return err
}
