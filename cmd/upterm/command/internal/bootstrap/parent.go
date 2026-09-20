package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/owenthereal/upterm/host/api"
)

// ErrDaemonGone: the daemon closed the channel before saying whether it
// started. Its log says why.
var ErrDaemonGone = errors.New("the session daemon exited before reporting whether it started")

// Handlers receives the child's reports. Each is called on Run's goroutine,
// between messages; SessionCreated blocks the exchange for as long as the
// operator takes, which is the point.
type Handlers struct {
	Claimed        func(*api.Claimed)
	SessionCreated func(*api.GetSessionResponse) api.Accept_Decision
	Listening      func(*api.Listening)
}

// Outcome is how the exchange ended: exactly one of the two is set.
type Outcome struct {
	Started *api.Started
	Failed  *api.Failed
}

// Parent is `upterm host`'s half of the exchange.
type Parent struct {
	conn       *Conn
	stdin      io.Reader
	stderr     io.Writer
	readSecret func(prompt string) ([]byte, error)
	closeOnce  sync.Once
}

// NewParent wraps the parent's end. stdin answers non-secret reads (nil:
// none can be answered); readSecret answers secret ones (nil: no terminal).
func NewParent(rw io.ReadWriteCloser, stdin io.Reader, stderr io.Writer, readSecret func(prompt string) ([]byte, error)) *Parent {
	return &Parent{conn: NewConn(rw), stdin: stdin, stderr: stderr, readSecret: readSecret}
}

// Run reads the child's messages until it reports started or failed. ctx
// ending closes the connection, which is what ends a Recv.
func (p *Parent) Run(ctx context.Context, h Handlers) (Outcome, error) {
	stop := context.AfterFunc(ctx, func() { _ = p.Close() })
	defer stop()
	for {
		m, err := p.conn.Recv()
		if err != nil {
			return Outcome{}, p.ended(ctx)
		}
		switch v := m.Msg.(type) {
		case *api.Startup_Print:
			_, _ = fmt.Fprint(p.stderr, v.Print.Text)
		case *api.Startup_Read:
			if err := p.answer(v.Read); err != nil {
				return Outcome{}, p.ended(ctx)
			}
		case *api.Startup_Claimed:
			if h.Claimed != nil {
				h.Claimed(v.Claimed)
			}
		case *api.Startup_SessionCreated:
			d := api.Accept_ACCEPTED
			if h.SessionCreated != nil {
				d = h.SessionCreated(v.SessionCreated.Session)
			}
			if err := p.conn.Send(&api.Startup{Msg: &api.Startup_Accept{Accept: &api.Accept{Decision: d}}}); err != nil {
				return Outcome{}, p.ended(ctx)
			}
		case *api.Startup_Listening:
			if h.Listening != nil {
				h.Listening(v.Listening)
			}
		case *api.Startup_Started:
			return Outcome{Started: v.Started}, nil
		case *api.Startup_Failed:
			return Outcome{Failed: v.Failed}, nil
		case *api.Startup_Hello:
			// The transport that needs it checks it before Run sees the
			// connection; here it is nothing.
		}
	}
}

// ended reports why Run's connection failed: ctx ending closes it (via the
// context.AfterFunc in Run), so a cancellation in flight when a Recv or Send
// fails is the reason, not a daemon that vanished on its own.
func (p *Parent) ended(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrDaemonGone
}

func (p *Parent) answer(r *api.Read) error {
	if r.Prompt != "" {
		_, _ = fmt.Fprint(p.stderr, r.Prompt)
	}
	var reply *api.Startup
	switch {
	case r.Secret && p.readSecret == nil:
		reply = readFailed("no terminal to read a secret from")
	case r.Secret:
		b, err := p.readSecret(r.Prompt)
		if err != nil {
			reply = readFailed(err.Error())
		} else {
			reply = line(string(b))
		}
	case p.stdin == nil:
		reply = readFailed("no input to read from")
	default:
		s, err := readLine(p.stdin)
		if err != nil {
			reply = readFailed("stdin: " + err.Error())
		} else {
			reply = line(s)
		}
	}
	return p.conn.Send(reply)
}

func line(s string) *api.Startup {
	return &api.Startup{Msg: &api.Startup_Line{Line: &api.Line{Text: s}}}
}

func readFailed(reason string) *api.Startup {
	return &api.Startup{Msg: &api.Startup_ReadFailed{ReadFailed: &api.ReadFailed{Reason: reason}}}
}

// readLine reads one line a byte at a time, so nothing past the newline is
// taken from a stream that another reader — the attach client — will read
// next. A final line without a newline still counts.
func readLine(r io.Reader) (string, error) {
	var buf []byte
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n == 1 {
			if b[0] == '\n' {
				return strings.TrimSuffix(string(buf), "\r"), nil
			}
			buf = append(buf, b[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				return strings.TrimSuffix(string(buf), "\r"), nil
			}
			return "", err
		}
	}
}

// Close closes the connection. Idempotent.
func (p *Parent) Close() error {
	var err error
	p.closeOnce.Do(func() { err = p.conn.Close() })
	return err
}
