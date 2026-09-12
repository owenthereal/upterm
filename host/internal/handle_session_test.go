package internal

import (
	"io"
	"testing"
	"time"

	gssh "charm.land/ssh"
	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/require"
)

// A read-only guest that is not draining must not hold up its own handler.
//
// The banner is the handler's own write to the guest, and it has to travel the
// same path as everything else the guest receives. Written straight to the
// session it is a synchronous write to a peer that may not be reading: the
// handler blocks there before it has started a single actor, and never reaches
// the teardown that would release it. Through the sink it is queued behind the
// replay handed over during attach, which is also the only thing that orders
// the two — a direct write races the sink's goroutine and can arrive ahead of
// the replay, or between the packets of a chunk already in flight.
//
// The stalled guest is what makes this deterministic rather than a race: the
// blocking path blocks every time.
func TestHandleSessionDoesNotBlockOnAStalledReadOnlyGuest(t *testing.T) {
	writers := uio.NewMultiWriter(5)
	_, err := writers.Write([]byte("output from before this guest joined"))
	require.NoError(t, err)

	// Never released: the guest stays stalled for the whole test, so anything
	// written to it directly blocks forever.
	gate := make(chan struct{})
	guest := &fakeGuestSession{
		ctx:   fakeGuestContext{sessionID: "test-session"},
		winCh: make(chan gssh.Window),
		out:   &gatedWriter{gate: gate, rec: &recordingWriter{}},
	}

	h := &sessionHandler{
		readonly:          true,
		writers:           writers,
		eventEmmiter:      emitter.New(1),
		keepAliveDuration: time.Hour, // long enough never to fire
		ctx:               t.Context(),
		logger:            discardLogger(),
	}

	done := make(chan struct{})
	go func() { defer close(done); h.HandleSession(guest) }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("HandleSession blocked writing to a guest that was not draining")
	}
}

// fakeGuestSession is the whole of gssh.Session that HandleSession touches:
// Close, Context, Exit, Pty, SendRequest, and the Read and Write of the
// embedded channel. The rest is left nil on purpose, so a handler that grows a
// new dependency on the session panics here instead of passing quietly.
type fakeGuestSession struct {
	gssh.Session

	ctx   gssh.Context
	winCh chan gssh.Window
	out   io.Writer
}

// Read reports EOF at once, standing in for a guest that has closed its input.
// That is what returns the stdin actor and unwinds run.Group, so the handler
// reaches its end by the route a real departing guest takes.
func (f *fakeGuestSession) Read([]byte) (int, error) { return 0, io.EOF }

func (f *fakeGuestSession) Write(p []byte) (int, error) { return f.out.Write(p) }
func (f *fakeGuestSession) Close() error                { return nil }
func (f *fakeGuestSession) Exit(int) error              { return nil }
func (f *fakeGuestSession) Context() gssh.Context       { return f.ctx }

func (f *fakeGuestSession) Pty() (gssh.Pty, <-chan gssh.Window, bool) {
	return gssh.Pty{Term: "xterm"}, f.winCh, true
}

func (f *fakeGuestSession) SendRequest(string, bool, []byte) (bool, error) { return true, nil }

// fakeGuestContext supplies the one thing HandleSession asks of a session's
// context, the session ID, and leaves the rest nil for the same reason.
type fakeGuestContext struct {
	gssh.Context

	sessionID string
}

func (c fakeGuestContext) Value(key any) any {
	if key == gssh.ContextKeySessionID {
		return c.sessionID
	}
	return nil
}
