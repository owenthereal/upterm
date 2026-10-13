package internal

import (
	"context"
	"io"
	"testing"
	"time"

	gssh "charm.land/ssh"
	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/assert"
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
	writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
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
		kind:              kindGuest,
		readonly:          true,
		writers:           writers,
		eventEmmiter:      emitter.New(1),
		terminals:         newTerminalWindows(discardLogger()),
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

// A guest that reaches the door as the session ends is sent a status at once
// -- the fan-out has closed to it, or its forced command would only be hung up
// again -- and its handler then waits, as every guest's does, for that to be
// answered before it returns: the session's end waits for the handler, and the
// tunnel closes behind it. Returning straight after Exit let the tunnel close
// on a status still in transit, and an `upterm join` rejoining in that window
// waited for a host that was never coming back.
func TestALateGuestWaitsForItsCloseToBeAnswered(t *testing.T) {
	for _, forced := range []bool{false, true} {
		name := "shared command"
		if forced {
			name = "forced command"
		}
		t.Run(name, func(t *testing.T) {
			ending, cancel := context.WithCancel(t.Context())
			cancel()
			writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
			require.NoError(t, writers.Shutdown(t.Context()))

			guest := &exitRecordingGuest{
				fakeGuestSession: fakeGuestSession{ctx: fakeGuestContext{sessionID: "late"}, winCh: make(chan gssh.Window), out: io.Discard},
				exited:           make(chan int, 1),
			}
			h := &sessionHandler{
				kind:              kindGuest,
				writers:           writers,
				eventEmmiter:      emitter.New(1),
				terminals:         newTerminalWindows(discardLogger()),
				keepAliveDuration: time.Hour,
				ctx:               ending,
				logger:            discardLogger(),
				forceCommands:     &guestHandlers{},
				sharedGuests:      &guestHandlers{},
			}
			waitedOn := h.sharedGuests
			if forced {
				h.forceCommand = []string{"true"}
				waitedOn = h.forceCommands
			}

			done := make(chan struct{})
			go func() { defer close(done); h.HandleSession(guest) }()

			select {
			case code := <-guest.exited:
				assert.Equal(t, 0, code)
			case <-time.After(10 * time.Second):
				t.Fatal("the late guest was never sent a status")
			}
			select {
			case <-done:
				t.Fatal("the late guest's handler returned before its close was answered")
			case <-time.After(200 * time.Millisecond):
			}
			assert.False(t, waitedOn.wait(0), "the session's end would not wait for the late guest's handler")

			close(guest.winCh) // the far side answers the close
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the late guest's handler did not return once its close was answered")
			}
		})
	}
}

// exitRecordingGuest is a fakeGuestSession that reports the status it is
// sent.
type exitRecordingGuest struct {
	fakeGuestSession
	exited chan int
}

func (g *exitRecordingGuest) Exit(code int) error {
	g.exited <- code
	return nil
}

// The session's end waits for the guests' handlers that register while it
// waits, as well as those already there: a guest can reach the door while
// the session is ending -- the door stays open until the waits are done, so it
// is told rather than refused -- and its status is no less cut off by the
// tunnel's close than an earlier guest's.
func TestGuestHandlersWaitCoversHandlersRegisteredWhileItWaits(t *testing.T) {
	var handlers guestHandlers
	first := handlers.begin()
	waited := make(chan bool, 1)
	go func() { waited <- handlers.wait(10 * time.Second) }()
	// Long enough for wait to be waiting on the first before the second
	// arrives.
	time.Sleep(100 * time.Millisecond)
	second := handlers.begin()

	first()
	select {
	case <-waited:
		t.Fatal("wait returned with a handler that registered while it waited still running")
	case <-time.After(200 * time.Millisecond):
	}

	second()
	select {
	case ok := <-waited:
		assert.True(t, ok)
	case <-time.After(10 * time.Second):
		t.Fatal("wait did not return once every handler had finished")
	}
}
