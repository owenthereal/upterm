package internal

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"sync"
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

// A guest whose shell the door accepted as the session ended is sent a status
// at once -- the fan-out has closed to it, or its forced command would only be
// hung up again -- and its handler then waits, as every guest's does, for that
// to be answered before it returns: the session's end waits for the handler,
// and the tunnel closes behind it. Returning straight after Exit let the
// tunnel close on a status still in transit, and an `upterm join` rejoining in
// that window waited for a host that was never coming back.
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

			// The door admits the shell before the handler runs.
			require.True(t, h.admitGuest(guest, "shell"))
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

// A guest turned away mid-session -- its forced command fails to start, or its
// output can't be attached -- is sent 1, and its handler waits for that to be
// answered as every guest's does: the session may end within the round trip,
// and its tunnel would then close on the status.
func TestAGuestTurnedAwayWaitsForItsCloseToBeAnswered(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(h *sessionHandler)
	}{
		{"forced command fails to start", func(h *sessionHandler) {
			h.forceCommand = []string{filepath.Join(t.TempDir(), "no-such-command")}
		}},
		{"output can't be attached", func(h *sessionHandler) {
			// A replay larger than a guest's buffer overflows it as it is
			// handed over.
			h.writers = uio.NewMultiWriter(2 * uio.DefaultGuestBufferSize)
			_, err := h.writers.Write(bytes.Repeat([]byte("x"), uio.DefaultGuestBufferSize+1))
			require.NoError(t, err)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guest := &exitRecordingGuest{
				fakeGuestSession: fakeGuestSession{ctx: fakeGuestContext{sessionID: "turned-away"}, winCh: make(chan gssh.Window), out: io.Discard},
				exited:           make(chan int, 1),
			}
			h := &sessionHandler{
				kind:              kindGuest,
				writers:           uio.NewMultiWriter(uio.DefaultReplayBytes),
				eventEmmiter:      emitter.New(1),
				terminals:         newTerminalWindows(discardLogger()),
				keepAliveDuration: time.Hour,
				ctx:               t.Context(),
				logger:            discardLogger(),
				forceCommands:     &guestHandlers{},
				sharedGuests:      &guestHandlers{},
			}
			tc.setup(h)
			require.True(t, h.admitGuest(guest, "shell"))
			done := make(chan struct{})
			go func() { defer close(done); h.HandleSession(guest) }()

			select {
			case code := <-guest.exited:
				assert.Equal(t, 1, code)
			case <-time.After(10 * time.Second):
				t.Fatal("the guest was never sent a status")
			}
			select {
			case <-done:
				t.Fatal("the handler returned before its close was answered")
			case <-time.After(200 * time.Millisecond):
			}
			assert.False(t, h.guestTracker().wait(0), "the session's end would not wait for the handler")

			close(guest.winCh) // the far side answers the close
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the handler did not return once its close was answered")
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

// admittingContext is a fakeGuestContext that keeps what is set on it, as a
// connection's context does, so that a test can see nothing is left there.
type admittingContext struct {
	fakeGuestContext

	mu     sync.Mutex
	values map[any]any
}

func (c *admittingContext) SetValue(key, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.values == nil {
		c.values = map[any]any{}
	}
	c.values[key] = value
}

func (c *admittingContext) Value(key any) any {
	c.mu.Lock()
	v, ok := c.values[key]
	c.mu.Unlock()
	if ok {
		return v
	}
	return c.fakeGuestContext.Value(key)
}

// The session's end waits for the guests' handlers that register while it
// waits, as well as those already there: a guest can reach the door while
// the session is ending -- the door stays open until the waits are done, so it
// is sent a status rather than refused -- and its status is no less cut off by
// the tunnel's close than an earlier guest's.
func TestGuestHandlersWaitCoversHandlersRegisteredWhileItWaits(t *testing.T) {
	var handlers guestHandlers
	first, ok := handlers.begin()
	require.True(t, ok)
	waited := make(chan bool, 1)
	go func() { waited <- handlers.wait(10 * time.Second) }()
	// Long enough for wait to be waiting on the first before the second
	// arrives.
	time.Sleep(100 * time.Millisecond)
	second, ok := handlers.begin()
	require.True(t, ok, "a handler registering while wait waits was refused")

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

// Once wait has returned, the set is sealed: a handler that would register
// after it is refused, since nothing would wait for it. The seal is part of
// finding none running, under the same lock, so nothing registers between
// the two; and a wait that gave up seals the set too.
func TestGuestHandlersRefuseARegistrationOnceWaitHasReturned(t *testing.T) {
	t.Run("found none running", func(t *testing.T) {
		var handlers guestHandlers
		finish, ok := handlers.begin()
		require.True(t, ok)
		finish()
		require.True(t, handlers.wait(time.Second))

		_, ok = handlers.begin()
		assert.False(t, ok, "a handler registered after wait found none running would go unwaited for")
		assert.False(t, handlers.admits())
	})
	t.Run("gave up", func(t *testing.T) {
		var handlers guestHandlers
		_, ok := handlers.begin()
		require.True(t, ok)
		require.False(t, handlers.wait(10*time.Millisecond))

		_, ok = handlers.begin()
		assert.False(t, ok, "a handler registered after wait gave up would go unwaited for")
	})
}

// The door admits a subsystem -- SFTP -- without registering it, and refuses
// one, as it does a shell, once the session's end has stopped waiting.
func TestTheDoorAdmitsASubsystemUntilTheSessionStopsWaiting(t *testing.T) {
	guest := &fakeGuestSession{ctx: fakeGuestContext{sessionID: "sftp"}}
	h := &sessionHandler{kind: kindGuest, sharedGuests: &guestHandlers{}}

	require.True(t, h.admitGuest(guest, "subsystem"))
	require.True(t, h.sharedGuests.wait(0), "a subsystem was registered for the session's end to wait on")

	assert.False(t, h.admitGuest(guest, "subsystem"))
	assert.False(t, h.admitGuest(guest, "shell"))
}

// The door forgets each admission once the session's handler has taken it. A
// guest can keep one connection open and open session after session on it, so
// an admission left behind -- or a key left in the connection's context, which
// charm's SetValue can only overwrite -- would grow for as long as the
// connection lasts.
func TestTheDoorForgetsEachAdmissionOnceItsHandlerHasTakenIt(t *testing.T) {
	// One connection's context, shared by every session on it, as charm's is.
	conn := &admittingContext{fakeGuestContext: fakeGuestContext{sessionID: "one-connection"}}
	h := &sessionHandler{
		kind:              kindGuest,
		writers:           uio.NewMultiWriter(uio.DefaultReplayBytes),
		eventEmmiter:      emitter.New(1),
		terminals:         newTerminalWindows(discardLogger()),
		keepAliveDuration: time.Hour,
		ctx:               t.Context(),
		logger:            discardLogger(),
		forceCommands:     &guestHandlers{},
		sharedGuests:      &guestHandlers{},
	}

	for range 50 {
		// Each session's input ends at once, so its handler runs to its end,
		// and its channel is already closed, so nothing is left to wait for.
		winCh := make(chan gssh.Window)
		close(winCh)
		guest := &fakeGuestSession{ctx: conn, winCh: winCh, out: io.Discard}
		require.True(t, h.admitGuest(guest, "shell"))
		done := make(chan struct{})
		go func() { defer close(done); h.HandleSession(guest) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("a session's handler did not return")
		}
	}

	conn.mu.Lock()
	left := len(conn.values)
	conn.mu.Unlock()
	assert.Zero(t, left, "the connection's context holds an entry for sessions that have ended")
	h.sharedGuests.mu.Lock()
	kept := len(h.sharedGuests.admitted)
	h.sharedGuests.mu.Unlock()
	assert.Zero(t, kept, "the door holds admissions its handlers have taken")
	assert.True(t, h.sharedGuests.wait(0), "a handler that ended is still registered")
}
