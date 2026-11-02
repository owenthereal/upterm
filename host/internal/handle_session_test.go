package internal

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	gssh "charm.land/ssh"
	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// A read-only guest that is not draining must not block its own handler. The
// handler waits on such a guest only under bounds -- for what was queued for
// it to be flushed, for its close to be answered -- and then returns.
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

	// Keep the guest stalled until the handler returns, then release the
	// test-owned writer even if an assertion fails.
	gate := make(chan struct{})
	defer close(gate)
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
// Close, Context, Exit, Pty, SendRequest, Stderr, and the Read and Write of
// the embedded channel. The rest is left nil on purpose, so a handler that
// grows a new dependency on the session panics here instead of passing
// quietly.
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
func (f *fakeGuestSession) Signals(chan<- gssh.Signal)  {}
func (f *fakeGuestSession) Close() error                { return nil }
func (f *fakeGuestSession) Exit(int) error              { return nil }
func (f *fakeGuestSession) Context() gssh.Context       { return f.ctx }

// Stderr is where a guest whose forced command can't start is told so. It
// writes where the output does, and reads as the input does.
func (f *fakeGuestSession) Stderr() io.ReadWriter { return f }

func (f *fakeGuestSession) Pty() (gssh.Pty, <-chan gssh.Window, bool) {
	return gssh.Pty{Term: "xterm"}, f.winCh, true
}

func (f *fakeGuestSession) SendRequest(string, bool, []byte) (bool, error) { return true, nil }

// fakeGuestContext supplies what HandleSession asks of a session's context,
// the session ID and a Done for the departure of a client with a terminal to
// wait on, with the Err a pacer asks first, and leaves the rest nil for the
// same reason. This client never goes: a nil Done is one that is never closed.
type fakeGuestContext struct {
	gssh.Context

	sessionID string
}

func (c fakeGuestContext) Done() <-chan struct{} { return nil }
func (c fakeGuestContext) Err() error            { return nil }

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
				privateCommands:   &guestHandlers{},
				sharedGuests:      &guestHandlers{},
			}
			waitedOn := h.sharedGuests
			if forced {
				h.forceCommand = []string{"true"}
				waitedOn = h.privateCommands
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
				privateCommands:   &guestHandlers{},
				sharedGuests:      &guestHandlers{},
			}
			tc.setup(h)
			require.True(t, h.admitGuest(guest, "shell"))
			done := make(chan struct{})
			go func() { defer close(done); h.HandleSession(guest) }()

			select {
			case code := <-guest.exited:
				want := 1
				if tc.name == "forced command fails to start" {
					want = 127
				}
				assert.Equal(t, want, code)
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

// A guest whose input ends at once -- `ssh -tt door < /dev/null`, or an
// x/crypto client with no Stdin -- is leaving, and its group ends moments
// after its attach. What was queued for it by then is still its own: the
// replay handed to its sink during the attach is delivered by the sink's
// goroutine afterwards, and a status sent ahead of that, with the sink closed
// behind it, left the guest a clean exit and nothing on its screen. The
// guest's terminal is slow on purpose here, so that the status always gets
// there first unless the handler waits for the sink. What the session goes on
// writing once the guest has left is not its own, and is not waited for. The
// wait is bounded as the session's own flush is, and by the session: a guest
// that has stopped reading is sent its status without what it never took, at
// the bound or as the session ends, whichever comes first -- the session's
// end waits for this handler under a bound of its own.
func TestALeavingGuestIsSentWhatWasQueuedForItBeforeItsStatus(t *testing.T) {
	const replay = "output from before this guest joined"
	for _, tc := range []struct {
		name string
		// delay is how long the guest's terminal takes to take a write, end
		// is when the session ends, if it does, and due is when the status
		// is sent; shown is what the terminal has taken by then.
		delay, end, due time.Duration
		shown           string
	}{
		{"slow terminal", 100 * time.Millisecond, 0, 100 * time.Millisecond, replay},
		{"terminal that has stopped reading", time.Hour, 0, guestFlushTimeout, ""},
		{"session ending as a guest that has stopped reading leaves", time.Hour, 300 * time.Millisecond, 300 * time.Millisecond, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				session, end := context.WithCancel(t.Context())
				defer end()
				if tc.end > 0 {
					time.AfterFunc(tc.end, end)
				}

				writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
				_, err := writers.Write([]byte(replay))
				require.NoError(t, err)

				terminal := &slowTerminal{delay: tc.delay, letGo: make(chan struct{})}
				guest := &shownAtExitGuest{
					fakeGuestSession: fakeGuestSession{ctx: fakeGuestContext{sessionID: "leaving"}, winCh: make(chan gssh.Window), out: terminal},
					terminal:         terminal,
					exited:           make(chan guestExit, 1),
				}
				// No primary, as in a detached session: the guest attaches
				// through the pacer, and the command's output passes it.
				pacer := newGuestPacer(t.Context(), writers, 0)
				h := &sessionHandler{
					kind:              kindGuest,
					writers:           writers,
					pacer:             pacer,
					eventEmmiter:      emitter.New(1),
					terminals:         newTerminalWindows(discardLogger()),
					keepAliveDuration: time.Hour,
					ctx:               session,
					logger:            discardLogger(),
				}
				done := make(chan struct{})
				go func() { defer close(done); h.HandleSession(guest) }()
				// Whatever fails first, the far side answers the close and the
				// terminal takes what it was handed, so that the handler and
				// the sink's goroutine have both returned before the bubble
				// ends.
				answer := sync.OnceFunc(func() { close(guest.winCh) })
				defer func() {
					answer()
					<-done
					close(terminal.letGo)
					synctest.Wait()
				}()

				// The guest's input has ended by now, and the command writes
				// on.
				synctest.Wait()
				_, err = pacer.Write([]byte("output after the guest left"))
				require.NoError(t, err)

				time.Sleep(tc.due - time.Nanosecond)
				synctest.Wait()
				select {
				case exit := <-guest.exited:
					t.Fatalf("the guest was sent its status %d before %v, having been shown %q", exit.code, tc.due, exit.shown)
				default:
				}

				time.Sleep(time.Nanosecond)
				synctest.Wait()
				select {
				case exit := <-guest.exited:
					assert.Equal(t, guestExit{code: 0, shown: tc.shown}, exit)
				default:
					t.Fatalf("the guest was not sent its status %v after it left", tc.due)
				}

				answer()
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("the handler did not return once its close was answered")
				}
			})
		})
	}
}

// slowTerminal takes delay to take each write, or until it is let go, and
// keeps what it took.
type slowTerminal struct {
	delay time.Duration
	letGo chan struct{}
	shown recordingWriter
}

func (s *slowTerminal) Write(p []byte) (int, error) {
	select {
	case <-time.After(s.delay):
	case <-s.letGo:
	}
	return s.shown.Write(p)
}

type guestExit struct {
	code  int
	shown string
}

// shownAtExitGuest is a fakeGuestSession that reports, with the status it is
// sent, what its terminal had taken by then.
type shownAtExitGuest struct {
	fakeGuestSession
	terminal *slowTerminal
	exited   chan guestExit
}

func (g *shownAtExitGuest) Exit(code int) error {
	g.exited <- guestExit{code: code, shown: string(g.terminal.shown.bytes())}
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
	looked := make(chan struct{}, 8)
	handlers := guestHandlers{onWait: func() { looked <- struct{}{} }}
	lookedOnce := func(what string) {
		t.Helper()
		select {
		case <-looked:
		case <-time.After(10 * time.Second):
			t.Fatalf("wait never %s", what)
		}
	}
	first, ok := handlers.begin()
	require.True(t, ok)
	waited := make(chan bool, 1)
	go func() { waited <- handlers.wait(10 * time.Second) }()
	lookedOnce("began waiting on the first handler")

	second, ok := handlers.begin()
	require.True(t, ok, "a handler registering while wait waits was refused")
	first()
	select {
	case <-waited:
		t.Fatal("wait returned with a handler that registered while it waited still running")
	case <-looked:
	case <-time.After(10 * time.Second):
		t.Fatal("wait neither returned nor waited on the second handler")
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

// A subsystem the door serves -- SFTP -- is admitted with the session's end
// as a shell is, and holds the session's end until its handler starts, but no
// longer: an SFTP session in progress is not waited for. Once the session's
// end has stopped waiting, a subsystem is refused, as a shell is; and one the
// door doesn't serve is refused without being admitted, since charm would
// refuse it after the admission and nothing would ever take that.
func TestTheDoorHoldsASubsystemOnlyUntilItsHandlerStarts(t *testing.T) {
	h := &sessionHandler{kind: kindGuest, sharedGuests: &guestHandlers{}}
	started, release := make(chan struct{}), make(chan struct{})
	sftp := h.startAdmitted(func(gssh.Session) {
		close(started)
		<-release
	})
	h.subsystems = map[string]gssh.SubsystemHandler{"sftp": sftp}
	asking := func(name string) *subsystemGuest {
		return &subsystemGuest{fakeGuestSession: fakeGuestSession{ctx: fakeGuestContext{sessionID: "sftp"}}, subsystem: name}
	}

	assert.False(t, h.admitGuest(asking("no-such-subsystem"), "subsystem"), "a subsystem the door doesn't serve was admitted")
	guest := asking("sftp")
	require.True(t, h.admitGuest(guest, "subsystem"))

	waited := make(chan bool, 1)
	go func() { waited <- h.sharedGuests.wait(10 * time.Second) }()
	select {
	case <-waited:
		t.Fatal("the session's end did not wait for an admitted subsystem to start")
	case <-time.After(200 * time.Millisecond):
	}

	go sftp(guest)
	<-started
	select {
	case ok := <-waited:
		assert.True(t, ok)
	case <-time.After(10 * time.Second):
		t.Fatal("the session's end went on waiting for a subsystem that had started")
	}
	assert.False(t, h.admitGuest(asking("sftp"), "subsystem"), "a subsystem was admitted after the session's end stopped waiting")
	assert.False(t, h.admitGuest(asking("sftp"), "shell"))
	close(release)

	h.sharedGuests.mu.Lock()
	defer h.sharedGuests.mu.Unlock()
	assert.Empty(t, h.sharedGuests.admitted, "the door holds an admission its subsystem has taken")
}

// subsystemGuest is a fakeGuestSession that asked for a subsystem.
type subsystemGuest struct {
	fakeGuestSession
	subsystem string
}

func (g *subsystemGuest) Subsystem() string { return g.subsystem }

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
		privateCommands:   &guestHandlers{},
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

// hostDoorNotice is the line the host door's client in the tests below asks to
// be shown, as upterm attach asks on a door.
const hostDoorNotice = "upterm: this is home's door; 'exit' closes it"

// noticeClient is a client of the host door that asks to be shown
// hostDoorNotice, as HandleSession sees one when driven directly: what
// fakeGuestSession stands in for, and what the host door asks of a client
// besides -- its key, its environment, its signals. What it is shown is
// recorded, and a test ends its connection, its input and its session.
type noticeClient struct {
	gssh.Session

	ctx   noticeContext
	key   gssh.PublicKey
	winCh chan gssh.Window
	shown recordingWriter

	input     chan struct{}
	inputOnce sync.Once

	// leave ends the client's connection, and end the session it is a
	// client of. done closes once its handler has returned.
	leave, end context.CancelFunc
	done       chan struct{}
}

// Read waits for the client's input to end. Until then the handler's input
// actor, which is what ends its group as a client goes, stays up.
func (c *noticeClient) Read([]byte) (int, error) { <-c.input; return 0, io.EOF }

func (c *noticeClient) Write(p []byte) (int, error) { return c.shown.Write(p) }
func (c *noticeClient) Signals(chan<- gssh.Signal)  {}
func (c *noticeClient) Close() error                { return nil }
func (c *noticeClient) Exit(int) error              { return nil }
func (c *noticeClient) Context() gssh.Context       { return c.ctx }
func (c *noticeClient) PublicKey() gssh.PublicKey   { return c.key }
func (c *noticeClient) Environ() []string {
	return []string{upterm.AttachInteractiveEnvVar + "=1", upterm.AttachNoticeEnvVar + "=" + hostDoorNotice}
}
func (c *noticeClient) Pty() (gssh.Pty, <-chan gssh.Window, bool) {
	return gssh.Pty{Term: "xterm", Window: gssh.Window{Width: 80, Height: 24}}, c.winCh, true
}
func (c *noticeClient) SendRequest(string, bool, []byte) (bool, error) { return true, nil }

func (c *noticeClient) closeInput() { c.inputOnce.Do(func() { close(c.input) }) }

// notices is how many times the client has been shown the notice.
func (c *noticeClient) notices() int {
	return strings.Count(string(c.shown.bytes()), hostDoorNotice)
}

// noticeContext is a client's connection as its session's context: the
// session ID HandleSession asks for, and otherwise conn, which ends as the
// connection does.
type noticeContext struct {
	gssh.Context
	conn      context.Context
	sessionID string
}

func (c noticeContext) Done() <-chan struct{} { return c.conn.Done() }
func (c noticeContext) Err() error            { return c.conn.Err() }
func (c noticeContext) ClientVersion() string { return "test" }
func (c noticeContext) Value(key any) any {
	if key == gssh.ContextKeySessionID {
		return c.sessionID
	}
	return c.conn.Value(key)
}

// answeringPTY is a command's pty whose command answers the door's redraw
// nudge by calling answer, as a full-screen program repaints on SIGWINCH.
type answeringPTY struct {
	*exitedPTY
	answer func()
}

func (p *answeringPTY) Redraw() error {
	p.answer()
	return p.exitedPTY.Redraw()
}

// serveNoticeClient starts a host-door handler with timing for a
// noticeClient, which the handler elects primary, so that what it is sent
// reaches it as it is written. The command answers the attach's redraw nudge
// by calling answer with what its output reaches the fan-out through; a nil
// answer is a command that doesn't repaint.
func serveNoticeClient(t *testing.T, timing serverTiming, answer func(command io.Writer)) *noticeClient {
	t.Helper()
	writers := uio.NewMultiWriter(uio.DefaultReplayBytes)
	// The shared command's output copy, as its Run writes through it: what
	// the handler hears the command say.
	output := &activityWriter{Writer: writers}
	conn, leave := context.WithCancel(context.Background())
	session, end := context.WithCancel(context.Background())
	c := &noticeClient{
		ctx:   noticeContext{conn: conn, sessionID: t.Name()},
		key:   testSigners(t)[0].PublicKey(),
		winCh: make(chan gssh.Window),
		input: make(chan struct{}),
		leave: leave,
		end:   end,
		done:  make(chan struct{}),
	}
	h := &sessionHandler{
		kind: kindHost,
		ptmx: &answeringPTY{exitedPTY: &exitedPTY{}, answer: func() {
			if answer != nil {
				answer(output)
			}
		}},
		writers:           writers,
		output:            output,
		eventEmmiter:      emitter.New(1),
		terminals:         newTerminalWindows(discardLogger()),
		hostClients:       &hostClients{logger: discardLogger()},
		keepAliveDuration: time.Hour,
		ctx:               session,
		logger:            discardLogger(),
		timing:            timing,
	}
	go func() { defer close(c.done); h.HandleSession(c) }()
	t.Cleanup(func() {
		c.closeInput()
		leave()
		end()
		select {
		case <-c.done:
		case <-time.After(10 * time.Second):
			t.Error("the client's handler did not return")
		}
	})
	return c
}

// A command that answers the nudge in more than one write has repainted once
// its writes stop: the notice waits until noticeQuiet has passed since the
// last of them, and comes after it.
func TestHostDoorShowsTheNoticeOnceTheRepaintHasStopped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const quiet = 150 * time.Millisecond
		// Each within quiet of the one before, as a program drawing its screen
		// in pieces writes them.
		pieces := []string{"\x1b[H\x1b[2J", "FIRST", "LAST"}
		const gap = quiet / 2
		c := serveNoticeClient(t, serverTiming{noticeQuiet: quiet, noticeCap: time.Hour}, func(command io.Writer) {
			go func() {
				for _, p := range pieces {
					time.Sleep(gap)
					_, _ = io.WriteString(command, p)
				}
			}()
		})
		last := time.Duration(len(pieces)) * gap
		time.Sleep(last + quiet - time.Nanosecond)
		synctest.Wait()
		require.Zero(t, c.notices(), "the notice before the repaint had been quiet for %s", quiet)
		time.Sleep(quiet)
		synctest.Wait()
		got := string(c.shown.bytes())
		require.Equal(t, 1, c.notices(), "shown %q", got)
		require.Less(t, strings.Index(got, "LAST"), strings.Index(got, hostDoorNotice), "the notice ahead of the repaint's last write")
	})
}

// A command that doesn't answer the nudge, as bash at its prompt doesn't, has
// the notice written once noticeCap has passed since the nudge, and only then.
func TestHostDoorShowsTheNoticeAtItsCapWhenNothingRepaints(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const limit = 300 * time.Millisecond
		c := serveNoticeClient(t, serverTiming{noticeCap: limit}, nil)
		time.Sleep(limit - time.Nanosecond)
		synctest.Wait()
		require.Zero(t, c.notices(), "the notice before its cap")
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		require.Equal(t, 1, c.notices(), "the notice at its cap")
		// And never again, however long the client stays, nor as it goes.
		time.Sleep(time.Hour)
		c.closeInput()
		synctest.Wait()
		select {
		case <-c.done:
		default:
			t.Fatal("the client's handler did not return once its input ended")
		}
		require.Equal(t, 1, c.notices(), "the notice more than once")
	})
}

// A client that has gone by the time its notice is due is written nothing,
// whichever way it goes, and its going waits for none of the notice's timers,
// nor does the session's end.
func TestHostDoorShowsNoNoticeToAClientThatHasGone(t *testing.T) {
	// Its connection ends first. Its handler goes on until its input ends,
	// which a write parked in the pty can hold off for a long time, and the
	// notice falls due meanwhile.
	t.Run("connection", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const limit = 300 * time.Millisecond
			c := serveNoticeClient(t, serverTiming{noticeCap: limit}, nil)
			time.Sleep(limit / 2)
			c.leave()
			time.Sleep(limit)
			synctest.Wait()
			select {
			case <-c.done:
				t.Fatal("the handler returned before the client's input ended, so the notice never fell due while it ran")
			default:
			}
			require.Zero(t, c.notices(), "a notice for a client whose connection had ended")
			c.closeInput()
			synctest.Wait()
			select {
			case <-c.done:
			default:
				t.Fatal("the client's handler did not return once its input ended")
			}
			require.Zero(t, c.notices(), "a notice for a client that had gone")
		})
	})
	// The session ends first. The client's handler returns at once, not when
	// its notice would have been due.
	t.Run("session", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c := serveNoticeClient(t, serverTiming{noticeCap: time.Hour}, nil)
			synctest.Wait()
			c.end()
			synctest.Wait()
			select {
			case <-c.done:
			default:
				t.Fatal("the session's end waited for the client's notice")
			}
			require.Zero(t, c.notices(), "a notice for a client of a session that had ended")
		})
	})
	// Its input ends first, and so does its handler, leaving nothing behind
	// that would write the notice later or wait for it. On the real clock, so
	// that whatever is left waiting is still there to be found.
	t.Run("input", func(t *testing.T) {
		running := goleak.IgnoreCurrent()
		nudged := make(chan struct{})
		c := serveNoticeClient(t, serverTiming{noticeCap: time.Hour}, func(io.Writer) { close(nudged) })
		select {
		case <-nudged:
		case <-time.After(10 * time.Second):
			t.Fatal("the client was never attached")
		}
		c.closeInput()
		select {
		case <-c.done:
		case <-time.After(10 * time.Second):
			t.Fatal("the client's handler did not return once its input ended")
		}
		// Its connection is still open, as one can be once a session on it
		// has ended, so nothing waiting on the connection has been let go.
		goleak.VerifyNone(t, running)
		require.Zero(t, c.notices(), "a notice for a client whose input had ended")
	})
}
