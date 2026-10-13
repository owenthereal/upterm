//go:build !windows

package internal

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	gssh "charm.land/ssh"
	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// withForceCommandStopGrace sets forceCommandStopGrace for the duration of t.
func withForceCommandStopGrace(t *testing.T, d time.Duration) {
	t.Helper()
	orig := forceCommandStopGrace
	forceCommandStopGrace = d
	t.Cleanup(func() { forceCommandStopGrace = orig })
}

// A forced command whose guest leaves is hung up, as a terminal going away
// would hang it up, not killed outright: a full-screen program -- Herdr, say,
// as a door -- gets to clean up after itself.
func TestAForcedCommandIsHungUpWhenItsGuestLeaves(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "hup")
	h := startHost(t, &Server{
		Command:      []string{"sh", "-c", "sleep 30"},
		ForceCommand: []string{"sh", "-c", `trap 'echo hup > "$0"; exit 0' HUP; printf READY; while :; do sleep 0.05; done`, marker},
	})
	_, out, sess := h.connectGuestSession(t)
	readUntil(t, out, "READY")

	require.NoError(t, sess.Close())

	require.Eventually(t, func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}, 5*time.Second, 20*time.Millisecond, "the forced command was never hung up")
}

// A guest whose input ends is still there to read what its forced command
// writes: `ssh -tt door < /dev/null`, or a script feeding the door from a
// file. OpenSSH ignores a client's EOF on a pty session and runs the command
// to the end. Taken as the guest leaving, it hung the command up before it
// had finished, or before it had started, and the guest got nothing.
func TestAForcedCommandOutlivesItsGuestsInput(t *testing.T) {
	for _, readOnly := range []bool{false, true} {
		t.Run("read-only="+strconv.FormatBool(readOnly), func(t *testing.T) {
			h := startHost(t, &Server{
				Command:      []string{"sh", "-c", "sleep 30"},
				ForceCommand: []string{"sh", "-c", `sleep 0.3; printf DONE; exit 7`},
				ReadOnly:     readOnly,
			})
			in, out, sess := h.connectGuestSession(t)
			exited := make(chan error, 1)
			go func() { exited <- sess.Wait() }()

			require.NoError(t, in.(io.Closer).Close())

			readUntil(t, out, "DONE")
			select {
			case err := <-exited:
				var exitErr *ssh.ExitError
				require.ErrorAs(t, err, &exitErr)
				assert.Equal(t, 7, exitErr.ExitStatus(), "the forced command's own status")
			case <-time.After(harnessTimeout):
				t.Fatal("the guest was never sent its forced command's status")
			}
		})
	}
}

// A guest whose input has ended and who then leaves still hangs its forced
// command up: the end of its input is not the guest leaving, but its
// channel closing is.
func TestAForcedCommandIsHungUpWhenItsGuestLeavesAfterItsInputEnds(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "hup")
	h := startHost(t, &Server{
		Command:      []string{"sh", "-c", "sleep 30"},
		ForceCommand: []string{"sh", "-c", `trap 'echo hup > "$0"; exit 0' HUP; printf READY; while :; do sleep 0.05; done`, marker},
	})
	in, out, sess := h.connectGuestSession(t)
	readUntil(t, out, "READY")
	require.NoError(t, in.(io.Closer).Close())

	// Still running with its input closed.
	time.Sleep(300 * time.Millisecond)
	_, err := os.Stat(marker)
	require.ErrorIs(t, err, os.ErrNotExist, "the forced command was hung up when its guest's input ended")

	require.NoError(t, sess.Close())

	require.Eventually(t, func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}, 5*time.Second, 20*time.Millisecond, "the forced command was never hung up")
}

// When the session ends, a forced command is hung up too, and what it writes
// on its way out -- a full-screen program putting the guest's terminal back
// -- reaches the guest, with its exit status. The session waits for that
// rather than ending under it: in production the tunnel closes behind the
// session, and the guest would be cut off first.
func TestSessionEndHangsUpAForcedCommandAndWaitsForIt(t *testing.T) {
	// Long enough that the hangup handler below finishes inside the first
	// step, so nothing escalates past it.
	withHangupGrace(t, 3*time.Second)
	withForceCommandStopGrace(t, 3*time.Second)
	h := startHost(t, &Server{
		Command:      []string{"sh", "-c", "sleep 30"},
		ForceCommand: []string{"sh", "-c", `trap 'sleep 1; printf HUNGUP; exit 3' HUP; printf READY; while :; do sleep 0.05; done`},
	})
	_, out, sess := h.connectGuestSession(t)
	readUntil(t, out, "READY")
	exited := make(chan error, 1)
	go func() { exited <- sess.Wait() }()

	h.stop(t)

	// Already sent by the time the session has ended, so it arrives at once
	// rather than a second later.
	start := time.Now()
	readUntil(t, out, "HUNGUP")
	assert.Less(t, time.Since(start), 500*time.Millisecond, "the session ended before its forced command had")
	select {
	case err := <-exited:
		var exitErr *ssh.ExitError
		require.ErrorAs(t, err, &exitErr)
		assert.Equal(t, 3, exitErr.ExitStatus(), "the forced command's own status")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("the guest was not sent its forced command's status before the session ended")
	}
}

// A forced command that ignores the hangup and SIGTERM is still gone once the
// teardown has run its course, and the session's end is bounded by it.
func TestAForcedCommandThatIgnoresTheHangupIsKilled(t *testing.T) {
	withHangupGrace(t, 100*time.Millisecond)
	withForceCommandStopGrace(t, 100*time.Millisecond)
	h := startHost(t, &Server{
		Command:      []string{"sh", "-c", "sleep 30"},
		ForceCommand: []string{"sh", "-c", `trap '' HUP TERM; printf 'PID=%s;' $$; while :; do sleep 0.05; done`},
	})
	_, out, _ := h.connectGuestSession(t)
	seen := readUntil(t, out, ";")
	pid, err := strconv.Atoi(strings.TrimSuffix(seen[strings.Index(seen, "PID=")+len("PID="):], ";"))
	require.NoError(t, err)

	took := h.stop(t)

	assert.Less(t, took, 3*time.Second)
	require.Eventually(t, func() bool {
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	}, 2*time.Second, 20*time.Millisecond, "the forced command outlived its teardown")
}

// A guest's terminal is put back when its forced command ends: whatever modes
// the command left set are undone, behind its last output and before the
// guest's exit status. A plain ssh client restores termios on the way out and
// nothing more, so without this a guest whose door was killed, or a program
// that simply exits without cleaning up, is left on the alternate screen with
// the mouse reporting clicks as input.
func TestAForcedCommandsGuestIsPutBack(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		stop    bool
		want    string
	}{
		{
			name:    "the command exits leaving modes set",
			command: `printf '\033[?1049h\033[?2004hREADY'; exit 0`,
			want:    "\x1b[?1049h\x1b[?2004hREADY" + "\x1b[?1049l\x1b[?2004l",
		},
		{
			// sleep has no hangup handler, so nothing of the command's own
			// puts anything back.
			name:    "the session ends under it",
			command: `printf '\033[?1049h\033[?2004hREADY'; exec sleep 30`,
			stop:    true,
			want:    "\x1b[?1049h\x1b[?2004hREADY" + "\x1b[?1049l\x1b[?2004l",
		},
		{
			name:    "the command put everything back itself",
			command: `printf '\033[?2004hREADY\033[?2004l'; exit 0`,
			want:    "\x1b[?2004hREADY\x1b[?2004l",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := startHost(t, &Server{
				Command:      []string{"sh", "-c", "sleep 30"},
				ForceCommand: []string{"sh", "-c", tc.command},
			})
			_, out, _ := h.connectGuestSession(t)
			seen := readUntil(t, out, "READY")
			if tc.stop {
				h.stop(t)
			}
			rest, err := io.ReadAll(out)
			require.NoError(t, err)
			assert.Equal(t, tc.want, seen+string(rest))
		})
	}
}

// The same for the guests of the shared command: when the session ends with
// the command still holding the terminal, each guest is put back -- also when
// its output stopped inside a sequence, which the guest's own query filter is
// still holding and the reset has to get past. The title never reaches the
// guest: its filter is still holding it, unfinished, when the reset's CAN
// arrives, and a held string a CAN ends is dropped, which is what the guest's
// terminal would have done with it anyway. The CAN and the reset still get
// through.
func TestSessionEndPutsItsGuestsBack(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "modes set",
			command: `printf '\033[?1049h\033[?2004hREADY'; exec sleep 30`,
			want:    "\x1b[?1049h\x1b[?2004hREADY" + "\x1b[?1049l\x1b[?2004l",
		},
		{
			name:    "output stopped inside a title",
			command: `printf '\033[?2004hREADY\033]0;a title'; exec sleep 30`,
			want:    "\x1b[?2004hREADY" + "\x18\x1b[?2004l",
		},
		{
			// Nothing but the cancel to send, and nothing after it.
			name:    "output stopped inside a title and nothing else left set",
			command: `printf 'READY\033]0;a title'; exec sleep 30`,
			want:    "READY" + "\x18",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := startHost(t, &Server{Command: []string{"sh", "-c", tc.command}})
			_, out, _ := h.connectGuestSession(t)
			seen := readUntil(t, out, "READY")

			h.stop(t)

			rest, err := io.ReadAll(out)
			require.NoError(t, err)
			assert.Equal(t, tc.want, seen+string(rest))
		})
	}
}

// The wait at the session's end is bounded. A guest that has stopped reading
// holds its forced command's output in a write to the channel that nothing
// but the connection's end releases, so a wait for its handler is a wait for
// that; the session ends at the bound instead.
func TestSessionEndStopsWaitingForAGuestThatStoppedReading(t *testing.T) {
	withHangupGrace(t, 100*time.Millisecond)
	withForceCommandStopGrace(t, 100*time.Millisecond)
	h := startHost(t, &Server{
		Command:      []string{"sh", "-c", "sleep 30"},
		ForceCommand: []string{"yes"},
	})
	_, out, _ := h.connectGuestSession(t, withDialDeadline(time.Minute))
	readUntil(t, out, "y\r\ny")
	// And then nothing more is read: the channel's window fills, and the
	// handler's copy blocks writing to it.
	time.Sleep(500 * time.Millisecond)

	took := h.stop(t)

	assert.Less(t, took, forceCommandStopBound(hangupGrace, forceCommandStopGrace)+2*time.Second)
}

// stallingGuest is a guest that took everything its forced command wrote and
// then stopped taking output, as one whose SSH window the last write filled
// would: the reset blocks until the transport is closed under it.
type stallingGuest struct {
	fakeGuestSession
	reset  string
	closed chan struct{}
	once   sync.Once
}

func (g *stallingGuest) Read([]byte) (int, error) {
	<-g.closed
	return 0, io.EOF
}

func (g *stallingGuest) Write(p []byte) (int, error) {
	if strings.Contains(string(p), g.reset) {
		<-g.closed
		return 0, io.EOF
	}
	return len(p), nil
}

func (g *stallingGuest) Close() error {
	g.once.Do(func() { close(g.closed) })
	return nil
}

// The reset sent after a forced command's last output is bounded, as the
// session's own last notice to a client is: a guest that has stopped taking
// output does not keep its handler, or the command's exit status, past the
// bound.
func TestAForcedCommandsResetIsBounded(t *testing.T) {
	guest := &stallingGuest{
		fakeGuestSession: fakeGuestSession{ctx: fakeGuestContext{sessionID: "test-session"}, winCh: make(chan gssh.Window)},
		reset:            "\x1b[?2004l",
		closed:           make(chan struct{}),
	}
	h := &sessionHandler{
		kind:              kindGuest,
		forceCommand:      []string{"sh", "-c", `printf '\033[?2004hDONE'; exit 0`},
		writers:           uio.NewMultiWriter(uio.DefaultReplayBytes),
		eventEmmiter:      emitter.New(1),
		terminals:         newTerminalWindows(discardLogger()),
		keepAliveDuration: time.Hour,
		ctx:               t.Context(),
		logger:            discardLogger(),
	}

	done := make(chan struct{})
	go func() { defer close(done); h.HandleSession(guest) }()

	select {
	case <-done:
	case <-time.After(guestFlushTimeout + 5*time.Second):
		_ = guest.Close()
		t.Fatal("the handler waited on a guest that stopped taking output")
	}
}

// A guest is told how the session ended before the tunnel closes behind it.
// The host closes its tunnel once ServeWithContext has returned, and that
// takes every guest's connection with it, along with whatever the relay has
// not yet passed on. A guest whose status had not reached it by then saw its
// channel close without one: a plain ssh guest exited 255, "remote command
// exited without exit status", and `upterm join` took it for a drop and waited
// for a host that was never coming back.
func TestAGuestIsToldTheSessionsStatusBeforeTheTunnelCloses(t *testing.T) {
	h := startHost(t, &Server{Command: readsALine("READY", 7)})
	relay := newRelayStandIn(t, h.addr)
	go func() {
		<-h.stopped
		relay.closeTunnel()
	}()

	viaRelay := *h
	viaRelay.addr = relay.ln.Addr().String()
	in, out, sess := viaRelay.connectGuestSession(t)
	readUntil(t, out, "READY")

	// From here the relay is slow to pass on what the host sends, so a host
	// that closes the tunnel as soon as its guests' handlers have written
	// their status still cuts it off.
	relay.latency.Store(int64(250 * time.Millisecond))
	_, err := io.WriteString(in, "go\n")
	require.NoError(t, err)
	go func() { _, _ = io.Copy(io.Discard, out) }()

	exited := make(chan error, 1)
	go func() { exited <- sess.Wait() }()
	select {
	case err := <-exited:
		var exitErr *ssh.ExitError
		require.ErrorAs(t, err, &exitErr, "the guest was never sent the session's status")
		assert.Equal(t, 7, exitErr.ExitStatus())
	case <-time.After(harnessTimeout):
		t.Fatal("the guest's session never ended")
	}
}

// A guest's handler waits for the close it sent with the status to be answered
// for no longer than guestFlushTimeout. A relay that never passes the status
// on, or a guest that never answers, does not keep the handler, and with it
// the guest's place in the session, for as long as its connection lasts.
func TestAGuestsHandlerStopsWaitingForAnAnswerThatNeverComes(t *testing.T) {
	srv := &Server{Command: readsALine("READY", 7)}
	h := startHost(t, srv)
	left := srv.EventEmitter.On(upterm.EventClientLeft)
	defer srv.EventEmitter.Off(upterm.EventClientLeft, left)
	relay := newRelayStandIn(t, h.addr)

	viaRelay := *h
	viaRelay.addr = relay.ln.Addr().String()
	in, out, _ := viaRelay.connectGuestSession(t)
	readUntil(t, out, "READY")

	// From here nothing the host sends reaches the guest, so nothing answers
	// its close; and the tunnel stays up, so nothing else ends the wait.
	relay.latency.Store(int64(24 * time.Hour))
	_, err := io.WriteString(in, "go\n")
	require.NoError(t, err)

	budget := guestFlushTimeout + 2*time.Second
	select {
	case <-left:
	case <-time.After(budget):
		t.Fatalf("the guest's handler was still waiting for its close to be answered after %s", budget)
	}
	select {
	case <-h.stopped:
	case <-time.After(budget):
		t.Fatalf("the session had not ended %s after its guest's handler", budget)
	}
}

// The session's end waits for its guests' handlers for no longer than
// guestFlushTimeout. One stuck sending its guest the status -- the guest's
// socket has stopped taking bytes, so the write never returns -- does not hold
// the session, or the tunnel behind it, open; the tunnel's close then releases
// the handler.
func TestSessionEndStopsWaitingForAGuestItCannotSendTheStatusTo(t *testing.T) {
	stall := &stallingListener{stalled: make(chan struct{})}
	srv := &Server{Command: readsALine("READY", 7)}
	h := startHostBehind(t, srv, stall.wrap)
	t.Cleanup(stall.closeConns)
	left := srv.EventEmitter.On(upterm.EventClientLeft)
	defer srv.EventEmitter.Off(upterm.EventClientLeft, left)

	in, out, _ := h.connectGuestSession(t)
	readUntil(t, out, "READY")

	stall.stall()
	_, err := io.WriteString(in, "go\n")
	require.NoError(t, err)

	// The command's last output can't reach the guest either, so its flush
	// runs to its own bound before the session's end begins.
	budget := outputDrainTimeout + 2*guestFlushTimeout + 2*time.Second
	select {
	case <-h.stopped:
	case <-time.After(budget):
		t.Fatalf("the session had not ended %s after its command, waiting on a guest it could not send the status to", budget)
	}

	stall.closeConns()
	select {
	case <-left:
	case <-time.After(harnessTimeout):
		t.Fatal("the guest's handler was not released by its connection's close")
	}
}

// Once the session's end has finished waiting for its guests, the door
// refuses a guest's shell rather than accepting it: nothing is left to wait
// for its status, and the tunnel is about to close on it. The guest's client
// sees its shell fail to start, not a session that ends without a status.
func TestTheDoorRefusesAShellOnceTheSessionHasStoppedWaitingForGuests(t *testing.T) {
	h := startHost(t, &Server{Command: readsALine("READY", 7)})
	late := h.guestClient(t)

	in, out, _ := h.connectGuestSession(t)
	readUntil(t, out, "READY")
	go func() { _, _ = io.Copy(io.Discard, out) }()
	_, err := io.WriteString(in, "go\n")
	require.NoError(t, err)
	select {
	case <-h.stopped:
	case <-time.After(harnessTimeout):
		t.Fatal("the session did not end")
	}

	// The late guest's connection outlived the door, as one does until the
	// tunnel closes; its session is opened only now.
	sess, err := late.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	assert.Error(t, sess.Shell(), "the door accepted a shell once nothing would wait for its status")
}

// stallingListener is the host's side of its guests' connections, with a
// switch that stops the host's writes getting through: a guest whose socket
// has stopped taking bytes, so that whatever the host writes to it blocks until
// the connection is closed.
type stallingListener struct {
	net.Listener
	stalled   chan struct{}
	stallOnce sync.Once

	mu    sync.Mutex
	conns []net.Conn
}

func (l *stallingListener) wrap(ln net.Listener) net.Listener {
	l.Listener = ln
	return l
}

func (l *stallingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	sc := &stallingConn{Conn: c, stalled: l.stalled, closed: make(chan struct{})}
	l.mu.Lock()
	l.conns = append(l.conns, sc)
	l.mu.Unlock()
	return sc, nil
}

func (l *stallingListener) stall() { l.stallOnce.Do(func() { close(l.stalled) }) }

func (l *stallingListener) closeConns() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		_ = c.Close()
	}
}

type stallingConn struct {
	net.Conn
	stalled   <-chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *stallingConn) Write(p []byte) (int, error) {
	select {
	case <-c.stalled:
		<-c.closed
		return 0, net.ErrClosed
	default:
		return c.Conn.Write(p)
	}
}

func (c *stallingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// relayStandIn carries guests to a host as the relay does over the host's
// tunnel: it takes what the host writes at once and passes it on after
// latency, and closing the tunnel drops whatever it has not passed on yet.
type relayStandIn struct {
	ln      net.Listener
	latency atomic.Int64 // nanoseconds, host to guest
	done    chan struct{}

	mu     sync.Mutex
	conns  []net.Conn
	closed bool
}

func newRelayStandIn(t *testing.T, hostAddr string) *relayStandIn {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	r := &relayStandIn{ln: ln, done: make(chan struct{})}
	t.Cleanup(r.closeTunnel)
	go func() {
		for {
			guest, err := ln.Accept()
			if err != nil {
				return
			}
			host, err := net.Dial("tcp", hostAddr)
			if err != nil {
				_ = guest.Close()
				continue
			}
			if !r.track(guest, host) {
				return
			}
			go func() { _, _ = io.Copy(host, guest) }()
			go r.relay(host, guest)
		}
	}()
	return r
}

// relay reads what the host sends as soon as it is sent, and delivers each
// piece to the guest once latency has passed since it arrived.
func (r *relayStandIn) relay(host, guest net.Conn) {
	type piece struct {
		b   []byte
		due time.Time
	}
	pieces := make(chan piece, 1024)
	go func() {
		defer func() { _ = guest.Close() }()
		for p := range pieces {
			select {
			case <-time.After(time.Until(p.due)):
			case <-r.done:
				return
			}
			if _, err := guest.Write(p.b); err != nil {
				return
			}
		}
	}()
	defer close(pieces)
	buf := make([]byte, 32*1024)
	for {
		n, err := host.Read(buf)
		if n > 0 {
			pieces <- piece{bytes.Clone(buf[:n]), time.Now().Add(time.Duration(r.latency.Load()))}
		}
		if err != nil {
			return
		}
	}
}

func (r *relayStandIn) track(conns ...net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		for _, c := range conns {
			_ = c.Close()
		}
		return false
	}
	r.conns = append(r.conns, conns...)
	return true
}

// closeTunnel is the host closing its tunnel: every guest's connection goes,
// and nothing still in transit is delivered.
func (r *relayStandIn) closeTunnel() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		close(r.done)
	}
	r.closed = true
	_ = r.ln.Close()
	for _, c := range r.conns {
		_ = c.Close()
	}
}
