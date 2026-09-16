package attach

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gssh "charm.land/ssh"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const testTimeout = 10 * time.Second

func shortTempDir(t *testing.T) string {
	t.Helper()
	root := "/tmp"
	if runtime.GOOS == "windows" {
		root = ""
	}
	dir, err := os.MkdirTemp(root, "up")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// runAsync runs c on a goroutine and hands back its Result. Run's error is
// reported through t rather than dropped: a zero Result is indistinguishable
// from Detached, so a test that discarded the error would pass on a setup
// failure. t.Errorf is safe from a goroutine; FailNow is not, hence Errorf.
func runAsync(t *testing.T, ctx context.Context, c *Client) <-chan Result {
	t.Helper()
	done := make(chan Result, 1)
	go func() {
		res, err := c.Run(ctx)
		if err != nil {
			t.Errorf("Run: %v", err)
		}
		done <- res
	}()
	return done
}

// fakeDoor is a charm ssh server on a unix socket whose handler is the test's.
// It accepts any public key, as the host door does.
type fakeDoor struct {
	socket string
}

func serveDoor(t *testing.T, handler func(gssh.Session)) *fakeDoor {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)

	socket := filepath.Join(shortTempDir(t), "a.sock")
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)

	srv := &gssh.Server{
		HostSigners:      []gssh.Signer{signer},
		Handler:          handler,
		PublicKeyHandler: func(gssh.Context, gssh.PublicKey) bool { return true },
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return &fakeDoor{socket: socket}
}

func TestClientRequestsAPtyWithTheGivenGeometryAndForwardsBothWays(t *testing.T) {
	gotPty := make(chan gssh.Pty, 1)
	door := serveDoor(t, func(s gssh.Session) {
		pty, _, ok := s.Pty()
		require.True(t, ok)
		gotPty <- pty
		// Echo one line back, then exit 3.
		buf := make([]byte, 64)
		n, _ := s.Read(buf)
		_, _ = s.Write(append([]byte("echo:"), buf[:n]...))
		_ = s.Exit(3)
	})

	var out bytes.Buffer
	// Held open after the line: EOF on Stdin is a detach, and a finite
	// reader would race the remote exit.
	pr, pw := io.Pipe()
	go func() { _, _ = pw.Write([]byte("hello\n")) }()
	defer func() { _ = pw.Close() }()
	c := &Client{
		Socket: door.socket, Stdin: pr, Stdout: &out,
		Pty: &Pty{Term: "xterm-256color", Size: termsize.Size{Cols: 132, Rows: 43}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	res, err := c.Run(ctx)
	require.NoError(t, err)
	require.Equal(t, Result{Reason: Exited, Status: 3}, res)

	pty := <-gotPty
	require.Equal(t, "xterm-256color", pty.Term)
	require.Equal(t, 132, pty.Window.Width)
	require.Equal(t, 43, pty.Window.Height)
	// charm's default session handler emulates a pty for a pty session and
	// rewrites LF to CRLF on the way out (session.go:145-149, pty.go:27-38),
	// unlike the daemon's raw session; the client forwards the wire bytes
	// verbatim, which is what this asserts.
	require.Equal(t, "echo:hello\r\n", out.String())
}

func TestClientWithoutPtyIsAViewer(t *testing.T) {
	door := serveDoor(t, func(s gssh.Session) {
		_, _, ok := s.Pty()
		require.False(t, ok, "no pty was requested")
		_, _ = io.WriteString(s, "output for a viewer")
		_ = s.Exit(0)
	})
	var out bytes.Buffer
	c := &Client{Socket: door.socket, Stdout: &out}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	res, err := c.Run(ctx)
	require.NoError(t, err)
	require.Equal(t, Result{Reason: Exited, Status: 0}, res)
	require.Equal(t, "output for a viewer", out.String())
}

func TestClientHoldsInputOpenWhenStdinIsNil(t *testing.T) {
	// The server reads input; a client with nil Stdin must not send EOF, or a
	// viewer would end the session it is watching. The handler exits only when
	// the test tells it to, after proving the read is still blocked.
	release := make(chan struct{})
	readReturned := make(chan struct{})
	door := serveDoor(t, func(s gssh.Session) {
		go func() {
			buf := make([]byte, 1)
			_, _ = s.Read(buf)
			close(readReturned)
		}()
		<-release
		_ = s.Exit(0)
	})
	c := &Client{Socket: door.socket, Stdout: io.Discard}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	done := runAsync(t, ctx, c)

	select {
	case <-readReturned:
		t.Fatal("the session saw EOF on its input; a nil Stdin must hold it open")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	require.Equal(t, Result{Reason: Exited}, <-done)
}

func TestClientEscapeDetaches(t *testing.T) {
	closed := make(chan struct{})
	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.Copy(io.Discard, s) // returns when the client's input ends
		close(closed)
		// No Exit: the client left, and the server may close without a status.
	})
	pr, pw := io.Pipe()
	var out bytes.Buffer
	c := &Client{Socket: door.socket, Stdin: pr, Stdout: &out, Escape: '~',
		Pty: &Pty{Term: "xterm", Size: termsize.Default}}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	done := runAsync(t, ctx, c)

	_, err := pw.Write([]byte("typed\r~."))
	require.NoError(t, err)
	select {
	case res := <-done:
		require.Equal(t, Result{Reason: Detached}, res)
	case <-time.After(testTimeout):
		t.Fatal("~. did not detach")
	}
	select {
	case <-closed:
	case <-time.After(testTimeout):
		t.Fatal("the session did not see the client leave")
	}
}

func TestClientStdinEOFDetaches(t *testing.T) {
	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.Copy(io.Discard, s)
	})
	c := &Client{Socket: door.socket, Stdin: bytes.NewReader(nil), Stdout: io.Discard}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	res, err := c.Run(ctx)
	require.NoError(t, err)
	require.Equal(t, Result{Reason: Detached}, res, "a terminal that has gone away is a detach, not a session error")
}

func TestClientReportsAConnectionClosedWithoutStatusAsDisconnected(t *testing.T) {
	door := serveDoor(t, func(s gssh.Session) {
		conn := s.Context().Value(gssh.ContextKeyConn).(*ssh.ServerConn)
		_ = conn.Close() // what the stall watchdog does
	})
	c := &Client{Socket: door.socket, Stdout: io.Discard}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	res, err := c.Run(ctx)
	require.NoError(t, err)
	require.Equal(t, Result{Reason: Disconnected}, res)
}

// Two details of the libraries shape this test. charm pushes the pty-req's own
// window into winCh before any window-change (session.go:373), so the handler
// forwards only the resize and skips that first value. And x/crypto fills the
// pixel fields from the cell count (w*8, h*8, session.go:243-251), so the
// assertion is on the cells rather than on the whole Window.
//
// ptyRead is a barrier, not decoration: charm writes sess.pty.Window on a
// window-change (session.go:412) with nothing synchronising it against the
// read in Pty() (session.go:222), so the resize is sent only once the handler
// has finished reading the pty.
func TestClientForwardsWindowChanges(t *testing.T) {
	got := make(chan gssh.Window, 4)
	ptyRead := make(chan struct{})
	door := serveDoor(t, func(s gssh.Session) {
		_, winCh, ok := s.Pty()
		require.True(t, ok)
		close(ptyRead)
		for w := range winCh {
			if w.Width != 100 {
				continue // the pty-req's own window, which charm delivers first
			}
			got <- w
			_ = s.Exit(0)
			return
		}
	})
	resizes := make(chan termsize.Size, 1)
	c := &Client{Socket: door.socket, Stdout: io.Discard,
		Pty: &Pty{Term: "xterm", Size: termsize.Default}, Resizes: resizes}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	done := runAsync(t, ctx, c)
	select {
	case <-ptyRead:
	case <-time.After(testTimeout):
		t.Fatal("the handler never read the pty")
	}
	resizes <- termsize.Size{Cols: 100, Rows: 30}
	select {
	case w := <-got:
		require.Equal(t, 100, w.Width)
		require.Equal(t, 30, w.Height)
	case <-time.After(testTimeout):
		t.Fatal("window change never arrived")
	}
	<-done
}

// A remote exit is a remote exit even while input is being forwarded: the
// input actor is unblocked by internal cleanup on every ending, and that must
// not be mistaken for the terminal going away.
func TestClientReportsARemoteExitWhileForwardingInput(t *testing.T) {
	door := serveDoor(t, func(s gssh.Session) {
		time.Sleep(100 * time.Millisecond)
		_ = s.Exit(5)
	})
	pr, _ := io.Pipe() // held open, never written: a terminal nobody types on
	c := &Client{Socket: door.socket, Stdin: pr, Stdout: io.Discard,
		Pty: &Pty{Term: "xterm", Size: termsize.Default}}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	res, err := c.Run(ctx)
	require.NoError(t, err)
	require.Equal(t, Result{Reason: Exited, Status: 5}, res)
}

// slowSink delivers every write after a pause: output is provably still in
// flight when the session ends.
type slowSink struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	delay time.Duration
}

func (s *slowSink) Write(p []byte) (int, error) {
	time.Sleep(s.delay)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *slowSink) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Len()
}

// Delivery into SSH is not delivery into stdout. Run must not return until
// what the session sent has reached Stdout, or an immediate-exit command's
// output is cut off by whatever the caller does next — exiting, usually.
func TestClientDrainsOutputBeforeReturning(t *testing.T) {
	const payload = 256 << 10
	door := serveDoor(t, func(s gssh.Session) {
		_, _ = s.Write(bytes.Repeat([]byte("x"), payload))
		_ = s.Exit(0)
	})
	sink := &slowSink{delay: 5 * time.Millisecond}
	c := &Client{Socket: door.socket, Stdout: sink}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	res, err := c.Run(ctx)
	require.NoError(t, err)
	require.Equal(t, Result{Reason: Exited}, res)
	require.Equal(t, payload, sink.Len(), "Run returned with output still undelivered to Stdout")
}

// blockedSink blocks in its first write until released and counts the writes
// it was asked for: a stopped terminal, and a record of what reached it.
type blockedSink struct {
	entered chan struct{} // closed when the first write is in progress
	release chan struct{}
	once    sync.Once

	mu     sync.Mutex
	writes int
}

func newBlockedSink() *blockedSink {
	return &blockedSink{entered: make(chan struct{}), release: make(chan struct{})}
}

func (b *blockedSink) Write(p []byte) (int, error) {
	b.mu.Lock()
	b.writes++
	b.mu.Unlock()
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return len(p), nil
}

func (b *blockedSink) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.writes
}

// A blocked Stdout must not keep Run from returning once the session has
// disconnected the client: the copy is abandoned, parked in its write. And
// abandoned means abandoned: when that write is finally released, nothing
// further is written — the bytes the closed channel still holds must not
// land in a terminal that has since been restored or reused.
//
// The door waits until the sink has entered its blocked write before
// disconnecting, because two channel writes can reach the sink as one.
func TestClientReturnsWhenDisconnectedEvenIfStdoutIsBlocked(t *testing.T) {
	orig := outputDrainTimeout
	outputDrainTimeout = 200 * time.Millisecond
	t.Cleanup(func() { outputDrainTimeout = orig })

	sink := newBlockedSink()
	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, "first")
		<-sink.entered
		_, _ = io.WriteString(s, "second, buffered behind the blocked write")
		time.Sleep(100 * time.Millisecond)
		conn := s.Context().Value(gssh.ContextKeyConn).(*ssh.ServerConn)
		_ = conn.Close()
	})
	c := &Client{Socket: door.socket, Stdout: sink}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	done := runAsync(t, ctx, c)
	select {
	case res := <-done:
		require.Equal(t, Result{Reason: Disconnected}, res)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return while Stdout was blocked")
	}

	close(sink.release)
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, 1, sink.count(), "an abandoned copy must not resume writing once its blocked write is released")
}

// Stdout going away — EPIPE from a pipe whose reader left — is this terminal
// detaching, and with a quiet command nothing else would ever move.
func TestClientTreatsAStdoutWriteFailureAsADetach(t *testing.T) {
	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, "output")
		_, _ = io.Copy(io.Discard, s) // quiet forever; leaves only when the client does
	})
	pr, pw := io.Pipe()
	require.NoError(t, pr.Close()) // the reader is gone: every write fails
	c := &Client{Socket: door.socket, Stdout: pw}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	res, err := c.Run(ctx)
	require.NoError(t, err)
	require.Equal(t, Result{Reason: Detached}, res)
}

// shortSink accepts every write and reports one byte fewer: the failure
// io.Copy calls ErrShortWrite, which loses output silently if it is not one.
type shortSink struct{}

func (shortSink) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestClientTreatsAShortWriteToStdoutAsADetach(t *testing.T) {
	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, "output")
		_, _ = io.Copy(io.Discard, s)
	})
	c := &Client{Socket: door.socket, Stdout: shortSink{}}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	res, err := c.Run(ctx)
	require.NoError(t, err)
	require.Equal(t, Result{Reason: Detached}, res, "a short write is a failed write")
}

// blockableConn is a net.Conn whose writes block, once told to, until the
// connection is closed: a daemon that has stopped reading its socket, as
// seen from this side. Reads pass through so the session stays alive.
// entered is closed when the first write parks, so a test can know it did.
//
// fail is the other failure mode: a socket that is simply gone, whose writes
// return at once instead of parking. entered is closed for that one too.
type blockableConn struct {
	net.Conn
	block   chan struct{} // closed to make writes block
	fail    chan struct{} // closed to make writes fail immediately
	closed  chan struct{}
	entered chan struct{}
	once    sync.Once
	parked  sync.Once
}

func newBlockableConn() *blockableConn {
	return &blockableConn{block: make(chan struct{}), fail: make(chan struct{}), closed: make(chan struct{}), entered: make(chan struct{})}
}

func (b *blockableConn) Write(p []byte) (int, error) {
	select {
	case <-b.fail:
		b.parked.Do(func() { close(b.entered) })
		return 0, net.ErrClosed
	default:
	}
	select {
	case <-b.block:
		b.parked.Do(func() { close(b.entered) })
		<-b.closed
		return 0, net.ErrClosed
	default:
		return b.Conn.Write(p)
	}
}

// dialThrough is the dial hook that routes the client through b.
func (b *blockableConn) dialThrough(ctx context.Context, socket string) (net.Conn, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	b.Conn = raw
	return b, nil
}

func (b *blockableConn) Close() error {
	b.once.Do(func() { close(b.closed) })
	return b.Conn.Close()
}

// failingSink fails its first write and, in the same breath, makes the
// transport block: from here on nothing the client writes to the socket
// completes. Doing both in one place is what makes the order deterministic
// — the window adjust the channel sends when the output was read has
// already gone, and the very next packet, the interrupt's close, parks.
type failingSink struct {
	conn *blockableConn
	once sync.Once
}

func (f *failingSink) Write(p []byte) (int, error) {
	f.once.Do(func() { close(f.conn.block) })
	return 0, io.ErrClosedPipe
}

// An internally triggered detach — here, Stdout failing — must not wait on
// the transport. run.Group runs interrupts one after another, and a channel
// close is a packet written to the socket: with a daemon that has stopped
// reading, an interrupt that closed the session before cancelling would
// park, and the connection close that cancellation triggers would never
// come. The external-cancellation tests cannot catch this: there the context
// is already done when the interrupts run.
func TestClientInternalDetachDoesNotWaitOnABlockedTransport(t *testing.T) {
	door := serveDoor(t, func(s gssh.Session) {
		_, _ = io.WriteString(s, "output")
		_, _ = io.Copy(io.Discard, s)
	})
	conn := newBlockableConn()
	c := &Client{Socket: door.socket, Stdout: &failingSink{conn: conn}, dial: conn.dialThrough}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	done := runAsync(t, ctx, c)

	select {
	case res := <-done:
		require.Equal(t, Result{Reason: Detached}, res)
	case <-time.After(5 * time.Second):
		t.Fatal("an internal detach waited on a transport the daemon had stopped reading")
	}
}

// blockingHandler is a slog.Handler whose Handle never returns until
// released: a log file on a wedged filesystem, or a console that stopped.
// entered is closed the first time Handle is called, so a test can assert
// the line was attempted and not merely that nothing waited for it, and
// calls counts them, for a line that must be logged once however often the
// thing it describes happens.
type blockingHandler struct {
	release chan struct{}
	entered chan struct{}
	once    *sync.Once
	calls   *atomic.Int64
}

func newBlockingHandler(release chan struct{}) blockingHandler {
	return blockingHandler{release: release, entered: make(chan struct{}), once: &sync.Once{}, calls: &atomic.Int64{}}
}

func (h blockingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h blockingHandler) Handle(context.Context, slog.Record) error {
	h.calls.Add(1)
	h.once.Do(func() { close(h.entered) })
	<-h.release
	return nil
}

func (h blockingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h blockingHandler) WithGroup(string) slog.Handler      { return h }

func (h blockingHandler) count() int64 { return h.calls.Load() }

// sshWindow is x/crypto's channelWindowSize — 64 packets of 32 KiB — which
// is what a peer that never reads its input lets the client write before
// every further write parks in remoteWin.reserve, with no socket involved.
const sshWindow = 2 << 20

// A detected detach must not wait on an input write. Feed can return both
// the bytes before the escape and the detach itself — "\r~." in one read —
// and EOF can leave a held escape byte to flush; either write, on an
// exhausted window, never returns, and a detach that waited for it would
// never reach the cancellation that releases it.
func TestClientDetachIsNotHeldByAnInputWriteOnAnExhaustedWindow(t *testing.T) {
	orig := inputFlushTimeout
	inputFlushTimeout = 200 * time.Millisecond
	t.Cleanup(func() { inputFlushTimeout = orig })

	for _, tc := range []struct {
		name       string
		filler     int    // written first, all of it accepted
		tail       string // then this, whose delivery must not be waited on
		closeStdin bool
	}{
		// The window exactly full, then Enter and the escape in one read:
		// the Enter is the write that parks.
		{name: "escape after a newline", filler: sshWindow, tail: "\r~."},
		// One byte short of full, then Enter (the last byte the window
		// takes) and a lone escape byte held back; EOF flushes it into a
		// full window.
		{name: "EOF with a held escape byte", filler: sshWindow - 1, tail: "\r~", closeStdin: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			door := serveDoor(t, func(s gssh.Session) { select {} }) // never reads its input
			pr, pw := io.Pipe()
			c := &Client{Socket: door.socket, Stdin: pr, Stdout: io.Discard, Escape: '~'}
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			done := runAsync(t, ctx, c)

			_, err := pw.Write(bytes.Repeat([]byte("k"), tc.filler))
			require.NoError(t, err)
			_, err = pw.Write([]byte(tc.tail))
			require.NoError(t, err)
			if tc.closeStdin {
				require.NoError(t, pw.Close())
			}

			select {
			case res := <-done:
				require.Equal(t, Result{Reason: Detached}, res)
			case <-time.After(5 * time.Second):
				t.Fatal("the detach waited on an input write the session will never take")
			}
		})
	}
}

// The same detach, typed the ordinary way: Enter, and then ~. as the next
// keystrokes. The test above hands the filter "\r~." in one read, so one Feed
// sees the whole sequence; here the Enter is delivered first and parks on the
// exhausted window, and a client that read and wrote on one goroutine would
// never read the ~. that follows it.
//
// The keystrokes are typed from a goroutine because the pipe write is itself
// what parks: with the reader held inside an input write, nothing takes the
// Enter off the pipe, and a test that typed it inline would hang here instead
// of failing at the bound below.
func TestClientEscapeDetachesWhileAnInputWriteIsParked(t *testing.T) {
	door := serveDoor(t, func(s gssh.Session) { select {} }) // never reads its input
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	c := &Client{Socket: door.socket, Stdin: pr, Stdout: io.Discard, Escape: '~'}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	done := runAsync(t, ctx, c)

	_, err := pw.Write(bytes.Repeat([]byte("k"), sshWindow))
	require.NoError(t, err)
	go func() {
		if _, err := pw.Write([]byte("\r")); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
		_, _ = pw.Write([]byte("~."))
	}()

	select {
	case res := <-done:
		require.Equal(t, Result{Reason: Detached}, res)
	case <-time.After(5 * time.Second):
		t.Fatal("~. typed after an Enter the session never took did not detach")
	}
}

// Escape recognition lives in what has been read, so reading must go on while
// delivery is parked. Past the window every keystroke is queued rather than
// written, and the terminal is read at the speed it is typed at.
func TestClientKeepsReadingWhileDeliveryIsParked(t *testing.T) {
	door := serveDoor(t, func(s gssh.Session) { select {} }) // never reads its input
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	c := &Client{Socket: door.socket, Stdin: pr, Stdout: io.Discard, Escape: '~'}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	done := runAsync(t, ctx, c)

	_, err := pw.Write(bytes.Repeat([]byte("k"), sshWindow))
	require.NoError(t, err)

	// 16 KiB past the window, a kilobyte at a time. Every one of these has to
	// complete, and a pipe write completes only when something reads it.
	const pieces = 16
	typed := make(chan struct{}, pieces)
	go func() {
		for range pieces {
			if _, err := pw.Write(bytes.Repeat([]byte("k"), 1<<10)); err != nil {
				return
			}
			typed <- struct{}{}
		}
	}()
	deadline := time.After(5 * time.Second)
	for i := range pieces {
		select {
		case <-typed:
		case <-deadline:
			t.Fatalf("the client stopped reading its terminal %d KiB past the window", i)
		}
	}

	go func() {
		if _, err := pw.Write([]byte("\r")); err != nil {
			return
		}
		_, _ = pw.Write([]byte("~."))
	}()
	select {
	case res := <-done:
		require.Equal(t, Result{Reason: Detached}, res)
	case <-time.After(5 * time.Second):
		t.Fatal("~. did not detach behind a parked delivery")
	}
}

// recordingDoor collects everything its session reads, so a test can say what
// the session was actually given, and says when its handler started.
type recordingDoor struct {
	started chan struct{}

	mu  sync.Mutex
	got []byte
}

func newRecordingDoor() *recordingDoor {
	return &recordingDoor{started: make(chan struct{})}
}

func (d *recordingDoor) handle(s gssh.Session) {
	close(d.started)
	buf := make([]byte, 64)
	for {
		n, err := s.Read(buf)
		if n > 0 {
			d.mu.Lock()
			d.got = append(d.got, buf[:n]...)
			d.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (d *recordingDoor) taken() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return string(d.got)
}

// slowConn holds each write for delay once armed: a socket whose buffer is
// full for the moment, which is the ordinary reason a delivery is still in
// flight. Nothing is refused and nothing is lost — unless the connection is
// closed under it, which is what makes it the right stand-in here.
type slowConn struct {
	net.Conn
	armed atomic.Bool
	delay time.Duration
}

func (s *slowConn) Write(p []byte) (int, error) {
	if s.armed.Load() {
		time.Sleep(s.delay)
	}
	return s.Conn.Write(p)
}

func (s *slowConn) dialThrough(ctx context.Context, socket string) (net.Conn, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	s.Conn = raw
	return s, nil
}

// A detach owes the session what was typed before the escape — the Enter that
// ends the line ~. is typed on — and delivery is the writer's now, not the
// reader's. The wait on the way out is what hands it over: without it the
// reader returns, the cancellation behind it closes the connection, and the
// last thing the terminal typed is lost.
//
// The socket is slowed from the moment the shell is up, so that the Enter is
// provably still in flight when the escape is recognised. At full speed the
// writer delivers it in the gap between two keystrokes and the wait covers
// nothing — which is exactly the state a real session is not in when this
// matters.
func TestClientDetachDeliversTheBytesItOwes(t *testing.T) {
	door := newRecordingDoor()
	d := serveDoor(t, door.handle)
	conn := &slowConn{delay: 200 * time.Millisecond}
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	c := &Client{Socket: d.socket, Stdin: pr, Stdout: io.Discard, Escape: '~',
		dial: conn.dialThrough}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	done := runAsync(t, ctx, c)

	select {
	case <-door.started:
	case <-time.After(testTimeout):
		t.Fatal("the shell never started")
	}
	conn.armed.Store(true)

	_, err := pw.Write([]byte("x\r"))
	require.NoError(t, err)
	_, err = pw.Write([]byte("~."))
	require.NoError(t, err)

	select {
	case res := <-done:
		require.Equal(t, Result{Reason: Detached}, res)
	case <-time.After(5 * time.Second):
		t.Fatal("~. did not detach")
	}

	// Handed over before Run returned; the door still has to read it off the
	// channel, which is all this window is for.
	deadline := time.Now().Add(2 * time.Second)
	for door.taken() != "x\r" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.Equal(t, "x\r", door.taken(), "the detach left behind what the session was owed")
}

// Reading without bound would be its own defect. Past inputBacklogLimit the
// session is not taking input and the keystrokes are dropped — with one
// bounded warning, however many reads are dropped — while the escape is still
// recognised, which is the whole point of reading on.
func TestClientDropsInputBeyondTheBacklogAndStillDetaches(t *testing.T) {
	origLimit := inputBacklogLimit
	inputBacklogLimit = 64 << 10
	t.Cleanup(func() { inputBacklogLimit = origLimit })
	limit := inputBacklogLimit

	release := make(chan struct{})
	defer close(release)
	handler := newBlockingHandler(release)

	door := serveDoor(t, func(s gssh.Session) { select {} }) // never reads its input
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	c := &Client{Socket: door.socket, Stdin: pr, Stdout: io.Discard, Escape: '~',
		Logger: slog.New(handler)}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	done := runAsync(t, ctx, c)

	_, err := pw.Write(bytes.Repeat([]byte("k"), sshWindow))
	require.NoError(t, err)
	go func() {
		if _, err := pw.Write(bytes.Repeat([]byte("k"), 2*limit)); err != nil {
			return
		}
		if _, err := pw.Write([]byte("\r")); err != nil {
			return
		}
		_, _ = pw.Write([]byte("~."))
	}()

	select {
	case res := <-done:
		require.Equal(t, Result{Reason: Detached}, res)
	case <-time.After(5 * time.Second):
		t.Fatal("~. did not detach after the backlog filled")
	}
	select {
	case <-handler.entered:
	case <-time.After(time.Second):
		t.Fatal("dropping input was never logged")
	}
	require.Equal(t, int64(1), handler.count(), "one warning for the whole attachment, not one per dropped read")
}

// A resize that fails because the connection has gone must not park the
// unwind in a blocked debug handler: the actor would never return and the
// terminal would never be restored.
//
// It takes two resizes to get one failure out of x/crypto. A write that fails
// is recorded in the transport's writeError and reported as success to its
// caller; only the next writePacket returns it (handshake.go:591-593 and
// 634-639). So the first window-change arms the error and the second one
// receives it, and it is the second that the actor logs.
//
// Barriers, not sleeps: the door signals that the shell is up before the
// transport is broken, the connection signals that a write has failed before
// the second resize is sent, and the handler signals that it was entered —
// so the test cannot pass by cancelling before anything it is about happened.
func TestClientResizeFailureWithABlockedLoggerDoesNotHoldRun(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	handler := newBlockingHandler(release)

	attached := make(chan struct{})
	door := serveDoor(t, func(s gssh.Session) {
		close(attached)
		_, _ = io.Copy(io.Discard, s)
	})
	conn := newBlockableConn()
	resizes := make(chan termsize.Size, 1)
	c := &Client{Socket: door.socket, Stdout: io.Discard,
		Logger:  slog.New(handler),
		Pty:     &Pty{Term: "xterm", Size: termsize.Default},
		Resizes: resizes,
		dial:    conn.dialThrough,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runAsync(t, ctx, c)

	select {
	case <-attached:
	case <-time.After(testTimeout):
		t.Fatal("the shell never started")
	}
	close(conn.fail)                              // every write to the socket now fails
	resizes <- termsize.Size{Cols: 100, Rows: 30} // arms the transport's writeError
	select {
	case <-conn.entered:
	case <-time.After(testTimeout):
		t.Fatal("the window-change never reached the transport")
	}
	resizes <- termsize.Size{Cols: 101, Rows: 31} // receives it, and the actor logs
	select {
	case <-handler.entered:
	case <-time.After(testTimeout):
		t.Fatal("the failed resize was never logged, so the blocked handler was never on the path")
	}
	cancel()

	select {
	case res := <-done:
		require.Equal(t, Result{Reason: Detached}, res)
	case <-time.After(5 * time.Second):
		t.Fatal("a failed resize parked the unwind in a blocked logger")
	}
}

// Cancellation must reach the handshake itself. A peer that accepts the
// connection and then says nothing — no version string, no key exchange —
// leaves the client waiting, and until the handshake completes there is no
// ssh connection to close: the socket is the only thing cancellation can end,
// and without that the wait lasts until dialTimeout. The mute-peer test below
// covers the phase after the handshake; this one covers the phase before it.
func TestClientHandshakeIsBoundedByCancellation(t *testing.T) {
	socket := filepath.Join(shortTempDir(t), "mute-hs.sock")
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	// The accepted connection is held open until the test ends: a peer that
	// closed it would end the handshake without any help from cancellation.
	accepted := make(chan net.Conn, 1)
	t.Cleanup(func() {
		select {
		case conn := <-accepted:
			_ = conn.Close()
		default:
		}
	})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	c := &Client{Socket: socket, Stdout: io.Discard}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err = c.Run(ctx)
	require.Error(t, err, "a handshake the peer never begins must fail, not hang")
	require.Less(t, time.Since(start), 5*time.Second,
		"cancellation must close the socket during the handshake rather than wait out dialTimeout")
}

// Cancellation must not depend on the peer. A daemon that completed the
// handshake and then stopped answering — SIGSTOPped, say — never replies to
// the session request, and a Run that waited for it would wait forever.
func TestClientSetupIsBoundedByCancellationAgainstAnUnresponsivePeer(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	socket := filepath.Join(shortTempDir(t), "mute.sock")
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
		cfg.AddHostKey(signer)
		// Handshake, then silence: channels are never accepted, requests
		// never answered.
		_, _, _, _ = ssh.NewServerConn(conn, cfg)
		select {}
	}()

	c := &Client{Socket: socket, Stdout: io.Discard}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err = c.Run(ctx)
	require.Error(t, err, "a session request the peer never answers must fail, not hang")
	require.Less(t, time.Since(start), 5*time.Second)
}

// The same, once attached: an input write parked on an exhausted window is
// released only by closing the connection, and cancellation has to do that.
//
// Run returning is not that proof on its own — the parked write is on a
// goroutine Run does not wait for — so the door says when the connection went
// away, which is the event that fails the write. It says so from the session's
// context rather than from a read on the session: reading credits the window
// back, which would release the very write this test is about.
func TestClientCancellationReleasesABlockedInputWrite(t *testing.T) {
	sessionEnded := make(chan struct{})
	door := serveDoor(t, func(s gssh.Session) {
		defer close(sessionEnded)
		// Reads nothing: the client's writes fill the window and park.
		<-s.Context().Done()
	})
	// More than the 2 MiB channel window, written as fast as the pipe allows.
	pr, pw := io.Pipe()
	go func() { _, _ = pw.Write(bytes.Repeat([]byte("k"), 4<<20)) }()
	// A logger of its own: past the backlog this drops input and says so, and
	// the default logger would put that on the test's stderr.
	c := &Client{Socket: door.socket, Stdin: pr, Stdout: io.Discard,
		Logger: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(500 * time.Millisecond); cancel() }()
	done := runAsync(t, ctx, c)
	select {
	case res := <-done:
		require.Equal(t, Result{Reason: Detached}, res)
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not end Run")
	}
	select {
	case <-sessionEnded:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection outlived cancellation, so nothing released the parked input write")
	}
}

// Only a client that both displays on a terminal and forwards its keystrokes
// can answer the queries a primary is sent; only that client says so.
func TestClientDeclaresInteractivityOnlyWithPtyAndStdin(t *testing.T) {
	envs := make(chan []string, 3)
	door := serveDoor(t, func(s gssh.Session) {
		envs <- s.Environ()
		_ = s.Exit(0)
	})
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	held, _ := io.Pipe()

	for _, tc := range []struct {
		name        string
		client      *Client
		interactive bool
	}{
		{"pty and stdin", &Client{Socket: door.socket, Stdout: io.Discard, Stdin: held, Pty: &Pty{Term: "xterm", Size: termsize.Default}}, true},
		{"pty only", &Client{Socket: door.socket, Stdout: io.Discard, Pty: &Pty{Term: "xterm", Size: termsize.Default}}, false},
		{"stdin only", &Client{Socket: door.socket, Stdout: io.Discard, Stdin: held}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.client.Run(ctx)
			require.NoError(t, err)
			env := <-envs
			declared := slices.Contains(env, upterm.AttachInteractiveEnvVar+"=1")
			require.Equal(t, tc.interactive, declared, "env: %v", env)
		})
	}
}

func TestClientCannotAttachToANonexistentSocket(t *testing.T) {
	c := &Client{Socket: filepath.Join(shortTempDir(t), "none.sock"), Stdout: io.Discard}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	_, err := c.Run(ctx)
	require.Error(t, err)
}

func TestClientContextCancellationDetaches(t *testing.T) {
	door := serveDoor(t, func(s gssh.Session) { _, _ = io.Copy(io.Discard, s) })
	pr, _ := io.Pipe() // never written, never closed
	c := &Client{Socket: door.socket, Stdin: pr, Stdout: io.Discard}
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(t, ctx, c)
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case res := <-done:
		require.Equal(t, Result{Reason: Detached}, res)
	case <-time.After(testTimeout):
		t.Fatal("cancellation did not end Run")
	}
}
