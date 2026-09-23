//go:build !windows

package internal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// harnessTimeout bounds every wait in the harness, so a host or guest that
// never answers fails the test instead of hanging it.
const harnessTimeout = 10 * time.Second

// hostHarness runs a Server that serves guests over loopback and local
// clients over a unix socket. Tests that need the real SSH server and real
// child processes, rather than a fake Session, build on it.
type hostHarness struct {
	addr        string
	hostKey     ssh.PublicKey
	guestSigner ssh.Signer

	// attachSocket is the path of the host door's socket, and hostListener is
	// the listener bound to it, so a test can fail the door on its own.
	attachSocket string
	hostListener net.Listener

	// srv is the server under test, and done carries what ServeWithContext
	// returned, so a test can assert the session outlived something.
	srv  *Server
	done <-chan error
}

// startHost wires srv to a loopback listener, a host-door socket and a
// throwaway host key, then serves it until the test ends. The caller sets
// Command, ForceCommand and whatever else the test is about before passing
// srv in.
func startHost(t *testing.T, srv *Server) *hostHarness {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	cert := &server.UserCertSigner{
		User: "guest", SessionID: t.Name(),
		AuthRequest: &server.AuthRequest{AuthorizedKey: ssh.MarshalAuthorizedKey(signer.PublicKey())},
	}
	guestSigner, err := cert.SignCert(signer)
	require.NoError(t, err)

	// A test that wants to watch the door's key sets HostKey itself.
	if srv.HostKey == nil {
		srv.HostKey = signer
	}
	srv.EventEmitter = emitter.New(1)
	srv.KeepAliveDuration = time.Hour
	srv.Logger = discardLogger()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	hostLn, err := net.Listen("unix", filepath.Join(shortTempDir(t), "a.sock"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = hostLn.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		done <- srv.ServeWithContext(ctx, ln, hostLn)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(harnessTimeout):
			t.Error("host server did not stop")
		}
	})

	return &hostHarness{addr: ln.Addr().String(),
		attachSocket: hostLn.Addr().String(), hostListener: hostLn, srv: srv,
		hostKey: srv.HostKey.PublicKey(), guestSigner: guestSigner, done: done}
}

// dialGuest opens an SSH session to the host with an xterm PTY and starts its
// shell, returning the guest's stdin, stdout and session. It returns its
// errors rather than asserting them, so a test can dial from a goroutine.
func (h *hostHarness) dialGuest(t *testing.T, opts ...dialOption) (io.Writer, io.Reader, *ssh.Session, error) {
	t.Helper()

	cfg := dialConfig{deadline: harnessTimeout}
	for _, opt := range opts {
		opt(&cfg)
	}

	raw, err := net.DialTimeout("tcp", h.addr, harnessTimeout)
	if err != nil {
		return nil, nil, nil, err
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.SetDeadline(time.Now().Add(cfg.deadline)); err != nil {
		return nil, nil, nil, err
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, h.addr, &ssh.ClientConfig{
		Config: ssh.Config{RekeyThreshold: cfg.rekeyThreshold},
		User:   "guest", Auth: []ssh.AuthMethod{ssh.PublicKeys(h.guestSigner)},
		HostKeyCallback: ssh.FixedHostKey(h.hostKey),
	})
	if err != nil {
		return nil, nil, nil, err
	}
	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	sess, err := client.NewSession()
	if err != nil {
		return nil, nil, nil, err
	}
	t.Cleanup(func() { _ = sess.Close() })
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		return nil, nil, nil, err
	}
	guestInput, err := sess.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	t.Cleanup(func() { _ = guestInput.Close() })
	guestOutput, err := sess.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := sess.Shell(); err != nil {
		return nil, nil, nil, err
	}
	return guestInput, guestOutput, sess, nil
}

// connectGuest is dialGuest for the usual case, where failing to connect is a
// failure of the test.
func (h *hostHarness) connectGuest(t *testing.T, opts ...dialOption) (io.Writer, io.Reader) {
	t.Helper()

	guestInput, guestOutput, _ := h.connectGuestSession(t, opts...)
	return guestInput, guestOutput
}

// connectGuestSession is connectGuest for a test that needs the guest's
// session itself, to wait on the status it is closed with.
func (h *hostHarness) connectGuestSession(t *testing.T, opts ...dialOption) (io.Writer, io.Reader, *ssh.Session) {
	t.Helper()

	guestInput, guestOutput, sess, err := h.dialGuest(t, opts...)
	require.NoError(t, err)
	return guestInput, guestOutput, sess
}

type hostPty struct {
	term       string
	cols, rows int
	// viewer requests the pty without declaring interactivity: a
	// backgrounded `upterm host &`, which displays but does not read.
	viewer bool
}

// gatedConn is a client connection a test can stop reading from: the client
// that is still connected but is no longer taking bytes off the socket, which
// is what the host sees of a terminal under SIGSTOP.
//
// It exists to tell a closed connection from a closed channel. Both leave the
// same error on the session, and an in-process client whose mux is still
// running answers a channel close at once — so a host that closed the channel
// where it meant to close the connection would look identical, while releasing
// nothing that is parked in SSH. With the mux stopped, only the connection
// going away has any effect.
type gatedConn struct {
	net.Conn
	transportID string // SSH handshake ID, used by the host elector

	pause, resume     chan struct{}
	pauseOnce         sync.Once
	resumeOnce        sync.Once
	transportEnded    chan struct{}
	transportEndsOnce sync.Once
}

func newGatedConn(c net.Conn) *gatedConn {
	return &gatedConn{Conn: c,
		pause: make(chan struct{}), resume: make(chan struct{}),
		transportEnded: make(chan struct{})}
}

func (g *gatedConn) Read(p []byte) (int, error) {
	select {
	case <-g.pause:
		<-g.resume
	default:
	}
	n, err := g.Conn.Read(p)
	if err != nil {
		g.transportEndsOnce.Do(func() { close(g.transportEnded) })
	}
	return n, err
}

// pauseReads stops the client's mux dead. Nothing is read off the socket from
// here on, so the channel window is never adjusted and the host's writes park.
func (g *gatedConn) pauseReads() { g.pauseOnce.Do(func() { close(g.pause) }) }

// resumeReads lets the mux run again, so the client can find out what became
// of it while it was not looking.
func (g *gatedConn) resumeReads() { g.resumeOnce.Do(func() { close(g.resume) }) }

// transportClosed closes once the client's read side ends, which on this
// socket means the host closed the connection rather than the channel on it.
// Only observable after resumeReads: a paused mux reads nothing, including an
// EOF.
func (g *gatedConn) transportClosed() <-chan struct{} { return g.transportEnded }

// dialOption tunes one connection, on either door.
type dialOption func(*dialConfig)

type dialConfig struct {
	deadline time.Duration
	// rekeyThreshold, when non-zero, makes the client renegotiate keys after
	// that many bytes. x/crypto clamps it to its 256-byte minimum.
	rekeyThreshold uint64
}

// withRekeyThreshold forces key renegotiation early, so a test can watch what
// a rekey signs with.
func withRekeyThreshold(n uint64) dialOption {
	return func(c *dialConfig) { c.rekeyThreshold = n }
}

// withDialDeadline replaces the harness's absolute connection deadline for one
// connection. The tests that move several MiB, and the ones that deliberately
// stop reading for a while, need the room: with the default they could fail
// because a loaded runner ran out of deadline rather than because anything was
// wrong.
//
// Which is not hypothetical, and is why this now reaches the guest door too.
// TestUndrainedViewerDoesNotWedgeTheSession pushes 6 MB through a guest and
// failed in CI at 11.53 s with "stream ended before DONE: EOF" — the deadline
// on the guest's own connection, ten seconds after it dialled, cutting the
// stream off a little over a second short. Twelve local runs passed, and so
// did five under a loaded machine: the deadline is absolute, so what decides
// it is how long the whole test takes.
func withDialDeadline(d time.Duration) dialOption {
	return func(c *dialConfig) { c.deadline = d }
}

// dialHost completes the handshake on the host door with a throwaway key, the
// way upterm attach does, and opens no session: a connection is not yet a
// client.
func (h *hostHarness) dialHost(t *testing.T, opts ...dialOption) *ssh.Client {
	t.Helper()

	client, _ := h.dialHostConn(t, opts...)
	return client
}

// dialHostConn is dialHost for a test that needs the gate on the client's
// reads as well as the client.
func (h *hostHarness) dialHostConn(t *testing.T, opts ...dialOption) (*ssh.Client, *gatedConn) {
	t.Helper()

	cfg := dialConfig{deadline: harnessTimeout}
	for _, opt := range opts {
		opt(&cfg)
	}

	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)

	raw, err := net.DialTimeout("unix", h.attachSocket, harnessTimeout)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	require.NoError(t, raw.SetDeadline(time.Now().Add(cfg.deadline)))
	gated := newGatedConn(raw)
	// Released whatever the test does, so a mux parked in the gate can never
	// outlive the test that paused it.
	t.Cleanup(gated.resumeReads)
	conn, chans, reqs, err := ssh.NewClientConn(gated, h.attachSocket, &ssh.ClientConfig{
		User: "host", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(h.hostKey),
		ClientVersion:   upterm.AttachSSHClientVersion,
	})
	require.NoError(t, err)
	gated.transportID = hex.EncodeToString(conn.SessionID())
	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	return client, gated
}

// connectHost attaches through the host door with a throwaway key, the way
// upterm attach does. A nil pty makes it a pipe viewer; a pty that is not a
// viewer declares itself interactive, as attach.Client does with a Stdin.
func (h *hostHarness) connectHost(t *testing.T, pty *hostPty, opts ...dialOption) (io.WriteCloser, io.Reader, *ssh.Session) {
	t.Helper()

	in, out, sess, _ := h.connectHostGated(t, pty, opts...)
	return in, out, sess
}

// connectHostGated is connectHost for a test that needs to stop the client
// reading mid-session.
func (h *hostHarness) connectHostGated(t *testing.T, pty *hostPty, opts ...dialOption) (io.WriteCloser, io.Reader, *ssh.Session, *gatedConn) {
	t.Helper()

	client, gated := h.dialHostConn(t, opts...)
	sess, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	if pty != nil {
		require.NoError(t, sess.RequestPty(pty.term, pty.rows, pty.cols, ssh.TerminalModes{}))
		if !pty.viewer {
			require.NoError(t, sess.Setenv(upterm.AttachInteractiveEnvVar, "1"))
		}
	}
	in, err := sess.StdinPipe()
	require.NoError(t, err)
	out, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())
	return in, out, sess, gated
}

// readUntil reads r until marker appears, returning everything read.
func readUntil(t *testing.T, r io.Reader, marker string) string {
	t.Helper()
	return readUntilWithin(t, r, marker, harnessTimeout)
}

// readUntilWithin is readUntil with its own budget, for a marker that arrives
// only behind one of the multi-megabyte payloads. harnessTimeout is sized for
// a client that never answers at all; six megabytes through a pty takes most
// of it on a loaded macOS runner, where the stream tests measure 5-6s against
// its 10, so reading a payload on that budget fails on a slow runner rather
// than on a broken one. The sibling stream tests already give their own
// readers and connections a minute for the same reason.
func readUntilWithin(t *testing.T, r io.Reader, marker string, timeout time.Duration) string {
	t.Helper()
	var seen strings.Builder
	buf := make([]byte, 4096)
	deadline := time.Now().Add(timeout)
	// Reported through t.Fatalf rather than require, which formats the whole
	// of what it was given: handed a six-megabyte haystack it prints all of
	// it, and the padding is never what the failure is about.
	for !strings.Contains(seen.String(), marker) {
		if !time.Now().Before(deadline) {
			t.Fatalf("timed out after %s waiting for %q; saw %s", timeout, marker, summarize(seen.String()))
		}
		n, err := r.Read(buf)
		seen.Write(buf[:n])
		if err != nil {
			if !strings.Contains(seen.String(), marker) {
				t.Fatalf("stream ended before %q: %v; saw %s", marker, err, summarize(seen.String()))
			}
			break
		}
	}
	return seen.String()
}

// summarize is what a failure message shows of a stream that may be megabytes
// of padding: its length, and the tail the marker would have been at the end
// of. Testify renders a message this size and no more — handed the whole of a
// six-megabyte payload it prints "bufio.Scanner: token too long" instead, so
// an unbounded message is how a stream test comes to report nothing at all.
func summarize(s string) string {
	const tail = 256
	if len(s) <= tail {
		return fmt.Sprintf("%d bytes %q", len(s), s)
	}
	return fmt.Sprintf("%d bytes ending %q", len(s), s[len(s)-tail:])
}

// readsALine is a command that prints a marker, waits for one line of input,
// prints what it got, and exits with the given status.
func readsALine(marker string, status int) []string {
	return []string{"sh", "-c", `stty -echo -opost; printf '` + marker + `\n'; IFS= read -r line; printf 'got:%s\n' "$line"; exit ` + strconv.Itoa(status)}
}
