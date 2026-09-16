//go:build !windows

package internal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// hostHarness runs a Server with its terminal replaced by pipes and serves
// guests over loopback. Tests that need the real SSH server and real child
// processes, rather than a fake Session, build on it.
type hostHarness struct {
	// input is the write end of the host's stdin.
	input *os.File
	// stdout is the read end of the host's stdout, with a read deadline.
	stdout *os.File

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

// startHost wires srv to pipes, a loopback listener, a host-door socket and a
// throwaway host key, then serves it until the test ends. The caller sets
// Command, ForceCommand and whatever else the test is about before passing
// srv in.
func startHost(t *testing.T, srv *Server) *hostHarness {
	t.Helper()

	stdin, input, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = stdin.Close(); _ = input.Close() })
	stdout, hostOutput, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = stdout.Close(); _ = hostOutput.Close() })
	require.NoError(t, stdout.SetReadDeadline(time.Now().Add(harnessTimeout)))

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

	srv.Signers = []ssh.Signer{signer}
	srv.Stdin, srv.Stdout = stdin, hostOutput
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

	return &hostHarness{input: input, stdout: stdout, addr: ln.Addr().String(),
		attachSocket: hostLn.Addr().String(), hostListener: hostLn, srv: srv,
		hostKey: signer.PublicKey(), guestSigner: guestSigner, done: done}
}

// dialGuest opens an SSH session to the host with an xterm PTY and starts its
// shell, returning the guest's stdin, stdout and session. It returns its
// errors rather than asserting them, so a test can dial from a goroutine.
func (h *hostHarness) dialGuest(t *testing.T) (io.Writer, io.Reader, *ssh.Session, error) {
	t.Helper()

	raw, err := net.DialTimeout("tcp", h.addr, harnessTimeout)
	if err != nil {
		return nil, nil, nil, err
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.SetDeadline(time.Now().Add(harnessTimeout)); err != nil {
		return nil, nil, nil, err
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, h.addr, &ssh.ClientConfig{
		User: "guest", Auth: []ssh.AuthMethod{ssh.PublicKeys(h.guestSigner)},
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
func (h *hostHarness) connectGuest(t *testing.T) (io.Writer, io.Reader) {
	t.Helper()

	guestInput, guestOutput, _ := h.connectGuestSession(t)
	return guestInput, guestOutput
}

// connectGuestSession is connectGuest for a test that needs the guest's
// session itself, to wait on the status it is closed with.
func (h *hostHarness) connectGuestSession(t *testing.T) (io.Writer, io.Reader, *ssh.Session) {
	t.Helper()

	guestInput, guestOutput, sess, err := h.dialGuest(t)
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

// dialHost completes the handshake on the host door with a throwaway key, the
// way upterm attach does, and opens no session: a connection is not yet a
// client.
func (h *hostHarness) dialHost(t *testing.T) *ssh.Client {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)

	raw, err := net.DialTimeout("unix", h.attachSocket, harnessTimeout)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	require.NoError(t, raw.SetDeadline(time.Now().Add(harnessTimeout)))
	conn, chans, reqs, err := ssh.NewClientConn(raw, h.attachSocket, &ssh.ClientConfig{
		User: "host", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(h.hostKey),
		ClientVersion:   upterm.AttachSSHClientVersion,
	})
	require.NoError(t, err)
	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// connectHost attaches through the host door with a throwaway key, the way
// upterm attach does. A nil pty makes it a pipe viewer; a pty that is not a
// viewer declares itself interactive, as attach.Client does with a Stdin.
func (h *hostHarness) connectHost(t *testing.T, pty *hostPty) (io.WriteCloser, io.Reader, *ssh.Session) {
	t.Helper()

	sess, err := h.dialHost(t).NewSession()
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
	return in, out, sess
}

// readUntil reads r until marker appears, returning everything read.
func readUntil(t *testing.T, r io.Reader, marker string) string {
	t.Helper()
	var seen strings.Builder
	buf := make([]byte, 4096)
	deadline := time.Now().Add(harnessTimeout)
	for !strings.Contains(seen.String(), marker) {
		require.True(t, time.Now().Before(deadline), "timed out waiting for %q; saw %q", marker, seen.String())
		n, err := r.Read(buf)
		seen.Write(buf[:n])
		if err != nil {
			require.Contains(t, seen.String(), marker, "stream ended before %q: %v", marker, err)
			break
		}
	}
	return seen.String()
}

// readsALine is a command that prints a marker, waits for one line of input,
// prints what it got, and exits with the given status.
func readsALine(marker string, status int) []string {
	return []string{"sh", "-c", `stty -echo -opost; printf '` + marker + `\n'; IFS= read -r line; printf 'got:%s\n' "$line"; exit ` + strconv.Itoa(status)}
}
