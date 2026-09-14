//go:build !windows

package internal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/server"
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
}

// startHost wires srv to pipes, a loopback listener and a throwaway host key,
// then serves it until the test ends. The caller sets Command, ForceCommand
// and whatever else the test is about before passing srv in.
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

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.ServeWithContext(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(harnessTimeout):
			t.Error("host server did not stop")
		}
	})

	return &hostHarness{
		input: input, stdout: stdout,
		addr: ln.Addr().String(), hostKey: signer.PublicKey(), guestSigner: guestSigner,
	}
}

// connectGuest opens an SSH session to the host with an xterm PTY and starts
// its shell, returning the guest's stdin and stdout.
func (h *hostHarness) connectGuest(t *testing.T) (io.Writer, io.Reader) {
	t.Helper()

	raw, err := net.DialTimeout("tcp", h.addr, harnessTimeout)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	require.NoError(t, raw.SetDeadline(time.Now().Add(harnessTimeout)))
	conn, chans, reqs, err := ssh.NewClientConn(raw, h.addr, &ssh.ClientConfig{
		User: "guest", Auth: []ssh.AuthMethod{ssh.PublicKeys(h.guestSigner)},
		HostKeyCallback: ssh.FixedHostKey(h.hostKey),
	})
	require.NoError(t, err)
	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	sess, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	guestInput, err := sess.StdinPipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = guestInput.Close() })
	guestOutput, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())
	return guestInput, guestOutput
}
