//go:build !windows

package internal

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Exercise the server as well as its child processes: testing startAttachCmd
// alone would miss the dropped CommandEnv between Server and sessionHandler (#331).
func TestServerCommandEnvironment(t *testing.T) {
	const socket = "/tmp/upterm-current.sock"
	command := []string{"sh", "-c", `stty -echo -opost; printf 'SOCKET=%s\nTERM=%s\nINHERITED=%s\004' "$UPTERM_ADMIN_SOCKET" "$TERM" "$UPTERM_TEST_INHERITED"; IFS= read -r line`}
	for _, tc := range []struct {
		name      string
		inherited string
		unset     bool
	}{
		{name: "unset", unset: true},
		{name: "empty"},
		{name: "stale", inherited: "/tmp/upterm-outer.sock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("UPTERM_ADMIN_SOCKET", tc.inherited)
			if tc.unset {
				require.NoError(t, os.Unsetenv("UPTERM_ADMIN_SOCKET"))
			}
			t.Setenv("TERM", "host-term")
			t.Setenv("UPTERM_TEST_INHERITED", "inherited-ok")

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			stdin, input, err := os.Pipe()
			require.NoError(t, err)
			defer func() { _ = stdin.Close() }()
			defer func() { _ = input.Close() }()
			stdout, hostOutput, err := os.Pipe()
			require.NoError(t, err)
			defer func() { _ = stdout.Close() }()
			defer func() { _ = hostOutput.Close() }()
			require.NoError(t, stdout.SetReadDeadline(time.Now().Add(10*time.Second)))

			_, key, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			signer, err := ssh.NewSignerFromKey(key)
			require.NoError(t, err)
			cert := &server.UserCertSigner{
				User: "guest", SessionID: "environment-test",
				AuthRequest: &server.AuthRequest{AuthorizedKey: ssh.MarshalAuthorizedKey(signer.PublicKey())},
			}
			guestSigner, err := cert.SignCert(signer)
			require.NoError(t, err)

			srv := &Server{
				Command: command, ForceCommand: command,
				CommandEnv: []string{"UPTERM_ADMIN_SOCKET=" + socket},
				Signers:    []ssh.Signer{signer},
				Stdin:      stdin, Stdout: hostOutput, EventEmitter: emitter.New(1),
				KeepAliveDuration: time.Hour, Logger: discardLogger(),
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer func() { _ = ln.Close() }()
			done := make(chan error, 1)
			go func() { done <- srv.ServeWithContext(ctx, ln) }()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("host server did not stop")
				}
			}()

			got, err := bufio.NewReader(stdout).ReadString('\x04')
			require.NoError(t, err)
			assert.Equal(t, "SOCKET=/tmp/upterm-current.sock\nTERM=host-term\nINHERITED=inherited-ok\x04", got, "host environment")

			raw, err := net.DialTimeout("tcp", ln.Addr().String(), 10*time.Second)
			require.NoError(t, err)
			defer func() { _ = raw.Close() }()
			require.NoError(t, raw.SetDeadline(time.Now().Add(10*time.Second)))
			conn, chans, reqs, err := ssh.NewClientConn(raw, ln.Addr().String(), &ssh.ClientConfig{
				User: "guest", Auth: []ssh.AuthMethod{ssh.PublicKeys(guestSigner)},
				HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()),
			})
			require.NoError(t, err)
			client := ssh.NewClient(conn, chans, reqs)
			defer func() { _ = client.Close() }()
			sess, err := client.NewSession()
			require.NoError(t, err)
			defer func() { _ = sess.Close() }()
			require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
			guestInput, err := sess.StdinPipe()
			require.NoError(t, err)
			defer func() { _ = guestInput.Close() }()
			guestOutput, err := sess.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, sess.Shell())
			got, err = bufio.NewReader(guestOutput).ReadString('\x04')
			require.NoError(t, err)
			assert.Equal(t, "SOCKET=/tmp/upterm-current.sock\nTERM=xterm\nINHERITED=inherited-ok\x04", got, "forced command environment")
		})
	}
}
