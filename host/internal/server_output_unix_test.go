//go:build !windows

package internal

import (
	"bufio"
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

// Screen uses LF to move down without changing the cursor column. Rewriting
// it to CRLF loses indentation on redraw (#288) and misplaces pane output
// (#278). Exercise the real host SSH server: a fake Session.Write would hide
// the SSH library's additional newline processing.
func TestServerPreservesPTYOutput(t *testing.T) {
	const output = "\x1b[H\x1b[2JHELLO   \nHELLO\r\n\x1b[12;9Hpane\nnext\r\r\n\x04"
	command := []string{"sh", "-c", `stty -echo -opost; printf READY; IFS= read -r line; printf '\033[H\033[2JHELLO   \nHELLO\r\n\033[12;9Hpane\nnext\r\r\n\004'; IFS= read -r line`}

	for _, mode := range []string{"shared replay", "shared live", "forced command"} {
		t.Run(mode, func(t *testing.T) {
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
				User: "guest", SessionID: "output-test",
				AuthRequest: &server.AuthRequest{AuthorizedKey: ssh.MarshalAuthorizedKey(signer.PublicKey())},
			}
			guestSigner, err := cert.SignCert(signer)
			require.NoError(t, err)

			srv := &Server{
				Command: command, Signers: []ssh.Signer{signer},
				Stdin: stdin, Stdout: hostOutput, EventEmitter: emitter.New(1),
				KeepAliveDuration: time.Hour, Logger: discardLogger(),
				ForceForwardingInputForTesting: true,
			}
			if mode == "forced command" {
				srv.ForceCommand = command
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

			ready := make([]byte, len("READY"))
			_, err = io.ReadFull(stdout, ready)
			require.NoError(t, err)
			require.Equal(t, "READY", string(ready))
			if mode == "shared replay" {
				_, err = io.WriteString(input, "\n")
				require.NoError(t, err)
				got, err := bufio.NewReader(stdout).ReadString('\x04')
				require.NoError(t, err)
				require.Equal(t, output, got)
			}

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
			guestOutput, err := sess.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, sess.Shell())
			_, err = io.ReadFull(guestOutput, ready)
			require.NoError(t, err)
			require.Equal(t, "READY", string(ready))
			if mode != "shared replay" {
				_, err = io.WriteString(guestInput, "\n")
				require.NoError(t, err)
			}
			got, err := bufio.NewReader(guestOutput).ReadString('\x04')
			require.NoError(t, err)
			require.Equal(t, output, got, "SSH must preserve the bytes produced by the PTY")
		})
	}
}
