//go:build !windows

package host

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestSignersFromAgent(t *testing.T) {
	for _, populated := range []bool{false, true} {
		name := "empty"
		if populated {
			name = "populated"
		}
		t.Run(name, func(t *testing.T) {
			keyring := agent.NewKeyring()
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			if populated {
				require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: privateKey}))
			}

			// Keep the socket path below macOS's Unix socket path limit.
			dir, err := os.MkdirTemp("", "agent-")
			require.NoError(t, err)
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			socket := filepath.Join(dir, "sock")
			ln, err := net.Listen("unix", socket)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					done <- err
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				done <- agent.ServeAgent(keyring, conn)
			}()
			t.Cleanup(func() {
				_ = ln.Close()
				select {
				case err := <-done:
					if !errors.Is(err, io.EOF) {
						require.NoError(t, err)
					}
				case <-time.After(5 * time.Second):
					t.Error("agent did not stop")
				}
			})
			t.Setenv("SSH_AUTH_SOCK", socket)

			signers, cleanup, err := Signers(nil)
			if cleanup != nil {
				t.Cleanup(cleanup)
			}
			require.NoError(t, err)
			require.Len(t, signers, 1)
			message := []byte("authenticate with an agent or temporary key")
			signature, err := signers[0].Sign(rand.Reader, message)
			require.NoError(t, err)
			require.NoError(t, signers[0].PublicKey().Verify(message, signature))
			if populated {
				want, err := ssh.NewPublicKey(publicKey)
				require.NoError(t, err)
				require.Equal(t, want.Marshal(), signers[0].PublicKey().Marshal())
			}
		})
	}
}
