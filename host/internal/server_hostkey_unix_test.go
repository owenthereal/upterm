//go:build !windows

package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestDoorsPresentTheSessionHostKey pins that both doors present HostKey and
// nothing else. The harness pins FixedHostKey(HostKey) on every dial, so the
// two connections are the assertion; the third dial, pinned to a different
// key, shows the pin is doing work.
func TestDoorsPresentTheSessionHostKey(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostKey, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)

	h := startHost(t, &Server{Command: []string{"sh", "-c", "IFS= read -r line"}, HostKey: hostKey})
	require.Equal(t, hostKey.PublicKey().Marshal(), h.hostKey.Marshal(), "the harness pins the key it was given")
	h.connectGuest(t)
	h.connectHost(t, nil)

	_, other, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherSigner, err := ssh.NewSignerFromKey(other)
	require.NoError(t, err)
	raw, err := net.DialTimeout("tcp", h.addr, harnessTimeout)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	require.NoError(t, raw.SetDeadline(time.Now().Add(harnessTimeout)))
	_, _, _, err = ssh.NewClientConn(raw, h.addr, &ssh.ClientConfig{
		User: "guest", Auth: []ssh.AuthMethod{ssh.PublicKeys(h.guestSigner)},
		HostKeyCallback: ssh.FixedHostKey(otherSigner.PublicKey()),
	})
	require.ErrorContains(t, err, "host key mismatch")
}

// TestServeRequiresAHostKey: a door with no key would panic inside
// charm.land/ssh; refuse up front instead.
func TestServeRequiresAHostKey(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	srv := &Server{Command: []string{"true"}, Logger: discardLogger()}
	err = srv.ServeWithContext(t.Context(), ln, nil)
	require.ErrorContains(t, err, "HostKey is required")
}
