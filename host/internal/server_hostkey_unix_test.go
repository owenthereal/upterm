//go:build !windows

package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"sync/atomic"
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

// countingSigner counts every signature a door makes with the session host
// key. Both entry points are implemented because x/crypto's server uses
// SignWithAlgorithm when the signer offers it and Sign otherwise.
type countingSigner struct {
	ssh.Signer
	signatures atomic.Int32
}

func (s *countingSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	s.signatures.Add(1)
	return s.Signer.Sign(rand, data)
}

func (s *countingSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	s.signatures.Add(1)
	if as, ok := s.Signer.(ssh.AlgorithmSigner); ok {
		return as.SignWithAlgorithm(rand, data, algorithm)
	}
	return s.Signer.Sign(rand, data)
}

// TestRekeySignsWithTheSessionHostKey: a key exchange signs with the door's
// key, and a rekey is a key exchange. After this change the identity is not
// wired into the server at all, so the assertion is the positive one — the
// session key signs again — rather than an absence.
func TestRekeySignsWithTheSessionHostKey(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	inner, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	hostKey := &countingSigner{Signer: inner}

	h := startHost(t, &Server{Command: []string{"sh", "-c", "stty -echo; cat"}, HostKey: hostKey})
	guestIn, guestOut := h.connectGuest(t, withRekeyThreshold(256))
	handshakes := hostKey.signatures.Load()
	require.GreaterOrEqual(t, handshakes, int32(1), "the handshake signed")

	// Well past the threshold in both directions; cat echoes it back. In
	// lines, because the pty is in canonical mode and drops input lines
	// longer than its 4095-byte line buffer.
	payload := strings.Repeat(strings.Repeat("x", 200)+"\n", 20) + "END\n"
	_, err = io.WriteString(guestIn, payload)
	require.NoError(t, err)
	readUntil(t, guestOut, "END")

	require.Eventually(t, func() bool { return hostKey.signatures.Load() > handshakes },
		harnessTimeout, 10*time.Millisecond, "a rekey signed with the session host key")

	// Still working on the new keys.
	_, err = io.WriteString(guestIn, "AFTER\n")
	require.NoError(t, err)
	readUntil(t, guestOut, "AFTER")
}
