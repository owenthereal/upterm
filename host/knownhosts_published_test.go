package host

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owenthereal/upterm/server"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// publishedKnownHosts is the file shipped for the public relay.
const publishedKnownHosts = "../etc/known_hosts/uptermd.upterm.dev"

// relayHostCert is the certificate uptermd.upterm.dev actually presents.
func relayHostCert(t *testing.T) ssh.PublicKey {
	t.Helper()

	b, err := os.ReadFile("testdata/uptermd_host_cert.pub")
	require.NoError(t, err)

	// The fixture is `type base64`, the certificate's own authorized-key line.
	// Tolerate a keyscan-style `host type base64` capture too, by stripping a
	// leading hostname field when the line doesn't parse as-is.
	key, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		fields := strings.Fields(string(b))
		require.GreaterOrEqual(t, len(fields), 3, "expected `type base64` or `host type base64`")
		key, _, _, _, err = ssh.ParseAuthorizedKey([]byte(strings.Join(fields[1:], " ")))
		require.NoError(t, err)
	}
	_, isCert := key.(*ssh.Certificate)
	require.True(t, isCert, "the relay presents a host certificate; capture that, not the plain key")
	return key
}

// callbackFor is the production callback, over a copy of the published file, with
// stdin at EOF: a CI runner with no terminal. Never a nil reader -- an
// unexpected prompt would panic in bufio instead of failing the test.
func callbackFor(t *testing.T, contents string) ssh.HostKeyCallback {
	t.Helper()

	path := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	cb, err := NewPromptingHostKeyCallback(strings.NewReader(""), io.Discard, path, false)
	require.NoError(t, err)
	return cb
}

func TestPublishedKnownHostsVerifiesTheRelayUnattended(t *testing.T) {
	published, err := os.ReadFile(publishedKnownHosts)
	require.NoError(t, err)
	cert := relayHostCert(t)

	for _, addr := range []string{"uptermd.upterm.dev:22", "uptermd.upterm.dev:443"} {
		t.Run(addr, func(t *testing.T) {
			cb := callbackFor(t, string(published))
			require.NoError(t, cb(addr, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}, cert),
				"the published file must verify the relay with no prompt")
		})
	}
}

func TestPublishedKnownHostsRefusesAnotherSigner(t *testing.T) {
	published, err := os.ReadFile(publishedKnownHosts)
	require.NoError(t, err)

	// A host certificate from a signer that is not the published authority.
	impostor, err := ssh.NewSignerFromKey(mustGenerateEd25519(t))
	require.NoError(t, err)
	hcs := server.HostCertSigner{Hostnames: []string{"uptermd.upterm.dev"}}
	certSigner, err := hcs.SignCert(impostor)
	require.NoError(t, err)

	cb := callbackFor(t, string(published))
	err = cb("uptermd.upterm.dev:22", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}, certSigner.PublicKey())
	require.Error(t, err, "an unpublished signer must not verify")
	require.Contains(t, err.Error(), "could not read host-key confirmation from stdin",
		"it must reach the prompt and fail there, not verify silently")
}

// TestPlainKeyLineDoesNotAuthorizeTheCertificate is why the published file uses
// @cert-authority: it pins the behaviour that makes an ssh-keyscan recipe
// inadequate, so nobody 'simplifies' the file back to a plain key line.
func TestPlainKeyLineDoesNotAuthorizeTheCertificate(t *testing.T) {
	cert := relayHostCert(t).(*ssh.Certificate)
	plain := "uptermd.upterm.dev " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert.SignatureKey)))

	cb := callbackFor(t, plain+"\n")
	err := cb("uptermd.upterm.dev:22", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}, cert)
	require.Error(t, err, "a plain key line must not verify a host certificate")
}

func mustGenerateEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return key
}
