package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"

	"github.com/owenthereal/upterm/server"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// testSigner returns a throwaway ed25519 signer.
func testSigner(t *testing.T) ssh.Signer {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

func TestRelayAuthorityRecordsAnAcceptedKey(t *testing.T) {
	relay := testSigner(t)
	var ra RelayAuthority

	cb := ra.Wrap(func(string, net.Addr, ssh.PublicKey) error { return nil })
	require.NoError(t, cb("relay:22", &net.TCPAddr{}, relay.PublicKey()))

	require.True(t, ra.IsUserAuthority(relay.PublicKey()))
	require.False(t, ra.IsUserAuthority(testSigner(t).PublicKey()))
}

func TestRelayAuthorityUnwrapsAHostCertificateToItsSigner(t *testing.T) {
	relay := testSigner(t)
	// What uptermd actually presents: a host certificate signed by the same
	// key it mints guest certificates with.
	hcs := server.HostCertSigner{Hostnames: []string{"relay"}}
	certSigner, err := hcs.SignCert(relay)
	require.NoError(t, err)

	var ra RelayAuthority
	cb := ra.Wrap(func(string, net.Addr, ssh.PublicKey) error { return nil })
	require.NoError(t, cb("relay:22", &net.TCPAddr{}, certSigner.PublicKey()))

	// The authority is the signing key, not the certificate blob.
	require.True(t, ra.IsUserAuthority(relay.PublicKey()))
	require.False(t, ra.IsUserAuthority(certSigner.PublicKey()))
}

func TestRelayAuthorityRecordsNothingWhenTheCallbackRejects(t *testing.T) {
	relay := testSigner(t)
	rejected := errors.New("host key verification failed")
	var ra RelayAuthority

	cb := ra.Wrap(func(string, net.Addr, ssh.PublicKey) error { return rejected })
	require.ErrorIs(t, cb("relay:22", &net.TCPAddr{}, relay.PublicKey()), rejected)

	require.False(t, ra.IsUserAuthority(relay.PublicKey()),
		"a key the host refused must never become an authority")
}

func TestRelayAuthorityTrustsNothingBeforeAnythingIsRecorded(t *testing.T) {
	var ra RelayAuthority
	require.False(t, ra.IsUserAuthority(testSigner(t).PublicKey()))
	require.False(t, ra.IsUserAuthority(nil))
}

func TestRelayAuthorityWrapRequiresACallback(t *testing.T) {
	var ra RelayAuthority
	cb := ra.Wrap(nil)
	require.Error(t, cb("relay:22", &net.TCPAddr{}, testSigner(t).PublicKey()),
		"a nil callback must fail closed rather than accept every key")
	require.False(t, ra.IsUserAuthority(testSigner(t).PublicKey()))
}
