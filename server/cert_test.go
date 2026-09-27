package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

func certTestSigner(t *testing.T) ssh.Signer {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

// authorityOf is the IsUserAuthority a call site with one trusted signer uses.
func authorityOf(signers ...ssh.Signer) func(ssh.PublicKey) bool {
	return func(key ssh.PublicKey) bool {
		for _, s := range signers {
			if key != nil && string(key.Marshal()) == string(s.PublicKey().Marshal()) {
				return true
			}
		}
		return false
	}
}

// userCert mints a user certificate the way UserCertSigner does, but with every
// field a test needs to vary.
func userCert(t *testing.T, signer ssh.Signer, principal string, ext map[string]string, after, before time.Time) *ssh.Certificate {
	t.Helper()

	cert := &ssh.Certificate{
		Key:             certTestSigner(t).PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "test",
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(after.Unix()),
		ValidBefore:     uint64(before.Unix()),
		Permissions:     ssh.Permissions{Extensions: ext},
	}
	require.NoError(t, cert.SignCert(rand.Reader, signer))
	return cert
}

// authExt is the upterm extension naming authorizedKey as the guest identity.
func authExt(t *testing.T, authorizedKey ssh.PublicKey) map[string]string {
	t.Helper()

	b, err := proto.Marshal(&AuthRequest{AuthorizedKey: ssh.MarshalAuthorizedKey(authorizedKey)})
	require.NoError(t, err)
	return map[string]string{upterm.SSHCertExtension: string(b)}
}

func TestParseAuthRequestFromCert(t *testing.T) {
	relay := certTestSigner(t)
	other := certTestSigner(t)
	named := certTestSigner(t).PublicKey() // the identity an extension claims

	now := time.Now()
	wide := func() (time.Time, time.Time) { return now.Add(-time.Minute), now.Add(time.Minute) }

	t.Run("a trusted authority's extension names the identity", func(t *testing.T) {
		after, before := wide()
		cert := userCert(t, relay, "session", authExt(t, named), after, before)

		auth, key, err := parseAuthRequestFromCert("session", cert, authorityOf(relay))
		require.NoError(t, err)
		require.NotNil(t, auth)
		require.Equal(t, named.Marshal(), key.Marshal())
	})

	t.Run("an untrusted authority yields the certified key and no AuthRequest", func(t *testing.T) {
		after, before := wide()
		// A self-signed certificate naming an authorized key: its signer is not
		// an authority, so the name must not be honoured.
		cert := userCert(t, other, "session", authExt(t, named), after, before)

		auth, key, err := parseAuthRequestFromCert("session", cert, authorityOf(relay))
		require.ErrorIs(t, err, errCertUntrustedAuthority)
		require.Nil(t, auth, "an untrusted certificate must yield no AuthRequest")
		require.Equal(t, cert.Key.Marshal(), key.Marshal(),
			"the identity must be the key the certificate is for, never the one it names")
	})

	t.Run("a nil authority trusts nothing", func(t *testing.T) {
		after, before := wide()
		cert := userCert(t, relay, "session", authExt(t, named), after, before)

		auth, key, err := parseAuthRequestFromCert("session", cert, nil)
		require.ErrorIs(t, err, errCertUntrustedAuthority)
		require.Nil(t, auth)
		require.Equal(t, cert.Key.Marshal(), key.Marshal())
	})

	// A genuine certificate for one session, replayed at another on the same
	// relay. The authority matches, so only the principal check can refuse it.
	t.Run("a trusted certificate for another session is refused", func(t *testing.T) {
		after, before := wide()
		cert := userCert(t, relay, "session-a", authExt(t, named), after, before)

		auth, key, err := parseAuthRequestFromCert("session-b", cert, authorityOf(relay))
		require.Error(t, err)
		require.NotErrorIs(t, err, errCertUntrustedAuthority)
		require.Contains(t, err.Error(), "principal")
		require.Nil(t, auth)
		require.Equal(t, cert.Key.Marshal(), key.Marshal())
	})

	// The validity window still bites, with the authority check now ahead of
	// it. The window here is the one UserCertSigner mints, whose
	// bounds are the skew tolerance either side of now -- CheckCert applies no
	// tolerance of its own, so what the skew buys a host belongs with
	// UserCertSigner, not here.
	t.Run("a trusted certificate inside its validity window is accepted", func(t *testing.T) {
		cert := userCert(t, relay, "session", authExt(t, named),
			now.Add(-certClockSkewTolerance), now.Add(certClockSkewTolerance))

		_, _, err := parseAuthRequestFromCert("session", cert, authorityOf(relay))
		require.NoError(t, err)
	})

	t.Run("an expired trusted certificate is refused", func(t *testing.T) {
		cert := userCert(t, relay, "session", authExt(t, named),
			now.Add(-2*time.Hour), now.Add(-time.Hour))

		auth, _, err := parseAuthRequestFromCert("session", cert, authorityOf(relay))
		require.Error(t, err)
		require.Contains(t, err.Error(), "expired")
		require.Nil(t, auth)
	})

	t.Run("a trusted certificate with no upterm extension", func(t *testing.T) {
		after, before := wide()
		cert := userCert(t, relay, "session", nil, after, before)

		auth, key, err := parseAuthRequestFromCert("session", cert, authorityOf(relay))
		require.ErrorIs(t, err, errCertNotSignedByHost)
		require.Nil(t, auth)
		require.Equal(t, cert.Key.Marshal(), key.Marshal())
	})

	// A trusted signer but a broken payload. Never guessed.
	t.Run("an unparseable extension payload is refused", func(t *testing.T) {
		after, before := wide()
		ext := map[string]string{upterm.SSHCertExtension: "\xff\xfe not protobuf"}
		cert := userCert(t, relay, "session", ext, after, before)

		auth, key, err := parseAuthRequestFromCert("session", cert, authorityOf(relay))
		require.Error(t, err)
		require.NotErrorIs(t, err, errCertNotSignedByHost)
		require.NotErrorIs(t, err, errCertUntrustedAuthority)
		require.Nil(t, auth)
		require.Equal(t, cert.Key.Marshal(), key.Marshal())
	})

	t.Run("an unparseable authorized key is refused", func(t *testing.T) {
		after, before := wide()
		b, err := proto.Marshal(&AuthRequest{AuthorizedKey: []byte("not a key")})
		require.NoError(t, err)
		ext := map[string]string{upterm.SSHCertExtension: string(b)}
		cert := userCert(t, relay, "session", ext, after, before)

		auth, key, err := parseAuthRequestFromCert("session", cert, authorityOf(relay))
		require.Error(t, err)
		require.Nil(t, auth)
		require.Equal(t, cert.Key.Marshal(), key.Marshal(),
			"a failed parse must not return the key it failed to parse")
	})

	// The relay's own host certificate, replayed as a guest credential.
	// Refused on type, before the authority is even consulted.
	t.Run("a host certificate is not a user certificate", func(t *testing.T) {
		hcs := HostCertSigner{Hostnames: []string{"relay"}}
		certSigner, err := hcs.SignCert(relay)
		require.NoError(t, err)
		cert := certSigner.PublicKey().(*ssh.Certificate)

		auth, key, err := parseAuthRequestFromCert("session", cert, authorityOf(relay))
		require.Error(t, err)
		require.Contains(t, err.Error(), "cert has type")
		require.Nil(t, auth)
		require.Equal(t, cert.Key.Marshal(), key.Marshal())
	})
}

func TestUserCertCheckerFallsBackForAPlainKey(t *testing.T) {
	plain := certTestSigner(t).PublicKey()

	t.Run("with a fallback the key passes through", func(t *testing.T) {
		checker := UserCertChecker{
			UserKeyFallback: func(_ string, key ssh.PublicKey) (ssh.PublicKey, error) { return key, nil },
		}
		auth, key, err := checker.Authenticate("session", plain)
		require.NoError(t, err)
		require.Nil(t, auth)
		require.Equal(t, plain.Marshal(), key.Marshal())
	})

	t.Run("without a fallback a plain key is refused", func(t *testing.T) {
		var checker UserCertChecker
		_, _, err := checker.Authenticate("session", plain)
		require.Error(t, err)
	})
}
