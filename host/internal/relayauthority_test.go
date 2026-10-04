package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
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

// hostCert certifies key as a host key for principals, signed by ca.
func hostCert(t *testing.T, ca ssh.Signer, key ssh.PublicKey, principals []string, validBefore uint64) *ssh.Certificate {
	t.Helper()

	cert := &ssh.Certificate{
		Key:             key,
		CertType:        ssh.HostCert,
		ValidPrincipals: principals,
		ValidBefore:     validBefore,
	}
	require.NoError(t, cert.SignCert(rand.Reader, ca))
	return cert
}

func TestPinnedRelayAuthority(t *testing.T) {
	relay, other, hostKey := testSigner(t), testSigner(t), testSigner(t)
	var a RelayAuthority
	require.NoError(t, a.Wrap(ssh.InsecureIgnoreHostKey())("relay.example:22", nil, relay.PublicKey()))
	pinned := a.Pinned()

	// A user certificate is the one shape the table's constructor cannot make.
	userCert := hostCert(t, relay, hostKey.PublicKey(), []string{"relay.example"}, ssh.CertTimeInfinity)
	userCert.CertType = ssh.UserCert
	require.NoError(t, userCert.SignCert(rand.Reader, relay))

	for name, tc := range map[string]struct {
		key ssh.PublicKey
		ok  bool
	}{
		"the same key":                      {relay.PublicKey(), true},
		"another key":                       {other.PublicKey(), false},
		"a cert for this host":              {hostCert(t, relay, hostKey.PublicKey(), []string{"relay.example"}, ssh.CertTimeInfinity), true},
		"a cert naming no host":             {hostCert(t, relay, hostKey.PublicKey(), nil, ssh.CertTimeInfinity), true},
		"a cert for another host":           {hostCert(t, relay, hostKey.PublicKey(), []string{"elsewhere.example"}, ssh.CertTimeInfinity), false},
		"an expired cert":                   {hostCert(t, relay, hostKey.PublicKey(), []string{"relay.example"}, 1), false},
		"a user cert":                       {userCert, false},
		"another authority's cert":          {hostCert(t, other, hostKey.PublicKey(), []string{"relay.example"}, ssh.CertTimeInfinity), false},
		"another authority certifying ours": {hostCert(t, other, relay.PublicKey(), []string{"relay.example"}, ssh.CertTimeInfinity), false},
	} {
		t.Run(name, func(t *testing.T) {
			err := pinned("relay.example:22", nil, tc.key)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			var changed *RelayKeyChangedError
			require.ErrorAs(t, err, &changed)
			require.Equal(t, "relay.example:22", changed.Hostname)
			require.Equal(t, tc.key, changed.Key)
			require.Error(t, changed.Err, "the checker's own reason is kept")
		})
	}

	// Neither a refusal nor an acceptance changes what is recorded.
	require.True(t, a.IsUserAuthority(relay.PublicKey()))
	require.False(t, a.IsUserAuthority(other.PublicKey()))
	require.NoError(t, a.CheckRedial("relay.example:22"))
	// What the first connection was shown is the plain key, so a redial asked
	// about another hostname still passes. It would not if Pinned had replaced
	// that with a certificate it accepted for relay.example, which is done here
	// last, not left to the order the table above ran in.
	require.NoError(t, pinned("relay.example:22", nil, hostCert(t, relay, hostKey.PublicKey(), []string{"relay.example"}, ssh.CertTimeInfinity)))
	require.NoError(t, a.CheckRedial("elsewhere.example:22"))

	var none RelayAuthority
	var changed *RelayKeyChangedError
	require.ErrorAs(t, none.Pinned()("relay.example:22", nil, relay.PublicKey()), &changed, "nothing recorded admits nothing")
	require.ErrorAs(t, none.Pinned()("relay.example:22", nil, hostCert(t, relay, hostKey.PublicKey(), nil, ssh.CertTimeInfinity)), &changed, "nothing recorded admits no certificate either")
	require.False(t, none.IsUserAuthority(relay.PublicKey()), "refusing must not record what it refused")
}

// The callback is a closure over the authority, not a copy of what it held
// when Pinned was called: the host builds it once and a handshake records into
// the authority afterwards.
func TestPinnedRelayAuthorityReadsWhatIsRecordedWhenItIsAsked(t *testing.T) {
	relay := testSigner(t)
	var a RelayAuthority
	pinned := a.Pinned()

	var changed *RelayKeyChangedError
	require.ErrorAs(t, pinned("relay.example:22", nil, relay.PublicKey()), &changed)

	require.NoError(t, a.Wrap(ssh.InsecureIgnoreHostKey())("relay.example:22", nil, relay.PublicKey()))
	require.NoError(t, pinned("relay.example:22", nil, relay.PublicKey()))
}

func TestPinnedAuthorityRedialsOverBothTransports(t *testing.T) {
	relay := startTestRelay(t, withHostCert)
	impostor := startTestRelay(t, withHostCert)
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)

	for _, scheme := range []string{"ssh", "ws"} {
		endpoint := func(r testRelay) *url.URL {
			if scheme == "ws" {
				return r.wsURL
			}
			return r.url
		}
		t.Run(scheme, func(t *testing.T) {
			var a RelayAuthority
			var asked atomic.Int32
			counting := func(string, net.Addr, ssh.PublicKey) error {
				asked.Add(1)
				return nil
			}

			first := relay.tunnel(hostKey[0], endpoint(relay))
			first.HostKeyCallback = a.Wrap(counting)
			_, err := first.Establish(t.Context())
			require.NoError(t, err)
			first.Close()
			require.EqualValues(t, 1, asked.Load())
			require.NoError(t, a.CheckRedial(endpoint(relay).Host))

			redial := relay.tunnel(hostKey[0], endpoint(relay))
			redial.HostKeyCallback = a.Pinned()
			_, err = redial.Establish(t.Context())
			require.NoError(t, err)
			t.Cleanup(redial.Close)
			require.EqualValues(t, 1, asked.Load(), "a redial asks nobody")

			// The same authority, redialled against a relay with another identity.
			wrong := impostor.tunnel(hostKey[0], endpoint(impostor))
			wrong.HostKeyCallback = a.Pinned()
			_, err = wrong.Establish(t.Context())
			var changed *RelayKeyChangedError
			require.ErrorAs(t, err, &changed)
			require.Equal(t, endpoint(impostor).Host, changed.Hostname)
			require.EqualValues(t, 1, asked.Load())
		})
	}
}

func TestCheckRedialSaysWhenARedialWouldBeRefused(t *testing.T) {
	relay, hostKey := testSigner(t), testSigner(t)
	const host = "relay.example:22"
	shown := func(key ssh.PublicKey) *RelayAuthority {
		var a RelayAuthority
		require.NoError(t, a.Wrap(ssh.InsecureIgnoreHostKey())(host, nil, key))
		return &a
	}

	for name, tc := range map[string]struct {
		key ssh.PublicKey
		ok  bool
	}{
		"a plain key":                 {relay.PublicKey(), true},
		"a cert for the hostname":     {hostCert(t, relay, hostKey.PublicKey(), []string{"relay.example"}, ssh.CertTimeInfinity), true},
		"a cert naming no host":       {hostCert(t, relay, hostKey.PublicKey(), nil, ssh.CertTimeInfinity), true},
		"a cert for another hostname": {hostCert(t, relay, hostKey.PublicKey(), []string{"203.0.113.7"}, ssh.CertTimeInfinity), false},
	} {
		t.Run(name, func(t *testing.T) {
			err := shown(tc.key).CheckRedial(host)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			var changed *RelayKeyChangedError
			require.ErrorAs(t, err, &changed)
			require.Equal(t, host, changed.Hostname)
		})
	}

	t.Run("nothing shown", func(t *testing.T) {
		var a RelayAuthority
		var changed *RelayKeyChangedError
		require.ErrorAs(t, a.CheckRedial(host), &changed)
	})

	t.Run("a key the callback refused", func(t *testing.T) {
		var a RelayAuthority
		refused := a.Wrap(func(string, net.Addr, ssh.PublicKey) error { return errors.New("refused") })
		require.Error(t, refused(host, nil, relay.PublicKey()))

		var changed *RelayKeyChangedError
		require.ErrorAs(t, a.CheckRedial(host), &changed, "a refused key is not what a redial pins")
	})
}

func TestRelayKeyChangedErrorReads(t *testing.T) {
	key := testSigner(t).PublicKey()
	cause := errors.New("ssh: no authorities for hostname")
	err := &RelayKeyChangedError{Hostname: "relay.example:22", Key: key, Err: cause}

	require.Equal(t,
		"the relay's key for relay.example:22 ("+utils.FingerprintSHA256(key)+") is not the one this session started with",
		err.Error())
	require.ErrorIs(t, err, cause)

	// A certificate is named by the key that signed it, as the host key prompt
	// does: the certificate's own digest is not one anyone can compare.
	ca := testSigner(t)
	cert := hostCert(t, ca, key, nil, ssh.CertTimeInfinity)
	require.Contains(t, (&RelayKeyChangedError{Hostname: "relay.example:22", Key: cert}).Error(),
		"("+utils.FingerprintSHA256(ca.PublicKey())+")")

	// A zero value is printable, as a table of expected errors builds one.
	require.Equal(t, "the relay's key for relay.example:22 is not the one this session started with",
		(&RelayKeyChangedError{Hostname: "relay.example:22"}).Error())
	require.Equal(t, "the relay's key is not the one this session started with", (&RelayKeyChangedError{}).Error())
	require.NoError(t, (&RelayKeyChangedError{}).Unwrap())
}

// Each refusal says what happened. Only a certificate that names the authority
// this session started with, refused anyway, has its own text: calling the
// recorded key a changed one there would contradict the fingerprint beside it.
func TestPinnedRelayAuthorityRefusalsReadAsWhatHappened(t *testing.T) {
	relay, other, hostKey := testSigner(t), testSigner(t), testSigner(t)
	const host = "relay.example:22"
	var a RelayAuthority
	require.NoError(t, a.Wrap(ssh.InsecureIgnoreHostKey())(host, nil, relay.PublicKey()))
	pinned := a.Pinned()

	userCert := hostCert(t, relay, hostKey.PublicKey(), []string{"relay.example"}, ssh.CertTimeInfinity)
	userCert.CertType = ssh.UserCert
	require.NoError(t, userCert.SignCert(rand.Reader, relay))

	changedKey := func(signer ssh.Signer) string {
		return "the relay's key for " + host + " (" + utils.FingerprintSHA256(signer.PublicKey()) + ") is not the one this session started with"
	}
	notAccepted := func(reason error) string {
		return "the relay presented a certificate for " + host + " that names the authority this session started with (" +
			utils.FingerprintSHA256(relay.PublicKey()) + "), but it was not accepted: " + reason.Error()
	}

	for name, tc := range map[string]struct {
		key ssh.PublicKey
		// want is the full message, given the checker's reason.
		want func(reason error) string
	}{
		"another key": {other.PublicKey(), func(error) string { return changedKey(other) }},
		"a cert for another host": {
			hostCert(t, relay, hostKey.PublicKey(), []string{"elsewhere.example"}, ssh.CertTimeInfinity), notAccepted,
		},
		"an expired cert": {
			hostCert(t, relay, hostKey.PublicKey(), []string{"relay.example"}, 1), notAccepted,
		},
		"a user cert": {userCert, notAccepted},
		// Not naming the authority, so it is a changed key, and it is named by
		// the key it names as its signer: other, not the recorded one.
		"another authority's cert": {
			hostCert(t, other, hostKey.PublicKey(), []string{"relay.example"}, ssh.CertTimeInfinity),
			func(error) string { return changedKey(other) },
		},
		"another authority certifying ours": {
			hostCert(t, other, relay.PublicKey(), []string{"relay.example"}, ssh.CertTimeInfinity),
			func(error) string { return changedKey(other) },
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed *RelayKeyChangedError
			require.ErrorAs(t, pinned(host, nil, tc.key), &changed)
			require.Equal(t, tc.want(changed.Err), changed.Error())
		})
	}

	t.Run("the reasons", func(t *testing.T) {
		var changed *RelayKeyChangedError
		require.ErrorAs(t, pinned(host, nil, hostCert(t, relay, hostKey.PublicKey(), []string{"elsewhere.example"}, ssh.CertTimeInfinity)), &changed)
		require.ErrorContains(t, changed.Err, `principal "relay.example" not in the set of valid principals`)

		require.ErrorAs(t, pinned(host, nil, hostCert(t, relay, hostKey.PublicKey(), []string{"relay.example"}, 1)), &changed)
		require.ErrorContains(t, changed.Err, "expired")
	})

	// The text says the certificate names the authority, not that the authority
	// signed it: this one only claims to. The checker looks at the principals
	// before the signature, so the reason given for it may be the principals'.
	t.Run("a forged certificate naming the authority", func(t *testing.T) {
		for name, tc := range map[string]struct {
			principals []string
			reason     string
		}{
			"refused for its principals first": {[]string{"elsewhere.example"}, "not in the set of valid principals"},
			"refused for its signature":        {[]string{"relay.example"}, "signature does not verify"},
		} {
			t.Run(name, func(t *testing.T) {
				forged := hostCert(t, other, hostKey.PublicKey(), tc.principals, ssh.CertTimeInfinity)
				forged.SignatureKey = relay.PublicKey()

				var changed *RelayKeyChangedError
				require.ErrorAs(t, pinned(host, nil, forged), &changed)
				require.ErrorContains(t, changed.Err, tc.reason)
				require.Equal(t, notAccepted(changed.Err), changed.Error())
				require.Contains(t, changed.Error(), "that names the authority")
				require.NotContains(t, changed.Error(), "from the authority")
			})
		}
	})

	// The first connection auto-accepted a certificate that does not name the
	// hostname, so every redial would be refused, and CheckRedial says so in
	// the same words as the refusal.
	t.Run("CheckRedial says it the same way", func(t *testing.T) {
		var first RelayAuthority
		cert := hostCert(t, relay, hostKey.PublicKey(), []string{"203.0.113.7"}, ssh.CertTimeInfinity)
		require.NoError(t, first.Wrap(ssh.InsecureIgnoreHostKey())(host, nil, cert))

		var changed *RelayKeyChangedError
		require.ErrorAs(t, first.CheckRedial(host), &changed)
		require.Equal(t, notAccepted(changed.Err), changed.Error())
	})

	t.Run("a certificate has no recorded authority to name when nothing is recorded", func(t *testing.T) {
		var none RelayAuthority
		var changed *RelayKeyChangedError
		require.ErrorAs(t, none.Pinned()(host, nil, hostCert(t, relay, hostKey.PublicKey(), nil, ssh.CertTimeInfinity)), &changed)
		require.Equal(t, changedKey(relay), changed.Error())
	})
}

func TestRelayKeyChangedErrorSurvivesWhatItIsGivenToPrint(t *testing.T) {
	const want = "the relay's key for relay.example:22 is not the one this session started with"

	// A typed nil is not a nil interface, and is not a certificate to read.
	var none *ssh.Certificate
	require.Equal(t, want, (&RelayKeyChangedError{Hostname: "relay.example:22", Key: none}).Error())

	// A certificate with nothing to name it by.
	require.Equal(t, want, (&RelayKeyChangedError{Hostname: "relay.example:22", Key: &ssh.Certificate{}}).Error())

	// The authority's text needs a reason to give. Without one the message is
	// the other, not a half-sentence.
	ca := testSigner(t)
	cert := hostCert(t, ca, testSigner(t).PublicKey(), nil, ssh.CertTimeInfinity)
	fingerprint := utils.FingerprintSHA256(ca.PublicKey())
	err := &RelayKeyChangedError{Hostname: "relay.example:22", Key: cert, fromAuthority: true}
	require.Equal(t, "the relay's key for relay.example:22 ("+fingerprint+") is not the one this session started with", err.Error())

	// And with no hostname the text still reads.
	err = &RelayKeyChangedError{Key: cert, Err: errors.New("no"), fromAuthority: true}
	require.Equal(t, "the relay presented a certificate that names the authority this session started with ("+fingerprint+"), but it was not accepted: no", err.Error())

	// The marker alone, on a zero value.
	require.Equal(t, "the relay's key is not the one this session started with", (&RelayKeyChangedError{fromAuthority: true}).Error())
}
