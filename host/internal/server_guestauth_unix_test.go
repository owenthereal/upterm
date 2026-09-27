//go:build !windows

package internal

import (
	"testing"

	"github.com/owenthereal/upterm/server"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// testSigner comes from relayauthority_test.go, which carries no build tag, so
// it is available here.

// guestCert mints the credential a relay would: a user certificate for
// principal "guest" whose AuthRequest names authorizedKey.
func guestCert(t *testing.T, relay ssh.Signer, authorizedKey ssh.PublicKey) ssh.Signer {
	t.Helper()

	ucs := server.UserCertSigner{
		SessionID:   t.Name(),
		User:        "guest",
		AuthRequest: &server.AuthRequest{AuthorizedKey: ssh.MarshalAuthorizedKey(authorizedKey)},
	}
	signer, err := ucs.SignCert(relay)
	require.NoError(t, err)
	return signer
}

// Review Focus 2: relay B is a real relay, but not the one this host verified.
func TestGuestCertFromAnotherAuthorityIsRefused(t *testing.T) {
	authorized := testSigner(t)
	h := startHost(t, &Server{
		Command:        []string{"sh", "-c", "sleep 30"},
		AuthorizedKeys: []ssh.PublicKey{authorized.PublicKey()},
	})

	// A different relay, minting a certificate that names the authorized key.
	other := testSigner(t)
	forged := guestCert(t, other, authorized.PublicKey())

	_, _, _, err := h.dialGuest(t, withGuestSigners(forged))
	require.Error(t, err, "a certificate from an unverified relay must not authenticate")
}

// The same, with no allowlist. This is the branch that accepts every guest once
// the certificate has been believed, so it must never be reached by one that
// has not.
func TestGuestCertFromAnotherAuthorityIsRefusedWithNoAllowlist(t *testing.T) {
	h := startHost(t, &Server{Command: []string{"sh", "-c", "sleep 30"}})

	other := testSigner(t)
	forged := guestCert(t, other, testSigner(t).PublicKey())

	_, _, _, err := h.dialGuest(t, withGuestSigners(forged))
	require.Error(t, err)
}

func TestGuestCertFromTheVerifiedRelayIsAccepted(t *testing.T) {
	authorized := testSigner(t)
	h := startHost(t, &Server{
		Command:        []string{"sh", "-c", "stty -echo -opost; printf 'in\\n'; sleep 30"},
		AuthorizedKeys: []ssh.PublicKey{authorized.PublicKey()},
	})

	good := guestCert(t, h.relaySigner, authorized.PublicKey())

	_, out, _, err := h.dialGuest(t, withGuestSigners(good))
	require.NoError(t, err)
	readUntil(t, out, "in")
}

func TestGuestIsRefusedWhenNoRelayAuthorityWasRecorded(t *testing.T) {
	authorized := testSigner(t)
	h := startHostNoRelayAuthority(t, &Server{
		Command:        []string{"sh", "-c", "sleep 30"},
		AuthorizedKeys: []ssh.PublicKey{authorized.PublicKey()},
	})

	// Signed by the very key the harness's relay uses. With nothing recorded
	// there is no authority, so it is still refused.
	good := guestCert(t, h.relaySigner, authorized.PublicKey())

	_, _, _, err := h.dialGuest(t, withGuestSigners(good))
	require.Error(t, err, "a door with no recorded relay must admit nobody")
}

func TestGuestPlainPublicKeyIsRefused(t *testing.T) {
	authorized := testSigner(t)
	h := startHost(t, &Server{
		Command:        []string{"sh", "-c", "sleep 30"},
		AuthorizedKeys: []ssh.PublicKey{authorized.PublicKey()},
	})

	// No certificate at all: the guest door has no UserKeyFallback, so even the
	// authorized key itself cannot join without the relay's credential.
	_, _, _, err := h.dialGuest(t, withGuestSigners(authorized))
	require.Error(t, err)
}

// The MaxAuthTries bound the design documents: x/crypto counts a *rejected*
// public-key query against MaxAuthTries, which charm.land/ssh leaves at
// x/crypto's default of 6. A relay offers one certificate per signing key, so
// the pinned key has to be among the first six.
func TestGuestSurvivesFiveRejectedOffersBeforeTheAcceptedOne(t *testing.T) {
	authorized := testSigner(t)
	h := startHost(t, &Server{
		Command:        []string{"sh", "-c", "stty -echo -opost; printf 'in\\n'; sleep 30"},
		AuthorizedKeys: []ssh.PublicKey{authorized.PublicKey()},
	})

	var signers []ssh.Signer
	for i := 0; i < 5; i++ {
		signers = append(signers, guestCert(t, testSigner(t), authorized.PublicKey()))
	}
	signers = append(signers, guestCert(t, h.relaySigner, authorized.PublicKey()))

	_, out, _, err := h.dialGuest(t, withGuestSigners(signers...))
	require.NoError(t, err, "five rejected offers must still leave the sixth usable")
	readUntil(t, out, "in")
}

func TestGuestIsDisconnectedAfterSixRejectedOffers(t *testing.T) {
	authorized := testSigner(t)
	h := startHost(t, &Server{
		Command:        []string{"sh", "-c", "sleep 30"},
		AuthorizedKeys: []ssh.PublicKey{authorized.PublicKey()},
	})

	var signers []ssh.Signer
	for i := 0; i < 6; i++ {
		signers = append(signers, guestCert(t, testSigner(t), authorized.PublicKey()))
	}
	signers = append(signers, guestCert(t, h.relaySigner, authorized.PublicKey()))

	_, _, _, err := h.dialGuest(t, withGuestSigners(signers...))
	require.Error(t, err, "the sixth rejection hits MaxAuthTries, so the good offer is never reached")
}
