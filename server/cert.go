package server

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

var (
	errCertNotSignedByHost = fmt.Errorf("ssh cert not signed by host")

	// errCertUntrustedAuthority reports a certificate whose signer is not an
	// authority this call site recognizes. The relay's front door tolerates it
	// and authorizes the certified key instead; the host's sshd and the
	// internal node listener refuse the connection.
	errCertUntrustedAuthority = fmt.Errorf("ssh cert signed by an unrecognized authority")
)

// certClockSkewTolerance widens the user cert validity window symmetrically
// around time.Now() so that the host's embedded sshd (which validates with
// its own time.Now()) accepts the cert despite NTP drift between machines.
// One minute matches step-ca's default and sits comfortably above typical
// drift on dev environments where this fails (Docker Desktop / Rancher
// Desktop / colima after suspend/resume). See issue #151.
const certClockSkewTolerance = 1 * time.Minute

type UserCertChecker struct {
	// IsUserAuthority reports whether a key may vouch for a certificate's
	// AuthRequest. Nil trusts nothing, so a call site that names no authority
	// gets no certificate identities: the safe direction to fail in, and the
	// one a future call site that forgets this field lands in.
	//
	// The relay names its own signing keys, because it is the only party that
	// mints upterm certificates. A host names the single relay key its host
	// key callback accepted.
	//
	// A relay offers one certificate per signing key, and x/crypto counts a
	// rejected public-key query against MaxAuthTries -- 6 by default, which
	// charm.land/ssh does not change. So a host pinning one key survives five
	// rejected offers and is disconnected on the sixth: the pinned key must be
	// among the first six a relay offers. One key, or two through a rotation,
	// is always fine. Raising the guest door's MaxAuthTries through a
	// ServerConfigCallback is the escape hatch if that ever binds.
	IsUserAuthority func(auth ssh.PublicKey) bool

	UserKeyFallback func(user string, key ssh.PublicKey) (ssh.PublicKey, error)
}

// Authenticate tries to pass auth request and public key from a cert.
// If the public key is not a cert, it calls the UserKeyFallback func. Otherwise it returns an error.
func (c *UserCertChecker) Authenticate(user string, key ssh.PublicKey) (*AuthRequest, ssh.PublicKey, error) {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		if c.UserKeyFallback != nil {
			key, err := c.UserKeyFallback(user, key)
			return nil, key, err
		}

		return nil, nil, fmt.Errorf("public key not a cert")
	}

	return parseAuthRequestFromCert(user, cert, c.IsUserAuthority)
}

// parseAuthRequestFromCert parses the auth request and public key from a cert.
//
// A nil error means all of: a user certificate, signed by an authority the
// caller recognizes, valid now, for this principal, carrying an AuthRequest
// that parsed. Two call sites act on the error alone -- the host's sshd and the
// internal node listener -- so nothing less may return nil.
//
// On every failure path the key returned is cert.Key: the key the certificate
// is for, and the one whose private half a peer that completes public-key
// authentication has proved it holds. It is never cert.SignatureKey, which
// identifies whoever signed the certificate and which a caller must not mistake
// for the peer. Even cert.Key is only a claim here, because this runs from
// PublicKeyCallback, which x/crypto also invokes for unsigned queries, before
// any signature exists.
//
// The authority is checked before the principal and the validity window, as
// x/crypto's own CertChecker.Authenticate does. A certificate from an unrelated
// CA names principals in some other realm, and reporting that as a principal
// mismatch would hide the fact that upterm never issued it.
func parseAuthRequestFromCert(principal string, cert *ssh.Certificate, isAuthority func(ssh.PublicKey) bool) (*AuthRequest, ssh.PublicKey, error) {
	if cert.CertType != ssh.UserCert {
		return nil, cert.Key, fmt.Errorf("ssh: cert has type %d", cert.CertType)
	}

	// ssh.CertChecker.CheckCert below verifies that the signature matches
	// cert.SignatureKey, and nothing more: it never asks whose key that is.
	// Only CertChecker.Authenticate does, and upterm does not call it. So this
	// check is the one standing between a self-signed certificate and an
	// identity of its own choosing.
	if isAuthority == nil || !isAuthority(cert.SignatureKey) {
		return nil, cert.Key, errCertUntrustedAuthority
	}

	checker := &ssh.CertChecker{}
	if err := checker.CheckCert(principal, cert); err != nil {
		return nil, cert.Key, err
	}

	ext, ok := cert.Extensions[upterm.SSHCertExtension]
	if !ok {
		return nil, cert.Key, errCertNotSignedByHost
	}

	var auth AuthRequest
	if err := proto.Unmarshal([]byte(ext), &auth); err != nil {
		return nil, cert.Key, err
	}

	key, _, _, _, err := ssh.ParseAuthorizedKey(auth.AuthorizedKey)
	if err != nil {
		return nil, cert.Key, fmt.Errorf("error parsing public key from auth request: %w", err)
	}

	return &auth, key, nil
}

type UserCertSigner struct {
	SessionID   string
	User        string
	AuthRequest *AuthRequest
}

func (g *UserCertSigner) SignCert(signer ssh.Signer) (ssh.Signer, error) {
	b, err := proto.Marshal(g.AuthRequest)
	if err != nil {
		return nil, fmt.Errorf("error marshaling auth request: %w", err)
	}

	now := time.Now()
	at := now.Add(-certClockSkewTolerance)
	bt := now.Add(certClockSkewTolerance)
	cert := &ssh.Certificate{
		Key:             signer.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           g.SessionID,
		ValidPrincipals: []string{g.User},
		ValidAfter:      uint64(at.Unix()),
		ValidBefore:     uint64(bt.Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{upterm.SSHCertExtension: string(b)},
		},
	}

	// TODO: use different key to sign
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, fmt.Errorf("error signing host cert: %w", err)
	}

	cs, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, fmt.Errorf("error generating host signer: %w", err)
	}

	return cs, nil
}

type HostCertSigner struct {
	Hostnames []string
}

func (s *HostCertSigner) SignCert(signer ssh.Signer) (ssh.Signer, error) {
	cert := &ssh.Certificate{
		Key:             signer.PublicKey(),
		CertType:        ssh.HostCert,
		KeyId:           "uptermd",
		ValidPrincipals: s.Hostnames,
		ValidBefore:     ssh.CertTimeInfinity,
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}

	return ssh.NewCertSigner(cert, signer)
}
