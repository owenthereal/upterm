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
)

type UserCertChecker struct {
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

	return parseAuthRequestFromCert(user, cert)
}

// parseAuthRequestFromCert parses auth request and public key from a cert.
// The public key is always the signature key of the cert.
func parseAuthRequestFromCert(principal string, cert *ssh.Certificate) (*AuthRequest, ssh.PublicKey, error) {
	key := cert.SignatureKey

	if cert.CertType != ssh.UserCert {
		return nil, key, fmt.Errorf("ssh: cert has type %d", cert.CertType)
	}

	checker := &ssh.CertChecker{}
	if err := checker.CheckCert(principal, cert); err != nil {
		return nil, key, err
	}

	if len(cert.Extensions) == 0 {
		return nil, key, errCertNotSignedByHost
	}

	ext, ok := cert.Extensions[upterm.SSHCertExtension]
	if !ok {
		return nil, key, errCertNotSignedByHost
	}

	var auth AuthRequest
	if err := proto.Unmarshal([]byte(ext), &auth); err != nil {
		return nil, key, err
	}

	key, _, _, _, err := ssh.ParseAuthorizedKey(auth.AuthorizedKey)
	if err != nil {
		return nil, key, fmt.Errorf("error parsing public key from auth request: %w", err)
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

	at := time.Now()
	bt := at.Add(1 * time.Minute) // cert valid for 1 min
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
