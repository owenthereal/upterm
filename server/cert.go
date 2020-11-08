package server

import (
	"crypto/rand"
	"fmt"
	"time"

	proto "github.com/golang/protobuf/proto"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

var (
	errCertNotSignedByHost = fmt.Errorf("ssh cert not signed by host")
)

type CertChecker struct {
}

func (c *CertChecker) Authenticate(user string, key ssh.PublicKey) (*AuthRequest, ssh.PublicKey, error) {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, nil, fmt.Errorf("public key not a cert")
	}

	return ParseAuthRequestFromCert(user, cert)
}

// ParseAuthRequestFromCert parses auth request and public key from a cert
func ParseAuthRequestFromCert(principal string, cert *ssh.Certificate) (*AuthRequest, ssh.PublicKey, error) {
	checker := &ssh.CertChecker{}
	if err := checker.CheckCert(principal, cert); err != nil {
		return nil, nil, err
	}

	if cert.Permissions.Extensions == nil {
		return nil, nil, errCertNotSignedByHost
	}

	ext, ok := cert.Permissions.Extensions[upterm.SSHCertExtension]
	if !ok {
		return nil, nil, errCertNotSignedByHost
	}

	var auth AuthRequest
	if err := proto.Unmarshal([]byte(ext), &auth); err != nil {
		return nil, nil, err
	}

	key, _, _, _, err := ssh.ParseAuthorizedKey(auth.AuthorizedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing public key from auth request: %w", err)
	}

	return &auth, key, nil
}

type UserCertSigner struct {
	SessionID   string
	User        string
	AuthRequest AuthRequest
}

func (g *UserCertSigner) SignCert(signer ssh.Signer) (ssh.Signer, error) {
	b, err := proto.Marshal(&g.AuthRequest)
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

	// TODO: use differnt key to sign
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
