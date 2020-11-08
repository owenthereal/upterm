package server

import (
	"fmt"

	proto "github.com/golang/protobuf/proto"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

var (
	errCertNotSignedByHost = fmt.Errorf("ssh cert not signed by host")
)

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
