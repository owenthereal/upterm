package server

import (
	"fmt"

	proto "github.com/golang/protobuf/proto"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

// TODO: check cert comes from a public key
func ParseAuthRequestFromCert(principal string, cert *ssh.Certificate) (*AuthRequest, error) {
	checker := &ssh.CertChecker{}
	if err := checker.CheckCert(principal, cert); err != nil {
		return nil, err
	}

	ext, ok := cert.Permissions.Extensions[upterm.SSHCertExtension]
	if !ok {
		return nil, fmt.Errorf("cert missing upterm ssh cert ext")
	}

	var auth AuthRequest
	if err := proto.Unmarshal([]byte(ext), &auth); err != nil {
		return nil, err
	}

	return &auth, nil
}
