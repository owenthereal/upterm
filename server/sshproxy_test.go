package server

import (
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	HostPublicKeyContent  = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOA+rMcwWFPJVE2g6EwRPkYmNJfaS/+gkyZ99aR/65uz`
	HostPrivateKeyContent = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDgPqzHMFhTyVRNoOhMET5GJjSX2kv/oJMmffWkf+ubswAAAIiu5GOBruRj
gQAAAAtzc2gtZWQyNTUxOQAAACDgPqzHMFhTyVRNoOhMET5GJjSX2kv/oJMmffWkf+ubsw
AAAEDBHlsR95C/pGVHtQGpgrUi+Qwgkfnp9QlRKdEhhx4rxOA+rMcwWFPJVE2g6EwRPkYm
NJfaS/+gkyZ99aR/65uzAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----`
)

func Test_sshProxy_dialUpstream(t *testing.T) {
	logger := log.New()
	logger.Level = log.DebugLevel

	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	if err != nil {
		t.Fatal(err)
	}

	cs := HostCertSigner{
		Hostnames: []string{"127.0.0.1"},
	}
	hostSigner, err := cs.SignCert(signer)
	if err != nil {
		t.Fatal(err)
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = proxyLn.Close()
	}()

	proxyAddr := proxyLn.Addr().String()
	cd := sidewayConnDialer{
		NodeAddr:        proxyAddr,
		NeighbourDialer: tcpConnDialer{},
		Logger:          logger,
	}
	proxy := &sshProxy{
		HostSigners:     []ssh.Signer{hostSigner},
		Signers:         []ssh.Signer{signer},
		NodeAddr:        proxyAddr,
		ConnDialer:      cd,
		Logger:          logger,
		MetricsProvider: provider.NewDiscardProvider(),
	}

	go func() {
		_ = proxy.Serve(proxyLn)
	}()

	if err := utils.WaitForServer(proxyAddr); err != nil {
		t.Fatal(err)
	}

	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = sshLn.Close()
	}()

	sshdAddr := sshLn.Addr().String()
	sshd := &sshd{
		HostSigners: []ssh.Signer{signer},
		NodeAddr:    sshdAddr,
		Logger:      logger,
	}

	go func() {
		_ = sshd.Serve(sshLn)
	}()

	if err := utils.WaitForServer(sshdAddr); err != nil {
		t.Fatal(err)
	}

	id := &api.Identifier{
		Id:       xid.New().String(),
		Type:     api.Identifier_CLIENT,
		NodeAddr: sshdAddr,
	}
	user, err := api.EncodeIdentifier(id)
	if err != nil {
		t.Fatal(err)
	}

	ucs, err := testCertSigner(user, signer)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		Name   string
		Signer ssh.Signer
	}{
		{
			Name:   "public-key auth",
			Signer: signer,
		},
		{
			Name:   "public-key user cert auth",
			Signer: ucs,
		},
	}

	for _, c := range cases {
		cc := c

		t.Run(c.Name, func(t *testing.T) {
			config := &ssh.ClientConfig{
				User:            user,
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(cc.Signer)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}
			client, err := ssh.Dial("tcp", proxyAddr, config) // proxy to sshd
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.NewSession()
			if err == nil || !strings.Contains(err.Error(), "unsupported channel type") {
				t.Fatalf("expect unsupported channel type error but got %v", err)
			}
		})
	}
}

func testCertSigner(user string, signer ssh.Signer) (ssh.Signer, error) {
	cert := &ssh.Certificate{
		Key:             signer.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "1234",
		ValidPrincipals: []string{user},
		ValidBefore:     ssh.CertTimeInfinity,
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}

	return ssh.NewCertSigner(cert, signer)
}

func Test_sshProxy_CheckAuthorizedKeys(t *testing.T) {
	logger := log.New()
	logger.Level = log.DebugLevel

	proxySigner, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	if err != nil {
		t.Fatal(err)
	}

	cs := HostCertSigner{
		Hostnames: []string{"127.0.0.1"},
	}

	proxyCertSigner, err := cs.SignCert(proxySigner)
	if err != nil {
		t.Fatal(err)
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	proxyAddr := proxyLn.Addr().String()

	cd := sidewayConnDialer{
		NodeAddr:         proxyAddr,
		NeighbourDialer:  tcpConnDialer{},
		Logger:           logger,
		SSHDDialListener: networks.Get("mem").SSHD(),
	}

	tempfile := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(tempfile, []byte(HostPublicKeyContent), 0600); err != nil {
		t.Fatal(err)
	}

	proxy := &sshProxy{
		HostSigners:        []ssh.Signer{proxyCertSigner},
		Signers:            []ssh.Signer{proxySigner},
		NodeAddr:           proxyAddr,
		ConnDialer:         cd,
		Logger:             logger,
		MetricsProvider:    provider.NewDiscardProvider(),
		AuthorizedKeysFile: tempfile,
	}

	go func() {
		_ = proxy.Serve(proxyLn)
	}()

	hostSigner, err := ssh.ParsePrivateKey([]byte(HostPrivateKeyContent))

	id := &api.Identifier{
		Id:       xid.New().String(),
		Type:     api.Identifier_HOST,
		NodeAddr: proxyAddr,
	}
	user, err := api.EncodeIdentifier(id)
	if err != nil {
		t.Fatal(err)
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(hostSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   upterm.HostSSHClientVersion,
	}

	_, err = ssh.Dial("tcp", proxyAddr, config) // proxy to sshd
	if err != nil {
		t.Fatal(err)
	}
}
