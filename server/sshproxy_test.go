package server

import (
	"context"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/utils"
	"github.com/rs/xid"
	"golang.org/x/crypto/ssh"
)

func Test_sshProxy_dialUpstream(t *testing.T) {
	logger := logging.Must(logging.Console(), logging.Debug()).Logger

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
		SessionManager:  newEmbeddedSessionManager(logger),
		NodeAddr:        proxyAddr,
		ConnDialer:      cd,
		Logger:          logger,
		MetricsProvider: provider.NewDiscardProvider(),
	}

	go func() {
		_ = proxy.Serve(proxyLn)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := utils.WaitForServer(ctx, proxyAddr); err != nil {
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
		SessionManager: newEmbeddedSessionManager(logger),
		HostSigners:    []ssh.Signer{signer},
		NodeAddr:       sshdAddr,
		Logger:         logger,
	}

	go func() {
		_ = sshd.Serve(sshLn)
	}()

	if err := utils.WaitForServer(ctx, sshdAddr); err != nil {
		t.Fatal(err)
	}

	encoder := routing.NewEncodeDecoder(routing.ModeEmbedded)
	user := encoder.Encode(xid.New().String(), sshdAddr)
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
