package server

import (
	"net"
	"strings"
	"testing"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/utils"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func Test_SSHProxy_findUpstream(t *testing.T) {
	logger := log.New()
	logger.Level = log.DebugLevel

	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	if err != nil {
		t.Fatal(err)
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	proxyAddr := proxyLn.Addr().String()
	cd := &connDialer{
		NodeAddr:         proxyAddr,
		DialNodeAddrFunc: func(addr string) (net.Conn, error) { return net.Dial("tcp", addr) },
		Logger:           logger,
	}
	proxy := &SSHProxy{
		HostSigners:     []ssh.Signer{signer},
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
	defer sshLn.Close()

	sshdAddr := sshLn.Addr().String()
	sshd := &SSHD{
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

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", proxyAddr, config) // proxy to sshd
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.NewSession()
	if err == nil || !strings.Contains(err.Error(), "unsupported channel type") {
		t.Fatalf("expect unsupported channle type error but got %v", err)
	}
}
