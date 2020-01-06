package ftests

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jingweno/upterm/host"
	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/host/api/swagger/models"
	"github.com/jingweno/upterm/server"
	"github.com/jingweno/upterm/utils"
	"github.com/pborman/ansi"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	ServerPublicKeyContent  = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7wM3URdkoip/GKliykxrkz5k5U9OeX3y/bE0Nz/Pl6`
	ServerPrivateKeyContent = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAO8DN1EXZKIqfxipYspMa5M+ZOVPTnl98v2xNDc/z5egAAAIj7+f6n+/n+
pwAAAAtzc2gtZWQyNTUxOQAAACAO8DN1EXZKIqfxipYspMa5M+ZOVPTnl98v2xNDc/z5eg
AAAECJxt3qnAWGGklvhi4HTwyzY3EdjOAKpgXvcYTX6mDa+g7wM3URdkoip/GKliykxrkz
5k5U9OeX3y/bE0Nz/Pl6AAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----`
	HostPublicKeyContent  = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOA+rMcwWFPJVE2g6EwRPkYmNJfaS/+gkyZ99aR/65uz`
	HostPrivateKeyContent = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDgPqzHMFhTyVRNoOhMET5GJjSX2kv/oJMmffWkf+ubswAAAIiu5GOBruRj
gQAAAAtzc2gtZWQyNTUxOQAAACDgPqzHMFhTyVRNoOhMET5GJjSX2kv/oJMmffWkf+ubsw
AAAEDBHlsR95C/pGVHtQGpgrUi+Qwgkfnp9QlRKdEhhx4rxOA+rMcwWFPJVE2g6EwRPkYm
NJfaS/+gkyZ99aR/65uzAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----`
	ClientPublicKeyContent  = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN0EWrjdcHcuMfI8bGAyHPcGsAc/vd/gl5673pRkRBGY`
	ClientPrivateKeyContent = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDdBFq43XB3LjHyPGxgMhz3BrAHP73f4Jeeu96UZEQRmAAAAIiRPFazkTxW
swAAAAtzc2gtZWQyNTUxOQAAACDdBFq43XB3LjHyPGxgMhz3BrAHP73f4Jeeu96UZEQRmA
AAAEDmpjZHP/SIyBTp6YBFPzUi18iDo2QHolxGRDpx+m7let0EWrjdcHcuMfI8bGAyHPcG
sAc/vd/gl5673pRkRBGYAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----`
)

var TestCases = []func(*testing.T, TestServer){
	testClientAttachHostWithSameCommand,
	testClientAttachHostWithDifferentCommand,
	testHostFailToShareWithoutPrivateKey,
	testHostSessionCreatedCallback,
	testHostUnknownClient,
}

var (
	HostPrivateKey   string
	ClientPrivateKey string
)

func RunServerTest(t *testing.T, name string, ts TestServer, tc []func(*testing.T, TestServer)) {
	for _, test := range tc {
		testLocal := test

		t.Run(funcName(testLocal)+"/"+name, func(t *testing.T) {
			t.Parallel()
			testLocal(t, ts)
		})
	}
}

func funcName(i interface{}) string {
	name := runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
	split := strings.Split(name, ".")

	return split[len(split)-1]
}

type TestServer interface {
	Addr() string
	NodeAddr() string
	Shutdown()
}

func NewServer(hostKey string, upstreamNode bool) (TestServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	s := &Server{
		hostKeyContent: hostKey,
		ln:             ln,
		upstreamNode:   upstreamNode,
	}
	go func() {
		if err := s.start(); err != nil {
			log.WithError(err).Error("error starting test server")
		}
	}()

	return s, WaitForServer(s.Addr())
}

type Server struct {
	*server.Server

	hostKeyContent string
	ln             net.Listener
	upstreamNode   bool
}

func (s *Server) start() error {
	signers, err := utils.CreateSigners([][]byte{[]byte(s.hostKeyContent)})
	if err != nil {
		return err
	}

	provider := &server.MemoryProvider{}
	_ = provider.SetOpts(nil)
	s.Server = &server.Server{
		HostSigners:     signers,
		NodeAddr:        s.Addr(),
		UpstreamNode:    s.upstreamNode,
		NetworkProvider: provider,
		Logger:          log.New(),
	}

	return s.Server.Serve(s.ln)
}

func (s *Server) Addr() string {
	return s.ln.Addr().String()
}

func (s *Server) NodeAddr() string {
	return s.Server.NodeAddr
}

func (s *Server) Shutdown() {
	s.Server.Shutdown()
}

func WaitForServer(addr string) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	count := 0

	for range ticker.C {
		log.WithField("addr", addr).Info("waiting for server")
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			count++
			if count >= 10 {
				return fmt.Errorf("waiting for unix socket failed")
			}
			continue
		}

		conn.Close()
		break
	}

	return nil
}

type Host struct {
	*host.Host

	Command                  []string
	ForceCommand             []string
	PrivateKeys              []string
	SessionID                string
	AdminSocketFile          string
	SessionCreatedCallback   func(*models.APIGetSessionResponse) error
	PermittedClientPublicKey string

	inputCh  chan string
	outputCh chan string
	ctx      context.Context
	cancel   func()
}

func (c *Host) Close() {
	c.cancel()
}

func (c *Host) init() {
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.inputCh = make(chan string)
	c.outputCh = make(chan string)
}

func (c *Host) Share(addr string) error {
	c.init()

	stdinr, stdinw, err := os.Pipe()
	if err != nil {
		return err
	}

	stdoutr, stdoutw, err := os.Pipe()
	if err != nil {
		return err
	}

	signers, err := host.SignersFromFiles(c.PrivateKeys)
	if err != nil {
		return err
	}

	// permit client public key
	var authorizedKeys []ssh.PublicKey
	if c.PermittedClientPublicKey != "" {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.PermittedClientPublicKey))
		if err != nil {
			return err
		}
		authorizedKeys = append(authorizedKeys, pk)
	}

	if c.AdminSocketFile == "" {
		adminSockDir, err := newAdminSocketDir()
		if err != nil {
			return err
		}
		defer os.RemoveAll(adminSockDir)

		c.AdminSocketFile = filepath.Join(adminSockDir, "upterm.sock")
	}

	if c.SessionID == "" {
		c.SessionID = xid.New().String()
	}

	c.Host = &host.Host{
		Host:                   addr,
		Command:                c.Command,
		ForceCommand:           c.ForceCommand,
		Signers:                signers,
		AuthorizedKeys:         authorizedKeys,
		AdminSocketFile:        c.AdminSocketFile,
		SessionCreatedCallback: c.SessionCreatedCallback,
		KeepAlive:              time.Duration(10),
		Logger:                 log.New(),
		Stdin:                  stdinr,
		Stdout:                 stdoutw,
		SessionID:              c.SessionID,
	}

	errCh := make(chan error)
	go func() {
		if err := c.Host.Run(c.ctx); err != nil {
			log.WithError(err).Error("error running host")
			errCh <- err
		}
	}()

	if err := waitForUnixSocket(c.AdminSocketFile, errCh); err != nil {
		return err
	}

	var hostWg sync.WaitGroup
	hostWg.Add(2)

	// output
	go func() {
		hostWg.Done()
		w := writeFunc(func(p []byte) (int, error) {
			b, err := ansi.Strip(p)
			if err != nil {
				return 0, err
			}
			c.outputCh <- string(b)
			return len(p), nil
		})
		if _, err := io.Copy(w, stdoutr); err != nil {
			log.WithError(err).Error("error copying from stdout")
		}
	}()

	// input
	go func() {
		hostWg.Done()
		for c := range c.inputCh {
			if _, err := io.Copy(stdinw, bytes.NewBufferString(c+"\n")); err != nil {
				log.WithError(err).Error("error copying to stdin")
			}
		}
	}()

	hostWg.Wait()

	return nil
}

func (c *Host) InputOutput() (chan string, chan string) {
	return c.inputCh, c.outputCh
}

type Client struct {
	PrivateKeys []string
	sshClient   *ssh.Client
	session     *ssh.Session
	sshStdin    io.WriteCloser
	sshStdout   io.Reader
	inputCh     chan string
	outputCh    chan string
}

func (c *Client) init() {
	c.inputCh = make(chan string)
	c.outputCh = make(chan string)
}

func (c *Client) InputOutput() (chan string, chan string) {
	return c.inputCh, c.outputCh
}

func (c *Client) Close() {
	c.session.Close()
	c.sshClient.Close()
}

func (c *Client) Join(session *models.APIGetSessionResponse, addr string) error {
	c.init()

	auths, err := authMethodsFromFiles(c.PrivateKeys)
	if err != nil {
		return err
	}

	user, err := api.EncodeIdentifierSession(session)
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	c.sshClient, err = ssh.Dial("tcp", addr, config)
	if err != nil {
		return err
	}

	c.session, err = c.sshClient.NewSession()
	if err != nil {
		return err
	}

	if err = c.session.RequestPty("xterm", 40, 80, ssh.TerminalModes{}); err != nil {
		return err
	}

	c.sshStdin, err = c.session.StdinPipe()
	if err != nil {
		return err
	}

	c.sshStdout, err = c.session.StdoutPipe()
	if err != nil {
		return err
	}

	if err = c.session.Shell(); err != nil {
		return err
	}

	var remoteWg sync.WaitGroup
	remoteWg.Add(2)

	// output
	go func() {
		remoteWg.Done()
		w := writeFunc(func(pp []byte) (int, error) {
			b, err := ansi.Strip(pp)
			if err != nil {
				return 0, err
			}
			c.outputCh <- string(b)
			return len(pp), nil
		})
		if _, err := io.Copy(w, c.sshStdout); err != nil {
			log.WithError(err).Error("error copying from stdout")
		}
	}()

	// input
	go func() {
		remoteWg.Done()
		for s := range c.inputCh {
			if _, err := io.Copy(c.sshStdin, bytes.NewBufferString(s+"\n")); err != nil {
				log.WithError(err).Error("error copying to stdin")
			}
		}
	}()

	remoteWg.Wait()

	return nil
}

func scanner(ch chan string) *bufio.Scanner {
	r, w := io.Pipe()
	s := bufio.NewScanner(r)

	go func() {
		for str := range ch {
			_, _ = w.Write([]byte(str))
		}

	}()

	return s
}

func scan(s *bufio.Scanner) string {
	for s.Scan() {
		return strings.TrimSpace(s.Text())
	}

	return s.Err().Error()
}

func waitForUnixSocket(socket string, errCh chan error) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	count := 0
	for {
		select {
		case err := <-errCh:
			return err
		case <-ticker.C:
			log.WithField("socket", socket).Info("waiting for unix socket")
			if _, err := os.Stat(socket); err == nil {
				return nil
			}
			count++
			if count >= 10 {
				return fmt.Errorf("waiting for unix socket failed")
			}
		}
	}
}

type writeFunc func(p []byte) (n int, err error)

func (rf writeFunc) Write(p []byte) (n int, err error) { return rf(p) }

func authMethodsFromFiles(privateKeys []string) ([]ssh.AuthMethod, error) {
	signers, err := host.SignersFromFiles(privateKeys)
	if err != nil {
		return nil, err
	}

	var auths []ssh.AuthMethod
	for _, signer := range signers {
		auths = append(auths, ssh.PublicKeys(signer))
	}

	return auths, nil
}

func SetupKeyPairs() (func(), error) {
	var err error

	HostPrivateKey, err = writeTempFile("id_ed25519", HostPrivateKeyContent)
	if err != nil {
		return nil, err
	}

	ClientPrivateKey, err = writeTempFile("id_ed25519", ClientPrivateKeyContent)
	if err != nil {
		return nil, err
	}

	remove := func() {
		os.Remove(HostPrivateKey)
		os.Remove(ClientPrivateKey)
	}

	return remove, nil
}

func writeTempFile(name, content string) (string, error) {
	file, err := ioutil.TempFile("", name)
	if err != nil {
		return "", err
	}
	defer file.Close()

	if _, err := file.Write([]byte(content)); err != nil {
		return "", err
	}

	return file.Name(), nil
}
