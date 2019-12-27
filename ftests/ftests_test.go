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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jingweno/upterm/host"
	"github.com/jingweno/upterm/server"
	"github.com/jingweno/upterm/utils"
	"github.com/pborman/ansi"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var (
	serverPublicKey  string
	serverPrivateKey string
	hostPublicKey    string
	hostPrivateKey   string
	clientPublicKey  string
	clientPrivateKey string
)

const (
	serverPublicKeyContent  = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7wM3URdkoip/GKliykxrkz5k5U9OeX3y/bE0Nz/Pl6`
	serverPrivateKeyContent = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAO8DN1EXZKIqfxipYspMa5M+ZOVPTnl98v2xNDc/z5egAAAIj7+f6n+/n+
pwAAAAtzc2gtZWQyNTUxOQAAACAO8DN1EXZKIqfxipYspMa5M+ZOVPTnl98v2xNDc/z5eg
AAAECJxt3qnAWGGklvhi4HTwyzY3EdjOAKpgXvcYTX6mDa+g7wM3URdkoip/GKliykxrkz
5k5U9OeX3y/bE0Nz/Pl6AAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----`
	hostPublicKeyContent  = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOA+rMcwWFPJVE2g6EwRPkYmNJfaS/+gkyZ99aR/65uz`
	hostPrivateKeyContent = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDgPqzHMFhTyVRNoOhMET5GJjSX2kv/oJMmffWkf+ubswAAAIiu5GOBruRj
gQAAAAtzc2gtZWQyNTUxOQAAACDgPqzHMFhTyVRNoOhMET5GJjSX2kv/oJMmffWkf+ubsw
AAAEDBHlsR95C/pGVHtQGpgrUi+Qwgkfnp9QlRKdEhhx4rxOA+rMcwWFPJVE2g6EwRPkYm
NJfaS/+gkyZ99aR/65uzAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----`
	clientPublicKeyContent  = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN0EWrjdcHcuMfI8bGAyHPcGsAc/vd/gl5673pRkRBGY`
	clientPrivateKeyContent = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDdBFq43XB3LjHyPGxgMhz3BrAHP73f4Jeeu96UZEQRmAAAAIiRPFazkTxW
swAAAAtzc2gtZWQyNTUxOQAAACDdBFq43XB3LjHyPGxgMhz3BrAHP73f4Jeeu96UZEQRmA
AAAEDmpjZHP/SIyBTp6YBFPzUi18iDo2QHolxGRDpx+m7let0EWrjdcHcuMfI8bGAyHPcG
sAc/vd/gl5673pRkRBGYAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----`
)

var (
	singleNodeServer TestServer
	router           TestServer
)

func TestMain(m *testing.M) {
	err := writeKeyPairs()
	if err != nil {
		log.Fatal(err)
	}
	defer removeKeyPairs()

	// start the single-node server
	singleNodeServer, err = NewServer(false)
	if err != nil {
		log.Fatal(err)
	}

	router, err = NewRouter()
	if err != nil {
		log.Fatal(err)
	}

	exitCode := m.Run()

	router.Shutdown()
	singleNodeServer.Shutdown()

	os.Exit(exitCode)
}

type TestServer interface {
	Addr() string
	HostAddr() string
	Shutdown()
}

func NewServer(upstreamNode bool) (TestServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	s := &Server{ln: ln, upstreamNode: upstreamNode}
	go func() {
		if err := s.start(); err != nil {
			log.WithError(err).Info("error starting test server")
		}
	}()

	return s, waitForServer(s.Addr())
}

func NewRouter() (TestServer, error) {
	// start the multi-node server
	multiNodeServer, err := NewServer(true)
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	r := &Router{ln: ln, multiNodeServer: multiNodeServer}
	go func() {
		if err := r.start(); err != nil {
			log.WithError(err).Info("error starting test router")
		}
	}()

	return r, waitForServer(r.Addr())
}

type Router struct {
	ln              net.Listener
	multiNodeServer TestServer
	*server.GlobalRouter
}

func (r *Router) start() error {
	signers, err := utils.CreateSigners([][]byte{[]byte(serverPrivateKeyContent)})
	if err != nil {
		return err
	}

	r.GlobalRouter = &server.GlobalRouter{
		HostSigners:  signers,
		UpstreamHost: r.multiNodeServer.Addr(),
		Logger:       log.New(),
	}

	return r.GlobalRouter.Serve(r.ln)
}

func (r *Router) Addr() string {
	return r.ln.Addr().String()
}

func (r *Router) HostAddr() string {
	return r.multiNodeServer.HostAddr()
}

func (r *Router) Shutdown() {
	r.GlobalRouter.Shutdown()
	r.multiNodeServer.Shutdown()
}

type Server struct {
	ln net.Listener
	*server.Server
	upstreamNode bool
}

func (s *Server) start() error {
	provider := &server.MemoryProvider{}
	provider.SetOpts(nil)
	s.Server = &server.Server{
		HostAddr:        s.Addr(),
		UpstreamNode:    s.upstreamNode,
		HostPrivateKeys: [][]byte{[]byte(serverPrivateKeyContent)},
		NetworkProvider: provider,
		Logger:          log.New(),
	}

	return s.Server.Serve(s.ln)
}

func (s *Server) Addr() string {
	return s.ln.Addr().String()
}

func (s *Server) HostAddr() string {
	return s.Server.HostAddr
}

func (s *Server) Shutdown() {
	s.Server.Shutdown()
}

type Host struct {
	*host.Host

	Command         []string
	JoinCommand     []string
	PrivateKeys     []string
	AdminSocketFile string

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
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(clientPublicKeyContent))
	if err != nil {
		return err
	}

	if c.AdminSocketFile == "" {
		adminSockDir, err := newAdminSocketDir()
		if err != nil {
			return err
		}
		defer os.RemoveAll(adminSockDir)

		c.AdminSocketFile = filepath.Join(adminSockDir, "upterm.sock")
	}

	c.Host = &host.Host{
		Host:            addr,
		Command:         c.Command,
		JoinCommand:     c.JoinCommand,
		Signers:         signers,
		AuthorizedKeys:  []ssh.PublicKey{pk},
		AdminSocketFile: c.AdminSocketFile,
		KeepAlive:       time.Duration(10),
		Logger:          log.New(),
		Stdin:           stdinr,
		Stdout:          stdoutw,
		SessionID:       xid.New().String(),
	}

	errCh := make(chan error)
	go func() {
		if err := c.Host.Run(c.ctx); err != nil {
			log.WithError(err).Info("error running host")
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
			log.WithError(err).Info("error copying from stdout")
		}
	}()

	// input
	go func() {
		hostWg.Done()
		for c := range c.inputCh {
			if _, err := io.Copy(stdinw, bytes.NewBufferString(c+"\n")); err != nil {
				log.WithError(err).Info("error copying to stdin")
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
	sshClient *ssh.Client
	session   *ssh.Session
	sshStdin  io.WriteCloser
	sshStdout io.Reader
	inputCh   chan string
	outputCh  chan string
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

func (c *Client) Join(clientID, addr string) error {
	c.init()

	auths, err := authMethodsFromFiles([]string{clientPrivateKey})
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User:            clientID,
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
			log.WithError(err).Info("error copying from stdout")
		}
	}()

	// input
	go func() {
		remoteWg.Done()
		for s := range c.inputCh {
			if _, err := io.Copy(c.sshStdin, bytes.NewBufferString(s+"\n")); err != nil {
				log.WithError(err).Info("error copying to stdin")
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
			w.Write([]byte(str))
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

func waitForServer(addr string) error {
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

	return nil
}

type writeFunc func(p []byte) (n int, err error)

func (rf writeFunc) Write(p []byte) (n int, err error) { return rf(p) }

func writeKeyPairs() error {
	var err error

	serverPublicKey, err = writeTempFile("id_ed25519.pub", serverPublicKeyContent)
	if err != nil {
		return err
	}

	serverPrivateKey, err = writeTempFile("id_ed25519", serverPrivateKeyContent)
	if err != nil {
		return err
	}

	hostPublicKey, err = writeTempFile("id_ed25519.pub", hostPublicKeyContent)
	if err != nil {
		return err
	}

	hostPrivateKey, err = writeTempFile("id_ed25519", hostPrivateKeyContent)
	if err != nil {
		return err
	}

	clientPublicKey, err = writeTempFile("id_ed25519.pub", clientPublicKeyContent)
	if err != nil {
		return err
	}

	clientPrivateKey, err = writeTempFile("id_ed25519", clientPrivateKeyContent)
	if err != nil {
		return err
	}

	return nil
}

func removeKeyPairs() {
	os.Remove(serverPublicKey)
	os.Remove(serverPrivateKey)
	os.Remove(hostPublicKey)
	os.Remove(hostPrivateKey)
	os.Remove(clientPublicKey)
	os.Remove(clientPrivateKey)
}

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
