package ftests

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/oklog/run"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	uio "github.com/owenthereal/upterm/io"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/owenthereal/upterm/ws"
	"github.com/pborman/ansi"
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

var (
	HostPrivateKey   string
	ClientPrivateKey string

	ts1 TestServer
	ts2 TestServer
)

func TestMain(m *testing.M) {
	remove, err := SetupKeyPairs()
	if err != nil {
		log.Fatal(err)
	}
	defer remove()

	ts1, err = NewServer(ServerPrivateKeyContent)
	if err != nil {
		log.Fatal(err)
	}
	ts2, err = NewServer(ServerPrivateKeyContent)
	if err != nil {
		log.Fatal(err)
	}

	exitCode := m.Run()

	ts1.Shutdown()
	ts2.Shutdown()

	os.Exit(exitCode)
}

func Test_ftest(t *testing.T) {
	testCases := []func(t *testing.T, hostURL, hostNodeAddr, clientJoinURL string){
		testHostNoAuthorizedKeyAnyClientJoin,
		testClientAuthorizedKeyNotMatching,
		testClientNonExistingSession,
		testClientAttachHostWithSameCommand,
		testClientAttachHostWithDifferentCommand,
		testClientAttachReadOnly,
		testHostFailToShareWithoutPrivateKey,
		testHostSessionCreatedCallback,
		testHostClientCallback,
	}

	for _, test := range testCases {
		testLocal := test

		t.Run("ssh/singleNode/"+funcName(testLocal), func(t *testing.T) {
			t.Parallel()
			testLocal(t, "ssh://"+ts1.SSHAddr(), ts1.NodeAddr(), "ssh://"+ts1.SSHAddr())
		})

		t.Run("ws/singleNode/"+funcName(testLocal), func(t *testing.T) {
			t.Parallel()
			testLocal(t, "ws://"+ts1.WSAddr(), ts1.NodeAddr(), "ws://"+ts1.WSAddr())
		})

		t.Run("ssh/multiNodes/"+funcName(testLocal), func(t *testing.T) {
			t.Parallel()
			testLocal(t, "ssh://"+ts1.SSHAddr(), ts1.NodeAddr(), "ssh://"+ts2.SSHAddr())
		})

		t.Run("ws/multiNodes/"+funcName(testLocal), func(t *testing.T) {
			t.Parallel()
			testLocal(t, "ws://"+ts1.WSAddr(), ts1.NodeAddr(), "ws://"+ts2.WSAddr())
		})
	}
}

func funcName(i interface{}) string {
	name := runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
	split := strings.Split(name, ".")

	return split[len(split)-1]
}

type TestServer interface {
	SSHAddr() string
	WSAddr() string
	NodeAddr() string
	Shutdown()
}

func NewServer(hostKey string) (TestServer, error) {
	sshln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	wsln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	s := &Server{
		hostKeyContent: hostKey,
		sshln:          sshln,
		wsln:           wsln,
	}

	go func() {
		if err := s.start(); err != nil {
			log.WithError(err).Error("error starting test server")
		}
	}()

	if err := utils.WaitForServer(s.SSHAddr()); err != nil {
		return nil, err
	}

	if err := utils.WaitForServer(s.WSAddr()); err != nil {
		return nil, err
	}

	return s, nil
}

type Server struct {
	Server *server.Server

	sshln net.Listener
	wsln  net.Listener

	hostKeyContent string
}

func (s *Server) start() error {
	signers, err := utils.CreateSigners([][]byte{[]byte(s.hostKeyContent)})
	if err != nil {
		return err
	}

	var hostSigners []ssh.Signer
	for _, s := range signers {
		cs := server.HostCertSigner{
			Hostnames: []string{"127.0.0.1"},
		}
		hostSigner, err := cs.SignCert(s)
		if err != nil {
			return err
		}

		hostSigners = append(hostSigners, hostSigner)
	}

	network := &server.MemoryProvider{}
	_ = network.SetOpts(nil)

	logger := log.New()
	logger.Level = log.DebugLevel

	s.Server = &server.Server{
		NodeAddr:        s.SSHAddr(), // node addr is hard coded to ssh addr
		HostSigners:     hostSigners,
		Signers:         signers,
		NetworkProvider: network,
		MetricsProvider: provider.NewDiscardProvider(),
		Logger:          logger,
	}

	return s.Server.ServeWithContext(context.Background(), s.sshln, s.wsln)
}

func (s *Server) SSHAddr() string {
	return s.sshln.Addr().String()
}

func (s *Server) WSAddr() string {
	return s.wsln.Addr().String()
}

func (s *Server) NodeAddr() string {
	return s.Server.NodeAddr
}

func (s *Server) Shutdown() {
	s.Server.Shutdown()
}

type Host struct {
	*host.Host

	Command                  []string
	ForceCommand             []string
	PrivateKeys              []string
	AdminSocketFile          string
	SessionCreatedCallback   func(*api.GetSessionResponse) error
	ClientJoinedCallback     func(*api.Client)
	ClientLeftCallback       func(*api.Client)
	PermittedClientPublicKey string
	ReadOnly                 bool
	inputCh                  chan string
	outputCh                 chan string
	ctx                      context.Context
	cancel                   func()
}

func (c *Host) Close() {
	c.cancel()
}

func (c *Host) init() {
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.inputCh = make(chan string)
	c.outputCh = make(chan string)
}

func (c *Host) Share(url string) error {
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
	var authorizedKeys []*host.AuthorizedKey
	if c.PermittedClientPublicKey != "" {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.PermittedClientPublicKey))
		if err != nil {
			return err
		}
		authorizedKeys = append(authorizedKeys, &host.AuthorizedKey{PublicKeys: []ssh.PublicKey{pk}})
	}

	if c.AdminSocketFile == "" {
		adminSockDir, err := newAdminSocketDir()
		if err != nil {
			return err
		}
		defer os.RemoveAll(adminSockDir)

		c.AdminSocketFile = filepath.Join(adminSockDir, "upterm.sock")
	}

	logger := log.New()
	logger.Level = log.DebugLevel

	c.Host = &host.Host{
		Host:                   url,
		Command:                c.Command,
		ForceCommand:           c.ForceCommand,
		Signers:                signers,
		AuthorizedKeys:         authorizedKeys,
		AdminSocketFile:        c.AdminSocketFile,
		SessionCreatedCallback: c.SessionCreatedCallback,
		ClientJoinedCallback:   c.ClientJoinedCallback,
		ClientLeftCallback:     c.ClientLeftCallback,
		KeepAliveDuration:      10 * time.Second,
		Logger:                 logger,
		HostKeyCallback:        ssh.InsecureIgnoreHostKey(),
		Stdin:                  stdinr,
		Stdout:                 stdoutw,
		ReadOnly:               c.ReadOnly,
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

func (c *Client) JoinWithContext(ctx context.Context, session *api.GetSessionResponse, clientJoinURL string) error {
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

	u, err := url.Parse(clientJoinURL)
	if err != nil {
		return err
	}

	if u.Scheme == "ws" || u.Scheme == "wss" {
		encodedNodeAddr := base64.URLEncoding.EncodeToString([]byte(session.NodeAddr))
		u, _ = url.Parse(u.String())
		u.User = url.UserPassword(session.SessionId, encodedNodeAddr)
		c.sshClient, err = ws.NewSSHClient(u, config, true)
	} else {
		c.sshClient, err = ssh.Dial("tcp", u.Host, config)
	}
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

	var g run.Group
	ctx, cancel := context.WithCancel(ctx)
	{
		// output
		g.Add(func() error {
			w := writeFunc(func(pp []byte) (int, error) {
				b, err := ansi.Strip(pp)
				if err != nil {
					return 0, err
				}
				c.outputCh <- string(b)
				return len(pp), nil
			})
			_, err := io.Copy(w, uio.NewContextReader(ctx, c.sshStdout))

			return err
		}, func(err error) {
			cancel()
		})

	}
	{
		// input
		g.Add(func() error {
			for {
				select {
				case s := <-c.inputCh:
					if _, err := io.Copy(c.sshStdin, bytes.NewBufferString(s+"\n")); err != nil {
						return err
					}

				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, func(err error) {
			cancel()
		})
	}

	go func() {
		if err := g.Run(); err != nil {
			log.WithError(err).Error("error joining host")

		}
	}()

	return nil
}

func (c *Client) Join(session *api.GetSessionResponse, clientJoinURL string) error {
	return c.JoinWithContext(context.Background(), session, clientJoinURL)
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
		text := strings.TrimSpace(s.Text())
		if text == "" {
			continue
		}

		return text
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
	file, err := os.CreateTemp("", name)
	if err != nil {
		return "", err
	}
	defer file.Close()

	if _, err := file.Write([]byte(content)); err != nil {
		return "", err
	}

	return file.Name(), nil
}
