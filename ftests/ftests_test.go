package ftests

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
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

	"github.com/jingweno/upterm/client"
	"github.com/jingweno/upterm/server"
	"github.com/jingweno/upterm/utils"
	"github.com/pborman/ansi"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var (
	hostPublicKey    string
	hostPrivateKey   string
	clientPublicKey  string
	clientPrivateKey string
)

const (
	hostPublicKeyContent  = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOA+rMcwWFPJVE2g6EwRPkYmNJfaS/+gkyZ99aR/65uz`
	hostPrivateKeyContent = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDgPqzHMFhTyVRNoOhMET5GJjSX2kv/oJMmffWkf+ubswAAAIiu5GOBruRj
gQAAAAtzc2gtZWQyNTUxOQAAACDgPqzHMFhTyVRNoOhMET5GJjSX2kv/oJMmffWkf+ubsw
AAAEDBHlsR95C/pGVHtQGpgrUi+Qwgkfnp9QlRKdEhhx4rxOA+rMcwWFPJVE2g6EwRPkYm
NJfaS/+gkyZ99aR/65uzAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
	`
	clientPublicKeyContent  = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN0EWrjdcHcuMfI8bGAyHPcGsAc/vd/gl5673pRkRBGY`
	clientPrivateKeyContent = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDdBFq43XB3LjHyPGxgMhz3BrAHP73f4Jeeu96UZEQRmAAAAIiRPFazkTxW
swAAAAtzc2gtZWQyNTUxOQAAACDdBFq43XB3LjHyPGxgMhz3BrAHP73f4Jeeu96UZEQRmA
AAAEDmpjZHP/SIyBTp6YBFPzUi18iDo2QHolxGRDpx+m7let0EWrjdcHcuMfI8bGAyHPcG
sAc/vd/gl5673pRkRBGYAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
`
)

func NewServer() (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	socketDir, err := ioutil.TempDir("", "sockets")
	if err != nil {
		return nil, err
	}

	s := &Server{ln, socketDir}
	go s.start()

	return s, waitForServer(s.Addr())
}

type Server struct {
	ln        net.Listener
	socketDir string
}

func (s *Server) start() error {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return err
	}

	ss := server.New([]ssh.Signer{signer}, s.socketDir, log.New())
	return ss.Serve(s.ln)
}

func (s *Server) Addr() string {
	return s.ln.Addr().String()
}

func (s *Server) SocketDir() string {
	return s.socketDir
}

func (s *Server) Close() {
	s.ln.Close()
	os.RemoveAll(s.socketDir)
}

type Host struct {
	Command     []string
	JoinCommand []string
	PrivateKeys []string

	inputCh  chan string
	outputCh chan string
	client   *client.Client
	ctx      context.Context
	cancel   func()
}

func (c *Host) SessionID() string {
	return c.client.ClientID()
}

func (c *Host) Close() {
	c.cancel()
}

func (c *Host) init() {
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.inputCh = make(chan string)
	c.outputCh = make(chan string)
}

func (c *Host) Share(addr, socketDir string) error {
	c.init()

	stdinr, stdinw, err := os.Pipe()
	if err != nil {
		return err
	}

	stdoutr, stdoutw, err := os.Pipe()
	if err != nil {
		return err
	}

	auths, err := client.AuthMethodsFromFiles(c.PrivateKeys)
	if err != nil {
		return err
	}

	// permit client public key
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(clientPublicKeyContent))
	if err != nil {
		return err
	}

	c.client = client.NewClient(c.Command, c.JoinCommand, addr, auths, []ssh.PublicKey{pk}, time.Duration(10), log.New())
	c.client.SetInputOutput(stdinr, stdoutw)
	go func() {
		if err := c.client.Run(c.ctx); err != nil {
			log.WithError(err).Info("error running client")
		}
	}()

	if err := waitForUnixSocket(filepath.Join(socketDir, utils.SocketFile(c.client.ClientID()))); err != nil {
		return err
	}

	var hostWg sync.WaitGroup
	hostWg.Add(1)

	// output
	go func() {
		hostWg.Wait()
		w := writeFunc(func(p []byte) (int, error) {
			b, err := ansi.Strip(p)
			if err != nil {
				return 0, err
			}
			s := bufio.NewScanner(bytes.NewBuffer(b))
			for s.Scan() {
				if s.Text() != "" {
					c.outputCh <- strings.TrimSpace(s.Text())
				}
			}

			return len(p), nil
		})
		if _, err := io.Copy(w, stdoutr); err != nil {
			log.WithError(err).Info("error copying from stdout")
		}
	}()

	// input
	go func() {
		hostWg.Wait()
		for c := range c.inputCh {
			if _, err := io.Copy(stdinw, bytes.NewBufferString(c+"\n")); err != nil {
				log.WithError(err).Info("error copying to stdin")
			}
		}
	}()

	hostWg.Done() // ready!

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

	auths, err := client.AuthMethodsFromFiles([]string{clientPrivateKey})
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
	remoteWg.Add(1)

	// output
	go func() {
		remoteWg.Wait()
		w := writeFunc(func(pp []byte) (int, error) {
			b, err := ansi.Strip(pp)
			if err != nil {
				return 0, err
			}
			s := bufio.NewScanner(bytes.NewBuffer(b))
			for s.Scan() {
				if s.Text() != "" {
					c.outputCh <- strings.TrimSpace(s.Text())
				}
			}

			return len(pp), nil
		})
		if _, err := io.Copy(w, c.sshStdout); err != nil {
			log.WithError(err).Info("error copying from stdout")
		}
	}()

	// input
	go func() {
		remoteWg.Wait()
		for s := range c.inputCh {
			if _, err := io.Copy(c.sshStdin, bytes.NewBufferString(s+"\n")); err != nil {
				log.WithError(err).Info("error copying to stdin")
			}
		}
	}()

	remoteWg.Done() // ready!

	return nil
}

var s *Server

func TestMain(m *testing.M) {
	err := writeKeyPairs()
	if err != nil {
		log.Fatal(err)
	}
	defer removeKeyPairs()

	// start the server
	s, err = NewServer()
	if err != nil {
		log.Fatal(err)
	}

	exitCode := m.Run()
	s.Close()

	os.Exit(exitCode)
}

func waitForServer(addr string) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	count := 0

	for range ticker.C {
		log.WithField("addr", addr).Info("waiting for server")
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			break
		}
		conn.Close()

		count++
		if count >= 10 {
			return fmt.Errorf("waiting for unix socket failed")
		}
	}

	return nil
}

func waitForUnixSocket(socket string) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	count := 0

	for range ticker.C {
		log.WithField("socket", socket).Info("waiting for unix socket")
		if _, err := os.Stat(socket); err == nil {
			break
		}
		count++
		if count >= 10 {
			return fmt.Errorf("waiting for unix socket failed")
		}
	}

	return nil
}

type writeFunc func(p []byte) (n int, err error)

func (rf writeFunc) Write(p []byte) (n int, err error) { return rf(p) }

func writeKeyPairs() error {
	var err error

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
	os.Remove(hostPublicKey)
	os.Remove(hostPrivateKey)
	os.Remove(clientPublicKey)
	os.Remove(clientPrivateKey)
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
