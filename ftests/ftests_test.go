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

	"github.com/google/go-cmp/cmp"
	"github.com/jingweno/upterm"
	"github.com/jingweno/upterm/client"
	"github.com/jingweno/upterm/server"
	"github.com/pborman/ansi"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	ln        net.Listener
	socketDir string
}

func (s *Server) Start() error {
	ss := server.New(s.socketDir, log.New())
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
	go s.Start()

	return s, waitForServer(s.Addr())
}

func NewClient(command, attachCommand []string) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		command:       command,
		attachCommand: attachCommand,
		inputCh:       make(chan string),
		outputCh:      make(chan string),
		ctx:           ctx,
		cancel:        cancel,
	}
}

type Client struct {
	command       []string
	attachCommand []string
	inputCh       chan string
	outputCh      chan string
	client        *client.Client
	ctx           context.Context
	cancel        func()
}

func (c *Client) ClientID() string {
	return c.client.ClientID()
}

func (c *Client) Close() {
	c.cancel()
}

func (c *Client) Connect(addr, socketDir string) error {
	stdinr, stdinw, err := os.Pipe()
	if err != nil {
		return err
	}

	stdoutr, stdoutw, err := os.Pipe()
	if err != nil {
		return err
	}

	c.client = client.NewClient(c.command, c.attachCommand, addr, log.New())
	c.client.SetInputOutput(stdinr, stdoutw)
	go func() {
		if err := c.client.Run(c.ctx); err != nil {
			log.WithError(err).Info("error running client")
		}
	}()

	if err := waitForUnixSocket(filepath.Join(socketDir, upterm.SocketFile(c.client.ClientID()))); err != nil {
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

func (c *Client) InputOutput() (chan string, chan string) {
	return c.inputCh, c.outputCh
}

func NewPair() *Pair {
	return &Pair{
		inputCh:  make(chan string),
		outputCh: make(chan string),
	}
}

type Pair struct {
	sshClient *ssh.Client
	session   *ssh.Session
	sshStdin  io.WriteCloser
	sshStdout io.Reader
	inputCh   chan string
	outputCh  chan string
}

func (p *Pair) InputOutput() (chan string, chan string) {
	return p.inputCh, p.outputCh
}

func (p *Pair) Close() {
	p.session.Close()
	p.sshClient.Close()
}

func (p *Pair) Join(clientID, addr string) error {
	config := &ssh.ClientConfig{
		User: clientID,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	var err error
	p.sshClient, err = ssh.Dial("tcp", addr, config)
	if err != nil {
		return err
	}

	p.session, err = p.sshClient.NewSession()
	if err != nil {
		return err
	}

	if err = p.session.RequestPty("xterm", 40, 80, ssh.TerminalModes{}); err != nil {
		return err
	}

	p.sshStdin, err = p.session.StdinPipe()
	if err != nil {
		return err
	}

	p.sshStdout, err = p.session.StdoutPipe()
	if err != nil {
		return err
	}

	if err = p.session.Shell(); err != nil {
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
					p.outputCh <- strings.TrimSpace(s.Text())
				}
			}

			return len(pp), nil
		})
		if _, err := io.Copy(w, p.sshStdout); err != nil {
			log.WithError(err).Info("error copying from stdout")
		}
	}()

	// input
	go func() {
		remoteWg.Wait()
		for c := range p.inputCh {
			if _, err := io.Copy(p.sshStdin, bytes.NewBufferString(c+"\n")); err != nil {
				log.WithError(err).Info("error copying to stdin")
			}
		}
	}()

	remoteWg.Done() // ready!

	return nil
}

var s *Server

func TestMain(m *testing.M) {
	var err error

	// start the server
	s, err = NewServer()
	if err != nil {
		log.Fatal(err)
	}
	exitCode := m.Run()
	s.Close()

	os.Exit(exitCode)
}

func Test_FTests(t *testing.T) {
	t.Run("pair attaches to host with the same command", func(t *testing.T) {
		t.Parallel()

		// client connects to server
		c := NewClient([]string{"bash"}, nil)
		if err := c.Connect(s.Addr(), s.SocketDir()); err != nil {
			t.Fatal(err)
		}
		defer c.Close()

		hostInputCh, hostOutputCh := c.InputOutput()

		<-hostOutputCh // discard prompt, e.g. bash-5.0$

		hostInputCh <- "echo hello"
		if want, got := "echo hello", <-hostOutputCh; !strings.Contains(got, want) {
			t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
		}
		if want, got := "hello", <-hostOutputCh; !strings.Contains(got, want) {
			t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
		}

		// pair joins client
		p := NewPair()
		if err := p.Join(c.ClientID(), s.Addr()); err != nil {
			t.Fatal(err)
		}

		remoteInputCh, remoteOutputCh := p.InputOutput()

		<-remoteOutputCh // discard cached prompt, e.g. bash-5.0$
		<-remoteOutputCh // discard prompt, e.g. bash-5.0$

		remoteInputCh <- "echo hello again"
		if want, got := "echo hello again", <-remoteOutputCh; !strings.Contains(got, want) {
			t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
		}
		if want, got := "hello again", <-remoteOutputCh; !strings.Contains(got, want) {
			t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
		}

		<-hostOutputCh // discard prompt, e.g. bash-5.0$
		// host should link to remote with the same input/output
		if want, got := "echo hello again", <-hostOutputCh; !strings.Contains(got, want) {
			t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
		}
		if want, got := "hello again", <-hostOutputCh; !strings.Contains(got, want) {
			t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
		}
	})

	t.Run("pair attaches to host with a different command", func(t *testing.T) {
		t.Parallel()

		// client connects to server
		c := NewClient([]string{"bash"}, []string{"bash"})
		if err := c.Connect(s.Addr(), s.SocketDir()); err != nil {
			t.Fatal(err)
		}
		defer c.Close()

		hostInputCh, hostOutputCh := c.InputOutput()

		<-hostOutputCh // discard prompt, e.g. bash-5.0$

		hostInputCh <- "echo hello"
		if want, got := "echo hello", <-hostOutputCh; !strings.Contains(got, want) {
			t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
		}
		if want, got := "hello", <-hostOutputCh; !strings.Contains(got, want) {
			t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
		}

		// pair joins client
		p := NewPair()
		if err := p.Join(c.ClientID(), s.Addr()); err != nil {
			t.Fatal(err)
		}

		remoteInputCh, remoteOutputCh := p.InputOutput()

		<-remoteOutputCh // discard prompt, e.g. bash-5.0$

		remoteInputCh <- "echo hello again"
		if want, got := "echo hello again", <-remoteOutputCh; !strings.Contains(got, want) {
			t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
		}
		if want, got := "hello again", <-remoteOutputCh; !strings.Contains(got, want) {
			t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
		}

		<-hostOutputCh // discard prompt, e.g. bash-5.0$

		// host shouldn't be linked to remote
		hostInputCh <- "echo hello"
		if want, got := "echo hello", <-hostOutputCh; !strings.Contains(got, want) {
			t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
		}
		if want, got := "hello", <-hostOutputCh; !strings.Contains(got, want) {
			t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
		}
	})
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
