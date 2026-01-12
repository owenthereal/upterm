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
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"log/slog"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/oklog/run"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/testhelpers"
	uio "github.com/owenthereal/upterm/io"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/owenthereal/upterm/ws"
	"github.com/pborman/ansi"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/ssh"
)

var (
	// Shared debug logger for all tests
	testLogger = logging.Must(logging.Console(), logging.Debug()).Logger
)

// getTestShell returns platform-appropriate shell command for tests
func getTestShell() []string {
	if runtime.GOOS == "windows" {
		// Prefer PowerShell Core (pwsh) if available, otherwise use Windows PowerShell (powershell)
		// -NonInteractive disables PSReadLine (no syntax highlighting/line editing)
		// -NoProfile/-NoLogo reduce startup noise
		// Tests must drain the initial "PS >" prompt
		shell := "powershell" // Default to Windows PowerShell (always available)
		if _, err := exec.LookPath("pwsh"); err == nil {
			shell = "pwsh" // Use PowerShell Core if available
		}
		return []string{shell, "-NoProfile", "-NoLogo", "-NonInteractive"}
	}
	return []string{"bash", "-c", "PS1='' BASH_SILENCE_DEPRECATION_WARNING=1 bash --norc"}
}

const (
	serverStartupTimeout  = 3 * time.Second
	unixSocketWaitTimeout = 3 * time.Second
	keepAliveDuration     = 2 * time.Second
	sshAttachTimeout      = 500 * time.Millisecond

	// Test key material
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
)

// FtestCase represents a functional test case
type FtestCase func(t *testing.T, hostURL, hostNodeAddr, clientJoinURL string)

// AuthTestCases contains all authentication-related test functions
var AuthTestCases = []FtestCase{
	testHostNoAuthorizedKeyAnyClientJoin,
	testClientAuthorizedKeyNotMatching,
	testHostFailToShareWithoutPrivateKey,
}

// SessionTestCases contains all session management test functions
var SessionTestCases = []FtestCase{
	testClientNonExistingSession,
}

// ConnectionTestCases contains all connection-related test functions
var ConnectionTestCases = []FtestCase{
	testClientAttachHostWithSameCommand,
	testClientAttachHostWithDifferentCommand,
	testClientAttachReadOnly,
}

// CallbackTestCases contains all callback/event-related test functions
var CallbackTestCases = []FtestCase{
	testHostClientCallback,
	testHostSessionCreatedCallback,
}

// BackwardCompatibilityTestCases contains tests for backward compatibility scenarios
var BackwardCompatibilityTestCases = []FtestCase{
	testOldClientToNewConsulServer,
}

// FtestSuite runs functional tests with different session routing modes
type FtestSuite struct {
	suite.Suite
	mode routing.Mode
	ts1  TestServer
	ts2  TestServer
}

func (suite *FtestSuite) SetupSuite() {
	// Setup key pairs
	remove, err := setupKeyPairs()
	suite.Require().NoError(err)
	suite.T().Cleanup(remove)

	// Create test servers with the specified routing mode
	suite.ts1, err = NewServerWithMode(ServerPrivateKeyContent, suite.mode)
	suite.Require().NoError(err)

	suite.ts2, err = NewServerWithMode(ServerPrivateKeyContent, suite.mode)
	suite.Require().NoError(err)
}

func (suite *FtestSuite) TearDownSuite() {
	if suite.ts1 != nil {
		_ = suite.ts1.Shutdown()
	}
	if suite.ts2 != nil {
		_ = suite.ts2.Shutdown()
	}
}

func (suite *FtestSuite) TestAuth() {
	suite.runTestCategory(AuthTestCases)
}

func (suite *FtestSuite) TestSession() {
	suite.runTestCategory(SessionTestCases)
}

func (suite *FtestSuite) TestConnection() {
	suite.runTestCategory(ConnectionTestCases)
}

func (suite *FtestSuite) TestCallbacks() {
	suite.runTestCategory(CallbackTestCases)
}

func (suite *FtestSuite) TestBackwardCompatibility() {
	// Only run backward compatibility tests in Consul mode
	// (since embedded mode doesn't need backward compatibility)
	if suite.mode != routing.ModeConsul {
		suite.T().Skip("Backward compatibility tests only run in Consul mode")
		return
	}
	suite.runTestCategory(BackwardCompatibilityTestCases)
}

func (suite *FtestSuite) runTestCategory(testCases []FtestCase) {
	protocols := []string{"ssh", "ws"}

	for _, protocol := range protocols {
		suite.T().Run(protocol, func(t *testing.T) {
			suite.runTestsForProtocol(protocol, testCases)
		})
	}
}

func (suite *FtestSuite) runTestsForProtocol(protocol string, testCases []FtestCase) {
	topologies := []struct {
		name      string
		hostURL   string
		clientURL string
	}{
		{
			name:      "singleNode",
			hostURL:   protocol + "://" + suite.getServerAddr(protocol, suite.ts1),
			clientURL: protocol + "://" + suite.getServerAddr(protocol, suite.ts1),
		},
		{
			name:      "multiNodes",
			hostURL:   protocol + "://" + suite.getServerAddr(protocol, suite.ts1),
			clientURL: protocol + "://" + suite.getServerAddr(protocol, suite.ts2),
		},
	}

	for _, topo := range topologies {
		suite.T().Run(topo.name, func(t *testing.T) {
			for _, testFunc := range testCases {
				testName := funcName(testFunc)
				t.Run(testName, func(t *testing.T) {
					t.Parallel()
					testFunc(t, topo.hostURL, suite.ts1.NodeAddr(), topo.clientURL)
				})
			}
		})
	}
}

func (suite *FtestSuite) getServerAddr(protocol string, server TestServer) string {
	if protocol == "ssh" {
		return server.SSHAddr()
	}
	return server.WSAddr()
}

// Test runners for different modes
func TestEmbedded(t *testing.T) {
	suite.Run(t, &FtestSuite{mode: routing.ModeEmbedded})
}

func TestConsul(t *testing.T) {
	// Skip if Consul is not available
	if !testhelpers.IsConsulAvailable() {
		t.Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
	}
	suite.Run(t, &FtestSuite{mode: routing.ModeConsul})
}

func mustParseURL(urlStr string) *url.URL {
	u, err := url.Parse(urlStr)
	if err != nil {
		panic(fmt.Sprintf("failed to parse URL %s: %v", urlStr, err))
	}
	return u
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
	Shutdown() error
}

func NewServerWithMode(hostKey string, mode routing.Mode) (TestServer, error) {
	sshln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH listener: %w", err)
	}

	wsln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = sshln.Close()
		return nil, fmt.Errorf("failed to create WebSocket listener: %w", err)
	}

	s := &Server{
		hostKeyContent: hostKey,
		sshln:          sshln,
		wsln:           wsln,
		mode:           mode,
	}

	// Start server in background
	startErrCh := make(chan error, 1)
	go func() {
		if err := s.start(); err != nil {
			testLogger.Error("error starting test server", "error", err, "mode", mode)
			startErrCh <- err
		}
	}()

	// Wait for server to start with timeout
	ctx, cancel := context.WithTimeout(context.Background(), serverStartupTimeout)
	defer cancel()

	// Wait for SSH server
	if err := utils.WaitForServer(ctx, s.SSHAddr()); err != nil {
		_ = s.Shutdown()
		return nil, fmt.Errorf("SSH server failed to start: %w", err)
	}

	// Wait for WebSocket server
	if err := utils.WaitForServer(ctx, s.WSAddr()); err != nil {
		_ = s.Shutdown()
		return nil, fmt.Errorf("WebSocket server failed to start: %w", err)
	}

	// Check for startup errors
	select {
	case err := <-startErrCh:
		_ = s.Shutdown()
		return nil, fmt.Errorf("server startup failed: %w", err)
	default:
	}

	return s, nil
}

type Server struct {
	Server *server.Server

	sshln          net.Listener
	wsln           net.Listener
	hostKeyContent string
	mode           routing.Mode
	logger         *slog.Logger

	shutdownOnce sync.Once
	mu           sync.RWMutex
}

func (s *Server) start() error {
	signers, err := utils.CreateSigners([][]byte{[]byte(s.hostKeyContent)})
	if err != nil {
		return fmt.Errorf("failed to create signers: %w", err)
	}

	var hostSigners []ssh.Signer
	for _, signer := range signers {
		cs := server.HostCertSigner{
			Hostnames: []string{"127.0.0.1"},
		}
		hostSigner, err := cs.SignCert(signer)
		if err != nil {
			return fmt.Errorf("failed to sign host certificate: %w", err)
		}

		hostSigners = append(hostSigners, hostSigner)
	}

	network := &server.MemoryProvider{}
	if err := network.SetOpts(nil); err != nil {
		return fmt.Errorf("failed to set network provider options: %w", err)
	}

	logger := testLogger.With(
		"mode", s.mode,
		"ssh", s.SSHAddr(),
		"ws", s.WSAddr(),
	)
	s.logger = logger

	// Create session manager based on the mode
	var sm *server.SessionManager
	switch s.mode {
	case routing.ModeEmbedded:
		sm, err = server.NewSessionManager(
			routing.ModeEmbedded,
			server.WithSessionManagerLogger(logger),
		)
		if err != nil {
			return fmt.Errorf("failed to create embedded session manager: %w", err)
		}
	case routing.ModeConsul:
		sm, err = server.NewSessionManager(
			routing.ModeConsul,
			server.WithSessionManagerLogger(logger),
			server.WithSessionManagerConsulURL(mustParseURL(testhelpers.ConsulURL())),
		)
		if err != nil {
			return fmt.Errorf("failed to create consul session manager: %w", err)
		}
	default:
		return fmt.Errorf("unsupported routing mode: %s", s.mode)
	}

	s.mu.Lock()
	s.Server = &server.Server{
		NodeAddr:        s.SSHAddr(), // node addr is hard coded to ssh addr
		HostSigners:     hostSigners,
		Signers:         signers,
		NetworkProvider: network,
		MetricsProvider: provider.NewDiscardProvider(),
		SessionManager:  sm,
		Logger:          logger,
	}
	s.mu.Unlock()

	return s.Server.ServeWithContext(context.Background(), s.sshln, s.wsln)
}

func (s *Server) SSHAddr() string {
	return s.sshln.Addr().String()
}

func (s *Server) WSAddr() string {
	return s.wsln.Addr().String()
}

func (s *Server) NodeAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.Server == nil {
		return ""
	}
	return s.Server.NodeAddr
}

func (s *Server) Shutdown() error {
	var err error
	s.shutdownOnce.Do(func() {
		if s.logger != nil {
			s.logger.Info("shutting down test server")
		}

		if s.Server != nil {
			err = s.Server.Shutdown()
		}
	})
	return err
}

type Host struct {
	*host.Host

	Command                  []string
	ForceCommand             []string
	PrivateKeys              []string
	AdminSocketFile          string
	SessionCreatedCallback   func(context.Context, *api.GetSessionResponse) error
	ClientJoinedCallback     func(*api.Client)
	ClientLeftCallback       func(*api.Client)
	PermittedClientPublicKey string
	ReadOnly     bool
	SFTPDisabled bool // Disable SFTP subsystem
	inputCh      chan string
	outputCh                 chan string
	ctx                      context.Context
	cancel                   func()
	wg                       sync.WaitGroup
}

func (c *Host) Close() {
	// Cancel context to signal goroutines to stop
	c.cancel()

	// Close input channel to unblock the input goroutine
	if c.inputCh != nil {
		close(c.inputCh)
	}

	// Wait for all goroutines to finish with a timeout
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Clean shutdown completed
	case <-time.After(2 * time.Second):
		// Timeout - goroutines didn't finish in time, but that's okay for tests
		testLogger.Warn("timeout waiting for host goroutines to finish")
	}
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
		return fmt.Errorf("AdminSocketFile is required but not set")
	}

	logger := testLogger

	c.Host = &host.Host{
		Host:                           url,
		Command:                        c.Command,
		ForceCommand:                   c.ForceCommand,
		Signers:                        signers,
		AuthorizedKeys:                 authorizedKeys,
		AdminSocketFile:                c.AdminSocketFile,
		SessionCreatedCallback:         c.SessionCreatedCallback,
		ClientJoinedCallback:           c.ClientJoinedCallback,
		ClientLeftCallback:             c.ClientLeftCallback,
		KeepAliveDuration:              keepAliveDuration,
		Logger:                         logger,
		HostKeyCallback:                ssh.InsecureIgnoreHostKey(),
		Stdin:                          stdinr,
		Stdout:                         stdoutw,
		ReadOnly:                       c.ReadOnly,
		SFTPDisabled:                   c.SFTPDisabled,
		ForceForwardingInputForTesting: true,
	}

	errCh := make(chan error)
	go func() {
		if err := c.Run(c.ctx); err != nil {
			testLogger.Error("error running host", "error", err)
			errCh <- err
		}
	}()

	if err := waitForUnixSocket(c.AdminSocketFile, errCh); err != nil {
		return err
	}

	// Start I/O goroutines with proper synchronization
	c.wg.Add(2)

	// output - reads from stdout and forwards to output channel
	go func() {
		defer c.wg.Done()
		w := writeFunc(func(p []byte) (int, error) {
			b, err := ansi.Strip(p)
			if err != nil {
				// Ignore ANSI parsing errors (e.g., malformed OSC sequences)
				// and use the original bytes instead
				testLogger.Warn("failed to strip ANSI codes", "p", p, "error", err)
				b = p
			}
			// Use select to respect context cancellation when sending to channel
			select {
			case c.outputCh <- string(b):
			case <-c.ctx.Done():
				return 0, c.ctx.Err()
			}
			return len(p), nil
		})
		_, _ = io.Copy(w, stdoutr)
	}()

	// input - reads from input channel and forwards to stdin
	go func() {
		defer c.wg.Done()
		for {
			select {
			case str, ok := <-c.inputCh:
				if !ok {
					// Channel closed, exit goroutine
					return
				}
				// On Windows, cmd.exe needs \r\n to execute commands
				lineEnding := "\n"
				if runtime.GOOS == "windows" {
					lineEnding = "\r\n"
				}
				if _, err := io.Copy(stdinw, bytes.NewBufferString(str+lineEnding)); err != nil {
					testLogger.Error("error copying to stdin", "error", err)
					return
				}
			case <-c.ctx.Done():
				// Context cancelled, exit goroutine
				return
			}
		}
	}()

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
	cancel      func()
	wg          sync.WaitGroup
}

func (c *Client) init() {
	c.inputCh = make(chan string)
	c.outputCh = make(chan string)
}

func (c *Client) InputOutput() (chan string, chan string) {
	return c.inputCh, c.outputCh
}

// SFTP returns an SFTP client using the existing SSH connection.
// The caller is responsible for closing the returned SFTP client.
func (c *Client) SFTP() (*sftp.Client, error) {
	if c.sshClient == nil {
		return nil, fmt.Errorf("SSH client not connected")
	}
	return sftp.NewClient(c.sshClient)
}

func (c *Client) Close() {
	// Cancel context to signal goroutines to stop
	if c.cancel != nil {
		c.cancel()
	}

	// Close input channel to unblock input goroutine
	if c.inputCh != nil {
		close(c.inputCh)
	}

	// Wait for goroutines to finish with a timeout
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Clean shutdown completed
	case <-time.After(2 * time.Second):
		// Timeout - goroutines didn't finish in time
		testLogger.Warn("timeout waiting for client goroutines to finish")
	}

	// Now close the session and client
	if c.session != nil {
		_ = c.session.Close()
	}
	if c.sshClient != nil {
		_ = c.sshClient.Close()
	}
}

func (c *Client) JoinWithContext(ctx context.Context, session *api.GetSessionResponse, clientJoinURL string) error {
	c.init()

	auths, err := authMethodsFromFiles(c.PrivateKeys)
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User:            session.SshUser,
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
	c.cancel = cancel // Store cancel function for cleanup
	{
		// output
		g.Add(func() error {
			w := writeFunc(func(pp []byte) (int, error) {
				b, err := ansi.Strip(pp)
				if err != nil {
					// Ignore ANSI parsing errors (e.g., malformed OSC sequences)
					// and use the original bytes instead
					testLogger.Warn("failed to strip ANSI codes", "pp", pp, "error", err)
					b = pp
				}
				// Use select to respect context cancellation
				select {
				case c.outputCh <- string(b):
				case <-ctx.Done():
					return 0, ctx.Err()
				}
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
				case s, ok := <-c.inputCh:
					if !ok {
						// Channel closed, exit goroutine
						return nil
					}
					// On Windows, cmd.exe needs \r\n to execute commands
					lineEnding := "\n"
					if runtime.GOOS == "windows" {
						lineEnding = "\r\n"
					}
					if _, err := io.Copy(c.sshStdin, bytes.NewBufferString(s+lineEnding)); err != nil {
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

	// Track the goroutine running the group
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		if err := g.Run(); err != nil {
			testLogger.Error("error in client run group", "error", err)
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

// stripShellPrompt removes PowerShell prompt prefix and ANSI codes on Windows
// PowerShell outputs: "\x1b[...ANSI codes...PS C:\path> command" instead of just "command"
func stripShellPrompt(s string) string {
	if runtime.GOOS != "windows" {
		return s
	}

	// First, remove all ANSI escape sequences
	// CSI sequences: ESC [ ... final byte (0x40-0x7E per ECMA-48)
	// OSC sequences: ESC ] ... BEL (0x07)
	ansiRe := regexp.MustCompile(`\x1b\[[^\x40-\x7e]*[\x40-\x7e]|\x1b\][^\x07]*\x07`)
	s = ansiRe.ReplaceAllString(s, "")

	// Then remove "PS <path>>" (can appear multiple times due to screen redraws)
	// Don't use ^ anchor so we match all occurrences, not just start of line
	promptRe := regexp.MustCompile(`PS [^>]+>\s*`)
	return promptRe.ReplaceAllString(s, "")
}

func scan(s *bufio.Scanner) string {
	for s.Scan() {
		text := stripShellPrompt(strings.TrimSpace(s.Text()))
		if text == "" {
			continue
		}

		return text
	}

	return s.Err().Error()
}

func waitForUnixSocket(socket string, errCh chan error) error {
	ctx, cancel := context.WithTimeout(context.Background(), unixSocketWaitTimeout)
	defer cancel()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for unix socket %s: %w", socket, ctx.Err())
		case <-ticker.C:
			testLogger.Debug("waiting for unix socket", "socket", socket)
			if _, err := os.Stat(socket); err == nil {
				return nil
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

func setupKeyPairs() (func(), error) {
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
		_ = os.Remove(HostPrivateKey)
		_ = os.Remove(ClientPrivateKey)
	}

	return remove, nil
}

func writeTempFile(name, content string) (string, error) {
	file, err := os.CreateTemp("", name)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()

	if _, err := file.Write([]byte(content)); err != nil {
		return "", err
	}

	return file.Name(), nil
}
