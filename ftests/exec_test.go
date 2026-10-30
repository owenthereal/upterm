package ftests

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

var ExecTestCases = []FtestCase{
	testExecBinaryStdoutStderr,
	testExecStdinScriptHalfClose,
	testExecIndependentExitStatuses,
	testExecSeveralChannelsAndCancellation,
	testExecLoginVersusExplicit,
	testExecRawQuotingCwdEnv,
	testExecConcurrentForwardSFTP,
	testExecForegroundDisconnectAndHostStop,
	testExecBootstrapOwnedListener,
}

func (suite *FtestSuite) TestExec() { suite.runTestCategory(ExecTestCases) }

func execFixture(t *testing.T) *Host {
	t.Helper()
	return &Host{Command: getTestShell(), PrivateKeys: []string{HostPrivateKey}, AdminSocketFile: setupAdminSocket(t), PermittedClientPublicKey: ClientPublicKeyContent, AcceptExec: true}
}

// These byte assertions catch PTY insertion, merged stderr and truncated output.
func testExecBinaryStdoutStderr(t *testing.T, hostURL, node, joinURL string) {
	h := execFixture(t)
	c := connectRelayGuest(t, shareHost(t, h, hostURL, node), joinURL)
	expectedBinaryPayload := bytes.Repeat([]byte{0, 1, 127, 255, 13, 10}, 65536)
	expectedStderr := bytes.Repeat([]byte{255, 0, 'e', 'r', 'r', 13, 10}, 32768)
	out, stderr, status := relayExec(t, c, guestToolCommand(t, "binary"), nil)
	require.Equal(t, expectedBinaryPayload, out)
	require.Equal(t, expectedStderr, stderr)
	require.Equal(t, 23, status)
}

// EOF must deliver a stdin-fed script and let its child finish normally.
func testExecStdinScriptHalfClose(t *testing.T, hostURL, node, joinURL string) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX stdin-fed sh script")
	}
	h := execFixture(t)
	c := connectRelayGuest(t, shareHost(t, h, hostURL, node), joinURL)
	out, stderr, status := relayExec(t, c, "sh", strings.NewReader("printf 'script complete'; printf 'script stderr' >&2; exit 23\n"))
	require.Equal(t, "script complete", string(out))
	require.Equal(t, "script stderr", string(stderr))
	require.Equal(t, 23, status)
}

func testExecIndependentExitStatuses(t *testing.T, hostURL, node, joinURL string) {
	h := execFixture(t)
	c := connectRelayGuest(t, shareHost(t, h, hostURL, node), joinURL)
	type result struct {
		out, stderr bytes.Buffer
		session     *ssh.Session
		done        chan error
	}
	runs := make([]*result, 6)
	for i := range runs {
		s, err := c.sshClient.NewSession()
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })
		r := &result{session: s, done: make(chan error, 1)}
		runs[i] = r
		s.Stdout = &r.out
		s.Stderr = &r.stderr
		require.NoError(t, s.Start(guestToolCommand(t, fmt.Sprintf("probe-%d", i))))
		go func() { r.done <- s.Wait() }()
	}
	for i, r := range runs {
		require.Equal(t, i+20, relayStatus(t, awaitRelayWait(t, r.done)))
		require.Equal(t, fmt.Sprintf("probe-%d", i), r.out.String())
		require.Equal(t, fmt.Sprintf("err-%d", i), r.stderr.String())
	}
}

func testExecSeveralChannelsAndCancellation(t *testing.T, hostURL, node, joinURL string) {
	h := execFixture(t)
	c := connectRelayGuest(t, shareHost(t, h, hostURL, node), joinURL)
	const expectedChannelCount = 3
	sessions := make([]*ssh.Session, expectedChannelCount)
	inputs := make([]io.WriteCloser, expectedChannelCount)
	waits := make([]chan error, expectedChannelCount)
	for i := range sessions {
		s, err := c.sshClient.NewSession()
		require.NoError(t, err)
		sessions[i] = s
		t.Cleanup(func() { _ = s.Close() })
		inputs[i], err = s.StdinPipe()
		require.NoError(t, err)
		ready, err := s.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, s.Start(guestToolCommand(t, "hold")))
		b := make([]byte, 1)
		_, err = io.ReadFull(ready, b)
		require.NoError(t, err)
		require.Equal(t, []byte("R"), b)
		waits[i] = make(chan error, 1)
		go func() { waits[i] <- s.Wait() }()
	}
	requireGuestPresence(t, h, expectedChannelCount)
	require.NoError(t, sessions[0].Close())
	require.NotNil(t, awaitRelayWait(t, waits[0]))
	requireGuestPresence(t, h, 2)
	for i := 1; i < len(sessions); i++ {
		require.NoError(t, inputs[i].Close())
		require.Equal(t, 23, relayStatus(t, awaitRelayWait(t, waits[i])))
	}
	requireGuestPresence(t, h, 0)
	out, _, status := relayExec(t, c, guestToolCommand(t, "sibling"), nil)
	require.Equal(t, 0, status)
	require.Equal(t, "sibling still usable", string(out))
}

func testExecLoginVersusExplicit(t *testing.T, hostURL, node, joinURL string) {
	h := execFixture(t)
	h.LoginCommand = guestToolArgv(t, "login")
	c := connectRelayGuest(t, shareHost(t, h, hostURL, node), joinURL)
	s, err := c.sshClient.NewSession()
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	var out bytes.Buffer
	s.Stdout = &out
	require.NoError(t, s.Shell())
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	require.NoError(t, awaitRelayWait(t, done))
	require.Equal(t, "login only", out.String())
	got, _, status := relayExec(t, c, guestToolCommand(t, "explicit"), nil)
	require.Equal(t, 0, status)
	require.Equal(t, "explicit exec", string(got))
}

func testExecConcurrentForwardSFTP(t *testing.T, hostURL, node, joinURL string) {
	h := execFixture(t)
	h.AllowLoopbackTCPForwarding = true
	h.SFTPAutoAccept = true
	prompts := newRelayPrompter()
	h.PermissionChecker = prompts.manager(t)
	c := connectRelayGuest(t, shareHost(t, h, hostURL, node), joinURL)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, e := ln.Accept()
		if e == nil {
			accepted <- conn
		}
	}()
	forward, err := c.sshClient.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = forward.Close() }()
	peer := <-accepted
	defer func() { _ = peer.Close() }()
	// Keep an exec, SFTP channel and forward live together on one transport.
	s, err := c.sshClient.NewSession()
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	in, err := s.StdinPipe()
	require.NoError(t, err)
	ready, err := s.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, s.Start(guestToolCommand(t, "hold")))
	b := make([]byte, 1)
	_, err = io.ReadFull(ready, b)
	require.NoError(t, err)
	sf := openConcurrentRelaySFTP(t, c)
	defer func() { _ = sf.Close() }()
	requireGuestPresence(t, h, 2)
	go func() { _, _ = peer.Write([]byte{255, 0, 1}) }()
	_, err = io.ReadFull(forward, b)
	require.NoError(t, err)
	require.Equal(t, byte(255), b[0])
	require.NoError(t, in.Close())
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	require.Equal(t, 23, relayStatus(t, awaitRelayWait(t, done)))
	require.Equal(t, 0, prompts.count(), "explicit unattended grants must issue zero approval requests")
	requireForwardPresence(t, h, 1)
	require.NoError(t, forward.Close())
	requireForwardPresence(t, h, 1) // connection lifetime
	require.NoError(t, c.sshClient.Close())
	requireForwardPresence(t, h, 0)
}

func testExecForegroundDisconnectAndHostStop(t *testing.T, hostURL, node, joinURL string) {
	h := execFixture(t)
	record := shareHost(t, h, hostURL, node)
	for _, stopHost := range []bool{false, true} {
		c := connectRelayGuest(t, record, joinURL)
		s, err := c.sshClient.NewSession()
		require.NoError(t, err)
		defer func() { _ = s.Close() }()
		in, err := s.StdinPipe()
		require.NoError(t, err)
		defer func() { _ = in.Close() }()
		out, err := s.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, s.Start(guestToolCommand(t, "foreground")))
		b := make([]byte, 1)
		_, err = io.ReadFull(out, b)
		require.NoError(t, err)
		requireGuestPresence(t, h, 1)
		done := make(chan error, 1)
		go func() { done <- s.Wait() }()
		if stopHost {
			h.cancel()
		} else {
			require.NoError(t, c.sshClient.Close())
		}
		require.Error(t, awaitRelayWait(t, done), "disconnect/host stop must not report success")
		if stopHost {
			select {
			case <-h.Done():
			case <-time.After(reachTimeout):
				t.Fatal("host stop did not finish")
			}
			late, err := c.sshClient.NewSession()
			if err == nil {
				defer func() { _ = late.Close() }()
				require.Error(t, late.Run(guestToolCommand(t, "forbidden")))
			}
		} else {
			requireGuestPresence(t, h, 0)
		}
	}
}

// TestGuestToolListener is a fixture-owned background service, not an installed
// application. Only the child started by the bootstrap case enters this path.
// It has a bounded lifetime and an explicit stop protocol, avoiding PID reuse.
func TestGuestToolListener(t *testing.T) {
	file := os.Getenv("UPTERM_FTEST_LISTENER")
	if file == "" {
		return
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	// Publish readiness atomically: observing a newly created empty file is not readiness.
	require.NoError(t, os.WriteFile(file+".ready", []byte(ln.Addr().String()), 0600))
	require.NoError(t, os.Rename(file+".ready", file))
	defer func() { _ = os.WriteFile(file+".stopped", []byte("stopped"), 0600) }()
	deadline := time.Now().Add(30 * time.Second)
	for {
		_ = ln.(*net.TCPListener).SetDeadline(deadline)
		socket, err := ln.Accept()
		if err != nil {
			return
		}
		_ = socket.SetDeadline(deadline)
		b := make([]byte, 4)
		_, err = io.ReadFull(socket, b)
		if err == nil && string(b) == "stop" {
			_ = socket.Close()
			return
		}
		if err == nil {
			_, _ = socket.Write([]byte("owned-listener"))
		}
		_ = socket.Close()
	}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func testExecBootstrapOwnedListener(t *testing.T, hostURL, node, joinURL string) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX nohup bootstrap; portable exec/forward coverage runs separately")
	}
	h := execFixture(t)
	h.AllowLoopbackTCPForwarding = true
	record := shareHost(t, h, hostURL, node)
	c := connectRelayGuest(t, record, joinURL)
	address := startOwnedRelayListener(t, c)
	require.NoError(t, c.sshClient.Close())
	fresh := connectRelayGuest(t, record, joinURL)
	requireOwnedListenerReachable(t, fresh, address)
}

func requireOwnedListenerReachable(t *testing.T, c *Client, address string) {
	t.Helper()
	socket, err := c.sshClient.Dial("tcp", address)
	require.NoError(t, err)
	defer func() { _ = socket.Close() }()
	_, err = socket.Write([]byte("ping"))
	require.NoError(t, err)
	reply, err := io.ReadAll(socket)
	require.NoError(t, err)
	require.Equal(t, "owned-listener", string(reply))
}

func startOwnedRelayListener(t *testing.T, c *Client) string {
	t.Helper()
	executable, err := os.Executable()
	require.NoError(t, err)
	file := filepath.Join(t.TempDir(), "listener.addr")
	// Redirect all three streams: this fixture specifically owns a service whose
	// lifetime is separate from the bootstrap's foreground leader.
	raw := "UPTERM_FTEST_LISTENER=" + shellQuote(file) + " nohup " + shellQuote(executable) + " -test.run='^TestGuestToolListener$' >" + shellQuote(file+".log") + " 2>&1 </dev/null &"
	_, _, status := relayExec(t, c, raw, nil)
	require.Equal(t, 0, status)
	require.Eventually(t, func() bool { _, e := os.ReadFile(file); return e == nil }, reachTimeout, redialPoll)
	b, err := os.ReadFile(file)
	require.NoError(t, err)
	address := string(b)
	t.Cleanup(func() {
		socket, e := net.DialTimeout("tcp", address, time.Second)
		if e == nil {
			_, _ = socket.Write([]byte("stop"))
			_ = socket.Close()
		}
		require.Eventually(t, func() bool { _, e := os.Stat(file + ".stopped"); return e == nil }, reachTimeout, redialPoll, "owned listener did not stop")
	})
	return address
}

// TestGuestToolProcess uses this existing test binary as an explicitly owned
// child so portable protocol cases exercise exact bytes and real exit codes
// without depending on an installed tool or a particular shell's builtins.
func TestGuestToolProcess(t *testing.T) {
	mode := ""
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "--upterm-ftest-mode=") {
			mode = strings.TrimPrefix(arg, "--upterm-ftest-mode=")
		}
	}
	if mode == "" {
		return
	}
	switch {
	case mode == "binary":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{0, 1, 127, 255, 13, 10}, 65536))
		_, _ = os.Stderr.Write(bytes.Repeat([]byte{255, 0, 'e', 'r', 'r', 13, 10}, 32768))
		os.Exit(23)
	case strings.HasPrefix(mode, "probe-"):
		i, err := strconv.Atoi(strings.TrimPrefix(mode, "probe-"))
		if err != nil {
			os.Exit(127)
		}
		_, _ = fmt.Fprintf(os.Stdout, "probe-%d", i)
		_, _ = fmt.Fprintf(os.Stderr, "err-%d", i)
		os.Exit(i + 20)
	case mode == "hold" || mode == "foreground":
		_, _ = os.Stdout.Write([]byte("R"))
		_, _ = io.Copy(io.Discard, os.Stdin)
		if mode == "hold" {
			os.Exit(23)
		}
		os.Exit(0)
	case mode == "login":
		_, _ = io.WriteString(os.Stdout, "login only")
	case mode == "explicit":
		_, _ = io.WriteString(os.Stdout, "explicit exec")
	case mode == "sibling":
		_, _ = io.WriteString(os.Stdout, "sibling still usable")
	case mode == "reconnected":
		_, _ = io.WriteString(os.Stdout, "reconnected")
		os.Exit(23)
	case mode == "status23":
		os.Exit(23)
	default:
		_, _ = io.WriteString(os.Stdout, mode)
	}
	os.Exit(0)
}

func guestToolArgv(t *testing.T, mode string) []string {
	t.Helper()
	executable, err := os.Executable()
	require.NoError(t, err)
	return []string{executable, "-test.run=^TestGuestToolProcess$", "--", "--upterm-ftest-mode=" + mode}
}
func guestToolCommand(t *testing.T, mode string) string {
	t.Helper()
	argv := guestToolArgv(t, mode)
	powershell := false
	if runtime.GOOS == "windows" {
		for _, name := range []string{"pwsh", "powershell"} {
			if _, err := exec.LookPath(name); err == nil {
				powershell = true
				break
			}
		}
	}
	for i, arg := range argv {
		switch {
		case powershell:
			argv[i] = "'" + strings.ReplaceAll(arg, "'", "''") + "'"
		case runtime.GOOS == "windows":
			argv[i] = `"` + strings.ReplaceAll(arg, `"`, `""`) + `"`
		default:
			argv[i] = shellQuote(arg)
		}
	}
	raw := strings.Join(argv, " ")
	if powershell {
		// -Command otherwise normalizes a native child's nonzero status to 1.
		return "& " + raw + "; exit $LASTEXITCODE"
	}
	return raw
}
