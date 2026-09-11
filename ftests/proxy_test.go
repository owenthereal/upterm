package ftests

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/ws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// ProxyTestCases pins the behaviour of the relay's front door at the SSH
// connection-protocol layer.
//
// The relay forwards decrypted SSH *packets* today, so channel numbering,
// windows, request ordering and close ordering all survive untouched and none
// of the cases below can fail for a reason the front door is responsible for.
// Replacing it with a stock golang.org/x/crypto proxy terminates the channel
// layer on each side and re-originates every channel and every request, at
// which point each of these becomes a way to lose data silently. They are
// written against the piper first so that a failure afterwards means the
// rewrite broke something, rather than meaning the test was never right.
//
// Not covered here, deliberately, because upterm's guest surface cannot reach
// them and a test that cannot fail is worse than no test:
//
//   - stderr as a separate stream. Nothing on the host writes to a session
//     channel's extended-data stream, so a forwarder that dropped Stderr()
//     entirely would still pass every case in this package.
//   - stdin half-close. The host ends the session when the guest's stdin
//     reaches EOF, so there is no post-EOF behaviour to pin.
//   - a guest whose key the *host* rejects. The relay checks the guest's key
//     against the session's authorized keys during its own auth, so the host
//     never sees a key it will refuse. testClientAuthorizedKeyNotMatching
//     covers the relay-rejects case, which is the one that happens today.
//
// One case here does not use a Go client at all:
// testProxyStockSSHClientTrailingOutput drives the system ssh binary, because
// that is what README tells a guest to run and because a client that stopped
// reading on exit-status would truncate output in a way no x/crypto client
// test in this package can see. It skips where that binary or a direct ssh
// endpoint is unavailable.
//
// All three belong to the forwarder's own unit tests, against a stock SSH
// server and client with no upterm involved.
var ProxyTestCases = []FtestCase{
	testProxyExitStatus,
	testProxyForcedCommandExitStatus,
	testProxyStockSSHClientTrailingOutput,
	testProxyLargeTransfer,
	testProxyWindowChange,
	testProxyPreShellRequests,
	testProxyUnknownChannelRequest,
	testProxyConcurrentGuests,
	testProxyIdleKeepalive,
}

// TestProxy runs the channel-proxy characterization tests.
func (suite *FtestSuite) TestProxy() {
	suite.runTestCategory(ProxyTestCases)
}

// shellLineEnding matches what the Host and Client pumps append to input.
func shellLineEnding() string {
	if runtime.GOOS == "windows" {
		return "\r\n"
	}
	return "\n"
}

// exitCodeCommand returns a shell invocation that exits with code.
func exitCodeCommand(code int) []string {
	if runtime.GOOS == "windows" {
		return []string{"powershell", "-NoProfile", "-NoLogo", "-Command", fmt.Sprintf("exit %d", code)}
	}
	return []string{"bash", "-c", fmt.Sprintf("exit %d", code)}
}

// dialGuest opens a raw SSH connection to the relay as a guest, without the
// pty/shell/pump machinery Client.Join sets up. The request-level cases below
// need to drive the session channel themselves.
func dialGuest(t *testing.T, session *api.GetSessionResponse, clientJoinURL string) *ssh.Client {
	t.Helper()

	auths, err := authMethodsFromFiles([]string{ClientPrivateKey})
	require.NoError(t, err)

	config := &ssh.ClientConfig{
		User:            session.SshUser,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	u, err := url.Parse(clientJoinURL)
	require.NoError(t, err)

	var client *ssh.Client
	if u.Scheme == "ws" || u.Scheme == "wss" {
		encodedNodeAddr := base64.URLEncoding.EncodeToString([]byte(session.NodeAddr))
		u.User = url.UserPassword(session.SessionId, encodedNodeAddr)
		client, err = ws.NewSSHClient(u, config, true)
	} else {
		client, err = ssh.Dial("tcp", u.Host, config)
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	return client
}

// shareHost starts a host and returns its session record.
func shareHost(t *testing.T, h *Host, hostShareURL, hostNodeAddr string) *api.GetSessionResponse {
	t.Helper()

	require.NoError(t, h.Share(hostShareURL))
	t.Cleanup(h.Close)

	return getAndVerifySession(t, h.AdminSocketFile, hostShareURL, hostNodeAddr)
}

// requireStockSSH skips unless the system ssh binary can reach this topology,
// and returns its path.
//
// The ws topologies would need `upterm proxy` as a ProxyCommand, which means
// building and locating the CLI from a test. The ssh topologies are exactly
// what README.md:77 tells a guest to type, and they are what this case is
// about, so restricting to them costs no coverage that matters.
func requireStockSSH(t *testing.T, clientJoinURL string) string {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("stock ssh guest case is POSIX-only")
	}

	u, err := url.Parse(clientJoinURL)
	require.NoError(t, err)
	if u.Scheme != "ssh" {
		t.Skipf("stock ssh guest needs a direct ssh endpoint, got scheme %q", u.Scheme)
	}

	path, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh binary on PATH")
	}
	return path
}

// stockSSHGuestArgs builds the argv a guest would type, minus the binary.
//
// -tt forces a pty even though the test's stdin is not a terminal: upterm
// rejects a session without one. IdentitiesOnly keeps a developer's running
// agent from offering a key the session does not permit, which would surface
// as an auth failure that has nothing to do with this case.
func stockSSHGuestArgs(t *testing.T, session *api.GetSessionResponse, clientJoinURL string) []string {
	t.Helper()

	u, err := url.Parse(clientJoinURL)
	require.NoError(t, err)

	hostname, port, err := net.SplitHostPort(u.Host)
	require.NoError(t, err)

	return []string{
		"-tt",
		"-p", port,
		"-i", ClientPrivateKey,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + os.DevNull,
		"-o", "BatchMode=yes",
		"-o", "LogLevel=ERROR",
		session.SshUser + "@" + hostname,
	}
}

// trailingOutputCommand writes lines numbered from zero and then exits, with
// nothing in between, so exit-status is sent while output is still in flight.
func trailingOutputCommand(lines, code int) []string {
	return []string{"bash", "-c", fmt.Sprintf(
		`i=0; while [ $i -lt %d ]; do printf 'line-%%06d\n' $i; i=$((i+1)); done; exit %d`,
		lines, code)}
}

// testProxyStockSSHClientTrailingOutput joins with the system ssh binary and
// checks that output written immediately before exit arrives complete.
//
// README.md:77 documents `ssh TOKEN@uptermd.upterm.dev` as the way to join, so
// OpenSSH is the default guest, not an exotic one. exit-status is a channel
// request and can overtake buffered stdout inside the forwarder; the forwarder
// only guarantees that forwarded data precedes CLOSE. So a guest that stopped
// reading on exit-status would truncate here, and every Go-client test in this
// package would still pass. This is the case that says it does not.
func testProxyStockSSHClientTrailingOutput(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	// 200k lines of 12 bytes plus the pty's \r is ~2.6 MB, comfortably past
	// x/crypto's 2 MB channel window, so output is still being forwarded when
	// the command exits.
	const (
		wantLines = 200000
		wantCode  = 42
	)

	sshPath := requireStockSSH(t, clientJoinURL)

	adminSocketFile := setupAdminSocket(t)
	session := shareHost(t, &Host{
		Command:                  getTestShell(),
		ForceCommand:             trailingOutputCommand(wantLines, wantCode),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}, hostShareURL, hostNodeAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, sshPath, stockSSHGuestArgs(t, session, clientJoinURL)...)

	// Hold the guest's stdin open. ssh forwards its own stdin EOF, and the
	// host ends the session on stdin EOF, so /dev/null would race the forced
	// command's output. Nothing is ever written; cmd.Wait closes it.
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	defer func() { _ = stdin.Close() }()

	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	runErr := cmd.Run()
	require.NoError(t, ctx.Err(), "stock ssh guest timed out; stderr: %s", stderr.String())

	var exitErr *exec.ExitError
	require.ErrorAs(t, runErr, &exitErr,
		"expected the forced command's exit code, got %v; stderr: %s", runErr, stderr.String())
	assert.Equal(t, wantCode, exitErr.ExitCode(), "forced command's exit code should reach the stock ssh guest")

	out := stdout.String()
	assert.Equal(t, wantLines, strings.Count(out, "line-"),
		"every line written before the exit should reach the stock ssh guest")
	assert.Contains(t, out, fmt.Sprintf("line-%06d", wantLines-1),
		"the last line written before the exit should not be truncated by an early close")
}

// testProxyExitStatus pins that an exit status, and the output that precedes
// it, reach the guest.
//
// exit-status is a channel request the host sends immediately before closing
// the channel (RFC 4254 §6.10). A proxy that closes the downstream channel as
// soon as its data copy finishes drops it, and the guest reports "no exit
// status" or -1 with no explanation. This is the most common defect in this
// class of proxy: moul/sshportal shipped it for years (PR #183).
//
// The case used is a session with no pty, which upterm refuses with a message
// on stdout and exit status 1. That makes the expected status non-zero and
// deterministic, so the test detects a dropped exit-status, a zeroed payload,
// and output truncated by an early close, all three.
func testProxyExitStatus(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	adminSocketFile := setupAdminSocket(t)
	session := shareHost(t, &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}, hostShareURL, hostNodeAddr)

	client := dialGuest(t, session, clientJoinURL)

	sess, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = sess.Close() }()

	var stdout bytes.Buffer
	sess.Stdout = &stdout

	// No RequestPty: upterm rejects the session with exit status 1.
	require.NoError(t, sess.Shell())

	err = sess.Wait()

	var missing *ssh.ExitMissingError
	require.NotErrorAs(t, err, &missing,
		"guest received no exit-status before the channel closed")

	var exitErr *ssh.ExitError
	require.ErrorAs(t, err, &exitErr, "expected a non-zero exit status, got %v", err)
	assert.Equal(t, 1, exitErr.ExitStatus(), "exit status payload should survive the relay")

	assert.Contains(t, stdout.String(), "PTY is required",
		"output written before the exit status should not be truncated by the close")
}

// testProxyForcedCommandExitStatus pins that a forced command's exit code
// reaches the guest.
//
// This is the realistic shape of the exit-status hazard, and the case Expo's
// join.sh runs. It is also a regression test for the host: HandleSession used
// to read the status off run.Group's return value, which reports whichever
// actor finished first, so the command's wait raced the pty's EOF and the
// guest saw 42 or a clean 0 depending on scheduling.
func testProxyForcedCommandExitStatus(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	const wantCode = 42

	adminSocketFile := setupAdminSocket(t)
	session := shareHost(t, &Host{
		Command:                  getTestShell(),
		ForceCommand:             exitCodeCommand(wantCode),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}, hostShareURL, hostNodeAddr)

	client := dialGuest(t, session, clientJoinURL)

	sess, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = sess.Close() }()

	require.NoError(t, sess.RequestPty("xterm", 40, 80, ssh.TerminalModes{}))

	// Hold stdin open. With Session.Stdin nil, x/crypto copies an empty
	// buffer and calls CloseWrite immediately after Shell, and the host ends
	// the session on stdin EOF, so the forced command would never get to exit.
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	defer func() { _ = stdin.Close() }()

	require.NoError(t, sess.Shell())

	err = sess.Wait()

	var missing *ssh.ExitMissingError
	require.NotErrorAs(t, err, &missing,
		"guest received no exit-status before the channel closed")

	var exitErr *ssh.ExitError
	require.ErrorAs(t, err, &exitErr, "expected exit status %d, got %v", wantCode, err)
	assert.Equal(t, wantCode, exitErr.ExitStatus(), "forced command's exit code should reach the guest")
}

// testProxyLargeTransfer pushes several megabytes through the relay in both
// directions over the sftp subsystem.
//
// Packet piping has no per-hop flow control: the guest and the host negotiate
// one window end to end. A channel-level proxy gives each leg its own 2 MB
// window and must chain back-pressure between them, so a payload larger than
// one window is the smallest case that can deadlock or truncate.
func testProxyLargeTransfer(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	// Comfortably more than x/crypto's 2 MB per-direction channel window, so
	// the transfer cannot complete without the window being replenished.
	const payloadSize = 5 << 20

	testDir := t.TempDir()

	payload := make([]byte, payloadSize)
	_, err := rand.Read(payload)
	require.NoError(t, err)

	downloadPath := filepath.Join(testDir, "download.bin")
	require.NoError(t, os.WriteFile(downloadPath, payload, 0644))

	adminSocketFile := setupAdminSocket(t)
	session := shareHost(t, &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}, hostShareURL, hostNodeAddr)

	c := &Client{PrivateKeys: []string{ClientPrivateKey}}
	require.NoError(t, c.Join(session, clientJoinURL))
	defer c.Close()

	sftpClient, err := c.SFTP()
	require.NoError(t, err)
	defer func() { _ = sftpClient.Close() }()

	// Host to guest.
	f, err := sftpClient.Open(remotePath(downloadPath))
	require.NoError(t, err)
	got, err := io.ReadAll(f)
	_ = f.Close()
	require.NoError(t, err)
	require.Equal(t, payloadSize, len(got), "downloaded size should match")
	assert.True(t, bytes.Equal(payload, got), "downloaded bytes should be identical")

	// Guest to host.
	uploadPath := filepath.Join(testDir, "upload.bin")
	w, err := sftpClient.Create(remotePath(uploadPath))
	require.NoError(t, err)
	n, err := io.Copy(w, bytes.NewReader(payload))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.Equal(t, int64(payloadSize), n, "uploaded size should match")

	uploaded, err := os.ReadFile(uploadPath)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(payload, uploaded), "uploaded bytes should be identical")
}

// testProxyWindowChange resizes the terminal mid-session and checks the host's
// pty followed.
//
// window-change is an unsolicited channel request with WantReply false, sent
// after the shell has started. A forwarder that only relays the requests it
// recognises, or that stops reading a channel's request queue once the shell
// is running, drops it and the guest's terminal silently disagrees with the
// host's for the rest of the session.
//
// The round trip before the resize is load-bearing, and not only because it
// makes this a mid-session resize. charm.land/ssh does not guard sess.pty with
// the mutex the session struct already embeds, so the "window-change" case
// writing sess.pty.Window (session.go:412 in v0.4.3) races any handler reading
// sess.Pty(), which upterm's HandleSession does on entry. Resizing before the
// session has exchanged anything makes the two unordered and -race reports it.
// Unfixable from here, because Pty() is the only way to obtain the window
// channel; a guest that resizes in the first moments of a session can still
// hit it in production. Reported upstream with a fix; drop this round trip
// once a release carrying it is in go.mod.
func testProxyWindowChange(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	if runtime.GOOS == "windows" {
		t.Skip("stty is not available on Windows")
	}

	adminSocketFile := setupAdminSocket(t)
	session := shareHost(t, &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}, hostShareURL, hostNodeAddr)

	c := &Client{PrivateKeys: []string{ClientPrivateKey}}
	require.NoError(t, c.Join(session, clientJoinURL))
	defer c.Close()

	remoteInputCh, remoteOutputCh := c.InputOutput()
	deadlineAt := time.Now().Add(10 * time.Second)
	deadline := time.NewTimer(time.Until(deadlineAt))
	defer deadline.Stop()
	var pending, lastSize string

	// Read chunks directly so the deadline also bounds missing output, without
	// leaving a scanner goroutine blocked after this test closes the client.
	readLine := func() string {
		t.Helper()
		for {
			if !time.Now().Before(deadlineAt) {
				t.Fatalf("timed out observing terminal size; last stty size was %q, want 24 120", lastSize)
			}
			if line, rest, ok := strings.Cut(pending, "\n"); ok {
				pending = rest
				if line = stripShellPrompt(strings.TrimSpace(line)); line != "" {
					return line
				}
				continue
			}
			select {
			case chunk, ok := <-remoteOutputCh:
				require.True(t, ok, "terminal output closed before observing the requested size")
				pending += chunk
			case <-deadline.C:
				t.Fatalf("timed out waiting for terminal output; last stty size was %q, want 24 120", lastSize)
			}
		}
	}
	send := func(command string) {
		t.Helper()
		select {
		case remoteInputCh <- command:
		case <-deadline.C:
			t.Fatalf("timed out sending %q; last stty size was %q, want 24 120", command, lastSize)
		}
	}
	expect := func(want, message string) {
		t.Helper()
		const maxLines = 20
		var seen []string
		for i := 0; i < maxLines; i++ {
			got := readLine()
			if got == want {
				return
			}
			seen = append(seen, got)
		}
		assert.Fail(t, fmt.Sprintf("line %q not seen within %d lines; got %q", want, maxLines, seen), message)
	}

	// Establish the session before resizing, so this is a mid-session resize
	// rather than one racing the shell's start.
	send(`echo "before-resize"`)
	expect(`echo "before-resize"`, "guest should echo before resizing")
	expect("before-resize", "guest should see output before resizing")

	// Client.Join requests 40x80. Resize to something unmistakably different;
	// x/crypto's WindowChange takes rows first, the wire format is columns
	// first, and getting that backwards is a live hazard in this area.
	require.NoError(t, c.session.WindowChange(24, 120))

	// This checks eventual resize application. The proxy relays requests and
	// data independently, and the host applies window events separately from
	// copying stdin to the pty. WindowChange has no acknowledgement of that
	// application, so a following stty can still see the old size. Sampling
	// again tests resize delivery, not the proxy's packet ordering.
	retry := time.NewTicker(50 * time.Millisecond)
	defer retry.Stop()
	for {
		send("stty size")
		expect("stty size", "guest should echo the command")
		lastSize = readLine()
		if lastSize == "24 120" {
			return
		}
		select {
		case <-retry.C:
		case <-deadline.C:
			t.Fatalf("host pty should have been resized to 24 rows by 120 columns; last stty size was %q", lastSize)
		}
	}
}

// testProxyPreShellRequests sends channel requests before starting the shell.
//
// env arrives between pty-req and shell, with WantReply true, and RFC 4254 §4
// requires replies on one channel to come back in the order the requests were
// sent. A forwarder that answers requests concurrently, or that starts
// relaying only once it has seen a shell, breaks the guest's handshake in a
// way that looks like a hang rather than an error.
func testProxyPreShellRequests(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	adminSocketFile := setupAdminSocket(t)
	session := shareHost(t, &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}, hostShareURL, hostNodeAddr)

	client := dialGuest(t, session, clientJoinURL)

	sess, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = sess.Close() }()

	for i := range 4 {
		require.NoError(t, sess.Setenv(fmt.Sprintf("UPTERM_FTEST_%d", i), fmt.Sprintf("value-%d", i)),
			"env request %d should be answered", i)
	}

	require.NoError(t, sess.RequestPty("xterm", 40, 80, ssh.TerminalModes{}))

	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)

	require.NoError(t, sess.Shell(), "shell should start after the pre-shell requests")

	// The session is still usable, which is the point: the requests were
	// forwarded and answered without desynchronising the channel.
	_, err = io.WriteString(stdin, "echo pre-shell-ok"+shellLineEnding())
	require.NoError(t, err)

	outputCh := make(chan string)
	go func() {
		buf := make([]byte, 4096)
		var seen bytes.Buffer
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				seen.Write(buf[:n])
				if bytes.Contains(seen.Bytes(), []byte("pre-shell-ok")) {
					outputCh <- seen.String()
					return
				}
			}
			if err != nil {
				outputCh <- seen.String()
				return
			}
		}
	}()

	select {
	case got := <-outputCh:
		assert.Contains(t, got, "pre-shell-ok", "shell should work after pre-shell requests")
	case <-time.After(callbackTimeout):
		t.Fatal("shell produced no output after pre-shell requests")
	}
}

// testProxyUnknownChannelRequest sends a channel request nothing understands.
//
// RFC 4254 §5.4 says an unrecognised request gets SSH_MSG_CHANNEL_FAILURE, not
// a dropped connection. The relay must forward it and relay the refusal rather
// than answering on the host's behalf: the moment it starts deciding which
// request types are allowed, every extension OpenSSH adds later stops working
// through upterm, and the failure mode is silence.
func testProxyUnknownChannelRequest(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	adminSocketFile := setupAdminSocket(t)
	session := shareHost(t, &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}, hostShareURL, hostNodeAddr)

	client := dialGuest(t, session, clientJoinURL)

	sess, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = sess.Close() }()

	require.NoError(t, sess.RequestPty("xterm", 40, 80, ssh.TerminalModes{}))

	// Hold stdin open so the host does not end the session out from under the
	// requests below; see testProxyExitStatus.
	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	defer func() { _ = stdin.Close() }()

	require.NoError(t, sess.Shell())

	ok, err := sess.SendRequest("not-a-real-request@upterm.dev", true, []byte("payload"))
	require.NoError(t, err, "an unknown request should be refused, not kill the channel")
	assert.False(t, ok, "an unknown request should be refused")

	// The connection survived the refusal.
	ok, err = sess.SendRequest("also-not-real@upterm.dev", true, nil)
	require.NoError(t, err, "the channel should still be usable after a refused request")
	assert.False(t, ok)

	_, _, err = client.SendRequest("not-a-real-global@upterm.dev", true, nil)
	require.NoError(t, err, "the connection should still be usable after a refused global request")
}

// testProxyConcurrentGuests attaches several guests to one session at once.
//
// Every guest is a separate SSH connection through the relay to the same host,
// and the host fans its pty output out to all of them. A forwarder that keeps
// per-connection state in the wrong place mixes their channels together; the
// symptom is one guest seeing another's output, or a single guest leaving and
// taking the others with it.
func testProxyConcurrentGuests(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	const guests = 8

	adminSocketFile := setupAdminSocket(t)
	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	session := shareHost(t, h, hostShareURL, hostNodeAddr)

	hostInputCh, hostOutputCh := h.InputOutput()
	hostScanner := scanner(hostOutputCh)

	scanners := make([]*bufio.Scanner, 0, guests)
	for i := range guests {
		c := &Client{PrivateKeys: []string{ClientPrivateKey}}
		require.NoError(t, c.Join(session, clientJoinURL), "guest %d should join", i)
		t.Cleanup(c.Close)

		_, out := c.InputOutput()
		scanners = append(scanners, scanner(out))
	}

	// One line from the host must reach every guest.
	hostInputCh <- `echo "broadcast"`
	expectLine(t, hostScanner, `echo "broadcast"`, "host should echo the command")
	expectLine(t, hostScanner, "broadcast", "host should show the output")

	var wg sync.WaitGroup
	for i, s := range scanners {
		wg.Add(1)
		go func(i int, s *bufio.Scanner) {
			defer wg.Done()
			expectLine(t, s, "broadcast", "guest %d should see the host's output", i)
		}(i, s)
	}
	wg.Wait()
}

// testProxyIdleKeepalive leaves a session idle across several keepalive
// intervals.
//
// The host sends keepalive@openssh.com as a channel request with WantReply
// true every KeepAliveDuration, and its reverse tunnel sends the global-request
// form to the relay. Any reply, success or failure, satisfies OpenSSH; no reply
// tears the connection down. This is the case that catches a forwarder which
// stops servicing a request queue once a channel goes quiet, because in
// x/crypto an unread request channel blocks the whole connection's mux loop.
func testProxyIdleKeepalive(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	adminSocketFile := setupAdminSocket(t)
	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	session := shareHost(t, h, hostShareURL, hostNodeAddr)

	c := &Client{PrivateKeys: []string{ClientPrivateKey}}
	require.NoError(t, c.Join(session, clientJoinURL))
	defer c.Close()

	remoteInputCh, remoteOutputCh := c.InputOutput()
	remoteScanner := scanner(remoteOutputCh)

	remoteInputCh <- `echo "before-idle"`
	expectLine(t, remoteScanner, `echo "before-idle"`, "guest should echo before going idle")
	expectLine(t, remoteScanner, "before-idle", "guest should see output before going idle")

	// Long enough for several keepalive rounds in both directions with no
	// other traffic on the connection.
	time.Sleep(3 * keepAliveDuration)

	remoteInputCh <- `echo "after-idle"`
	expectLine(t, remoteScanner, `echo "after-idle"`, "session should survive the idle period")
	expectLine(t, remoteScanner, "after-idle", "session should still carry output after the idle period")
}
