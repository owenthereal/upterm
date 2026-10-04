package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// reconnectSessionInfo is the part of `upterm host --detach -o json` and
// `upterm session info -o json` this test reads.
type reconnectSessionInfo struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	SessionID    string `json:"sessionId"`
	SSHCommand   string `json:"sshCommand"`
	TunnelReason string `json:"tunnelReason"`
	LogPath      string `json:"logPath"`
}

// testRelay is an uptermd built for one test. It listens on one loopback port
// and runs with one host key however many times it is restarted: a host that
// redials a relay it has already pinned accepts the new run only if its key
// is the one it pinned, and only the same address gives the same connect string.
type testRelay struct {
	t       *testing.T
	bin     string
	keyFile string
	logFile string
	addr    string

	cmd  *exec.Cmd
	done chan struct{} // closed once cmd has been reaped
}

// newTestRelay builds uptermd and picks the port and host key it will run
// with. It starts nothing, and registers the cleanup that kills whichever run
// is current.
func newTestRelay(t *testing.T) *testRelay {
	t.Helper()
	dir := t.TempDir()
	r := &testRelay{
		t:       t,
		bin:     filepath.Join(dir, "uptermd"),
		keyFile: filepath.Join(dir, "uptermd_host_key"),
		logFile: filepath.Join(dir, "uptermd.log"),
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "go", "build", "-o", r.bin, "github.com/owenthereal/upterm/cmd/uptermd").CombinedOutput()
	require.NoError(t, err, "building uptermd: %s", out)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(r.keyFile, pem.EncodeToMemory(block), 0600))

	// A port that was free a moment ago: nothing else on a test machine is
	// likely to take it before uptermd does.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	r.addr = l.Addr().String()
	require.NoError(t, l.Close())

	t.Cleanup(r.kill)
	return r
}

// start runs uptermd and returns once it accepts connections.
func (r *testRelay) start() {
	r.t.Helper()
	log, err := os.OpenFile(r.logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	require.NoError(r.t, err)
	defer func() { _ = log.Close() }() // the child keeps its own copy

	cmd := exec.Command(r.bin, "--ssh-addr", r.addr, "--private-key", r.keyFile)
	cmd.Stdout, cmd.Stderr = log, log
	require.NoError(r.t, cmd.Start())
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	r.cmd, r.done = cmd, done

	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		select {
		case <-done:
			r.t.Fatalf("uptermd exited before it listened on %s:\n%s", r.addr, r.logTail())
		default:
		}
		if conn, err := net.DialTimeout("tcp", r.addr, time.Second); err == nil {
			_ = conn.Close()
			return
		}
	}
	r.t.Fatalf("uptermd did not listen on %s in time:\n%s", r.addr, r.logTail())
}

// kill ends the current run abruptly, SIGKILL on Unix, and waits for it to be
// reaped. It is safe to call with no run, or one that has already ended.
func (r *testRelay) kill() {
	if r.cmd == nil {
		return
	}
	_ = r.cmd.Process.Kill()
	<-r.done
	r.cmd = nil
}

func (r *testRelay) logTail() string { return fileTail(r.logFile) }

// fileTail is the last 40 lines of the file at path, or why they can't be
// shown: a failure log must never fail the cleanup that prints it.
func fileTail(path string) string {
	if path == "" {
		return "(no log path to read)"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > 40 {
		lines = lines[len(lines)-40:]
	}
	return strings.Join(lines, "\n")
}

// uptermOutput runs the upterm CLI and returns its stdout and stderr apart, so
// that JSON is parsed from stdout alone and a warning on stderr cannot break it.
func uptermOutput(ctx context.Context, timeout time.Duration, args ...string) (stdout, stderr []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var out, errOut bytes.Buffer
	cmd := exec.CommandContext(ctx, "upterm", args...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	cmd.WaitDelay = time.Second
	err = cmd.Run()
	return out.Bytes(), errOut.Bytes(), err
}

// infoPoller reads `upterm session info -o json` for one session and keeps the
// last answer, for the failure log and for the caller of a poll that succeeded.
type infoPoller struct {
	ctx  context.Context
	name string

	mu   sync.Mutex
	raw  string
	info reconnectSessionInfo
}

func (p *infoPoller) read() (reconnectSessionInfo, error) {
	stdout, stderr, err := uptermOutput(p.ctx, 5*time.Second, "session", "info", p.name, "-o", "json")
	p.mu.Lock()
	p.raw = string(stdout) + string(stderr)
	p.mu.Unlock()
	var info reconnectSessionInfo
	if err == nil {
		err = json.Unmarshal(stdout, &info)
	}
	if err == nil {
		p.mu.Lock()
		p.info = info
		p.mu.Unlock()
	}
	return info, err
}

// until polls every 200 ms until check holds on a session info, or fails the
// test after timeout. It returns the answer that satisfied check.
func (p *infoPoller) until(t *testing.T, timeout time.Duration, msg string, check func(c *assert.CollectT, info reconnectSessionInfo)) reconnectSessionInfo {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		info, err := p.read()
		require.NoError(c, err)
		check(c, info)
	}, timeout, 200*time.Millisecond, msg)
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.info
}

func (p *infoPoller) last() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.raw
}

// hostLogPath is the host daemon's log, from the last answer that parsed. It
// is where the redial attempts and their reasons are written.
func (p *infoPoller) hostLogPath() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.info.LogPath
}

// A detached session whose relay is killed redials it, and when uptermd comes
// back on the same address it is registered again under the same session ID:
// the connect string it printed at the start keeps working for a guest. Every
// step runs a real uptermd, upterm and ssh.
func TestReconnectAfterTheRelayIsKilled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the e2e suite drives tmux, which Windows does not have")
	}
	skipIfNoTmux(t)

	// Built first so that its cleanup runs last: the session is stopped while
	// the relay it is attached to still answers.
	relay := newTestRelay(t)
	h := newTestHarness(t, 200)
	poll := &infoPoller{ctx: h.ctx, name: h.name}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("uptermd log (tail):\n%s", relay.logTail())
			t.Logf("last session info:\n%s", poll.last())
			t.Logf("host log (tail):\n%s", fileTail(poll.hostLogPath()))
		}
	})

	relay.start()

	stdout, stderr, err := uptermOutput(h.ctx, 30*time.Second, "host", "--detach", "--accept", "-o", "json",
		"--server", "ssh://"+relay.addr,
		"--known-hosts", filepath.Join(h.tmpDir, "known_hosts"), "--skip-host-key-check",
		"--private-key", h.keyFile, "--name", h.name,
		"--", "bash", "--rcfile", h.rcFile, "--noprofile")
	require.NoError(t, err, "upterm host failed:\nstdout: %s\nstderr: %s", stdout, stderr)
	var started reconnectSessionInfo
	require.NoError(t, json.Unmarshal(stdout, &started), "stdout: %s\nstderr: %s", stdout, stderr)
	require.Equal(t, h.name, started.Name)
	require.NotEmpty(t, started.SessionID)
	require.NotEmpty(t, started.SSHCommand)

	poll.until(t, 30*time.Second, "the session never became ready", func(c *assert.CollectT, info reconnectSessionInfo) {
		require.Equal(c, "ready", info.Status)
		require.Equal(c, started.SessionID, info.SessionID)
	})

	// The relay dies without a goodbye. The host sees its tunnel drop and
	// starts redialling; the closed port keeps every attempt a network failure.
	relay.kill()

	reconnecting := poll.until(t, 10*time.Second, "the session never reported reconnecting with a network reason",
		func(c *assert.CollectT, info reconnectSessionInfo) {
			require.Equal(c, "reconnecting", info.Status)
			require.Equal(c, "network", info.TunnelReason)
		})
	require.Equal(t, started.SessionID, reconnecting.SessionID)
	require.Equal(t, started.SSHCommand, reconnecting.SSHCommand,
		"the connect string must stay on show while the session reconnects")

	// The same address and host key: the restarted relay is the one the host
	// pinned, and the next attempt that reaches it registers the session again.
	relay.start()

	poll.until(t, 40*time.Second, "the session never came back to ready under its own session ID",
		func(c *assert.CollectT, info reconnectSessionInfo) {
			require.Equal(c, "ready", info.Status)
			require.Equal(c, started.SessionID, info.SessionID)
		})

	// A guest joins with the command the session printed before the outage.
	client := h.splitPane(h.host)
	h.connectClientWithKey(client, started.SSHCommand, h.clientKeyFile)
}
