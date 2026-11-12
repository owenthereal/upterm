package ftests

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/testhelpers/proxyfront"
	"github.com/owenthereal/upterm/internal/testhelpers/testextension/calls"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// buildBinary builds the command at pkg, this checkout's, as name.
func buildBinary(t *testing.T, name, pkg string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), name)
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "building %s: %s", pkg, output)
	return out
}

// extensionRelay is a running uptermd-test, enabled, behind a PROXY v2 front:
// its SSH listener takes only connections that come through the front.
type extensionRelay struct {
	front string // host:port, where the test broker places runs
	keys  string // the relay's key, as an authorized_keys line
}

func startExtensionRelay(t *testing.T) *extensionRelay {
	t.Helper()
	bin := buildBinary(t, "uptermd-test", "github.com/owenthereal/upterm/internal/testhelpers/testextension/cmd/uptermd-test")
	keyFile := filepath.Join(t.TempDir(), "relay_key")
	require.NoError(t, os.WriteFile(keyFile, []byte(ServerPrivateKeyContent), 0o600))
	relayKey, err := ssh.ParsePrivateKey([]byte(ServerPrivateKeyContent))
	require.NoError(t, err)
	for attempt := 1; ; attempt++ {
		sshAddr, releaseSSH := reserveLoopback(t)
		internal, releaseInternal := reserveLoopback(t)
		args := []string{
			"--ssh-addr", sshAddr, "--ssh-network", "tcp4", "--ssh-proxy-protocol-required",
			"--internal-addr", internal, "--node-addr", internal, "--node-id", "node-test",
			"--legacy-hops=false", "--private-key", keyFile,
			// The relay presents a host certificate, and a delegated run's
			// relay names the host it is dialled at in its own.
			"--hostname", "127.0.0.1",
		}
		output := &syncBuffer{}
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Stdout, cmd.Stderr = output, output
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
		releaseSSH()
		releaseInternal()
		require.NoError(t, cmd.Start())
		exited := make(chan struct{})
		go func() { _ = cmd.Wait(); close(exited) }()
		stop := func() { cancel(); <-exited }
		started := false
		deadline := time.After(15 * time.Second)
	wait:
		for !started {
			select {
			case <-exited:
				break wait
			case <-deadline:
				stop()
				t.Fatalf("uptermd-test never started:\n%s", output.String())
			case <-time.After(20 * time.Millisecond):
				started = strings.Contains(output.String(), "starting server")
			}
		}
		if !started {
			cancel()
			require.True(t, strings.Contains(output.String(), "address already in use") && attempt < 5,
				"uptermd-test (%s) exited:\n%s", strings.Join(args, " "), output.String())
			continue
		}
		t.Cleanup(func() {
			stop()
			if t.Failed() {
				t.Logf("uptermd-test (%s) output:\n%s", strings.Join(args, " "), output.String())
			}
		})
		require.Eventually(t, func() bool {
			c, err := net.DialTimeout("tcp4", sshAddr, time.Second)
			if err != nil {
				return false
			}
			_ = c.Close()
			return true
		}, 15*time.Second, 50*time.Millisecond, "uptermd-test never listened on %s:\n%s", sshAddr, output.String())
		front, err := proxyfront.Start("127.0.0.1:0", sshAddr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = front.Close() })
		return &extensionRelay{front: front.Addr(), keys: string(ssh.MarshalAuthorizedKey(relayKey.PublicKey()))}
	}
}

// syncBuffer is an io.Writer a test can read while a process writes it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// reserveLoopback holds a loopback port open until release closes it, for
// the process that takes it.
func reserveLoopback(t *testing.T) (addr string, release func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// cliEnv is the environment upterm-test runs in: a home and XDG roots of its
// own, and the test extension told where to place runs and what to log.
type cliEnv struct {
	bin, home, log, config string
	env                    []string
}

func newCLIEnv(t *testing.T, relay *extensionRelay) *cliEnv {
	t.Helper()
	home := shortXDGDir(t)
	runtimeDir := filepath.Join(home, "r")
	require.NoError(t, os.Mkdir(runtimeDir, 0o700))
	c := &cliEnv{
		bin:    buildBinary(t, "upterm-test", "github.com/owenthereal/upterm/internal/testhelpers/testextension/cmd/upterm-test"),
		home:   home,
		log:    filepath.Join(home, "extension.log"),
		config: filepath.Join(home, "c", "upterm", "config.yaml"),
	}
	require.NoError(t, os.MkdirAll(filepath.Dir(c.config), 0o700))
	c.env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home, "USERPROFILE=" + home, "SHELL=/bin/sh",
		"XDG_STATE_HOME=" + filepath.Join(home, "s"), "XDG_CONFIG_HOME=" + filepath.Join(home, "c"),
		"XDG_DATA_HOME=" + filepath.Join(home, "d"), "XDG_CACHE_HOME=" + filepath.Join(home, "k"),
		"XDG_RUNTIME_DIR=" + runtimeDir,
		calls.LogEnv + "=" + c.log,
	}
	if systemRoot := os.Getenv("SystemRoot"); systemRoot != "" {
		c.env = append(c.env, "SystemRoot="+systemRoot)
	}
	if relay != nil {
		c.env = append(c.env, calls.RelayEnv+"="+relay.front, calls.KeysEnv+"="+relay.keys)
	}
	return c
}

// run runs upterm-test with args, and extra in its environment.
func (c *cliEnv) run(t *testing.T, extra []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := exec.Command(c.bin, args...)
	cmd.Env = append(append([]string{}, c.env...), extra...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	code = cmd.ProcessState.ExitCode()
	if err != nil && code < 0 {
		t.Fatalf("upterm-test %s: %v", strings.Join(args, " "), err)
	}
	return out.String(), errOut.String(), code
}

// hostDetached starts a detached delegated session with args, and stops it
// when the test ends. It returns what --detach -o json printed.
func (c *cliEnv) hostDetached(t *testing.T, extra []string, args ...string) map[string]any {
	t.Helper()
	argv := append([]string{"host", "--detach", "--accept", "-o", "json", "--test-delegate"}, args...)
	stdout, stderr, code := c.run(t, extra, argv...)
	require.Equal(t, 0, code, "upterm-test %s:\nstdout: %s\nstderr: %s\nlog: %s", strings.Join(argv, " "), stdout, stderr, c.daemonLog(t))
	var started map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &started), stdout)
	name, _ := started["name"].(string)
	require.NotEmpty(t, name, stdout)
	t.Cleanup(func() {
		_, _, _ = c.run(t, nil, "session", "stop", name)
		if pid, ok := started["pid"].(float64); ok {
			if p, err := os.FindProcess(int(pid)); err == nil {
				_ = p.Kill()
			}
		}
	})
	return started
}

func (c *cliEnv) daemonLog(t *testing.T) string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(c.home, "s", "upterm", "upterm.log"))
	return string(b)
}

// calls is every call the test extension logged, by kind.
func (c *cliEnv) logged(t *testing.T) (factories []calls.FactoryCall, places []calls.PlaceCall) {
	t.Helper()
	f, err := os.Open(c.log)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var kind struct{ Kind string }
		require.NoError(t, json.Unmarshal(sc.Bytes(), &kind))
		switch kind.Kind {
		case "factory":
			var call calls.FactoryCall
			require.NoError(t, json.Unmarshal(sc.Bytes(), &call))
			factories = append(factories, call)
		case "place":
			var call calls.PlaceCall
			require.NoError(t, json.Unmarshal(sc.Bytes(), &call))
			places = append(places, call)
		}
	}
	require.NoError(t, sc.Err())
	return factories, places
}

// hostedCommand is a command that runs until it is stopped, as the hosted
// command of a session.
func hostedCommand() []string { return getTestShell() }

func TestDaemonUsesTheParentsSnapshot(t *testing.T) {
	relay := startExtensionRelay(t)
	c := newCLIEnv(t, relay)
	require.NoError(t, os.WriteFile(c.config, []byte("read-only: false\nforce-command: /bin/echo forced\nextensions:\n  test:\n    test-service: one\n"), 0o600))
	// What Prepare writes, after the parent has read the file and before the
	// session process starts.
	rewrite := calls.RewriteConfigEnv + "=read-only: true\nextensions:\n  test:\n    test-service: two\n"

	started := c.hostDetached(t, []string{rewrite}, append([]string{"--"}, hostedCommand()...)...)
	content, err := os.ReadFile(c.config)
	require.NoError(t, err)
	require.Contains(t, string(content), "test-service: two", "Prepare didn't rewrite the file")

	require.Equal(t, false, started["readOnly"], started)
	require.Equal(t, "/bin/echo forced", started["forceCommand"], started)

	factories, places := c.logged(t)
	require.Len(t, factories, 1)
	require.False(t, factories[0].Settings.ReadOnly)
	require.Equal(t, "/bin/echo forced", factories[0].Settings.ForceCommand)
	require.Equal(t, "one", factories[0].Extension["test-service"].Value)
	require.Equal(t, calls.Payload, factories[0].Payload)
	require.Len(t, places, 1)
	require.Equal(t, []string{"/bin/echo", "forced"}, places[0].ForceCommand)
	require.Contains(t, places[0].Capabilities, "exec")
	require.Contains(t, places[0].Capabilities, "direct-tcpip")
}

func TestDelegatedRunResolvesNoKeysAndIgnoresOSSFlags(t *testing.T) {
	relay := startExtensionRelay(t)
	c := newCLIEnv(t, relay)
	var conns atomic.Int32
	keys := httptest.NewUnstartedServer(http.NotFoundHandler())
	keys.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	keys.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	keys.StartTLS()
	t.Cleanup(keys.Close)
	knownHosts := filepath.Join(c.home, "known_hosts")
	const lines = "other ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"
	require.NoError(t, os.WriteFile(knownHosts, []byte(lines), 0o600))

	started := c.hostDetached(t, nil,
		"--authorized-user", "github:alice@"+strings.TrimPrefix(keys.URL, "https://"), "--github-user", "alice",
		"--server", "ssh://other.invalid:22", "--known-hosts", knownHosts, "--skip-host-key-check", "--proxy", "socks5://x",
		"--", hostedCommand()[0])

	require.Zero(t, conns.Load(), "a user's keys were fetched")
	content, err := os.ReadFile(knownHosts)
	require.NoError(t, err)
	require.Equal(t, lines, string(content), "known_hosts changed")
	// It registered, which the relay refuses to a delegated run that lists
	// keys, and at the relay the placement named.
	require.Equal(t, "ready", started["status"], started)
	require.Equal(t, "delegated", started["access"], started)
	delegation, _ := started["delegation"].(map[string]any)
	require.Equal(t, "Test authority", delegation["authority"], started)
	require.Contains(t, c.daemonLog(t), relay.front)

	factories, _ := c.logged(t)
	require.Len(t, factories, 1)
	require.Empty(t, factories[0].Settings.Proxy)
	require.Empty(t, factories[0].Flags["proxy"].Value)
	require.Equal(t, "command-line", string(factories[0].Flags["proxy"].Source))
	require.Equal(t, []string{"--authorized-user=github:alice@" + strings.TrimPrefix(keys.URL, "https://"), "--github-user=github:alice"}, factories[0].UserRefs)
}

func TestNormalizedNamesAreClaimedByTheBuiltCLI(t *testing.T) {
	relay := startExtensionRelay(t)
	c := newCLIEnv(t, relay)
	// A command named R, which runs until it is stopped.
	dir := t.TempDir()
	r := filepath.Join(dir, "R")
	want := `^r-[0-9a-f]{4}$`
	if runtime.GOOS == "windows" {
		r += ".cmd"
		want = `^r\.cmd-[0-9a-f]{4}$`
		require.NoError(t, os.WriteFile(r, []byte("@ping -n 600 127.0.0.1 >nul\r\n"), 0o700))
	} else {
		require.NoError(t, os.WriteFile(r, []byte("#!/bin/sh\nexec sleep 600\n"), 0o700))
	}

	started := c.hostDetached(t, nil, "--", r)
	require.Regexp(t, want, started["name"])
	started = c.hostDetached(t, nil, "--name", "Work", "--", r)
	require.Equal(t, "work", started["name"])
	_, places := c.logged(t)
	require.Len(t, places, 2)
	require.True(t, places[0].NameGenerated)
	require.Equal(t, "work", places[1].Name)
	require.False(t, places[1].NameGenerated)

	// An ordinary run's session process claims the normalized name too,
	// though its argv still says --name "Work Space".
	stdout, stderr, code := c.run(t, nil, "host", "--detach", "--accept", "-o", "json", "--name", "Work Space",
		"--server", "ssh://"+relay.front, "--skip-host-key-check", "--known-hosts", filepath.Join(c.home, "known_hosts"), "--", r)
	require.Equal(t, 0, code, "stdout: %s\nstderr: %s\nlog: %s", stdout, stderr, c.daemonLog(t))
	var ordinary map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &ordinary), stdout)
	require.Equal(t, "work-space", ordinary["name"])
	t.Cleanup(func() { _, _, _ = c.run(t, nil, "session", "stop", "work-space") })

	_, stderr, code = c.run(t, nil, "host", "--detach", "--accept", "--test-delegate", "--name", "Refused", "--", r)
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: the test extension refuses that name\nchoose another\n", stderr)
}

func TestTheBuiltCLIsErrorsAreVerbatim(t *testing.T) {
	c := newCLIEnv(t, &extensionRelay{front: "127.0.0.1:1"})
	_, stderr, code := c.run(t, []string{calls.FactoryErrorEnv + "=no login here"},
		"host", "--detach", "--accept", "--test-delegate", "--", hostedCommand()[0])
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: no login here\n(see "+filepath.Join(c.home, "s", "upterm", "upterm.log")+")\n", stderr)

	_, stderr, code = c.run(t, []string{calls.PrepareErrorEnv + "=not here\nnor there"},
		"host", "--detach", "--accept", "--", hostedCommand()[0])
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: not here\nnor there\n", stderr)

	stdout, _, code := c.run(t, nil, "upgrade")
	require.Equal(t, 0, code)
	require.Equal(t, calls.UpgradeLine+"\n", stdout)
}
