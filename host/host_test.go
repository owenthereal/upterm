package host

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	testPublicKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN0EWrjdcHcuMfI8bGAyHPcGsAc/vd/gl5673pRkRBGY`
)

func Test_hostKeyCallbackKnowHostsFileNotExist(t *testing.T) {
	dir := t.TempDir()

	knownHostsFile := filepath.Join(dir, "known_hosts")

	stdin := bytes.NewBufferString("yes\n") // Simulate typing "yes" in stdin
	stdout := bytes.NewBuffer(nil)

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	fp := utils.FingerprintSHA256(pk)

	cb, err := NewPromptingHostKeyCallback(stdin, stdout, knownHostsFile, false)
	if err != nil {
		t.Fatal(err)
	}

	addr := &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 22,
	}
	if err := cb("127.0.0.1:22", addr, pk); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "ED25519 key fingerprint is "+fp) {
		t.Fatalf("stdout should contain fingerprint %s: %s", fp, stdout)
	}
}

func Test_hostKeyCallback(t *testing.T) {
	tempfile := filepath.Join(t.TempDir(), "known_hosts")
	err := os.WriteFile(tempfile, []byte("[127.0.0.1]:23 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpVcpc3t5GZHQFlbSLyj6sQY4wWLjNZsLTkfo9Cdjit\n"), 0600)
	require.NoError(t, err)

	stdin := bytes.NewBufferString("yes\n") // Simulate typing "yes" in stdin
	stdout := bytes.NewBuffer(nil)

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testPublicKey))
	require.NoError(t, err)
	fp := utils.FingerprintSHA256(pk)

	cb, err := NewPromptingHostKeyCallback(stdin, stdout, tempfile, false)
	require.NoError(t, err)

	// 127.0.0.1:22 is not in known_hosts
	addr := &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 22,
	}
	err = cb("127.0.0.1:22", addr, pk)
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "ED25519 key fingerprint is "+fp)

	// 127.0.0.1:23 is in known_hosts
	addr = &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 23,
	}
	err = cb("127.0.0.1:23", addr, pk)
	assert.Error(t, err, "key mismatched error is expected")
	assert.Contains(t, err.Error(), "Offending ED25519 key in "+tempfile)
}

func Test_hostKeyCallbackStdinReadError(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, devNull.Close()) })
	closed, err := os.Open(os.DevNull)
	require.NoError(t, err)
	require.NoError(t, closed.Close())

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testPublicKey))
	require.NoError(t, err)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}

	for _, tt := range []struct {
		name    string
		stdin   io.Reader
		wantErr error
	}{
		{"empty reader", strings.NewReader(""), io.EOF},
		{"null device", devNull, io.EOF},
		{"closed file", closed, os.ErrClosed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			knownHostsFile := filepath.Join(t.TempDir(), "known_hosts")
			stdout := new(bytes.Buffer)
			cb, err := NewPromptingHostKeyCallback(tt.stdin, stdout, knownHostsFile, false)
			require.NoError(t, err)

			err = cb("127.0.0.1:22", addr, pk)
			assert.ErrorIs(t, err, tt.wantErr)
			assert.ErrorContains(t, err, "could not read host-key confirmation from stdin")
			assert.ErrorContains(t, err, "ED25519 host key of 127.0.0.1:22")
			assert.ErrorContains(t, err, "interactively")
			assert.ErrorContains(t, err, knownHostsFile)
			assert.ErrorContains(t, err, "--skip-host-key-check")
			assert.Contains(t, stdout.String(), "Are you sure you want to continue connecting")

			content, err := os.ReadFile(knownHostsFile)
			require.NoError(t, err)
			assert.Empty(t, content, "an unconfirmed host key must not be trusted")
		})
	}
}

func Test_hostKeyCallbackRedirectedStdin(t *testing.T) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testPublicKey))
	require.NoError(t, err)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}

	for _, source := range []string{"pipe", "file"} {
		for _, answer := range []string{"yes", "no"} {
			t.Run(source+"/"+answer, func(t *testing.T) {
				var stdin *os.File
				if source == "pipe" {
					reader, writer, err := os.Pipe()
					require.NoError(t, err)
					t.Cleanup(func() { _ = writer.Close() })
					stdin = reader
					t.Cleanup(func() { assert.NoError(t, stdin.Close()) })
					_, err = writer.WriteString(answer + "\n")
					require.NoError(t, err)
					require.NoError(t, writer.Close())
				} else {
					filename := filepath.Join(t.TempDir(), "stdin")
					require.NoError(t, os.WriteFile(filename, []byte(answer+"\n"), 0600))
					stdin, err = os.Open(filename)
					require.NoError(t, err)
					t.Cleanup(func() { assert.NoError(t, stdin.Close()) })
				}

				knownHostsFile := filepath.Join(t.TempDir(), "known_hosts")
				cb, err := NewPromptingHostKeyCallback(stdin, io.Discard, knownHostsFile, false)
				require.NoError(t, err)
				err = cb("127.0.0.1:22", addr, pk)
				if answer == "yes" {
					require.NoError(t, err)
				} else {
					require.EqualError(t, err, "Host key verification failed")
				}

				content, err := os.ReadFile(knownHostsFile)
				require.NoError(t, err)
				if answer == "yes" {
					assert.Equal(t, "127.0.0.1 "+testPublicKey+"\n", string(content))
				} else {
					assert.Empty(t, content, "a rejected host key must not be trusted")
				}
			})
		}
	}
}

func Test_hostKeyCallbackIPv6WithPort(t *testing.T) {
	tempfile := filepath.Join(t.TempDir(), "known_hosts")

	stdin := bytes.NewBufferString("yes\n")
	stdout := bytes.NewBuffer(nil)

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testPublicKey))
	require.NoError(t, err)

	cb, err := NewPromptingHostKeyCallback(stdin, stdout, tempfile, false)
	require.NoError(t, err)

	// Test IPv6 address with port - even though remote is IPv6,
	// only hostname should be stored for operational flexibility
	addr := &net.TCPAddr{
		IP:   net.ParseIP("2a09:8280:1::3:4b89"),
		Port: 443,
	}
	hostname := "uptermd.upterm.dev:443"

	err = cb(hostname, addr, pk)
	require.NoError(t, err)

	// Read the known_hosts file and verify the entry is properly formatted
	content, err := os.ReadFile(tempfile)
	require.NoError(t, err)

	contentStr := string(content)

	// Should contain the hostname with port
	assert.Contains(t, contentStr, "[uptermd.upterm.dev]:443",
		"known_hosts should contain hostname with port")

	// Should NOT contain the IP address - only hostname for operational flexibility
	// This prevents breakage when IPs change due to load balancers, redeployments, etc.
	assert.NotContains(t, contentStr, "2a09:8280:1::3:4b89",
		"known_hosts should NOT contain IP address to avoid breakage on IP changes")
}

func Test_hostKeyCallbackIPv6WithCertAuthority(t *testing.T) {
	tempfile := filepath.Join(t.TempDir(), "known_hosts")

	stdin := bytes.NewBufferString("yes\n")
	stdout := bytes.NewBuffer(nil)

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testPublicKey))
	require.NoError(t, err)

	// Create a certificate
	cert := &ssh.Certificate{
		Key:          pk,
		CertType:     ssh.HostCert,
		SignatureKey: pk,
	}

	cb, err := NewPromptingHostKeyCallback(stdin, stdout, tempfile, false)
	require.NoError(t, err)

	// Test IPv6 address with certificate authority
	addr := &net.TCPAddr{
		IP:   net.ParseIP("2a09:8280:1::3:4b89"),
		Port: 443,
	}
	hostname := "uptermd.upterm.dev:443"

	err = cb(hostname, addr, cert)
	require.NoError(t, err)

	// Read the known_hosts file and verify the entry is properly formatted
	content, err := os.ReadFile(tempfile)
	require.NoError(t, err)

	contentStr := string(content)

	// Should contain @cert-authority marker
	assert.Contains(t, contentStr, "@cert-authority",
		"known_hosts should contain @cert-authority marker")

	// Should contain the hostname with port
	assert.Contains(t, contentStr, "[uptermd.upterm.dev]:443",
		"known_hosts should contain hostname with port")

	// Should NOT include the IP address for operational flexibility
	assert.NotContains(t, contentStr, "2a09:8280:1::3:4b89",
		"known_hosts should NOT contain IP address to avoid breakage on IP changes")

	// Expected format: @cert-authority [hostname]:port ssh-ed25519 key
	// NOT: @cert-authority [hostname]:port,[ip]:port ssh-ed25519 key
	assert.Contains(t, contentStr, "@cert-authority [uptermd.upterm.dev]:443 ssh-ed25519",
		"known_hosts should have correct cert-authority format with only hostname")
}

func Test_autoAcceptingHostKeyCallback(t *testing.T) {
	tempfile := filepath.Join(t.TempDir(), "known_hosts")

	stdout := bytes.NewBuffer(nil)

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testPublicKey))
	require.NoError(t, err)

	cb, err := NewAutoAcceptingHostKeyCallback(stdout, tempfile)
	require.NoError(t, err)

	// Test auto-accepting an unknown host key
	addr := &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 22,
	}
	err = cb("127.0.0.1:22", addr, pk)
	require.NoError(t, err)

	// Should contain warning message about permanently adding the host (matching SSH's accept-new behavior)
	assert.Contains(t, stdout.String(), "Warning: Permanently added '127.0.0.1' (ED25519) to the list of known hosts.")

	// Verify the key was written to known_hosts
	content, err := os.ReadFile(tempfile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "ssh-ed25519")
}

func Test_autoAcceptingHostKeyCallbackWithCertificate(t *testing.T) {
	tempfile := filepath.Join(t.TempDir(), "known_hosts")

	stdout := bytes.NewBuffer(nil)

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testPublicKey))
	require.NoError(t, err)

	// Create a certificate
	cert := &ssh.Certificate{
		Key:          pk,
		CertType:     ssh.HostCert,
		SignatureKey: pk,
	}

	cb, err := NewAutoAcceptingHostKeyCallback(stdout, tempfile)
	require.NoError(t, err)

	// Test auto-accepting a certificate
	addr := &net.TCPAddr{
		IP:   net.ParseIP("2a09:8280:1::3:4b89"),
		Port: 443,
	}
	hostname := "uptermd.upterm.dev:443"

	err = cb(hostname, addr, cert)
	require.NoError(t, err)

	// Verify the certificate was written with @cert-authority marker
	content, err := os.ReadFile(tempfile)
	require.NoError(t, err)

	contentStr := string(content)
	assert.Contains(t, contentStr, "@cert-authority")
	assert.Contains(t, contentStr, "[uptermd.upterm.dev]:443")
	assert.NotContains(t, contentStr, "2a09:8280:1::3:4b89")
}

func Test_autoAcceptingHostKeyCallbackValidatesKnownKeys(t *testing.T) {
	tempfile := filepath.Join(t.TempDir(), "known_hosts")

	// Pre-populate known_hosts with a different key
	differentKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpVcpc3t5GZHQFlbSLyj6sQY4wWLjNZsLTkfo9Cdjit"
	err := os.WriteFile(tempfile, []byte("[127.0.0.1]:22 "+differentKey+"\n"), 0600)
	require.NoError(t, err)

	stdout := bytes.NewBuffer(nil)

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testPublicKey))
	require.NoError(t, err)

	cb, err := NewAutoAcceptingHostKeyCallback(stdout, tempfile)
	require.NoError(t, err)

	// Try to connect with a different key - should fail (MITM protection)
	addr := &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 22,
	}
	err = cb("127.0.0.1:22", addr, pk)
	assert.Error(t, err, "should reject mismatched key to prevent MITM")
	assert.Contains(t, err.Error(), "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED")
}

func TestGuestLatchDisarmsBeforePublishing(t *testing.T) {
	// The in-memory disarm must not wait on the record write. A slow disk
	// would otherwise let the deadline fire after the guest had already
	// arrived, which is the failure the latch exists to prevent.
	release := make(chan struct{})
	var rec sessiondir.Record
	update := func(mutate func(*sessiondir.Record)) error {
		<-release // publication is stuck
		mutate(&rec)
		return nil
	}

	joined := make(chan struct{})
	var once sync.Once
	go noteGuestJoined(update, &api.Client{Kind: api.Client_GUEST}, time.Now,
		func() { once.Do(func() { close(joined) }) })

	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		t.Fatal("the disarm waited on the record write")
	}
	close(release)
}

func TestGuestLatchIgnoresHostAndLaterGuests(t *testing.T) {
	var rec sessiondir.Record
	update := func(mutate func(*sessiondir.Record)) error { mutate(&rec); return nil }
	noop := func() {}

	first := time.Now().UTC().Add(-time.Hour)
	noteGuestJoined(update, &api.Client{Kind: api.Client_GUEST}, func() time.Time { return first }, noop)
	noteGuestJoined(update, &api.Client{Kind: api.Client_GUEST}, time.Now, noop)
	require.True(t, rec.FirstGuestJoinedAt.Equal(first), "a later guest must not move it")

	var hostOnly sessiondir.Record
	updateHost := func(mutate func(*sessiondir.Record)) error { mutate(&hostOnly); return nil }
	noteGuestJoined(updateHost, &api.Client{Kind: api.Client_HOST}, time.Now, noop)
	require.True(t, hostOnly.FirstGuestJoinedAt.IsZero(), "the host's own terminal is not a guest")
}

// Through a tunnel, x/crypto hands the callback the proxy's address. Printing
// it as the server's is misleading — OpenSSH prints a placeholder instead —
// and it is display-only: what gets written to known_hosts is the hostname
// either way.
func Test_hostKeyCallback_proxiedPromptHidesTheProxyAddress(t *testing.T) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testPublicKey))
	require.NoError(t, err)

	// The peer here is the proxy, not uptermd.
	proxyAddr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 3128}

	for _, tc := range []struct {
		name        string
		proxied     bool
		wantShown   string
		wantMissing string
	}{
		{name: "direct", proxied: false, wantShown: "10.0.0.5"},
		{name: "proxied", proxied: true, wantShown: noHostIP, wantMissing: "10.0.0.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			knownHosts := filepath.Join(t.TempDir(), "known_hosts")
			stdin := bytes.NewBufferString("yes\n")
			stdout := bytes.NewBuffer(nil)

			cb, err := NewPromptingHostKeyCallback(stdin, stdout, knownHosts, tc.proxied)
			require.NoError(t, err)
			require.NoError(t, cb("uptermd.upterm.dev:22", proxyAddr, pk))

			assert.Contains(t, stdout.String(), "uptermd.upterm.dev", "the server is always named")
			assert.Contains(t, stdout.String(), tc.wantShown)
			if tc.wantMissing != "" {
				assert.NotContains(t, stdout.String(), tc.wantMissing)
			}

			// Either way the stored line is the hostname, never the peer.
			stored, err := os.ReadFile(knownHosts)
			require.NoError(t, err)
			assert.Contains(t, string(stored), "uptermd.upterm.dev")
			assert.NotContains(t, string(stored), "10.0.0.5")
		})
	}
}

// joinTimeoutHost runs the real Host actors against an in-process relay. The
// command exits only when the test writes its requested status to finishFile.
type joinTimeoutHost struct {
	h                           *Host
	root, relayAddr, finishFile string
	ready                       chan struct{}
	joined                      chan struct{}
	created                     *api.GetSessionResponse
	done                        chan error
}

func newJoinTimeoutHost(t *testing.T) *joinTimeoutHost {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fixture command uses a POSIX shell")
	}
	root, err := os.MkdirTemp("/tmp", "up-join-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	t.Setenv("XDG_RUNTIME_DIR", root)
	t.Setenv("XDG_STATE_HOME", root)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	key, err := NewHostKey()
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	network := &server.MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))
	sm, err := server.NewSessionManager(routing.ModeEmbedded, server.WithSessionManagerLogger(logger))
	require.NoError(t, err)
	relay := &server.Server{NodeAddr: ln.Addr().String(), HostSigners: []ssh.Signer{key}, Signers: []ssh.Signer{key},
		NetworkProvider: network, MetricsProvider: provider.NewDiscardProvider(), SessionManager: sm, Logger: logger}
	ctx, cancel := context.WithCancel(context.Background())
	relayDone := make(chan error, 1)
	go func() { relayDone <- relay.ServeWithContext(ctx, ln, nil) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-relayDone:
		case <-time.After(10 * time.Second):
			t.Error("relay did not stop")
		}
	})
	f := &joinTimeoutHost{root: root, relayAddr: ln.Addr().String(), finishFile: filepath.Join(root, "finish"),
		ready: make(chan struct{}), joined: make(chan struct{}, 4), done: make(chan error, 1)}
	f.h = &Host{Host: "ssh://" + f.relayAddr, Name: "deadline", Logger: logger,
		KeepAliveDuration: time.Second, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Signers: []ssh.Signer{key}, StopGrace: 50 * time.Millisecond,
		Command:                []string{"sh", "-c", `while [ ! -f "$1" ]; do sleep 0.01; done; read code < "$1"; exit "$code"`, "sh", f.finishFile},
		SessionCreatedCallback: func(_ context.Context, s *api.GetSessionResponse) error { f.created = s; return nil },
		SessionReadyCallback:   func(string) { close(f.ready) },
		ClientJoinedCallback: func(c *api.Client) {
			if c.Kind == api.Client_GUEST {
				f.joined <- struct{}{}
			}
		},
	}
	return f
}

func (f *joinTimeoutHost) start(t *testing.T) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	finished := make(chan struct{})
	go func() { defer close(finished); f.done <- f.h.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("Host.Run cleanup did not finish")
		}
	})
	return cancel
}

func awaitJoinTimeoutSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func (f *joinTimeoutHost) result(t *testing.T) error {
	t.Helper()
	select {
	case err := <-f.done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Host.Run did not return")
		return nil
	}
}

func (f *joinTimeoutHost) finish(t *testing.T, code string) {
	t.Helper()
	require.NoError(t, os.WriteFile(f.finishFile, []byte(code+"\n"), 0600))
}

func (f *joinTimeoutHost) record(t *testing.T) *sessiondir.Record {
	t.Helper()
	rec, err := sessiondir.ReadRecord(utils.UptermStateDir(), "deadline")
	require.NoError(t, err)
	return rec
}

func (f *joinTimeoutHost) join(t *testing.T) {
	t.Helper()
	key, err := NewHostKey()
	require.NoError(t, err)
	conn, err := net.DialTimeout("tcp", f.relayAddr, 3*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, f.relayAddr, &ssh.ClientConfig{User: f.created.SshUser,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	require.NoError(t, err)
	client := ssh.NewClient(sshConn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	require.NoError(t, sess.Shell())
	awaitJoinTimeoutSignal(t, f.joined, "guest join")
	// Leaving cannot re-arm the deadline.
	require.NoError(t, client.Close())
}

func TestJoinTimeoutDoesNotEndAJoinedSession(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = 200 * time.Millisecond
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	f.join(t)
	select {
	case err := <-f.done:
		t.Fatalf("joined session ended: %v", err)
	case <-time.After(600 * time.Millisecond):
	}
	f.finish(t, "0")
	require.NoError(t, f.result(t))
	require.Equal(t, sessiondir.ReasonExited, f.record(t).Reason)
}

func TestJoinTimeoutZeroDoesNotEndASession(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = 0
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	f.join(t)
	select {
	case err := <-f.done:
		t.Fatalf("default session ended: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	f.finish(t, "0")
	require.NoError(t, f.result(t))
}

func TestJoinTimeoutClockStartsAtReadiness(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = 400 * time.Millisecond
	f.h.SessionReadyCallback = func(string) { time.Sleep(700 * time.Millisecond); close(f.ready) }
	start := time.Now()
	f.start(t)
	require.NoError(t, f.result(t))
	require.Greater(t, time.Since(start), 1000*time.Millisecond)
	require.Equal(t, sessiondir.ReasonJoinTimeout, f.record(t).Reason)
}

func TestJoinTimeoutEndsAnUnjoinedSessionWithReasonAndZero(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = 200 * time.Millisecond
	f.start(t)
	require.NoError(t, f.result(t), "a join timeout is not a failure")
	require.Equal(t, sessiondir.ReasonJoinTimeout, f.record(t).Reason)
}

func TestJoinTimeoutDoesNotStealACompetingOutcome(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = 50 * time.Millisecond
	reached, released := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(released) }) }
	f.h.onJoinDeadlineFired = func(stop <-chan struct{}) {
		close(reached)
		// Both waits are bounded, including failure cleanup. stop proves the
		// group has chosen the competing error before the timer returns.
		select {
		case <-released:
		case <-time.After(5 * time.Second):
			t.Error("deadline barrier not released")
			return
		}
		select {
		case <-stop:
		case <-time.After(5 * time.Second):
			t.Error("competing actor did not win")
		}
	}
	cancel := f.start(t)
	t.Cleanup(release)
	awaitJoinTimeoutSignal(t, reached, "deadline barrier")
	// Only the signal actor observes cancellation while the timer is
	// parked: the SSH actor is canceled by its group interrupt with the
	// selected winner. A shell failure cannot establish this ordering,
	// because its output EOF may legitimately win the inner group with nil.
	cancel()
	release()
	require.ErrorIs(t, f.result(t), context.Canceled, "the winning cancellation must survive")
	require.Equal(t, sessiondir.ReasonStopped, f.record(t).Reason)
}

func TestJoinTimeoutAttachedClientExitsZero(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = 200 * time.Millisecond
	clientDone, _ := f.attach(t)
	select {
	case err := <-clientDone:
		require.NoError(t, err, "foreground receives SSH exit status zero")
	case <-time.After(5 * time.Second):
		t.Fatal("attached client did not receive exit status")
	}
	require.NoError(t, f.result(t))
	require.Equal(t, sessiondir.ReasonJoinTimeout, f.record(t).Reason)
}

func TestJoinTimeoutParentCancellationStopsAttachedClient(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = time.Hour
	clientDone, cancel := f.attach(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	cancel()
	select {
	case err := <-clientDone:
		var exitErr *ssh.ExitError
		require.ErrorAs(t, err, &exitErr)
		require.Equal(t, 1, exitErr.ExitStatus(), "ordinary cancellation retains its attached status")
	case <-time.After(5 * time.Second):
		t.Fatal("parent cancellation did not release attached client")
	}
	// A cancellation may also be observed by the deadline actor as nil; the persisted stop reason is the existing cancellation contract.
	_ = f.result(t)
	require.Equal(t, sessiondir.ReasonStopped, f.record(t).Reason)
}

func (f *joinTimeoutHost) attach(t *testing.T) (<-chan error, context.CancelFunc) {
	t.Helper()
	f.h.AwaitInitialClient = true
	listening := make(chan string, 1)
	f.h.AttachListeningCallback = func(socket string) { listening <- socket }
	cancel := f.start(t)
	var socket string
	select {
	case socket = <-listening:
	case <-time.After(5 * time.Second):
		t.Fatal("attach socket never bound")
	}
	conn, err := net.DialTimeout("unix", socket, 3*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, socket, &ssh.ClientConfig{User: "host", Auth: []ssh.AuthMethod{ssh.PublicKeys(f.h.Signers...)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	require.NoError(t, err)
	client := ssh.NewClient(sshConn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	_, err = sess.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())
	clientDone := make(chan error, 1)
	go func() { clientDone <- sess.Wait() }()
	return clientDone, cancel
}
