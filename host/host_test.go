package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
	latch := &guestJoinLatch{update: update, now: time.Now,
		disarm: func() { once.Do(func() { close(joined) }) }}
	errCh := make(chan error, 1)
	go func() {
		errCh <- latch.note(&api.Client{Kind: api.Client_GUEST})
	}()

	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		close(release)
		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(2 * time.Second):
			t.Fatal("noteGuestJoined did not finish after the publication release")
		}
		t.Fatal("the disarm waited on the record write")
	}
	close(release)
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("noteGuestJoined did not finish after the publication release")
	}
}

func TestGuestLatchIgnoresHostAndLaterGuests(t *testing.T) {
	var rec sessiondir.Record
	updates := 0
	update := func(mutate func(*sessiondir.Record)) error { updates++; mutate(&rec); return nil }
	noop := func() {}

	first := time.Now().UTC().Add(-time.Hour)
	latch := &guestJoinLatch{update: update, now: func() time.Time { return first }, disarm: noop}
	require.NoError(t, latch.note(&api.Client{Kind: api.Client_GUEST}))
	require.NoError(t, latch.note(&api.Client{Kind: api.Client_GUEST}))
	require.True(t, rec.FirstGuestJoinedAt.Equal(first), "a later guest must not move it")
	require.Equal(t, 1, updates, "later guests must not publish the record again")

	var hostOnly sessiondir.Record
	updateHost := func(mutate func(*sessiondir.Record)) error { mutate(&hostOnly); return nil }
	hostLatch := &guestJoinLatch{update: updateHost, now: time.Now, disarm: noop}
	require.NoError(t, hostLatch.note(&api.Client{Kind: api.Client_HOST}))
	require.True(t, hostOnly.FirstGuestJoinedAt.IsZero(), "the host's own terminal is not a guest")
}

func TestGuestLatchRetriesFailedPublication(t *testing.T) {
	var rec sessiondir.Record
	updates := 0
	update := func(mutate func(*sessiondir.Record)) error {
		updates++
		mutate(&rec)
		if updates == 1 {
			return errors.New("disk write failed")
		}
		return nil
	}
	first := time.Now().UTC().Add(-time.Hour)
	guest := &api.Client{Kind: api.Client_GUEST}
	clock := first
	now := func() time.Time { return clock }
	noop := func() {}
	latch := &guestJoinLatch{update: update, now: now, disarm: noop}
	require.Error(t, latch.note(guest))
	clock = first.Add(time.Hour)
	require.NoError(t, latch.note(guest))
	require.NoError(t, latch.note(guest))
	require.Equal(t, 2, updates)
	require.True(t, rec.FirstGuestJoinedAt.Equal(first))
}

func TestClientLifecyclePairsLeftBeforeJoined(t *testing.T) {
	repo := internal.NewClientRepo()
	var events []string
	lifecycle := &clientLifecycle{
		repo:        repo,
		pendingLeft: make(map[string]struct{}),
		onGuestJoin: func(*api.Client) error { events = append(events, "latch"); return nil },
		onJoined:    func(*api.Client) { events = append(events, "joined") },
		onLeft:      func(*api.Client) { events = append(events, "left") },
	}
	guest := &api.Client{Id: "quick-session", Kind: api.Client_GUEST}
	lifecycle.left(guest.Id)
	lifecycle.joined(guest)
	require.Nil(t, repo.Get(guest.Id), "a rapid accepted session must not remain connected")
	require.Equal(t, []string{"latch", "joined", "left"}, events)
}

func TestClientLifecycleKeepsLaterDistinctIDAfterDepartures(t *testing.T) {
	repo := internal.NewClientRepo()
	lifecycle := &clientLifecycle{repo: repo, pendingLeft: make(map[string]struct{})}
	first := &api.Client{Id: "transport/1", Kind: api.Client_HOST}
	second := &api.Client{Id: "transport/2", Kind: api.Client_HOST}
	third := &api.Client{Id: "transport/3", Kind: api.Client_HOST}
	lifecycle.joined(first)
	lifecycle.joined(second)
	lifecycle.left(first.Id)
	lifecycle.left(second.Id)
	lifecycle.joined(third)
	require.Same(t, third, repo.Get(third.Id), "third session must remain until its own departure")
	require.Len(t, repo.Clients(), 1)
	lifecycle.left(third.Id)
	require.Empty(t, repo.Clients())
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
	left                        chan struct{}
	created                     *api.GetSessionResponse
	done                        chan error
	output                      bytes.Buffer
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
		ready: make(chan struct{}), joined: make(chan struct{}, 4), left: make(chan struct{}, 4), done: make(chan error, 1)}
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
		ClientLeftCallback: func(c *api.Client) {
			if c.Kind == api.Client_GUEST {
				f.left <- struct{}{}
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
	client := f.guestClient(t)
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	require.NoError(t, sess.Shell())
	awaitJoinTimeoutSignal(t, f.joined, "guest join")
	// Leaving cannot re-arm the deadline.
	require.NoError(t, client.Close())
}

func (f *joinTimeoutHost) guestClient(t *testing.T) *ssh.Client {
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
	return client
}

func TestJoinTimeoutAuthOnlyGuestDoesNotJoin(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = 300 * time.Millisecond
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	client := f.guestClient(t)
	defer func() { _ = client.Close() }()
	require.NoError(t, f.result(t))
	require.Equal(t, sessiondir.ReasonJoinTimeout, f.record(t).Reason)
	require.True(t, f.record(t).FirstGuestJoinedAt.IsZero())
}

func TestJoinTimeoutRejectedNoPtyGuestDoesNotJoin(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = 300 * time.Millisecond
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	client := f.guestClient(t)
	defer func() { _ = client.Close() }()
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())
	_ = sess.Wait()
	require.NoError(t, f.result(t))
	require.Equal(t, sessiondir.ReasonJoinTimeout, f.record(t).Reason)
	require.True(t, f.record(t).FirstGuestJoinedAt.IsZero())
}

func TestJoinTimeoutDoesNotEndAJoinedSession(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = 200 * time.Millisecond
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	f.join(t)
	awaitJoinTimeoutSignal(t, f.left, "guest left")
	select {
	case err := <-f.done:
		t.Fatalf("joined session ended: %v", err)
	case <-time.After(600 * time.Millisecond):
	}
	f.finish(t, "0")
	require.NoError(t, f.result(t))
	require.Equal(t, sessiondir.ReasonExited, f.record(t).Reason)
	require.False(t, f.record(t).FirstGuestJoinedAt.IsZero())
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
	clientDone, cancel := f.attach(t)
	t.Cleanup(release)
	awaitJoinTimeoutSignal(t, reached, "deadline barrier")
	// Only the signal actor observes cancellation while the timer is
	// parked: the SSH actor is canceled by its group interrupt with the
	// selected winner. A shell failure cannot establish this ordering,
	// because its output EOF may legitimately win the inner group with nil.
	cancel()
	release()
	require.ErrorIs(t, f.result(t), context.Canceled, "the winning cancellation must survive")
	require.Equal(t, sessiondir.ReasonCanceled, f.record(t).Reason)
	outcome := <-clientDone
	require.NoError(t, outcome.err)
	require.Equal(t, attach.Exited, outcome.result.Reason)
	require.Equal(t, 1, outcome.result.Status)
	require.NotContains(t, f.output.String(), "no guest joined")
}

func TestJoinTimeoutAttachedClientExitsZero(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = 200 * time.Millisecond
	clientDone, _ := f.attach(t)
	select {
	case outcome := <-clientDone:
		require.NoError(t, outcome.err)
		require.Equal(t, attach.Exited, outcome.result.Reason)
		require.Zero(t, outcome.result.Status, "foreground receives SSH exit status zero")
	case <-time.After(5 * time.Second):
		t.Fatal("attached client did not receive exit status")
	}
	require.NoError(t, f.result(t))
	require.Equal(t, 1, strings.Count(f.output.String(), "no guest joined within the join timeout; session ended"))
	require.Equal(t, sessiondir.ReasonJoinTimeout, f.record(t).Reason)
}

func TestJoinTimeoutParentCancellationStopsAttachedClient(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = time.Hour
	clientDone, cancel := f.attach(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	cancel()
	select {
	case outcome := <-clientDone:
		require.NoError(t, outcome.err)
		require.Equal(t, attach.Exited, outcome.result.Reason)
		require.Equal(t, 1, outcome.result.Status, "ordinary cancellation retains its attached status")
	case <-time.After(5 * time.Second):
		t.Fatal("parent cancellation did not release attached client")
	}
	require.ErrorIs(t, f.result(t), context.Canceled)
	require.NotContains(t, f.output.String(), "no guest joined")
	require.Equal(t, sessiondir.ReasonCanceled, f.record(t).Reason)
}

type joinAttachmentResult struct {
	result attach.Result
	err    error
}

func (f *joinTimeoutHost) attach(t *testing.T) (<-chan joinAttachmentResult, context.CancelFunc) {
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
	rec := f.record(t)
	require.NotEmpty(t, rec.HostKeys)
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rec.HostKeys[0]))
	require.NoError(t, err)
	client := &attach.Client{Socket: socket, HostKeys: []ssh.PublicKey{key}, Stdout: &f.output, Pty: &attach.Pty{Term: "xterm"}}
	clientCtx, clientCancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(clientCancel)
	clientDone := make(chan joinAttachmentResult, 1)
	go func() { result, err := client.Run(clientCtx); clientDone <- joinAttachmentResult{result, err} }()
	return clientDone, cancel
}

func TestJoinTimeoutCancellationBeforeReadiness(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = time.Hour
	f.h.AwaitInitialClient = true
	listening := make(chan struct{})
	f.h.AttachListeningCallback = func(string) { close(listening) }
	cancel := f.start(t)
	awaitJoinTimeoutSignal(t, listening, "attach listener before command start")
	cancel()
	require.ErrorIs(t, f.result(t), context.Canceled)
	select {
	case <-f.ready:
		t.Fatal("unstarted command reported readiness")
	default:
	}
}

func TestJoinTimeoutHeldAdminDoesNotDelayCommandCancellation(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprint("timeout=", timeout), func(t *testing.T) {
			f := newJoinTimeoutHost(t)
			started, terminated := filepath.Join(f.root, "started"), filepath.Join(f.root, "terminated")
			f.h.Command = []string{"sh", "-c", `trap 'echo stopped > "$2"; exit 1' HUP; echo ready > "$1"; while :; do sleep 0.01; done`, "sh", started, terminated}
			f.h.JoinTimeout = time.Hour
			fire, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			if timeout {
				f.h.JoinTimeout = 50 * time.Millisecond
				f.h.onJoinDeadlineFired = func(<-chan struct{}) { close(fire); <-release }
			}
			defer unblock()
			clientDone, cancel := f.attach(t)
			awaitJoinTimeoutSignal(t, f.ready, "readiness")
			require.Eventually(t, func() bool { _, err := os.Stat(started); return err == nil }, time.Second, time.Millisecond)
			adminSocket := f.h.AdminSocketFile
			conn, err := grpc.NewClient("unix://"+adminSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()
			rpcCtx, rpcCancel := context.WithCancel(context.Background())
			defer rpcCancel()
			_, err = conn.NewStream(rpcCtx, &grpc.StreamDesc{}, "/api.AdminService/GetSession")
			require.NoError(t, err)
			barrierCtx, barrierCancel := context.WithTimeout(context.Background(), time.Second)
			defer barrierCancel()
			_, err = api.NewAdminServiceClient(conn).GetSession(barrierCtx, &api.GetSessionRequest{})
			require.NoError(t, err)
			shutdownStart := time.Now()
			if timeout {
				awaitJoinTimeoutSignal(t, fire, "deadline")
				unblock()
			} else {
				cancel()
			}
			// The command's HUP trap must run before the one-second admin drain
			// expires, without releasing the pending RPC from this client.
			require.Eventually(t, func() bool { _, err := os.Stat(terminated); return err == nil }, 700*time.Millisecond, time.Millisecond)
			select {
			case outcome := <-clientDone:
				require.NoError(t, outcome.err)
				require.Equal(t, attach.Exited, outcome.result.Reason)
				if timeout {
					require.Zero(t, outcome.result.Status)
				} else {
					require.Equal(t, 1, outcome.result.Status)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("attached client remained blocked")
			}

			if timeout {
				require.NoError(t, f.result(t))
				require.Equal(t, sessiondir.ReasonJoinTimeout, f.record(t).Reason)
			} else {
				require.ErrorIs(t, f.result(t), context.Canceled)
				require.Equal(t, sessiondir.ReasonCanceled, f.record(t).Reason)
			}
			require.Less(t, time.Since(shutdownStart), 2*time.Second, "one-second admin budget plus fixture teardown")
			if timeout {
				require.Equal(t, 1, strings.Count(f.output.String(), "no guest joined within the join timeout"))
			} else {
				require.NotContains(t, f.output.String(), "no guest joined")
			}
			_, err = os.Stat(filepath.Dir(adminSocket))
			require.True(t, os.IsNotExist(err), "released session runtime directory")
		})
	}
}

func TestJoinTimeoutOrdinaryExitHasNoNotice(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = time.Hour
	clientDone, _ := f.attach(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	f.finish(t, "7")
	outcome := <-clientDone
	require.NoError(t, outcome.err)
	require.Equal(t, attach.Exited, outcome.result.Reason)
	require.Equal(t, 7, outcome.result.Status)
	_ = f.result(t)
	require.Equal(t, sessiondir.ReasonExited, f.record(t).Reason)
	require.NotContains(t, f.output.String(), "no guest joined")
}

func TestParentCancellationBeforeSignalActor(t *testing.T) {
	f := newJoinTimeoutHost(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.h.SessionCreatedCallback = func(context.Context, *api.GetSessionResponse) error {
		cancel()
		return ctx.Err()
	}
	require.ErrorIs(t, f.h.Run(ctx), context.Canceled)
	require.Equal(t, sessiondir.ReasonCanceled, f.record(t).Reason)
}

func TestStartupFailureBeatsLateCancellation(t *testing.T) {
	f := newJoinTimeoutHost(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failure := errors.New("callback failed")
	f.h.SessionCreatedCallback = func(context.Context, *api.GetSessionResponse) error {
		cancel()
		return failure
	}
	require.ErrorIs(t, f.h.Run(ctx), failure)
	require.Equal(t, sessiondir.ReasonStartupFailed, f.record(t).Reason)
}

func TestAdminStopWithJoinTimerRemainsStopped(t *testing.T) {
	for i := 0; i < 30; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			f := newJoinTimeoutHost(t)
			f.h.JoinTimeout = time.Hour
			f.start(t)
			awaitJoinTimeoutSignal(t, f.ready, "readiness")
			conn, err := grpc.NewClient("unix://"+f.h.AdminSocketFile, grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = api.NewAdminServiceClient(conn).StopSession(ctx, &api.StopSessionRequest{LaunchId: f.record(t).LaunchID})
			require.NoError(t, err)
			require.ErrorIs(t, f.result(t), context.Canceled)
			require.Equal(t, sessiondir.ReasonStopped, f.record(t).Reason)
		})
	}
}

func TestParentCancellationImmediatelyAfterClaim(t *testing.T) {
	f := newJoinTimeoutHost(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.h.SessionClaimedCallback = func(*sessiondir.Dir) { cancel() }
	require.ErrorIs(t, f.h.Run(ctx), context.Canceled)
	require.Equal(t, sessiondir.ReasonCanceled, f.record(t).Reason)
}

func TestLateParentCancellationDoesNotReplaceCommandWinner(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = 30 * time.Millisecond
	reached, selected, released := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(released) }) }
	defer release()
	f.h.onJoinDeadlineFired = func(stop <-chan struct{}) {
		close(reached)
		select {
		case <-stop:
			close(selected)
		case <-time.After(5 * time.Second):
			t.Error("command did not win")
			return
		}
		select {
		case <-released:
		case <-time.After(5 * time.Second):
			t.Error("late cancellation barrier not released")
		}
	}
	cancel := f.start(t)
	awaitJoinTimeoutSignal(t, reached, "timer barrier")
	f.finish(t, "0")
	awaitJoinTimeoutSignal(t, selected, "command winner")
	cancel()
	release()
	require.NoError(t, f.result(t))
	rec := f.record(t)
	require.Equal(t, sessiondir.ReasonExited, rec.Reason)
	require.NotNil(t, rec.ExitCode)
	require.Zero(t, *rec.ExitCode)
}
