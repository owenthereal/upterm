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
	"github.com/owenthereal/upterm/host/consent"
	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
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

// hostKeyCallbacks are upterm host's two callbacks, the prompting one and
// --skip-host-key-check's.
var hostKeyCallbacks = []struct {
	name string
	new  func(stdin io.Reader, stdout io.Writer, file string) (ssh.HostKeyCallback, error)
}{
	{"prompting", func(stdin io.Reader, stdout io.Writer, file string) (ssh.HostKeyCallback, error) {
		return NewPromptingHostKeyCallback(stdin, stdout, file, false)
	}},
	{"auto-accepting", func(_ io.Reader, stdout io.Writer, file string) (ssh.HostKeyCallback, error) {
		return NewAutoAcceptingHostKeyCallback(stdout, file)
	}},
}

// Neither callback asks about, or records, a certificate that a key line
// already decides.
func Test_hostKeyCallbackJudgesACertificateFromAnUntrustedAuthorityByItsOwnKey(t *testing.T) {
	ca := newSigner(t)
	pinned, presented := newSigner(t).PublicKey(), newSigner(t).PublicKey()
	pin := knownhosts.Line([]string{"relay.test"}, pinned) + "\n"
	recorded := "@cert-authority relay.test " + string(ssh.MarshalAuthorizedKey(ca.PublicKey()))

	for _, tc := range []struct {
		name       string
		knownHosts string
		key        ssh.PublicKey // the certificate's own key
		wantErr    error
		wantFile   string // known_hosts afterwards
	}{
		{"its own key is pinned", pin, pinned, nil, pin},
		{"the host's line names another key", pin, presented, ErrHostKeyChanged, pin},
		{"no line names the host", "", presented, nil, recorded},
	} {
		for _, c := range hostKeyCallbacks {
			t.Run(c.name+"/"+tc.name, func(t *testing.T) {
				file := writeKnownHosts(t, tc.knownHosts)
				stdout := &bytes.Buffer{}
				cb, err := c.new(strings.NewReader("yes\n"), stdout, file)
				require.NoError(t, err)

				err = cb("relay.test:22", fakeAddr, signHostCert(t, ca, tc.key, "relay.test"))
				if tc.wantErr == nil {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, tc.wantErr)
				}
				content, err := os.ReadFile(file)
				require.NoError(t, err)
				require.Equal(t, tc.wantFile, string(content))
				if tc.wantFile == tc.knownHosts {
					require.Empty(t, stdout.String(), "nothing is asked or announced")
				} else {
					require.NotEmpty(t, stdout.String(), "the user is asked, or told the key was added")
				}
			})
		}
	}
}

func Test_hostKeyCallbackRefusesACertificateWhoseSignerIsRevoked(t *testing.T) {
	ca := newSigner(t)
	known := "@revoked * " + string(ssh.MarshalAuthorizedKey(ca.PublicKey()))

	for _, c := range hostKeyCallbacks {
		t.Run(c.name, func(t *testing.T) {
			file := writeKnownHosts(t, known)
			stdout := &bytes.Buffer{}
			cb, err := c.new(strings.NewReader("yes\n"), stdout, file)
			require.NoError(t, err)

			err = cb("relay.test:22", fakeAddr, signHostCert(t, ca, newSigner(t).PublicKey(), "relay.test"))
			var r *knownhosts.RevokedError
			require.ErrorAs(t, err, &r)
			content, err := os.ReadFile(file)
			require.NoError(t, err)
			require.Equal(t, known, string(content))
			require.Empty(t, stdout.String(), "nothing is asked or announced")
		})
	}
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
	latch := &guestJoinLatch{update: update, disarm: func() (time.Time, bool) { once.Do(func() { close(joined) }); return time.Now().UTC(), false }}
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

	first := time.Now().UTC().Add(-time.Hour)
	latch := &guestJoinLatch{update: update, disarm: func() (time.Time, bool) { return first, false }}
	require.NoError(t, latch.note(&api.Client{Kind: api.Client_GUEST}))
	require.NoError(t, latch.note(&api.Client{Kind: api.Client_GUEST}))
	require.True(t, rec.FirstGuestJoinedAt.Equal(first), "a later guest must not move it")
	require.Equal(t, 1, updates, "later guests must not publish the record again")

	var hostOnly sessiondir.Record
	updateHost := func(mutate func(*sessiondir.Record)) error { mutate(&hostOnly); return nil }
	hostLatch := &guestJoinLatch{update: updateHost, disarm: func() (time.Time, bool) { return time.Now(), false }}
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
	latch := &guestJoinLatch{update: update, disarm: func() (time.Time, bool) { return first, false }}
	require.Error(t, latch.note(guest))
	require.NoError(t, latch.note(guest))
	require.NoError(t, latch.note(guest))
	require.Equal(t, 2, updates)
	require.True(t, rec.FirstGuestJoinedAt.Equal(first))
}

// A join registered after the timeout committed is late: publishing it would
// leave a record claiming a join beside reason join_timeout.
func TestGuestLatchDoesNotPublishALateJoin(t *testing.T) {
	updates := 0
	latch := &guestJoinLatch{
		update: func(func(*sessiondir.Record)) error { updates++; return nil },
		disarm: func() (time.Time, bool) { return time.Time{}, true },
	}
	require.NoError(t, latch.note(&api.Client{Kind: api.Client_GUEST}))
	require.Zero(t, updates)
}

// Joining claims the session for good, so the write that publishes the join
// also clears the join timeout, whatever an earlier write left.
func TestGuestLatchClearsTheJoinTimeoutWithTheJoin(t *testing.T) {
	first := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	rec := sessiondir.Record{JoinTimeout: time.Minute, JoinDeadline: first.Add(time.Minute)}
	latch := &guestJoinLatch{
		update: func(mutate func(*sessiondir.Record)) error { mutate(&rec); return nil },
		disarm: func() (time.Time, bool) { return first, false },
	}
	require.NoError(t, latch.note(&api.Client{Kind: api.Client_GUEST}))
	require.True(t, rec.FirstGuestJoinedAt.Equal(first))
	require.Zero(t, rec.JoinTimeout)
	require.True(t, rec.JoinDeadline.IsZero())
}

func TestClientLifecyclePairsLeftBeforeJoined(t *testing.T) {
	repo := internal.NewClientRepo()
	var events []string
	lifecycle := &clientLifecycle{
		repo:        repo,
		pendingLeft: make(map[string]*api.Client),
		onGuestJoin: func(*api.Client) error { events = append(events, "latch"); return nil },
		onJoined:    func(*api.Client) { events = append(events, "joined") },
		onLeft:      func(*api.Client) { events = append(events, "left") },
	}
	guest := &api.Client{Id: "quick-session", Kind: api.Client_GUEST}
	lifecycle.left(guest.Id, nil)
	lifecycle.joined(guest, true)
	require.Nil(t, repo.Get(guest.Id), "a rapid accepted session must not remain connected")
	require.Equal(t, []string{"latch", "joined", "left"}, events)
}

func TestClientLifecycleKeepsLaterDistinctIDAfterDepartures(t *testing.T) {
	repo := internal.NewClientRepo()
	lifecycle := &clientLifecycle{repo: repo, pendingLeft: make(map[string]*api.Client)}
	first := &api.Client{Id: "transport/1", Kind: api.Client_HOST}
	second := &api.Client{Id: "transport/2", Kind: api.Client_HOST}
	third := &api.Client{Id: "transport/3", Kind: api.Client_HOST}
	lifecycle.joined(first, true)
	lifecycle.joined(second, true)
	lifecycle.left(first.Id, nil)
	lifecycle.left(second.Id, nil)
	lifecycle.joined(third, true)
	require.Same(t, third, repo.Get(third.Id), "third session must remain until its own departure")
	require.Len(t, repo.Clients(), 1)
	lifecycle.left(third.Id, nil)
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
	// afterRun, if set, is called the moment Run returns.
	afterRun func()
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
		case err := <-relayDone:
			require.NoError(t, err, "a relay told to stop reports a clean stop")
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
		// Every client but the session's own terminal: a guest, or a jump.
		ClientJoinedCallback: func(c *api.Client) {
			if c.Kind != api.Client_HOST {
				f.joined <- struct{}{}
			}
		},
		ClientLeftCallback: func(c *api.Client) {
			if c.Kind != api.Client_HOST {
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
	go func() {
		defer close(finished)
		err := f.h.Run(ctx)
		if f.afterRun != nil {
			f.afterRun()
		}
		f.done <- err
	}()
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

// only is the one live join timer, which must have been armed for d. It fails
// the test, rather than panicking, when there isn't exactly one.
func (f *fakeJoinClock) only(t *testing.T, d time.Duration) *fakeTimer {
	t.Helper()
	live := f.live()
	require.Len(t, live, 1, "exactly one live join timer")
	require.Equal(t, d, live[0].duration())
	return live[0]
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
	// The fixture command polls for finishFile to exist, then reads it:
	// `while [ ! -f "$1" ]; do sleep 0.01; done; read code < "$1"`. Writing
	// directly with os.WriteFile creates the file before its content is
	// flushed, so the poll can observe the file between create and write and
	// read an empty code (sh then runs `exit ""`, which is status 2). Write
	// to a sibling temp file and rename it into place so the file only ever
	// appears with its content already written.
	tmp := f.finishFile + ".tmp"
	require.NoError(t, os.WriteFile(tmp, []byte(code+"\n"), 0600))
	require.NoError(t, os.Rename(tmp, f.finishFile))
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
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
	f.h.JoinTimeout = 300 * time.Millisecond
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	client := f.guestClient(t)
	defer func() { _ = client.Close() }()
	// A bare window before the fire, in real time: nothing signals that a
	// join emitted as the guest authenticated would have reached the
	// lifecycle actor by now, since the emitter delivers asynchronously and
	// the fixture hears nothing of a guest that never joins. The window is
	// the 300 ms the real timer ran for, counted from the connection rather
	// than from readiness, so it is no shorter than the margin that timer
	// gave. A join that arrives inside it is reported, and stops the timer;
	// one that takes longer is caught neither here nor by the real timer
	// this replaces.
	select {
	case <-f.joined:
		t.Fatal("a guest that only authenticated joined")
	case <-time.After(300 * time.Millisecond):
	}
	clock.only(t, 300*time.Millisecond).fire()
	require.NoError(t, f.result(t))
	require.Equal(t, sessiondir.ReasonJoinTimeout, f.record(t).Reason)
	require.True(t, f.record(t).FirstGuestJoinedAt.IsZero())
}

func TestJoinTimeoutRejectedNoPtyGuestDoesNotJoin(t *testing.T) {
	f := newJoinTimeoutHost(t)
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
	f.h.JoinTimeout = 300 * time.Millisecond
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	client := f.guestClient(t)
	defer func() { _ = client.Close() }()
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())
	_ = sess.Wait()
	// The same bare window as TestJoinTimeoutAuthOnlyGuestDoesNotJoin's, for
	// the same reason: nothing signals that a join emitted for the rejected
	// session would have been processed by now.
	select {
	case <-f.joined:
		t.Fatal("a guest refused for want of a pty joined")
	case <-time.After(300 * time.Millisecond):
	}
	clock.only(t, 300*time.Millisecond).fire()
	require.NoError(t, f.result(t))
	require.Equal(t, sessiondir.ReasonJoinTimeout, f.record(t).Reason)
	require.True(t, f.record(t).FirstGuestJoinedAt.IsZero())
}

func TestJoinTimeoutDoesNotEndAJoinedSession(t *testing.T) {
	f := newJoinTimeoutHost(t)
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
	f.h.JoinTimeout = 200 * time.Millisecond
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	joins := f.h.joins
	armed := clock.only(t, 200*time.Millisecond)
	f.join(t)
	// Checked directly, because expire's own check of the join would keep
	// even a live timer from ending the session.
	require.True(t, armed.stopped(), "the join stopped the timer")
	require.True(t, joins.snapshot().Deadline.IsZero(), "the join cleared the deadline")
	awaitJoinTimeoutSignal(t, f.left, "guest left")
	require.Len(t, clock.timers(), 1, "leaving armed nothing new")
	// A fire already on its way when the join stopped the timer.
	armed.fire()
	require.False(t, hasFired(joins), "a joined session's timeout never commits")
	f.finish(t, "0")
	require.NoError(t, f.result(t))
	require.Equal(t, sessiondir.ReasonExited, f.record(t).Reason)
	require.False(t, f.record(t).FirstGuestJoinedAt.IsZero())
}

func TestJoinTimeoutZeroDoesNotEndASession(t *testing.T) {
	f := newJoinTimeoutHost(t)
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
	f.h.JoinTimeout = 0
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	require.Empty(t, clock.timers(), "no timeout, no timer at readiness")
	f.join(t)
	require.Empty(t, clock.timers(), "nor after a join")
	f.finish(t, "0")
	require.NoError(t, f.result(t))
}

func TestJoinTimeoutClockStartsAtReadiness(t *testing.T) {
	f := newJoinTimeoutHost(t)
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clockWithNow()
	f.h.JoinTimeout = 400 * time.Millisecond
	// Readiness waits for the initial attach, held back here. The checks are
	// made at readiness itself, in beforeReadyPublish, which the ready actor
	// runs once readiness is established and before it starts the clock: the
	// hook counts the timers made so far, then moves the fake now on 700 ms.
	// A clock that started before readiness would have armed a timer by then,
	// and since the fake now moves only in the hook, a deadline counted from
	// any moment before it falls 700 ms short of the one checked below. The
	// checks need a point the actors reach, not the moment attachAfter
	// returns: the attach socket is bound before Run starts its actors, so a
	// count made there can come before an early start has armed anything,
	// and a move made there can come before that start, which would then
	// count from the moved now.
	armedBeforeReady := make(chan int, 1)
	f.h.beforeReadyPublish = func(*sessionState) {
		armedBeforeReady <- len(clock.timers())
		clock.advance(700 * time.Millisecond)
	}
	hold := make(chan struct{})
	clientDone, _ := f.attachAfter(t, hold)
	require.Empty(t, clock.timers(), "nothing counts while the attach is held back")
	close(hold)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	select {
	case n := <-armedBeforeReady:
		require.Zero(t, n, "nothing counts before readiness")
	default:
		t.Fatal("readiness came without the ready write")
	}
	joins := f.h.joins
	timer := clock.only(t, 400*time.Millisecond)
	require.Equal(t, clock.now().Add(400*time.Millisecond), joins.snapshot().Deadline, "counted from readiness")
	timer.fire()
	require.NoError(t, f.result(t))
	require.Equal(t, sessiondir.ReasonJoinTimeout, f.record(t).Reason)
	select {
	case outcome := <-clientDone:
		require.NoError(t, outcome.err)
		require.Equal(t, attach.Exited, outcome.result.Reason, "the timeout ending the session releases its terminal")
	case <-time.After(5 * time.Second):
		t.Fatal("the attached client was not released")
	}
}

func TestJoinTimeoutEndsAnUnjoinedSessionWithReasonAndZero(t *testing.T) {
	f := newJoinTimeoutHost(t)
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
	f.h.JoinTimeout = 200 * time.Millisecond
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	clock.only(t, 200*time.Millisecond).fire()
	require.NoError(t, f.result(t), "a join timeout is not a failure")
	require.Equal(t, sessiondir.ReasonJoinTimeout, f.record(t).Reason)
}

func TestJoinTimeoutDoesNotStealACompetingOutcome(t *testing.T) {
	f := newJoinTimeoutHost(t)
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
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
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	clock.only(t, 50*time.Millisecond).fire()
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
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
	f.h.JoinTimeout = 200 * time.Millisecond
	clientDone, _ := f.attach(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	clock.only(t, 200*time.Millisecond).fire()
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
	return f.attachAfter(t, nil)
}

// attachAfter is attach with the local terminal held back until hold closes.
// The command waits for that terminal, and readiness for the command, so this
// is how a test holds the session short of readiness without blocking inside
// Run itself.
func (f *joinTimeoutHost) attachAfter(t *testing.T, hold <-chan struct{}) (<-chan joinAttachmentResult, context.CancelFunc) {
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
	go func() {
		if hold != nil {
			select {
			case <-hold:
			case <-clientCtx.Done():
				clientDone <- joinAttachmentResult{err: clientCtx.Err()}
				return
			}
		}
		result, err := client.Run(clientCtx)
		clientDone <- joinAttachmentResult{result, err}
	}()
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
			clock := newFakeJoinClock()
			if timeout {
				f.h.joinClock = clock.clock()
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
				clock.only(t, 50*time.Millisecond).fire()
				awaitJoinTimeoutSignal(t, fire, "deadline")
				unblock()
			} else {
				cancel()
			}
			// The command's HUP trap must run before the one-second admin drain
			// expires, without releasing the pending RPC from this client. This
			// 700 ms, and the 2 s bound below, stay real time: they measure the
			// HUP and the admin drain, which the join clock doesn't drive.
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

// The failure matrix promises "reports, exits" and startup_failed for a bind,
// mkdir or tunnel failure at startup. These four pin the recorded reason for
// each row.

func TestRunRecordsStartupFailedWhenTheAttachSocketCannotBeBound(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.SessionClaimedCallback = func(dir *sessiondir.Dir) {
		// A regular file where the socket goes: bind fails with EADDRINUSE.
		require.NoError(t, os.WriteFile(dir.AttachSocket(), nil, 0o600))
	}
	f.start(t)
	err := f.result(t)
	require.Error(t, err)
	require.Contains(t, err.Error(), "attach.sock")
	select {
	case <-f.ready:
		t.Fatal("the session became ready despite the bind failure")
	default:
	}
	require.Equal(t, sessiondir.ReasonStartupFailed, f.record(t).Reason)
}

func TestRunRecordsStartupFailedWhenTheAdminSocketCannotBeBound(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.SessionClaimedCallback = func(dir *sessiondir.Dir) {
		// A regular file where the socket goes: bind fails with EADDRINUSE.
		require.NoError(t, os.WriteFile(dir.AdminSocket(), nil, 0o600))
	}
	f.start(t)
	err := f.result(t)
	require.Error(t, err)
	require.Contains(t, err.Error(), "admin.sock")
	select {
	case <-f.ready:
		t.Fatal("the session became ready despite the bind failure")
	default:
	}
	require.Equal(t, sessiondir.ReasonStartupFailed, f.record(t).Reason)
}

func TestRunFailsBeforeClaimingWhenTheRuntimeDirCannotBeCreated(t *testing.T) {
	f := newJoinTimeoutHost(t)
	blocker := filepath.Join(f.root, "not-a-dir")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	t.Setenv("XDG_RUNTIME_DIR", blocker) // the runtime dir would have to live under a file
	f.start(t)
	err := f.result(t)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not-a-dir", "the error names the path that could not be created")
	// Nothing was claimed before CreateUptermRuntimeDir failed, so there is no
	// directory to publish a record into: the honest outcome is no record at
	// all, not startup_failed.
	_, rerr := sessiondir.ReadRecord(utils.UptermStateDir(), f.h.Name)
	require.True(t, os.IsNotExist(rerr), "nothing was claimed, so no record may claim this run happened: %v", rerr)
}

func TestRunRecordsStartupFailedWhenTheTunnelCannotBeEstablished(t *testing.T) {
	f := newJoinTimeoutHost(t)
	// A server that hangs up on every connection, so the SSH handshake fails
	// at once. Holding the port, rather than closing it to leave it dead,
	// keeps anything else from binding it before the dial.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	f.h.Host = "ssh://" + ln.Addr().String()
	f.start(t)
	runErr := f.result(t)
	require.Error(t, runErr)
	require.Contains(t, runErr.Error(), "ssh dial error")
	select {
	case <-f.ready:
		t.Fatal("the session became ready despite the tunnel failure")
	default:
	}
	require.Equal(t, sessiondir.ReasonStartupFailed, f.record(t).Reason)
}

// A failed ready write ends the run with the command already running, and it
// is the teardown that follows which stops the command. Whatever the command
// did under that teardown is not its own ending, and the record must not say
// it is: `session wait` turns exited and signaled into the command's status.
func TestRunRecordsStartupFailedWhenReadinessCannotBePublished(t *testing.T) {
	f := newJoinTimeoutHost(t)
	failure := errors.New("disk full")
	f.h.onReadyPublish = func() error { return failure }
	f.start(t)
	require.ErrorIs(t, f.result(t), failure)
	select {
	case <-f.ready:
		t.Fatal("the session was reported ready despite the failed write")
	default:
	}
	rec := f.record(t)
	require.Equal(t, sessiondir.ReasonStartupFailed, rec.Reason)
	require.Nil(t, rec.ExitCode)
	require.Empty(t, rec.Signal)
	require.Nil(t, rec.SignalNumber)
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
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
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
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	clock.only(t, 30*time.Millisecond).fire()
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

func (f *joinTimeoutHost) admin(t *testing.T) api.AdminServiceClient {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+f.h.AdminSocketFile, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return api.NewAdminServiceClient(conn)
}

func (f *joinTimeoutHost) set(t *testing.T, d time.Duration) (*api.SetJoinTimeoutResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return f.admin(t).SetJoinTimeout(ctx, &api.SetJoinTimeoutRequest{LaunchId: f.record(t).LaunchID, TimeoutNanos: int64(d)})
}

// The daemon sends a local client its status before it exits. A client that
// never answers the session's end -- a terminal suspended with ^Z -- holds
// its status back for the reply's bound, and a daemon that ended its run
// without waiting for that would exit with the status unsent: the client would
// see its connection dropped rather than the session ended.
func TestTheDaemonDeliversTheStatusBeforeItExits(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.closeConnectionsWhenRunReturns(t)
	client := f.attachIgnoringSessionEnd(t)

	f.stop(t)

	err := client.Wait()
	var exit *ssh.ExitError
	require.ErrorAs(t, err, &exit, "a status, not a connection closed under it: %v", err)
	require.Equal(t, 1, exit.ExitStatus())
}

// closeConnectionsWhenRunReturns plays the daemon's exit for the attach
// socket: the moment Run returns, its listener and every connection it
// accepted are closed. In process, a handler can outlive Run; once the daemon
// has exited, nothing it was still to send is sent.
func (f *joinTimeoutHost) closeConnectionsWhenRunReturns(t *testing.T) {
	t.Helper()
	var (
		mu    sync.Mutex
		ln    net.Listener
		conns []net.Conn
	)
	f.h.wrapAttachListener = func(l net.Listener) net.Listener {
		mu.Lock()
		defer mu.Unlock()
		ln = l
		return &acceptedListener{Listener: l, accepted: func(c net.Conn) {
			mu.Lock()
			defer mu.Unlock()
			conns = append(conns, c)
		}}
	}
	f.afterRun = func() {
		mu.Lock()
		defer mu.Unlock()
		if ln != nil {
			_ = ln.Close()
		}
		for _, c := range conns {
			_ = c.Close()
		}
	}
}

// acceptedListener reports each connection it accepts.
type acceptedListener struct {
	net.Listener
	accepted func(net.Conn)
}

func (l *acceptedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted(c)
	}
	return c, err
}

// attachIgnoringSessionEnd is attach with a client that reads the session-end
// request and never answers it, returning the client's session.
func (f *joinTimeoutHost) attachIgnoringSessionEnd(t *testing.T) *ssh.Session {
	t.Helper()
	f.h.AwaitInitialClient = true
	listening := make(chan string, 1)
	f.h.AttachListeningCallback = func(socket string) { listening <- socket }
	f.start(t)
	var socket string
	select {
	case socket = <-listening:
	case <-time.After(5 * time.Second):
		t.Fatal("attach socket never bound")
	}
	rec := f.record(t)
	require.NotEmpty(t, rec.HostKeys)
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rec.HostKeys[0]))
	require.NoError(t, err)
	key, err := NewHostKey()
	require.NoError(t, err)

	raw, err := net.DialTimeout("unix", socket, 3*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	conn, chans, reqs, err := ssh.NewClientConn(raw, socket, &ssh.ClientConfig{
		User: "host", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		ClientVersion:   upterm.AttachSSHClientVersion,
	})
	require.NoError(t, err)
	go func() {
		for req := range reqs {
			if req.Type != upterm.SessionEndRequestType {
				_ = req.Reply(false, nil)
			}
		}
	}()
	none := make(chan *ssh.Request)
	close(none)
	client := ssh.NewClient(conn, chans, none)
	t.Cleanup(func() { _ = client.Close() })
	sess, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	// Held open: a session whose input ends is a client that has left.
	in, err := sess.StdinPipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = in.Close() })
	sess.Stdout = io.Discard
	require.NoError(t, sess.Shell())
	return sess
}

// stop stops the session once it is ready, as `upterm session stop` does.
func (f *joinTimeoutHost) stop(t *testing.T) {
	t.Helper()
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := f.admin(t).StopSession(ctx, &api.StopSessionRequest{LaunchId: f.record(t).LaunchID})
	require.NoError(t, err)
}

func TestSessionSetArmsTheJoinTimeoutAfterReadiness(t *testing.T) {
	f := newJoinTimeoutHost(t)
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	require.Empty(t, clock.timers(), "no join timeout was set")

	resp, err := f.set(t, 200*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, api.SetJoinTimeoutResponse_COUNTING, resp.GetOutcome())
	deadline := time.Unix(0, resp.GetState().GetDeadlineUnixNano()).UTC()
	clock.only(t, 200*time.Millisecond).fire()

	require.NoError(t, f.result(t), "a join timeout is not a failure")
	rec := f.record(t)
	require.Equal(t, sessiondir.ReasonJoinTimeout, rec.Reason)
	require.True(t, rec.JoinDeadline.Equal(deadline), "the ended record shows the deadline that fired")
	require.True(t, rec.FirstGuestJoinedAt.IsZero())
}

func TestSessionSetReplacesAndDisablesALaunchTimeTimeout(t *testing.T) {
	f := newJoinTimeoutHost(t)
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
	f.h.JoinTimeout = 300 * time.Millisecond
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	joins := f.h.joins
	launch := clock.only(t, 300*time.Millisecond)

	resp, err := f.set(t, time.Hour)
	require.NoError(t, err)
	require.Equal(t, api.SetJoinTimeoutResponse_COUNTING, resp.GetOutcome())
	replacement := clock.only(t, time.Hour)
	require.True(t, launch.stopped(), "the replaced timer is stopped")
	// Each fire below is a callback already on its way when its timer was
	// stopped: expire must turn it away.
	launch.fire()
	require.False(t, hasFired(joins), "the launch-time timeout was replaced")

	resp, err = f.set(t, 0)
	require.NoError(t, err)
	require.Equal(t, api.SetJoinTimeoutResponse_DISABLED, resp.GetOutcome())
	require.Empty(t, clock.live(), "disabling leaves nothing counting")
	require.True(t, replacement.stopped(), "the disabled timer is stopped")
	replacement.fire()
	require.False(t, hasFired(joins), "the timeout was disabled")
	require.Eventually(t, func() bool {
		rec := f.record(t)
		return rec.JoinTimeout == 0 && rec.JoinDeadline.IsZero()
	}, 5*time.Second, 10*time.Millisecond, "the publisher writes the disabled state")

	f.finish(t, "0")
	require.NoError(t, f.result(t))
	require.Equal(t, sessiondir.ReasonExited, f.record(t).Reason)
}

func TestSessionSetAfterAJoinIsClaimed(t *testing.T) {
	f := newJoinTimeoutHost(t)
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	f.join(t)

	resp, err := f.set(t, 50*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, api.SetJoinTimeoutResponse_CLAIMED, resp.GetOutcome())
	require.True(t, time.Unix(0, resp.GetState().GetFirstGuestJoinedUnixNano()).Equal(f.record(t).FirstGuestJoinedAt))
	require.Empty(t, clock.timers(), "a claimed session is never armed")

	f.finish(t, "0")
	require.NoError(t, f.result(t))
}

func TestSessionSetRefusesAnotherLaunch(t *testing.T) {
	f := newJoinTimeoutHost(t)
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := f.admin(t).SetJoinTimeout(ctx, &api.SetJoinTimeoutRequest{LaunchId: "not-this-one", TimeoutNanos: int64(time.Millisecond)})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Empty(t, clock.timers(), "nothing was set")
	f.finish(t, "0")
	require.NoError(t, f.result(t))
}

func TestGetSessionReportsTheLiveJoinState(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	resp, err := f.set(t, time.Hour)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sess, err := f.admin(t).GetSession(ctx, &api.GetSessionRequest{})
	require.NoError(t, err)
	require.Equal(t, int64(time.Hour), sess.GetJoinState().GetTimeoutNanos())
	require.Equal(t, resp.GetState().GetDeadlineUnixNano(), sess.GetJoinState().GetDeadlineUnixNano())

	f.finish(t, "0")
	require.NoError(t, f.result(t))
}

// A session is open when anyone with its ID can join and nobody was asked: no
// allowlist, and started with --accept. Both the operator's first look at it
// and every later `session info` say so.
func TestGetSessionSaysWhetherTheSessionIsOpen(t *testing.T) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testPublicKey))
	require.NoError(t, err)
	for _, tc := range []struct {
		name       string
		autoAccept bool
		keys       []*AuthorizedKey
		want       bool
	}{
		{name: "no allowlist, accepted unasked", autoAccept: true, want: true},
		{name: "an allowlist", autoAccept: true, keys: []*AuthorizedKey{{PublicKeys: []ssh.PublicKey{key}}}},
		{name: "confirmed at start", autoAccept: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newJoinTimeoutHost(t)
			f.h.AutoAccept = tc.autoAccept
			f.h.AuthorizedKeys = tc.keys
			f.start(t)
			awaitJoinTimeoutSignal(t, f.ready, "readiness")

			require.Equal(t, tc.want, f.created.GetOpen(), "the session as created")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			sess, err := f.admin(t).GetSession(ctx, &api.GetSessionRequest{})
			require.NoError(t, err)
			require.Equal(t, tc.want, sess.GetOpen(), "the session as GetSession reports it")

			f.finish(t, "0")
			require.NoError(t, f.result(t))
		})
	}
}

// The first look at a session and every later `session info` say what it is
// called, how its tunnel is doing and what guests may do with it. The tunnel's
// state is read for each answer, from the same facts the record is written from.
func TestSessionReportsItsNameStateAndPermissions(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.ReadOnly = true
	f.h.AllowLocalTCPForwarding = true
	f.h.FileTransferApprovalRequired = true
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")

	get := func() *api.GetSessionResponse {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		sess, err := f.admin(t).GetSession(ctx, &api.GetSessionRequest{})
		require.NoError(t, err)
		return sess
	}

	reconnect := f.record(t).Reconnect
	require.NotEmpty(t, reconnect, "the relay has shown whether it derives session IDs by the time the session is ready")
	for _, tc := range []struct {
		what       string
		sess       *api.GetSessionResponse
		wantStatus string
	}{
		{"as created", f.created, sessiondir.StatusStarting},
		{"as GetSession reports it", get(), sessiondir.StatusReady},
	} {
		require.Equal(t, "deadline", tc.sess.GetName(), tc.what)
		require.Equal(t, tc.wantStatus, tc.sess.GetStatus(), tc.what)
		require.Equal(t, reconnect, tc.sess.GetReconnect(), tc.what)
		require.True(t, tc.sess.GetStartConfirmed(), "%s: nobody passed --accept", tc.what)
		require.True(t, tc.sess.GetReadOnly(), tc.what)
		require.True(t, tc.sess.GetLocalForwarding(), tc.what)
		require.Equal(t, "downloads", tc.sess.GetFileTransfer(), tc.what)
		require.True(t, tc.sess.GetFileTransferApprovalRequired(), tc.what)
		require.Nil(t, tc.sess.TunnelLostAtUnixNano, "%s: the tunnel has not dropped", tc.what)
		require.Nil(t, tc.sess.NextAttemptAtUnixNano, tc.what)
	}

	lostAt := time.Date(2026, 10, 12, 9, 30, 0, 0, time.UTC)
	nextAt := lostAt.Add(2 * time.Second)
	state := f.h.state.Load()
	state.tunnelReconnecting(lostAt, sessiondir.TunnelReasonNetwork, "EOF", nextAt)
	sess := get()
	require.Equal(t, sessiondir.StatusReconnecting, sess.GetStatus())
	require.Equal(t, sessiondir.TunnelReasonNetwork, sess.GetTunnelReason())
	require.Equal(t, lostAt.UnixNano(), sess.GetTunnelLostAtUnixNano())
	require.Equal(t, nextAt.UnixNano(), sess.GetNextAttemptAtUnixNano())

	state.tunnelUp()
	sess = get()
	require.Equal(t, sessiondir.StatusReady, sess.GetStatus())
	require.Empty(t, sess.GetTunnelReason())
	require.Nil(t, sess.TunnelLostAtUnixNano, "an outage that ended is not reported")
	require.Nil(t, sess.NextAttemptAtUnixNano)

	f.finish(t, "0")
	require.NoError(t, f.result(t))
}

// Accepted unasked, with file transfer off, the session reports both: nobody
// confirmed it, and nothing waits for terminal approval because nothing can
// be transferred.
func TestSessionReportsAcceptedWithNoFileTransfer(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.AutoAccept = true
	f.h.SFTPDisabled = true
	f.h.FileTransferApprovalRequired = true
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	live, err := f.admin(t).GetSession(ctx, &api.GetSessionRequest{})
	require.NoError(t, err)
	for what, sess := range map[string]*api.GetSessionResponse{"as created": f.created, "as GetSession reports it": live} {
		require.NotNil(t, sess.StartConfirmed, what)
		require.False(t, sess.GetStartConfirmed(), what)
		require.False(t, sess.GetReadOnly(), what)
		require.False(t, sess.GetLocalForwarding(), what)
		require.Equal(t, "off", sess.GetFileTransfer(), what)
		require.NotNil(t, sess.FileTransferApprovalRequired, what)
		require.False(t, sess.GetFileTransferApprovalRequired(), what)
	}

	f.finish(t, "0")
	require.NoError(t, f.result(t))
}

func TestJoinTimeoutIsPublishedPendingThenCounting(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = time.Hour
	// Held short of readiness by the initial attach, which is let through only
	// once the pending record has been seen.
	hold := make(chan struct{})
	clientDone, _ := f.attachAfter(t, hold)

	require.Eventually(t, func() bool {
		rec, err := sessiondir.ReadRecord(utils.UptermStateDir(), "deadline")
		return err == nil && rec.JoinTimeout == time.Hour && rec.JoinDeadline.IsZero()
	}, 5*time.Second, 10*time.Millisecond, "a launch-time timeout is published pending before readiness")
	select {
	case <-f.ready:
		t.Fatal("ready before the initial client attached")
	default:
	}

	close(hold)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	require.Eventually(t, func() bool { return !f.record(t).JoinDeadline.IsZero() }, 5*time.Second, 10*time.Millisecond,
		"counting from readiness, with a deadline")
	f.finish(t, "0")
	require.NoError(t, f.result(t))
	select {
	case outcome := <-clientDone:
		require.NoError(t, outcome.err)
	case <-time.After(5 * time.Second):
		t.Fatal("the attached client was not released")
	}
}

// Readiness is reported with the timeout already counting, so a caller told
// "ready" -- `--detach` returning -- never finds it still pending.
func TestJoinTimeoutIsCountingWhenReadinessIsReported(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = time.Hour
	var atReady *api.JoinState
	f.h.SessionReadyCallback = func(string) { atReady = f.h.JoinState(); close(f.ready) }
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	require.NotNil(t, atReady, "the join state is there to ask while Run runs")
	require.Equal(t, int64(time.Hour), atReady.GetTimeoutNanos())
	require.NotZero(t, atReady.GetDeadlineUnixNano(), "counting, not pending, by the time readiness is reported")

	f.finish(t, "0")
	require.NoError(t, f.result(t))
	require.Nil(t, f.h.JoinState(), "nothing to report once Run has returned")
}

// The guarantee is exact: shutting the command and its clients down never
// waits on a record write. The final bookkeeping -- the last write and
// releasing the name -- may, because the publisher is a run-group actor and
// must never write to a Dir that has been released.
func TestJoinTimeoutShutsDownWhileARecordWriteIsBlocked(t *testing.T) {
	f := newJoinTimeoutHost(t)
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
	f.h.JoinTimeout = 100 * time.Millisecond
	writing, unblocked := make(chan struct{}), make(chan struct{})
	var writingOnce, unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(unblocked) }) }
	f.h.onJoinPublish = func() error {
		writingOnce.Do(func() { close(writing) })
		<-unblocked
		return nil
	}
	clientDone, _ := f.attach(t)
	t.Cleanup(unblock)

	awaitJoinTimeoutSignal(t, writing, "a record write held open")
	// The write held may be the pending one, from before readiness, so the
	// timeout is fired only once the session is ready too.
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	clock.only(t, 100*time.Millisecond).fire()
	select {
	case outcome := <-clientDone:
		require.NoError(t, outcome.err, "the attached terminal is released while the write is still blocked")
	case <-time.After(5 * time.Second):
		t.Fatal("shutting the command down waited on a blocked record write")
	}
	// A bare window, in real time: nothing signals that Run would have
	// finished by now had it not waited for the held write. The window is
	// that wait's, not the join clock's.
	select {
	case err := <-f.done:
		t.Fatalf("Run finished, releasing the name, with a record write still pending: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	require.Equal(t, sessiondir.ReasonUnknown, f.record(t).Reason,
		"the final bookkeeping waits for the held write: no outcome is recorded yet")

	unblock()
	require.NoError(t, f.result(t), "finalisation completes once the write is released")
	require.Equal(t, sessiondir.ReasonJoinTimeout, f.record(t).Reason)
}

// When a record write fails, the daemon's live answer is still right.
func TestLiveJoinStateSurvivesAFailedPublication(t *testing.T) {
	f := newJoinTimeoutHost(t)
	failed := make(chan struct{})
	var failedOnce sync.Once
	f.h.onJoinPublish = func() error {
		failedOnce.Do(func() { close(failed) })
		return errors.New("disk full")
	}
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")

	resp, err := f.set(t, time.Hour)
	require.NoError(t, err)
	// Only once the publisher has actually tried and failed does the live
	// answer prove anything about a failed write.
	awaitJoinTimeoutSignal(t, failed, "the failed record write")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sess, err := f.admin(t).GetSession(ctx, &api.GetSessionRequest{})
	require.NoError(t, err)
	require.Equal(t, resp.GetState().GetDeadlineUnixNano(), sess.GetJoinState().GetDeadlineUnixNano())
	require.True(t, f.record(t).JoinDeadline.IsZero(), "the failed write left the record without it")

	f.finish(t, "0")
	require.NoError(t, f.result(t))
}

// parkAfterCommit holds the deadline actor just after the timeout commits,
// before it returns, so a test can act in the window after the commit. The
// caller registers release as a cleanup *after* f.start, so it runs before
// start's own cleanup waits for Run: cleanups run last-registered first.
func parkAfterCommit(t *testing.T, f *joinTimeoutHost) (reached <-chan struct{}, release func()) {
	t.Helper()
	r, released := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(released) }) }
	f.h.onJoinDeadlineFired = func(<-chan struct{}) {
		close(r)
		select {
		case <-released:
		case <-time.After(5 * time.Second):
			t.Error("deadline barrier not released")
		}
	}
	return r, release
}

func TestJoinAfterTheJoinTimeoutCommitsIsNotRecorded(t *testing.T) {
	f := newJoinTimeoutHost(t)
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
	f.h.JoinTimeout = 50 * time.Millisecond
	reached, release := parkAfterCommit(t, f)
	f.start(t)
	t.Cleanup(release)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	clock.only(t, 50*time.Millisecond).fire()
	awaitJoinTimeoutSignal(t, reached, "committed expiry")

	f.join(t) // registered after the commit
	release()
	require.NoError(t, f.result(t))
	rec := f.record(t)
	require.Equal(t, sessiondir.ReasonJoinTimeout, rec.Reason)
	require.True(t, rec.FirstGuestJoinedAt.IsZero(), "a join after the commit must not be published beside join_timeout")
}

func TestSessionSetAfterTheJoinTimeoutCommitsAnswersEnding(t *testing.T) {
	f := newJoinTimeoutHost(t)
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
	f.h.JoinTimeout = 50 * time.Millisecond
	reached, release := parkAfterCommit(t, f)
	f.start(t)
	t.Cleanup(release)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	clock.only(t, 50*time.Millisecond).fire()
	awaitJoinTimeoutSignal(t, reached, "committed expiry")

	resp, err := f.set(t, time.Hour)
	require.NoError(t, err)
	require.Equal(t, api.SetJoinTimeoutResponse_ENDING, resp.GetOutcome())
	release()
	require.NoError(t, f.result(t))
	require.Equal(t, sessiondir.ReasonJoinTimeout, f.record(t).Reason)
}

// A Host can run again, and each run makes a fresh join state on the Host's
// join clock: each run arms its own timer once it is ready.
func TestJoinClockAppliesToEachRun(t *testing.T) {
	f := newJoinTimeoutHost(t)
	clock := newFakeJoinClock()
	f.h.joinClock = clock.clock()
	// An hour, so that a second run that fell back to the real clock could
	// not end within the test.
	f.h.JoinTimeout = time.Hour

	// The first run ends by its timeout, not through finishFile, which would
	// still be there to end the second run's command at once.
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "the first run's readiness")
	first := f.h.joins
	clock.only(t, time.Hour).fire()
	require.NoError(t, f.result(t))
	rec := f.record(t)
	require.Equal(t, sessiondir.ReasonJoinTimeout, rec.Reason)
	firstLaunch := rec.LaunchID

	// The ready callback closes f.ready, so the second run gets a new one.
	f.ready = make(chan struct{})
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "the second run's readiness")
	require.NotSame(t, first, f.h.joins, "each run has its own join state")
	made := clock.timers()
	require.Len(t, made, 2, "each run armed its own timer on the Host's clock")
	second := clock.only(t, time.Hour)
	require.Same(t, made[1], second, "the live timer is the second run's")
	second.fire()
	require.NoError(t, f.result(t), "a join timeout is not a failure")
	rec = f.record(t)
	require.NotEqual(t, firstLaunch, rec.LaunchID, "the record is the second run's")
	require.Equal(t, sessiondir.ReasonJoinTimeout, rec.Reason)
}

// A Host's ClaimTimeout wins; left zero, the package's applies, read when Run
// asks rather than copied anywhere. This test assigns the deprecated package
// variable on purpose: it pins that the variable still works for a Host that
// sets nothing.
func TestClaimTimeoutIsTheFieldOrElseThePackages(t *testing.T) {
	orig := ClaimTimeout
	t.Cleanup(func() { ClaimTimeout = orig })
	var h Host
	require.Equal(t, ClaimTimeout, h.claimTimeout())
	ClaimTimeout = 3 * time.Second
	require.Equal(t, 3*time.Second, h.claimTimeout(), "read when Run asks, not cached")
	h.ClaimTimeout = 200 * time.Millisecond
	require.Equal(t, 200*time.Millisecond, h.claimTimeout())
	h.ClaimTimeout = -time.Second
	require.Equal(t, -time.Second, h.claimTimeout(),
		"a negative field gives the claim no time to wait for a held registry lock, as the package's does")
}

func TestHostConsentConfiguration(t *testing.T) {
	checker := consent.NewManager(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer checker.Close()
	h := &Host{TerminalConsent: true, PermissionChecker: checker}
	require.ErrorContains(t, h.Run(t.Context()), "mutually exclusive")
}

func TestHostGuestCommandOptions(t *testing.T) {
	for _, tc := range []struct {
		name         string
		login, force []string
	}{
		{"conflict", []string{"login"}, []string{"force"}},
		{"empty login", []string{}, nil}, {"empty force", nil, []string{}},
		{"whitespace login", []string{"  "}, nil}, {"empty argv0 force", nil, []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Host{Host: "ssh://unreachable.invalid:22", Name: "must-not-be-claimed", LoginCommand: tc.login, ForceCommand: tc.force}
			err := h.Run(t.Context())
			require.Error(t, err)
			require.True(t, strings.Contains(err.Error(), "mutually exclusive") || strings.Contains(err.Error(), "executable"))
			require.Nil(t, h.SessionDir)
		})
	}

}
