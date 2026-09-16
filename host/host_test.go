package host

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
