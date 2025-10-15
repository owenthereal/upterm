package host

import (
	"bytes"
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

	cb, err := NewPromptingHostKeyCallback(stdin, stdout, knownHostsFile)
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

	cb, err := NewPromptingHostKeyCallback(stdin, stdout, tempfile)
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

func Test_hostKeyCallbackIPv6WithPort(t *testing.T) {
	tempfile := filepath.Join(t.TempDir(), "known_hosts")

	stdin := bytes.NewBufferString("yes\n")
	stdout := bytes.NewBuffer(nil)

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testPublicKey))
	require.NoError(t, err)

	cb, err := NewPromptingHostKeyCallback(stdin, stdout, tempfile)
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

	cb, err := NewPromptingHostKeyCallback(stdin, stdout, tempfile)
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
