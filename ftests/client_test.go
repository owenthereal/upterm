package ftests

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/routing"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testHostNoAuthorizedKeyAnyClientJoin(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)

	// Setup admin socket
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:         []string{"bash", "-c", "PS1='' BASH_SILENCE_DEPRECATION_WARNING=1 bash --norc"},
		PrivateKeys:     []string{HostPrivateKey},
		AdminSocketFile: adminSocketFile,
	}
	err := h.Share(hostShareURL)
	require.NoError(err)
	defer h.Close()

	// Verify admin server - require session exists to continue
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	c := &Client{
		PrivateKeys: []string{HostPrivateKey}, // use the wrong key
	}

	err = c.Join(session, clientJoinURL)
	require.NoError(err)
}

func testClientAuthorizedKeyNotMatching(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)
	assert := assert.New(t)

	// Setup admin socket
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  []string{"bash", "-c", "PS1='' BASH_SILENCE_DEPRECATION_WARNING=1 bash --norc"},
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	err := h.Share(hostShareURL)
	require.NoError(err)
	defer h.Close()

	// Verify admin server - require session exists to continue
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	c := &Client{
		PrivateKeys: []string{HostPrivateKey}, // use the wrong key
	}

	err = c.Join(session, clientJoinURL)

	// Test authorization failure - use assert for expected error validation
	require.Error(err, "connection should be rejected with wrong key")
	assert.ErrorContains(err, "ssh: handshake failed", "should fail with SSH handshake error")
}

func testClientNonExistingSession(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)

	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  []string{"bash", "-c", "PS1='' BASH_SILENCE_DEPRECATION_WARNING=1 bash --norc"},
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	err := h.Share(hostShareURL)
	require.NoError(err)

	defer h.Close()

	// verify admin server
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	// verify input/output
	hostInputCh, hostOutputCh := h.InputOutput()
	hostScanner := scanner(hostOutputCh)

	hostInputCh <- "echo hello"
	require.Equal("echo hello", scan(hostScanner))
	require.Equal("hello", scan(hostScanner))

	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	session.SshUser = "non-existing-user" // set SSH user to non-existing
	err = c.Join(session, clientJoinURL)

	// Unfortunately there is no explicit error to the client.
	// But ssh handshake fails with the connection closed
	require.ErrorContains(err, "ssh: handshake failed")
}

func testClientAttachHostWithSameCommand(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)
	assert := assert.New(t)

	// Setup - use require for critical setup steps
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  []string{"bash", "-c", "PS1='' BASH_SILENCE_DEPRECATION_WARNING=1 bash --norc"},
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	err := h.Share(hostShareURL)
	require.NoError(err)
	defer h.Close()

	// verify admin server
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	// verify input/output
	hostInputCh, hostOutputCh := h.InputOutput()
	hostScanner := scanner(hostOutputCh)

	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	err = c.Join(session, clientJoinURL)
	require.NoError(err)

	remoteInputCh, remoteOutputCh := c.InputOutput()
	remoteScanner := scanner(remoteOutputCh)

	// host input
	hostInputCh <- "echo hello"
	assert.Equal("echo hello", scan(hostScanner), "host should echo command")
	assert.Equal("hello", scan(hostScanner), "host should show command output")

	// client output
	assert.Equal("echo hello", scan(remoteScanner), "client should see host command")
	assert.Equal("hello", scan(remoteScanner), "client should see host output")

	// client input
	remoteInputCh <- "echo hello again"
	assert.Equal("echo hello again", scan(remoteScanner), "client should echo its own command")
	assert.Equal("hello again", scan(remoteScanner), "client should see its own output")

	// host output
	// host should link to remote with the same input/output
	assert.Equal("echo hello again", scan(hostScanner), "host should see client command")
	assert.Equal("hello again", scan(hostScanner), "host should see client output")
}

func testClientAttachHostWithDifferentCommand(t *testing.T, hostShareURL string, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)
	assert := assert.New(t)

	// Setup - use require for critical setup steps
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  []string{"bash", "-c", "PS1='' BASH_SILENCE_DEPRECATION_WARNING=1 bash --norc"},
		ForceCommand:             []string{"bash", "-c", "PS1='' BASH_SILENCE_DEPRECATION_WARNING=1 bash --norc"},
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	err := h.Share(hostShareURL)
	require.NoError(err)
	defer h.Close()

	// verify admin server
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	// verify input/output
	hostInputCh, hostOutputCh := h.InputOutput()
	hostScanner := scanner(hostOutputCh)

	hostInputCh <- "echo hello"
	assert.Equal("echo hello", scan(hostScanner), "host should echo initial command")
	assert.Equal("hello", scan(hostScanner), "host should show initial output")

	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	err = c.Join(session, clientJoinURL)
	require.NoError(err)

	remoteInputCh, remoteOutputCh := c.InputOutput()
	remoteScanner := scanner(remoteOutputCh)

	// Wait for ssh stdin/stdout to fully attach - critical for force command isolation
	time.Sleep(time.Second)

	remoteInputCh <- "echo hello again"
	assert.Equal("echo hello again", scan(remoteScanner), "client should echo its command")
	assert.Equal("hello again", scan(remoteScanner), "client should see its output")

	// host shouldn't be linked to remote
	hostInputCh <- "echo hello"
	assert.Equal("echo hello", scan(hostScanner), "host should echo second command independently")
	assert.Equal("hello", scan(hostScanner), "host should show second output independently")
}

func testClientAttachReadOnly(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)
	assert := assert.New(t)

	// Setup - use require for critical setup steps
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  []string{"bash", "-c", "PS1='' BASH_SILENCE_DEPRECATION_WARNING=1 bash --norc"},
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
		ReadOnly:                 true,
	}
	err := h.Share(hostShareURL)
	require.NoError(err)
	defer h.Close()

	// verify admin server
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	// verify input/output
	hostInputCh, hostOutputCh := h.InputOutput()
	hostScanner := scanner(hostOutputCh)

	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	err = c.Join(session, clientJoinURL)
	require.NoError(err)

	remoteInputCh, remoteOutputCh := c.InputOutput()
	remoteScanner := scanner(remoteOutputCh)

	// client output
	// client should get "welcome message"
	// \n
	// === Attached to read-only session ===
	// \n
	assert.Equal("=== Attached to read-only session ===", scan(remoteScanner), "client should see read-only welcome message")

	// host input should still work
	hostInputCh <- "echo hello"
	assert.Equal("echo hello", scan(hostScanner), "host should echo command in read-only mode")
	assert.Equal("hello", scan(hostScanner), "host should show output in read-only mode")

	// client input should be disabled
	remoteInputCh <- "echo hello again"
	// client should read what was sent by hostInputCh and not what was sent on remoteInputCh
	assert.Equal("echo hello", scan(remoteScanner), "client should see host output, not its own input")

	select {
	// host shouldn't receive anything from client and because client input is disabled
	case str := <-hostOutputCh:
		t.Fatalf("host shouldn't receive client input: receive=%s", str)
	case <-time.After(sshAttachTimeout):
		log.Debug("Read-only timeout confirmed - client input properly blocked")
		return
	}

}

func getAndVerifySession(t *testing.T, adminSocketFile string, wantHostURL, wantNodeURL string) *api.GetSessionResponse {
	require := require.New(t)

	adminClient, err := host.AdminClient(adminSocketFile)
	require.NoError(err)

	sess, err := adminClient.GetSession(context.Background(), &api.GetSessionRequest{})
	require.NoError(err)

	checkSessionPayload(t, sess, wantHostURL, wantNodeURL)

	return sess
}

func checkSessionPayload(t *testing.T, sess *api.GetSessionResponse, wantHostURL, wantNodeURL string) {
	require := require.New(t)
	require.NotEmpty(sess.SessionId, "session ID should not be empty")
	require.Equal(wantHostURL, sess.Host, "host URL mismatch")
	require.Equal(wantNodeURL, sess.NodeAddr, "node URL mismatch")
	require.NotEmpty(sess.SshUser, "SSH user should not be empty")
}

// testOldClientToNewConsulServer tests backward compatibility scenario where
// an old upterm client (using embedded format) connects to a new uptermd server running in Consul mode
func testOldClientToNewConsulServer(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)

	// Setup admin socket
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:         []string{"bash", "-c", "PS1='' BASH_SILENCE_DEPRECATION_WARNING=1 bash --norc"},
		PrivateKeys:     []string{HostPrivateKey},
		AdminSocketFile: adminSocketFile,
	}
	err := h.Share(hostShareURL)
	require.NoError(err)
	defer h.Close()

	// Get session info from host (this is in the new format for Consul mode)
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	// Create an embedded format SSH user (what old clients would send)
	embeddedEncoder := routing.NewEncodeDecoder(routing.ModeEmbedded)
	oldClientSSHUser := embeddedEncoder.Encode(session.SessionId, session.NodeAddr)

	t.Logf("Testing backward compatibility:")
	t.Logf("  Session ID: %s", session.SessionId)
	t.Logf("  Node Address: %s", session.NodeAddr)
	t.Logf("  New client SSH user (Consul format): %s", session.SshUser)
	t.Logf("  Old client SSH user (embedded format): %s", oldClientSSHUser)

	// Create a regular client but override the SSH username to simulate old client behavior
	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}

	// Create a modified session response with the old format SSH user
	oldFormatSession := &api.GetSessionResponse{
		SessionId: session.SessionId,
		NodeAddr:  session.NodeAddr,
		Host:      session.Host,
		SshUser:   oldClientSSHUser, // Use old embedded format instead of Consul format
	}

	// This should work thanks to our backward compatibility fix
	err = c.Join(oldFormatSession, clientJoinURL)
	require.NoError(err, "Old client with embedded format should be able to connect to Consul server")
	defer c.Close()

	t.Log("Backward compatibility test passed: old client successfully connected to new Consul server")
}

// setupAdminSocket creates a temporary admin socket and returns the socket file path
func setupAdminSocket(t *testing.T) string {
	require := require.New(t)

	// Use a shorter temp dir to avoid Unix socket path length limits
	adminSockDir, err := os.MkdirTemp("", "up")
	require.NoError(err)

	t.Cleanup(func() {
		_ = os.RemoveAll(adminSockDir)
	})
	return filepath.Join(adminSockDir, "u.sock")
}
