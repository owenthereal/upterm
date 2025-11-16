package ftests

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func testHostClientCallback(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)
	assert := assert.New(t)

	jch := make(chan *api.Client)
	lch := make(chan *api.Client)

	// Setup admin socket
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
		ClientJoinedCallback: func(c *api.Client) {
			jch <- c
		},
		ClientLeftCallback: func(c *api.Client) {
			lch <- c
		},
	}

	err := h.Share(hostShareURL)
	require.NoError(err)
	defer h.Close()

	// verify admin server
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	err = c.JoinWithContext(ctx, session, clientJoinURL)
	require.NoError(err)

	var clientID string
	select {
	case cc := <-jch:
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPublicKeyContent))
		require.NoError(err)

		assert.NotEmpty(cc.Id, "client id can't be empty")
		clientID = cc.Id

		assert.Equal(utils.FingerprintSHA256(pk), cc.PublicKeyFingerprint, "public key fingerprint should match")
		assert.Equal("SSH-2.0-Go", cc.Version, "client version should match")
	case <-time.After(2 * time.Second):
		t.Fatal("client joined callback is not called")
	}

	// client leaves
	cancel()
	c.Close()

	select {
	case cc := <-lch:
		assert.NotEmpty(cc.Id, "client id can't be empty")

		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPublicKeyContent))
		require.NoError(err)

		assert.Equal(clientID, cc.Id, "client ID should match on leave")
		assert.Equal(utils.FingerprintSHA256(pk), cc.PublicKeyFingerprint, "public key fingerprint should match on leave")
		assert.Equal("SSH-2.0-Go", cc.Version, "client version should match on leave")
	case <-time.After(2 * time.Second):
		if os.Getenv("MUTE_FLAKY_TESTS") != "" {
			testLogger.Error("FLAKY_TEST: client left callback is not called")
		} else {
			t.Fatal("client left callback is not called")
		}
	}
}

func testHostSessionCreatedCallback(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)
	assert := assert.New(t)

	// Setup admin socket
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:         getTestShell(),
		ForceCommand:    []string{"vim"},
		PrivateKeys:     []string{HostPrivateKey},
		AdminSocketFile: adminSocketFile,
		SessionCreatedCallback: func(session *api.GetSessionResponse) error {
			assert.Equal(getTestShell(), session.Command, "command should match")
			assert.Equal([]string{"vim"}, session.ForceCommand, "force command should match")

			checkSessionPayload(t, session, hostShareURL, hostNodeAddr)
			return nil
		},
	}

	err := h.Share(hostShareURL)
	require.NoError(err)
	defer h.Close()
}

func testHostFailToShareWithoutPrivateKey(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)

	// Setup admin socket
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:         getTestShell(),
		AdminSocketFile: adminSocketFile,
	}
	err := h.Share(hostShareURL)
	require.Error(err, "should fail without private key")
	require.ErrorContains(err, "Permission denied (publickey)", "should fail with permission denied error")
}
