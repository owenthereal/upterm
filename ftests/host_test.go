package ftests

import (
	"bytes"
	"context"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// callbackTimeout bounds how long a test waits for a host callback that is
// causally downstream of an action the test has already taken. Measured on the
// happy path, the client-left callback fires ~600µs after Client.Close()
// returns, so this ceiling is four orders of magnitude of headroom: it costs
// nothing when the callback fires and keeps the assertion about *whether* the
// event happened rather than about how loaded the machine is.
//
// It replaces a 2s budget that failed roughly one full-suite run in five on
// testHostClientCallback. A flaky baseline is worse than a slow one here,
// because the functional suite is the safety net for the front-door rewrite,
// and a failure that cannot be trusted is not a safety net.
const callbackTimeout = 10 * time.Second

// awaitClientCallback waits for a client event, dumping goroutine stacks if it
// never arrives. A bare "callback is not called" says nothing about whether the
// event was dropped, the host's event loop wedged, or the relay never tore the
// connection down; the stacks say which.
func awaitClientCallback(t *testing.T, ch <-chan *api.Client, what string) *api.Client {
	t.Helper()

	select {
	case c := <-ch:
		return c
	case <-time.After(callbackTimeout):
		var stacks bytes.Buffer
		_ = pprof.Lookup("goroutine").WriteTo(&stacks, 2)
		t.Logf("goroutine dump at %s callback timeout:\n%s", what, stacks.String())
		t.Fatalf("client %s callback was not called within %s", what, callbackTimeout)
		return nil
	}
}

func testHostClientCallback(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	testClientCallbacks(t, hostShareURL, hostNodeAddr, clientJoinURL, false)
}

// testHostClientCallbackReadOnly covers the read-only session path, which
// has no input copy and so relies on the window-change channel closing to
// learn that the client has left.
func testHostClientCallbackReadOnly(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	testClientCallbacks(t, hostShareURL, hostNodeAddr, clientJoinURL, true)
}

func testClientCallbacks(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string, readOnly bool) {
	require := require.New(t)
	assert := assert.New(t)

	// Buffered so a duplicate event cannot wedge the host. The emitter
	// delivers to listeners from a goroutine that holds an emitter-wide lock
	// while it blocks on the listener channel, so one callback stuck on an
	// unbuffered send stalls every later event on that host, including the
	// client-left event this test is waiting for. The spare capacity also
	// lets the test observe duplicates instead of deadlocking on them.
	jch := make(chan *api.Client, 4)
	lch := make(chan *api.Client, 4)

	// Setup admin socket
	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
		ReadOnly:                 readOnly,
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

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPublicKeyContent))
	require.NoError(err)

	joined := awaitClientCallback(t, jch, "joined")
	assert.NotEmpty(joined.Id, "client id can't be empty")
	assert.Equal(utils.FingerprintSHA256(pk), joined.PublicKeyFingerprint, "public key fingerprint should match")
	assert.Equal("SSH-2.0-Go", joined.Version, "client version should match")

	// client leaves
	cancel()
	c.Close()

	left := awaitClientCallback(t, lch, "left")
	assert.NotEmpty(left.Id, "client id can't be empty")
	assert.Equal(joined.Id, left.Id, "client ID should match on leave")
	assert.Equal(utils.FingerprintSHA256(pk), left.PublicKeyFingerprint, "public key fingerprint should match on leave")
	assert.Equal("SSH-2.0-Go", left.Version, "client version should match on leave")

	// Exactly one event of each kind per guest. The relay terminates SSH on
	// both sides, so a change to how it originates connections upstream can
	// easily make the host see a guest join or leave twice; today it does not.
	// These can only fire on a real duplicate, never on a slow machine.
	assert.Empty(jch, "expected exactly one client joined event")
	assert.Empty(lch, "expected exactly one client left event")
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
		SessionCreatedCallback: func(_ context.Context, session *api.GetSessionResponse) error {
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
