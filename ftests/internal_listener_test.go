package ftests

import (
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// With an internal listener on every node, a guest joins however its host
// registered and wherever it enters: another node's SSH listener hops it to the
// session's node on that node's internal listener, and a WebSocket listener
// bridges it to its own node's SSH proxy, or hands it to the session's node
// raw.
func TestInternalListenerJoins(t *testing.T) {
	for _, mode := range []routing.Mode{routing.ModeEmbedded, routing.ModeConsul} {
		t.Run(string(mode), func(t *testing.T) {
			if mode == routing.ModeConsul && !testhelpers.IsConsulAvailable() {
				t.Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
			}
			useTestKeyPairs(t)
			n1 := newRedialRelay(t, mode, withInternalListener())
			n2 := newRedialRelay(t, mode, withInternalListener())

			for _, tc := range []struct {
				name        string
				host, guest string
			}{
				{"host n1 SSH, guest n2 SSH", n1.joinURL("ssh"), n2.joinURL("ssh")},
				{"host n1 SSH, guest n2 WebSocket", n1.joinURL("ssh"), n2.joinURL("ws")},
				{"host n1 WebSocket, guest n1 WebSocket", n1.joinURL("ws"), n1.joinURL("ws")},
				{"host n1 WebSocket, guest n2 SSH", n1.joinURL("ws"), n2.joinURL("ssh")},
			} {
				t.Run(tc.name, func(t *testing.T) {
					requireJoinsAsItsOwnKey(t, tc.host, n1.NodeAddr(), tc.guest)
				})
			}
		})
	}
}

// A node with an internal listener and one without join in both directions
// with no coordination. The new node records its internal listener in the
// store, and the old node hops there and hands its WebSocket guests there; the
// new node hops to the old one's SSH listener, which the old node recorded, as
// today.
func TestInternalListenerMixedFleet(t *testing.T) {
	if !testhelpers.IsConsulAvailable() {
		t.Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
	}
	useTestKeyPairs(t)
	n1 := newRedialRelay(t, routing.ModeConsul)
	n2 := newRedialRelay(t, routing.ModeConsul, withInternalListener())

	for _, tc := range []struct {
		name           string
		host           *Server
		hostURL, guest string
	}{
		{"host n1, guest n2", n1, n1.joinURL("ssh"), n2.joinURL("ssh")},
		{"host n2, guest n1", n2, n2.joinURL("ssh"), n1.joinURL("ssh")},
		{"host n2, WebSocket guest n1", n2, n2.joinURL("ssh"), n1.joinURL("ws")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireJoinsAsItsOwnKey(t, tc.hostURL, tc.host.NodeAddr(), tc.guest)
		})
	}
}

// useTestKeyPairs writes the fixture's host and guest keys for a test that runs
// outside the suites, which write them in SetupSuite.
func useTestKeyPairs(t *testing.T) {
	t.Helper()
	remove, err := setupKeyPairs()
	require.NoError(t, err)
	t.Cleanup(remove)
}

// requireJoinsAsItsOwnKey shares a session at hostURL that admits only the
// guest's key, joins it at joinURL, and requires the guest to reach the host's
// shell and the host to see the guest's own key. A hop taken for the key the
// relay presents would be refused by such a session; on one that admitted any
// key, it would join and show the host the relay's key.
func requireJoinsAsItsOwnKey(t *testing.T, hostURL, hostNodeAddr, joinURL string) {
	t.Helper()
	joined := make(chan *api.Client, 4)
	adminSocketFile := setupAdminSocket(t)
	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
		// The fixture's own terminal is announced as a client too.
		ClientJoinedCallback: func(c *api.Client) {
			if c.Kind != api.Client_HOST {
				joined <- c
			}
		},
	}
	require.NoError(t, h.Share(hostURL))
	t.Cleanup(h.Close)

	session := getAndVerifySession(t, adminSocketFile, hostURL, hostNodeAddr)
	joinAndReachHost(t, session, joinURL)

	guestKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPublicKeyContent))
	require.NoError(t, err)
	require.Equal(t, utils.FingerprintSHA256(guestKey), awaitClientCallback(t, joined, "joined").PublicKeyFingerprint,
		"the host saw a key other than the guest's own")
	requireRefusedHop(t, session, hostNodeAddr)
}

// A refused key in a relay certificate earns a hop-only banner. Probe the same
// restricted session separately from the successful join to observe the
// receiving relay's classification without exposing its connection state.
func requireRefusedHop(t *testing.T, session *api.GetSessionResponse, addr string) {
	t.Helper()
	authority, err := ssh.ParsePrivateKey([]byte(ServerPrivateKeyContent))
	require.NoError(t, err)
	otherGuest, _, _, _, err := ssh.ParseAuthorizedKey([]byte(HostPublicKeyContent))
	require.NoError(t, err)
	cert, err := (&server.UserCertSigner{
		SessionID: "refused-hop",
		User:      session.SshUser,
		AuthRequest: &server.AuthRequest{
			ClientVersion: "SSH-2.0-Go",
			AuthorizedKey: ssh.MarshalAuthorizedKey(otherGuest),
		},
	}).SignCert(authority)
	require.NoError(t, err)

	var banners []string
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: session.SshUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(cert)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
		BannerCallback: func(message string) error {
			banners = append(banners, message)
			return nil
		},
	})
	if client != nil {
		_ = client.Close()
	}
	require.ErrorContains(t, err, "unable to authenticate")
	require.Equal(t, []string{upterm.HopBannerKeyRefused}, banners,
		"the receiving relay did not classify the certificate as a hop")
}
