package ftests

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/owenthereal/upterm/ws"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// With an internal listener on every node, a guest joins however its host
// registered and wherever it enters: another node's SSH listener hops it to the
// session's node on that node's internal listener, and a WebSocket listener
// bridges it to its own node's SSH proxy, or hands it to the session's node
// raw.
func TestInternalListenerJoins(t *testing.T) {
	testInternalListenerJoins(t, false)
}

func TestStrictInternalListenerJoins(t *testing.T) {
	testInternalListenerJoins(t, true)
}

func testInternalListenerJoins(t *testing.T, strict bool) {
	for _, mode := range []routing.Mode{routing.ModeEmbedded, routing.ModeConsul} {
		t.Run(string(mode), func(t *testing.T) {
			if mode == routing.ModeConsul && !testhelpers.IsConsulAvailable() {
				t.Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
			}
			useTestKeyPairs(t)
			n1 := newRedialRelay(t, mode, withInternalListener(strict))
			n2 := newRedialRelay(t, mode, withInternalListener(strict))

			for _, tc := range []struct {
				name        string
				host, guest string
				hop         bool
			}{
				{"host n1 SSH, guest n2 SSH", n1.joinURL("ssh"), n2.joinURL("ssh"), true},
				{"host n1 SSH, guest n2 WebSocket", n1.joinURL("ssh"), n2.joinURL("ws"), mode == routing.ModeEmbedded},
				{"host n1 WebSocket, guest n1 WebSocket", n1.joinURL("ws"), n1.joinURL("ws"), false},
				{"host n1 WebSocket, guest n2 SSH", n1.joinURL("ws"), n2.joinURL("ssh"), true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					requireJoinsAsItsOwnKey(t, tc.host, n1.NodeAddr(), tc.guest)
					requireSuccessfulRouteClassification(t, n1, tc.guest, tc.hop)
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
	n2 := newRedialRelay(t, routing.ModeConsul, withInternalListener(false))

	for _, tc := range []struct {
		name           string
		host           *Server
		hostURL, guest string
		hop            bool
	}{
		{"host n1, guest n2", n1, n1.joinURL("ssh"), n2.joinURL("ssh"), true},
		{"host n2, guest n1", n2, n2.joinURL("ssh"), n1.joinURL("ssh"), true},
		{"host n2, WebSocket guest n1", n2, n2.joinURL("ssh"), n1.joinURL("ws"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireJoinsAsItsOwnKey(t, tc.hostURL, tc.host.NodeAddr(), tc.guest)
			requireSuccessfulRouteClassification(t, tc.host, tc.guest, tc.hop)
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

// Exercise the successful connection's hop marker through channel rejection
// wording. The endpoint sees the guest's key, echoes bytes, and rejects another
// channel on that same connection. An entry speaking upterm preserves the wire
// text, so a receiving hop must also preserve it; a raw guest reads a sentence.
func requireSuccessfulRouteClassification(t *testing.T, relay *Server, joinURL string, hop bool) {
	t.Helper()
	session, authenticated := classificationSession(t, relay)
	auths, err := authMethodsFromFiles([]string{ClientPrivateKey})
	require.NoError(t, err)
	config := &ssh.ClientConfig{User: session.SshUser, Auth: auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second}
	want := fmt.Sprintf("upterm: the relay can't reach the host of session %s right now; try again shortly.", session.SessionId)
	if hop {
		config.ClientVersion = upterm.JoinSSHClientVersion
		want = upterm.UpstreamUnavailable
	}
	u, err := url.Parse(joinURL)
	require.NoError(t, err)
	var client *ssh.Client
	if u.Scheme == "ws" {
		u.User = url.UserPassword(session.SessionId, base64.URLEncoding.EncodeToString([]byte(session.NodeAddr)))
		client, err = ws.NewSSHClient(u, config, true, nil)
	} else {
		client, err = ssh.Dial("tcp", u.Host, config)
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	deadline := time.AfterFunc(5*time.Second, func() { _ = client.Close() })
	defer deadline.Stop()

	channel, requests, err := client.OpenChannel("echo@upterm.test", nil)
	require.NoError(t, err)
	go ssh.DiscardRequests(requests)
	payload := []byte("the routed guest's bytes")
	_, err = channel.Write(payload)
	require.NoError(t, err)
	got := make([]byte, len(payload))
	_, err = io.ReadFull(channel, got)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.NoError(t, channel.Close())

	select {
	case fingerprint := <-authenticated:
		guest, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPublicKeyContent))
		require.NoError(t, err)
		require.Equal(t, utils.FingerprintSHA256(guest), fingerprint, "the endpoint saw another key")
	case <-time.After(5 * time.Second):
		t.Fatal("the session endpoint did not authenticate the routed guest")
	}
	_, _, err = client.OpenChannel("classification@upterm.test", nil)
	var rejection *ssh.OpenChannelError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, ssh.Prohibited, rejection.Reason)
	require.Equal(t, want, rejection.Message, "the admitted route's hop classification changed")
}

// classificationSession installs a restricted session with a controllable SSH
// endpoint. The session socket forwards bytes to loopback TCP, keeping the SSH
// handshake on a real socket while using the relay's ordinary session routing.
func classificationSession(t *testing.T, relay *Server) (*api.GetSessionResponse, <-chan string) {
	t.Helper()
	hostKey, err := ssh.ParsePrivateKey([]byte(HostPrivateKeyContent))
	require.NoError(t, err)
	authority, err := ssh.ParsePrivateKey([]byte(ServerPrivateKeyContent))
	require.NoError(t, err)
	guest, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPublicKeyContent))
	require.NoError(t, err)
	id := utils.GenerateSessionID()
	socket, err := relay.Server.NetworkProvider.Session().Listen(id)
	require.NoError(t, err)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close(); _ = socket.Close() })
	user, err := relay.Server.SessionManager.CreateSession(server.NewSession(id, relay.NodeAddr(), "host",
		[][]byte{ssh.MarshalAuthorizedKey(hostKey.PublicKey())}, [][]byte{ssh.MarshalAuthorizedKey(guest)}))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, relay.Server.SessionManager.DeleteSession(id)) })

	checker := server.UserCertChecker{IsUserAuthority: func(key ssh.PublicKey) bool {
		return utils.KeysEqual(key, authority.PublicKey())
	}}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		_, key, err := checker.Authenticate(meta.User(), key)
		if err != nil {
			return nil, err
		}
		if !utils.KeysEqual(key, guest) {
			return nil, fmt.Errorf("unexpected guest key")
		}
		return &ssh.Permissions{Extensions: map[string]string{"guest": utils.FingerprintSHA256(key)}}, nil
	}}
	cfg.AddHostKey(hostKey)
	authenticated := make(chan string, 1)
	finished := make(chan error, 1)
	go func() { finished <- serveClassificationSession(ln, cfg, authenticated) }()
	forwarded := make(chan struct{})
	go func() {
		defer close(forwarded)
		down, err := socket.Accept()
		if err != nil {
			return
		}
		defer func() { _ = down.Close() }()
		up, err := net.DialTimeout("tcp4", ln.Addr().String(), 5*time.Second)
		if err != nil {
			return
		}
		defer func() { _ = up.Close() }()
		copied := make(chan struct{})
		go func() { _, _ = io.Copy(up, down); _ = up.Close(); close(copied) }()
		_, _ = io.Copy(down, up)
		_ = down.Close()
		<-copied
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = socket.Close()
		select {
		case err := <-finished:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("the classification endpoint did not stop")
		}
		select {
		case <-forwarded:
		case <-time.After(5 * time.Second):
			t.Error("the session socket forwarder did not stop")
		}
	})
	return &api.GetSessionResponse{SessionId: id, SshUser: user, NodeAddr: relay.NodeAddr()}, authenticated
}

func serveClassificationSession(ln net.Listener, cfg *ssh.ServerConfig, authenticated chan<- string) error {
	raw, err := ln.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
	defer func() { _ = raw.Close() }()
	if err := raw.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	conn, channels, requests, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	authenticated <- conn.Permissions.Extensions["guest"]
	go ssh.DiscardRequests(requests)
	for incoming := range channels {
		if incoming.ChannelType() != "echo@upterm.test" {
			if err := incoming.Reject(ssh.Prohibited, upterm.UpstreamUnavailable); err != nil {
				return err
			}
			continue
		}
		channel, requests, err := incoming.Accept()
		if err != nil {
			return err
		}
		go ssh.DiscardRequests(requests)
		_, err = io.Copy(channel, channel)
		_ = channel.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
