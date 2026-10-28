package ftests

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
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
func requireJoinsAsItsOwnKey(t *testing.T, hostURL, hostNodeAddr, joinURL string, authorities ...ssh.Signer) {
	t.Helper()
	requireJoinsWithNodeKey(t, hostURL, hostNodeAddr, joinURL, nil, authorities...)
}

func requireJoinsWithNodeKey(t *testing.T, hostURL, hostNodeAddr, joinURL string, nodeKey ssh.PublicKey, authorities ...ssh.Signer) {
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
	if nodeKey != nil {
		h.HostKeyCallback = func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !utils.KeysEqual(key, nodeKey) {
				return fmt.Errorf("host connected to a relay with another key")
			}
			return nil
		}
	}
	require.NoError(t, h.Share(hostURL))
	t.Cleanup(h.Close)

	session := getAndVerifySession(t, adminSocketFile, hostURL, hostNodeAddr)
	joinAndReachHost(t, session, joinURL)

	guestKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPublicKeyContent))
	require.NoError(t, err)
	require.Equal(t, utils.FingerprintSHA256(guestKey), awaitClientCallback(t, joined, "joined").PublicKeyFingerprint,
		"the host saw a key other than the guest's own")
	requireRefusedHop(t, session, hostNodeAddr, authorities...)
}

// A refused key in a relay certificate earns a hop-only banner. Probe the same
// restricted session separately from the successful join to observe the
// receiving relay's classification without exposing its connection state.
func requireRefusedHop(t *testing.T, session *api.GetSessionResponse, addr string, authorities ...ssh.Signer) {
	t.Helper()
	authority, err := ssh.ParsePrivateKey([]byte(ServerPrivateKeyContent))
	require.NoError(t, err)
	if len(authorities) > 0 {
		authority = authorities[0]
	}
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
	authority := relay.Server.Signers[0]
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

func hopOptions(sign ssh.Signer, trusted []ssh.PublicKey, refuse bool) func(*Server) {
	return func(s *Server) {
		s.beforeServe = func(s *Server) {
			if sign != nil {
				s.Server.HopSigners = []ssh.Signer{sign}
			}
			s.Server.HopTrusted = trusted
			s.Server.RefuseHostKeyHops = refuse
		}
	}
}

func TestHopKeyRegistration(t *testing.T) {
	useTestKeyPairs(t)
	hop := newTestSigner(t)
	for _, mode := range []routing.Mode{routing.ModeEmbedded, routing.ModeConsul} {
		t.Run(string(mode), func(t *testing.T) {
			if mode == routing.ModeConsul && !testhelpers.IsConsulAvailable() {
				t.Skip("Consul not available")
			}
			nodes := []*Server{newRedialRelay(t, mode, withInternalListener(false), hopOptions(hop, nil, true)), newRedialRelay(t, mode, withInternalListener(false), hopOptions(hop, nil, true))}
			for i, host := range nodes {
				for _, protocol := range []string{"ssh", "ws"} {
					for j, guest := range nodes {
						t.Run(fmt.Sprintf("host%d_%s_guest%d", i, protocol, j), func(t *testing.T) {
							requireJoinsAsItsOwnKey(t, host.joinURL(protocol), host.NodeAddr(), guest.joinURL("ssh"), hop)
							requireSuccessfulRouteClassification(t, host, guest.joinURL("ssh"), i != j)
						})
					}
				}
			}
		})
	}
}

func TestHopKeyRotationPhases(t *testing.T) {
	if !testhelpers.IsConsulAvailable() {
		t.Skip("Consul not available")
	}
	useTestKeyPairs(t)
	h1, h2, h3 := newTestSigner(t), newTestSigner(t), newTestSigner(t)
	relay, err := ssh.ParsePrivateKey([]byte(ServerPrivateKeyContent))
	require.NoError(t, err)
	for phase := 0; phase <= 6; phase++ {
		t.Run(fmt.Sprintf("phase%d", phase), func(t *testing.T) {
			nodes := make([]*Server, 3)
			signers := make([]ssh.Signer, 3)
			for i := range nodes {
				var sign ssh.Signer
				var trust []ssh.PublicKey
				if phase >= 1 {
					trust = []ssh.PublicKey{h1.PublicKey()}
				}
				if phase >= 2 && (phase >= 3 || i == 0) {
					sign = h1
				}
				if phase >= 4 {
					trust = []ssh.PublicKey{h1.PublicKey(), h2.PublicKey()}
				}
				if phase >= 5 && (phase == 6 || i == 0) {
					sign = h2
				}
				if phase == 6 {
					trust = []ssh.PublicKey{h2.PublicKey()}
				}
				refuse := phase >= 4 || (phase == 3 && i == 0)
				nodes[i] = newRedialRelay(t, routing.ModeConsul, withInternalListener(false), hopOptions(sign, trust, refuse))
				signers[i] = relay
				if sign != nil {
					signers[i] = sign
				}
			}
			for i, host := range nodes {
				for j, guest := range nodes {
					if i != j {
						t.Run(fmt.Sprintf("guest%d_to_host%d", j, i), func(t *testing.T) {
							requireJoinsAsItsOwnKey(t, host.joinURL("ssh"), host.NodeAddr(), guest.joinURL("ssh"), signers[i])
							requireSuccessfulRouteClassification(t, host, guest.joinURL("ssh"), true)
						})
					}
				}
			}
			for i, node := range nodes {
				t.Run(fmt.Sprintf("untrusted_on%d", i), func(t *testing.T) { requireHopSignerRefused(t, node, h3) })
			}
			if phase == 3 {
				requireHopSignerRefused(t, nodes[0], relay)
			}
		})
	}
	t.Run("retiring H1 during mixed signing refuses H1", func(t *testing.T) {
		node := newRedialRelay(t, routing.ModeConsul, withInternalListener(false), hopOptions(h2, []ssh.PublicKey{h2.PublicKey()}, true))
		old := newRedialRelay(t, routing.ModeConsul, withInternalListener(false), hopOptions(h1, []ssh.PublicKey{h1.PublicKey(), h2.PublicKey()}, true))
		requireHopSignerRefused(t, node, h1)
		session, _ := classificationSession(t, node)
		auths, err := authMethodsFromFiles([]string{ClientPrivateKey})
		require.NoError(t, err)
		client, err := ssh.Dial("tcp", old.SSHAddr(), &ssh.ClientConfig{User: session.SshUser, ClientVersion: upterm.JoinSSHClientVersion, Auth: auths, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
		require.NoError(t, err)
		defer client.Close()
		_, _, err = client.OpenChannel("echo@upterm.test", nil)
		var refusal *ssh.OpenChannelError
		require.ErrorAs(t, err, &refusal)
		require.Equal(t, upterm.UpstreamAuthFailed, refusal.Message)
	})
}

// The claimed guest is admitted by this restricted session. If the receiving
// node accepts the authority, authentication succeeds: this catches an ignored
// refusal switch as well as the untrusted-certificate fallback.
func requireHopSignerRefused(t *testing.T, node *Server, signer ssh.Signer) {
	t.Helper()
	requireRotationSignerRefused(t, node, signer, true)
}

func requireRotationSignerRefused(t *testing.T, node *Server, signer ssh.Signer, restricted bool) {
	t.Helper()
	guest, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPublicKeyContent))
	require.NoError(t, err)
	host, _, _, _, err := ssh.ParseAuthorizedKey([]byte(HostPublicKeyContent))
	require.NoError(t, err)
	id := utils.GenerateSessionID()
	var allowed [][]byte
	if restricted {
		allowed = [][]byte{ssh.MarshalAuthorizedKey(guest)}
	}
	user, err := node.Server.SessionManager.CreateSession(server.NewSession(id, node.NodeAddr(), "host", [][]byte{ssh.MarshalAuthorizedKey(host)}, allowed))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Server.SessionManager.DeleteSession(id)) })
	cert, err := (&server.UserCertSigner{SessionID: "untrusted", User: user, AuthRequest: &server.AuthRequest{ClientVersion: "SSH-2.0-Go", AuthorizedKey: ssh.MarshalAuthorizedKey(guest)}}).SignCert(signer)
	require.NoError(t, err)
	guestSigner, err := ssh.ParsePrivateKey([]byte(ClientPrivateKeyContent))
	require.NoError(t, err)
	signed := cert.PublicKey().(*ssh.Certificate)
	signed.Key = guestSigner.PublicKey()
	require.NoError(t, signed.SignCert(rand.Reader, signer))
	cert, err = ssh.NewCertSigner(signed, guestSigner)
	require.NoError(t, err)
	c, err := ssh.Dial("tcp", node.NodeAddr(), &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(cert)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if c != nil {
		_ = c.Close()
	}
	require.ErrorContains(t, err, "unable to authenticate")
}

// A gate interrupts the first upstream attempt after its credentials were
// selected, while the host reconnects to the other node. Both retry directions
// must retain the guest's identity and use the newly appropriate credentials.
func TestRefreshAcrossCredKinds(t *testing.T) {
	if !testhelpers.IsConsulAvailable() {
		t.Skip("Consul not available")
	}
	useTestKeyPairs(t)
	for _, localFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("local_first_%v", localFirst), func(t *testing.T) {
			hop := newTestSigner(t)
			gate := &credentialGate{entered: make(chan struct{}), release: make(chan struct{})}
			options := hopOptions(hop, nil, true)
			setup := func(s *Server) {
				options(s)
				base := s.beforeServe
				s.beforeServe = func(s *Server) {
					base(s)
					s.Server.HandshakeTimeout = 30 * time.Second
					s.Server.NetworkProvider = &credentialGateNetwork{NetworkProvider: s.Server.NetworkProvider, gate: gate}
					s.internalln = &credentialGateListener{Listener: s.internalln, gate: gate}
				}
			}
			n1 := newRedialRelay(t, routing.ModeConsul, withInternalListener(false), setup)
			n2 := newRedialRelay(t, routing.ModeConsul, withInternalListener(false), setup)
			t.Cleanup(gate.open)
			entry := n2
			initial, next := n1, n2
			if localFirst {
				initial, next = n2, n1
			}
			joined := make(chan *api.Client, 4)
			h := shareRedialling(t, "ssh", initial, redialTiming, func(c *api.Client) {
				if c.Kind != api.Client_HOST {
					joined <- c
				}
			})
			// Wait until the entry cache names the original registration.
			require.Eventually(t, func() bool {
				s := entry.registered(h.first.SessionId)
				return s != nil && s.NodeAddr == initial.NodeAddr()
			}, redialTimeout, redialPoll)
			gate.arm()
			c := &Client{PrivateKeys: []string{ClientPrivateKey}}
			t.Cleanup(c.Close)
			done := make(chan error, 1)
			go func() { done <- c.Join(h.first, entry.joinURL("ssh")) }()
			select {
			case <-gate.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("upstream attempt did not reach the gate")
			}
			h.fwd.Redirect(next.addr("ssh"))
			h.fwd.Cut()
			h.awaitServedBy(t, next, redialTimeout)
			gate.open()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("guest did not join after refresh")
			}
			requireReachesHost(t, c)
			guest, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPublicKeyContent))
			require.NoError(t, err)
			require.Equal(t, utils.FingerprintSHA256(guest), awaitClientCallback(t, joined, "joined").PublicKeyFingerprint)
			requireSuccessfulRouteClassification(t, next, entry.joinURL("ssh"), next != entry)
		})
	}
}

type credentialGate struct {
	mu               sync.Mutex
	armed            bool
	entered, release chan struct{}
	once             sync.Once
}

func (g *credentialGate) arm() { g.mu.Lock(); g.armed = true; g.mu.Unlock() }
func (g *credentialGate) take() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.armed {
		return false
	}
	g.armed = false
	close(g.entered)
	return true
}
func (g *credentialGate) open() { g.once.Do(func() { close(g.release) }) }

type credentialGateListener struct {
	net.Listener
	gate *credentialGate
}

func (l *credentialGateListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil && l.gate.take() {
		<-l.gate.release
		_ = c.Close()
	}
	return c, err
}

type credentialGateNetwork struct {
	server.NetworkProvider
	gate *credentialGate
}

func (n *credentialGateNetwork) Session() server.SessionDialListener {
	return &credentialGateSession{SessionDialListener: n.NetworkProvider.Session(), gate: n.gate}
}

type credentialGateSession struct {
	server.SessionDialListener
	gate *credentialGate
}

func (s *credentialGateSession) DialContext(ctx context.Context, id string) (net.Conn, error) {
	if s.gate.take() {
		select {
		case <-s.gate.release:
			return nil, fmt.Errorf("session moved during upstream attempt")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.SessionDialListener.DialContext(ctx, id)
}

// Every node carries the same complete trust sets throughout the mixed fleet.
func TestServerKeyRotationKeepsFleetJoined(t *testing.T) {
	if !testhelpers.IsConsulAvailable() {
		t.Skip("Consul not available")
	}
	useTestKeyPairs(t)
	k1, k2, hop := newTestSigner(t), newTestSigner(t), newTestSigner(t)
	both := []ssh.PublicKey{k1.PublicKey(), k2.PublicKey()}
	for _, tc := range []struct {
		name  string
		keys  [2]ssh.Signer
		trust []ssh.PublicKey
	}{
		{"trust", [2]ssh.Signer{k1, k1}, both},
		{"present_mixed", [2]ssh.Signer{k2, k1}, both},
		{"present_complete", [2]ssh.Signer{k2, k2}, both},
		{"retire", [2]ssh.Signer{k2, k2}, []ssh.PublicKey{k2.PublicKey()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodes := []*Server{rotationRelay(t, tc.keys[0], tc.trust, hop, nil), rotationRelay(t, tc.keys[1], tc.trust, hop, nil)}
			requireRotationJoinsBothWays(t, nodes, tc.keys, [2]ssh.Signer{hop, hop})
		})
	}
	for _, name := range []string{"retired_key", "old_key_retired_early"} {
		t.Run(name, func(t *testing.T) {
			entry := rotationRelay(t, k2, []ssh.PublicKey{k2.PublicKey()}, hop, nil)
			targetTrust := []ssh.PublicKey{k2.PublicKey()}
			if name == "old_key_retired_early" {
				targetTrust = both
			}
			target := rotationRelay(t, k1, targetTrust, hop, nil)
			requireRotationRouteRefused(t, entry, target, upterm.UpstreamHostKeyMismatch)
		})
	}
}

func TestServerKeyRotationWithoutHopKey(t *testing.T) {
	if !testhelpers.IsConsulAvailable() {
		t.Skip("Consul not available")
	}
	useTestKeyPairs(t)
	k1, k2 := newTestSigner(t), newTestSigner(t)
	both := []ssh.PublicKey{k1.PublicKey(), k2.PublicKey()}
	for _, tc := range []struct {
		name     string
		hopTrust []ssh.PublicKey
		joins    [2]bool
	}{
		{"node_trust_only", nil, [2]bool{false, false}},
		{"new_hop_key_only", []ssh.PublicKey{k2.PublicKey()}, [2]bool{true, false}},
		{"both_hop_keys", both, [2]bool{true, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys := [2]ssh.Signer{k2, k1}
			nodes := []*Server{rotationRelay(t, k2, both, nil, tc.hopTrust), rotationRelay(t, k1, both, nil, tc.hopTrust)}
			for entry, target := range []int{1, 0} {
				t.Run(fmt.Sprintf("n%d_to_n%d", entry+1, target+1), func(t *testing.T) {
					if tc.joins[entry] {
						requireJoinsWithNodeKey(t, nodes[target].joinURL("ssh"), nodes[target].NodeAddr(), nodes[entry].joinURL("ssh"), keys[target].PublicKey(), keys[target])
						requireSuccessfulRouteClassification(t, nodes[target], nodes[entry].joinURL("ssh"), true)
					} else {
						requireRotationRouteRefused(t, nodes[entry], nodes[target], upterm.UpstreamAuthFailed)
						t.Run("restricted", func(t *testing.T) { requireRotationSignerRefused(t, nodes[target], keys[entry], true) })
						t.Run("open_session_control", func(t *testing.T) { requireRotationSignerRefused(t, nodes[target], keys[entry], false) })
					}
				})
			}
		})
	}
	for _, tc := range []struct {
		name  string
		keys  [2]ssh.Signer
		trust []ssh.PublicKey
	}{
		{"trust", [2]ssh.Signer{k1, k1}, both},
		{"present_complete", [2]ssh.Signer{k2, k2}, both},
		{"retire", [2]ssh.Signer{k2, k2}, []ssh.PublicKey{k2.PublicKey()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodes := []*Server{rotationRelay(t, tc.keys[0], tc.trust, nil, tc.trust), rotationRelay(t, tc.keys[1], tc.trust, nil, tc.trust)}
			requireRotationJoinsBothWays(t, nodes, tc.keys, tc.keys)
		})
	}
}

func rotationRelay(t *testing.T, key ssh.Signer, nodeTrust []ssh.PublicKey, hop ssh.Signer, hopTrust []ssh.PublicKey) *Server {
	t.Helper()
	ready := make(chan struct{})
	relay := newRedialRelay(t, routing.ModeConsul, withInternalListener(false), func(s *Server) {
		s.beforeServe = func(s *Server) {
			s.Server.HostSigners = []ssh.Signer{key}
			s.Server.Signers = []ssh.Signer{key}
			s.Server.NodeTrusted = nodeTrust
			if hop != nil {
				s.Server.HopSigners = []ssh.Signer{hop}
				s.Server.RefuseHostKeyHops = true
			}
			s.Server.HopTrusted = hopTrust
			close(ready)
		}
	})
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("rotation relay did not initialize")
	}
	return relay
}

func requireRotationJoinsBothWays(t *testing.T, nodes []*Server, keys, authorities [2]ssh.Signer) {
	t.Helper()
	for entry, target := range []int{1, 0} {
		t.Run(fmt.Sprintf("n%d_to_n%d", entry+1, target+1), func(t *testing.T) {
			requireJoinsWithNodeKey(t, nodes[target].joinURL("ssh"), nodes[target].NodeAddr(), nodes[entry].joinURL("ssh"), keys[target].PublicKey(), authorities[target])
			requireSuccessfulRouteClassification(t, nodes[target], nodes[entry].joinURL("ssh"), true)
		})
	}
}

func requireRotationRouteRefused(t *testing.T, entry, target *Server, want string) {
	t.Helper()
	session, _ := classificationSession(t, target)
	auths, err := authMethodsFromFiles([]string{ClientPrivateKey})
	require.NoError(t, err)
	client, err := ssh.Dial("tcp", entry.SSHAddr(), &ssh.ClientConfig{User: session.SshUser, ClientVersion: upterm.JoinSSHClientVersion, Auth: auths, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	require.NoError(t, err)
	defer client.Close()
	_, _, err = client.OpenChannel("echo@upterm.test", nil)
	var refusal *ssh.OpenChannelError
	require.ErrorAs(t, err, &refusal)
	require.Equal(t, want, refusal.Message)
}
