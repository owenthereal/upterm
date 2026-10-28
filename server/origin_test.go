package server

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// The golden bytes were written from the wire contract's field numbers and
// types, not by the generated code, so renumbering or retyping a field, which a
// relay of another version would misread, fails here.
func TestAuthRequestWireGolden(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("testdata", "authrequest.golden"))
	require.NoError(t, err)
	b, err := proto.Marshal(&AuthRequest{
		ClientVersion:     "SSH-2.0-x",
		RemoteAddr:        "203.0.113.7:4711",
		AuthorizedKey:     []byte("k"),
		LocalAddr:         "10.0.0.1:22",
		Ingress:           Ingress_INGRESS_WEBSOCKET,
		IngressNode:       "n1:2223",
		IngressConnection: []byte{1, 2, 3},
	})
	require.NoError(t, err)
	require.Equal(t, golden, b)

	// A relay that predates the origin fields sends 1-4 alone, and its
	// request reads as one whose origin is unknown.
	var legacy []byte
	for i, value := range []string{"SSH-2.0-x", "203.0.113.7:4711", "k", "10.0.0.1:22"} {
		legacy = protowire.AppendTag(legacy, protowire.Number(i+1), protowire.BytesType)
		legacy = protowire.AppendString(legacy, value)
	}
	var auth AuthRequest
	require.NoError(t, proto.Unmarshal(legacy, &auth))
	require.Equal(t, "SSH-2.0-x", auth.ClientVersion)
	require.Equal(t, "203.0.113.7:4711", auth.RemoteAddr)
	require.Equal(t, []byte("k"), auth.AuthorizedKey)
	require.Equal(t, "10.0.0.1:22", auth.LocalAddr)
	require.Equal(t, Ingress_INGRESS_UNSPECIFIED, auth.Ingress)
	require.Equal(t, "", auth.IngressNode)
	require.Nil(t, auth.IngressConnection)
}

// sessionConn is fakeConnMetadata with an SSH session ID of its own.
type sessionConn struct {
	fakeConnMetadata
	sessionID []byte
}

func (c *sessionConn) SessionID() []byte { return c.sessionID }

// originConn is a connection as user, announcing clientVersion, whose SSH
// session ID is sessionID.
func originConn(user, clientVersion, sessionID string) *sessionConn {
	return &sessionConn{
		fakeConnMetadata: fakeConnMetadata{
			user:          user,
			clientVersion: clientVersion,
			remote:        &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234},
			local:         &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 22},
		},
		sessionID: []byte(sessionID),
	}
}

var allListenerKinds = []listenerKind{listenerShared, listenerPublic, listenerInternal, listenerBridge}

func TestOriginOf(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	sm := newEmbeddedSessionManager(logger)
	key := certTestSigner(t)

	for _, tc := range []struct {
		name    string
		kind    listenerKind
		ingress Ingress
		node    string
	}{
		// Bridged guests and other nodes' hops share it with direct clients.
		{"the shared listener", listenerShared, Ingress_INGRESS_UNSPECIFIED, ""},
		{"the public listener", listenerPublic, Ingress_INGRESS_SSH, "n1:22"},
		{"this node's WebSocket bridge", listenerBridge, Ingress_INGRESS_WEBSOCKET, "n1:22"},
		// A neighbour's bridged guest, or an unknown peer.
		{"a raw connection on the internal listener", listenerInternal, Ingress_INGRESS_UNSPECIFIED, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guest := originConn(sm.GetEncodeDecoder().Encode("session", "n9:22"), "SSH-2.0-OpenSSH_9.0", "sid")
			ingress, node, connection := originOf(tc.kind, guest, "n1:22")
			require.Equal(t, tc.ingress, ingress)
			require.Equal(t, tc.node, node)
			require.Equal(t, []byte("sid"), connection)

			// A direct guest's request records the same.
			a := proxyAuth{NodeAddr: "n1:22", listener: tc.kind, SessionManager: sm, Logger: logger}
			auth, _, hop, err := a.authenticate(guest, key.PublicKey())
			require.NoError(t, err)
			require.False(t, hop)
			require.Equal(t, tc.ingress, auth.GetIngress())
			require.Equal(t, tc.node, auth.GetIngressNode())
			require.Equal(t, []byte("sid"), auth.GetIngressConnection())
		})
	}

	// Whichever listener it arrives on, a host's request stays as it has
	// always been: this node's own sshd admits the host by it.
	t.Run("a host connection", func(t *testing.T) {
		for _, kind := range allListenerKinds {
			a := proxyAuth{NodeAddr: "n1:22", listener: kind, SessionManager: sm, Logger: logger}
			auth, _, hop, err := a.authenticate(originConn("session", upterm.HostSSHClientVersion, "sid"), key.PublicKey())
			require.NoError(t, err)
			require.False(t, hop)
			want := &AuthRequest{
				ClientVersion: upterm.HostSSHClientVersion,
				RemoteAddr:    "203.0.113.7:51234",
				LocalAddr:     "198.51.100.1:22",
				AuthorizedKey: ssh.MarshalAuthorizedKey(key.PublicKey()),
			}
			require.True(t, proto.Equal(want, auth), "listener %d: %v", kind, auth)
		}
	})
}

// A hop's request is the guest's own, as the node it entered by recorded it.
// The node it reaches, whatever listener that is on, passes it on unchanged,
// and mints its certificates onward under its own connection's ID.
func TestHopPreservesOrigin(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	authority, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	guest := certTestSigner(t)
	sm := newSessionManagerWithStore(newMemorySessionStore(logger), routing.NewEncodeDecoder(routing.ModeConsul))

	for name, carried := range map[string]*AuthRequest{
		"a known entry": {
			ClientVersion: "SSH-2.0-OpenSSH_9.0", RemoteAddr: "203.0.113.7:4711", LocalAddr: "10.0.0.1:2223",
			AuthorizedKey: ssh.MarshalAuthorizedKey(guest.PublicKey()),
			Ingress:       Ingress_INGRESS_WEBSOCKET, IngressNode: "n1", IngressConnection: []byte("sid-1"),
		},
		// From a relay that predates the origin fields: the node it reaches
		// doesn't fill them in.
		"an older relay's": {
			ClientVersion: "SSH-2.0-OpenSSH_9.0", RemoteAddr: "203.0.113.7:4711", LocalAddr: "10.0.0.1:2223",
			AuthorizedKey: ssh.MarshalAuthorizedKey(guest.PublicKey()),
		},
	} {
		t.Run(name, func(t *testing.T) {
			hopCert, err := (&UserCertSigner{SessionID: "sid-1", User: "session", AuthRequest: carried}).SignCert(authority)
			require.NoError(t, err)
			for _, kind := range allListenerKinds {
				a := proxyAuth{NodeAddr: "n2", listener: kind, Signers: []ssh.Signer{authority}, SessionManager: sm, Logger: logger}
				conn := originConn("session", "SSH-2.0-Go", "sid-2")
				auth, key, hop, err := a.authenticate(conn, hopCert.PublicKey())
				require.NoError(t, err)
				require.True(t, hop)
				require.Equal(t, ssh.MarshalAuthorizedKey(guest.PublicKey()), ssh.MarshalAuthorizedKey(key))
				require.Equal(t, carried.GetIngress(), auth.GetIngress(), "listener %d", kind)
				require.Equal(t, carried.GetIngressNode(), auth.GetIngressNode(), "listener %d", kind)
				require.Equal(t, carried.GetIngressConnection(), auth.GetIngressConnection(), "listener %d", kind)
				require.True(t, proto.Equal(carried, auth), "listener %d: %v", kind, auth)

				signers, err := a.newUserCertSigners(conn, auth)
				require.NoError(t, err)
				onward := signers[0].PublicKey().(*ssh.Certificate)
				require.Equal(t, "sid-2", onward.KeyId, "minted under this connection's ID")
				var minted AuthRequest
				require.NoError(t, proto.Unmarshal([]byte(onward.Extensions[upterm.SSHCertExtension]), &minted))
				require.True(t, proto.Equal(carried, &minted), "listener %d: %v", kind, &minted)
			}
		})
	}
}

// originNode is a relay node at nodeAddr, serving one SSH listener of kind on
// loopback TCP, whose upstream connections go where dialer sends them.
func originNode(t *testing.T, kind listenerKind, nodeAddr string, dialer connDialer) (*sshProxy, string) {
	t.Helper()
	proxy, addr, _, _ := stockTestProxy(t, 4*time.Second, dialer, func(p *sshProxy) {
		p.listener = kind
		p.NodeAddr = nodeAddr
	})
	return proxy, addr
}

// holdSession registers a session on proxy's node that admits only guest, and
// whose host presents the relay's key, as stockTestUpstream does. It returns
// the user a guest joins it as.
func holdSession(t *testing.T, proxy *sshProxy, guest ssh.PublicKey) string {
	t.Helper()
	relay, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	user, err := proxy.SessionManager.CreateSession(NewSession("session", proxy.NodeAddr, "host",
		[][]byte{ssh.MarshalAuthorizedKey(relay.PublicKey())}, [][]byte{ssh.MarshalAuthorizedKey(guest)}))
	require.NoError(t, err)
	return user
}

// arrived waits for the upstream to authenticate a connection, and returns it,
// the certificate it presented and the AuthRequest that certificate carried.
func arrived(t *testing.T, peers <-chan *ssh.ServerConn) (*ssh.ServerConn, *ssh.Certificate, *AuthRequest) {
	t.Helper()
	var peer *ssh.ServerConn
	select {
	case peer = <-peers:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not authenticate")
	}
	pk, err := ssh.ParsePublicKey([]byte(peer.Permissions.Extensions["cert"]))
	require.NoError(t, err)
	cert, ok := pk.(*ssh.Certificate)
	require.True(t, ok)
	var auth AuthRequest
	require.NoError(t, proto.Unmarshal([]byte(cert.Extensions[upterm.SSHCertExtension]), &auth))
	return peer, cert, &auth
}

// End to end, through real proxies on loopback TCP, each a node. The node
// holding the session admits only the guest's key, so a node that took a hop
// for the key it presents, the relay's own, would refuse it; and the upstream,
// which stands where the session's host reads the request, must see the
// guest's key. A WebSocket bridge hands its guest's SSH on as it is, so a guest
// dialling the listener itself looks to it as a bridged one does, whether this
// node's bridge carried it over loopback or a neighbour's.
func TestOriginAcrossHops(t *testing.T) {
	type nodes struct {
		entry string // where the guest dials
		user  string
	}
	for _, tc := range []struct {
		name string
		// build starts the nodes, the last sending its upstream to upstream.
		build   func(t *testing.T, upstream string, guest ssh.PublicKey) nodes
		ingress Ingress
		node    string
		// hop says the guest reaches the upstream through a second node, which
		// mints the certificate the upstream sees under its own connection's
		// ID.
		hop bool
	}{
		// With internal listeners.
		{
			name: "an SSH guest on the public listener",
			build: func(t *testing.T, upstream string, guest ssh.PublicKey) nodes {
				n1, addr := originNode(t, listenerPublic, "n1:22", &stockTestDialer{addr: upstream})
				return nodes{addr, holdSession(t, n1, guest)}
			},
			ingress: Ingress_INGRESS_SSH, node: "n1:22",
		},
		{
			name: "a guest this node's WebSocket bridges",
			build: func(t *testing.T, upstream string, guest ssh.PublicKey) nodes {
				n1, addr := originNode(t, listenerBridge, "n1:22", &stockTestDialer{addr: upstream})
				return nodes{addr, holdSession(t, n1, guest)}
			},
			ingress: Ingress_INGRESS_WEBSOCKET, node: "n1:22",
		},
		{
			name: "an SSH guest carried from the public listener to another node's internal one",
			build: func(t *testing.T, upstream string, guest ssh.PublicKey) nodes {
				n2, n2Addr := originNode(t, listenerInternal, "n2:22", &stockTestDialer{addr: upstream})
				user := holdSession(t, n2, guest)
				_, n1Addr := originNode(t, listenerPublic, "n1:22", &routeDialer{routes: map[string]func(ctx context.Context) (net.Conn, error){
					"n2:22": dialTo(n2Addr),
				}})
				return nodes{n1Addr, user}
			},
			// n1's, not n2's.
			ingress: Ingress_INGRESS_SSH, node: "n1:22", hop: true,
		},
		{
			name: "a raw guest on the internal listener",
			build: func(t *testing.T, upstream string, guest ssh.PublicKey) nodes {
				n2, addr := originNode(t, listenerInternal, "n2:22", &stockTestDialer{addr: upstream})
				return nodes{addr, holdSession(t, n2, guest)}
			},
			ingress: Ingress_INGRESS_UNSPECIFIED, node: "",
		},
		// Without internal listeners, the default.
		{
			name: "an SSH guest on the shared listener",
			build: func(t *testing.T, upstream string, guest ssh.PublicKey) nodes {
				n1, addr := originNode(t, listenerShared, "n1:22", &stockTestDialer{addr: upstream})
				return nodes{addr, holdSession(t, n1, guest)}
			},
			ingress: Ingress_INGRESS_UNSPECIFIED, node: "",
		},
		{
			name: "a guest this node's WebSocket bridges over loopback to the shared listener",
			build: func(t *testing.T, upstream string, guest ssh.PublicKey) nodes {
				n1, addr := originNode(t, listenerShared, "n1:22", &stockTestDialer{addr: upstream})
				return nodes{addr, holdSession(t, n1, guest)}
			},
			// Not (SSH, n1).
			ingress: Ingress_INGRESS_UNSPECIFIED, node: "",
		},
		{
			name: "a guest a neighbour's WebSocket bridges to the shared listener",
			build: func(t *testing.T, upstream string, guest ssh.PublicKey) nodes {
				n2, addr := originNode(t, listenerShared, "n2:22", &stockTestDialer{addr: upstream})
				return nodes{addr, holdSession(t, n2, guest)}
			},
			// Not (SSH, n2).
			ingress: Ingress_INGRESS_UNSPECIFIED, node: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guest := certTestSigner(t)
			upstream, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
			n := tc.build(t, upstream, guest.PublicKey())
			client, err := ssh.Dial("tcp", n.entry, &ssh.ClientConfig{User: n.user, Auth: []ssh.AuthMethod{ssh.PublicKeys(guest)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })

			peer, cert, auth := arrived(t, peers)
			require.Equal(t, string(ssh.MarshalAuthorizedKey(guest.PublicKey())), peer.Permissions.Extensions["key"],
				"the upstream saw the guest's key")
			require.Equal(t, tc.ingress, auth.GetIngress())
			require.Equal(t, tc.node, auth.GetIngressNode())
			require.Equal(t, client.SessionID(), auth.GetIngressConnection(), "the guest's own connection, at the node it dialled")
			if tc.hop {
				require.NotEqual(t, string(client.SessionID()), cert.KeyId, "the second node mints under its own connection's ID")
			} else {
				require.Equal(t, string(client.SessionID()), cert.KeyId)
			}
		})
	}
}
