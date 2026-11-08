package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/ws"
	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// denyAddrs is a SourceFilter denying the addresses it holds, and recording
// every address it is asked about.
type denyAddrs struct {
	deny []netip.Addr

	mu    sync.Mutex
	asked []netip.Addr
}

func newDenyAddrs(addrs ...string) *denyAddrs {
	f := &denyAddrs{}
	for _, a := range addrs {
		f.deny = append(f.deny, netip.MustParseAddr(a))
	}
	return f
}

func (f *denyAddrs) Denied(addr netip.Addr) bool {
	f.mu.Lock()
	f.asked = append(f.asked, addr)
	f.mu.Unlock()
	for _, d := range f.deny {
		if d == addr {
			return true
		}
	}
	return false
}

func (f *denyAddrs) askedAbout() []netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netip.Addr(nil), f.asked...)
}

// denyAll is a SourceFilter that denies every source.
type denyAll struct{}

func (denyAll) Denied(netip.Addr) bool { return true }

func prefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	p, err := parseDenySources(values)
	require.NoError(t, err)
	return p
}

// sendProxyHeader writes a PROXY v2 header naming source to raw.
func sendProxyHeader(t *testing.T, raw net.Conn, source string) {
	t.Helper()
	ap := netip.MustParseAddrPort(source)
	transport := proxyproto.TCPv4
	if ap.Addr().Is6() {
		transport = proxyproto.TCPv6
	}
	_, err := (&proxyproto.Header{Version: 2, Command: proxyproto.PROXY, TransportProtocol: transport,
		SourceAddr: net.TCPAddrFromAddrPort(ap), DestinationAddr: raw.RemoteAddr()}).WriteTo(raw)
	require.NoError(t, err)
}

// dialSSHListener dials addr and, if source isn't empty, sends a PROXY v2
// header naming it.
func dialSSHListener(t *testing.T, addr, source string) net.Conn {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	require.NoError(t, raw.SetDeadline(time.Now().Add(5*time.Second)))
	if source != "" {
		sendProxyHeader(t, raw, source)
	}
	return raw
}

// requireClosedSilently proves the server closed raw without writing a byte,
// rather than leaving it open.
func requireClosedSilently(t *testing.T, raw net.Conn) {
	t.Helper()
	var b [1]byte
	n, err := raw.Read(b[:])
	require.Zero(t, n, "a denied source received an SSH banner")
	require.ErrorIs(t, err, io.EOF)
}

// requireBanner proves the server sent raw an SSH banner.
func requireBanner(t *testing.T, raw net.Conn) {
	t.Helper()
	b := make([]byte, len("SSH-2.0-"))
	_, err := io.ReadFull(raw, b)
	require.NoError(t, err)
	require.Equal(t, "SSH-2.0-", string(b))
}

// hopTo dials addr as another relay node hops a guest holding key: with a
// certificate this relay's authority minted, as user, recording that the
// guest came from remoteAddr.
func hopTo(addr, user, remoteAddr string, key ssh.PublicKey) (*ssh.Client, error) {
	authority, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	if err != nil {
		return nil, err
	}
	cert, err := (&UserCertSigner{SessionID: "entry", User: user, AuthRequest: &AuthRequest{
		ClientVersion: "SSH-2.0-OpenSSH_9.9", RemoteAddr: remoteAddr, LocalAddr: "192.0.2.200:22",
		AuthorizedKey: ssh.MarshalAuthorizedKey(key), Ingress: Ingress_INGRESS_SSH, IngressNode: "n0:22",
	}}).SignCert(authority)
	if err != nil {
		return nil, err
	}
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(cert)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
}

// registerAt has a host whose certificate records remoteAddr ask the sshd
// reached over network to create a session, and returns its answer.
func registerAt(t *testing.T, network *MemoryProvider, remoteAddr string) (bool, []byte) {
	t.Helper()
	return registerFrom(t, network, remoteAddr, Ingress_INGRESS_UNSPECIFIED, "")
}

// registerFrom is registerAt for a host whose certificate also records that
// it entered by ingress at the node at node.
func registerFrom(t *testing.T, network *MemoryProvider, remoteAddr string, ingress Ingress, node string) (bool, []byte) {
	t.Helper()
	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	cert, err := (&UserCertSigner{SessionID: "host-conn", User: "owen", AuthRequest: &AuthRequest{
		ClientVersion: upterm.HostSSHClientVersion, RemoteAddr: remoteAddr, LocalAddr: "192.0.2.200:22",
		AuthorizedKey: []byte(TestPublicKeyContent), Ingress: ingress, IngressNode: node,
	}}).SignCert(signer)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := network.SSHD().DialContext(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	conn, chans, reqs, err := ssh.NewClientConn(raw, "sshd", &ssh.ClientConfig{User: "owen", ClientVersion: upterm.HostSSHClientVersion,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(cert)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	require.NoError(t, err)
	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	request, err := proto.Marshal(&CreateSessionRequest{HostUser: "owen", HostPublicKeys: [][]byte{[]byte(TestPublicKeyContent)}})
	require.NoError(t, err)
	ok, body, err := client.SendRequest(upterm.ServerCreateSessionRequestType, true, request)
	require.NoError(t, err)
	return ok, body
}

func TestDenySourceAtEveryEntry(t *testing.T) {
	guest := certTestSigner(t)

	t.Run("public entries", func(t *testing.T) {
		filter := newDenyAddrs("198.51.100.7")
		sshln, internal := listenLoopback(t), listenLoopback(t)
		ts := serveListeners(t, Listeners{SSH: RequireProxyV2(sshln), WS: listenLoopback(t), Internal: internal}, func(s *Server) {
			s.DenySources = prefixes(t, "203.0.113.0/24")
			s.Extensions.Sources = filter
		})
		requireSSHDServing(t, ts.network)

		// (a) The SSH listener, by the PROXY header's source.
		t.Run("ssh, a denied source", func(t *testing.T) {
			requireClosedSilently(t, dialSSHListener(t, sshln.Addr().String(), "203.0.113.9:4711"))
		})
		t.Run("ssh, a source the filter denies", func(t *testing.T) {
			requireClosedSilently(t, dialSSHListener(t, sshln.Addr().String(), "198.51.100.7:4711"))
			require.Contains(t, filter.askedAbout(), netip.MustParseAddr("198.51.100.7"))
		})
		t.Run("ssh, an allowed source", func(t *testing.T) {
			requireBanner(t, dialSSHListener(t, sshln.Addr().String(), "192.0.2.1:4711"))
		})

		// (c) Host registration, by the source the host's certificate records.
		t.Run("a host whose certified source is denied", func(t *testing.T) {
			for _, source := range []string{"203.0.113.9:4711", "198.51.100.7:4711", "[::ffff:203.0.113.9]:4711"} {
				ok, body := registerAt(t, ts.network, source)
				require.False(t, ok, source)
				require.Empty(t, body, source)
			}
			sessions, err := ts.SessionManager.GetStore().List()
			require.NoError(t, err)
			require.Empty(t, sessions, "a denied host's route was stored")

			ok, body := registerAt(t, ts.network, "192.0.2.1:4711")
			require.True(t, ok, "%s", body)
			sessions, err = ts.SessionManager.GetStore().List()
			require.NoError(t, err)
			require.Len(t, sessions, 1)
		})

		// (d) A hop, by the source its certificate records, whatever node
		// sends it.
		t.Run("a hop whose certified source is denied", func(t *testing.T) {
			upstream, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
			user := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode("session", upstream)
			for _, source := range []string{"203.0.113.9:4711", "198.51.100.7:4711"} {
				_, err := hopTo(internal.Addr().String(), user, source, guest.PublicKey())
				require.ErrorContains(t, err, "unable to authenticate", source)
			}
			client, err := hopTo(internal.Addr().String(), user, "192.0.2.1:4711", guest.PublicKey())
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })
			_, _, auth := arrived(t, peers)
			require.Equal(t, "192.0.2.1:4711", auth.GetRemoteAddr())
		})
	})

	t.Run("loopback denied", func(t *testing.T) {
		sshln, wsln, internal := listenLoopback(t), listenLoopback(t), listenLoopback(t)
		ts := serveListeners(t, Listeners{SSH: sshln, WS: wsln, Internal: internal}, func(s *Server) {
			s.DenySources = prefixes(t, "127.0.0.0/8")
		})
		requireSSHDServing(t, ts.network)

		// (b) The WebSocket upgrade.
		t.Run("a websocket upgrade", func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://"+wsln.Addr().String()+"/", nil)
			require.NoError(t, err)
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			req.Header.Set(upterm.HeaderUptermClientVersion, "0.0.0")
			req.SetBasicAuth("session", "")
			resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, http.StatusForbidden, resp.StatusCode)
			require.Len(t, body, 0)
		})

		// The SSH listener's own peer is checked.
		t.Run("ssh", func(t *testing.T) {
			requireClosedSilently(t, dialSSHListener(t, sshln.Addr().String(), ""))
		})

		// The internal listener's peer is another node, and is never checked:
		// only the source the hop's certificate records is.
		t.Run("a hop from a node at a denied address", func(t *testing.T) {
			upstream, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
			user := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode("session", upstream)
			client, err := hopTo(internal.Addr().String(), user, "192.0.2.1:4711", guest.PublicKey())
			require.NoError(t, err, "the internal listener refused a node at a denied address")
			t.Cleanup(func() { _ = client.Close() })
			_, _, auth := arrived(t, peers)
			require.Equal(t, "192.0.2.1:4711", auth.GetRemoteAddr())
		})
	})

	// Only the listeners direct clients reach check a guest's peer. The
	// internal listener's peer is a node, and the bridge's is this node, so a
	// guest there, handed over by a WebSocket listener that checked its
	// client already, isn't checked again by the address it arrives from.
	t.Run("the listeners that check a guest's peer", func(t *testing.T) {
		for _, tc := range []struct {
			kind   listenerKind
			checks bool
		}{
			{listenerShared, true},
			{listenerPublic, true},
			{listenerInternal, false},
			{listenerBridge, false},
		} {
			for _, deny := range []string{"127.0.0.0/8", "203.0.113.0/24"} {
				upstream, _ := stockTestUpstream(t, false, TestPrivateKeyContent)
				proxy, addr, _, _ := stockTestProxy(t, 4*time.Second, &stockTestDialer{addr: upstream}, func(p *sshProxy) {
					p.listener = tc.kind
					p.NodeAddr = "n1:22"
					p.deny = sourceDeny{prefixes: prefixes(t, deny)}
				})
				user := holdSession(t, proxy, guest.PublicKey())
				raw := dialSSHListener(t, addr, "")
				if deny == "127.0.0.0/8" && tc.checks {
					requireClosedSilently(t, raw)
					continue
				}
				requireBanner(t, raw)
				_ = raw.Close()
				client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(guest)},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
				require.NoError(t, err, "listener %d, deny %s", tc.kind, deny)
				_ = client.Close()
			}
		}
	})

	// A WebSocket guest is judged by its client's address at the upgrade,
	// not by the loopback address its bridge hands it over from.
	t.Run("a websocket guest from an allowed address", func(t *testing.T) {
		wsln, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skip("no ::1 on this host, so no WebSocket client outside 127.0.0.0/8")
		}
		upstream, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
		serveListeners(t, Listeners{SSH: listenLoopback(t), WS: wsln, Internal: listenLoopback(t)}, func(s *Server) {
			s.DenySources = prefixes(t, "127.0.0.0/8")
		})
		user := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode("session", upstream)
		u := &url.URL{Scheme: "ws", Host: wsln.Addr().String(),
			User: url.UserPassword("session", base64.URLEncoding.EncodeToString([]byte(upstream)))}
		client, err := ws.NewSSHClient(u, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(guest)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second}, true, nil)
		require.NoError(t, err, "a bridged guest was refused by the bridge's address")
		t.Cleanup(func() { _ = client.Close() })
		arrived(t, peers)
	})
}

// On the internal listener, a guest a neighbour's WebSocket listener hands
// over raw isn't judged by that neighbour's address, while a hop is judged by
// the source its certificate records, whichever node sends it.
func TestDenySourceOnTheInternalListener(t *testing.T) {
	guest := certTestSigner(t)
	internal := listenLoopback(t)
	ts := serveListeners(t, Listeners{SSH: listenLoopback(t), Internal: internal}, func(s *Server) {
		s.DenySources = prefixes(t, "127.0.0.0/8")
	})
	requireSSHDServing(t, ts.network)
	upstream, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
	user := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode("session", upstream)

	t.Run("a raw guest from a denied neighbour", func(t *testing.T) {
		client, err := ssh.Dial("tcp", internal.Addr().String(), &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(guest)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
		require.NoError(t, err, "a raw guest was refused by its neighbour's address")
		t.Cleanup(func() { _ = client.Close() })
		_, _, auth := arrived(t, peers)
		require.Equal(t, client.LocalAddr().String(), auth.GetRemoteAddr())
	})

	t.Run("a hop whose certified source is denied", func(t *testing.T) {
		_, err := hopTo(internal.Addr().String(), user, "127.0.0.5:4711", guest.PublicKey())
		require.ErrorContains(t, err, "unable to authenticate")
	})
}

// wsHost connects to the WebSocket listener at addr as a host does, and asks
// to create a session.
func wsHost(t *testing.T, addr string) (bool, []byte, error) {
	t.Helper()
	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	raw, err := ws.NewWSConn(&url.URL{Scheme: "ws", Host: addr, User: url.UserPassword("owen", "")}, true, nil)
	if err != nil {
		return false, nil, err
	}
	t.Cleanup(func() { _ = raw.Close() })
	conn, chans, reqs, err := ssh.NewClientConn(raw, addr, &ssh.ClientConfig{User: "owen", ClientVersion: upterm.HostSSHClientVersion,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	require.NoError(t, err)
	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	request, err := proto.Marshal(&CreateSessionRequest{HostUser: "owen", HostPublicKeys: [][]byte{[]byte(TestPublicKeyContent)}})
	require.NoError(t, err)
	ok, body, err := client.SendRequest(upterm.ServerCreateSessionRequestType, true, request)
	require.NoError(t, err)
	return ok, body, nil
}

// A host this node's WebSocket bridge carried is judged by its client's
// address at the upgrade, not by the bridge's loopback address its
// certificate records. Any other host is judged at registration by the source
// its certificate records.
func TestDenySourceAtHostRegistration(t *testing.T) {
	t.Run("a websocket host from an allowed address", func(t *testing.T) {
		wsln, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skip("no ::1 on this host, so no WebSocket client outside 127.0.0.0/8")
		}
		ts := serveListeners(t, Listeners{SSH: listenLoopback(t), WS: wsln, Internal: listenLoopback(t)}, func(s *Server) {
			s.DenySources = prefixes(t, "127.0.0.0/8")
		})
		ok, body, err := wsHost(t, wsln.Addr().String())
		require.NoError(t, err)
		require.True(t, ok, "a bridged host was refused by the bridge's address: %s", body)
		sessions, err := ts.SessionManager.GetStore().List()
		require.NoError(t, err)
		require.Len(t, sessions, 1)
	})

	sshln, wsln, internal := listenLoopback(t), listenLoopback(t), listenLoopback(t)
	ts := serveListeners(t, Listeners{SSH: sshln, WS: wsln, Internal: internal}, func(s *Server) {
		s.DenySources = prefixes(t, "127.0.0.0/8")
	})
	requireSSHDServing(t, ts.network)

	t.Run("a websocket host from a denied address", func(t *testing.T) {
		_, _, err := wsHost(t, wsln.Addr().String())
		require.ErrorContains(t, err, "bad handshake", "the upgrade let a denied host through")
	})

	t.Run("a host whose certified source is denied", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			ingress Ingress
			node    string
		}{
			{"over the SSH listener", Ingress_INGRESS_SSH, ts.NodeAddr},
			{"with no recorded entry", Ingress_INGRESS_UNSPECIFIED, ""},
			{"over another node's WebSocket listener", Ingress_INGRESS_WEBSOCKET, "n9:2223"},
		} {
			ok, body := registerFrom(t, ts.network, "127.0.0.9:4711", tc.ingress, tc.node)
			require.False(t, ok, tc.name)
			require.Empty(t, body, tc.name)
		}
		sessions, err := ts.SessionManager.GetStore().List()
		require.NoError(t, err)
		require.Empty(t, sessions, "a denied host's route was stored")

		// Carried by this node's own bridge.
		ok, body := registerFrom(t, ts.network, "127.0.0.9:4711", Ingress_INGRESS_WEBSOCKET, ts.NodeAddr)
		require.True(t, ok, "%s", body)
	})
}

func TestDenySourceUnmapsIPv4MappedAddresses(t *testing.T) {
	require.True(t, sourceDenied(prefixes(t, "203.0.113.0/24"), nil, "[::ffff:203.0.113.9]:5"))
	require.True(t, sourceDenied(prefixes(t, "203.0.113.9"), nil, "[::ffff:203.0.113.9]:5"))
	require.True(t, sourceDenied(prefixes(t, "::ffff:203.0.113.9"), nil, "203.0.113.9:5"))
	require.False(t, sourceDenied(prefixes(t, "203.0.113.0/24"), nil, "[::ffff:203.0.114.9]:5"))
	// A CIDR written in the mapped form denies the IPv4 sources it maps.
	require.True(t, sourceDenied(prefixes(t, "::ffff:203.0.113.0/120"), nil, "203.0.113.9:5"))
	require.True(t, sourceDenied(prefixes(t, "::ffff:203.0.113.0/120"), nil, "[::ffff:203.0.113.9]:5"))
	require.True(t, sourceDenied(prefixes(t, "::ffff:203.0.113.9/128"), nil, "203.0.113.9:5"))
	require.False(t, sourceDenied(prefixes(t, "::ffff:203.0.113.0/120"), nil, "203.0.114.9:5"))

	filter := newDenyAddrs("203.0.113.9")
	require.True(t, sourceDenied(nil, filter, "[::ffff:203.0.113.9]:5"))
	require.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.9")}, filter.askedAbout())
	require.True(t, filter.askedAbout()[0].Is4())
}

func TestUnparseableSourceIsNotDenied(t *testing.T) {
	everything := prefixes(t, "0.0.0.0/0", "::/0")
	for _, addr := range []string{"not-an-address", "", "203.0.113.9", "host.example:22", "[::1]"} {
		require.False(t, sourceDenied(everything, denyAll{}, addr), addr)
	}
	require.True(t, sourceDenied(everything, nil, "203.0.113.9:22"))
	require.True(t, sourceDenied(nil, denyAll{}, "203.0.113.9:22"))
	// A link-local peer's address carries its zone.
	require.True(t, sourceDenied(prefixes(t, "fe80::/10"), nil, "[fe80::1%en0]:22"))
	require.False(t, sourceDenied(nil, nil, "203.0.113.9:22"))
}

func TestParseDenySources(t *testing.T) {
	got, err := parseDenySources([]string{
		"203.0.113.9", "203.0.113.77/24", "2001:db8::1", "2001:db8::/32", "::ffff:198.51.100.7",
		"::ffff:198.51.100.77/120", "::ffff:192.0.2.1/128", "::ffff:0:0/96", "::/80",
	})
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("203.0.113.9/32"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::1/128"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("198.51.100.7/32"),
		// A prefix inside the IPv4-mapped range is the IPv4 prefix it maps;
		// a wider IPv6 prefix stays IPv6.
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("192.0.2.1/32"),
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/80"),
	}, got)
	for _, bad := range []string{"300.1.1.1", "", "203.0.113.0/33", "fe80::1%en0", "host.example", "203.0.113.9:22"} {
		_, err := parseDenySources([]string{"192.0.2.1", bad})
		require.EqualError(t, err, `--deny-source "`+bad+`": not an IP address or CIDR`)
	}
	got, err = parseDenySources(nil)
	require.NoError(t, err)
	require.Empty(t, got)
}

// startForSources starts a server as uptermd does, with opt's SSH listener on
// loopback, and returns that listener's address and what the server logs.
func startForSources(t *testing.T, opt Opt) (string, *syncBuffer) {
	t.Helper()
	t.Setenv("PRIVATE_KEY", "")
	keyPath := filepath.Join(t.TempDir(), "host_key")
	require.NoError(t, os.WriteFile(keyPath, []byte(TestPrivateKeyContent), 0o600))
	opt.SSHAddr, opt.PrivateKeys, opt.Network, opt.HandshakeTimeout = "127.0.0.1:0", []string{keyPath}, "mem", 4*time.Second
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Start(ctx, opt, logger) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	record := awaitLogRecord(t, logs, func(r map[string]any) bool { return r["msg"] == "starting server" })
	return record["ssh_addr"].(string), logs
}

// awaitLogRecord waits for logs to hold a record match accepts, and returns it.
func awaitLogRecord(t *testing.T, logs *syncBuffer, match func(map[string]any) bool) map[string]any {
	t.Helper()
	var found map[string]any
	require.Eventually(t, func() bool {
		for _, line := range strings.Split(logs.String(), "\n") {
			var record map[string]any
			if json.Unmarshal([]byte(line), &record) == nil && match(record) {
				found = record
				return true
			}
		}
		return false
	}, 5*time.Second, time.Millisecond)
	return found
}

// refusedFrom matches the log record of a connection refused for its source,
// which names the address the relay records for it.
func refusedFrom(ip string) func(map[string]any) bool {
	return func(r map[string]any) bool {
		addr, _ := r["addr"].(map[string]any)
		return r["msg"] == "SSH connection ended" && r["error"] == errSourceDenied.Error() && addr != nil && addr["IP"] == ip
	}
}

func TestDenySourceChecksTheAddressTheRelayRecords(t *testing.T) {
	t.Run("without PROXY, the TCP peer", func(t *testing.T) {
		addr, logs := startForSources(t, Opt{DenySources: []string{"127.0.0.1"}})
		requireClosedSilently(t, dialSSHListener(t, addr, ""))
		awaitLogRecord(t, logs, refusedFrom("127.0.0.1"))
	})

	t.Run("without PROXY, a header is not read", func(t *testing.T) {
		addr, _ := startForSources(t, Opt{DenySources: []string{"203.0.113.0/24"}})
		requireBanner(t, dialSSHListener(t, addr, "203.0.113.9:4711"))
	})

	t.Run("with optional PROXY, the header's source", func(t *testing.T) {
		addr, logs := startForSources(t, Opt{SSHProxyProtocol: true, DenySources: []string{"203.0.113.0/24", "127.0.0.1"}})
		requireClosedSilently(t, dialSSHListener(t, addr, "203.0.113.9:4711"))
		awaitLogRecord(t, logs, refusedFrom("203.0.113.9"))
		// The peer is denied too, but it isn't the source the header names.
		requireBanner(t, dialSSHListener(t, addr, "192.0.2.1:4711"))
		// Without a header, the source is the peer.
		requireClosedSilently(t, dialSSHListener(t, addr, ""))
	})
}
