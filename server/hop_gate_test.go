package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/internal/version"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// fixtureBootID is a home's boot ID, a canonical version 4 UUID.
const fixtureBootID = "55555555-5555-4555-8555-555555555555"

// gatingIngress makes a proxy one that starts gate hops: it refuses legacy
// hops, so it gates every hop it starts, and holds no registration itself.
func gatingIngress(p *sshProxy) {
	p.authorities = &gateFixtureRegistry{}
	p.RefuseLegacyHops = true
}

// A contract peer speaks SSH over a real socket. Its application counter is
// downstream-visible work: no broken mode exchange may reach this handler.
func TestHopModeBrokenAdvertisedExchange(t *testing.T) {
	for _, fault := range []string{"missing", "no_response", "malformed", "unknown_mode", "wrong_route", "wrong_nonce", "wrong_protocol", "duplicate_scalar", "unknown_field", "oversized"} {
		t.Run(fault, func(t *testing.T) {
			key, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
			require.NoError(t, err)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer func() { _ = ln.Close() }()
			var application atomic.Int32
			done := make(chan struct{})
			go func() {
				defer close(done)
				raw, err := ln.Accept()
				if err != nil {
					return
				}
				defer func() { _ = raw.Close() }()
				cfg := &ssh.ServerConfig{ServerVersion: "SSH-2.0-uptermd gate-v1", PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
				cfg.AddHostKey(key)
				conn, channels, requests, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				go func() {
					for ch := range channels {
						application.Add(1)
						_ = ch.Reject(ssh.Prohibited, "denied")
					}
				}()
				for req := range requests {
					if req.Type == "gate-mode@upterm.dev" {
						switch fault {
						case "no_response":
							continue
						case "missing":
							_ = req.Reply(false, nil)
						case "malformed":
							_ = req.Reply(true, []byte{0xff})
						default:
							var request GateModeRequest
							if proto.Unmarshal(req.Payload, &request) != nil {
								return
							}
							reply := &GateModeReply{Protocol: 1, Nonce: request.Nonce, Registration: &GateRegistration{Mode: GateMode_GATE_MODE_LOCAL, SessionId: "session", RoutingId: "session", RunPublicKeys: [][]byte{key.PublicKey().Marshal()}, RegistrationId: []byte("host-original"), HomeNode: "127.0.0.1:3333"}}
							switch fault {
							case "unknown_mode":
								reply.Registration.Mode = 99
							case "wrong_route":
								reply.Registration.RoutingId = "other"
								reply.Registration.SessionId = "other"
							case "wrong_nonce":
								reply.Nonce = bytes.Repeat([]byte{7}, 32)
							case "wrong_protocol":
								reply.Protocol = 2
							}
							body, _ := proto.Marshal(reply)
							switch fault {
							case "duplicate_scalar":
								body = append(body, 8, 1)
							case "unknown_field":
								body = append(body, 32, 1)
							case "oversized":
								body = make([]byte, 65537)
							}
							_ = req.Reply(true, body)
						}
					} else {
						application.Add(1)
						_ = req.Reply(true, nil)
					}
				}
			}()
			dialer := &stockTestDialer{addr: ln.Addr().String()}
			_, addr, _, signer := stockTestProxy(t, 2*time.Second, dialer, gatingIngress)
			user := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode("session", "127.0.0.1:3333")
			c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(key.PublicKey()), Timeout: time.Second})
			require.NoError(t, err)
			defer func() { _ = c.Close() }()
			ok, _, err := c.SendRequest("application-probe", true, nil)
			require.False(t, ok, "broken gate must refuse application work; error=%v", err)
			require.Zero(t, application.Load(), "host received application traffic before a valid mode answer")
			_ = c.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("contract home did not close")
			}
		})
	}
}

func TestHopModeWireValidation(t *testing.T) {
	for _, body := range [][]byte{
		{8, 1, 8, 1},        // duplicated protocol
		{8, 1, 32, 1},       // unknown field
		{8, 1, 18, 1, 0xff}, // invalid nonce
		make([]byte, 65537),
	} {
		var request GateModeRequest
		require.Error(t, decodeGate(body, &request))
	}
}

// gateFixtureRegistry holds at most one home, and the session adopted with
// it. lookups counts the lookups the gate makes, so a test can tell that no
// gate request was answered.
type gateFixtureRegistry struct {
	current atomic.Pointer[localHome]
	session *Session
	lookups atomic.Int32
}

func (r *gateFixtureRegistry) Lookup(id string) (Home, bool) {
	r.lookups.Add(1)
	return r.find(id)
}

func (r *gateFixtureRegistry) find(id string) (Home, bool) {
	h := r.current.Load()
	if h == nil || !h.Held() || h.Ref().RoutingID != id {
		return nil, false
	}
	return h, true
}

func (r *gateFixtureRegistry) localSession(h Home) (*Session, bool) {
	current, ok := r.find(h.Ref().RoutingID)
	return r.session, ok && current == h
}

type hopGateFixture struct {
	proxy                    *sshProxy
	addr                     string
	route                    string
	signer, guest, authority ssh.Signer
	registry                 *gateFixtureRegistry
	home                     *localHome
	dialer                   *stockTestDialer
	peers                    <-chan *ssh.ServerConn
	auth                     *AuthRequest
}

// newHopGateFixture is a home node's internal listener holding the local
// registration "route". It gates: it refuses legacy hops. Its host echoes.
func newHopGateFixture(t *testing.T, options ...func(*sshProxy)) *hopGateFixture {
	t.Helper()
	return newHopGateFixtureFor(t, "route", options...)
}

// newHopGateFixtureFor is newHopGateFixture holding the registration route.
func newHopGateFixtureFor(t *testing.T, route string, options ...func(*sshProxy)) *hopGateFixture {
	t.Helper()
	host, peers := gateEchoHost(t)
	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	guest, authority := certTestSigner(t), certTestSigner(t)
	ref := RegistrationRef{Authority: AuthorityLocal, SessionID: route, Generation: 7, RoutingID: route, RunPublicKeys: [][]byte{signer.PublicKey().Marshal()}, RegistrationID: []byte("host-original-session"), HomeNode: "home:2222", HomeNodeID: "home-machine", HomeBootID: fixtureBootID}
	h := newLocalHome(ref)
	registry := &gateFixtureRegistry{}
	registry.current.Store(h)
	dialer := &stockTestDialer{addr: host}
	proxy, addr, _, _ := stockTestProxy(t, 2*time.Second, dialer, func(p *sshProxy) {
		p.NodeAddr = ref.HomeNode
		p.authorities = registry
		p.listener = listenerInternal
		p.RefuseLegacyHops = true
		p.HopTrusted = []ssh.PublicKey{authority.PublicKey()}
		p.RefuseHostKeyHops = true
		p.SessionManager = newSessionManagerWithStore(newMemorySessionStore(p.Logger), routing.NewEncodeDecoder(routing.ModeConsul))
		for _, option := range options {
			option(p)
		}
		session := &Session{ID: route, NodeAddr: ref.HomeNode, Generation: 7, HostPublicKeys: []ssh.PublicKey{signer.PublicKey()}, ClientAuthorizedKeys: []ssh.PublicKey{guest.PublicKey()}, AuthorityHint: AuthorityLocal}
		registry.session = session
		_, err := p.SessionManager.CreateSession(session)
		require.NoError(t, err)
	})
	return &hopGateFixture{proxy: proxy, addr: addr, route: route, signer: signer, guest: guest, authority: authority, registry: registry, home: h, dialer: dialer, peers: peers, auth: &AuthRequest{ClientVersion: "SSH-2.0-original-client", RemoteAddr: "203.0.113.7:1234", LocalAddr: "198.51.100.1:22", AuthorizedKey: ssh.MarshalAuthorizedKey(guest.PublicKey()), Ingress: Ingress_INGRESS_SSH, IngressNode: "ingress:2222", IngressConnection: []byte("original-guest-session"), TypedAddress: "typed-user", TargetRoutingId: route, IngressNodeId: "ingress-machine", ConnectionId: "60000000-0000-4000-8000-000000000006", GateProtocol: 1}}
}

func (f *hopGateFixture) connect(t *testing.T, auth *AuthRequest, authority ssh.Signer) (*upstreamConn, error) {
	t.Helper()
	cert, err := (&UserCertSigner{SessionID: "ingress-cert-id", User: f.route, AuthRequest: auth}).SignCert(authority)
	require.NoError(t, err)
	raw, err := net.DialTimeout("tcp", f.addr, time.Second)
	require.NoError(t, err)
	conn, channels, requests, err := ssh.NewClientConn(raw, f.addr, &ssh.ClientConfig{User: f.route, Auth: []ssh.AuthMethod{ssh.PublicKeys(cert)}, HostKeyCallback: ssh.FixedHostKey(f.signer.PublicKey())})
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	u := &upstreamConn{sshPeer: sshPeer{conn, channels, requests}, raw: raw, homeNode: "home:2222"}
	t.Cleanup(u.Close)
	require.True(t, hasGateCapability(conn.ServerVersion()))
	return u, nil
}

func TestHopModeEmbeddedHome(t *testing.T) {
	f := newHopGateFixture(t)
	// Authenticate against an embedded-mode parser: the certified routing ID
	// must not be interpreted as an ordinary encoded user.
	a := *f.proxy.routing.Auth
	a.SessionManager = newEmbeddedSessionManager(f.proxy.Logger)
	cert, err := (&UserCertSigner{SessionID: "hop", User: "route", AuthRequest: f.auth}).SignCert(f.authority)
	require.NoError(t, err)
	auth, key, hop, err := a.authenticate(originConn("route", "SSH-2.0-Go", "hop"), cert.PublicKey())
	require.NoError(t, err)
	require.True(t, hop)
	require.Equal(t, "typed-user", auth.TypedAddress)
	require.Equal(t, f.guest.PublicKey().Marshal(), key.Marshal())
}

// The responder waits behind an explicit barrier; the injected monotonic
// reading tests receipt at the boundary without relying on socket timing.
func TestHopModeReplyDeadline(t *testing.T) {
	for _, offset := range []time.Duration{5 * time.Second, 5*time.Second + time.Nanosecond} {
		t.Run(offset.String(), func(t *testing.T) {
			key := certTestSigner(t)
			received, replyNow := make(chan struct{}), make(chan struct{})
			u := gateContractPeer(t, key, func(r *ssh.Request) {
				var request GateModeRequest
				require.NoError(t, proto.Unmarshal(r.Payload, &request))
				close(received)
				<-replyNow
				reply := &GateModeReply{Protocol: 1, Nonce: request.Nonce, Registration: &GateRegistration{Mode: GateMode_GATE_MODE_LOCAL, SessionId: "route", RoutingId: "route", RunPublicKeys: [][]byte{key.PublicKey().Marshal()}, RegistrationId: []byte("host-original"), HomeNode: "home"}}
				body, _ := proto.Marshal(reply)
				_ = r.Reply(true, body)
			})
			start := time.Now()
			var elapsed atomic.Int64
			u.now = func() time.Time { return start.Add(time.Duration(elapsed.Load())) }
			result := make(chan error, 1)
			go func() { _, err := negotiateHome(t.Context(), u, freshModeRequest("route")); result <- err }()
			<-received
			elapsed.Store(int64(offset))
			close(replyNow)
			err := <-result
			if offset > 5*time.Second {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func gateContractPeer(t *testing.T, key ssh.Signer, handler func(*ssh.Request)) *upstreamConn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = raw.Close() }()
		cfg := &ssh.ServerConfig{ServerVersion: "SSH-2.0-home gate-v1", PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
		cfg.AddHostKey(key)
		c, ch, reqs, err := ssh.NewServerConn(raw, cfg)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		go func() {
			for channel := range ch {
				_ = channel.Reject(ssh.Prohibited, "no application")
			}
		}()
		for r := range reqs {
			handler(r)
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	conn, ch, reqs, err := ssh.NewClientConn(raw, ln.Addr().String(), &ssh.ClientConfig{User: "route", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.FixedHostKey(key.PublicKey())})
	require.NoError(t, err)
	u := &upstreamConn{sshPeer: sshPeer{conn, ch, reqs}, raw: raw}
	t.Cleanup(func() {
		u.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("contract peer stuck")
		}
	})
	return u
}

func TestHopModeControlCancellation(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		t.Run(fmt.Sprint(concurrent), func(t *testing.T) {
			received := make(chan struct{})
			release := make(chan struct{})
			u := gateContractPeer(t, certTestSigner(t), func(r *ssh.Request) { close(received); <-release })
			defer close(release)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := negotiateHome(ctx, u, freshModeRequest("route")); result <- err }()
			<-received
			if concurrent {
				_, err := negotiateHome(t.Context(), u, freshModeRequest("route"))
				require.Error(t, err)
			} else {
				cancel()
			}
			select {
			case err := <-result:
				require.Error(t, err)
			case <-time.After(time.Second):
				t.Fatal("cancellation failed to unblock control request")
			}
		})
	}
}

func TestLegacyModeMigration(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run("local"+fmt.Sprint(legacy), func(t *testing.T) {
			f := newHopGateFixture(t, func(p *sshProxy) { p.RefuseLegacyHops = !legacy })
			auth := proto.Clone(f.auth).(*AuthRequest)
			auth.GateProtocol = 0
			u, err := f.connect(t, auth, f.authority)
			if !legacy {
				require.Error(t, err)
				require.Zero(t, f.dialer.calls.Load())
				return
			}
			require.NoError(t, err)
			ok, _, err := u.conn.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, int32(1), f.dialer.calls.Load())
		})
	}
}

// The fixture gates, so every hop's AuthRequest is held to the strict scan.
func TestHopModeCertificateStrictFields(t *testing.T) {
	f := newHopGateFixture(t)
	signed, err := (&UserCertSigner{SessionID: "hop", User: "route", AuthRequest: f.auth}).SignCert(f.authority)
	require.NoError(t, err)
	_, _, hop, err := f.proxy.routing.Auth.authenticate(originConn("route", "SSH-2.0-Go", "hop"), signed.PublicKey())
	require.NoError(t, err, "the certificate as signed is a valid gate hop")
	require.True(t, hop)
	cert := signed.PublicKey().(*ssh.Certificate)
	// A last-zero protocol must not erase a duplicated scalar's evidence.
	cert.Extensions[upterm.SSHCertExtension] += string([]byte{96, 0})
	require.NoError(t, cert.SignCert(rand.Reader, f.authority))
	_, _, _, err = f.proxy.routing.Auth.authenticate(originConn("route", "SSH-2.0-Go", "hop"), cert)
	require.Error(t, err)
}

func TestHopModeUsesAdoptedKeys(t *testing.T) {
	f := newHopGateFixture(t)
	f.registry.session.ClientAuthorizedKeys = []ssh.PublicKey{certTestSigner(t).PublicKey()}
	store := f.proxy.SessionManager.GetStore().(*memorySessionStore)
	store.mutex.Lock()
	poisoned := *f.registry.session
	poisoned.ClientAuthorizedKeys = nil
	store.sessions["route"] = &poisoned
	store.mutex.Unlock()
	u, err := f.connect(t, f.auth, f.authority)
	require.NoError(t, err)
	_, err = negotiateHome(t.Context(), u, freshModeRequest("route"))
	if err == nil {
		ok, _, _ := u.conn.SendRequest("application", true, nil)
		require.False(t, ok)
	}
	require.Zero(t, f.dialer.calls.Load(), "cached keys replaced the locally adopted authorization")
}

func TestHopModeRejectsOverflowedEnum(t *testing.T) {
	f := newHopGateFixture(t)
	wire, err := proto.Marshal(gateRegistration(f.home.Ref()))
	require.NoError(t, err)
	// Enum 2^32+1 must not truncate to the valid local value 1.
	wire = append([]byte{8, 0x81, 0x80, 0x80, 0x80, 0x10}, wire[2:]...)
	var ref GateRegistration
	require.Error(t, decodeGate(wire, &ref))
}

func TestHopModeRefusesNonlocalTarget(t *testing.T) {
	f := newHopGateFixture(t)
	// The route cache still advertises the target, but this home no longer holds it.
	f.registry.current.Store(nil)
	u, err := f.connect(t, f.auth, f.authority)
	require.NoError(t, err)
	_, err = negotiateHome(t.Context(), u, freshModeRequest("route"))
	require.Error(t, err)
	require.Zero(t, f.dialer.calls.Load(), "a nonlocal mode request was forwarded transitively")
}

func TestHopModeLocalPathFence(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint(replace), func(t *testing.T) {
			f := newHopGateFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			dialer := &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){"home:2222": func(ctx context.Context) (net.Conn, error) {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", f.dialer.addr)
			}}}
			_, addr, _, _ := stockTestProxy(t, 2*time.Second, dialer, func(p *sshProxy) {
				p.NodeAddr = "home:2222"
				p.SessionManager = f.proxy.SessionManager
				p.authorities = f.registry
				p.listener = listenerPublic
				p.RefuseLegacyHops = true
			})
			c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "route", Auth: []ssh.AuthMethod{ssh.PublicKeys(f.guest)}, HostKeyCallback: ssh.FixedHostKey(f.signer.PublicKey())})
			require.NoError(t, err)
			defer func() { _ = c.Close() }()
			<-entered
			if replace {
				f.registry.current.Store(newLocalHome(f.home.Ref()))
			}
			close(release)
			ok, _, err := c.SendRequest("application", true, nil)
			require.Equal(t, !replace, ok, "local forwarding ignored the original handle's fence")
			if !replace {
				require.NoError(t, err)
			}
			select {
			case host := <-f.peers:
				certKey, err := ssh.ParsePublicKey([]byte(host.Permissions.Extensions["cert"]))
				require.NoError(t, err)
				require.Equal(t, string(c.SessionID()), certKey.(*ssh.Certificate).KeyId, "local path unexpectedly created a hop")
			case <-time.After(time.Second):
				t.Fatal("local handshake missing")
			}
			require.Equal(t, int32(1), dialer.calls.Load())
		})
	}
}

// gateEchoHost is a contract host with real live session traffic. Its
// certificate checker enforces the relay key and records the guest identity.
func gateEchoHost(t *testing.T) (string, <-chan *ssh.ServerConn) {
	t.Helper()
	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		auth, _, err := (&UserCertChecker{IsUserAuthority: func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), signer.PublicKey().Marshal()) }}).Authenticate(meta.User(), key)
		if err != nil {
			return nil, err
		}
		return &ssh.Permissions{Extensions: map[string]string{"key": string(auth.AuthorizedKey), "cert": string(key.Marshal())}}, nil
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	peers := make(chan *ssh.ServerConn, 8)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = raw.Close() }()
				conn, channels, requests, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				peers <- conn
				go func() {
					for r := range requests {
						_ = r.Reply(true, r.Payload)
					}
				}()
				for incoming := range channels {
					channel, requests, err := incoming.Accept()
					if err != nil {
						continue
					}
					go ssh.DiscardRequests(requests)
					go func() { defer func() { _ = channel.Close() }(); _, _ = io.Copy(channel, channel) }()
				}
			}()
		}
	}()
	return ln.Addr().String(), peers
}

func TestHopModeUpgradedEmbeddedPeers(t *testing.T) {
	home := newHopGateFixture(t, func(p *sshProxy) { p.SessionManager = newEmbeddedSessionManager(p.Logger) })
	_, entry, _, _ := stockTestProxy(t, 2*time.Second, &stockTestDialer{addr: home.addr}, func(p *sshProxy) {
		p.NodeAddr = "ingress:2222"
		p.authorities = &gateFixtureRegistry{}
		p.listener = listenerPublic
		p.RefuseLegacyHops = true
		p.HopSigners = []ssh.Signer{home.authority}
		p.NodeID = "ingress-machine"
	})
	typed := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode("route", "home:2222")
	guest, err := ssh.Dial("tcp", entry, &ssh.ClientConfig{User: typed, Auth: []ssh.AuthMethod{ssh.PublicKeys(home.guest)}, HostKeyCallback: ssh.FixedHostKey(home.signer.PublicKey())})
	require.NoError(t, err)
	defer func() { _ = guest.Close() }()
	channel, requests, err := guest.OpenChannel("session", nil)
	require.NoError(t, err)
	defer func() { _ = channel.Close() }()
	go ssh.DiscardRequests(requests)
	_, err = channel.Write([]byte("embedded guest"))
	require.NoError(t, err)
	echo := make([]byte, len("embedded guest"))
	_, err = io.ReadFull(channel, echo)
	require.NoError(t, err)
	require.Equal(t, "embedded guest", string(echo))
	select {
	case arrived := <-home.peers:
		require.Equal(t, "route", arrived.User())
		require.Equal(t, string(ssh.MarshalAuthorizedKey(home.guest.PublicKey())), arrived.Permissions.Extensions["key"])
		certKey, err := ssh.ParsePublicKey([]byte(arrived.Permissions.Extensions["cert"]))
		require.NoError(t, err)
		cert := certKey.(*ssh.Certificate)
		auth, _, err := parseAuthRequestFromCert("route", cert, func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), home.signer.PublicKey().Marshal()) })
		require.NoError(t, err)
		require.Equal(t, typed, auth.TypedAddress)
		require.Equal(t, "route", auth.TargetRoutingId)
		require.Equal(t, "ingress-machine", auth.IngressNodeId)
		require.Equal(t, guest.SessionID(), auth.IngressConnection)
		require.Equal(t, Ingress_INGRESS_SSH, auth.Ingress)
		require.NotEqual(t, string(guest.SessionID()), cert.KeyId, "remote embedded path did not traverse a hop")
	case <-time.After(time.Second):
		t.Fatal("upgraded embedded peers never reached the host")
	}
}

// ---- hops with nothing composed, and where the token goes ----

// recordedHop is what advertisingHome saw of one hop.
type recordedHop struct {
	user string
	cert *ssh.Certificate
	auth *AuthRequest
}

// advertisingHome stands in for a node's internal listener, as a hop sees
// one: it advertises the gate-v1 token after this build's version, as every
// internal listener does.
func advertisingHome(t *testing.T, signer ssh.Signer) (string, <-chan recordedHop, func() []string) {
	t.Helper()
	return contractHome(t, signer, version.ServerSSHVersion()+" gate-v1")
}

// oldNodeHome is a node from before the gate, as a hop sees one: it reports
// this build's version with no token.
func oldNodeHome(t *testing.T, signer ssh.Signer) (string, <-chan recordedHop, func() []string) {
	t.Helper()
	return contractHome(t, signer, version.ServerSSHVersion())
}

// contractHome is a home node as a hop sees one, identifying itself as
// serverVersion: it admits any certificate signer signed, and echoes a
// session channel. It reports each hop it admitted, and records the type of
// every global request it receives, answering each false.
func contractHome(t *testing.T, signer ssh.Signer, serverVersion string) (addr string, hops <-chan recordedHop, requests func() []string) {
	t.Helper()
	var (
		mu   = make(chan struct{}, 1)
		seen []string
	)
	record := func(name string) {
		mu <- struct{}{}
		seen = append(seen, name)
		<-mu
	}
	requests = func() []string {
		mu <- struct{}{}
		defer func() { <-mu }()
		return append([]string(nil), seen...)
	}
	arrived := make(chan recordedHop, 8)
	cfg := &ssh.ServerConfig{ServerVersion: serverVersion, PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		cert, ok := key.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("not a hop")
		}
		auth, _, err := parseAuthRequestFromCert(meta.User(), cert, func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), signer.PublicKey().Marshal()) })
		if err != nil {
			return nil, err
		}
		select {
		case arrived <- recordedHop{user: meta.User(), cert: cert, auth: auth}:
		default:
		}
		return &ssh.Permissions{}, nil
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = raw.Close() }()
				conn, channels, reqs, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				go func() {
					for r := range reqs {
						record(r.Type)
						_ = r.Reply(false, nil)
					}
				}()
				for incoming := range channels {
					channel, chReqs, err := incoming.Accept()
					if err != nil {
						continue
					}
					go ssh.DiscardRequests(chReqs)
					go func() { defer func() { _ = channel.Close() }(); _, _ = io.Copy(channel, channel) }()
				}
			}()
		}
	}()
	return ln.Addr().String(), arrived, requests
}

// requireEcho opens a session channel on c, and requires it to echo.
func requireEcho(t *testing.T, c ssh.Conn, payload string) {
	t.Helper()
	channel, requests, err := c.OpenChannel("session", nil)
	require.NoError(t, err)
	defer func() { _ = channel.Close() }()
	go ssh.DiscardRequests(requests)
	_, err = channel.Write([]byte(payload))
	require.NoError(t, err)
	echo := make([]byte, len(payload))
	_, err = io.ReadFull(channel, echo)
	require.NoError(t, err)
	require.Equal(t, payload, string(echo))
}

// requireHostCert reads the certificate a gateEchoHost connection presented,
// and the AuthRequest it carries, signed by signer.
func requireHostCert(t *testing.T, host *ssh.ServerConn, signer ssh.Signer) (*ssh.Certificate, *AuthRequest) {
	t.Helper()
	certKey, err := ssh.ParsePublicKey([]byte(host.Permissions.Extensions["cert"]))
	require.NoError(t, err)
	cert := certKey.(*ssh.Certificate)
	auth, _, err := parseAuthRequestFromCert(host.User(), cert, func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), signer.PublicKey().Marshal()) })
	require.NoError(t, err)
	return cert, auth
}

// requireNoGateFields requires auth to be in the format that predates the
// gate.
func requireNoGateFields(t *testing.T, auth *AuthRequest) {
	t.Helper()
	require.Zero(t, auth.GateProtocol)
	require.Empty(t, auth.TypedAddress)
	require.Empty(t, auth.TargetRoutingId)
	require.Empty(t, auth.IngressNodeId)
	require.Empty(t, auth.ConnectionId)
}

// awaitHost is the next connection host saw.
func awaitHost(t *testing.T, peers <-chan *ssh.ServerConn) *ssh.ServerConn {
	t.Helper()
	select {
	case host := <-peers:
		return host
	case <-time.After(5 * time.Second):
		t.Fatal("the host saw no connection")
		return nil
	}
}

// legacyHopCert is a hop certificate in the format that predates the gate,
// for user, signed by authority, whose AuthRequest bytes end with extra.
func legacyHopCert(t *testing.T, user string, guest ssh.PublicKey, authority ssh.Signer, extra []byte) ssh.Signer {
	t.Helper()
	auth := &AuthRequest{ClientVersion: "SSH-2.0-Go", RemoteAddr: "203.0.113.7:1234", LocalAddr: "198.51.100.1:22", AuthorizedKey: ssh.MarshalAuthorizedKey(guest), Ingress: Ingress_INGRESS_SSH, IngressNode: "ingress:2222", IngressConnection: []byte("original-guest-session")}
	return certWithAuthBytes(t, user, auth, authority, extra)
}

// certWithAuthBytes signs a hop certificate for user carrying auth, with
// extra appended to its encoding, as a relay that knows more fields would.
func certWithAuthBytes(t *testing.T, user string, auth *AuthRequest, authority ssh.Signer, extra []byte) ssh.Signer {
	t.Helper()
	signed, err := (&UserCertSigner{SessionID: "hop", User: user, AuthRequest: auth}).SignCert(authority)
	require.NoError(t, err)
	if len(extra) == 0 {
		return signed
	}
	cert := signed.PublicKey().(*ssh.Certificate)
	cert.Extensions[upterm.SSHCertExtension] += string(extra)
	require.NoError(t, cert.SignCert(rand.Reader, authority))
	s, err := ssh.NewCertSigner(cert, authority)
	require.NoError(t, err)
	return s
}

// routingFixture is a session manager in mode, with the session "route" on
// node, and the SSH user that names it there.
func routingFixture(t *testing.T, mode routing.Mode, node string, guest ssh.PublicKey) (*SessionManager, string) {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	sm := newSessionManagerWithStore(newMemorySessionStore(logger), routing.NewEncodeDecoder(mode))
	key, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	session := &Session{ID: "route", NodeAddr: node, Generation: 7, HostPublicKeys: []ssh.PublicKey{key.PublicKey()}, ClientAuthorizedKeys: []ssh.PublicKey{guest}}
	user, err := sm.CreateSession(session)
	require.NoError(t, err)
	return sm, user
}

func TestHopsAreTodaysFormatWithNothingComposed(t *testing.T) {
	for _, mode := range []routing.Mode{routing.ModeEmbedded, routing.ModeConsul} {
		t.Run(string(mode), func(t *testing.T) {
			t.Run("ingress", func(t *testing.T) {
				relay, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
				require.NoError(t, err)
				guest := certTestSigner(t)
				home, hops, requests := advertisingHome(t, relay)
				sm, user := routingFixture(t, mode, "home:2222", guest.PublicKey())
				registry := &gateFixtureRegistry{}
				_, entry, _, _ := stockTestProxy(t, 2*time.Second, &stockTestDialer{addr: home}, func(p *sshProxy) {
					p.NodeAddr = "ingress:2222"
					p.SessionManager = sm
					p.authorities = registry
					p.listener = listenerPublic
					p.NodeID = "ingress-machine"
				})
				c, err := ssh.Dial("tcp", entry, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(guest)}, HostKeyCallback: ssh.FixedHostKey(relay.PublicKey()), Timeout: 5 * time.Second})
				require.NoError(t, err)
				defer func() { _ = c.Close() }()
				requireEcho(t, c, "today's hop")
				var hop recordedHop
				select {
				case hop = <-hops:
				case <-time.After(5 * time.Second):
					t.Fatal("no hop reached the home")
				}
				require.Equal(t, user, hop.user, "the hop's user is the downstream user")
				require.Equal(t, []string{user}, hop.cert.ValidPrincipals, "the hop's principal is the downstream user")
				requireNoGateFields(t, hop.auth)
				require.NotContains(t, requests(), upterm.GateModeRequestType, "the home saw a gate request")
				require.Zero(t, registry.lookups.Load())
			})

			// A home with nothing composed, sent hops in the format that
			// predates the gate.
			t.Run("home", func(t *testing.T) {
				guest, authority := certTestSigner(t), certTestSigner(t)
				third, thirdPeers := gateEchoHost(t)
				host, hostPeers := gateEchoHost(t)
				for _, tc := range []struct {
					name string
					node string // where the store, or the user, says the session is
					want <-chan *ssh.ServerConn
				}{
					// A field this build doesn't know decodes as master decodes
					// it, and is passed over.
					{"unknown field", "home:2222", hostPeers},
					// A session the home no longer holds is resolved again and
					// the hop forwarded there.
					{"stale route", "third:2222", thirdPeers},
				} {
					t.Run(tc.name, func(t *testing.T) {
						sm, user := routingFixture(t, mode, tc.node, guest.PublicKey())
						registry := &gateFixtureRegistry{}
						dialer := &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){
							"home:2222":  func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", host) },
							"third:2222": func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", third) },
						}}
						proxy, addr, _, _ := stockTestProxy(t, 2*time.Second, dialer, func(p *sshProxy) {
							p.NodeAddr = "home:2222"
							p.SessionManager = sm
							p.authorities = registry
							p.listener = listenerInternal
							p.HopTrusted = []ssh.PublicKey{authority.PublicKey()}
						})
						// A field number no AuthRequest has, set to 1.
						cert := legacyHopCert(t, user, guest.PublicKey(), authority, []byte{0xf8, 0x07, 1})
						c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(cert)}, HostKeyCallback: ssh.FixedHostKey(proxy.HostSigners[0].PublicKey()), Timeout: 5 * time.Second})
						require.NoError(t, err)
						defer func() { _ = c.Close() }()
						requireEcho(t, c, tc.name)
						arrived := awaitHost(t, tc.want)
						require.Equal(t, user, arrived.User())
						_, auth := requireHostCert(t, arrived, proxy.Signers[0])
						requireNoGateFields(t, auth)
						require.Equal(t, string(ssh.MarshalAuthorizedKey(guest.PublicKey())), arrived.Permissions.Extensions["key"])
						require.Zero(t, registry.lookups.Load(), "a legacy hop reached the gate")
					})
				}
			})
		})
	}
}

// bannerOf is the SSH identification line the server at addr sends first.
func bannerOf(t *testing.T, addr string) string {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()
	require.NoError(t, raw.SetDeadline(time.Now().Add(5*time.Second)))
	var line []byte
	one := make([]byte, 1)
	for len(line) < 256 {
		_, err := raw.Read(one)
		require.NoError(t, err)
		if one[0] == '\n' {
			break
		}
		line = append(line, one[0])
	}
	return string(bytes.TrimSuffix(line, []byte("\r")))
}

// startNode starts a node as uptermd does, and returns its SSH listener's
// address and, when it has one, its internal listener's.
func startNode(t *testing.T, opt Opt) (string, string) {
	t.Helper()
	addr, logs := startForSources(t, opt)
	started := awaitLogRecord(t, logs, func(r map[string]any) bool { return r["msg"] == "starting server" })
	internal, _ := started["internal_addr"].(string)
	return addr, internal
}

func TestSharedListenerAdvertisesOnlyWhenItGates(t *testing.T) {
	plain := version.ServerSSHVersion()
	gating := plain + " gate-v1"

	// Nothing composed.
	a, _ := startNode(t, Opt{})
	require.Equal(t, plain, bannerOf(t, a), "a shared listener of a node that doesn't gate")
	public, internal := startNode(t, Opt{InternalAddr: "127.0.0.1:0"})
	require.Equal(t, gating, bannerOf(t, internal), "an internal listener always advertises")
	require.Equal(t, plain, bannerOf(t, public), "a public listener never advertises")

	// Legacy hops refused, so the node gates.
	a, _ = startNode(t, Opt{RefuseLegacyHops: true})
	require.Equal(t, gating, bannerOf(t, a), "a shared listener of a node that gates")
	public, internal = startNode(t, Opt{InternalAddr: "127.0.0.1:0", RefuseLegacyHops: true})
	require.Equal(t, gating, bannerOf(t, internal))
	require.Equal(t, plain, bannerOf(t, public), "a public listener never advertises")

	// An authority composed, dark, so the node gates with legacy hops on.
	a, _ = startNode(t, Opt{Extensions: Extensions{Authority: &fakeAuthority{}, Protocols: []string{testProtocol}}})
	require.Equal(t, gating, bannerOf(t, a), "a shared listener of a node with an authority composed")
	public, internal = startNode(t, Opt{InternalAddr: "127.0.0.1:0", Extensions: Extensions{Authority: &fakeAuthority{}, Protocols: []string{testProtocol}}})
	require.Equal(t, gating, bannerOf(t, internal))
	require.Equal(t, plain, bannerOf(t, public), "a public listener never advertises")
}

// gateHopCert is a gate hop's certificate for user, signed by authority:
// GateProtocol 1, aimed at target.
func gateHopCert(t *testing.T, user, target string, guest ssh.PublicKey, authority ssh.Signer) ssh.Signer {
	t.Helper()
	auth := &AuthRequest{ClientVersion: "SSH-2.0-Go", RemoteAddr: "203.0.113.7:1234", LocalAddr: "198.51.100.1:22", AuthorizedKey: ssh.MarshalAuthorizedKey(guest), Ingress: Ingress_INGRESS_SSH, IngressNode: "ingress:2222", IngressConnection: []byte("original-guest-session"), TypedAddress: "typed-user", TargetRoutingId: target, IngressNodeId: "ingress-machine", ConnectionId: "60000000-0000-4000-8000-000000000006", GateProtocol: 1}
	return certWithAuthBytes(t, user, auth, authority, nil)
}

// requireGateModeLocal requires a gate-mode request over c to be answered
// with the local registration "route".
func requireGateModeLocal(t *testing.T, c ssh.Conn) {
	t.Helper()
	request := freshModeRequest("route")
	body, err := proto.Marshal(request)
	require.NoError(t, err)
	ok, reply, err := c.SendRequest(upterm.GateModeRequestType, true, body)
	require.NoError(t, err)
	require.True(t, ok, "the gate refused its mode request: %q", reply)
	var mode GateModeReply
	require.NoError(t, decodeGate(reply, &mode))
	require.Equal(t, request.Nonce, mode.Nonce)
	require.Equal(t, GateMode_GATE_MODE_LOCAL, mode.Registration.Mode)
	require.Equal(t, "route", mode.Registration.RoutingId)
}

func TestHopOnANonAdvertisingListenerIsServedAsToday(t *testing.T) {
	relay, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	// newHop is a node holding the local registration "route" in mode, on a
	// listener of kind, its own host echoing.
	newHop := func(t *testing.T, mode routing.Mode, kind listenerKind, gates bool, sm *SessionManager, routes map[string]string) (*sshProxy, string, *gateFixtureRegistry, ssh.Signer, ssh.Signer, <-chan *ssh.ServerConn) {
		t.Helper()
		guest, authority := certTestSigner(t), certTestSigner(t)
		host, peers := gateEchoHost(t)
		ref := RegistrationRef{Authority: AuthorityLocal, SessionID: "route", Generation: 7, RoutingID: "route", RunPublicKeys: [][]byte{relay.PublicKey().Marshal()}, RegistrationID: []byte("host-original-session"), HomeNode: "home:2222"}
		registry := &gateFixtureRegistry{}
		registry.current.Store(newLocalHome(ref))
		dials := map[string]func(context.Context) (net.Conn, error){
			"home:2222": func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", host) },
		}
		for node, addr := range routes {
			dials[node] = func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", addr) }
		}
		proxy, addr, _, _ := stockTestProxy(t, 2*time.Second, &routeDialer{routes: dials}, func(p *sshProxy) {
			p.NodeAddr = "home:2222"
			p.authorities = registry
			p.listener = kind
			p.RefuseLegacyHops = gates
			p.HopTrusted = []ssh.PublicKey{authority.PublicKey()}
			if sm != nil {
				p.SessionManager = sm
			} else {
				p.SessionManager = newSessionManagerWithStore(newMemorySessionStore(p.Logger), routing.NewEncodeDecoder(mode))
			}
			session := &Session{ID: "route", NodeAddr: "home:2222", Generation: 7, HostPublicKeys: []ssh.PublicKey{relay.PublicKey()}, ClientAuthorizedKeys: []ssh.PublicKey{guest.PublicKey()}}
			registry.session = session
			_, err := p.SessionManager.CreateSession(session)
			require.NoError(t, err)
		})
		return proxy, addr, registry, guest, authority, peers
	}
	dial := func(t *testing.T, addr, user string, cert ssh.Signer) (*ssh.Client, error) {
		t.Helper()
		c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(cert)}, HostKeyCallback: ssh.FixedHostKey(relay.PublicKey()), Timeout: 5 * time.Second})
		if c != nil {
			t.Cleanup(func() { _ = c.Close() })
		}
		return c, err
	}

	for _, mode := range []routing.Mode{routing.ModeEmbedded, routing.ModeConsul} {
		t.Run(string(mode), func(t *testing.T) {
			// A shared listener of a node with nothing composed doesn't
			// advertise, so a gate hop there is a legacy hop to the session
			// its certificate names.
			t.Run("non-advertising", func(t *testing.T) {
				proxy, addr, registry, guest, authority, peers := newHop(t, mode, listenerShared, false, nil, nil)
				c, err := dial(t, addr, "route", gateHopCert(t, "route", "route", guest.PublicKey(), authority))
				require.NoError(t, err)
				require.NotContains(t, string(c.ServerVersion()), "gate-v1")
				requireEcho(t, c, "legacy-served gate hop")
				arrived := awaitHost(t, peers)
				require.Equal(t, "route", arrived.User(), "the host sees the user a legacy hop delivers")
				_, auth := requireHostCert(t, arrived, proxy.Signers[0])
				requireNoGateFields(t, auth)
				// Under legacy handling, a gate request never reaches anyone.
				ok, _, err := c.SendRequest(upterm.GateModeRequestType, true, nil)
				require.NoError(t, err)
				require.False(t, ok)
				require.Zero(t, registry.lookups.Load(), "a hop on a listener that didn't advertise reached the gate")
			})
			for _, tc := range []struct {
				name  string
				kind  listenerKind
				gates bool
			}{
				{"advertising/internal, nothing composed", listenerInternal, false},
				{"advertising/shared, gating", listenerShared, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					_, addr, _, guest, authority, peers := newHop(t, mode, tc.kind, tc.gates, nil, nil)
					c, err := dial(t, addr, "route", gateHopCert(t, "route", "route", guest.PublicKey(), authority))
					require.NoError(t, err)
					require.True(t, hasGateCapability(c.ServerVersion()))
					requireGateModeLocal(t, c)
					requireEcho(t, c, "gate hop")
					require.Equal(t, "route", awaitHost(t, peers).User())
				})
			}

			// The session has moved to a third node, whose internal listener
			// advertises.
			t.Run("stale route", func(t *testing.T) {
				logger := slog.New(slog.DiscardHandler)
				shared := newSessionManagerWithStore(newMemorySessionStore(logger), routing.NewEncodeDecoder(mode))
				thirdHost, thirdPeers := gateEchoHost(t)
				third, thirdAddr, _, _ := stockTestProxy(t, 2*time.Second, &stockTestDialer{addr: thirdHost}, func(p *sshProxy) {
					p.NodeAddr = "third:2222"
					p.authorities = &gateFixtureRegistry{}
					p.listener = listenerInternal
					p.SessionManager = shared
				})
				_, addr, _, guest, authority, _ := newHop(t, mode, listenerShared, false, shared, map[string]string{"third:2222": thirdAddr})
				key, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
				require.NoError(t, err)
				_, err = shared.CreateSession(&Session{ID: "route", NodeAddr: "third:2222", Generation: 8, HostPublicKeys: []ssh.PublicKey{key.PublicKey()}, ClientAuthorizedKeys: []ssh.PublicKey{guest.PublicKey()}})
				require.NoError(t, err)
				if mode == routing.ModeEmbedded {
					// The embedded store is this node's own: the session it
					// held is gone, and a bare routing ID names no other node.
					require.NoError(t, shared.DeleteSession("route"))
				}
				c, err := dial(t, addr, "route", gateHopCert(t, "route", "route", guest.PublicKey(), authority))
				if mode == routing.ModeEmbedded {
					require.ErrorContains(t, err, "unable to authenticate", "a hop to a session this node doesn't hold was served")
					return
				}
				require.NoError(t, err)
				requireEcho(t, c, "forwarded as a legacy hop")
				arrived := awaitHost(t, thirdPeers)
				require.Equal(t, "route", arrived.User())
				_, auth := requireHostCert(t, arrived, third.Signers[0])
				requireNoGateFields(t, auth)
			})

			// The certificate names one session and the hop another.
			t.Run("mismatched identity", func(t *testing.T) {
				for _, kind := range []listenerKind{listenerShared, listenerInternal} {
					_, addr, _, guest, authority, peers := newHop(t, mode, kind, false, nil, nil)
					for _, user := range []string{"other", routing.NewEncodeDecoder(mode).Encode("other", "home:2222")} {
						c, err := dial(t, addr, user, gateHopCert(t, user, "route", guest.PublicKey(), authority))
						require.Error(t, err, "a hop whose target isn't its user was let in")
						require.Nil(t, c)
					}
					select {
					case <-peers:
						t.Fatal("a mismatched hop reached the host")
					default:
					}
				}
			})
		})
	}
}

func TestLegacyHopsOffGatesEveryHop(t *testing.T) {
	relay, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	for _, mode := range []routing.Mode{routing.ModeEmbedded, routing.ModeConsul} {
		t.Run(string(mode), func(t *testing.T) {
			// The hop such an ingress starts.
			t.Run("hop format", func(t *testing.T) {
				// The home trusts hops signed with the relay's own key, which
				// is what the ingress signs them with.
				home := newHopGateFixture(t, func(p *sshProxy) {
					p.HopTrusted = nil
					p.RefuseHostKeyHops = false
				})
				guest := home.guest
				sm, user := routingFixture(t, mode, "home:2222", guest.PublicKey())
				_, entry, _, _ := stockTestProxy(t, 2*time.Second, &stockTestDialer{addr: home.addr}, func(p *sshProxy) {
					p.NodeAddr = "ingress:2222"
					p.SessionManager = sm
					p.authorities = &gateFixtureRegistry{}
					p.listener = listenerPublic
					p.RefuseLegacyHops = true
				})
				c, err := ssh.Dial("tcp", entry, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(guest)}, HostKeyCallback: ssh.FixedHostKey(relay.PublicKey()), Timeout: 5 * time.Second})
				require.NoError(t, err)
				defer func() { _ = c.Close() }()
				requireEcho(t, c, "through the gate")
				arrived := awaitHost(t, home.peers)
				require.Equal(t, "route", arrived.User(), "a gate hop's user is the routing ID")
				_, auth := requireHostCert(t, arrived, relay)
				require.Equal(t, "route", auth.TargetRoutingId)
				require.Equal(t, user, auth.TypedAddress)
				require.Positive(t, home.registry.lookups.Load(), "the hop didn't go through the gate")
			})

			// A peer that advertises this build's version, but not the token:
			// a node from before the gate.
			t.Run("old peer", func(t *testing.T) {
				guest := certTestSigner(t)
				oldHome, oldHops, oldRequests := oldNodeHome(t, relay)
				sm, user := routingFixture(t, mode, "home:2222", guest.PublicKey())
				_, entry, _, _ := stockTestProxy(t, 2*time.Second, &stockTestDialer{addr: oldHome}, func(p *sshProxy) {
					p.NodeAddr = "ingress:2222"
					p.SessionManager = sm
					p.authorities = &gateFixtureRegistry{}
					p.listener = listenerPublic
					p.RefuseLegacyHops = true
				})
				c, err := ssh.Dial("tcp", entry, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(guest)}, HostKeyCallback: ssh.FixedHostKey(relay.PublicKey()), Timeout: 5 * time.Second})
				require.NoError(t, err)
				defer func() { _ = c.Close() }()
				ok, _, err := c.SendRequest("application", true, nil)
				require.False(t, ok, "the ingress hopped to a peer without the token; error=%v", err)
				_, _, err = c.OpenChannel("session", nil)
				require.Error(t, err, "the ingress hopped to a peer without the token")
				select {
				case <-oldHops:
				case <-time.After(5 * time.Second):
					t.Fatal("the ingress never authenticated to the old peer")
				}
				require.Empty(t, oldRequests(), "the ingress sent the old peer requests")
			})
		})
	}

	// A hop from such a peer, in the format that predates the gate.
	t.Run("hop from an old peer", func(t *testing.T) {
		home := newHopGateFixture(t)
		cert := legacyHopCert(t, "route", home.guest.PublicKey(), home.authority, nil)
		hop, err := ssh.Dial("tcp", home.addr, &ssh.ClientConfig{User: "route", ClientVersion: version.ServerSSHVersion(), Auth: []ssh.AuthMethod{ssh.PublicKeys(cert)}, HostKeyCallback: ssh.FixedHostKey(relay.PublicKey()), Timeout: 5 * time.Second})
		if hop != nil {
			_ = hop.Close()
		}
		require.Error(t, err, "a legacy hop was let in")
		require.Zero(t, home.dialer.calls.Load())

		// The same peer's hop, through the gate, is let in: the refusal is
		// the legacy format's alone.
		u, err := home.connect(t, home.auth, home.authority)
		require.NoError(t, err)
		_, err = negotiateHome(t.Context(), u, freshModeRequest("route"))
		require.NoError(t, err)
	})
}

// countingSigner counts the signatures it makes.
type countingSigner struct {
	ssh.Signer
	signed *atomic.Int32
}

func (s countingSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	s.signed.Add(1)
	return s.Signer.Sign(r, data)
}

func TestGateUnsignedProbeDialsNothing(t *testing.T) {
	var signed atomic.Int32
	f := newHopGateFixture(t, func(p *sshProxy) {
		p.Signers = []ssh.Signer{countingSigner{p.Signers[0], &signed}}
	})
	cert, err := (&UserCertSigner{SessionID: "probe", User: "route", AuthRequest: f.auth}).SignCert(f.authority)
	require.NoError(t, err)
	_, err = ssh.Dial("tcp", f.addr, &ssh.ClientConfig{User: "route", Auth: []ssh.AuthMethod{ssh.PublicKeys(refusingSigner{cert})}, HostKeyCallback: ssh.FixedHostKey(f.signer.PublicKey())})
	require.Error(t, err)
	require.Zero(t, f.dialer.calls.Load(), "an unsigned probe started a host handshake")
	require.Zero(t, signed.Load(), "an unsigned probe minted a certificate")
	require.Zero(t, f.registry.lookups.Load(), "an unsigned probe reached the gate")

	// The same certificate, signed, goes through: the probe's refusal is the
	// missing signature's alone.
	u, err := f.connect(t, f.auth, f.authority)
	require.NoError(t, err)
	_, err = negotiateHome(t.Context(), u, freshModeRequest("route"))
	require.NoError(t, err)
}

func TestGateRefusesAnUntrustedHomeOrHop(t *testing.T) {
	// A hop certificate no hop authority signed.
	f := newHopGateFixture(t)
	_, err := f.connect(t, f.auth, certTestSigner(t))
	require.Error(t, err)
	require.Zero(t, f.dialer.calls.Load())
	require.Zero(t, f.registry.lookups.Load(), "an untrusted hop reached the gate")

	// A home whose host key this ingress doesn't trust: a route-store key
	// cannot authorize a neighbour's host key.
	dialer := &stockTestDialer{addr: f.addr}
	proxy, addr, _, key := stockTestProxy(t, time.Second, dialer, func(p *sshProxy) {
		gatingIngress(p)
		p.HostSigners = []ssh.Signer{certTestSigner(t)}
		p.NodeTrusted = []ssh.PublicKey{certTestSigner(t).PublicKey()}
		p.HopSigners = []ssh.Signer{f.authority}
	})
	user := proxy.SessionManager.GetEncodeDecoder().Encode("route", "home:2222")
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.FixedHostKey(proxy.HostSigners[0].PublicKey())})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	ok, _, _ := c.SendRequest("probe", true, nil)
	require.False(t, ok)
	require.Equal(t, int32(1), dialer.calls.Load(), "the ingress never tried the home")
	require.Zero(t, f.dialer.calls.Load())
	require.Zero(t, f.registry.lookups.Load(), "a gate request went to an untrusted home")
}

func TestGateAcrossTwoConsulNodes(t *testing.T) {
	if !testhelpers.IsConsulAvailable() {
		t.Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
	}
	consulURL, err := suiteConsulURL("hop-gate")
	require.NoError(t, err)
	logger := slog.New(slog.DiscardHandler)
	homeSM, err := newConsulSessionManager(consulURL, 10*time.Second, logger)
	require.NoError(t, err)
	ingressSM, err := newConsulSessionManager(consulURL, 10*time.Second, logger)
	require.NoError(t, err)
	client := ownedConsulTestClient(t)
	t.Cleanup(func() {
		_ = ingressSM.GetStore().(*consulSessionStore).Close()
		_ = homeSM.GetStore().(*consulSessionStore).Close()
		require.NoError(t, removeSuiteConsulData(client, homeSM.GetStore().(*consulSessionStore)))
	})
	key, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	guest := certTestSigner(t)
	host, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
	mp, _ := newTestMetrics(t)
	work := newTestSSHWork(t)
	local := newLocalSessions(work.owner, mp, homeSM, logger)
	homes := &localAuthorityRegistry{sessions: local}
	// The route's hint says delegated; the gate answers from the registration
	// the home holds, never from the hint.
	reg, _, err := homeSM.Register(t.Context(), &Session{ID: "consul-route", NodeAddr: "home:2222", Generation: 1, HostPublicKeys: []ssh.PublicKey{key.PublicKey()}, ClientAuthorizedKeys: []ssh.PublicKey{guest.PublicKey()}, AuthorityHint: AuthorityDelegated})
	require.NoError(t, err)
	reg.localRef = RegistrationRef{Authority: AuthorityLocal, SessionID: "consul-route", RoutingID: "consul-route", Generation: 1, RegistrationID: []byte("host-original"), HomeNode: "home:2222"}
	_, err = local.add(testSSHWork(t, work.owner), reg, newCloser())
	require.NoError(t, err)
	t.Cleanup(func() { local.end(reg) })
	_, homeAddr, _, _ := stockTestProxy(t, 2*time.Second, &stockTestDialer{addr: host}, func(p *sshProxy) {
		p.NodeAddr = "home:2222"
		p.SessionManager = homeSM
		p.authorities = homes
		p.listener = listenerInternal
		p.RefuseLegacyHops = true
	})
	_, entry, _, _ := stockTestProxy(t, 2*time.Second, &stockTestDialer{addr: homeAddr}, func(p *sshProxy) {
		p.NodeAddr = "ingress:2222"
		p.SessionManager = ingressSM
		p.authorities = &gateFixtureRegistry{}
		p.listener = listenerPublic
		p.NodeID = "ingress-machine"
		p.RefuseLegacyHops = true
	})
	c, err := ssh.Dial("tcp", entry, &ssh.ClientConfig{User: "consul-route", Auth: []ssh.AuthMethod{ssh.PublicKeys(guest)}, HostKeyCallback: ssh.FixedHostKey(key.PublicKey())})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	ok, _, err := c.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil)
	require.NoError(t, err)
	require.True(t, ok)
	select {
	case arrived := <-peers:
		require.Equal(t, string(ssh.MarshalAuthorizedKey(guest.PublicKey())), arrived.Permissions.Extensions["key"])
		certKey, err := ssh.ParsePublicKey([]byte(arrived.Permissions.Extensions["cert"]))
		require.NoError(t, err)
		auth, _, err := parseAuthRequestFromCert("consul-route", certKey.(*ssh.Certificate), func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), key.PublicKey().Marshal()) })
		require.NoError(t, err)
		require.Equal(t, c.SessionID(), auth.IngressConnection)
		require.Equal(t, Ingress_INGRESS_SSH, auth.Ingress)
		require.Equal(t, "consul-route", auth.TargetRoutingId)
		require.Equal(t, "ingress-machine", auth.IngressNodeId)
	case <-time.After(5 * time.Second):
		t.Fatal("two-node hop never reached host")
	}
	// The host echoes arbitrary requests. A true reply would prove a guest's
	// gate request reached the hop.
	for _, name := range []string{upterm.GateModeRequestType, upterm.GateAdmitRequestType} {
		ok, _, err = c.SendRequest(name, true, []byte("guest-controlled"))
		require.NoError(t, err)
		require.False(t, ok, name)
	}
	ok, _, err = c.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil)
	require.NoError(t, err)
	require.True(t, ok)
}

// A guest's global request under a gate request's name is answered false at
// its ingress, and reaches no one: not the next node, whose gate would take it
// for the ingress's own, nor the host. A request under any other name goes on,
// in its turn, after them.
func TestGuestGateRequestsReachNoOne(t *testing.T) {
	names := []string{upterm.GateModeRequestType, "gate-admit@upterm.dev", "gate-held@upterm.dev"}
	relay, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	sendGateNames := func(t *testing.T, c ssh.Conn) {
		t.Helper()
		for _, name := range names {
			ok, _, err := c.SendRequest(name, true, []byte("guest-controlled"))
			require.NoError(t, err)
			require.False(t, ok, "a guest's %s was answered true", name)
		}
	}

	// To a node from before the gate, which records every request it gets.
	t.Run("legacy hop", func(t *testing.T) {
		home, hops, requests := oldNodeHome(t, relay)
		guest := certTestSigner(t)
		sm, user := routingFixture(t, routing.ModeEmbedded, "home:2222", guest.PublicKey())
		_, entry, _, _ := stockTestProxy(t, 2*time.Second, &stockTestDialer{addr: home}, func(p *sshProxy) {
			p.NodeAddr = "ingress:2222"
			p.SessionManager = sm
			p.authorities = &gateFixtureRegistry{}
			p.listener = listenerPublic
		})
		c, err := ssh.Dial("tcp", entry, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(guest)}, HostKeyCallback: ssh.FixedHostKey(relay.PublicKey()), Timeout: 5 * time.Second})
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		requireEcho(t, c, "joined")
		select {
		case <-hops:
		case <-time.After(5 * time.Second):
			t.Fatal("no hop reached the home")
		}
		sendGateNames(t, c)
		// The home answers every request false; that it answered this one
		// means it recorded it, and everything forwarded before it.
		ok, _, err := c.SendRequest("probe@upterm.test", true, nil)
		require.NoError(t, err)
		require.False(t, ok)
		got := requests()
		require.Contains(t, got, "probe@upterm.test")
		for _, name := range names {
			require.NotContains(t, got, name, "a guest's %s was forwarded", name)
		}
	})

	// Through the gate, where a forwarded gate request would reach the home's
	// gate as the ingress's own.
	t.Run("gate hop", func(t *testing.T) {
		home := newHopGateFixture(t, func(p *sshProxy) { p.SessionManager = newEmbeddedSessionManager(p.Logger) })
		_, entry, _, _ := stockTestProxy(t, 2*time.Second, &stockTestDialer{addr: home.addr}, func(p *sshProxy) {
			gatingIngress(p)
			p.NodeAddr = "ingress:2222"
			p.listener = listenerPublic
			p.HopSigners = []ssh.Signer{home.authority}
		})
		user := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode("route", "home:2222")
		c, err := ssh.Dial("tcp", entry, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(home.guest)}, HostKeyCallback: ssh.FixedHostKey(home.signer.PublicKey()), Timeout: 5 * time.Second})
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		requireEcho(t, c, "joined")
		awaitHost(t, home.peers)
		sendGateNames(t, c)
		// The host answers every request true: this one reached it, over a
		// hop the home's gate still holds open.
		ok, _, err := c.SendRequest("probe@upterm.test", true, nil)
		require.NoError(t, err)
		require.True(t, ok, "the hop didn't survive the guest's gate requests")
		requireEcho(t, c, "still joined")
	})
}

// ---- an authority composed ----

// darkIngress makes a proxy one with an authority composed, dark, and legacy
// hops accepted: it gates every hop it starts, and holds no registration.
func darkIngress(p *sshProxy) {
	p.authorities = &gateFixtureRegistry{}
	p.AuthorityComposed = true
}

// delegatedHome makes f's home hold a delegated registration of "route"
// instead of its local one.
func (f *hopGateFixture) delegatedHome(t *testing.T) {
	t.Helper()
	ref := f.home.Ref()
	ref.Authority, ref.AccountID, ref.SessionID = AuthorityDelegated, fixtureAccountID, externalSessionID
	f.home = newLocalHome(ref)
	f.registry.current.Store(f.home)
	f.registry.session.ClientAuthorizedKeys = nil
}

// With a dark authority and legacy hops accepted, a node takes a legacy hop
// to a local registration, and never one to a delegated registration; with
// legacy hops refused it takes neither. Its own hops use the gate, and fall
// back to today's handling toward a home without the token only while legacy
// hops are accepted.
func TestLegacyMigrationWithADarkAuthority(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run("delegated"+fmt.Sprint(legacy), func(t *testing.T) {
			f := newHopGateFixture(t, func(p *sshProxy) {
				p.RefuseLegacyHops = !legacy
				p.AuthorityComposed = true
			})
			f.delegatedHome(t)
			auth := proto.Clone(f.auth).(*AuthRequest)
			auth.GateProtocol = 0
			_, err := f.connect(t, auth, f.authority)
			require.Error(t, err)
			require.Zero(t, f.dialer.calls.Load())
		})
	}
	for _, legacy := range []bool{false, true} {
		t.Run("capabilityless_home"+fmt.Sprint(legacy), func(t *testing.T) {
			upstream, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
			proxy, addr, _, signer := stockTestProxy(t, time.Second, &stockTestDialer{addr: upstream}, func(p *sshProxy) {
				darkIngress(p)
				p.RefuseLegacyHops = !legacy
				p.SessionManager = newSessionManagerWithStore(newMemorySessionStore(p.Logger), routing.NewEncodeDecoder(routing.ModeConsul))
				_, err := p.SessionManager.CreateSession(&Session{ID: "old-route", NodeAddr: "old-home", HostPublicKeys: []ssh.PublicKey{certTestSigner(t).PublicKey()}})
				require.NoError(t, err)
			})
			c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "old-route", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(proxy.HostSigners[0].PublicKey())})
			require.NoError(t, err)
			defer func() { _ = c.Close() }()
			ok, _, _ := c.SendRequest("application", true, nil)
			require.Equal(t, legacy, ok)
			select {
			case host := <-peers:
				require.Equal(t, "old-route", host.User())
			case <-time.After(time.Second):
				t.Fatal("missing authenticated legacy attempt")
			}
		})
	}
}

// A delegated session's guest is admitted only by its authority's allow: an
// attempt that isn't a delegated guest's refuses a home that reports a
// delegated registration, without reaching its host, and a guest the
// authority doesn't allow never reaches the host at its home. The home's own
// gate holds a hop until its admission is asserted; see
// TestHopGateAdmission.
func TestDelegatedSessionAdmitsNoGuestWithoutAnAllow(t *testing.T) {
	t.Run("a home that reports one", func(t *testing.T) {
		key, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
		require.NoError(t, err)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		var application atomic.Int32
		go func() {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = raw.Close() }()
			cfg := &ssh.ServerConfig{ServerVersion: "SSH-2.0-uptermd gate-v1", PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
			cfg.AddHostKey(key)
			conn, channels, requests, err := ssh.NewServerConn(raw, cfg)
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			go func() {
				for ch := range channels {
					application.Add(1)
					_ = ch.Reject(ssh.Prohibited, "denied")
				}
			}()
			for req := range requests {
				if req.Type != upterm.GateModeRequestType {
					application.Add(1)
					_ = req.Reply(true, nil)
					continue
				}
				var request GateModeRequest
				if proto.Unmarshal(req.Payload, &request) != nil {
					return
				}
				registration := gateRegistration(RegistrationRef{Authority: AuthorityDelegated, AccountID: fixtureAccountID, SessionID: externalSessionID, Generation: 1, RoutingID: request.RoutingId,
					RunPublicKeys: [][]byte{key.PublicKey().Marshal()}, RegistrationID: []byte("host-original"), HomeNode: "127.0.0.1:3333", HomeNodeID: "home-machine", HomeBootID: fixtureBootID})
				require.NoError(t, validGateRegistration(registration))
				body, _ := proto.Marshal(&GateModeReply{Protocol: 1, Nonce: request.Nonce, Registration: registration})
				_ = req.Reply(true, body)
			}
		}()
		_, addr, _, signer := stockTestProxy(t, 2*time.Second, &stockTestDialer{addr: ln.Addr().String()}, darkIngress)
		user := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode("session", "127.0.0.1:3333")
		c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(key.PublicKey()), Timeout: 5 * time.Second})
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		ok, _, err := c.SendRequest("application-probe", true, nil)
		require.False(t, ok, "a guest of a delegated home was forwarded; error=%v", err)
		require.Zero(t, application.Load(), "the delegated home received application traffic")
	})

	t.Run("a guest at its home", func(t *testing.T) {
		ts := newDelegatedTestServer(t, &fakeAuthority{})
		host := newProven(t)
		client := dialHost(t, ts.addr, ts.signer, nil)
		ok, body := sendCreate(t, client, host.delegatedRequest(t, client, 1, delegatedSession()))
		require.True(t, ok, "%q", body)
		var resp CreateSessionResponse
		require.NoError(t, proto.Unmarshal(body, &resp))
		ln, err := client.Listen("unix", host.id())
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		reached := make(chan struct{}, 1)
		go func() {
			if conn, err := ln.Accept(); err == nil {
				reached <- struct{}{}
				_ = conn.Close()
			}
		}()
		_, err = ssh.Dial("tcp", ts.addr, &ssh.ClientConfig{User: resp.SshUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(certTestSigner(t))}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
		require.ErrorContains(t, err, "unable to authenticate", "a guest of a delegated session was let in")
		select {
		case <-reached:
			t.Fatal("a guest of a delegated session reached its host")
		default:
		}
	})
}

// echoGuests has client's host take its guests on the forward for id, with
// an SSH server of hostKey that accepts any key and echoes a session channel.
func echoGuests(t *testing.T, client *ssh.Client, hostKey ssh.Signer, id string) {
	t.Helper()
	ln, err := client.Listen("unix", id)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	config := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	config.AddHostKey(hostKey)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer func() { _ = sconn.Close() }()
				go ssh.DiscardRequests(reqs)
				for incoming := range chans {
					channel, requests, err := incoming.Accept()
					if err != nil {
						continue
					}
					go ssh.DiscardRequests(requests)
					go func() { defer func() { _ = channel.Close() }(); _, _ = io.Copy(channel, channel) }()
				}
			}()
		}
	}()
}

// A node with a dark authority and legacy hops accepted gates its own hops,
// and still joins guests across a fleet with a node that has nothing
// composed and only a shared listener, in both directions and both routing
// modes: toward that node, which doesn't advertise the gate, its gate hop
// falls back and is served as a legacy hop; from it, the hop is today's.
func TestDarkIngressFallsBackToUpgradedPeers(t *testing.T) {
	plain := version.ServerSSHVersion()
	for _, mode := range []routing.Mode{routing.ModeEmbedded, routing.ModeConsul} {
		t.Run(string(mode), func(t *testing.T) {
			logger := slog.New(slog.DiscardHandler)
			shared := newMemorySessionStore(logger)
			node := func(dark bool) (string, *listenersTestServer) {
				ln := listenLoopback(t)
				ts := serveListeners(t, Listeners{SSH: ln}, func(s *Server) {
					if mode == routing.ModeConsul {
						s.SessionManager = newSessionManagerWithStore(shared, routing.NewEncodeDecoder(routing.ModeConsul))
					}
					if dark {
						s.Extensions = Extensions{Authority: &fakeAuthority{}, Protocols: []string{testProtocol}}
					}
				})
				requireSSHDServing(t, ts.network)
				return ln.Addr().String(), ts
			}
			a, _ := node(true)
			b, _ := node(false)
			require.Equal(t, plain+" gate-v1", bannerOf(t, a), "a node with an authority composed gates")
			require.Equal(t, plain, bannerOf(t, b))
			signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
			require.NoError(t, err)
			for _, dir := range []struct{ name, ingress, home string }{{"A to B", a, b}, {"B to A", b, a}} {
				t.Run(dir.name, func(t *testing.T) {
					host := newProven(t)
					client := dialHost(t, dir.home, signer, nil)
					ok, body := sendCreate(t, client, host.delegatedRequest(t, client, 1, nil))
					require.True(t, ok, "%q", body)
					var resp CreateSessionResponse
					require.NoError(t, proto.Unmarshal(body, &resp))
					echoGuests(t, client, host.key, resp.SessionID)
					guest, err := ssh.Dial("tcp", dir.ingress, &ssh.ClientConfig{User: resp.SshUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(certTestSigner(t))}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
					require.NoError(t, err)
					defer func() { _ = guest.Close() }()
					requireEcho(t, guest, "joined "+dir.name)
				})
			}
		})
	}
}

// ---- delegated registrations through the gate ----

// admissionOf is the assertion an ingress makes of h, f's delegated home over
// its hop, for f's guest.
func (f *hopGateFixture) admissionOf(h Home) *GateAdmission {
	remote := h.(*remoteHome)
	return &GateAdmission{Protocol: 1, ModeNonce: bytes.Clone(remote.nonce), Registration: gateRegistration(h.Ref()), IngressNodeId: f.auth.IngressNodeId, ConnectionId: f.auth.ConnectionId,
		IngressSshSessionId: bytes.Clone(f.auth.IngressConnection), KeyFingerprint: publicKeyFingerprint(f.guest.PublicKey()), Sequence: 1, Capabilities: []string{"shell"}}
}

// A delegated registration's home holds a hop, channels and requests alike,
// until the ingress asserts its authority's allow: once, over that hop, for
// that guest, of exactly the registration it answered with. Any other
// assertion is refused before its host is reached. An asserted hop reaches
// the host as the guest, is confirmed held over the hop, and ends when the
// registration does.
func TestHopGateAdmission(t *testing.T) {
	for _, fault := range []string{"missing_assertion", "wrong_generation", "wrong_registration", "wrong_run_key", "wrong_nonce", "wrong_account", "wrong_home_node", "wrong_home_node_id", "wrong_home_boot", "wrong_session", "wrong_route", "wrong_key", "wrong_ingress", "wrong_connection", "wrong_original_session", "zero_sequence", "unknown_capability", "duplicate_capability", "retired_after_reply", "replaced_same_reference", "another_hop"} {
		t.Run(fault, func(t *testing.T) {
			f := delegatedGateHome(t)
			u, err := f.connect(t, f.auth, f.authority)
			require.NoError(t, err)
			h, err := negotiateHome(t.Context(), u, freshModeRequest(f.route))
			require.NoError(t, err)
			// Both channels and globals are refused while the assertion is
			// outstanding.
			_, _, err = u.conn.OpenChannel("session", nil)
			require.Error(t, err)
			ok, _, err := u.conn.SendRequest("application-probe", true, nil)
			require.NoError(t, err)
			require.False(t, ok)
			require.Zero(t, f.dialer.calls.Load(), "the host handshake didn't wait for the assertion")
			a := f.admissionOf(h)
			switch fault {
			case "missing_assertion":
				u.Close()
				return
			case "wrong_generation":
				a.Registration.Generation++
			case "wrong_registration":
				a.Registration.RegistrationId = []byte("another-host")
			case "wrong_run_key":
				a.Registration.RunPublicKeys = [][]byte{certTestSigner(t).PublicKey().Marshal()}
			case "wrong_nonce":
				a.ModeNonce[0] ^= 1
			case "wrong_account":
				a.Registration.AccountId = "another-account"
			case "wrong_home_node":
				a.Registration.HomeNode = "another-home"
			case "wrong_home_node_id":
				a.Registration.HomeNodeId = "another-machine"
			case "wrong_home_boot":
				a.Registration.HomeBootId = "70000000-0000-4000-8000-000000000007"
			case "wrong_session":
				a.Registration.SessionId = "another-session"
			case "wrong_route":
				a.Registration.RoutingId = "another-route"
			case "wrong_key":
				a.KeyFingerprint = publicKeyFingerprint(f.authority.PublicKey())
			case "wrong_ingress":
				a.IngressNodeId = "another-ingress"
			case "wrong_connection":
				a.ConnectionId = "70000000-0000-4000-8000-000000000007"
			case "wrong_original_session":
				a.IngressSshSessionId = []byte("hop-session")
			case "zero_sequence":
				a.Sequence = 0
			case "unknown_capability":
				a.Capabilities = []string{"admin"}
			case "duplicate_capability":
				a.Capabilities = []string{"shell", "shell"}
			case "replaced_same_reference":
				f.registry.current.Store(newLocalHome(f.home.Ref()))
			case "retired_after_reply":
				f.home.retire()
			case "another_hop":
				// This hop's assertion, made on another hop to the same
				// registration.
				other, err := f.connect(t, f.auth, f.authority)
				require.NoError(t, err)
				_, err = negotiateHome(t.Context(), other, freshModeRequest(f.route))
				require.NoError(t, err)
				u = other
			}
			// Sent directly, to exercise the home apart from the ingress's own
			// checks.
			body, err := proto.Marshal(a)
			require.NoError(t, err)
			ok, _, _ = u.conn.SendRequest(upterm.GateAdmitRequestType, true, body)
			require.False(t, ok, "the home accepted a mismatched assertion")
			require.Zero(t, f.dialer.calls.Load(), "the refusal didn't precede every host byte and channel")
		})
	}

	t.Run("healthy_delegated", func(t *testing.T) {
		f := delegatedGateHome(t)
		u, err := f.connect(t, f.auth, f.authority)
		require.NoError(t, err)
		h, err := negotiateHome(t.Context(), u, freshModeRequest(f.route))
		require.NoError(t, err)
		a := f.admissionOf(h)
		require.NoError(t, assertHomeAdmission(t.Context(), h, a))
		host := awaitHost(t, f.peers)
		require.Equal(t, string(ssh.MarshalAuthorizedKey(f.guest.PublicKey())), host.Permissions.Extensions["key"], "the host saw the hop's signer, not the guest")
		certKey, err := ssh.ParsePublicKey([]byte(host.Permissions.Extensions["cert"]))
		require.NoError(t, err)
		cert := certKey.(*ssh.Certificate)
		require.Equal(t, []string{f.route}, cert.ValidPrincipals)
		carried, _, err := parseAuthRequestFromCert(f.route, cert, func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), f.signer.PublicKey().Marshal()) })
		require.NoError(t, err)
		require.Equal(t, f.auth.IngressConnection, carried.IngressConnection)
		require.Equal(t, f.auth.ConnectionId, carried.ConnectionId)
		require.Equal(t, f.auth.TypedAddress, carried.TypedAddress)
		require.Equal(t, string(u.conn.SessionID()), cert.KeyId, "the host certificate doesn't identify this hop")
		_, guests := f.proxy.delegated.Counts()
		require.Equal(t, 1, guests, "an asserted hop isn't counted as delegated work")

		channel, requests, err := u.conn.OpenChannel("session", nil)
		require.NoError(t, err)
		defer func() { _ = channel.Close() }()
		go ssh.DiscardRequests(requests)
		_, err = channel.Write([]byte("original guest data"))
		require.NoError(t, err)
		require.NoError(t, h.(*remoteHome).checkHeld(t.Context(), 2, gateTimeout))
		require.True(t, h.Confirm(t.Context()), "a held registration wasn't confirmed over the hop")
		echo := make([]byte, len("original guest data"))
		_, err = io.ReadFull(channel, echo)
		require.NoError(t, err)
		require.Equal(t, "original guest data", string(echo))
		ok, _, err := u.conn.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil)
		require.NoError(t, err)
		require.True(t, ok)
		// The home holds the hop to the capabilities the assertion named, a
		// shell, whatever the ingress lets through.
		ok, err = channel.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{"uptime"}))
		require.NoError(t, err)
		require.False(t, ok, "the home let a shell-only hop exec")
		_, _, err = u.conn.OpenChannel("direct-tcpip", nil)
		var refused *ssh.OpenChannelError
		require.ErrorAs(t, err, &refused, "the home opened a forwarding channel on a shell-only hop")
		require.Equal(t, ssh.Prohibited, refused.Reason)
		f.home.retire()
		select {
		case <-h.Done():
		case <-time.After(time.Second):
			t.Fatal("a retired registration kept its admitted hop open")
		}
		require.False(t, h.Confirm(t.Context()), "a retired registration was confirmed")
		require.Eventually(t, func() bool { _, g := f.proxy.delegated.Counts(); return g == 0 }, 5*time.Second, 10*time.Millisecond, "an ended hop is still counted")
	})

	t.Run("replayed", func(t *testing.T) {
		f := delegatedGateHome(t)
		u, err := f.connect(t, f.auth, f.authority)
		require.NoError(t, err)
		h, err := negotiateHome(t.Context(), u, freshModeRequest(f.route))
		require.NoError(t, err)
		a := f.admissionOf(h)
		require.NoError(t, assertHomeAdmission(t.Context(), h, a))
		awaitHost(t, f.peers)
		require.Error(t, assertHomeAdmission(t.Context(), h, a), "the ingress asserted twice")
		body, err := proto.Marshal(a)
		require.NoError(t, err)
		ok, _, _ := u.conn.SendRequest(upterm.GateAdmitRequestType, true, body)
		require.False(t, ok, "the home accepted a replayed assertion")
		require.EqualValues(t, 1, f.dialer.calls.Load())
		select {
		case <-h.Done():
		case <-time.After(time.Second):
			t.Fatal("a replayed assertion left the hop open")
		}
	})

	// A held check at the asserted sequence is answered; one below it is
	// refused, and the home closes the hop.
	t.Run("held_below_the_assertion", func(t *testing.T) {
		f := delegatedGateHome(t)
		u, err := f.connect(t, f.auth, f.authority)
		require.NoError(t, err)
		h, err := negotiateHome(t.Context(), u, freshModeRequest(f.route))
		require.NoError(t, err)
		a := f.admissionOf(h)
		a.Sequence = 5
		require.NoError(t, assertHomeAdmission(t.Context(), h, a))
		awaitHost(t, f.peers)
		held := func(sequence uint64) (bool, []byte) {
			body, err := proto.Marshal(&GateHeldRequest{Protocol: 1, ModeNonce: bytes.Clone(h.(*remoteHome).nonce), Registration: gateRegistration(h.Ref()), Sequence: sequence})
			require.NoError(t, err)
			ok, reply, err := u.conn.SendRequest(upterm.GateHeldRequestType, true, body)
			require.NoError(t, err)
			return ok, reply
		}
		ok, body := held(5)
		require.True(t, ok, "the home refused a held check at the asserted sequence")
		var reply GateHeldReply
		require.NoError(t, proto.Unmarshal(body, &reply))
		require.True(t, reply.Held)
		ok, _ = held(4)
		require.False(t, ok, "the home answered a held check below the asserted sequence")
		select {
		case <-h.Done():
		case <-time.After(time.Second):
			t.Fatal("a held check below the asserted sequence left the hop open")
		}
	})
}

// The home accepts the assertion at exactly 5 seconds after the mode
// exchange, and refuses it a nanosecond later.
func TestHopModeAssertionDeadline(t *testing.T) {
	for _, offset := range []time.Duration{5 * time.Second, 5*time.Second + time.Nanosecond} {
		t.Run(offset.String(), func(t *testing.T) {
			f := delegatedGateHome(t)
			now := time.Now()
			g := &hopGate{auth: f.auth, key: f.guest.PublicKey(), lookup: f.registry, now: func() time.Time { return now }}
			request := freshModeRequest(f.route)
			body, err := proto.Marshal(request)
			require.NoError(t, err)
			ok, _, err := g.request(&ssh.Request{Type: upterm.GateModeRequestType, WantReply: true, Payload: body})
			require.NoError(t, err)
			require.True(t, ok)
			require.False(t, g.admitted, "a delegated hop was admitted by its mode exchange")
			a := &GateAdmission{Protocol: 1, ModeNonce: request.Nonce, Registration: gateRegistration(f.home.Ref()), IngressNodeId: f.auth.IngressNodeId, ConnectionId: f.auth.ConnectionId, IngressSshSessionId: f.auth.IngressConnection, KeyFingerprint: publicKeyFingerprint(f.guest.PublicKey()), Sequence: 1, Capabilities: []string{"shell"}}
			body, err = proto.Marshal(a)
			require.NoError(t, err)
			now = now.Add(offset)
			ok, _, err = g.request(&ssh.Request{Type: upterm.GateAdmitRequestType, WantReply: true, Payload: body})
			require.Equal(t, offset == 5*time.Second, ok)
			if offset > 5*time.Second {
				require.Error(t, err)
				require.False(t, g.admitted)
			} else {
				require.NoError(t, err)
				require.True(t, g.admitted)
			}
		})
	}
}

// Neither an unsigned probe with a hop's certificate nor a guest that
// connects to the internal listener raw reaches the home's host, a
// signature or the authority, even an enabled one: the internal listener is
// no SSH ingress.
func TestHopGateUnsignedProbeAndRawInternal(t *testing.T) {
	authority := &fakeAuthority{}
	f := delegatedGateHome(t, func(p *sshProxy) {
		p.authority, p.AuthorityEnabled, p.AuthorityComposed = authority, true, true
		p.NodeID = "home-machine"
	})
	cert, err := (&UserCertSigner{SessionID: "probe", User: f.route, AuthRequest: f.auth}).SignCert(f.authority)
	require.NoError(t, err)
	_, err = ssh.Dial("tcp", f.addr, &ssh.ClientConfig{User: f.route, Auth: []ssh.AuthMethod{ssh.PublicKeys(refusingSigner{cert})}, HostKeyCallback: ssh.FixedHostKey(f.signer.PublicKey())})
	require.Error(t, err)
	require.Zero(t, f.dialer.calls.Load(), "an unsigned probe started a host handshake")
	_, err = ssh.Dial("tcp", f.addr, &ssh.ClientConfig{User: f.route, Auth: []ssh.AuthMethod{ssh.PublicKeys(f.guest)}, HostKeyCallback: ssh.FixedHostKey(f.signer.PublicKey())})
	require.Error(t, err)
	admissions, _ := authority.guests()
	require.Empty(t, admissions, "a raw internal guest reached the authority")
	require.Zero(t, f.dialer.calls.Load())
}

// A hop no hop authority signed never reaches a delegated home's gate.
func TestHopModeUntrustedHomeAndHop(t *testing.T) {
	f := delegatedGateHome(t)
	_, err := f.connect(t, f.auth, certTestSigner(t))
	require.Error(t, err)
	require.Zero(t, f.dialer.calls.Load())
	require.Zero(t, f.registry.lookups.Load(), "an untrusted hop reached the gate")
}

// A hop whose assertion never comes is closed within the stage, without its
// host ever being dialled.
func TestHopModePreForwardTimeout(t *testing.T) {
	f := delegatedGateHome(t)
	u, err := f.connect(t, f.auth, f.authority)
	require.NoError(t, err)
	h, err := negotiateHome(t.Context(), u, freshModeRequest(f.route))
	require.NoError(t, err)
	select {
	case <-h.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("a hop without its assertion was kept open")
	}
	require.Zero(t, f.dialer.calls.Load(), "the timeout reached the host")
}

// A home on this node confirms while it is held and ctx lasts. A home on
// another node is asked over the hop, and is confirmed by an answer at
// exactly 2 seconds and not by one a nanosecond later, which retires it.
func TestHomeConfirm(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		home := newLocalHome(RegistrationRef{Authority: AuthorityDelegated, RoutingID: sessionRoute})
		require.True(t, home.Confirm(t.Context()))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		require.False(t, home.Confirm(ctx), "a local home was confirmed after its context ended")
		home.retire()
		require.False(t, home.Confirm(t.Context()), "a retired local home was confirmed")
	})

	for _, offset := range []time.Duration{2 * time.Second, 2*time.Second + time.Nanosecond} {
		t.Run(offset.String(), func(t *testing.T) {
			key := certTestSigner(t)
			received, replyNow := make(chan struct{}), make(chan struct{})
			u := gateContractPeer(t, key, func(r *ssh.Request) {
				switch r.Type {
				case upterm.GateModeRequestType:
					var request GateModeRequest
					if proto.Unmarshal(r.Payload, &request) != nil {
						_ = r.Reply(false, nil)
						return
					}
					reply := &GateModeReply{Protocol: 1, Nonce: request.Nonce, Registration: gateRegistration(RegistrationRef{Authority: AuthorityDelegated, AccountID: fixtureAccountID, SessionID: externalSessionID, Generation: 1, RoutingID: sessionRoute,
						RunPublicKeys: [][]byte{key.PublicKey().Marshal()}, RegistrationID: []byte("host-original"), HomeNode: "home", HomeNodeID: "home-machine", HomeBootID: fixtureBootID})}
					body, _ := proto.Marshal(reply)
					_ = r.Reply(true, body)
				case upterm.GateHeldRequestType:
					var request GateHeldRequest
					if proto.Unmarshal(r.Payload, &request) != nil {
						_ = r.Reply(false, nil)
						return
					}
					close(received)
					<-replyNow
					body, _ := proto.Marshal(&GateHeldReply{Request: &request, Held: true})
					_ = r.Reply(true, body)
				default:
					_ = r.Reply(false, nil)
				}
			})
			home, err := negotiateHome(t.Context(), u, freshModeRequest(sessionRoute))
			require.NoError(t, err)
			start := time.Now()
			var elapsed atomic.Int64
			u.now = func() time.Time { return start.Add(time.Duration(elapsed.Load())) }
			confirmed := make(chan bool, 1)
			go func() { confirmed <- home.Confirm(t.Context()) }()
			<-received
			elapsed.Store(int64(offset))
			close(replyNow)
			if offset > 2*time.Second {
				require.False(t, <-confirmed, "an answer after 2 seconds confirmed the home")
				require.False(t, home.Held(), "a home that failed its check was kept")
			} else {
				require.True(t, <-confirmed, "an answer at 2 seconds didn't confirm the home")
				require.True(t, home.Held())
			}
		})
	}
}

// A delegated registration's home answers the mode exchange only for a hop
// whose guest came in by SSH ingress that recorded its node, its node ID, its
// own SSH session and a connection ID; any other hop is refused before its
// host is reached.
func TestHopGateRefusesAnUntrustedOrigin(t *testing.T) {
	for name, change := range map[string]func(*AuthRequest){
		"websocket ingress":     func(a *AuthRequest) { a.Ingress = Ingress_INGRESS_WEBSOCKET },
		"unspecified ingress":   func(a *AuthRequest) { a.Ingress = Ingress_INGRESS_UNSPECIFIED },
		"no ingress node":       func(a *AuthRequest) { a.IngressNode = "" },
		"no ingress node ID":    func(a *AuthRequest) { a.IngressNodeId = "" },
		"no connection ID":      func(a *AuthRequest) { a.ConnectionId = "connection" },
		"no ingress connection": func(a *AuthRequest) { a.IngressConnection = nil },
	} {
		t.Run(name, func(t *testing.T) {
			f := delegatedGateHome(t)
			auth := proto.Clone(f.auth).(*AuthRequest)
			change(auth)
			u, err := f.connect(t, auth, f.authority)
			require.NoError(t, err)
			_, err = negotiateHome(t.Context(), u, freshModeRequest(f.route))
			require.Error(t, err, "a delegated home answered a hop from an untrusted origin")
			require.Zero(t, f.dialer.calls.Load())
		})
	}
	// The same hop from SSH ingress is answered.
	f := delegatedGateHome(t)
	u, err := f.connect(t, f.auth, f.authority)
	require.NoError(t, err)
	_, err = negotiateHome(t.Context(), u, freshModeRequest(f.route))
	require.NoError(t, err)
}
