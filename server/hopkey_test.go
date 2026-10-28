package server

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

func TestHopAuthority(t *testing.T) {
	relay, h1, h2, trusted, stranger := certTestSigner(t), certTestSigner(t), certTestSigner(t), certTestSigner(t), certTestSigner(t)
	for _, tc := range []struct {
		name   string
		hop    []ssh.Signer
		trust  []ssh.PublicKey
		refuse bool
	}{
		{name: "defaults"}, {name: "hop keys", hop: []ssh.Signer{h1, h2}},
		{name: "trusted key", trust: []ssh.PublicKey{trusted.PublicKey()}},
		{name: "refuse relay", hop: []ssh.Signer{h1, h2}, trust: []ssh.PublicKey{trusted.PublicKey()}, refuse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := proxyAuth{Signers: []ssh.Signer{relay}, HopSigners: tc.hop, HopTrusted: tc.trust, RefuseHostKeyHops: tc.refuse}
			require.Equal(t, !tc.refuse, a.isHopAuthority(relay.PublicKey()))
			require.Equal(t, len(tc.hop) > 0, a.isHopAuthority(h1.PublicKey()))
			require.Equal(t, len(tc.hop) > 0, a.isHopAuthority(h2.PublicKey()), "every configured signing key is trusted")
			require.Equal(t, len(tc.trust) > 0, a.isHopAuthority(trusted.PublicKey()))
			require.False(t, a.isHopAuthority(stranger.PublicKey()))
		})
	}
}

func TestRefuseHostKeyNeedsHopKey(t *testing.T) {
	t.Setenv("HOP_KEY", "")
	opt := Opt{SSHAddr: "127.0.0.1:0", HopRefuseHostKey: true}
	require.EqualError(t, opt.Validate(), "hop-refuse-host-key needs hop-key or hop-trusted-key, or no node could hop")
	opt.HopKeys = []string{"key"}
	require.NoError(t, opt.Validate())
	opt.HopKeys = nil
	opt.HopTrustedKeys = []string{TestPublicKeyContent}
	require.NoError(t, opt.Validate())
	opt.HopTrustedKeys = nil
	t.Setenv("HOP_KEY", HostPrivateKeyContent)
	require.NoError(t, opt.Validate())
}

func TestNeedsRelayCreds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target upstreamTarget
		want   bool
	}{
		{"host", upstreamTarget{id: &api.Identifier{Type: api.Identifier_HOST}}, true},
		{"local guest", upstreamTarget{id: &api.Identifier{Type: api.Identifier_CLIENT}, local: &Session{}}, true},
		{"remote guest", upstreamTarget{id: &api.Identifier{Type: api.Identifier_CLIENT}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) { require.Equal(t, tc.want, tc.target.needsRelayCreds()) })
	}
}

// Inspect the certificate the real SSH handshake authenticates with, including
// a second attempt made from the same credentials after its locality changes.
func TestPlanPicksCreds(t *testing.T) {
	relay, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	hop, second := certTestSigner(t), refusingSigner{certTestSigner(t)}
	for _, dedicated := range []bool{false, true} {
		t.Run(map[bool]string{false: "fallback", true: "dedicated"}[dedicated], func(t *testing.T) {
			upstream, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
			a := proxyAuth{Signers: []ssh.Signer{relay}, HostSigners: []ssh.Signer{relay}}
			if dedicated {
				a.HopSigners = []ssh.Signer{hop, second}
			}
			sm := newEmbeddedSessionManager(slog.New(slog.DiscardHandler))
			a.SessionManager = sm
			a.NodeAddr = "local:22"
			conn := originConn(sm.GetEncodeDecoder().Encode("session", "remote:22"), "SSH-2.0-Go", "sid")
			guest := certTestSigner(t)
			first, _, err := a.prepare(conn, guest.PublicKey())
			require.NoError(t, err)
			for _, tc := range []struct {
				name   string
				target *upstreamTarget
				want   ssh.PublicKey
			}{
				{"host", &upstreamTarget{id: &api.Identifier{Type: api.Identifier_HOST}}, relay.PublicKey()},
				{"local", &upstreamTarget{id: &api.Identifier{Type: api.Identifier_CLIENT}, local: &Session{HostPublicKeys: []ssh.PublicKey{relay.PublicKey()}}}, relay.PublicKey()},
				{"remote", &upstreamTarget{id: &api.Identifier{Type: api.Identifier_CLIENT}}, func() ssh.PublicKey {
					if dedicated {
						return hop.PublicKey()
					}
					return relay.PublicKey()
				}()},
			} {
				t.Run(tc.name, func(t *testing.T) {
					attempt := a.plan(conn, tc.target, first.creds)
					cfg := *attempt.config
					cfg.Timeout = 3 * time.Second
					client, err := ssh.Dial("tcp", upstream, &cfg)
					require.NoError(t, err)
					defer func() { _ = client.Close() }()
					select {
					case peer := <-peers:
						key, err := ssh.ParsePublicKey([]byte(peer.Permissions.Extensions["cert"]))
						require.NoError(t, err)
						require.True(t, utils.KeysEqual(tc.want, key.(*ssh.Certificate).SignatureKey))
					case <-time.After(5 * time.Second):
						t.Fatal("upstream did not authenticate")
					}
				})
			}
		})
	}
}

func TestTrustedKeyParseError(t *testing.T) {
	t.Setenv("HOP_KEY", "")
	err := Start(context.Background(), Opt{SSHAddr: "127.0.0.1:0", Network: "mem", HopTrustedKeys: []string{TestPublicKeyContent, "bad-key"}}, slog.New(slog.DiscardHandler))
	require.ErrorContains(t, err, "hop-trusted-key at index 1")
}

func TestHopKeyStartup(t *testing.T) {
	t.Setenv("PRIVATE_KEY", TestPrivateKeyContent)
	for _, source := range []string{"file", "PEM"} {
		t.Run(source, func(t *testing.T) {
			t.Setenv("HOP_KEY", "")
			opt := Opt{SSHAddr: "127.0.0.1:0", InternalAddr: "127.0.0.1:0", Network: "mem", HopRefuseHostKey: true}
			if source == "file" {
				opt.HopKeys = []string{writeKeyFile(t, HostPrivateKeyContent)}
			} else {
				t.Setenv("HOP_KEY", HostPrivateKeyContent)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			logs := make(proxyProtocolTestLogs, 128)
			done := make(chan error, 1)
			go func() { done <- Start(ctx, opt, slog.New(slog.NewJSONHandler(logs, nil))) }()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-time.After(5 * time.Second):
					t.Error("server did not stop")
				}
			})
			var addr, internal string
			timeout := time.After(5 * time.Second)
			for addr == "" {
				select {
				case record := <-logs:
					if record["msg"] == "starting server" {
						addr = record["ssh_addr"].(string)
						internal = record["internal_addr"].(string)
					}
				case <-timeout:
					t.Fatal("server did not start")
				}
			}
			// A successful registration request proves the hop key did not reach sshd.
			relay, err := ssh.ParsePrivateKey([]byte(HostPrivateKeyContent))
			require.NoError(t, err)
			raw, err := net.Dial("tcp", addr)
			require.NoError(t, err)
			defer func() { _ = raw.Close() }()
			require.NoError(t, raw.SetDeadline(time.Now().Add(5*time.Second)))
			c, ch, req, err := ssh.NewClientConn(raw, addr, &ssh.ClientConfig{User: "host", ClientVersion: upterm.HostSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(relay)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
			require.NoError(t, err)
			client := ssh.NewClient(c, ch, req)
			defer func() { _ = client.Close() }()
			request, err := proto.Marshal(&CreateSessionRequest{HostUser: "host", HostPublicKeys: [][]byte{ssh.MarshalAuthorizedKey(relay.PublicKey())}, ClientAuthorizedKeys: [][]byte{ssh.MarshalAuthorizedKey(relay.PublicKey())}})
			require.NoError(t, err)
			ok, body, err := client.SendRequest(upterm.ServerCreateSessionRequestType, true, request)
			require.NoError(t, err)
			require.True(t, ok, "sshd refused registration: %s", body)
			var session CreateSessionResponse
			require.NoError(t, proto.Unmarshal(body, &session))
			// A hop-key certificate with a refused guest earns a hop-only banner.
			other, _, _, _, err := ssh.ParseAuthorizedKey([]byte(TestPublicKeyContent))
			require.NoError(t, err)
			cert, err := (&UserCertSigner{SessionID: "hop", User: session.SshUser, AuthRequest: &AuthRequest{ClientVersion: "SSH-2.0-Go", AuthorizedKey: ssh.MarshalAuthorizedKey(other)}}).SignCert(relay)
			require.NoError(t, err)
			var banners []string
			hopClient, err := ssh.Dial("tcp", internal, &ssh.ClientConfig{User: session.SshUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(cert)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second, BannerCallback: func(m string) error { banners = append(banners, m); return nil }})
			if hopClient != nil {
				_ = hopClient.Close()
			}
			require.ErrorContains(t, err, "unable to authenticate")
			require.Equal(t, []string{upterm.HopBannerKeyRefused}, banners)
		})
	}
	t.Run("invalid PEM", func(t *testing.T) {
		t.Setenv("HOP_KEY", "bad key")
		require.ErrorContains(t, Start(context.Background(), Opt{SSHAddr: "127.0.0.1:0", Network: "mem"}, slog.New(slog.DiscardHandler)), "ssh: no key found")
	})
}

// A peer pinning the second relay key must still be offered its certificate
// when hops fall back to the relay's full certificate set.
func TestPlanPicksCredsRelayRotation(t *testing.T) {
	first, second := certTestSigner(t), certTestSigner(t)
	sm := newEmbeddedSessionManager(slog.New(slog.DiscardHandler))
	a := proxyAuth{Signers: []ssh.Signer{first, second}, HostSigners: []ssh.Signer{second}, SessionManager: sm, NodeAddr: "local:22"}
	conn := originConn(sm.GetEncodeDecoder().Encode("session", "remote:22"), "SSH-2.0-Go", "sid")
	initial, _, err := a.prepare(conn, first.PublicKey())
	require.NoError(t, err)
	creds := initial.creds
	for _, target := range []*upstreamTarget{
		{id: &api.Identifier{Type: api.Identifier_HOST}},
		{id: &api.Identifier{Type: api.Identifier_CLIENT}, local: &Session{HostPublicKeys: []ssh.PublicKey{second.PublicKey()}}},
		{id: &api.Identifier{Type: api.Identifier_CLIENT}},
	} {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()
		cfg := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			checker := UserCertChecker{IsUserAuthority: func(key ssh.PublicKey) bool { return utils.KeysEqual(key, second.PublicKey()) }}
			_, _, err := checker.Authenticate(c.User(), key)
			return nil, err
		}}
		cfg.AddHostKey(second)
		done := make(chan error, 1)
		go func() {
			raw, err := ln.Accept()
			if err != nil {
				done <- err
				return
			}
			defer func() { _ = raw.Close() }()
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			sc, _, _, err := ssh.NewServerConn(raw, cfg)
			if sc != nil {
				_ = sc.Close()
			}
			done <- err
		}()
		attempt := a.plan(conn, target, creds)
		client, err := ssh.Dial("tcp", ln.Addr().String(), attempt.config)
		require.NoError(t, err)
		_ = client.Close()
		require.NoError(t, <-done)
	}
}

// Configured hop trust must never turn an untrusted relay into a plain guest.
func TestSharedListenerHopTrust(t *testing.T) {
	relay, hop, retired, guest := certTestSigner(t), certTestSigner(t), certTestSigner(t), certTestSigner(t)
	logger := slog.New(slog.DiscardHandler)
	sm := newSessionManagerWithStore(newMemorySessionStore(logger), routing.NewEncodeDecoder(routing.ModeConsul))
	carried := &AuthRequest{ClientVersion: "SSH-2.0-OpenSSH_9.0", AuthorizedKey: ssh.MarshalAuthorizedKey(guest.PublicKey()),
		RemoteAddr: "203.0.113.7:4711", Ingress: Ingress_INGRESS_WEBSOCKET, IngressNode: "entry:22", IngressConnection: []byte("entry-id")}
	for _, tc := range []struct {
		name                  string
		signing               []ssh.Signer
		trusted               []ssh.PublicKey
		nodeTrusted           []ssh.PublicKey
		refuse, rejectRetired bool
	}{
		{name: "no hop options legacy fallback"},
		{name: "node trust alone legacy fallback", nodeTrusted: []ssh.PublicKey{retired.PublicKey()}},
		{name: "hop signing alone", signing: []ssh.Signer{hop}, rejectRetired: true},
		{name: "trusted hop alone", trusted: []ssh.PublicKey{hop.PublicKey()}, rejectRetired: true},
		{name: "refusal alone", refuse: true, rejectRetired: true},
		{name: "dedicated hop with server key refusal", signing: []ssh.Signer{hop}, refuse: true, rejectRetired: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := proxyAuth{listener: listenerShared, Signers: []ssh.Signer{relay}, HopSigners: tc.signing, HopTrusted: tc.trusted,
				NodeTrusted: tc.nodeTrusted, RefuseHostKeyHops: tc.refuse, SessionManager: sm, Logger: logger}
			for _, offer := range []struct {
				name            string
				signer          ssh.Signer
				reject, wantHop bool
			}{
				{"retired hop key", retired, tc.rejectRetired, false},
				{"server key", relay, tc.refuse, true},
				{"current hop key", hop, tc.rejectRetired && len(tc.signing) == 0 && len(tc.trusted) == 0, len(tc.signing) > 0 || len(tc.trusted) > 0},
			} {
				t.Run(offer.name, func(t *testing.T) {
					cert, err := (&UserCertSigner{SessionID: "entry-id", User: "session", AuthRequest: carried}).SignCert(offer.signer)
					require.NoError(t, err)
					auth, key, isHop, err := a.authenticate(originConn("session", "SSH-2.0-Go", "next-id"), cert.PublicKey())
					if offer.reject {
						require.ErrorIs(t, err, errRelayCertFromUntrustedSigner)
						require.Nil(t, auth)
						return
					}
					require.NoError(t, err)
					require.Equal(t, offer.wantHop, isHop)
					if offer.wantHop {
						require.True(t, utils.KeysEqual(guest.PublicKey(), key))
						require.True(t, proto.Equal(carried, auth), "trusted hop must preserve guest identity and origin")
					} else {
						require.True(t, utils.KeysEqual(offer.signer.PublicKey(), key))
						require.Equal(t, ssh.MarshalAuthorizedKey(offer.signer.PublicKey()), auth.AuthorizedKey)
						require.Equal(t, []byte("next-id"), auth.IngressConnection)
					}
				})
			}
			bareRelay, err := testCertSigner("session", relay)
			require.NoError(t, err)
			for name, offered := range map[string]ssh.Signer{
				"agent certificate without relay extension":  agentCert(t, guest),
				"server certificate without relay extension": bareRelay,
			} {
				t.Run(name, func(t *testing.T) {
					auth, key, isHop, err := a.authenticate(originConn("session", "SSH-2.0-Go", "next-id"), offered.PublicKey())
					require.NoError(t, err)
					require.False(t, isHop)
					certifiedKey := offered.PublicKey().(*ssh.Certificate).Key
					require.True(t, utils.KeysEqual(certifiedKey, key))
					require.Equal(t, ssh.MarshalAuthorizedKey(certifiedKey), auth.AuthorizedKey)
				})
			}
		})
	}
}

func TestSharedListenerLegacyFallback(t *testing.T) {
	for _, nodeTrust := range []bool{false, true} {
		t.Run(map[bool]string{false: "no hop options", true: "node trust alone"}[nodeTrust], func(t *testing.T) {
			authority, guest := certTestSigner(t), certTestSigner(t)
			upstream, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
			proxy, addr, _, _ := stockTestProxy(t, 4*time.Second, &stockTestDialer{addr: upstream}, func(p *sshProxy) {
				if nodeTrust {
					p.NodeTrusted = []ssh.PublicKey{authority.PublicKey()}
				}
			})
			user := holdSession(t, proxy, authority.PublicKey())
			cert, err := (&UserCertSigner{SessionID: "entry-id", User: user, AuthRequest: &AuthRequest{
				ClientVersion: "SSH-2.0-Go", AuthorizedKey: ssh.MarshalAuthorizedKey(guest.PublicKey()), IngressConnection: []byte("entry-id"),
			}}).SignCert(authority)
			require.NoError(t, err)
			client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(cert)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })
			peer, _, auth := arrived(t, peers)
			require.Equal(t, string(ssh.MarshalAuthorizedKey(authority.PublicKey())), peer.Permissions.Extensions["key"])
			require.Equal(t, client.SessionID(), auth.IngressConnection, "fallback records this guest connection's origin")
		})
	}
}
