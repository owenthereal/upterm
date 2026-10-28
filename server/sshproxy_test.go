package server

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	HostPublicKeyContent  = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOA+rMcwWFPJVE2g6EwRPkYmNJfaS/+gkyZ99aR/65uz`
	HostPrivateKeyContent = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDgPqzHMFhTyVRNoOhMET5GJjSX2kv/oJMmffWkf+ubswAAAIiu5GOBruRj
gQAAAAtzc2gtZWQyNTUxOQAAACDgPqzHMFhTyVRNoOhMET5GJjSX2kv/oJMmffWkf+ubsw
AAAEDBHlsR95C/pGVHtQGpgrUi+Qwgkfnp9QlRKdEhhx4rxOA+rMcwWFPJVE2g6EwRPkYm
NJfaS/+gkyZ99aR/65uzAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----`
)

func Test_sshProxy_dialUpstream(t *testing.T) {
	logger := logging.Must(logging.Console(), logging.Debug()).Logger

	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	if err != nil {
		t.Fatal(err)
	}

	cs := HostCertSigner{
		Hostnames: []string{"127.0.0.1"},
	}
	hostSigner, err := cs.SignCert(signer)
	if err != nil {
		t.Fatal(err)
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = proxyLn.Close()
	}()

	proxyAddr := proxyLn.Addr().String()
	mp, reg := newTestMetrics(t)
	cd := sidewayConnDialer{
		NodeAddr:        proxyAddr,
		NeighbourDialer: tcpConnDialer{},
		Logger:          logger,
	}
	proxy := &sshProxy{
		HostSigners:     []ssh.Signer{hostSigner},
		Signers:         []ssh.Signer{signer},
		SessionManager:  newEmbeddedSessionManager(logger),
		NodeAddr:        proxyAddr,
		ConnDialer:      cd,
		Logger:          logger,
		MetricsProvider: mp,
	}

	go func() {
		_ = proxy.Serve(proxyLn)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := utils.WaitForServer(ctx, proxyAddr); err != nil {
		t.Fatal(err)
	}

	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = sshLn.Close()
	}()

	sshdAddr := sshLn.Addr().String()
	sshd := &sshd{
		SessionManager:  newEmbeddedSessionManager(logger),
		HostSigners:     []ssh.Signer{signer},
		Signers:         []ssh.Signer{signer},
		NodeAddr:        sshdAddr,
		MetricsProvider: provider.NewDiscardProvider(),
		Logger:          logger,
	}

	go func() {
		_ = sshd.Serve(sshLn)
	}()

	if err := utils.WaitForServer(ctx, sshdAddr); err != nil {
		t.Fatal(err)
	}

	encoder := routing.NewEncodeDecoder(routing.ModeEmbedded)
	user := encoder.Encode(xid.New().String(), sshdAddr)
	ucs, err := testCertSigner(user, signer)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		Name   string
		Signer ssh.Signer
	}{
		{
			Name:   "public-key auth",
			Signer: signer,
		},
		{
			Name:   "public-key user cert auth",
			Signer: ucs,
		},
	}

	for _, c := range cases {
		cc := c

		t.Run(c.Name, func(t *testing.T) {
			config := &ssh.ClientConfig{
				User:            user,
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(cc.Signer)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}
			client, err := ssh.Dial("tcp", proxyAddr, config) // proxy to sshd
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.NewSession()
			if err == nil || !strings.Contains(err.Error(), "unsupported channel type") {
				t.Fatalf("expect unsupported channel type error but got %v", err)
			}
		})
	}

	// Both cases authenticated as clients (non-host SSH client version) and
	// none as hosts.
	const authenticated = "test_server_routing_authenticated_connections_count"
	v, ok := gatherValue(t, reg, authenticated, map[string]string{"kind": "client"})
	require.True(t, ok)
	require.Equal(t, float64(len(cases)), v)
	v, ok = gatherValue(t, reg, authenticated, map[string]string{"kind": "host"})
	require.True(t, ok, "host series should be exported even at zero")
	require.Equal(t, 0.0, v)

	// A client that answers the server's key query but never signs runs
	// PublicKeyCallback yet fails authentication; it must not be counted.
	_, err = ssh.Dial("tcp", proxyAddr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(refusingSigner{signer})},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	require.Error(t, err)
	v, ok = gatherValue(t, reg, authenticated, map[string]string{"kind": "client"})
	require.True(t, ok)
	require.Equal(t, float64(len(cases)), v, "failed authentication must not be counted")
}

// refusingSigner presents a public key but refuses to sign with it.
type refusingSigner struct {
	ssh.Signer
}

func (s refusingSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errors.New("refused to sign")
}

func testCertSigner(user string, signer ssh.Signer) (ssh.Signer, error) {
	cert := &ssh.Certificate{
		Key:             signer.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "1234",
		ValidPrincipals: []string{user},
		ValidBefore:     ssh.CertTimeInfinity,
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}

	return ssh.NewCertSigner(cert, signer)
}

// fakeConnMetadata is a minimal ssh.ConnMetadata stub for unit tests that
// consult the user and the client version, and the connection's two ends when
// a test sets them.
type fakeConnMetadata struct {
	user          string
	clientVersion string
	remote, local net.Addr
}

func (f *fakeConnMetadata) User() string          { return f.user }
func (f *fakeConnMetadata) SessionID() []byte     { return nil }
func (f *fakeConnMetadata) ClientVersion() []byte { return []byte(f.clientVersion) }
func (f *fakeConnMetadata) ServerVersion() []byte { return nil }
func (f *fakeConnMetadata) RemoteAddr() net.Addr  { return f.remote }
func (f *fakeConnMetadata) LocalAddr() net.Addr   { return f.local }

// A guest's forced command is told both ends of the guest's connection, as
// sshd tells a session in SSH_CONNECTION, and the relay is the only one that
// knows them: the host sees the relay's connection, not the guest's.
func Test_proxyAuth_authenticateRecordsBothEndsOfTheConnection(t *testing.T) {
	sm, err := NewSessionManager(routing.ModeEmbedded)
	require.NoError(t, err)
	guest, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)

	a := proxyAuth{SessionManager: sm, Logger: logging.Must(logging.Console(), logging.Debug()).Logger}
	conn := &fakeConnMetadata{
		user:          sm.GetEncodeDecoder().Encode("session", "127.0.0.1:2222"),
		clientVersion: "SSH-2.0-OpenSSH_9.0",
		remote:        &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234},
		local:         &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 22},
	}

	auth, _, _, err := a.authenticate(conn, guest.PublicKey())
	require.NoError(t, err)
	require.Equal(t, "203.0.113.7:51234", auth.GetRemoteAddr(), "the guest's end")
	require.Equal(t, "198.51.100.1:22", auth.GetLocalAddr(), "the relay's end")
}

func writeKeyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authorized_keys")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

func Test_loadAuthorizedKeys(t *testing.T) {
	hostSigner, err := ssh.ParsePrivateKey([]byte(HostPrivateKeyContent))
	require.NoError(t, err)
	hostFp := utils.FingerprintSHA256(hostSigner.PublicKey())

	otherSigner, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	otherPubKeyLine := string(ssh.MarshalAuthorizedKey(otherSigner.PublicKey()))
	otherFp := utils.FingerprintSHA256(otherSigner.PublicKey())

	t.Run("nil paths returns nil set (gate disabled)", func(t *testing.T) {
		got, err := loadAuthorizedKeys(nil)
		require.NoError(t, err)
		require.Nil(t, got)
	})

	t.Run("single file is parsed into fingerprint set", func(t *testing.T) {
		got, err := loadAuthorizedKeys([]string{writeKeyFile(t, HostPublicKeyContent+"\n")})
		require.NoError(t, err)
		require.Contains(t, got, hostFp)
		require.Len(t, got, 1)
	})

	t.Run("multiple files are unioned", func(t *testing.T) {
		got, err := loadAuthorizedKeys([]string{
			writeKeyFile(t, HostPublicKeyContent+"\n"),
			writeKeyFile(t, otherPubKeyLine),
		})
		require.NoError(t, err)
		require.Contains(t, got, hostFp)
		require.Contains(t, got, otherFp)
	})

	t.Run("comment-only file yields empty set, not an error", func(t *testing.T) {
		got, err := loadAuthorizedKeys([]string{writeKeyFile(t, "# header\n# nothing else\n")})
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("missing file fails fast", func(t *testing.T) {
		_, err := loadAuthorizedKeys([]string{filepath.Join(t.TempDir(), "does-not-exist")})
		require.Error(t, err)
	})
}

func Test_proxyAuth_checkAuthorizedKeys(t *testing.T) {
	logger := logging.Must(logging.Console(), logging.Debug()).Logger

	hostSigner, err := ssh.ParsePrivateKey([]byte(HostPrivateKeyContent))
	require.NoError(t, err)
	hostPubKey := hostSigner.PublicKey()
	hostFp := utils.FingerprintSHA256(hostPubKey)

	// Wrap the host's key in a certificate to mimic an agent-provided CertSigner:
	// the SSH library passes the certificate (not the raw key) to PublicKeyCallback.
	hostCertSigner, err := testCertSigner("host", hostSigner)
	require.NoError(t, err)
	hostCertAsPubKey := hostCertSigner.PublicKey()

	otherSigner, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	otherFp := utils.FingerprintSHA256(otherSigner.PublicKey())

	hostMeta := &fakeConnMetadata{clientVersion: upterm.HostSSHClientVersion}
	clientMeta := &fakeConnMetadata{clientVersion: "SSH-2.0-OpenSSH_9.0"}

	cases := []struct {
		name      string
		keys      map[string]struct{}
		meta      ssh.ConnMetadata
		offered   ssh.PublicKey
		wantGrant bool
	}{
		{
			name:      "nil set bypasses gate",
			keys:      nil,
			meta:      hostMeta,
			offered:   hostPubKey,
			wantGrant: true,
		},
		{
			name:      "non-host client version bypasses gate",
			keys:      map[string]struct{}{otherFp: {}}, // host key NOT in set
			meta:      clientMeta,
			offered:   hostPubKey,
			wantGrant: true,
		},
		{
			name:      "host key present in set is granted",
			keys:      map[string]struct{}{hostFp: {}},
			meta:      hostMeta,
			offered:   hostPubKey,
			wantGrant: true,
		},
		{
			name:      "host key absent from non-empty set is denied",
			keys:      map[string]struct{}{otherFp: {}},
			meta:      hostMeta,
			offered:   hostPubKey,
			wantGrant: false,
		},
		{
			name:      "empty (non-nil) set denies all hosts",
			keys:      map[string]struct{}{},
			meta:      hostMeta,
			offered:   hostPubKey,
			wantGrant: false,
		},
		{
			name:      "cert is matched against its underlying key (in set)",
			keys:      map[string]struct{}{hostFp: {}},
			meta:      hostMeta,
			offered:   hostCertAsPubKey,
			wantGrant: true,
		},
		{
			name:      "cert is matched against its underlying key (absent)",
			keys:      map[string]struct{}{otherFp: {}},
			meta:      hostMeta,
			offered:   hostCertAsPubKey,
			wantGrant: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := proxyAuth{
				authorizedKeys: tc.keys,
				Logger:         logger,
			}
			err := a.checkAuthorizedKeys(tc.meta, tc.offered)
			if tc.wantGrant {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// The internal listener is where other relay nodes reach this one, and hosts
// register on the public listener. A host on the internal listener is refused
// before anything is dialed for it, this node's sshd included.
func TestInternalListenerRefusesHosts(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	key := certTestSigner(t)
	a := proxyAuth{NodeAddr: "n1:22", listener: listenerInternal, SessionManager: newEmbeddedSessionManager(logger), Logger: logger}
	_, _, _, err := a.authenticate(originConn("session", upterm.HostSSHClientVersion, "sid"), key.PublicKey())
	require.EqualError(t, err, "hosts register on the public listener")

	// End to end, with the same host on the public listener as the control: a
	// dial count of zero proves nothing unless the host would otherwise have
	// been dialed for.
	for _, tc := range []struct {
		name     string
		kind     listenerKind
		admitted bool
	}{
		{"the public listener", listenerPublic, true},
		{"the internal listener", listenerInternal, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
			dialer := &stockTestDialer{addr: upstream}
			_, addr, _, signer := stockTestProxy(t, 2*time.Second, dialer, func(p *sshProxy) { p.listener = tc.kind })
			client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
				User:            "session",
				ClientVersion:   upterm.HostSSHClientVersion,
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         5 * time.Second,
			})
			if !tc.admitted {
				require.ErrorContains(t, err, "unable to authenticate")
				require.Zero(t, dialer.calls.Load(), "the sshd was dialed for a host the internal listener refused")
				return
			}
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })
			select {
			case <-peers:
			case <-time.After(5 * time.Second):
				t.Fatal("upstream did not authenticate")
			}
			require.Equal(t, int32(1), dialer.calls.Load())
		})
	}
}

// A relay certificate is one carrying an AuthRequest, judged from the
// certificate itself, whoever signed it. With an internal listener it is a hop
// there and nowhere else: the public listener and the bridge refuse it from any
// signer, and the internal listener refuses it from one that isn't a hop
// authority rather than authorizing its key. A certificate without an
// AuthRequest is its key on every listener. The shared listener, a node without
// an internal one, keeps the legacy fallback when no hop options are set.
func TestRelayCertsByListener(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	authority, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	guest := certTestSigner(t)
	foreign := certTestSigner(t)
	sm := newSessionManagerWithStore(newMemorySessionStore(logger), routing.NewEncodeDecoder(routing.ModeConsul))

	relayCert := func(signer ssh.Signer) ssh.PublicKey {
		cert, err := (&UserCertSigner{SessionID: "sid-1", User: "session", AuthRequest: &AuthRequest{
			ClientVersion: "SSH-2.0-OpenSSH_9.0", AuthorizedKey: ssh.MarshalAuthorizedKey(guest.PublicKey()),
		}}).SignCert(signer)
		require.NoError(t, err)
		return cert.PublicKey()
	}
	// The relay's own signing key, certified by itself with no AuthRequest.
	bareRelayCert, err := testCertSigner("session", authority)
	require.NoError(t, err)

	type outcome struct {
		key ssh.PublicKey // the key authorized
		hop bool
		err string
	}
	admits := func(key ssh.PublicKey, hop bool) outcome { return outcome{key: key, hop: hop} }
	refuses := func(err string) outcome { return outcome{err: err} }
	everywhere := func(o outcome) map[listenerKind]outcome {
		return map[listenerKind]outcome{listenerShared: o, listenerPublic: o, listenerBridge: o, listenerInternal: o}
	}
	const (
		onPublic  = "relay certificate on a public listener"
		untrusted = "relay certificate from an untrusted signer"
	)

	for _, tc := range []struct {
		name    string
		offered ssh.PublicKey
		want    map[listenerKind]outcome
	}{
		{"a hop authority's relay certificate", relayCert(authority), map[listenerKind]outcome{
			listenerShared:   admits(guest.PublicKey(), true),
			listenerPublic:   refuses(onPublic),
			listenerBridge:   refuses(onPublic),
			listenerInternal: admits(guest.PublicKey(), true),
		}},
		{"another signer's relay certificate", relayCert(foreign), map[listenerKind]outcome{
			listenerShared:   admits(foreign.PublicKey(), false),
			listenerPublic:   refuses(onPublic),
			listenerBridge:   refuses(onPublic),
			listenerInternal: refuses(untrusted),
		}},
		{"an agent's certificate from its own CA", agentCert(t, guest).PublicKey(), everywhere(admits(guest.PublicKey(), false))},
		{"the relay's key certified without an AuthRequest", bareRelayCert.PublicKey(), everywhere(admits(authority.PublicKey(), false))},
		{"a plain key", guest.PublicKey(), everywhere(admits(guest.PublicKey(), false))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, kind := range allListenerKinds {
				want := tc.want[kind]
				a := proxyAuth{NodeAddr: "n1:22", listener: kind, Signers: []ssh.Signer{authority}, SessionManager: sm, Logger: logger}
				auth, key, hop, err := a.authenticate(originConn("session", "SSH-2.0-Go", "sid-2"), tc.offered)
				if want.err != "" {
					require.EqualError(t, err, want.err, "listener %d", kind)
					require.Nil(t, auth, "listener %d", kind)
					continue
				}
				require.NoError(t, err, "listener %d", kind)
				require.Equal(t, string(ssh.MarshalAuthorizedKey(want.key)), string(ssh.MarshalAuthorizedKey(key)), "listener %d", kind)
				require.Equal(t, want.hop, hop, "listener %d", kind)
			}
		})
	}
}

// A guest's own key on the internal listener is a guest a neighbour's
// WebSocket hands over raw, or a peer this node knows nothing about. It is
// served as on any listener, and its request claims no entry. An agent's
// certificate, carrying no AuthRequest, is the guest's key there too.
func TestRawInternalGuestOrigin(t *testing.T) {
	guest := certTestSigner(t)
	for name, offered := range map[string]ssh.Signer{
		"a plain key":            guest,
		"an agent's certificate": agentCert(t, guest),
	} {
		t.Run(name, func(t *testing.T) {
			upstream, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
			n2, addr := originNode(t, listenerInternal, "n2:22", &stockTestDialer{addr: upstream})
			user := holdSession(t, n2, guest.PublicKey())
			client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(offered)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })

			peer, _, auth := arrived(t, peers)
			require.Equal(t, string(ssh.MarshalAuthorizedKey(guest.PublicKey())), peer.Permissions.Extensions["key"],
				"the upstream saw the guest's key")
			require.Equal(t, Ingress_INGRESS_UNSPECIFIED, auth.GetIngress())
			require.Empty(t, auth.GetIngressNode())
			require.Equal(t, client.SessionID(), auth.GetIngressConnection())
		})
	}
}

func TestNeighbourHostKeyTrust(t *testing.T) {
	own, trusted, other := certTestSigner(t), certTestSigner(t), certTestSigner(t)
	a := proxyAuth{HostSigners: []ssh.Signer{own}, NodeTrusted: []ssh.PublicKey{trusted.PublicKey()}}
	for _, tc := range []struct {
		name     string
		target   *upstreamTarget
		key      ssh.PublicKey
		accepted bool
	}{
		{"own key", &upstreamTarget{id: &api.Identifier{Type: api.Identifier_CLIENT}}, own.PublicKey(), true},
		{"listed neighbour", &upstreamTarget{id: &api.Identifier{Type: api.Identifier_CLIENT}}, trusted.PublicKey(), true},
		{"other neighbour", &upstreamTarget{id: &api.Identifier{Type: api.Identifier_CLIENT}}, other.PublicKey(), false},
		{"registration keeps own key", &upstreamTarget{id: &api.Identifier{Type: api.Identifier_HOST}}, own.PublicKey(), true},
		{"registration excludes neighbour trust", &upstreamTarget{id: &api.Identifier{Type: api.Identifier_HOST}}, trusted.PublicKey(), false},
		{"local host excludes neighbour trust", &upstreamTarget{id: &api.Identifier{Type: api.Identifier_CLIENT}, local: &Session{HostPublicKeys: []ssh.PublicKey{other.PublicKey()}}}, trusted.PublicKey(), false},
		{"local host retains session key", &upstreamTarget{id: &api.Identifier{Type: api.Identifier_CLIENT}, local: &Session{HostPublicKeys: []ssh.PublicKey{other.PublicKey()}}}, other.PublicKey(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := a.plan(&fakeConnMetadata{user: "session"}, tc.target, routeCreds{})
			err := route.config.HostKeyCallback("node", &net.TCPAddr{}, tc.key)
			if tc.accepted {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, errUpstreamHostKeyMismatch)
			}
		})
	}
}

func TestNodeTrustedKeyParseError(t *testing.T) {
	t.Setenv("HOP_KEY", "")
	err := Start(context.Background(), Opt{SSHAddr: "127.0.0.1:0", Network: "mem", NodeTrustedKeys: []string{TestPublicKeyContent, "bad-key"}}, slog.New(slog.DiscardHandler))
	require.ErrorContains(t, err, "node-trusted-key at index 1")
}
