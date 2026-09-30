package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

const (
	TestPublicKeyContent  = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN0EWrjdcHcuMfI8bGAyHPcGsAc/vd/gl5673pRkRBGY`
	TestPrivateKeyContent = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDdBFq43XB3LjHyPGxgMhz3BrAHP73f4Jeeu96UZEQRmAAAAIiRPFazkTxW
swAAAAtzc2gtZWQyNTUxOQAAACDdBFq43XB3LjHyPGxgMhz3BrAHP73f4Jeeu96UZEQRmA
AAAEDmpjZHP/SIyBTp6YBFPzUi18iDo2QHolxGRDpx+m7let0EWrjdcHcuMfI8bGAyHPcG
sAc/vd/gl5673pRkRBGYAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----`
)

func Test_sshd_DisallowSession(t *testing.T) {
	logger := logging.Must(logging.Console(), logging.Debug()).Logger

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = ln.Close()
	}()

	addr := ln.Addr().String()

	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	if err != nil {
		t.Fatal(err)
	}

	// Set up cert signer for sshd public key validation
	cs := UserCertSigner{
		SessionID: "1234",
		User:      "owen",
		AuthRequest: &AuthRequest{
			ClientVersion: upterm.HostSSHClientVersion,
			RemoteAddr:    addr,
			AuthorizedKey: []byte(TestPublicKeyContent),
		},
	}
	certSigner, err := cs.SignCert(signer)
	if err != nil {
		t.Fatal(err)
	}

	sshd := &sshd{
		SessionManager: func() *SessionManager {
			sm, _ := NewSessionManager(routing.ModeEmbedded,
				WithSessionManagerLogger(logger))
			return sm
		}(),
		HostSigners:     []ssh.Signer{signer},
		Signers:         []ssh.Signer{signer},
		NodeAddr:        addr,
		MetricsProvider: provider.NewDiscardProvider(),
		Logger:          logger,
	}

	go func() {
		_ = sshd.Serve(ln)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := utils.WaitForServer(ctx, addr); err != nil {
		t.Fatal(err)
	}

	config := &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		User:            "owen",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.NewSession()
	if err == nil || !strings.Contains(err.Error(), "unsupported channel type") {
		t.Fatalf("expect unsupported channel type error but got %v", err)
	}
}

// testSSHD is an sshd on a loopback listener with a private metrics
// registry and an in-memory session network.
type testSSHD struct {
	sshd    *sshd
	addr    string
	signer  ssh.Signer // the relay's own key, which mints the proxy's certificates
	reg     *prometheus.Registry
	network *MemoryProvider
}

// newTestSSHD starts an sshd, applying options to it before it serves.
func newTestSSHD(t *testing.T, options ...func(*sshd)) *testSSHD {
	t.Helper()
	logger := logging.Must(logging.Console(), logging.Debug()).Logger

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	addr := ln.Addr().String()

	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)

	network := &MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))

	mp, reg := newTestMetrics(t)
	sshd := &sshd{
		SessionManager:      newEmbeddedSessionManager(logger),
		HostSigners:         []ssh.Signer{signer},
		Signers:             []ssh.Signer{signer},
		NodeAddr:            addr,
		SessionDialListener: network.Session(),
		MetricsProvider:     mp,
		Logger:              logger,
	}
	for _, option := range options {
		option(sshd)
	}
	go func() {
		_ = sshd.Serve(ln)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, utils.WaitForServer(ctx, addr))

	return &testSSHD{sshd: sshd, addr: addr, signer: signer, reg: reg, network: network}
}

func (s *testSSHD) dial(t *testing.T) *ssh.Client {
	t.Helper()
	return s.dialAs(t, "1234")
}

// dialAs connects as the proxy does on behalf of a host whose own connection
// has the SSH session ID keyID: the proxy mints that ID into the certificate's
// KeyId, and a proof is bound to it.
func (s *testSSHD) dialAs(t *testing.T, keyID string) *ssh.Client {
	t.Helper()
	cs := UserCertSigner{
		SessionID: keyID,
		User:      "owen",
		AuthRequest: &AuthRequest{
			ClientVersion: upterm.HostSSHClientVersion,
			RemoteAddr:    s.addr,
			AuthorizedKey: []byte(TestPublicKeyContent),
		},
	}
	certSigner, err := cs.SignCert(s.signer)
	require.NoError(t, err)

	client, err := ssh.Dial("tcp", s.addr, &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		User:            "owen",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// waitClosed fails with what unless client's connection ends within 5 s.
func waitClosed(t *testing.T, client *ssh.Client, what string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s stayed open", what)
	}
}

// proven is a host that proves its session key: the key and the secret its
// session ID derives from.
type proven struct {
	key    ssh.Signer
	secret []byte
}

func newProven(t *testing.T) proven {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	secret, err := registration.NewSecret()
	require.NoError(t, err)
	return proven{key: key, secret: secret}
}

// id is the session ID the relay derives for p.
func (p proven) id() string { return registration.ID(p.key.PublicKey(), p.secret) }

func (p proven) hostKeys() [][]byte {
	return [][]byte{ssh.MarshalAuthorizedKey(p.key.PublicKey())}
}

// register creates p's session at generation gen over client, with a proof
// bound to keyID, the SSH session ID client was dialed as.
func (p proven) register(t *testing.T, client *ssh.Client, keyID string, gen uint64) (bool, []byte) {
	t.Helper()
	proof, err := registration.Sign(p.key, []byte(keyID), p.secret, gen)
	require.NoError(t, err)
	return p.send(t, client, gen, proof, p.hostKeys())
}

// send creates a session over client with p's secret and whatever generation,
// proof and host keys it is given.
func (p proven) send(t *testing.T, client *ssh.Client, gen uint64, proof []byte, hostKeys [][]byte) (bool, []byte) {
	t.Helper()
	req, err := proto.Marshal(&CreateSessionRequest{
		HostUser:       "owen",
		HostPublicKeys: hostKeys,
		SessionSecret:  p.secret,
		Generation:     gen,
		HostKeyProof:   proof,
	})
	require.NoError(t, err)
	ok, body, err := client.SendRequest(upterm.ServerCreateSessionRequestType, true, req)
	require.NoError(t, err)
	return ok, body
}

func (s *testSSHD) gauge(t *testing.T) float64 {
	t.Helper()
	v, ok := gatherValue(t, s.reg, "test_server_sessions_active_count", nil)
	require.True(t, ok, "sessions_active_count not exported")
	return v
}

// createSession has the host create a session over client and returns its ID.
func (s *testSSHD) createSession(t *testing.T, client *ssh.Client) string {
	t.Helper()
	reqBytes, err := proto.Marshal(&CreateSessionRequest{
		HostUser:       "owen",
		HostPublicKeys: [][]byte{[]byte(TestPublicKeyContent)},
	})
	require.NoError(t, err)
	ok, body, err := client.SendRequest(upterm.ServerCreateSessionRequestType, true, reqBytes)
	require.NoError(t, err)
	require.True(t, ok, string(body))
	var resp CreateSessionResponse
	require.NoError(t, proto.Unmarshal(body, &resp))
	return resp.SessionID
}

func forwardRequest(t *testing.T, client *ssh.Client, reqType, sessionID string) (bool, string) {
	t.Helper()
	ok, body, err := client.SendRequest(reqType, true, ssh.Marshal(&streamlocalChannelForwardMsg{SocketPath: sessionID}))
	require.NoError(t, err)
	return ok, string(body)
}

func Test_sshd_SessionsActiveGauge(t *testing.T) {
	s := newTestSSHD(t)
	require.Equal(t, 0.0, s.gauge(t), "gauge should be exported as 0 before any session")

	client := s.dial(t)
	sessionID := s.createSession(t, client)
	require.Equal(t, 1.0, s.gauge(t), "gauge should count the created session")

	// Host opens its reverse tunnel; the gauge counts sessions, not tunnels.
	ok, body := forwardRequest(t, client, streamlocalForwardChannelType, sessionID)
	require.True(t, ok, body)
	require.Equal(t, 1.0, s.gauge(t))

	// Host tears the tunnel down, which deletes the session.
	ok, body = forwardRequest(t, client, cancelStreamlocalForwardChannelType, sessionID)
	require.True(t, ok, body)
	require.Equal(t, 0.0, s.gauge(t), "gauge should drop when the session is deleted")
	_, err := s.sshd.SessionManager.GetSession(sessionID)
	require.Error(t, err, "session should be deleted")

	// A second cancel for the same session must not decrement again.
	ok, _ = forwardRequest(t, client, cancelStreamlocalForwardChannelType, sessionID)
	require.True(t, ok)
	require.Equal(t, 0.0, s.gauge(t))
}

func Test_sshd_SessionsActiveGauge_DisconnectWithoutForward(t *testing.T) {
	s := newTestSSHD(t)

	client := s.dial(t)
	sessionID := s.createSession(t, client)
	require.Equal(t, 1.0, s.gauge(t))

	// The host goes away before ever opening its tunnel, so no listener
	// cleanup runs; the connection ending must still release the count and
	// delete the session from the store.
	require.NoError(t, client.Close())
	require.Eventually(t, func() bool { return s.gauge(t) == 0 }, 5*time.Second, 10*time.Millisecond,
		"gauge should drop when the owning connection ends")
	require.Eventually(t, func() bool {
		_, err := s.sshd.SessionManager.GetSession(sessionID)
		return err != nil
	}, 5*time.Second, 10*time.Millisecond, "session should be deleted when the owning connection ends")
}

func Test_sshd_ForwardRequiresActiveSession(t *testing.T) {
	s := newTestSSHD(t)

	client := s.dial(t)
	sessionID := s.createSession(t, client)
	ok, body := forwardRequest(t, client, streamlocalForwardChannelType, sessionID)
	require.True(t, ok, body)
	ok, body = forwardRequest(t, client, cancelStreamlocalForwardChannelType, sessionID)
	require.True(t, ok, body)
	require.Equal(t, 0.0, s.gauge(t))

	// If the store delete had failed, the record would still be there while
	// the session is no longer counted. The connection still owns the ID, so
	// ownership alone must not be enough to reopen the tunnel.
	sess, err := s.sshd.SessionManager.GetSession(sessionID)
	require.Error(t, err)
	require.Nil(t, sess)
	_, err = s.sshd.SessionManager.CreateSession(NewSession(sessionID, s.addr, "owen", nil, nil))
	require.NoError(t, err)

	ok, _ = forwardRequest(t, client, streamlocalForwardChannelType, sessionID)
	require.False(t, ok, "forward of an ended session must be rejected")
	require.Equal(t, 0.0, s.gauge(t))
}

func Test_sshd_ForwardRequiresSessionOwnership(t *testing.T) {
	s := newTestSSHD(t)

	// A session created on another node is visible in a shared store but
	// belongs to a connection this node never saw.
	foreign := NewSession("foreign-session", "other-node:22", "owen", nil, nil)
	_, err := s.sshd.SessionManager.CreateSession(foreign)
	require.NoError(t, err)

	owner := s.dial(t)
	other := s.dial(t)
	sessionID := s.createSession(t, owner)
	require.Equal(t, 1.0, s.gauge(t))

	for name, id := range map[string]string{"foreign node": foreign.ID, "other connection": sessionID} {
		t.Run(name, func(t *testing.T) {
			ok, _ := forwardRequest(t, other, streamlocalForwardChannelType, id)
			require.False(t, ok, "forward of a session not created on this connection must be rejected")
			ok, _ = forwardRequest(t, other, cancelStreamlocalForwardChannelType, id)
			require.False(t, ok, "cancel of a session not created on this connection must be rejected")
			_, err := s.sshd.SessionManager.GetSession(id)
			require.NoError(t, err, "rejected requests must not delete the session")
			require.Equal(t, 1.0, s.gauge(t))
		})
	}

	// The creating connection can still forward and cancel its own session.
	ok, body := forwardRequest(t, owner, streamlocalForwardChannelType, sessionID)
	require.True(t, ok, body)
	ok, body = forwardRequest(t, owner, cancelStreamlocalForwardChannelType, sessionID)
	require.True(t, ok, body)
	_, err = s.sshd.SessionManager.GetSession(sessionID)
	require.Error(t, err)
	require.Equal(t, 0.0, s.gauge(t))
}

// blockingReleaseStore signals on entered when Release is called, then holds
// the call until release is closed.
type blockingReleaseStore struct {
	SessionStore
	entered chan struct{}
	release chan struct{}
}

func (s blockingReleaseStore) Release(ctx context.Context, reg *Registration) error {
	close(s.entered)
	<-s.release
	return s.SessionStore.Release(ctx, reg)
}

func Test_localSessions_SlowReleaseDoesNotBlockAdd(t *testing.T) {
	logger := logging.Must(logging.Console(), logging.Debug()).Logger
	store := blockingReleaseStore{
		SessionStore: newMemorySessionStore(logger),
		entered:      make(chan struct{}),
		release:      make(chan struct{}),
	}
	sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	mp, metrics := newTestMetrics(t)
	sessions := newLocalSessions(mp, sm, logger)

	slow, _, err := sm.Register(context.Background(), NewSession("slow", "node", "owen", nil, nil))
	require.NoError(t, err)
	_, err = sessions.add(slow, newCloser())
	require.NoError(t, err)
	other, _, err := sm.Register(context.Background(), NewSession("other", "node", "owen", nil, nil))
	require.NoError(t, err)

	ended := make(chan struct{})
	go func() {
		sessions.end(slow)
		close(ended)
	}()
	<-store.entered // end is now inside the store release

	// A Consul release can take a while; other hosts creating sessions must
	// not queue behind it.
	added := make(chan struct{})
	go func() {
		_, _ = sessions.add(other, newCloser())
		close(added)
	}()
	select {
	case <-added:
	case <-time.After(2 * time.Second):
		t.Fatal("add blocked behind a slow release")
	}

	close(store.release)
	<-ended
	v, ok := gatherValue(t, metrics, "test_server_sessions_active_count", nil)
	require.True(t, ok)
	require.Equal(t, 1.0, v)
}

// closer records a close; a second close is fine, as for a real connection.
type closer struct {
	once   sync.Once
	closed chan struct{}
}

func newCloser() *closer       { return &closer{closed: make(chan struct{})} }
func (c *closer) Close() error { c.once.Do(func() { close(c.closed) }); return nil }

func (c *closer) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func newTestLocalSessions(t *testing.T) (*localSessions, *SessionManager, func() float64) {
	t.Helper()
	logger := logging.Must(logging.Console(), logging.Debug()).Logger
	sm := newEmbeddedSessionManager(logger)
	mp, metrics := newTestMetrics(t)
	return newLocalSessions(mp, sm, logger), sm, func() float64 {
		v, _ := gatherValue(t, metrics, "test_server_sessions_active_count", nil)
		return v
	}
}

func Test_localSessions_TakeoverKeepsOneCount(t *testing.T) {
	sessions, sm, gauge := newTestLocalSessions(t)
	ctx := context.Background()
	gen1, _, err := sm.Register(ctx, &Session{ID: "id", NodeAddr: "node", Generation: 1})
	require.NoError(t, err)
	prev, err := sessions.add(gen1, newCloser())
	require.NoError(t, err)
	require.Nil(t, prev)
	gen2, _, err := sm.Register(ctx, &Session{ID: "id", NodeAddr: "node", Generation: 2})
	require.NoError(t, err)
	prev, err = sessions.add(gen2, newCloser())
	require.NoError(t, err)
	require.True(t, prev.reg.Same(gen1))
	require.Equal(t, 1.0, gauge())
	sessions.end(gen1)
	require.Equal(t, 1.0, gauge())
	got, err := sm.GetSession("id")
	require.NoError(t, err)
	require.Equal(t, uint64(2), got.Generation)
	sessions.end(gen2)
	require.Equal(t, 0.0, gauge())
}

// Review P1, at this layer: an older registration adopting after a newer one
// changes nothing and closes nothing.
func Test_localSessions_OlderAdoptionIsRefused(t *testing.T) {
	sessions, _, gauge := newTestLocalSessions(t)
	gen1 := &Registration{Session: &Session{ID: "id", NodeAddr: "node", Generation: 1}}
	gen2 := &Registration{Session: &Session{ID: "id", NodeAddr: "node", Generation: 2}}
	conn2 := newCloser()
	_, err := sessions.add(gen2, conn2)
	require.NoError(t, err)
	prev, err := sessions.add(gen1, newCloser())
	require.ErrorIs(t, err, ErrSuperseded)
	require.Nil(t, prev)
	require.True(t, sessions.active(gen2))
	require.False(t, conn2.isClosed())
	require.Equal(t, 1.0, gauge())
}

func Test_forwards_OldRegistrationCannotCloseTheNew(t *testing.T) {
	sessions, sm, _ := newTestLocalSessions(t)
	network := &MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))
	h := newStreamlocalForwardHandler(sm, network.Session(), sessions, slog.New(slog.DiscardHandler))
	ctx := context.Background()
	gen1, _, _ := sm.Register(ctx, &Session{ID: "id", NodeAddr: "node", Generation: 1})
	_, _ = sessions.add(gen1, newCloser())
	ln1, err := network.Session().Listen("id")
	require.NoError(t, err)
	h.trackListener(gen1, ln1)
	gen2, _, _ := sm.Register(ctx, &Session{ID: "id", NodeAddr: "node", Generation: 2})
	_, _ = sessions.add(gen2, newCloser())
	h.closeListener(gen1) // the takeover frees the socket name
	ln2, err := network.Session().Listen("id")
	require.NoError(t, err)
	h.trackListener(gen2, ln2)

	h.closeListener(gen1) // the old registration's late cleanup

	accepted := make(chan error, 1) // a bufconn dial blocks until accepted
	go func() {
		c, err := ln2.Accept()
		if err == nil {
			_ = c.Close()
		}
		accepted <- err
	}()
	dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	c, err := network.Session().DialContext(dctx, "id")
	require.NoError(t, err, "the new listener must still be open")
	_ = c.Close()
	require.NoError(t, <-accepted)
}

// Test_sshd_PublicKeyAuthority pins what the internal node door accepts. It has
// no authorized-key check of its own, so a certificate from a signer that is
// not one of this relay's own has to be refused outright.
func Test_sshd_PublicKeyAuthority(t *testing.T) {
	logger := logging.Must(logging.Console(), logging.Debug()).Logger

	relay, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	// A real signer, but not this relay's.
	other, err := ssh.ParsePrivateKey([]byte(HostPrivateKeyContent))
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	addr := ln.Addr().String()

	s := &sshd{
		SessionManager: func() *SessionManager {
			sm, _ := NewSessionManager(routing.ModeEmbedded,
				WithSessionManagerLogger(logger))
			return sm
		}(),
		HostSigners:     []ssh.Signer{relay},
		Signers:         []ssh.Signer{relay},
		NodeAddr:        addr,
		MetricsProvider: provider.NewDiscardProvider(),
		Logger:          logger,
	}
	go func() { _ = s.Serve(ln) }()
	defer func() { _ = s.Shutdown() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, utils.WaitForServer(ctx, addr))

	// mint is what a proxy hands the node door: a user certificate carrying an
	// AuthRequest, signed by the given key.
	mint := func(t *testing.T, signer ssh.Signer) ssh.Signer {
		t.Helper()

		cs := UserCertSigner{
			SessionID: "1234",
			User:      "owen",
			AuthRequest: &AuthRequest{
				ClientVersion: upterm.HostSSHClientVersion,
				RemoteAddr:    addr,
				AuthorizedKey: []byte(TestPublicKeyContent),
			},
		}
		certSigner, err := cs.SignCert(signer)
		require.NoError(t, err)
		return certSigner
	}

	cases := []struct {
		name    string
		auth    func(t *testing.T) ssh.Signer
		wantErr bool
	}{
		{"a certificate this relay minted is admitted", func(t *testing.T) ssh.Signer { return mint(t, relay) }, false},
		{"a certificate from another signer is refused", func(t *testing.T) ssh.Signer { return mint(t, other) }, true},
		{"a plain public key is refused", func(t *testing.T) ssh.Signer { return relay }, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
				User:            "owen",
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(tc.auth(t))},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         10 * time.Second,
			})
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "unable to authenticate")
				return
			}
			require.NoError(t, err)
			_ = client.Close()
		})
	}
}

func Test_sshd_ClosesTunnelChannelWhenGuestLeaves(t *testing.T) {
	s := newTestSSHD(t)

	client := s.dial(t)
	incoming := client.HandleChannelOpen(forwardedStreamlocalChannelType)
	sessionID := s.createSession(t, client)
	ok, body := forwardRequest(t, client, streamlocalForwardChannelType, sessionID)
	require.True(t, ok, body)

	// The relay dials the session socket on a guest's behalf, which opens a
	// forwarded channel to the host.
	guest, err := s.network.Session().Dial(sessionID)
	require.NoError(t, err)
	var newCh ssh.NewChannel
	select {
	case newCh = <-incoming:
	case <-time.After(5 * time.Second):
		t.Fatal("host never received the forwarded channel")
	}
	ch, reqs, err := newCh.Accept()
	require.NoError(t, err)
	go ssh.DiscardRequests(reqs)

	// The guest goes away. The host must learn of it without having to
	// write anything first: that is what drives its client-left event.
	require.NoError(t, guest.Close())
	read := make(chan error, 1)
	go func() {
		_, err := ch.Read(make([]byte, 1))
		read <- err
	}()
	select {
	case err := <-read:
		require.ErrorIs(t, err, io.EOF)
	case <-time.After(2 * time.Second):
		t.Fatal("channel stayed open after the guest disconnected")
	}
}

func Test_sshd_ProvenRegistrationDerivesTheID(t *testing.T) {
	for _, gated := range []bool{false, true} {
		s := newTestSSHD(t, func(d *sshd) { d.HostGateEnabled = gated })
		host := newProven(t)
		ok, body := host.register(t, s.dialAs(t, "conn-1"), "conn-1", 1)
		require.True(t, ok, string(body))
		var resp CreateSessionResponse
		require.NoError(t, proto.Unmarshal(body, &resp))
		require.Equal(t, host.id(), resp.SessionID)
		require.Equal(t, !gated, resp.SessionKeyRedial)
		sess, err := s.sshd.SessionManager.GetSession(resp.SessionID)
		require.NoError(t, err)
		require.Equal(t, uint64(1), sess.Generation)
	}
}

// Review Focus 1 and 2.
func Test_sshd_ProofRefusals(t *testing.T) {
	s := newTestSSHD(t)
	host, other := newProven(t), newProven(t)
	sign := func(t *testing.T, key ssh.Signer, keyID string, gen uint64) []byte {
		p, err := registration.Sign(key, []byte(keyID), host.secret, gen)
		require.NoError(t, err)
		return p
	}
	for name, send := range map[string]func(t *testing.T, c *ssh.Client) (bool, []byte){
		"another key": func(t *testing.T, c *ssh.Client) (bool, []byte) {
			return host.send(t, c, 1, sign(t, other.key, "conn-1", 1), host.hostKeys())
		},
		"another connection": func(t *testing.T, c *ssh.Client) (bool, []byte) {
			return host.send(t, c, 1, sign(t, host.key, "conn-2", 1), host.hostKeys())
		},
		"tampered generation": func(t *testing.T, c *ssh.Client) (bool, []byte) {
			return host.send(t, c, 2, sign(t, host.key, "conn-1", 1), host.hostKeys())
		},
		"malformed": func(t *testing.T, c *ssh.Client) (bool, []byte) {
			return host.send(t, c, 1, []byte("junk"), host.hostKeys())
		},
		"two host keys": func(t *testing.T, c *ssh.Client) (bool, []byte) {
			return host.send(t, c, 1, sign(t, host.key, "conn-1", 1), append(host.hostKeys(), other.hostKeys()...))
		},
		"short secret": func(t *testing.T, c *ssh.Client) (bool, []byte) {
			return proven{host.key, host.secret[:8]}.send(t, c, 1, sign(t, host.key, "conn-1", 1), host.hostKeys())
		},
		"generation zero": func(t *testing.T, c *ssh.Client) (bool, []byte) {
			return host.send(t, c, 0, sign(t, host.key, "conn-1", 1), host.hostKeys())
		},
	} {
		t.Run(name, func(t *testing.T) {
			ok, body := send(t, s.dialAs(t, "conn-1"))
			require.False(t, ok)
			require.Contains(t, string(body), registration.RefusedProof)
			_, err := s.sshd.SessionManager.GetSession(host.id())
			require.Error(t, err)
		})
	}
}

func Test_sshd_NewerRegistrationSupersedesTheOlder(t *testing.T) {
	s := newTestSSHD(t)
	host := newProven(t)
	first := s.dialAs(t, "conn-1")
	ok, body := host.register(t, first, "conn-1", 1)
	require.True(t, ok, string(body))
	ok, reason := forwardRequest(t, first, streamlocalForwardChannelType, host.id())
	require.True(t, ok, reason)

	second := s.dialAs(t, "conn-2")
	ok, body = host.register(t, second, "conn-2", 2)
	require.True(t, ok, string(body))
	waitClosed(t, first, "the superseded registration's connection (I5)")
	require.Equal(t, 1.0, s.gauge(t))
	ok, reason = forwardRequest(t, second, streamlocalForwardChannelType, host.id())
	require.True(t, ok, reason)

	ok, body = host.register(t, s.dialAs(t, "conn-3"), "conn-3", 1)
	require.False(t, ok)
	require.Equal(t, registration.Superseded, string(body))
}

// Review P1, end to end: generation 1 commits, then pauses before adoption
// while generation 2 commits and adopts. When 1 resumes it is refused, and 2
// keeps its connection and its listener.
func Test_sshd_DelayedAdoptionCannotEvictItsReplacement(t *testing.T) {
	var stall sync.Once
	paused, resume := make(chan struct{}), make(chan struct{})
	s := newTestSSHD(t, func(d *sshd) {
		d.onRegistered = func(reg *Registration) {
			if reg.Generation() == 1 {
				stall.Do(func() { close(paused); <-resume })
			}
		}
	})
	host := newProven(t)
	first := s.dialAs(t, "conn-1")
	// Signed here: require must not run on the goroutine below.
	proof, err := registration.Sign(host.key, []byte("conn-1"), host.secret, 1)
	require.NoError(t, err)
	req, err := proto.Marshal(&CreateSessionRequest{HostUser: "owen", HostPublicKeys: host.hostKeys(),
		SessionSecret: host.secret, Generation: 1, HostKeyProof: proof})
	require.NoError(t, err)
	type reply struct {
		body []byte
		err  error
	}
	result := make(chan reply, 1)
	go func() {
		_, body, err := first.SendRequest(upterm.ServerCreateSessionRequestType, true, req)
		result <- reply{body, err}
	}()
	<-paused

	second := s.dialAs(t, "conn-2")
	incoming := second.HandleChannelOpen(forwardedStreamlocalChannelType)
	ok, body := host.register(t, second, "conn-2", 2)
	require.True(t, ok, string(body))
	ok, reason := forwardRequest(t, second, streamlocalForwardChannelType, host.id())
	require.True(t, ok, reason)

	close(resume)
	r := <-result
	require.NoError(t, r.err)
	require.Equal(t, registration.Superseded, string(r.body))
	sess, err := s.sshd.SessionManager.GetSession(host.id())
	require.NoError(t, err)
	require.Equal(t, uint64(2), sess.Generation)

	// Generation 2's listener still routes to generation 2's connection.
	guest, err := s.network.Session().Dial(host.id())
	require.NoError(t, err, "generation 2's listener was closed")
	defer func() { _ = guest.Close() }()
	select {
	case ch := <-incoming:
		_ = ch.Reject(ssh.Prohibited, "test") // sshd_test.go imports x/crypto/ssh as ssh
	case <-time.After(2 * time.Second):
		t.Fatal("a guest reaching the session socket never reached generation 2")
	}
}
