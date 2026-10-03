package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gliderssh "charm.land/ssh"
	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/internal/liveness"
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
	client, err := ssh.Dial("tcp", s.addr, s.proxyConfig(t, keyID))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// proxyConfig is the client configuration of a connection made as the proxy
// does on behalf of a host whose own connection has the SSH session ID keyID.
func (s *testSSHD) proxyConfig(t *testing.T, keyID string) *ssh.ClientConfig {
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
	return &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		User:            "owen",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

// freezableConn is a client's end of a connection that can go silent: once
// frozen it delivers nothing more to the client, as a peer whose network has
// gone away does, until thawed.
type freezableConn struct {
	net.Conn
	frozen, thawed chan struct{}
}

func (c *freezableConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	// Checked after the read, so that bytes already on their way when the conn
	// froze are held back too.
	select {
	case <-c.frozen:
		<-c.thawed
	default:
	}
	return n, err
}

// dialFreezable is dialAs over a connection that freeze silences. The test's
// cleanup thaws it, so the client's read loop can end.
func (s *testSSHD) dialFreezable(t *testing.T, keyID string) (*ssh.Client, func()) {
	t.Helper()
	raw, err := net.Dial("tcp", s.addr)
	require.NoError(t, err)
	conn := &freezableConn{Conn: raw, frozen: make(chan struct{}), thawed: make(chan struct{})}
	t.Cleanup(func() { close(conn.thawed) })
	c, chans, reqs, err := ssh.NewClientConn(conn, s.addr, s.proxyConfig(t, keyID))
	require.NoError(t, err)
	client := ssh.NewClient(c, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	var once sync.Once
	return client, func() { once.Do(func() { close(conn.frozen) }) }
}

// dialMute is dialAs over a connection whose client never answers the relay's
// global requests, as a host does whose replies sit behind queued output, and
// which sends bytes of its own every `every` until stop is called.
//
// pings counts the keepalives the relay has sent it. stop ends the sending,
// waits for it to end, and returns when the last send began: before the write,
// so that the relay can't have read those bytes any earlier.
func (s *testSSHD) dialMute(t *testing.T, keyID string, every time.Duration) (*ssh.Client, *atomic.Int64, func() time.Time) {
	t.Helper()
	raw, err := net.Dial("tcp", s.addr)
	require.NoError(t, err)
	c, chans, reqs, err := ssh.NewClientConn(raw, s.addr, s.proxyConfig(t, keyID))
	require.NoError(t, err)
	pings := new(atomic.Int64)
	go func() { // taken and counted, never answered
		for req := range reqs {
			if req.Type == "keepalive@openssh.com" {
				pings.Add(1)
			}
		}
	}()
	none := make(chan *ssh.Request) // NewClient answers nothing from here
	t.Cleanup(func() { close(none) })
	client := ssh.NewClient(c, chans, none)
	t.Cleanup(func() { _ = client.Close() })
	quit, ended := make(chan struct{}), make(chan struct{})
	var lastSent time.Time // the sender's, to be read once it has ended
	go func() {
		defer close(ended)
		for {
			select {
			case <-quit:
				return
			case <-time.After(every):
				sent := time.Now()
				if _, _, err := client.SendRequest("keepalive@openssh.com", false, nil); err == nil {
					lastSent = sent
				}
			}
		}
	}()
	var once sync.Once
	stop := func() time.Time {
		once.Do(func() { close(quit) })
		<-ended
		return lastSent
	}
	t.Cleanup(func() { stop() }) // so a test that fails early doesn't leave it sending
	return client, pings, stop
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
	at     time.Time // when it was first closed; read it only once closed is
}

func newCloser() *closer { return &closer{closed: make(chan struct{})} }

func (c *closer) Close() error {
	c.once.Do(func() {
		c.at = time.Now()
		close(c.closed)
	})
	return nil
}

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

// At the node: an older registration adopting after a newer one changes
// nothing and closes nothing.
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

// A rebuild swaps the handle in the slot and nothing else: the slot keeps the
// connection, the keeper's stop and whatever else it holds.
func Test_localSessions_ReplaceKeepsTheSlot(t *testing.T) {
	sessions, _, _ := newTestLocalSessions(t)
	reg := &Registration{Session: &Session{ID: "id", NodeAddr: "node", Generation: 1}, lease: "lost"}
	_, err := sessions.add(reg, newCloser())
	require.NoError(t, err)
	slot := func() *localRegistration {
		sessions.mu.Lock()
		defer sessions.mu.Unlock()
		return sessions.regs["id"]
	}
	before := slot()
	rebuilt := &Registration{Session: reg.Session, lease: "rebuilt"}
	require.True(t, sessions.replace(rebuilt))
	require.Same(t, before, slot())
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	require.Same(t, rebuilt, before.reg)
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

// Takeovers on this node can overlap: generation 2 adopts, but before it
// closes generation 1's listener, generation 3 adopts and closes generation
// 2's, which never bound one. Generation 3's forward still binds: the listener
// of a registration this node no longer serves is closed first, and ending
// that registration leaves generation 3's entry and slot alone. Generation
// 3's own listener is never closed that way.
func Test_forwards_OverlappingTakeoversBindTheLatest(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	store := &releaseRecordingStore{SessionStore: newMemorySessionStore(logger)}
	sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	mp, metrics := newTestMetrics(t)
	sessions := newLocalSessions(mp, sm, logger)
	gauge := func() float64 {
		v, _ := gatherValue(t, metrics, "test_server_sessions_active_count", nil)
		return v
	}
	network := &MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))
	h := newStreamlocalForwardHandler(sm, network.Session(), sessions, logger)
	register := func(gen uint64) *Registration {
		reg, _, err := sm.Register(context.Background(), &Session{ID: "id", NodeAddr: "node", Generation: gen})
		require.NoError(t, err)
		return reg
	}

	gen1 := register(1)
	_, err := sessions.add(gen1, newCloser())
	require.NoError(t, err)
	ln1, err := h.bind(gen1)
	require.NoError(t, err)

	// Generation 2 adopts, and is held up before it closes generation 1's
	// listener.
	gen2 := register(2)
	prev1, err := sessions.add(gen2, newCloser())
	require.NoError(t, err)

	// Generation 3 adopts in full, and its host forwards.
	gen3 := register(3)
	prev2, err := sessions.add(gen3, newCloser())
	require.NoError(t, err)
	h.closeListener(prev2.reg)
	require.NoError(t, prev2.conn.Close())
	ln3, err := h.bind(gen3)
	require.NoError(t, err, "an older takeover's listener kept the socket from the latest registration")
	defer h.closeListener(gen3)

	accepted := make(chan error, 1)
	go func() {
		_, err := ln1.Accept()
		accepted <- err
	}()
	select {
	case err := <-accepted:
		require.Error(t, err, "generation 1's listener accepted a connection")
	case <-time.After(2 * time.Second):
		t.Fatal("generation 1's listener is still open")
	}
	// Generation 1 is ended in the background; once it has been released,
	// generation 3's entry and slot are still in place.
	require.Eventually(t, func() bool { return store.releasedHandle(gen1) }, 2*time.Second, 10*time.Millisecond,
		"generation 1 was never ended")
	require.True(t, sessions.active(gen3))
	require.Equal(t, 1.0, gauge())
	sess, err := sm.GetSession("id")
	require.NoError(t, err)
	require.Equal(t, uint64(3), sess.Generation, "ending generation 1 removed generation 3's entry")

	// A second forward from the registration this node serves still fails,
	// rather than closing its own listener.
	_, err = h.bind(gen3)
	require.Error(t, err)
	require.True(t, sessions.active(gen3))

	// Generation 2 resumes: generation 1's listener is gone already, and
	// generation 3's stays.
	h.closeListener(prev1.reg)
	require.NoError(t, prev1.conn.Close())
	go func() {
		c, err := ln3.Accept()
		if err == nil {
			_ = c.Close()
		}
		accepted <- err
	}()
	dctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := network.Session().DialContext(dctx, "id")
	require.NoError(t, err, "generation 3's listener was closed")
	_ = c.Close()
	require.NoError(t, <-accepted)
}

// testConnContext stands in for a host connection's context, for tests that
// drive the node's handlers without an SSH connection. It carries no
// connection, so nothing may be dialed through it.
type testConnContext struct {
	context.Context
	sync.Mutex // the connection lock an ssh.Context carries

	valuesMu sync.Mutex
	values   map[any]any
}

func newTestConnContext(t *testing.T) (*testConnContext, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &testConnContext{
		Context: ctx,
		values:  map[any]any{gliderssh.ContextKeyConn: (*ssh.ServerConn)(nil)},
	}, cancel
}

func (c *testConnContext) Value(key any) any {
	c.valuesMu.Lock()
	v, ok := c.values[key]
	c.valuesMu.Unlock()
	if ok {
		return v
	}
	return c.Context.Value(key)
}

func (c *testConnContext) SetValue(key, value any) {
	c.valuesMu.Lock()
	defer c.valuesMu.Unlock()
	c.values[key] = value
}

func (*testConnContext) User() string                        { return "owen" }
func (*testConnContext) SessionID() string                   { return "" }
func (*testConnContext) ClientVersion() string               { return "" }
func (*testConnContext) ServerVersion() string               { return "" }
func (*testConnContext) RemoteAddr() net.Addr                { return nil }
func (*testConnContext) LocalAddr() net.Addr                 { return nil }
func (*testConnContext) Permissions() *gliderssh.Permissions { return nil }

// pausingGetStore holds the first Get until release is closed, and closes
// entered when that Get arrives.
type pausingGetStore struct {
	SessionStore
	once             sync.Once
	entered, release chan struct{}
}

func (s *pausingGetStore) Get(sessionID string) (*Session, error) {
	s.once.Do(func() {
		close(s.entered)
		<-s.release
	})
	return s.SessionStore.Get(sessionID)
}

// A takeover on this node closes the old registration's listener before the
// new host binds the socket's name. A forward the old registration began
// before the takeover, and that is still reading the store, must not bind in
// between: it is refused, and the new host's forward binds.
func Test_forwards_ATakeoverRefusesAnOldForwardInFlight(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	store := &pausingGetStore{
		SessionStore: newMemorySessionStore(logger),
		entered:      make(chan struct{}),
		release:      make(chan struct{}),
	}
	sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	mp, _ := newTestMetrics(t)
	sessions := newLocalSessions(mp, sm, logger)
	network := &MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))
	h := newStreamlocalForwardHandler(sm, network.Session(), sessions, logger)
	srv := &gliderssh.Server{ReversePortForwardingCallback: func(gliderssh.Context, string, uint32) bool { return true }}
	forward := func(conn gliderssh.Context) (bool, []byte) {
		return h.Handler(conn, srv, &ssh.Request{
			Type:    streamlocalForwardChannelType,
			Payload: ssh.Marshal(&streamlocalChannelForwardMsg{SocketPath: "id"}),
		})
	}
	ctx := context.Background()

	gen1, _, err := sm.Register(ctx, &Session{ID: "id", NodeAddr: "node", Generation: 1})
	require.NoError(t, err)
	_, err = sessions.add(gen1, newCloser())
	require.NoError(t, err)
	conn1, closeConn1 := newTestConnContext(t)
	ownSession(conn1, gen1)
	old := make(chan bool, 1)
	go func() {
		ok, _ := forward(conn1)
		old <- ok
	}()
	select {
	case <-store.entered: // past its first check, and reading the store
	case <-time.After(5 * time.Second):
		t.Fatal("the old forward never reached the store")
	}

	// The takeover, in adopt's order.
	gen2, _, err := sm.Register(ctx, &Session{ID: "id", NodeAddr: "node", Generation: 2})
	require.NoError(t, err)
	prev, err := sessions.add(gen2, newCloser())
	require.NoError(t, err)
	h.evict(prev.reg)
	closeConn1()

	close(store.release)
	select {
	case ok := <-old:
		require.False(t, ok, "the old forward bound the socket after the takeover")
	case <-time.After(5 * time.Second):
		t.Fatal("the old forward never finished")
	}

	conn2, _ := newTestConnContext(t)
	ownSession(conn2, gen2)
	ok, body := forward(conn2)
	require.True(t, ok, string(body))
}

// releaseRecordingStore records every handle it is asked to release, and its
// lease.
type releaseRecordingStore struct {
	SessionStore
	mu      sync.Mutex
	leases  []string
	handles []*Registration
}

func (s *releaseRecordingStore) Release(ctx context.Context, reg *Registration) error {
	err := s.SessionStore.Release(ctx, reg)
	s.mu.Lock()
	s.leases = append(s.leases, reg.lease)
	s.handles = append(s.handles, reg)
	s.mu.Unlock()
	return err
}

// releasedHandle reports whether reg itself has been released.
func (s *releaseRecordingStore) releasedHandle(reg *Registration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.handles, reg)
}

func (s *releaseRecordingStore) released(lease string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.leases, lease)
}

// A takeover on this node releases the lease its keeper rebuilt for the old
// registration, though no listener was bound for evict to end it with: the
// old connection's cleanup only knows the handle it was adopted with, and the
// rebuilt lease would otherwise linger until it expired.
func Test_sshd_TakeoverReleasesARebuiltLease(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	store := &releaseRecordingStore{SessionStore: newMemorySessionStore(logger)}
	sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	mp, _ := newTestMetrics(t)
	sessions := newLocalSessions(mp, sm, logger)
	network := &MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))
	s := &sshd{
		SessionManager: sm,
		Logger:         logger,
		sessions:       sessions,
		forwardHandler: newStreamlocalForwardHandler(sm, network.Session(), sessions, logger),
	}

	adopted := &Registration{Session: &Session{ID: "id", NodeAddr: "node", Generation: 1}, lease: "adopted"}
	oldConn := newCloser()
	_, err := sessions.add(adopted, oldConn)
	require.NoError(t, err)
	require.True(t, sessions.replace(&Registration{Session: adopted.Session, lease: "rebuilt"}))

	next := &Registration{Session: &Session{ID: "id", NodeAddr: "node", Generation: 2}, lease: "next"}
	conn, _ := newTestConnContext(t)
	ok, refusal := s.adopt(conn, next, nil)
	require.True(t, ok, string(refusal))
	require.True(t, oldConn.isClosed())
	require.Eventually(t, func() bool { return store.released("rebuilt") }, 2*time.Second, 10*time.Millisecond,
		"the rebuilt lease was left to expire")
	require.False(t, store.released("next"), "the takeover released the new registration")
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

// Without a proof, the secret and generation a request carries count for
// nothing: it gets a random ID at generation 0, as an old host always has, and
// the ID they would derive stays unclaimed.
func Test_sshd_UnprovenRequestGetsARandomID(t *testing.T) {
	s := newTestSSHD(t)
	host := newProven(t)
	ok, body := host.send(t, s.dialAs(t, "conn-1"), 3, nil, host.hostKeys())
	require.True(t, ok, string(body))
	var resp CreateSessionResponse
	require.NoError(t, proto.Unmarshal(body, &resp))
	require.NotEqual(t, host.id(), resp.SessionID)
	sess, err := s.sshd.SessionManager.GetSession(resp.SessionID)
	require.NoError(t, err)
	require.Zero(t, sess.Generation)
	_, err = s.sshd.SessionManager.GetSession(host.id())
	require.Error(t, err)
}

// A proof is refused, and the derived ID left unregistered, when it was signed
// by another key, over another connection or for another generation; when it
// doesn't parse; when the request names two host keys, or one that doesn't
// parse; when its secret is short or its generation zero; and when the
// connection carries no SSH session ID to verify it over.
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
		"unparseable host key": func(t *testing.T, c *ssh.Client) (bool, []byte) {
			return host.send(t, c, 1, sign(t, host.key, "conn-1", 1), [][]byte{[]byte("not a key")})
		},
		"no SSH session ID": func(t *testing.T, _ *ssh.Client) (bool, []byte) {
			return host.send(t, s.dialAs(t, ""), 1, sign(t, host.key, "conn-1", 1), host.hostKeys())
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
	waitClosed(t, first, "the superseded registration's connection")
	require.Equal(t, 1.0, s.gauge(t))
	ok, reason = forwardRequest(t, second, streamlocalForwardChannelType, host.id())
	require.True(t, ok, reason)

	ok, body = host.register(t, s.dialAs(t, "conn-3"), "conn-3", 1)
	require.False(t, ok)
	require.Equal(t, registration.Superseded, string(body))
}

// slot returns the registration this node serves for id, as its local
// sessions hold it.
func (s *testSSHD) slot(id string) *localRegistration {
	s.sshd.mux.Lock()
	sessions := s.sshd.sessions
	s.sshd.mux.Unlock()
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	return sessions.regs[id]
}

// A host that registers the same generation again over another connection,
// say after losing the first reply, is refused: that is the same registration,
// and the first connection's cleanup, which ends it, would take the second's
// slot and entry along. The next generation takes over as usual.
func Test_sshd_SameGenerationFromAnotherConnectionIsRefused(t *testing.T) {
	s := newTestSSHD(t)
	host := newProven(t)
	first := s.dialAs(t, "conn-1")
	incoming := first.HandleChannelOpen(forwardedStreamlocalChannelType)
	ok, body := host.register(t, first, "conn-1", 1)
	require.True(t, ok, string(body))
	ok, reason := forwardRequest(t, first, streamlocalForwardChannelType, host.id())
	require.True(t, ok, reason)
	before := s.slot(host.id())
	require.NotNil(t, before)

	second := s.dialAs(t, "conn-2")
	ok, body = host.register(t, second, "conn-2", 1)
	require.False(t, ok)
	require.Equal(t, registration.Superseded, string(body))
	require.Same(t, before, s.slot(host.id()), "the refused registration touched the first one's slot")
	sess, err := s.sshd.SessionManager.GetSession(host.id())
	require.NoError(t, err)
	require.Equal(t, uint64(1), sess.Generation)
	// The first registration's listener still routes to its connection.
	guest, err := s.network.Session().Dial(host.id())
	require.NoError(t, err, "the first registration's listener was closed")
	select {
	case ch := <-incoming:
		_ = ch.Reject(ssh.Prohibited, "test")
	case <-time.After(2 * time.Second):
		t.Fatal("a guest reaching the session socket never reached the first connection")
	}
	_ = guest.Close()

	ok, body = host.register(t, second, "conn-2", 2)
	require.True(t, ok, string(body))
	waitClosed(t, first, "the superseded registration's connection")
	sess, err = s.sshd.SessionManager.GetSession(host.id())
	require.NoError(t, err)
	require.Equal(t, uint64(2), sess.Generation)
}

// At the node: another connection's registration of the generation this node
// already serves is refused, even when the store took it, as it does once the
// entry is gone; the connection that holds the slot may register again.
func Test_localSessions_SameGenerationFromAnotherConnectionIsRefused(t *testing.T) {
	sessions, _, gauge := newTestLocalSessions(t)
	reg := &Registration{Session: &Session{ID: "id", NodeAddr: "node", Generation: 1}}
	conn := newCloser()
	_, err := sessions.add(reg, conn)
	require.NoError(t, err)
	again := &Registration{Session: &Session{ID: "id", NodeAddr: "node", Generation: 1}}
	prev, err := sessions.add(again, newCloser())
	require.ErrorIs(t, err, ErrSuperseded)
	require.Nil(t, prev)
	require.True(t, sessions.active(reg))
	require.False(t, conn.isClosed())
	prev, err = sessions.add(again, conn)
	require.NoError(t, err, "the connection that holds the slot")
	require.Same(t, reg, prev.reg)
	require.Equal(t, 1.0, gauge())
}

// A host that goes while its registration is being stored leaves nothing
// behind: the node releases the registration rather than holding the ID for
// no one.
func Test_sshd_RegistrationOfAGoneHostIsReleased(t *testing.T) {
	clients, registered := make(chan *ssh.Client, 1), make(chan string, 1)
	s := newTestSSHD(t, func(d *sshd) {
		d.onRegistered = func(ctx context.Context, reg *Registration) {
			_ = (<-clients).Close()
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
			registered <- reg.ID()
		}
	})
	host := newProven(t)
	client := s.dialAs(t, "conn-1")
	clients <- client
	proof, err := registration.Sign(host.key, []byte("conn-1"), host.secret, 1)
	require.NoError(t, err)
	req, err := proto.Marshal(&CreateSessionRequest{HostUser: "owen", HostPublicKeys: host.hostKeys(),
		SessionSecret: host.secret, Generation: 1, HostKeyProof: proof})
	require.NoError(t, err)
	_, _, err = client.SendRequest(upterm.ServerCreateSessionRequestType, true, req)
	require.Error(t, err, "the host went before its reply")

	select {
	case id := <-registered: // the store took it before the host went
		require.Equal(t, host.id(), id)
	case <-time.After(5 * time.Second):
		t.Fatal("the registration never reached the store")
	}
	require.Eventually(t, func() bool {
		_, err := s.sshd.SessionManager.GetSession(host.id())
		return err != nil
	}, 5*time.Second, 10*time.Millisecond, "the registration outlived its host")
	require.Equal(t, 0.0, s.gauge(t))
}

// End to end: generation 1 commits, then pauses before adoption
// while generation 2 commits and adopts. When 1 resumes it is refused, and 2
// keeps its connection and its listener.
func Test_sshd_DelayedAdoptionCannotEvictItsReplacement(t *testing.T) {
	var stall sync.Once
	paused, resume := make(chan struct{}), make(chan struct{})
	s := newTestSSHD(t, func(d *sshd) {
		d.onRegistered = func(_ context.Context, reg *Registration) {
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
	select {
	case <-paused:
	case <-time.After(5 * time.Second):
		t.Fatal("generation 1 never reached adoption")
	}

	second := s.dialAs(t, "conn-2")
	incoming := second.HandleChannelOpen(forwardedStreamlocalChannelType)
	ok, body := host.register(t, second, "conn-2", 2)
	require.True(t, ok, string(body))
	ok, reason := forwardRequest(t, second, streamlocalForwardChannelType, host.id())
	require.True(t, ok, reason)

	close(resume)
	var r reply
	select {
	case r = <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("generation 1 never got a reply")
	}
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
		_ = ch.Reject(ssh.Prohibited, "test")
	case <-time.After(2 * time.Second):
		t.Fatal("a guest reaching the session socket never reached generation 2")
	}
}

// A reconnect-capable host's connection is pinged, and closed when it goes
// silent, so its registration doesn't outlive a host that went without a
// word. A legacy host can't redial, so its connection is left alone however
// quiet.
func Test_sshd_PingsOnlyCapableHosts(t *testing.T) {
	s := newTestSSHD(t, func(d *sshd) {
		d.liveness = liveness.Timing{Interval: 50 * time.Millisecond, Bound: 50 * time.Millisecond}
	})
	legacy, freezeLegacy := s.dialFreezable(t, "legacy")
	legacyID := s.createSession(t, legacy)
	host := newProven(t)
	capable, freezeCapable := s.dialFreezable(t, "capable")
	ok, body := host.register(t, capable, "capable", 1)
	require.True(t, ok, string(body))

	freezeLegacy()
	freezeCapable()
	require.Eventually(t, func() bool { _, err := s.sshd.SessionManager.GetSession(host.id()); return err != nil },
		2*time.Second, 10*time.Millisecond, "a silent capable host is closed")
	require.Never(t, func() bool { _, err := s.sshd.SessionManager.GetSession(legacyID); return err != nil },
		500*time.Millisecond, 20*time.Millisecond, "a legacy host is never pinged")
}

// A capable host whose replies queue behind its own output is alive for as long
// as that output arrives: the relay pings it, and closes it for the silence
// that follows its last byte, not for a reply that hadn't come.
func Test_sshd_KeepsACapableHostWhoseRepliesQueueBehindData(t *testing.T) {
	// The mute client's bytes come every 100 ms, twice Interval, so the relay
	// has to ping it between them, and no reply ever comes. Bound is long
	// enough that the 2*Bound window below outlasts a deadline on that reply
	// but never a silence, which each byte resets.
	timing := liveness.Timing{Interval: 50 * time.Millisecond, Bound: 300 * time.Millisecond}
	s := newTestSSHD(t, func(d *sshd) { d.liveness = timing })
	host := newProven(t)
	client, pings, stopSending := s.dialMute(t, "mute", 100*time.Millisecond)
	ok, body := host.register(t, client, "mute", 1)
	require.True(t, ok, string(body))
	gone := func() bool { _, err := s.sshd.SessionManager.GetSession(host.id()); return err != nil }

	require.Never(t, gone, 2*timing.Bound, 10*time.Millisecond,
		"a host whose bytes kept arriving was closed for a reply that hadn't come")
	require.Positive(t, pings.Load(), "the relay never pinged: nothing here was left waiting for a reply")

	lastSent := stopSending()
	require.False(t, lastSent.IsZero(), "the client never sent a byte")
	silent := lastSent.Add(timing.Interval + timing.Bound)
	limit := silent.Add(2 * lateWake)
	for !gone() {
		require.True(t, time.Now().Before(limit), "a silent host was kept")
		time.Sleep(2 * time.Millisecond)
	}
	requireClosedAt(t, time.Now(), silent, "its last byte plus Interval+Bound")
}

// A host is judged by what it sends the proxy, not by what crosses the
// proxy-to-sshd connection. With maxSSHConcurrentChannelOpens guest opens
// pending on a host that answers none of them, the proxy rejects every further
// open itself, so a silent host whose guests keep retrying would be kept alive
// forever by the sshd's own connection, and its dead registration with it.
//
// The test plays the proxy: it records the reads of the host-facing connection
// and registers it with the sshd's hostActivity, under the session ID the
// certificate carries.
func Test_sshd_ProxyTrafficDoesNotKeepASilentHostAlive(t *testing.T) {
	timing := liveness.Timing{Interval: 100 * time.Millisecond, Bound: 400 * time.Millisecond}
	activity := newHostActivity()
	s := newTestSSHD(t, func(d *sshd) {
		d.liveness = timing
		d.hostActivity = activity
		d.Logger = slog.New(slog.DiscardHandler)
	})
	var hostFacing *liveness.Conn // set before forwardTestPairWrapped returns
	hostPeer, downstream := forwardTestPairWrapped(t, nil, nil, func(c net.Conn) net.Conn {
		hostFacing = liveness.NewConn(c)
		return hostFacing
	})
	t.Cleanup(activity.track([]byte("outer"), hostFacing))

	raw, err := net.Dial("tcp", s.addr)
	require.NoError(t, err)
	c, chans, reqs, err := ssh.NewClientConn(raw, s.addr, s.proxyConfig(t, "outer"))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_ = forwardSSH(ctx, downstream, sshPeer{conn: c, channels: chans, requests: reqs}, abortChannel, discardCounter)
	}()
	t.Cleanup(func() { cancel(); <-finished })

	// The host takes what the relay sends it and answers none of it.
	var hostOpens, hostPings atomic.Int64
	go func() {
		for range hostPeer.channels {
			hostOpens.Add(1)
		}
	}()
	go func() {
		for range hostPeer.requests {
			hostPings.Add(1)
		}
	}()
	noChans := make(chan ssh.NewChannel)
	noReqs := make(chan *ssh.Request)
	client := ssh.NewClient(hostPeer.conn, noChans, noReqs)
	t.Cleanup(func() { close(noChans); close(noReqs); _ = client.Close() })
	host := newProven(t)
	ok, body := host.register(t, client, "outer", 1)
	require.True(t, ok, string(body))
	ok, reason := forwardRequest(t, client, streamlocalForwardChannelType, host.id())
	require.True(t, ok, reason)
	// The host has now said everything it will. The proxy's read of it is the
	// last byte the silence is counted from: read here, once the reply is in,
	// it can't be earlier than the host's last write.
	lastByte := hostFacing.LastRead()
	silent := lastByte.Add(timing.Interval + timing.Bound)

	gone := func() bool { _, err := s.sshd.SessionManager.GetSession(host.id()); return err != nil }
	var guests []net.Conn
	dialGuest := func() {
		if guest, err := s.network.Session().DialContext(ctx, host.id()); err == nil {
			guests = append(guests, guest)
		}
	}
	for range maxSSHConcurrentChannelOpens {
		dialGuest()
	}
	require.Eventually(t, func() bool { return hostOpens.Load() == maxSSHConcurrentChannelOpens }, time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return hostPings.Load() > 0 }, 400*time.Millisecond, time.Millisecond)

	// From here every guest open is one the proxy rejects without a word from
	// the host, each a read on the sshd's connection, twice per Interval.
	stop, retried := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(retried)
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				dialGuest()
			}
		}
	}()
	t.Cleanup(func() {
		for _, guest := range guests {
			_ = guest.Close()
		}
	})
	defer func() { close(stop); <-retried }()

	limit := silent.Add(lateWake)
	for !gone() {
		require.True(t, time.Now().Before(limit),
			"proxy-generated channel rejections kept a host that sent nothing alive past its silence budget")
		time.Sleep(time.Millisecond)
	}
	requireClosedAt(t, time.Now(), silent, "the host's last byte plus Interval+Bound")
	require.Equal(t, lastByte, hostFacing.LastRead(), "the host sent something after its last byte, so the silence was not its own")
}

// advancingConn is a liveness.Conn whose reads advance every interval until
// stop is called, as the proxy's connection from a host does while the host
// sends. It carries no SSH: the test only needs a connection that registers
// activity.
func advancingConn(t *testing.T, interval time.Duration) (*liveness.Conn, func()) {
	t.Helper()
	feed, fed := net.Pipe()
	conn := liveness.NewConn(fed)
	read := make(chan struct{})
	go func() {
		defer close(read)
		_, _ = io.Copy(io.Discard, conn)
	}()
	quit, ended := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(ended)
		for {
			select {
			case <-quit:
				return
			case <-time.After(interval):
				if _, err := feed.Write([]byte{0}); err != nil {
					return
				}
			}
		}
	}()
	var once sync.Once
	stop := func() { once.Do(func() { close(quit) }); <-ended }
	t.Cleanup(func() {
		stop()
		_ = feed.Close()
		_ = fed.Close()
		<-read
	})
	return conn, stop
}

// Without an entry in the hostActivity, a host's connection to the sshd is the
// only one there is to judge it by: it is the host-facing connection when no
// proxy sits in between, as when a WebSocket-only relay hands the host straight
// to the sshd. And when there is an entry, it is the one the sshd goes by, so a
// host the proxy still hears from is not closed for the silence of the
// connection the proxy keeps to the sshd.
func Test_sshd_PingsFallBackToTheNodeConnectionWithoutAProxy(t *testing.T) {
	t.Run("no entry", func(t *testing.T) {
		timing := liveness.Timing{Interval: 100 * time.Millisecond, Bound: 200 * time.Millisecond}
		// A registry with nothing in it, which is what a relay with no SSH
		// listener has: Server makes one either way.
		s := newTestSSHD(t, func(d *sshd) {
			d.liveness = timing
			d.hostActivity = newHostActivity()
		})
		host := newProven(t)
		client, _, stopSending := s.dialMute(t, "direct", 30*time.Millisecond)
		ok, body := host.register(t, client, "direct", 1)
		require.True(t, ok, string(body))
		gone := func() bool { _, err := s.sshd.SessionManager.GetSession(host.id()); return err != nil }

		// Its bytes keep it, as they would on any connection.
		require.Never(t, gone, 2*(timing.Interval+timing.Bound), 10*time.Millisecond,
			"a host whose own connection kept delivering bytes was closed")
		lastSent := stopSending()
		require.False(t, lastSent.IsZero(), "the client never sent a byte")
		silent := lastSent.Add(timing.Interval + timing.Bound)
		limit := silent.Add(2 * lateWake)
		for !gone() {
			require.True(t, time.Now().Before(limit), "a silent host on a direct connection was kept")
			time.Sleep(time.Millisecond)
		}
		requireClosedAt(t, time.Now(), silent, "its last byte plus Interval+Bound")
	})

	t.Run("an entry wins", func(t *testing.T) {
		timing := liveness.Timing{Interval: 200 * time.Millisecond, Bound: 200 * time.Millisecond}
		activity := newHostActivity()
		s := newTestSSHD(t, func(d *sshd) {
			d.liveness = timing
			d.hostActivity = activity
		})
		// The host-facing connection is in the registry before the host
		// registers, as the proxy puts it there once the host's handshake is
		// done, and the node connection is as silent as one can be.
		hostFacing, stopSending := advancingConn(t, 20*time.Millisecond)
		t.Cleanup(activity.track([]byte("proxied"), hostFacing))
		host := newProven(t)
		client, freeze := s.dialFreezable(t, "proxied")
		ok, body := host.register(t, client, "proxied", 1)
		require.True(t, ok, string(body))
		freeze()
		gone := func() bool { _, err := s.sshd.SessionManager.GetSession(host.id()); return err != nil }

		require.Never(t, gone, 3*(timing.Interval+timing.Bound), 10*time.Millisecond,
			"a host the proxy still hears from was closed for its node connection's silence")

		stopSending()
		silent := hostFacing.LastRead().Add(timing.Interval + timing.Bound)
		limit := silent.Add(2 * lateWake)
		for !gone() {
			require.True(t, time.Now().Before(limit), "a host the proxy no longer hears from was kept")
			time.Sleep(time.Millisecond)
		}
		requireClosedAt(t, time.Now(), silent, "the host-facing connection's last byte plus Interval+Bound")
	})
}

// A capable host that answers its pings keeps its connection, and with it its
// registration, however many pings go by.
func Test_sshd_KeepsACapableHostThatAnswers(t *testing.T) {
	interval := 50 * time.Millisecond
	s := newTestSSHD(t, func(d *sshd) {
		d.liveness = liveness.Timing{Interval: interval, Bound: 4 * interval}
	})
	host := newProven(t)
	capable := s.dialAs(t, "capable")
	ok, body := host.register(t, capable, "capable", 1)
	require.True(t, ok, string(body))

	require.Never(t, func() bool { _, err := s.sshd.SessionManager.GetSession(host.id()); return err != nil },
		12*interval, interval/5, "a capable host that answers is kept")
}

// heldReleaseStore holds every Release until open is closed, and counts the
// ones that went through.
type heldReleaseStore struct {
	SessionStore
	open chan struct{}
	done atomic.Int32
}

func (s *heldReleaseStore) Release(ctx context.Context, reg *Registration) error {
	select {
	case <-s.open:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer s.done.Add(1)
	return s.SessionStore.Release(ctx, reg)
}

// A takeover on this node ends the registration it replaced in the background:
// neither the reply to the new registration nor the old connection's close,
// which takes its guests with it, waits on the store's release.
func Test_sshd_TakeoverDoesNotWaitOnTheStore(t *testing.T) {
	logger := logging.Must(logging.Console(), logging.Debug()).Logger
	store := &heldReleaseStore{SessionStore: newMemorySessionStore(logger), open: make(chan struct{})}
	s := newTestSSHD(t, func(d *sshd) {
		d.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	})
	host := newProven(t)
	first := s.dialAs(t, "conn-1")
	ok, body := host.register(t, first, "conn-1", 1)
	require.True(t, ok, string(body))
	ok, reason := forwardRequest(t, first, streamlocalForwardChannelType, host.id())
	require.True(t, ok, reason)
	firstClosed := make(chan struct{})
	go func() { _ = first.Wait(); close(firstClosed) }()

	// Dialed before the clock starts: the budget below times the reply, not
	// the handshake, which under -race is slow enough to matter.
	second := s.dialAs(t, "conn-2")
	start := time.Now()
	ok, body = host.register(t, second, "conn-2", 2)
	require.True(t, ok, string(body))
	require.Less(t, time.Since(start), time.Second, "the new registration's reply waited on the old one's release")
	select {
	case <-firstClosed:
	case <-time.After(time.Second):
		t.Fatal("the superseded connection waited on the store")
	}

	close(store.open)
	// Two releases of generation 1 happen: evict's, and the old connection's
	// own when its context ends. The memory store has no lease, so nothing
	// else releases it. Waiting for both means the check below runs after
	// every release of the old registration, not after the first.
	require.Eventually(t, func() bool { return store.done.Load() >= 2 }, 5*time.Second, 10*time.Millisecond,
		"both of generation 1's releases went through")
	require.Never(t, func() bool {
		sess, err := s.sshd.SessionManager.GetSession(host.id())
		return err != nil || sess.Generation != 2
	}, 300*time.Millisecond, 10*time.Millisecond, "the old registration's releases left the new entry")
}
