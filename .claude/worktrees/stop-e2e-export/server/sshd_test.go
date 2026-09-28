package server

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/internal/logging"
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
	sshd       *sshd
	addr       string
	certSigner ssh.Signer
	reg        *prometheus.Registry
	network    *MemoryProvider
}

func newTestSSHD(t *testing.T) *testSSHD {
	t.Helper()
	logger := logging.Must(logging.Console(), logging.Debug()).Logger

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	addr := ln.Addr().String()

	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)

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

	network := &MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))

	mp, reg := newTestMetrics(t)
	sshd := &sshd{
		SessionManager:      newEmbeddedSessionManager(logger),
		HostSigners:         []ssh.Signer{signer},
		NodeAddr:            addr,
		SessionDialListener: network.Session(),
		MetricsProvider:     mp,
		Logger:              logger,
	}
	go func() {
		_ = sshd.Serve(ln)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, utils.WaitForServer(ctx, addr))

	return &testSSHD{sshd: sshd, addr: addr, certSigner: certSigner, reg: reg, network: network}
}

func (s *testSSHD) dial(t *testing.T) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", s.addr, &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(s.certSigner)},
		User:            "owen",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
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

// blockingDeleteStore signals on entered when Delete is called, then holds
// the call until release is closed.
type blockingDeleteStore struct {
	SessionStore
	entered chan struct{}
	release chan struct{}
}

func (s blockingDeleteStore) Delete(sessionID string) error {
	close(s.entered)
	<-s.release
	return s.SessionStore.Delete(sessionID)
}

func Test_localSessions_SlowDeleteDoesNotBlockAdd(t *testing.T) {
	logger := logging.Must(logging.Console(), logging.Debug()).Logger
	store := blockingDeleteStore{
		SessionStore: newMemorySessionStore(logger),
		entered:      make(chan struct{}),
		release:      make(chan struct{}),
	}
	sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	mp, reg := newTestMetrics(t)
	sessions := newLocalSessions(mp, sm, logger)

	_, err := sm.CreateSession(NewSession("slow", "node", "owen", nil, nil))
	require.NoError(t, err)
	sessions.add("slow")

	ended := make(chan struct{})
	go func() {
		sessions.end("slow")
		close(ended)
	}()
	<-store.entered // end is now inside the store delete

	// A Consul delete can take a while; other hosts creating sessions must
	// not queue behind it.
	added := make(chan struct{})
	go func() {
		sessions.add("other")
		close(added)
	}()
	select {
	case <-added:
	case <-time.After(2 * time.Second):
		t.Fatal("add blocked behind a slow delete")
	}

	close(store.release)
	<-ended
	v, ok := gatherValue(t, reg, "test_server_sessions_active_count", nil)
	require.True(t, ok)
	require.Equal(t, 1.0, v)
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
