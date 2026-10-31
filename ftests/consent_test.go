package ftests

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/consent"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// The manager is real; this deterministic local approval peer records actual
// reviews, not policy/audit messages, and explicitly chooses guest grants.
type relayPrompter struct {
	mu      sync.Mutex
	prompts []consent.Prompt
	deny    bool
}

func newRelayPrompter() *relayPrompter { return &relayPrompter{} }
func (p *relayPrompter) Prompt(_ context.Context, request consent.Prompt) (consent.Decision, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prompts = append(p.prompts, request)
	if p.deny {
		return consent.Deny, nil
	}
	return consent.AllowGuest, nil
}
func (p *relayPrompter) count() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.prompts) }
func (p *relayPrompter) snapshot() []consent.Prompt {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]consent.Prompt(nil), p.prompts...)
}
func (p *relayPrompter) manager(t *testing.T) *consent.Manager {
	t.Helper()
	m := consent.NewManager(p, testLogger)
	t.Cleanup(m.Close)
	return m
}

var ConsentTestCases = []FtestCase{testConsentDifferentGuestAndCapability, testConsentDeniedForwardNeverDials}

func (suite *FtestSuite) TestConsent() { suite.runTestCategory(ConsentTestCases) }

func testConsentDifferentGuestAndCapability(t *testing.T, hostURL, node, joinURL string) {
	h := execFixture(t)
	h.AcceptExec = false
	h.PermittedClientPublicKey = ""
	prompts := newRelayPrompter()
	h.PermissionChecker = prompts.manager(t)
	record := shareHost(t, h, hostURL, node)
	c := connectRelayGuest(t, record, joinURL)
	out, _, status := relayExec(t, c, guestToolCommand(t, "granted"), nil)
	require.Equal(t, 0, status)
	require.Equal(t, "granted", string(out))
	require.Equal(t, 1, prompts.count())
	// A new SSH connection authenticated by the same key reuses the exec grant.
	again := connectRelayGuest(t, record, joinURL)
	_, _, status = relayExec(t, again, guestToolCommand(t, "status23"), nil)
	require.Equal(t, 23, status)
	require.Equal(t, 1, prompts.count())
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	other := &Client{Signers: []ssh.Signer{signer}}
	require.NoError(t, other.Connect(record, joinURL))
	t.Cleanup(other.Close)
	_, _, status = relayExec(t, other, guestToolCommand(t, "other"), nil)
	require.Equal(t, 0, status)
	require.Equal(t, 2, prompts.count())
	reviews := prompts.snapshot()
	keys, err := utils.CreateSigners([][]byte{[]byte(ClientPrivateKeyContent)})
	require.NoError(t, err)
	require.Equal(t, utils.FingerprintSHA256(keys[0].PublicKey()), reviews[0].Client.Fingerprint)
	require.Equal(t, utils.FingerprintSHA256(signer.PublicKey()), reviews[1].Client.Fingerprint)
	require.NotEqual(t, reviews[0].Client.ConnectionID, reviews[1].Client.ConnectionID)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		socket, e := ln.Accept()
		if e == nil {
			accepted <- socket
		}
	}()
	fwd, err := again.sshClient.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = fwd.Close() }()
	peer := <-accepted
	defer func() { _ = peer.Close() }()
	require.Equal(t, 1, prompts.count()-len(reviews), "one additional prompt for a different capability")
	require.Equal(t, consent.OpForward, prompts.snapshot()[2].Operation)
	require.Equal(t, reviews[0].Client.Fingerprint, prompts.snapshot()[2].Client.Fingerprint)
}

func testConsentDeniedForwardNeverDials(t *testing.T, hostURL, node, joinURL string) {
	h := execFixture(t)
	prompts := newRelayPrompter()
	prompts.deny = true
	h.PermissionChecker = prompts.manager(t)
	c := connectRelayGuest(t, shareHost(t, h, hostURL, node), joinURL)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	fwd, err := c.sshClient.Dial("tcp", ln.Addr().String())
	if fwd != nil {
		_ = fwd.Close()
	}
	require.Error(t, err)
	require.Equal(t, 1, prompts.count())
	require.NoError(t, ln.(*net.TCPListener).SetDeadline(time.Now().Add(150*time.Millisecond)))
	socket, err := ln.Accept()
	if socket != nil {
		_ = socket.Close()
	}
	require.Nil(t, socket, "denied forwarding must never contact the destination")
	var timeout net.Error
	require.ErrorAs(t, err, &timeout)
	require.True(t, timeout.Timeout())
	requireForwardPresence(t, h, 0)
}

// recordingGuestSigner observes the exact fully signed guest certificate minted
// by signUserCerts and used by the relay's upstream SSH authentication. It never
// substitutes keys or certificates, and leaves host certificates untouched.
type recordingGuestSigner struct {
	ssh.Signer
	mu    sync.Mutex
	certs []*ssh.Certificate
}

func (s *recordingGuestSigner) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	sig, err := s.Signer.Sign(random, data)
	if err != nil {
		return nil, err
	}
	encoded := append(append([]byte(nil), data...), ssh.Marshal(struct{ Signature []byte }{ssh.Marshal(sig)})...)
	key, parseErr := ssh.ParsePublicKey(encoded)
	if cert, ok := key.(*ssh.Certificate); parseErr == nil && ok && cert.CertType == ssh.UserCert {
		s.mu.Lock()
		auth := &server.AuthRequest{}
		if proto.Unmarshal([]byte(cert.Extensions[upterm.SSHCertExtension]), auth) == nil && auth.ClientVersion != upterm.HostSSHClientVersion {
			s.certs = append(s.certs, cert)
		}
		s.mu.Unlock()
	}
	return sig, nil
}
func (s *recordingGuestSigner) snapshot() []*ssh.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*ssh.Certificate(nil), s.certs...)
}

func testExecGuestGrantAcrossRelayReconnect(t *testing.T, mode routing.Mode, protocol string) {

	keys, err := utils.CreateSigners([][]byte{[]byte(ServerPrivateKeyContent)})
	require.NoError(t, err)
	recorder := &recordingGuestSigner{Signer: keys[0]}
	relay := newRedialRelay(t, mode, func(s *Server) {
		s.beforeServe = func(s *Server) {
			s.Server.Signers = []ssh.Signer{recorder}
		}
	})
	prompts := newRelayPrompter()
	h := shareRediallingConfigured(t, protocol, relay, redialTiming, func(h *Host) {
		h.AcceptExec = false
		h.AllowLoopbackTCPForwarding = true
		h.PermissionChecker = prompts.manager(t)
	})
	first := connectRelayGuest(t, h.first, relay.joinURL(protocol))
	_, _, status := relayExec(t, first, guestToolCommand(t, "first"), nil)
	require.Equal(t, 0, status)
	require.Equal(t, 1, prompts.count())
	var address string
	if runtime.GOOS != "windows" {
		address = startOwnedRelayListener(t, first)
	}
	certs := recorder.snapshot()
	require.Len(t, certs, 1)
	firstCert := certs[0]
	h.fwd.Redirect(closedAddr(t))
	h.fwd.Cut()
	h.awaitStatus(t, "reconnecting")
	require.Eventually(t, func() bool { return relay.registered(h.first.SessionId) == nil }, redialTimeout, redialPoll)
	h.fwd.Redirect(relay.addr(protocol))
	h.awaitStatus(t, "ready")
	h.awaitRegistered(t, relay)
	again := connectRelayGuest(t, h.first, relay.joinURL(protocol))
	out, _, status := relayExec(t, again, guestToolCommand(t, "reconnected"), nil)
	require.Equal(t, 23, status)
	require.Equal(t, "reconnected", string(out))
	if address != "" {
		requireOwnedListenerReachable(t, again, address)
	}
	require.Equal(t, 1, prompts.count(), "one exec capability prompt across the same guest's relay reconnect")
	certs = recorder.snapshot()
	require.Len(t, certs, 2)
	require.NotEqual(t, ssh.FingerprintSHA256(firstCert), ssh.FingerprintSHA256(certs[1]), "relay must mint a different presented guest certificate")
	for _, cert := range certs {
		auth := &server.AuthRequest{}
		require.NoError(t, proto.Unmarshal([]byte(cert.Extensions[upterm.SSHCertExtension]), auth))
		recovered, _, _, _, err := ssh.ParseAuthorizedKey(auth.AuthorizedKey)
		require.NoError(t, err)
		require.Equal(t, prompts.snapshot()[0].Client.Fingerprint, utils.FingerprintSHA256(recovered))
		require.NotEqual(t, prompts.snapshot()[0].Client.Fingerprint, utils.FingerprintSHA256(cert))
	}
}
