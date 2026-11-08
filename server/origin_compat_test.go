package server

import (
	"errors"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// A filter alone, with no built-in list, refuses at each point.
func TestSourceFilterStandalone(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	guest, relay := certTestSigner(t), certTestSigner(t)
	sm := newEmbeddedSessionManager(logger)
	user := sm.GetEncodeDecoder().Encode("session", "n1:22")

	// Before the banner, by the connection's own source.
	_, addr, _, _ := stockTestProxy(t, 4*time.Second, nil, func(p *sshProxy) {
		p.deny = sourceDeny{filter: newDenyAddrs("127.0.0.1")}
	})
	raw, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()
	require.NoError(t, raw.SetReadDeadline(time.Now().Add(2*time.Second)))
	var one [1]byte
	n, err := raw.Read(one[:])
	require.Zero(t, n, "a denied source received an SSH banner")
	require.Error(t, err)
	var ne net.Error
	require.False(t, errors.As(err, &ne) && ne.Timeout(), "a denied source was left open")

	// A hop, by the source its certificate records, not by the node it
	// arrives from.
	carried := &AuthRequest{ClientVersion: "SSH-2.0-OpenSSH_9.9", RemoteAddr: "203.0.113.7:4711", AuthorizedKey: ssh.MarshalAuthorizedKey(guest.PublicKey()), Ingress: Ingress_INGRESS_SSH}
	cert, err := (&UserCertSigner{SessionID: "entry", User: user, AuthRequest: carried}).SignCert(relay)
	require.NoError(t, err)
	a := proxyAuth{NodeAddr: "n1:22", listener: listenerInternal, Signers: []ssh.Signer{relay}, SessionManager: sm, Logger: logger,
		deny: sourceDeny{filter: newDenyAddrs("203.0.113.7")}}
	neighbor := originConn(user, "SSH-2.0-Go", "hop")
	neighbor.remote = &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 51234}
	_, _, _, err = a.authenticate(neighbor, cert.PublicKey())
	require.ErrorIs(t, err, errSourceDenied)
	a.deny = sourceDeny{filter: newDenyAddrs("10.0.0.2")}
	_, _, _, err = a.authenticate(neighbor, cert.PublicKey())
	require.NoError(t, err, "the certified source was replaced by the node the hop came from")
	a.deny = sourceDeny{}
	_, _, hop, err := a.authenticate(originConn(user, "SSH-2.0-Go", "hop"), cert.PublicKey())
	require.NoError(t, err)
	require.True(t, hop)

	// The WebSocket upgrade.
	h := &wsHandler{Logger: logger, deny: sourceDeny{filter: newDenyAddrs("203.0.113.7")}}
	r := httptest.NewRequest("GET", "http://relay/", nil)
	r.RemoteAddr = "203.0.113.7:4711"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	require.Equal(t, 403, w.Code)
	require.Zero(t, w.Body.Len())
}

// Start hands the server its identity, its deny list and its extensions'
// filter, and the server hands the filter to its SSH listener.
func TestSourceFilterIsWired(t *testing.T) {
	filter := newDenyAddrs("127.0.0.1")
	addr, logs := startForSources(t, Opt{
		NodeID:      "machine-1",
		BootID:      "0b0b5a7e-6d43-4b8e-9f43-2b1d8c4e6f10",
		DenySources: []string{"203.0.113.0/24"},
		Extensions:  Extensions{Sources: filter},
	})
	started := awaitLogRecord(t, logs, func(r map[string]any) bool { return r["msg"] == "starting server" })
	require.Equal(t, "machine-1", started["node-id"])
	require.Equal(t, "0b0b5a7e-6d43-4b8e-9f43-2b1d8c4e6f10", started["boot-id"])

	raw, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()
	require.NoError(t, raw.SetReadDeadline(time.Now().Add(2*time.Second)))
	var banner [1]byte
	n, err := raw.Read(banner[:])
	require.Zero(t, n, "the server did not pass its filter to the SSH listener")
	require.Error(t, err)
	var ne net.Error
	require.False(t, errors.As(err, &ne) && ne.Timeout(), "a denied source was left open")
	require.Contains(t, filter.askedAbout(), netip.MustParseAddr("127.0.0.1"))
}

// Without a node ID, the log names none.
func TestEmptyNodeIDIsNotLogged(t *testing.T) {
	_, logs := startForSources(t, Opt{})
	started := awaitLogRecord(t, logs, func(r map[string]any) bool { return r["msg"] == "starting server" })
	require.NotContains(t, started, "node-id")
	require.NotContains(t, started, "boot-id")
}
