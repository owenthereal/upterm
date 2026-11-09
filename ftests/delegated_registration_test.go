package ftests

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/internal/testhelpers/testauthority"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

const (
	delegatedProtocol  = "test_v1"
	delegatedSessionID = "33333333-3333-4333-8333-333333333333"
	delegatedBootID    = "55555555-5555-4555-8555-555555555555"
)

// withAuthority composes authority into the relay, enabled or dark. An
// enabled one is given what it needs: an internal listener, legacy hops
// refused, a node ID and a UUID boot ID.
func withAuthority(authority server.Authority, enabled bool) func(*Server) {
	return func(s *Server) {
		if enabled {
			withInternalListener(false)(s)
			withLegacyHopsRefused()(s)
		}
		base := s.beforeServe
		s.beforeServe = func(s *Server) {
			if base != nil {
				base(s)
			}
			s.Server.Extensions = server.Extensions{Authority: authority, Enabled: enabled, Protocols: []string{delegatedProtocol}}
			s.Server.NodeID = "node-a"
			s.Server.BootID = delegatedBootID
		}
	}
}

// A composed authority whose every call blocks forever holds up no local
// work, dark or enabled: a local host registers, a guest joins, and the host
// redials, each within the budgets these tests give a relay with no
// authority, and the authority is never asked.
func TestHangingAuthorityNeverDelaysLocalWork(t *testing.T) {
	useTestKeyPairs(t)
	for _, enabled := range []bool{false, true} {
		for _, protocol := range []string{"ssh", "ws"} {
			t.Run(map[bool]string{false: "dark", true: "enabled"}[enabled]+"/"+protocol, func(t *testing.T) {
				authority := testauthority.New()
				authority.Hang()
				relay := newRedialRelay(t, routing.ModeEmbedded, withAuthority(authority, enabled))
				h := shareRedialling(t, protocol, relay, redialTiming)
				first := h.awaitRegistered(t, relay)
				joinAndReachHost(t, h.first, relay.joinURL(protocol))

				h.fwd.Redirect(closedAddr(t))
				h.fwd.Cut()
				h.awaitStatus(t, sessiondir.StatusReconnecting)
				h.fwd.Redirect(relay.addr(protocol))
				h.awaitStatus(t, sessiondir.StatusReady)
				again := h.awaitRegistered(t, relay)
				require.Greater(t, again.Generation, first.Generation, "registered again, under a later generation")
				joinAndReachHost(t, h.first, relay.joinURL(protocol))

				require.Empty(t, authority.Calls(), "local work reached the authority")
			})
		}
	}
}

// delegatedHost is a host's own connection to a relay, which makes its
// requests by hand, and the key and secret its session ID derives from.
type delegatedHost struct {
	client *ssh.Client
	key    ssh.Signer
	secret []byte
}

func dialDelegatedHost(t *testing.T, addr string) *delegatedHost {
	t.Helper()
	signer, err := ssh.ParsePrivateKey([]byte(HostPrivateKeyContent))
	require.NoError(t, err)
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "host", ClientVersion: upterm.HostSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	secret, err := registration.NewSecret()
	require.NoError(t, err)
	return &delegatedHost{client: client, key: key, secret: secret}
}

// request is the host's delegated registration at generation 1.
func (h *delegatedHost) request(t *testing.T) []byte {
	t.Helper()
	proof, err := registration.Sign(h.key, h.client.SessionID(), h.secret, 1)
	require.NoError(t, err)
	b, err := proto.Marshal(&server.CreateSessionRequest{HostUser: "host", HostPublicKeys: [][]byte{ssh.MarshalAuthorizedKey(h.key.PublicKey())}, SessionSecret: h.secret, Generation: 1, HostKeyProof: proof,
		DelegatedSession: &server.DelegatedSession{Protocol: delegatedProtocol, ExternalSessionId: delegatedSessionID}})
	require.NoError(t, err)
	return b
}

// register asks for the host's delegated registration.
func (h *delegatedHost) register(t *testing.T) (bool, []byte) {
	t.Helper()
	ok, body, err := h.client.SendRequest(upterm.ServerCreateSessionRequestType, true, h.request(t))
	require.NoError(t, err)
	return ok, body
}

func (h *delegatedHost) id() string { return registration.ID(h.key.PublicKey(), h.secret) }

func requireRefusedAs(t *testing.T, ok bool, body []byte, code server.DelegatedErrorCode) {
	t.Helper()
	require.False(t, ok, "accepted")
	refused, decoded := server.DecodeDelegatedError(body)
	require.True(t, decoded, "the refusal is no DelegatedError: %q", body)
	require.Equal(t, code, refused.Code)
	require.Equal(t, code == server.DelegatedErrorCode_DELEGATED_UNAVAILABLE, refused.Retryable())
}

// A delegated registration through a whole relay: the authority decides it
// from what the relay verified, a current decision publishes its route, the
// host's reports reach the authority on its own connection, and a dark
// relay, or one whose authority fails, publishes nothing.
func TestDelegatedRegistrationThroughARelay(t *testing.T) {
	authority := testauthority.New()
	relay := newRedialRelay(t, routing.ModeEmbedded, withAuthority(authority, true))

	host := dialDelegatedHost(t, relay.SSHAddr())
	arrived, release := authority.Gate()
	type answer struct {
		ok   bool
		body []byte
		err  error
	}
	answered := make(chan answer, 1)
	payload := host.request(t)
	go func() {
		ok, body, err := host.client.SendRequest(upterm.ServerCreateSessionRequestType, true, payload)
		answered <- answer{ok, body, err}
	}()
	select {
	case <-arrived:
	case <-time.After(redialTimeout):
		t.Fatal("the registration never reached the authority")
	}
	require.Nil(t, relay.registered(host.id()), "a route before the authority decided")
	release()
	a := <-answered
	require.NoError(t, a.err)
	ok, body := a.ok, a.body
	require.True(t, ok, "%q", body)
	var resp server.CreateSessionResponse
	require.NoError(t, proto.Unmarshal(body, &resp))
	require.Equal(t, host.id(), resp.SessionID)
	require.True(t, proto.Equal(&server.DelegatedSession{Protocol: delegatedProtocol, ExternalSessionId: delegatedSessionID, Disposition: server.DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, resp.DelegatedSession))
	route := relay.registered(host.id())
	require.NotNil(t, route)
	require.Equal(t, server.AuthorityDelegated, route.AuthorityHint)

	calls := authority.Calls()
	require.Len(t, calls, 1)
	require.Equal(t, "Register", calls[0].Method)
	reg := calls[0].Registration
	require.Equal(t, host.id(), reg.RoutingID)
	require.Equal(t, host.client.SessionID(), reg.RegistrationID)
	require.Equal(t, server.Ingress_INGRESS_SSH, reg.Origin.Ingress)
	require.Equal(t, "node-a", reg.HomeNodeID)
	require.Equal(t, delegatedBootID, reg.HomeBootID)
	require.True(t, reg.Contact().Connected)

	// The host's report, which the authority answers final.
	authority.Reply(func(r server.Report) (*server.DelegatedControlReply, error) {
		return &server.DelegatedControlReply{ExternalSessionId: r.Request.ExternalSessionId, Generation: r.Request.Generation, AcknowledgedSequence: r.Request.Sequence, Disposition: server.DelegatedDisposition_DELEGATED_WITHDRAWN, DecisionRevision: 2}, nil
	})
	report, err := proto.Marshal(&server.DelegatedControlRequest{ExternalSessionId: delegatedSessionID, Generation: 1, Sequence: 1, Event: &server.DelegatedControlRequest_Ready{Ready: &server.DelegatedReady{}}})
	require.NoError(t, err)
	ok, body, err = host.client.SendRequest(upterm.ServerDelegatedControlRequestType, true, report)
	require.NoError(t, err)
	require.True(t, ok, "%q", body)
	var reply server.DelegatedControlReply
	require.NoError(t, proto.Unmarshal(body, &reply))
	require.Equal(t, server.DelegatedDisposition_DELEGATED_WITHDRAWN, reply.Disposition)
	require.Nil(t, relay.registered(host.id()), "a final reply left the route")
	calls = authority.Calls()
	require.Len(t, calls, 2)
	require.Equal(t, "Control", calls[1].Method)
	require.Equal(t, uint64(1), calls[1].Request.Sequence)

	// A stopped decision publishes nothing.
	authority.Script(server.RegistrationResult{AccountID: testauthority.AccountID, Disposition: server.DelegatedDisposition_DELEGATED_STOPPED, DecisionRevision: 3})
	stopped := dialDelegatedHost(t, relay.SSHAddr())
	ok, body = stopped.register(t)
	require.True(t, ok, "%q", body)
	require.NoError(t, proto.Unmarshal(body, &resp))
	require.Empty(t, resp.SshUser)
	require.Nil(t, relay.registered(stopped.id()))

	// An authority that fails is unavailable, never a decision.
	authority.ScriptErr(errors.New("the authority is down"))
	failed := dialDelegatedHost(t, relay.SSHAddr())
	ok, body = failed.register(t)
	requireRefusedAs(t, ok, body, server.DelegatedErrorCode_DELEGATED_UNAVAILABLE)
	require.Nil(t, relay.registered(failed.id()))

	// A dark relay never asks.
	dark := testauthority.New()
	darkRelay := newRedialRelay(t, routing.ModeEmbedded, withAuthority(dark, false))
	darkHost := dialDelegatedHost(t, darkRelay.SSHAddr())
	ok, body = darkHost.register(t)
	requireRefusedAs(t, ok, body, server.DelegatedErrorCode_DELEGATED_UNAVAILABLE)
	require.Nil(t, darkRelay.registered(darkHost.id()))
	require.Empty(t, dark.Calls())
}
