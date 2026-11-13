package internal

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/internal/liveness"
	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/internal/testhelpers/fakerelay"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

const (
	externalSessionID = "33333333-3333-4333-8333-333333333333"
	testProtocol      = "test_v1"
)

// fakeAuthority is a delegating relay's authority: it records every call and
// answers with register and control, or with a current decision at revision
// 1.
type fakeAuthority struct {
	mu            sync.Mutex
	registrations []server.DelegatedRegistration
	controls      []*server.DelegatedControlRequest
	register      func(server.DelegatedRegistration) (server.RegistrationResult, error)
	control       func(*server.DelegatedControlRequest) (*server.DelegatedControlReply, error)
}

func (f *fakeAuthority) Register(_ context.Context, r server.DelegatedRegistration) (server.RegistrationResult, error) {
	f.mu.Lock()
	f.registrations = append(f.registrations, r)
	answer := f.register
	f.mu.Unlock()
	if answer == nil {
		return server.RegistrationResult{AccountID: "11111111-1111-4111-8111-111111111111", Disposition: server.DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, nil
	}
	return answer(r)
}

func (f *fakeAuthority) Control(_ context.Context, r server.Report) (*server.DelegatedControlReply, error) {
	f.mu.Lock()
	f.controls = append(f.controls, r.Request)
	answer := f.control
	f.mu.Unlock()
	if answer == nil {
		return echo(r.Request, server.DelegatedDisposition_DELEGATED_CURRENT, 1), nil
	}
	return answer(r.Request)
}

// The relay's authority decides no guest: these tests are the host's.
func (f *fakeAuthority) Claims(string) bool { return false }

func (f *fakeAuthority) Admit(context.Context, *server.Guest, server.GuestRequest) (server.Admission, error) {
	return server.Admission{}, nil
}

func (f *fakeAuthority) Unreachable(context.Context, *server.Guest, server.Target) []byte {
	return nil
}

func (f *fakeAuthority) answerControl(fn func(*server.DelegatedControlRequest) (*server.DelegatedControlReply, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.control = fn
}

func (f *fakeAuthority) seen() ([]server.DelegatedRegistration, []*server.DelegatedControlRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]server.DelegatedRegistration(nil), f.registrations...), append([]*server.DelegatedControlRequest(nil), f.controls...)
}

func echo(req *server.DelegatedControlRequest, d server.DelegatedDisposition, revision uint64) *server.DelegatedControlReply {
	return &server.DelegatedControlReply{ExternalSessionId: req.ExternalSessionId, Generation: req.Generation, AcknowledgedSequence: req.Sequence, Disposition: d, DecisionRevision: revision}
}

func decided(d server.DelegatedDisposition, revision uint64) func(server.DelegatedRegistration) (server.RegistrationResult, error) {
	return func(server.DelegatedRegistration) (server.RegistrationResult, error) {
		return server.RegistrationResult{AccountID: "11111111-1111-4111-8111-111111111111", Disposition: d, DecisionRevision: revision}, nil
	}
}

// runtimeOf is a Lifecycle that hands over the relay's Runtime once it
// starts.
type runtimeOf struct{ rt chan server.Runtime }

func (l runtimeOf) Start(_ context.Context, rt server.Runtime) error {
	l.rt <- rt
	return nil
}

func (runtimeOf) Stop() {}

// delegatingRelay is an in-process relay whose authority decides its
// delegated hosts; it serves ssh:// only.
type delegatingRelay struct {
	testRelay
	runtime server.Runtime
}

func startDelegatingRelay(t *testing.T, authority server.Authority, opts ...func(*server.Server)) delegatingRelay {
	t.Helper()
	identity, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	sshln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sshln.Close() })
	network := &server.MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sessions, err := server.NewSessionManager(routing.ModeEmbedded, server.WithSessionManagerLogger(logger))
	require.NoError(t, err)
	lifecycle := runtimeOf{rt: make(chan server.Runtime, 1)}
	srv := &server.Server{
		NodeAddr:         sshln.Addr().String(),
		HostSigners:      identity,
		Signers:          identity,
		NetworkProvider:  network,
		MetricsProvider:  provider.NewDiscardProvider(),
		SessionManager:   sessions,
		Logger:           logger,
		Extensions:       server.Extensions{Authority: authority, Enabled: true, Protocols: []string{testProtocol}, Lifecycle: lifecycle},
		RefuseLegacyHops: true,
		NodeID:           "test-node", BootID: "55555555-5555-4555-8555-555555555555",
	}
	for _, opt := range opts {
		opt(srv)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	internal, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { done <- srv.ServeListeners(ctx, server.Listeners{SSH: sshln, Internal: internal}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err, "a relay told to stop reports a clean stop")
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	var rt server.Runtime
	select {
	case rt = <-lifecycle.rt:
	case err := <-done:
		t.Fatalf("the relay stopped before it started: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the relay never started its lifecycle")
	}
	readyCtx, readyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readyCancel()
	require.NoError(t, utils.WaitForServer(readyCtx, sshln.Addr().String()))
	return delegatingRelay{
		testRelay: testRelay{url: &url.URL{Scheme: "ssh", Host: sshln.Addr().String()}, identity: identity, sessions: sessions},
		runtime:   rt,
	}
}

func delegatedRun() *server.DelegatedSession {
	return &server.DelegatedSession{Protocol: testProtocol, ExternalSessionId: externalSessionID}
}

// delegatedTunnel is a delegated host of hostKey registering at generation
// over r, with a fresh secret.
func (r testRelay) delegatedTunnel(t *testing.T, hostKey ssh.Signer, generation uint64, decisions *DelegatedDecisions) *ReverseTunnel {
	t.Helper()
	secret, err := registration.NewSecret()
	require.NoError(t, err)
	rt := r.tunnel(hostKey, r.url)
	rt.SessionSecret, rt.Generation = secret, generation
	rt.Delegated, rt.Decisions = delegatedRun(), decisions
	t.Cleanup(rt.Close)
	return rt
}

// fakeDelegatedTunnel is a delegated host of hostKey with secret, registering
// over fake.
func fakeDelegatedTunnel(t *testing.T, fake *fakerelay.Relay, relayKey, hostKey ssh.Signer, secret []byte, decisions *DelegatedDecisions) *ReverseTunnel {
	t.Helper()
	rt := &ReverseTunnel{
		Host: &url.URL{Scheme: "ssh", Host: fake.Addr}, HostKey: hostKey, Signers: []ssh.Signer{hostKey},
		HostKeyCallback: ssh.FixedHostKey(relayKey.PublicKey()), SessionSecret: secret, Generation: 1,
		KeepAlive: liveness.Timing{Interval: time.Hour, Bound: time.Hour},
		Delegated: delegatedRun(), Decisions: decisions,
	}
	t.Cleanup(rt.Close)
	return rt
}

func newKeyAndSecret(t *testing.T) (ssh.Signer, ssh.Signer, []byte) {
	t.Helper()
	relayKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	secret, err := registration.NewSecret()
	require.NoError(t, err)
	return relayKey[0], hostKey[0], secret
}

func requireUndecided(t *testing.T, decisions *DelegatedDecisions) {
	t.Helper()
	d, revision := decisions.Current()
	require.Equal(t, server.DelegatedDisposition_DELEGATED_UNSPECIFIED, d)
	require.Zero(t, revision)
	select {
	case <-decisions.Terminal():
		t.Fatal("an undecided session was announced final")
	default:
	}
}

func requireTerminal(t *testing.T, decisions *DelegatedDecisions, want server.DelegatedDisposition, revision uint64) {
	t.Helper()
	d, rev := decisions.Current()
	require.Equal(t, want, d)
	require.Equal(t, revision, rev)
	select {
	case <-decisions.Terminal():
	case <-time.After(5 * time.Second):
		t.Fatal("a final decision was not announced")
	}
}

// A delegated host listens for guests only on the relay's exact
// acknowledgment of a current decision. A stopped or withdrawn one leaves the
// connection for reports and no listener; anything else, a refusal it cannot
// read included, fails the registration as unsupported, without the relay's
// bytes and without recording a decision.
func TestDelegatedAcknowledgment(t *testing.T) {
	t.Run("current", func(t *testing.T) {
		authority := &fakeAuthority{}
		relay := startDelegatingRelay(t, authority)
		hostKey, err := utils.CreateSigners(nil)
		require.NoError(t, err)
		var decisions DelegatedDecisions
		rt := relay.delegatedTunnel(t, hostKey[0], 1, &decisions)
		resp, err := rt.Establish(t.Context())
		require.NoError(t, err)
		require.NotNil(t, rt.Listener(), "a current registration listens for guests")
		require.True(t, proto.Equal(&server.DelegatedSession{Protocol: testProtocol, ExternalSessionId: externalSessionID, Disposition: server.DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, resp.DelegatedSession))
		d, revision := decisions.Current()
		require.Equal(t, server.DelegatedDisposition_DELEGATED_CURRENT, d)
		require.Equal(t, uint64(1), revision)
		_, err = relay.sessions.GetSession(resp.SessionID)
		require.NoError(t, err)

		registrations, _ := authority.seen()
		require.Len(t, registrations, 1)
		require.True(t, proto.Equal(delegatedRun(), registrations[0].Session), "the request carried the run as given")
		require.Equal(t, rt.SessionID(), registrations[0].RegistrationID)
	})

	for _, d := range []server.DelegatedDisposition{server.DelegatedDisposition_DELEGATED_STOPPED, server.DelegatedDisposition_DELEGATED_WITHDRAWN} {
		t.Run(d.String(), func(t *testing.T) {
			authority := &fakeAuthority{register: decided(d, 3)}
			authority.answerControl(func(req *server.DelegatedControlRequest) (*server.DelegatedControlReply, error) {
				return echo(req, d, 3), nil
			})
			relay := startDelegatingRelay(t, authority)
			hostKey, err := utils.CreateSigners(nil)
			require.NoError(t, err)
			var decisions DelegatedDecisions
			rt := relay.delegatedTunnel(t, hostKey[0], 1, &decisions)
			resp, err := rt.Establish(t.Context())
			require.NoError(t, err)
			require.Nil(t, rt.Listener(), "a final registration listens for no guest")
			require.Empty(t, resp.SshUser)
			requireTerminal(t, &decisions, d, 3)
			_, err = relay.sessions.GetSession(resp.SessionID)
			require.Error(t, err, "a final registration has a route")

			// The connection stays for the final report.
			require.NoError(t, rt.Report(t.Context(), DelegatedEvent{Exit: true, StatusKnown: true}))
			_, controls := authority.seen()
			require.Len(t, controls, 1)
			require.NotNil(t, controls[0].GetExit())
		})
	}

	ack := func(d server.DelegatedDisposition, revision uint64) *server.DelegatedSession {
		return &server.DelegatedSession{Protocol: testProtocol, ExternalSessionId: externalSessionID, Disposition: d, DecisionRevision: revision}
	}
	refusal := func(code server.DelegatedErrorCode) []byte {
		b, _ := proto.Marshal(&server.DelegatedError{Code: code})
		return b
	}
	unsupported := ErrDelegatedRelayUnsupported
	for name, tc := range map[string]struct {
		answer func(id string) (bool, []byte)
		want   error
		code   server.DelegatedErrorCode
	}{
		"no acknowledgment":      {answer: respond(nil, "user"), want: unsupported},
		"another protocol":       {answer: respond(&server.DelegatedSession{Protocol: "test_v2", ExternalSessionId: externalSessionID, Disposition: server.DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, "user"), want: unsupported},
		"another session":        {answer: respond(&server.DelegatedSession{Protocol: testProtocol, ExternalSessionId: "44444444-4444-4444-8444-444444444444", Disposition: server.DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, "user"), want: unsupported},
		"no disposition":         {answer: respond(ack(server.DelegatedDisposition_DELEGATED_UNSPECIFIED, 1), "user"), want: unsupported},
		"an unknown disposition": {answer: respond(ack(server.DelegatedDisposition(9), 1), "user"), want: unsupported},
		"no revision":            {answer: respond(ack(server.DelegatedDisposition_DELEGATED_CURRENT, 0), "user"), want: unsupported},
		"a final route":          {answer: respond(ack(server.DelegatedDisposition_DELEGATED_STOPPED, 1), "user"), want: unsupported},
		"an unreadable reply":    {answer: func(string) (bool, []byte) { return true, []byte{0xff, 0xff, 0xff} }, want: unsupported},
		"another route": {answer: func(string) (bool, []byte) {
			return respond(ack(server.DelegatedDisposition_DELEGATED_CURRENT, 1), "user")("unrelated-route")
		}, want: ErrRelayUnsupported},
		"a plain refusal": {answer: func(string) (bool, []byte) { return false, []byte("secret relay text") }, want: unsupported},
		"an unknown code": {answer: func(string) (bool, []byte) { return false, refusal(9) }, want: unsupported},
		"a code and more": {answer: func(string) (bool, []byte) {
			return false, append(refusal(server.DelegatedErrorCode_DELEGATED_UNAVAILABLE), 0x10, 0x01)
		}, want: unsupported},
		"unavailable": {answer: func(string) (bool, []byte) { return false, refusal(server.DelegatedErrorCode_DELEGATED_UNAVAILABLE) }, code: server.DelegatedErrorCode_DELEGATED_UNAVAILABLE},
		"stale generation": {answer: func(string) (bool, []byte) {
			return false, refusal(server.DelegatedErrorCode_DELEGATED_STALE_GENERATION)
		}, code: server.DelegatedErrorCode_DELEGATED_STALE_GENERATION},
		"invalid": {answer: func(string) (bool, []byte) {
			return false, refusal(server.DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
		}, code: server.DelegatedErrorCode_DELEGATED_INVALID_REQUEST},
	} {
		t.Run(name, func(t *testing.T) {
			relayKey, hostKey, secret := newKeyAndSecret(t)
			id := registration.ID(hostKey.PublicKey(), secret)
			fake := fakerelay.Start(t, relayKey, func(*server.CreateSessionRequest) (bool, []byte) { return tc.answer(id) })
			var decisions DelegatedDecisions
			rt := fakeDelegatedTunnel(t, fake, relayKey, hostKey, secret, &decisions)
			_, err := rt.Establish(t.Context())
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
			} else {
				var refused *server.DelegatedRefusedError
				require.ErrorAs(t, err, &refused)
				require.Equal(t, tc.code, refused.Code)
				require.Equal(t, tc.code == server.DelegatedErrorCode_DELEGATED_UNAVAILABLE, refused.Retryable())
			}
			require.NotContains(t, err.Error(), "secret", "the relay's bytes reached the error")
			require.Zero(t, fake.Forwards(), "a registration the host could not accept listened for guests")
			requireUndecided(t, &decisions)
		})
	}

	// Ordered against what the run was already told: a later registration
	// cannot undo a final decision, and cannot contradict a revision in force.
	t.Run("a later current cannot undo a final decision", func(t *testing.T) {
		relayKey, hostKey, secret := newKeyAndSecret(t)
		id := registration.ID(hostKey.PublicKey(), secret)
		fake := fakerelay.Start(t, relayKey, func(*server.CreateSessionRequest) (bool, []byte) {
			return respond(ack(server.DelegatedDisposition_DELEGATED_CURRENT, 6), "user")(id)
		})
		var decisions DelegatedDecisions
		require.NoError(t, decisions.Apply(server.DelegatedDisposition_DELEGATED_STOPPED, 5))
		rt := fakeDelegatedTunnel(t, fake, relayKey, hostKey, secret, &decisions)
		_, err := rt.Establish(t.Context())
		require.NoError(t, err)
		require.Nil(t, rt.Listener())
		require.Zero(t, fake.Forwards())
		requireTerminal(t, &decisions, server.DelegatedDisposition_DELEGATED_STOPPED, 5)
	})
	t.Run("a contradiction of the revision in force", func(t *testing.T) {
		relayKey, hostKey, secret := newKeyAndSecret(t)
		id := registration.ID(hostKey.PublicKey(), secret)
		fake := fakerelay.Start(t, relayKey, func(*server.CreateSessionRequest) (bool, []byte) {
			return respond(ack(server.DelegatedDisposition_DELEGATED_WITHDRAWN, 2), "")(id)
		})
		var decisions DelegatedDecisions
		require.NoError(t, decisions.Apply(server.DelegatedDisposition_DELEGATED_CURRENT, 2))
		rt := fakeDelegatedTunnel(t, fake, relayKey, hostKey, secret, &decisions)
		_, err := rt.Establish(t.Context())
		require.ErrorIs(t, err, ErrDelegatedRelayUnsupported)
		d, revision := decisions.Current()
		require.Equal(t, server.DelegatedDisposition_DELEGATED_CURRENT, d)
		require.Equal(t, uint64(2), revision)
	})

	t.Run("an incomplete run is never sent", func(t *testing.T) {
		relayKey, hostKey, secret := newKeyAndSecret(t)
		fake := fakerelay.Start(t, relayKey, fakerelay.RandomID)
		for name, change := range map[string]func(*ReverseTunnel){
			"no decisions":      func(rt *ReverseTunnel) { rt.Decisions = nil },
			"no secret":         func(rt *ReverseTunnel) { rt.SessionSecret = nil },
			"a session ID":      func(rt *ReverseTunnel) { rt.Delegated.ExternalSessionId = "external-session-1" },
			"a disposition":     func(rt *ReverseTunnel) { rt.Delegated.Disposition = server.DelegatedDisposition_DELEGATED_CURRENT },
			"a revision":        func(rt *ReverseTunnel) { rt.Delegated.DecisionRevision = 1 },
			"guest keys":        func(rt *ReverseTunnel) { rt.AuthorizedKeys = []ssh.PublicKey{hostKey.PublicKey()} },
			"no protocol":       func(rt *ReverseTunnel) { rt.Delegated.Protocol = "" },
			"a spaced protocol": func(rt *ReverseTunnel) { rt.Delegated.Protocol = "test v1" },
			"no generation":     func(rt *ReverseTunnel) { rt.Generation = 0 },
		} {
			var decisions DelegatedDecisions
			rt := fakeDelegatedTunnel(t, fake, relayKey, hostKey, secret, &decisions)
			change(rt)
			_, err := rt.Establish(t.Context())
			require.Error(t, err, name)
		}
		require.Zero(t, fake.Connections(), "an incomplete delegated run dialled the relay")
	})
}

// respond answers a registration as a relay would, with ack and sshUser.
func respond(ack *server.DelegatedSession, sshUser string) func(id string) (bool, []byte) {
	return func(id string) (bool, []byte) {
		b, err := proto.Marshal(&server.CreateSessionResponse{SessionID: id, SshUser: sshUser, DelegatedSession: ack})
		if err != nil {
			return false, []byte(err.Error())
		}
		return true, b
	}
}

// A relay with no authority refuses a delegated registration, and the host
// takes that as unsupported, not as a local session, and repeats none of the
// relay's words. A host that isn't delegated, for its part, refuses the
// relay's decisions as it refuses every request from the relay.
func TestStandaloneRefusesDelegated(t *testing.T) {
	relay := startTestRelay(t)
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	var decisions DelegatedDecisions
	rt := relay.delegatedTunnel(t, hostKey[0], 1, &decisions)
	_, err = rt.Establish(t.Context())
	require.ErrorIs(t, err, ErrDelegatedRelayUnsupported)
	require.NotContains(t, err.Error(), "not supported by this relay")
	require.Nil(t, rt.Listener())
	_, err = relay.sessions.GetSession(registration.ID(hostKey[0].PublicKey(), rt.SessionSecret))
	require.Error(t, err, "a delegated request created a local route")
	requireUndecided(t, &decisions)

	relayKey, standaloneKey, secret := newKeyAndSecret(t)
	id := registration.ID(standaloneKey.PublicKey(), secret)
	fake := fakerelay.Start(t, relayKey, func(*server.CreateSessionRequest) (bool, []byte) {
		return respond(nil, "user")(id)
	})
	standalone := &ReverseTunnel{
		Host: &url.URL{Scheme: "ssh", Host: fake.Addr}, HostKey: standaloneKey, Signers: []ssh.Signer{standaloneKey},
		HostKeyCallback: ssh.FixedHostKey(relayKey.PublicKey()), SessionSecret: secret, Generation: 1,
		KeepAlive: liveness.Timing{Interval: time.Hour, Bound: time.Hour},
	}
	t.Cleanup(standalone.Close)
	_, err = standalone.Establish(t.Context())
	require.NoError(t, err)
	payload, err := proto.Marshal(&server.DelegatedDecision{ExternalSessionId: externalSessionID, Generation: 1, Disposition: server.DelegatedDisposition_DELEGATED_STOPPED, DecisionRevision: 2})
	require.NoError(t, err)
	ok, body, err := fake.Push(upterm.HostDelegatedDecisionRequestType, payload)
	require.NoError(t, err)
	require.False(t, ok)
	require.Empty(t, body, "a host that isn't delegated interpreted a decision")
}

// Decisions are ordered by revision, not arrival: lower revisions are
// ignored, the same one again is harmless, the same one with another
// disposition is a protocol error that changes nothing, and the first final
// decision stays in force.
func TestDelegatedDecisionOrdering(t *testing.T) {
	const (
		current   = server.DelegatedDisposition_DELEGATED_CURRENT
		stopped   = server.DelegatedDisposition_DELEGATED_STOPPED
		withdrawn = server.DelegatedDisposition_DELEGATED_WITHDRAWN
	)
	var d DelegatedDecisions
	requireUndecided(t, &d)
	for i, step := range []struct {
		disposition server.DelegatedDisposition
		revision    uint64
		fails       bool
		want        server.DelegatedDisposition
		wantRev     uint64
	}{
		{current, 1, false, current, 1},
		{current, 1, false, current, 1},
		{stopped, 1, true, current, 1},
		{current, 0, true, current, 1},
		{server.DelegatedDisposition_DELEGATED_UNSPECIFIED, 2, true, current, 1},
		{server.DelegatedDisposition(7), 2, true, current, 1},
		{current, 3, false, current, 3},
		{withdrawn, 2, false, current, 3},
		{withdrawn, 4, false, withdrawn, 4},
		{current, 5, false, withdrawn, 4},
		{stopped, 6, false, withdrawn, 4},
		{withdrawn, 4, false, withdrawn, 4},
		{stopped, 4, true, withdrawn, 4},
		{current, 3, false, withdrawn, 4},
	} {
		err := d.Apply(step.disposition, step.revision)
		if step.fails {
			require.Error(t, err, "step %d", i)
		} else {
			require.NoError(t, err, "step %d", i)
		}
		got, rev := d.Current()
		require.Equal(t, step.want, got, "step %d", i)
		require.Equal(t, step.wantRev, rev, "step %d", i)
		select {
		case <-d.Terminal():
			require.Equal(t, withdrawn, got, "announced final at step %d", i)
		default:
			require.NotEqual(t, withdrawn, got, "not announced at step %d", i)
		}
	}

	var first DelegatedDecisions
	require.NoError(t, first.Apply(stopped, 2))
	requireTerminal(t, &first, stopped, 2)
}

// The relay's pushed decisions are ordered on the host and acknowledged as
// received, whatever their effect; one that cannot be ordered is refused.
func TestDelegatedDecisionPush(t *testing.T) {
	relay := startDelegatingRelay(t, &fakeAuthority{})
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	var decisions DelegatedDecisions
	rt := relay.delegatedTunnel(t, hostKey[0], 1, &decisions)
	_, err = rt.Establish(t.Context())
	require.NoError(t, err)

	push := func(d server.DelegatedDisposition, revision uint64) (*server.DelegatedDecisionAck, error) {
		return relay.runtime.PushDecision(t.Context(), &server.DelegatedDecision{ExternalSessionId: externalSessionID, Generation: 1, Disposition: d, DecisionRevision: revision})
	}
	acked := func(revision uint64) *server.DelegatedDecisionAck {
		return &server.DelegatedDecisionAck{ExternalSessionId: externalSessionID, Generation: 1, DecisionRevision: revision}
	}

	ack, err := push(server.DelegatedDisposition_DELEGATED_CURRENT, 2)
	require.NoError(t, err)
	require.True(t, proto.Equal(acked(2), ack))
	ack, err = push(server.DelegatedDisposition_DELEGATED_CURRENT, 1)
	require.NoError(t, err, "a lower revision is still received")
	require.True(t, proto.Equal(acked(1), ack))
	_, err = push(server.DelegatedDisposition_DELEGATED_WITHDRAWN, 2)
	var refused *server.DelegatedRefusedError
	require.ErrorAs(t, err, &refused)
	require.Equal(t, server.DelegatedErrorCode_DELEGATED_INVALID_REQUEST, refused.Code)
	d, revision := decisions.Current()
	require.Equal(t, server.DelegatedDisposition_DELEGATED_CURRENT, d)
	require.Equal(t, uint64(2), revision)
	select {
	case <-decisions.Terminal():
		t.Fatal("a contradicted decision was announced final")
	default:
	}

	ack, err = push(server.DelegatedDisposition_DELEGATED_STOPPED, 3)
	require.NoError(t, err)
	require.True(t, proto.Equal(acked(3), ack))
	requireTerminal(t, &decisions, server.DelegatedDisposition_DELEGATED_STOPPED, 3)
	ack, err = push(server.DelegatedDisposition_DELEGATED_CURRENT, 4)
	require.NoError(t, err, "a decision after a final one is still received")
	require.True(t, proto.Equal(acked(4), ack))
	requireTerminal(t, &decisions, server.DelegatedDisposition_DELEGATED_STOPPED, 3)
}

// What no ordering can place is refused, and changes nothing: bytes that are
// no decision, another session, a generation this connection never
// registered or one it replaced, an unknown disposition, no revision.
func TestDelegatedDecisionRefusals(t *testing.T) {
	relayKey, hostKey, secret := newKeyAndSecret(t)
	id := registration.ID(hostKey.PublicKey(), secret)
	fake := fakerelay.Start(t, relayKey, func(*server.CreateSessionRequest) (bool, []byte) {
		return respond(&server.DelegatedSession{Protocol: testProtocol, ExternalSessionId: externalSessionID, Disposition: server.DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, "user")(id)
	})
	var decisions DelegatedDecisions
	rt := fakeDelegatedTunnel(t, fake, relayKey, hostKey, secret, &decisions)
	_, err := rt.Establish(t.Context())
	require.NoError(t, err)

	decision := func(session string, generation uint64, d server.DelegatedDisposition, revision uint64) []byte {
		b, err := proto.Marshal(&server.DelegatedDecision{ExternalSessionId: session, Generation: generation, Disposition: d, DecisionRevision: revision})
		require.NoError(t, err)
		return b
	}
	stopped := server.DelegatedDisposition_DELEGATED_STOPPED
	for name, tc := range map[string]struct {
		payload []byte
		code    server.DelegatedErrorCode
	}{
		"not a decision":         {[]byte{0xff, 0xff, 0xff}, server.DelegatedErrorCode_DELEGATED_INVALID_REQUEST},
		"too large":              {append(decision(externalSessionID, 1, stopped, 2), make([]byte, maxDelegatedPayload)...), server.DelegatedErrorCode_DELEGATED_INVALID_REQUEST},
		"another session":        {decision("44444444-4444-4444-8444-444444444444", 1, stopped, 2), server.DelegatedErrorCode_DELEGATED_INVALID_REQUEST},
		"a later generation":     {decision(externalSessionID, 2, stopped, 2), server.DelegatedErrorCode_DELEGATED_INVALID_REQUEST},
		"an earlier generation":  {decision(externalSessionID, 0, stopped, 2), server.DelegatedErrorCode_DELEGATED_STALE_GENERATION},
		"no disposition":         {decision(externalSessionID, 1, server.DelegatedDisposition_DELEGATED_UNSPECIFIED, 2), server.DelegatedErrorCode_DELEGATED_INVALID_REQUEST},
		"an unknown disposition": {decision(externalSessionID, 1, server.DelegatedDisposition(9), 2), server.DelegatedErrorCode_DELEGATED_INVALID_REQUEST},
		"no revision":            {decision(externalSessionID, 1, stopped, 0), server.DelegatedErrorCode_DELEGATED_INVALID_REQUEST},
	} {
		t.Run(name, func(t *testing.T) {
			ok, body, err := fake.Push(upterm.HostDelegatedDecisionRequestType, tc.payload)
			require.NoError(t, err)
			require.False(t, ok)
			refused, parsed := server.DecodeDelegatedError(body)
			require.True(t, parsed)
			require.Equal(t, tc.code, refused.Code)
			d, revision := decisions.Current()
			require.Equal(t, server.DelegatedDisposition_DELEGATED_CURRENT, d)
			require.Equal(t, uint64(1), revision)
		})
	}
	select {
	case <-decisions.Terminal():
		t.Fatal("a refused decision was announced final")
	default:
	}

	// Every other request from the relay is answered as before.
	ok, _, err := fake.Push(upterm.OpenSSHKeepAliveRequestType, nil)
	require.NoError(t, err)
	require.False(t, ok)

	ok, body, err := fake.Push(upterm.HostDelegatedDecisionRequestType, decision(externalSessionID, 1, stopped, 2))
	require.NoError(t, err)
	require.True(t, ok)
	var ack server.DelegatedDecisionAck
	require.NoError(t, proto.Unmarshal(body, &ack))
	require.True(t, proto.Equal(&server.DelegatedDecisionAck{ExternalSessionId: externalSessionID, Generation: 1, DecisionRevision: 2}, &ack))
	requireTerminal(t, &decisions, stopped, 2)
}

// A registration's reports are numbered from 1, a new event taking the next
// number, and one sent again before its acknowledgment repeats its number and
// bytes exactly; the disposition the relay answers with is ordered with the
// rest.
func TestDelegatedReports(t *testing.T) {
	ready, exited := DelegatedEvent{}, DelegatedEvent{Exit: true, ExitStatus: -9, StatusKnown: true}

	t.Run("numbered", func(t *testing.T) {
		authority := &fakeAuthority{}
		relay := startDelegatingRelay(t, authority)
		hostKey, err := utils.CreateSigners(nil)
		require.NoError(t, err)
		var decisions DelegatedDecisions
		rt := relay.delegatedTunnel(t, hostKey[0], 3, &decisions)
		_, err = rt.Establish(t.Context())
		require.NoError(t, err)

		require.NoError(t, rt.Report(t.Context(), ready))
		authority.answerControl(func(req *server.DelegatedControlRequest) (*server.DelegatedControlReply, error) {
			return echo(req, server.DelegatedDisposition_DELEGATED_WITHDRAWN, 2), nil
		})
		require.NoError(t, rt.Report(t.Context(), exited))
		_, controls := authority.seen()
		require.Len(t, controls, 2)
		require.True(t, proto.Equal(&server.DelegatedControlRequest{ExternalSessionId: externalSessionID, Generation: 3, Sequence: 1, Event: &server.DelegatedControlRequest_Ready{Ready: &server.DelegatedReady{}}}, controls[0]))
		require.True(t, proto.Equal(&server.DelegatedControlRequest{ExternalSessionId: externalSessionID, Generation: 3, Sequence: 2, Event: &server.DelegatedControlRequest_Exit{Exit: &server.DelegatedExit{ExitStatus: -9, StatusKnown: true}}}, controls[1]))
		requireTerminal(t, &decisions, server.DelegatedDisposition_DELEGATED_WITHDRAWN, 2)

		for name, event := range map[string]DelegatedEvent{
			"ready with a status":       {ExitStatus: 1},
			"ready with a known status": {StatusKnown: true},
			"an unknown status":         {Exit: true, ExitStatus: 2},
		} {
			require.Error(t, rt.Report(t.Context(), event), name)
		}
		_, controls = authority.seen()
		require.Len(t, controls, 2, "an invalid event was sent")
	})

	t.Run("retried identically", func(t *testing.T) {
		authority := &fakeAuthority{}
		refuseOnce := true
		authority.answerControl(func(req *server.DelegatedControlRequest) (*server.DelegatedControlReply, error) {
			if refuseOnce {
				refuseOnce = false
				return nil, &server.DelegatedRefusedError{Code: server.DelegatedErrorCode_DELEGATED_UNAVAILABLE}
			}
			return echo(req, server.DelegatedDisposition_DELEGATED_CURRENT, 1), nil
		})
		relay := startDelegatingRelay(t, authority)
		hostKey, err := utils.CreateSigners(nil)
		require.NoError(t, err)
		var decisions DelegatedDecisions
		rt := relay.delegatedTunnel(t, hostKey[0], 1, &decisions)
		_, err = rt.Establish(t.Context())
		require.NoError(t, err)

		err = rt.Report(t.Context(), ready)
		var refused *server.DelegatedRefusedError
		require.ErrorAs(t, err, &refused)
		require.True(t, refused.Retryable())
		require.NoError(t, rt.Report(t.Context(), ready))
		require.NoError(t, rt.Report(t.Context(), exited))
		_, controls := authority.seen()
		require.Len(t, controls, 3)
		require.True(t, proto.Equal(controls[0], controls[1]), "the retry was not the identical report")
		require.Equal(t, uint64(1), controls[1].Sequence)
		require.Equal(t, uint64(2), controls[2].Sequence)
	})

	// Through a real relay: the retry of a report the relay was slow to
	// answer is that report's answer, not a second report.
	t.Run("an unanswered report's retry takes its answer", func(t *testing.T) {
		authority := &fakeAuthority{}
		release := make(chan struct{})
		var once sync.Once
		authority.answerControl(func(req *server.DelegatedControlRequest) (*server.DelegatedControlReply, error) {
			once.Do(func() { <-release })
			return echo(req, server.DelegatedDisposition_DELEGATED_CURRENT, 1), nil
		})
		relay := startDelegatingRelay(t, authority)
		hostKey, err := utils.CreateSigners(nil)
		require.NoError(t, err)
		var decisions DelegatedDecisions
		rt := relay.delegatedTunnel(t, hostKey[0], 1, &decisions)
		_, err = rt.Establish(t.Context())
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		require.ErrorIs(t, rt.Report(ctx, ready), context.DeadlineExceeded)
		close(release)
		require.NoError(t, rt.Report(t.Context(), ready))
		_, controls := authority.seen()
		require.Len(t, controls, 1, "the retry sent the report again")
		require.Equal(t, uint64(1), controls[0].Sequence)
	})

	// x/crypto sends one want-reply global request at a time, so a report
	// sent again while the relay hasn't answered the first would only queue
	// behind it, one more each retry, for as long as the relay stays silent.
	// A retry waits on the report already sent instead, and takes its answer.
	t.Run("a retry waits on the report already sent", func(t *testing.T) {
		relayKey, hostKey, secret := newKeyAndSecret(t)
		id := registration.ID(hostKey.PublicKey(), secret)
		fake := fakerelay.Start(t, relayKey, func(*server.CreateSessionRequest) (bool, []byte) {
			return respond(&server.DelegatedSession{Protocol: testProtocol, ExternalSessionId: externalSessionID, Disposition: server.DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, "user")(id)
		})
		var decisions DelegatedDecisions
		rt := fakeDelegatedTunnel(t, fake, relayKey, hostKey, secret, &decisions)
		_, err := rt.Establish(t.Context())
		require.NoError(t, err)

		var (
			mu       sync.Mutex
			payloads [][]byte
		)
		arrived := make(chan struct{})
		var once sync.Once
		release := make(chan struct{})
		// A failure before the relay is let answer must not leave its
		// handler blocked: registered after the relay's own cleanup, this
		// runs first.
		unblock := sync.OnceFunc(func() { close(release) })
		t.Cleanup(unblock)
		fake.Handle(upterm.ServerDelegatedControlRequestType, func(payload []byte) (bool, []byte) {
			var req server.DelegatedControlRequest
			if err := proto.Unmarshal(payload, &req); err != nil {
				return false, nil
			}
			mu.Lock()
			payloads = append(payloads, payload)
			mu.Unlock()
			once.Do(func() { close(arrived) })
			<-release
			b, _ := proto.Marshal(echo(&req, server.DelegatedDisposition_DELEGATED_CURRENT, 1))
			return true, b
		})

		// The first report reaches the relay, which doesn't answer it.
		first, cancelFirst := context.WithCancel(t.Context())
		reported := make(chan error, 1)
		go func() { reported <- rt.Report(first, ready) }()
		select {
		case <-arrived:
		case <-time.After(10 * time.Second):
			t.Fatal("the report never reached the relay")
		}
		cancelFirst()
		require.ErrorIs(t, <-reported, context.Canceled)

		// Retries whose wait is over before the relay answers, as one whose
		// time ran out is.
		over, cancel := context.WithCancel(t.Context())
		cancel()
		for range 3 {
			require.ErrorIs(t, rt.Report(over, ready), context.Canceled)
		}

		unblock()
		require.NoError(t, rt.Report(t.Context(), ready), "the relay's answer to the report already sent wasn't taken")
		mu.Lock()
		defer mu.Unlock()
		require.Equal(t, 1, len(payloads), "a retry sent the report again behind the one the relay hadn't answered")
		d, revision := decisions.Current()
		require.Equal(t, server.DelegatedDisposition_DELEGATED_CURRENT, d)
		require.Equal(t, uint64(1), revision)
	})

	t.Run("answers outside the protocol", func(t *testing.T) {
		relayKey, hostKey, secret := newKeyAndSecret(t)
		id := registration.ID(hostKey.PublicKey(), secret)
		fake := fakerelay.Start(t, relayKey, func(*server.CreateSessionRequest) (bool, []byte) {
			return respond(&server.DelegatedSession{Protocol: testProtocol, ExternalSessionId: externalSessionID, Disposition: server.DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, "user")(id)
		})
		var decisions DelegatedDecisions
		rt := fakeDelegatedTunnel(t, fake, relayKey, hostKey, secret, &decisions)
		_, err := rt.Establish(t.Context())
		require.NoError(t, err)

		var (
			mu       sync.Mutex
			payloads [][]byte
			answer   func(*server.DelegatedControlRequest) (bool, []byte)
		)
		fake.Handle(upterm.ServerDelegatedControlRequestType, func(payload []byte) (bool, []byte) {
			var req server.DelegatedControlRequest
			if err := proto.Unmarshal(payload, &req); err != nil {
				return false, nil
			}
			mu.Lock()
			payloads = append(payloads, payload)
			fn := answer
			mu.Unlock()
			return fn(&req)
		})
		reply := func(r *server.DelegatedControlReply) (bool, []byte) {
			b, _ := proto.Marshal(r)
			return true, b
		}
		for name, fn := range map[string]func(*server.DelegatedControlRequest) (bool, []byte){
			"another sequence": func(req *server.DelegatedControlRequest) (bool, []byte) {
				r := echo(req, server.DelegatedDisposition_DELEGATED_CURRENT, 1)
				r.AcknowledgedSequence = 9
				return reply(r)
			},
			"another generation": func(req *server.DelegatedControlRequest) (bool, []byte) {
				r := echo(req, server.DelegatedDisposition_DELEGATED_CURRENT, 1)
				r.Generation = 2
				return reply(r)
			},
			"no disposition": func(req *server.DelegatedControlRequest) (bool, []byte) {
				return reply(echo(req, server.DelegatedDisposition_DELEGATED_UNSPECIFIED, 1))
			},
			"a contradiction": func(req *server.DelegatedControlRequest) (bool, []byte) {
				return reply(echo(req, server.DelegatedDisposition_DELEGATED_STOPPED, 1))
			},
			"a plain refusal": func(*server.DelegatedControlRequest) (bool, []byte) { return false, []byte("secret relay text") },
			"unreadable":      func(*server.DelegatedControlRequest) (bool, []byte) { return true, []byte{0xff, 0xff} },
		} {
			t.Run(name, func(t *testing.T) {
				mu.Lock()
				answer = fn
				mu.Unlock()
				err := rt.Report(t.Context(), ready)
				require.ErrorIs(t, err, ErrDelegatedRelayUnsupported)
				require.NotContains(t, err.Error(), "secret")
			})
		}
		mu.Lock()
		defer mu.Unlock()
		for _, payload := range payloads[1:] {
			require.Equal(t, payloads[0], payload, "an unacknowledged report changed between sends")
		}
		d, revision := decisions.Current()
		require.Equal(t, server.DelegatedDisposition_DELEGATED_CURRENT, d)
		require.Equal(t, uint64(1), revision)
	})

	t.Run("only a delegated registration reports", func(t *testing.T) {
		require.Error(t, (&ReverseTunnel{}).Report(t.Context(), ready))
		relay := startTestRelay(t)
		hostKey, err := utils.CreateSigners(nil)
		require.NoError(t, err)
		rt := relay.tunnel(hostKey[0], relay.url)
		t.Cleanup(rt.Close)
		_, err = rt.Establish(t.Context())
		require.NoError(t, err)
		require.Error(t, rt.Report(t.Context(), ready))
	})
}

// The checks a delegated registration's own fields are held to before
// anything is dialled: a protocol of 1 to 64 printable ASCII bytes with no
// whitespace, and an external session ID in the same canonical form the
// relay accepts, checked against the relay's own vectors.
func TestDelegatedFieldChecks(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		ok       bool
	}{
		{"test_v1", true},
		{"a", true},
		{strings.Repeat("p", 64), true},
		{strings.Repeat("p", 65), false},
		{"", false},
		{"test v1", false},
		{"test\tv1", false},
		{"test\nv1", false},
		{"test\x00v1", false},
		{"test\x7fv1", false},
		{"tést", false},
		{"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", true},
	} {
		require.Equal(t, tc.ok, ValidDelegatedProtocol(tc.protocol), "%q", tc.protocol)
	}

	f, err := os.Open("../../server/testdata/uuid-vectors.txt")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	seen := map[bool]int{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		verdict, quoted, ok := strings.Cut(line, " ")
		require.True(t, ok, "a vector is VERDICT QUOTED: %q", line)
		value, err := strconv.Unquote(quoted)
		require.NoError(t, err, "%q", line)
		var want bool
		switch verdict {
		case "accept":
			want = true
		case "refuse":
		default:
			t.Fatalf("unknown verdict in %q", line)
		}
		require.Equal(t, want, ValidUUID(value), "%q", line)
		seen[want]++
	}
	require.NoError(t, scanner.Err())
	require.NotZero(t, seen[true])
	require.NotZero(t, seen[false])
}
