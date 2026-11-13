//go:build !windows

package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/internal/testhelpers/fakerelay"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	testService      = "https://authority.test"
	testProtocol     = "test_v1"
	testExternalID   = "33333333-3333-4333-8333-333333333333"
	testAccount      = "11111111-1111-4111-8111-111111111111"
	testLogin        = "66666666-6666-4666-8666-666666666666"
	testGuestAddress = "work"
	testAuthority    = "Example"
)

// testAuthorityRelay is a delegating relay's authority: it records every
// registration and report, answers them with register and control or, where
// those are nil, with a current decision at revision 1, and pokes calls
// after each.
type testAuthorityRelay struct {
	mu            sync.Mutex
	registrations []server.DelegatedRegistration
	controls      []*server.DelegatedControlRequest
	register      func(server.DelegatedRegistration) (server.RegistrationResult, error)
	control       func(*server.DelegatedControlRequest) (*server.DelegatedControlReply, error)
	calls         *wakeups
}

func (a *testAuthorityRelay) Register(_ context.Context, r server.DelegatedRegistration) (server.RegistrationResult, error) {
	a.mu.Lock()
	a.registrations = append(a.registrations, r)
	answer := a.register
	a.mu.Unlock()
	defer a.calls.poke()
	if answer == nil {
		return server.RegistrationResult{AccountID: testAccount, Disposition: server.DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, nil
	}
	return answer(r)
}

func (a *testAuthorityRelay) Control(_ context.Context, r server.Report) (*server.DelegatedControlReply, error) {
	a.mu.Lock()
	a.controls = append(a.controls, r.Request)
	answer := a.control
	a.mu.Unlock()
	defer a.calls.poke()
	if answer == nil {
		return delegatedReply(r.Request, server.DelegatedDisposition_DELEGATED_CURRENT, 1), nil
	}
	return answer(r.Request)
}

// The relay's authority decides no guest: these tests are the host's.
func (a *testAuthorityRelay) Claims(string) bool { return false }

func (a *testAuthorityRelay) Admit(context.Context, *server.Guest, server.GuestRequest) (server.Admission, error) {
	return server.Admission{}, nil
}

func (a *testAuthorityRelay) Unreachable(context.Context, *server.Guest, server.Target) []byte {
	return nil
}

func (a *testAuthorityRelay) seen() ([]server.DelegatedRegistration, []*server.DelegatedControlRequest) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]server.DelegatedRegistration(nil), a.registrations...), append([]*server.DelegatedControlRequest(nil), a.controls...)
}

// awaitControls waits for the relay to have been sent n reports.
func (a *testAuthorityRelay) awaitControls(t *testing.T, n int) []*server.DelegatedControlRequest {
	t.Helper()
	var controls []*server.DelegatedControlRequest
	a.calls.until(t, 10*time.Second, func() bool {
		_, controls = a.seen()
		return len(controls) >= n
	}, func() string { return fmt.Sprintf("the relay was sent %d reports, not %d", len(controls), n) })
	return controls
}

// awaitRegistrations waits for the relay to have decided n registrations.
func (a *testAuthorityRelay) awaitRegistrations(t *testing.T, n int) []server.DelegatedRegistration {
	t.Helper()
	var registrations []server.DelegatedRegistration
	a.calls.until(t, 10*time.Second, func() bool {
		registrations, _ = a.seen()
		return len(registrations) >= n
	}, func() string { return fmt.Sprintf("the relay decided %d registrations, not %d", len(registrations), n) })
	return registrations
}

func delegatedReply(req *server.DelegatedControlRequest, d server.DelegatedDisposition, revision uint64) *server.DelegatedControlReply {
	return &server.DelegatedControlReply{ExternalSessionId: req.ExternalSessionId, Generation: req.Generation, AcknowledgedSequence: req.Sequence, Disposition: d, DecisionRevision: revision}
}

func registeredAs(d server.DelegatedDisposition, revision uint64) func(server.DelegatedRegistration) (server.RegistrationResult, error) {
	return func(server.DelegatedRegistration) (server.RegistrationResult, error) {
		return server.RegistrationResult{AccountID: testAccount, Disposition: d, DecisionRevision: revision}, nil
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

// delegatingRelay is an in-process relay with an enabled authority: one TCP
// SSH listener, an internal listener, embedded routing, and authority
// deciding its delegated hosts. It presents a host certificate for 127.0.0.1
// signed by its key, which is the key a placement pins.
type delegatingRelay struct {
	runtime   server.Runtime
	addr      string
	key       ssh.Signer
	authority *testAuthorityRelay
}

func startDelegatingRelay(t *testing.T, key ssh.Signer) *delegatingRelay {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cert, err := (&server.HostCertSigner{Hostnames: []string{"127.0.0.1"}}).SignCert(key)
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	network := &server.MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))
	sessions, err := server.NewSessionManager(routing.ModeEmbedded, server.WithSessionManagerLogger(logger))
	require.NoError(t, err)
	authority := &testAuthorityRelay{calls: newWakeups()}
	lifecycle := runtimeOf{rt: make(chan server.Runtime, 1)}
	srv := &server.Server{
		NodeAddr:         ln.Addr().String(),
		HostSigners:      []ssh.Signer{cert},
		Signers:          []ssh.Signer{key},
		NetworkProvider:  network,
		MetricsProvider:  provider.NewDiscardProvider(),
		SessionManager:   sessions,
		Logger:           logger,
		Extensions:       server.Extensions{Authority: authority, Enabled: true, Protocols: []string{testProtocol}, Lifecycle: lifecycle},
		RefuseLegacyHops: true,
		NodeID:           "test-node", BootID: "55555555-5555-4555-8555-555555555555",
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	internalLn, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { served <- srv.ServeListeners(ctx, server.Listeners{SSH: ln, Internal: internalLn}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-served:
			require.NoError(t, err, "a relay told to stop reports a clean stop")
		case <-time.After(10 * time.Second):
			t.Error("the relay did not stop")
		}
	})
	var rt server.Runtime
	select {
	case rt = <-lifecycle.rt:
	case err := <-served:
		t.Fatalf("the relay stopped before it started: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the relay never started its lifecycle")
	}
	readyCtx, readyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readyCancel()
	require.NoError(t, utils.WaitForServer(readyCtx, ln.Addr().String()))
	return &delegatingRelay{runtime: rt, addr: ln.Addr().String(), key: key, authority: authority}
}

// push sends the host of generation the relay's decision d at revision.
func (r *delegatingRelay) push(t *testing.T, generation uint64, d server.DelegatedDisposition, revision uint64) {
	t.Helper()
	require.NoError(t, r.pushed(generation, d, revision))
}

// pushed is push for a goroutine other than the test's: it returns what went
// wrong rather than failing the test.
func (r *delegatingRelay) pushed(generation uint64, d server.DelegatedDisposition, revision uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ack, err := r.runtime.PushDecision(ctx, &server.DelegatedDecision{
		ExternalSessionId: testExternalID, Generation: generation, Disposition: d, DecisionRevision: revision})
	if err != nil {
		return err
	}
	if ack.DecisionRevision != revision {
		return fmt.Errorf("the host acknowledged revision %d, not %d", ack.DecisionRevision, revision)
	}
	return nil
}

// brokerFunc is a Broker that is a function.
type brokerFunc func(ctx context.Context, run Run) (Placement, error)

func (f brokerFunc) Place(ctx context.Context, run Run) (Placement, error) { return f(ctx, run) }

// delegatedHost runs a real delegated Host, with a session record, against
// a delegating relay it reaches through a forwarder. Its broker places the
// run as testExternalID at testGuestAddress, at the forwarder, pinning pins.
type delegatedHost struct {
	*reconnectHost
	delegatingRelay *delegatingRelay
	// pins are the relay keys the placement lists: the relay's key, unless
	// an option says otherwise.
	pins [][]byte
	// created receives what SessionCreatedCallback was given, decided what
	// DecisionCallback was.
	created chan *api.GetSessionResponse
	decided chan Decision

	mu     sync.Mutex
	run    Run
	places int
}

type delegatedOption func(*delegatedHost)

// withCommand hosts command in place of the ticking one.
func withCommand(command ...string) delegatedOption {
	return func(f *delegatedHost) { f.h.Command = command }
}

// newDelegatedHost starts a delegating relay, a forwarder to it, and a
// delegated host, with opts applied before the host runs. It returns at
// once: a test waits for what it expects, a session or a failure.
func newDelegatedHost(t *testing.T, opts ...delegatedOption) *delegatedHost {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "up-dl-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	t.Setenv("XDG_RUNTIME_DIR", root)
	t.Setenv("XDG_STATE_HOME", root)

	relayKey, err := NewHostKey()
	require.NoError(t, err)
	identity, err := NewHostKey()
	require.NoError(t, err)
	relay := startDelegatingRelay(t, relayKey)

	f := &delegatedHost{
		reconnectHost: &reconnectHost{
			fwd:       testhelpers.NewForwarder(t, relay.addr),
			root:      root,
			stateRoot: utils.UptermStateDir(),
			ready:     make(chan string, 1),
			done:      make(chan error, 1),
			logs:      &lockedBuffer{},
			records:   newWakeups(),
			statuses:  newWakeups(),
		},
		delegatingRelay: relay,
		pins:            [][]byte{relayKey.PublicKey().Marshal()},
		created:         make(chan *api.GetSessionResponse, 1),
		decided:         make(chan Decision, 2),
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("host log:\n%s", f.logs.String())
		}
	})
	f.h = &Host{
		// Never dialled: a delegated run registers where it was placed, and
		// never through a proxy, so a run that dialled either would fail.
		Host:     "ssh://" + closedAddr(t),
		ProxyURL: &url.URL{Scheme: "http", Host: closedAddr(t)},
		Name:     "delegated",
		Command:  []string{"sh", "-c", `i=0; while :; do i=$((i+1)); echo "` + reconnectTick + ` $i"; sleep 0.05; done`},
		Signers:  []ssh.Signer{identity},
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error {
			t.Error("a delegated run consulted the host key callback")
			return errors.New("no host key callback for a delegated run")
		},
		KeepAliveDuration: time.Second,
		StopGrace:         50 * time.Millisecond,
		Reconnect:         reconnectTiming,
		Logger:            slog.New(slog.NewTextHandler(f.logs, nil)),
		Broker:            brokerFunc(f.place),
		DecisionCallback: func(d Decision) {
			f.decided <- d
		},
		SessionCreatedCallback: func(_ context.Context, s *api.GetSessionResponse) error {
			f.created <- s
			return nil
		},
		SessionReadyCallback: func(status string) { f.ready <- status },
		onRecord:             f.records.poked,
		onStatus:             f.statuses.poke,
	}
	for _, opt := range opts {
		opt(f)
	}

	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		f.done <- f.h.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("Host.Run did not return after its context was cancelled")
		}
	})
	return f
}

// place is the broker: it places the run at the forwarder.
func (f *delegatedHost) place(_ context.Context, run Run) (Placement, error) {
	f.mu.Lock()
	f.run = run
	f.places++
	f.mu.Unlock()
	return Placement{
		RoutingID:    run.RoutingID,
		Relay:        f.fwd.Addr(),
		Trust:        InitialTrust{Keys: f.pins},
		Protocol:     testProtocol,
		ExternalID:   testExternalID,
		GuestAddress: testGuestAddress,
		Association:  sessiondir.DelegationAssociation{Service: testService, Account: testAccount, Login: testLogin},
		Display:      sessiondir.DelegationDisplay{Authority: testAuthority},
	}, nil
}

func (f *delegatedHost) placed() (Run, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.run, f.places
}

func (f *delegatedHost) awaitCreated(t *testing.T) *api.GetSessionResponse {
	t.Helper()
	select {
	case s := <-f.created:
		return s
	case err := <-f.done:
		t.Fatalf("Host.Run returned before the session was created: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the session was not created")
	}
	return nil
}

func (f *delegatedHost) awaitDecided(t *testing.T) Decision {
	t.Helper()
	select {
	case d := <-f.decided:
		return d
	case <-time.After(10 * time.Second):
		t.Fatal("the host was never told what the authority decided")
		return 0
	}
}

// requireUndecided fails the test if the host was told of a decision.
func (f *delegatedHost) requireUndecided(t *testing.T) {
	t.Helper()
	select {
	case d := <-f.decided:
		t.Fatalf("the host was told the authority decided %d", d)
	default:
	}
}

// markerCommand is a command that leaves a file behind the moment it runs.
func markerCommand(t *testing.T) (command []string, ran func() bool) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "ran")
	return []string{"sh", "-c", "touch " + marker + "; sleep 30"}, func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}
}

// wantDelegation is the record's delegation for the fixture's placement.
func wantDelegation(f *delegatedHost, routingID string) *sessiondir.Delegation {
	return &sessiondir.Delegation{
		DelegationAssociation: sessiondir.DelegationAssociation{Service: testService, Account: testAccount, Login: testLogin},
		DelegationDisplay:     sessiondir.DelegationDisplay{Authority: testAuthority, Links: []sessiondir.DelegationLink{}, Notes: []string{}},
		ExternalSessionID:     testExternalID,
		RoutingID:             routingID,
		Relay:                 f.fwd.Addr(),
		GuestAddress:          testGuestAddress,
	}
}

// A delegated run registers only with the relay its placement named,
// trusting only the keys the placement listed: the host's own --server and
// its host key callback are never consulted. What it registers is the
// placement's external session, under the run key and routing ID the broker
// was given, and the record ties the local session to it before the relay is
// dialled. The broker is told the run as the host has it.
func TestStartRelayTrustFromThePlacement(t *testing.T) {
	var atRegistration *sessiondir.Record
	f := newDelegatedHost(t, func(f *delegatedHost) {
		f.h.ForceCommand = []string{"top"}
		f.h.NameGenerated = true
		// With no authorized keys, what would make a local session open.
		f.h.AutoAccept = true
		f.delegatingRelay.authority.register = func(server.DelegatedRegistration) (server.RegistrationResult, error) {
			rec, err := sessiondir.ReadRecord(f.stateRoot, f.h.Name)
			if err == nil {
				atRegistration = rec
			}
			return server.RegistrationResult{AccountID: testAccount, Disposition: server.DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, nil
		}
	})

	created := f.awaitCreated(t)
	require.Equal(t, "ssh://"+f.fwd.Addr(), created.GetHost(), "the session is described at the relay it was placed on")
	require.Equal(t, testGuestAddress, created.GetSshUser(), "guests reach a delegated session at its guest address")
	require.False(t, created.GetOpen(), "a delegated session is not open to anyone with its ID")
	require.Equal(t, testGuestAddress, created.GetDelegatedAddress(), "a delegated session says it is one, at its guest address")
	f.awaitReady(t)

	run, places := f.placed()
	require.Equal(t, 1, places)
	require.Equal(t, "delegated", run.Name)
	require.True(t, run.NameGenerated)
	require.Equal(t, f.h.Command, run.Command)
	require.Equal(t, []string{"top"}, run.ForceCommand)
	require.Empty(t, run.LoginCommand)
	registrations, _ := f.delegatingRelay.authority.seen()
	require.Len(t, registrations, 1)
	reg := registrations[0]
	require.NotNil(t, reg.Session)
	require.Equal(t, testProtocol, reg.Session.GetProtocol())
	require.Equal(t, testExternalID, reg.Session.GetExternalSessionId())
	require.Equal(t, run.RunKey.Marshal(), reg.RunPublicKey.Marshal(), "the registration proves the key the broker was given")
	require.Equal(t, run.RoutingID, reg.RoutingID, "and registers under the routing ID the broker was given")
	require.Equal(t, uint64(1), reg.Generation)

	want := wantDelegation(f, run.RoutingID)
	require.NotNil(t, atRegistration)
	require.Equal(t, want, atRegistration.Delegation, "the delegation was recorded before the relay was dialled")
	rec := f.record(t)
	require.Equal(t, want, rec.Delegation)
	require.Equal(t, run.RoutingID, rec.SessionID)
	require.Len(t, rec.HostKeys, 1)
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rec.HostKeys[0]))
	require.NoError(t, err)
	require.Equal(t, run.RunKey.Marshal(), key.Marshal(), "the run key is the session's own host key")
}

// A broker that holds other runs off until this one can be seen is told when
// Run is through recording: once, after the record has the delegation, the
// session it superseded included, and before anything is dialled; and once
// all the same when the placement is refused.
func TestPublishedRunsOnEveryOutcome(t *testing.T) {
	const predecessor = "77777777-7777-4777-8777-777777777777"
	// published sends what the record said each time the broker was told,
	// and whether the relay had been dialled by then.
	type published struct {
		rec    *sessiondir.Record
		dialed bool
	}
	telling := func(told chan published, mutate func(*Placement)) delegatedOption {
		return func(f *delegatedHost) {
			f.h.Broker = brokerFunc(func(ctx context.Context, run Run) (Placement, error) {
				p, err := f.place(ctx, run)
				mutate(&p)
				p.Published = func() {
					rec, _ := sessiondir.ReadRecord(f.stateRoot, f.h.Name)
					registrations, _ := f.delegatingRelay.authority.seen()
					told <- published{rec: rec, dialed: len(registrations) > 0}
				}
				return p, err
			})
		}
	}

	t.Run("published", func(t *testing.T) {
		told := make(chan published, 2)
		f := newDelegatedHost(t, telling(told, func(p *Placement) { p.Association.SupersededSessionID = predecessor }))
		f.awaitReady(t)
		var got published
		select {
		case got = <-told:
		default:
			t.Fatal("never told the session was published")
		}
		require.NotNil(t, got.rec)
		require.NotNil(t, got.rec.Delegation, "told before the delegation was recorded")
		require.Equal(t, testExternalID, got.rec.Delegation.ExternalSessionID)
		require.Equal(t, predecessor, got.rec.Delegation.SupersededSessionID)
		require.False(t, got.dialed, "told after the relay was dialled")
		require.Equal(t, predecessor, f.record(t).Delegation.SupersededSessionID)
		select {
		case <-told:
			t.Fatal("told twice")
		default:
		}
	})

	t.Run("refused", func(t *testing.T) {
		told := make(chan published, 2)
		f := newDelegatedHost(t, telling(told, func(p *Placement) { p.RoutingID = "not-this-runs" }))
		require.EqualError(t, f.awaitRun(t, 10*time.Second), "the placement for this run is invalid: the routing ID is not this run's")
		select {
		case got := <-told:
			require.NotNil(t, got.rec)
			require.Nil(t, got.rec.Delegation, "a refused placement is not recorded")
			require.False(t, got.dialed)
		default:
			t.Fatal("never told about a placement that was refused")
		}
		select {
		case <-told:
			t.Fatal("told twice")
		default:
		}
	})
}

// A relay presenting a key the placement did not list is refused before the
// host authenticates, so it is never registered with and the command never
// runs.
func TestRelayPinMismatchNeverLaunches(t *testing.T) {
	command, ran := markerCommand(t)
	other, err := NewHostKey()
	require.NoError(t, err)
	f := newDelegatedHost(t, withCommand(command...), func(f *delegatedHost) {
		f.pins = [][]byte{other.PublicKey().Marshal()}
	})

	err = f.awaitRun(t, 10*time.Second)
	var notPinned *internal.RelayKeyNotPinnedError
	require.ErrorAs(t, err, &notPinned)
	require.Contains(t, err.Error(), " is not one "+testAuthority+" listed for this relay")
	require.False(t, ran(), "no command is launched for a relay outside the pins")
	registrations, controls := f.delegatingRelay.authority.seen()
	require.Empty(t, registrations, "nothing registered with a relay outside the pins")
	require.Empty(t, controls)
	select {
	case <-f.created:
		t.Fatal("a session was created on a relay outside the pins")
	default:
	}
	rec := f.record(t)
	require.Equal(t, sessiondir.ReasonStartupFailed, rec.Reason)
}

// A relay may move to any key the placement listed, and to no other: a
// redial to the second pin is a session back on the relay, and a redial to a
// key outside the pins is refused, and kept trying, as a changed relay key.
func TestRelayRotationWithinPlacementPins(t *testing.T) {
	rotatedKey, err := NewHostKey()
	require.NoError(t, err)
	rotated := startDelegatingRelay(t, rotatedKey)
	strangerKey, err := NewHostKey()
	require.NoError(t, err)
	stranger := startDelegatingRelay(t, strangerKey)

	f := newDelegatedHost(t, func(f *delegatedHost) {
		f.pins = append(f.pins, rotatedKey.PublicKey().Marshal())
	})
	f.awaitCreated(t)
	f.awaitReady(t)

	f.fwd.Redirect(rotated.addr)
	f.fwd.Cut()
	reg := rotated.authority.awaitRegistrations(t, 1)[0]
	require.Equal(t, uint64(2), reg.Generation)
	f.awaitStatus(t, sessiondir.StatusReady, 10*time.Second)

	f.fwd.Redirect(stranger.addr)
	f.fwd.Cut()
	var rec *sessiondir.Record
	f.records.until(t, 10*time.Second, func() bool {
		rec = f.record(t)
		return rec.Status == sessiondir.StatusReconnecting && rec.TunnelReason == sessiondir.TunnelReasonRelayKeyChanged
	}, func() string {
		return fmt.Sprintf("the redial to a key outside the pins was not refused as one: %s (reason %q, error %q)", rec.Status, rec.TunnelReason, rec.TunnelError)
	})
	require.Contains(t, rec.TunnelError, " is not one "+testAuthority+" listed for this relay")
	registrations, _ := stranger.authority.seen()
	require.Empty(t, registrations, "a relay outside the pins is never registered with")
}

// The authority stopping a running session stops it as `session stop` does:
// the command is terminated, its exit is reported on the registration, and
// the record says it was stopped. A stop pushed to the host and a stop in a
// report's reply are the same stop.
func TestStoppedTerminatesAndReportsExit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply bool
	}{{"pushed", false}, {"in a reply", true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDelegatedHost(t, func(f *delegatedHost) {
				if tc.reply {
					f.delegatingRelay.authority.control = func(req *server.DelegatedControlRequest) (*server.DelegatedControlReply, error) {
						return delegatedReply(req, server.DelegatedDisposition_DELEGATED_STOPPED, 2), nil
					}
				}
			})
			f.awaitCreated(t)
			f.awaitReady(t)
			ready := f.delegatingRelay.authority.awaitControls(t, 1)[0]
			require.NotNil(t, ready.GetReady())
			require.Equal(t, uint64(1), ready.GetSequence())
			if !tc.reply {
				f.delegatingRelay.push(t, 1, server.DelegatedDisposition_DELEGATED_STOPPED, 2)
			}

			require.Equal(t, DecisionStopped, f.awaitDecided(t))
			err := f.awaitRun(t, 15*time.Second)
			require.ErrorIs(t, err, errSessionStopped)
			rec := f.record(t)
			require.Equal(t, sessiondir.ReasonStopped, rec.Reason)
			require.Equal(t, sessiondir.DecisionStopped, rec.Delegation.Decision, "the record says it was the authority that stopped it")
			require.Contains(t, f.logs.String(), testAuthority+" stopped the session; terminating the command")

			controls := f.delegatingRelay.authority.awaitControls(t, 2)
			require.Len(t, controls, 2)
			exit := controls[1]
			require.NotNil(t, exit.GetExit(), "the command's exit is reported")
			require.Equal(t, testExternalID, exit.GetExternalSessionId())
			require.Equal(t, uint64(1), exit.GetGeneration())
			require.Equal(t, uint64(2), exit.GetSequence())
		})
	}
}

// The authority stopping a session is acted on before anyone is told: by the
// time the callback runs, the session's teardown has begun, so a callback
// that is slow to tell anyone holds up nothing.
func TestStopIsRequestedBeforeItsCallback(t *testing.T) {
	sawEnding := make(chan bool, 1)
	f := newDelegatedHost(t, func(f *delegatedHost) {
		f.h.DecisionCallback = func(Decision) {
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				if rec, err := sessiondir.ReadRecord(f.stateRoot, f.h.Name); err == nil && rec.Status == sessiondir.StatusEnding {
					sawEnding <- true
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			sawEnding <- false
		}
	})
	f.awaitCreated(t)
	f.awaitReady(t)
	f.delegatingRelay.authority.awaitControls(t, 1)
	f.delegatingRelay.push(t, 1, server.DelegatedDisposition_DELEGATED_STOPPED, 2)

	select {
	case saw := <-sawEnding:
		require.True(t, saw, "the stop waited on the callback")
	case <-time.After(15 * time.Second):
		t.Fatal("the callback was never called")
	}
	require.ErrorIs(t, f.awaitRun(t, 15*time.Second), errSessionStopped)
}

// Whoever is told the session stopped can read whose stop it was: the record
// says the authority stopped it before the stop is even requested.
func TestStopIsRecordedBeforeItIsRequested(t *testing.T) {
	atRequest := make(chan string, 1)
	f := newDelegatedHost(t, func(f *delegatedHost) {
		f.h.onStopRequested = func() {
			decision := "no record"
			if rec, err := sessiondir.ReadRecord(f.stateRoot, f.h.Name); err == nil && rec.Delegation != nil {
				decision = rec.Delegation.Decision
			}
			select {
			case atRequest <- decision:
			default:
			}
		}
	})
	f.awaitCreated(t)
	f.awaitReady(t)
	f.delegatingRelay.authority.awaitControls(t, 1)
	f.delegatingRelay.push(t, 1, server.DelegatedDisposition_DELEGATED_STOPPED, 2)

	require.ErrorIs(t, f.awaitRun(t, 15*time.Second), errSessionStopped)
	select {
	case decision := <-atRequest:
		require.Equal(t, sessiondir.DecisionStopped, decision, "the stop was requested before the record said whose it was")
	default:
		t.Fatal("the stop was never requested")
	}
	require.Equal(t, DecisionStopped, f.awaitDecided(t))
}

// The authority withdrawing a running session ends its remote access and
// nothing else: the command goes on running, the local terminal stays
// attached, the admin socket answers, nothing is redialled, and no exit is
// reported when the session later stops.
func TestWithdrawnKeepsCommandAndLocalAttach(t *testing.T) {
	f := newDelegatedHost(t)
	f.awaitCreated(t)
	f.awaitReady(t)
	local := f.attachLocally(t)
	f.delegatingRelay.authority.awaitControls(t, 1)

	f.delegatingRelay.push(t, 1, server.DelegatedDisposition_DELEGATED_WITHDRAWN, 2)
	require.Equal(t, DecisionWithdrawn, f.awaitDecided(t))
	rec := f.awaitStatus(t, sessiondir.StatusDisconnected, 10*time.Second)
	require.Equal(t, sessiondir.TunnelReasonWithdrawn, rec.TunnelReason)
	require.Equal(t, sessiondir.DecisionWithdrawn, f.record(t).Delegation.Decision)
	require.Contains(t, f.logs.String(), testAuthority+" withdrew the session's remote access; the command goes on running locally")

	// The relay's connection to the host is closed: it has nowhere left to
	// send a decision.
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := f.delegatingRelay.runtime.PushDecision(ctx, &server.DelegatedDecision{ExternalSessionId: testExternalID,
			Generation: 1, Disposition: server.DelegatedDisposition_DELEGATED_WITHDRAWN, DecisionRevision: 2})
		return errors.Is(err, server.ErrDelegatedHostNotFound)
	}, 10*time.Second, 50*time.Millisecond, "the delegated tunnel is still open")

	before := lastTick(local.out.String())
	require.Eventually(t, func() bool { return lastTick(local.out.String()) > before+3 }, 5*time.Second, 10*time.Millisecond,
		"the command stopped running after the withdrawal")
	local.requireAttached(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sess, err := f.admin(t).GetSession(ctx, &api.GetSessionRequest{})
	require.NoError(t, err)
	require.Equal(t, sessiondir.StatusDisconnected, sess.GetStatus())
	require.Equal(t, testGuestAddress, sess.GetDelegatedAddress(), "a withdrawn session still says it is delegated, at its guest address")
	select {
	case err := <-f.done:
		t.Fatalf("Host.Run returned after a withdrawal: %v", err)
	default:
	}

	// Long enough for several redials at this fixture's pace, had the
	// withdrawal left any to happen.
	time.Sleep(10 * reconnectTiming.FastCap)
	registrations, _ := f.delegatingRelay.authority.seen()
	require.Len(t, registrations, 1, "a withdrawn session is not redialled")

	f.stop(t)
	require.ErrorIs(t, f.awaitRun(t, 15*time.Second), errSessionStopped)
	require.Equal(t, sessiondir.ReasonStopped, f.record(t).Reason)
	_, controls := f.delegatingRelay.authority.seen()
	require.Len(t, controls, 1, "no exit is reported after a withdrawal")
	require.NotNil(t, controls[0].GetReady())
}

// A session the authority stops or withdraws before its command started
// launches nothing: decided in the registration's reply, pushed while the
// command waits for its first client, or pushed while the session is being
// created, on a host with nothing else holding the command back.
func TestDecisionBeforeLaunchLaunchesNothing(t *testing.T) {
	for _, tc := range []struct {
		d    server.DelegatedDisposition
		want string
	}{
		{server.DelegatedDisposition_DELEGATED_STOPPED, testAuthority + " stopped the session before its command started; no command was launched"},
		{server.DelegatedDisposition_DELEGATED_WITHDRAWN, testAuthority + " withdrew the session before its command started; no command was launched"},
	} {
		t.Run(tc.d.String()+"/in the registration's reply", func(t *testing.T) {
			command, ran := markerCommand(t)
			f := newDelegatedHost(t, withCommand(command...), func(f *delegatedHost) {
				f.delegatingRelay.authority.register = registeredAs(tc.d, 1)
			})
			require.EqualError(t, f.awaitRun(t, 10*time.Second), tc.want)
			require.False(t, ran())
			select {
			case <-f.created:
				t.Fatal("a session the authority decided against was created")
			default:
			}
			_, controls := f.delegatingRelay.authority.seen()
			require.Empty(t, controls)
			require.Equal(t, sessiondir.ReasonStartupFailed, f.record(t).Reason)
			require.Contains(t, f.logs.String(), testAuthority+" decided against the session before its command started")
		})
		t.Run(tc.d.String()+"/pushed before the command starts", func(t *testing.T) {
			command, ran := markerCommand(t)
			f := newDelegatedHost(t, withCommand(command...), func(f *delegatedHost) {
				f.h.AwaitInitialClient = true
				f.h.InitialClientTimeout = time.Minute
			})
			f.awaitCreated(t)
			f.delegatingRelay.push(t, 1, tc.d, 2)
			require.EqualError(t, f.awaitRun(t, 10*time.Second), tc.want)
			require.False(t, ran())
			f.requireUndecided(t)
			require.Equal(t, sessiondir.ReasonStartupFailed, f.record(t).Reason)
			require.Contains(t, f.logs.String(), testAuthority+" decided against the session before its command started")
		})
		// A host that doesn't wait for a first client, as a detached one
		// doesn't, has nothing else holding its command back once the
		// session is created; the decision comes while the operator is
		// still being asked to confirm it.
		t.Run(tc.d.String()+"/pushed while the session is being created", func(t *testing.T) {
			command, ran := markerCommand(t)
			var started atomic.Bool
			pushed := make(chan error, 1)
			f := newDelegatedHost(t, withCommand(command...), func(f *delegatedHost) {
				f.h.AwaitInitialClient = false
				f.h.CommandStartedCallback = func() { started.Store(true) }
				f.h.SessionCreatedCallback = func(context.Context, *api.GetSessionResponse) error {
					pushed <- f.delegatingRelay.pushed(1, tc.d, 2)
					return nil
				}
			})
			require.EqualError(t, f.awaitRun(t, 10*time.Second), tc.want)
			require.NoError(t, <-pushed)
			require.False(t, started.Load(), "the command was started")
			require.False(t, ran(), "the command ran")
			f.requireUndecided(t)
			require.Equal(t, sessiondir.ReasonStartupFailed, f.record(t).Reason)
			require.Contains(t, f.logs.String(), testAuthority+" decided against the session before its command started")
		})
	}
}

// Whether the command launched or a final decision came first is settled
// once, for both. A decision that comes once the command has been let start,
// though it hasn't quite started yet, is about a running session: a stop
// stops it and a withdrawal leaves it running locally, as they do after the
// start, and neither is told as coming before the launch.
func TestDecisionOnceTheLaunchIsLetIsAfterTheStart(t *testing.T) {
	for _, d := range []server.DelegatedDisposition{server.DelegatedDisposition_DELEGATED_STOPPED, server.DelegatedDisposition_DELEGATED_WITHDRAWN} {
		t.Run(d.String(), func(t *testing.T) {
			// Closed once the decision has been acted on, one way or the
			// other: as one about a running session, which tells the
			// callback, or by ending the run, which publishes that the
			// session is ending.
			acted := make(chan struct{})
			act := sync.OnceFunc(func() { close(acted) })
			started := make(chan struct{})
			start := sync.OnceFunc(func() { close(started) })
			atLaunch := make(chan error, 1)
			f := newDelegatedHost(t, func(f *delegatedHost) {
				f.h.AwaitInitialClient = false
				f.h.CommandStartedCallback = start
				f.h.DecisionCallback = func(d Decision) {
					f.decided <- d
					act()
				}
				f.h.afterEndingPublish = act
				// The decision comes with the command let start and held
				// back from starting until the decision has been acted on.
				f.h.atLaunch = func() {
					if err := f.delegatingRelay.pushed(1, d, 2); err != nil {
						atLaunch <- err
						return
					}
					select {
					case <-acted:
						atLaunch <- nil
					case <-time.After(10 * time.Second):
						atLaunch <- errors.New("the decision was never acted on")
					}
				}
			})
			select {
			case err := <-atLaunch:
				require.NoError(t, err)
			case err := <-f.done:
				t.Fatalf("Host.Run returned before its command was let start: %v", err)
			case <-time.After(15 * time.Second):
				t.Fatal("the command was never let start")
			}

			var got Decision
			// Run's error, when Run had already returned by the time the
			// decision was read: the callback is told before Run returns,
			// so a stop may be seen that way by a test that is slow to look.
			var runErr error
			returned := false
			select {
			case got = <-f.decided:
			case err := <-f.done:
				select {
				case got = <-f.decided:
					runErr, returned = err, true
				default:
					t.Fatalf("Host.Run returned without acting on the decision as one about a running session: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the host was never told what the authority decided")
			}
			if d == server.DelegatedDisposition_DELEGATED_STOPPED {
				require.Equal(t, DecisionStopped, got)
				if !returned {
					runErr = f.awaitRun(t, 15*time.Second)
				}
				require.ErrorIs(t, runErr, errSessionStopped)
				rec := f.record(t)
				require.Equal(t, sessiondir.ReasonStopped, rec.Reason)
				require.Equal(t, sessiondir.DecisionStopped, rec.Delegation.Decision)
				require.Contains(t, f.logs.String(), testAuthority+" stopped the session; terminating the command")
			} else {
				require.Equal(t, DecisionWithdrawn, got)
				if returned {
					t.Fatalf("Host.Run returned after a withdrawal: %v", runErr)
				}
				select {
				case <-started:
				case err := <-f.done:
					t.Fatalf("Host.Run returned after a withdrawal: %v", err)
				case <-time.After(10 * time.Second):
					t.Fatal("the command never started after the withdrawal")
				}
				require.Equal(t, sessiondir.DecisionWithdrawn, f.record(t).Delegation.Decision)
				f.stop(t)
				require.ErrorIs(t, f.awaitRun(t, 15*time.Second), errSessionStopped)
				require.Equal(t, sessiondir.ReasonStopped, f.record(t).Reason)
			}
			require.NotContains(t, f.logs.String(), "before its command started")
		})
	}
}

// The command's start and a final decision settle the launch once, between
// them, in whichever order they ask: a decision already in force when the
// command asks keeps it from starting, one that asks first keeps it from
// starting, and one that comes once it was let start is about a running
// session.
func TestTheLaunchIsSettledOnce(t *testing.T) {
	stop := func(t *testing.T, m *delegatedMode) {
		t.Helper()
		require.NoError(t, m.decisions.Apply(server.DelegatedDisposition_DELEGATED_STOPPED, 2))
	}
	t.Run("a decision in force before the command asks", func(t *testing.T) {
		m := &delegatedMode{decisions: &internal.DelegatedDecisions{}}
		stop(t, m)
		require.False(t, m.mayLaunch(), "the command was let start with a stop in force")
		require.False(t, m.launched(), "the stop was taken for one about a running session")
	})
	t.Run("the decision asks first", func(t *testing.T) {
		m := &delegatedMode{decisions: &internal.DelegatedDecisions{}}
		require.False(t, m.launched(), "a decision that asked first was taken for one about a running session")
		require.False(t, m.mayLaunch(), "the command was let start after a decision settled it")
	})
	t.Run("the command asks first", func(t *testing.T) {
		m := &delegatedMode{decisions: &internal.DelegatedDecisions{}}
		require.True(t, m.mayLaunch(), "the command was refused with no decision in force")
		stop(t, m)
		require.True(t, m.launched(), "a stop once the command was let start was taken for one before it")
	})
}

// A delegated session reports that it is ready, then the command's own exit.
// The relay answers a normal exit as withdrawn, which ends nothing more: the
// command has already exited, and the host is told of no withdrawal.
func TestReportsReadyAndTheCommandsExit(t *testing.T) {
	gate := filepath.Join(t.TempDir(), "gate")
	f := newDelegatedHost(t, withCommand("sh", "-c", "while [ ! -e "+gate+" ]; do sleep 0.05; done; exit 3"), func(f *delegatedHost) {
		f.delegatingRelay.authority.control = func(req *server.DelegatedControlRequest) (*server.DelegatedControlReply, error) {
			if req.GetExit() != nil {
				return delegatedReply(req, server.DelegatedDisposition_DELEGATED_WITHDRAWN, 2), nil
			}
			return delegatedReply(req, server.DelegatedDisposition_DELEGATED_CURRENT, 1), nil
		}
	})
	f.awaitCreated(t)
	f.awaitReady(t)
	f.delegatingRelay.authority.awaitControls(t, 1)
	require.NoError(t, os.WriteFile(gate, nil, 0o600))

	// What Run returns is whichever of its parts ends it first; the record
	// says how the command ended.
	_ = f.awaitRun(t, 15*time.Second)
	rec := f.record(t)
	require.Equal(t, sessiondir.ReasonExited, rec.Reason)
	require.NotNil(t, rec.ExitCode)
	require.Equal(t, 3, *rec.ExitCode)

	controls := f.delegatingRelay.authority.awaitControls(t, 2)
	require.Len(t, controls, 2)
	require.NotNil(t, controls[0].GetReady())
	require.Equal(t, uint64(1), controls[0].GetSequence())
	exit := controls[1].GetExit()
	require.NotNil(t, exit)
	require.Equal(t, uint64(2), controls[1].GetSequence())
	require.True(t, exit.GetStatusKnown())
	require.Equal(t, int32(3), exit.GetExitStatus())
	f.requireUndecided(t)
}

// A ready report the relay could not take is sent again, identically, until
// it is acknowledged.
func TestReadyIsRetriedUntilAcknowledged(t *testing.T) {
	var refusals atomic.Int32
	f := newDelegatedHost(t, func(f *delegatedHost) {
		f.delegatingRelay.authority.control = func(req *server.DelegatedControlRequest) (*server.DelegatedControlReply, error) {
			if req.GetReady() != nil && refusals.Add(1) == 1 {
				return nil, &server.DelegatedRefusedError{Code: server.DelegatedErrorCode_DELEGATED_UNAVAILABLE}
			}
			return delegatedReply(req, server.DelegatedDisposition_DELEGATED_CURRENT, 1), nil
		}
	})
	f.awaitCreated(t)
	f.awaitReady(t)
	controls := f.delegatingRelay.authority.awaitControls(t, 2)
	for _, c := range controls[:2] {
		require.NotNil(t, c.GetReady())
		require.Equal(t, uint64(1), c.GetGeneration())
		require.Equal(t, uint64(1), c.GetSequence(), "a retried report repeats its sequence")
	}
	require.Contains(t, f.logs.String(), testAuthority+" has not acknowledged that this session is ready; reporting it again until it does")
}

// stalledReporter is a registration whose relay answers a report when ack is
// closed, or never.
type stalledReporter struct {
	ack    chan struct{}
	closed atomic.Bool
}

func (r *stalledReporter) Report(ctx context.Context, _ internal.DelegatedEvent) error {
	select {
	case <-r.ack:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *stalledReporter) Close() { r.closed.Store(true) }

// The final report waits 5s for its acknowledgment and no longer: at 5s the
// registration is closed, and the exit stays unconfirmed. The budget is the
// protocol's, so it is spelled out here rather than read back from the
// constant under test.
func TestFinalReportDeadlineBoundary(t *testing.T) {
	const budget = 5 * time.Second
	exit := internal.DelegatedEvent{Exit: true, ExitStatus: 3, StatusKnown: true}
	t.Run("unanswered", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := &stalledReporter{ack: make(chan struct{})}
			done := make(chan error, 1)
			go func() { done <- reportFinal(r, exit) }()

			time.Sleep(budget - time.Nanosecond)
			synctest.Wait()
			require.False(t, r.closed.Load(), "closed before the budget ran out")
			select {
			case err := <-done:
				t.Fatalf("gave up on the acknowledgment before the budget ran out: %v", err)
			default:
			}

			time.Sleep(time.Nanosecond)
			synctest.Wait()
			require.True(t, r.closed.Load(), "still open at the budget")
			select {
			case err := <-done:
				require.ErrorIs(t, err, context.DeadlineExceeded)
			default:
				t.Fatal("still waiting at the budget")
			}
		})
	})
	t.Run("acknowledged at the last moment", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := &stalledReporter{ack: make(chan struct{})}
			done := make(chan error, 1)
			go func() { done <- reportFinal(r, exit) }()

			time.Sleep(budget - time.Nanosecond)
			close(r.ack)
			synctest.Wait()
			require.NoError(t, <-done)
			require.True(t, r.closed.Load(), "the registration is closed once the exit is confirmed")
		})
	})
}

// What a command's own outcome reports to the authority: its status when it
// exited, and an unknown one when it was killed.
func TestExitEvent(t *testing.T) {
	n := 15
	require.Equal(t, internal.DelegatedEvent{Exit: true, ExitStatus: 3, StatusKnown: true}, exitEvent(internal.CommandResult{Exited: true, Code: 3}))
	require.Equal(t, internal.DelegatedEvent{Exit: true}, exitEvent(internal.CommandResult{Signal: "TERM", SignalNumber: &n}))
	require.Equal(t, internal.DelegatedEvent{Exit: true}, exitEvent(internal.CommandResult{Exited: true, Code: 1 << 40}), "a status a report can't carry is unknown")
}

// The delegated reasons are a stable contract for integrations, as the
// others are.
func TestDelegatedTunnelReasonsAreTheDocumentedStrings(t *testing.T) {
	require.Equal(t, "authority_refused", sessiondir.TunnelReasonAuthorityRefused)
	require.Equal(t, "withdrawn", sessiondir.TunnelReasonWithdrawn)
	require.Equal(t, "trust_lapsed", sessiondir.TunnelReasonTrustLapsed)
}

func TestClassifyDelegatedFailures(t *testing.T) {
	refused := func(code server.DelegatedErrorCode) func(*testing.T) error {
		return fixedErr(fmt.Errorf("error creating session: %w", &server.DelegatedRefusedError{Code: code}))
	}
	runClassifyCases(t, []classifyCase{
		{
			name: "a relay key outside the pins",
			err: func(t *testing.T) error {
				relayKey, err := NewHostKey()
				require.NoError(t, err)
				relay := fakerelay.Start(t, relayKey, fakerelay.RandomID)
				pins, err := internal.ParseRelayPins([][]byte{freshSigners(t, 1)[0].PublicKey().Marshal()})
				require.NoError(t, err)
				var authority internal.RelayAuthority
				tunnel := classifyTunnel(t, &url.URL{Scheme: "ssh", Host: relay.Addr}, freshSigners(t, 1), authority.PinnedTo(pins, testAuthority))
				secret, err := registration.NewSecret()
				require.NoError(t, err)
				tunnel.SessionSecret, tunnel.Generation = secret, 1
				tunnel.Delegated = &server.DelegatedSession{Protocol: testProtocol, ExternalSessionId: testExternalID}
				tunnel.Decisions = &internal.DelegatedDecisions{}
				err = establishFails(t, tunnel)
				var notPinned *internal.RelayKeyNotPinnedError
				require.ErrorAs(t, err, &notPinned, "the chain must survive x/crypto's wrapping")
				return err
			},
			reason: sessiondir.TunnelReasonRelayKeyChanged, class: blocked,
		},
		{name: "the authority unavailable", err: refused(server.DelegatedErrorCode_DELEGATED_UNAVAILABLE), reason: sessiondir.TunnelReasonRelayError, class: transient},
		{name: "a newer registration", err: refused(server.DelegatedErrorCode_DELEGATED_STALE_GENERATION), reason: sessiondir.TunnelReasonRelayError, class: transient},
		{name: "an invalid registration", err: refused(server.DelegatedErrorCode_DELEGATED_INVALID_REQUEST), reason: sessiondir.TunnelReasonAuthorityRefused, class: blocked},
		{name: "an unsupported registration", err: refused(server.DelegatedErrorCode_DELEGATED_UNSUPPORTED), reason: sessiondir.TunnelReasonAuthorityRefused, class: blocked},
		{
			name:   "a relay outside the delegated protocol",
			err:    fixedErr(fmt.Errorf("error creating session: %w", internal.ErrDelegatedRelayUnsupported)),
			reason: sessiondir.TunnelReasonRelayUnsupported, class: blocked,
		},
	})
}

// placedHost is a delegated Host whose broker answers with place, against a
// fake relay, for a test about what happens before the relay is dialled.
type placedHost struct {
	h         *Host
	fake      *fakerelay.Relay
	relayKey  ssh.Signer
	stateRoot string
	logs      *lockedBuffer
	published atomic.Int32
}

func newPlacedHost(t *testing.T) *placedHost {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "up-pl-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	t.Setenv("XDG_RUNTIME_DIR", root)
	t.Setenv("XDG_STATE_HOME", root)
	relayKey, err := NewHostKey()
	require.NoError(t, err)
	identity, err := NewHostKey()
	require.NoError(t, err)
	p := &placedHost{
		fake:      fakerelay.Start(t, relayKey, fakerelay.RandomID),
		relayKey:  relayKey,
		stateRoot: utils.UptermStateDir(),
		logs:      &lockedBuffer{},
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("host log:\n%s", p.logs.String())
		}
	})
	p.h = &Host{
		Host:      "ssh://" + closedAddr(t),
		Name:      "placed",
		Command:   []string{"sh", "-c", "sleep 30"},
		Signers:   []ssh.Signer{identity},
		StopGrace: 50 * time.Millisecond,
		Logger:    slog.New(slog.NewTextHandler(p.logs, nil)),
	}
	return p
}

// placement is a valid placement of run at the fake relay, which counts its
// Published calls.
func (p *placedHost) placement(run Run) Placement {
	return Placement{
		RoutingID:    run.RoutingID,
		Relay:        p.fake.Addr,
		Trust:        InitialTrust{Keys: [][]byte{p.relayKey.PublicKey().Marshal()}},
		Protocol:     testProtocol,
		ExternalID:   testExternalID,
		GuestAddress: testGuestAddress,
		Association:  sessiondir.DelegationAssociation{Service: testService, Account: testAccount, Login: testLogin},
		Display: sessiondir.DelegationDisplay{
			Authority: testAuthority,
			Links:     []sessiondir.DelegationLink{{Label: "Dashboard", URL: "https://authority.test/s"}},
			Notes:     []string{"a note"},
		},
		Published: func() { p.published.Add(1) },
	}
}

// run runs the host, with its broker placing the run as mutate makes the
// valid placement, and returns Run's error.
func (p *placedHost) run(t *testing.T, mutate func(Run, *Placement)) error {
	t.Helper()
	p.h.Broker = brokerFunc(func(_ context.Context, run Run) (Placement, error) {
		pl := p.placement(run)
		mutate(run, &pl)
		return pl, nil
	})
	done := make(chan error, 1)
	go func() { done <- p.h.Run(context.Background()) }()
	select {
	case err := <-done:
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("Host.Run did not return")
		return nil
	}
}

// placementCheck breaks one of a placement's fields, as the checks take
// them, and is the reason the run ends with when it is the first broken.
type placementCheck struct {
	reason string
	breaks []func(Run, *Placement)
}

// placementChecks are the checks in the order they are made.
func placementChecks() []placementCheck {
	return []placementCheck{
		{"the routing ID is not this run's", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.RoutingID = "not-this-runs" },
			func(_ Run, p *Placement) { p.RoutingID = "" },
			func(r Run, p *Placement) { p.RoutingID = strings.ToUpper(r.RoutingID) },
		}},
		{"the protocol is not 1 to 64 printable ASCII bytes with no whitespace", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.Protocol = "" },
			func(_ Run, p *Placement) { p.Protocol = "test v1" },
			func(_ Run, p *Placement) { p.Protocol = strings.Repeat("p", 65) },
			func(_ Run, p *Placement) { p.Protocol = "tést" },
		}},
		{"the external session ID is not a canonical UUID", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.ExternalID = "" },
			func(_ Run, p *Placement) { p.ExternalID = "0123ABCD-4567-89EF-0123-456789ABCDEF" },
			func(_ Run, p *Placement) { p.ExternalID = "00000000-0000-0000-0000-000000000000" },
		}},
		{"the relay address is not a valid host:port", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.Relay = "" },
			func(_ Run, p *Placement) { p.Relay = "127.0.0.1" },
			func(_ Run, p *Placement) { p.Relay = "127.0.0.1:0" },
			func(_ Run, p *Placement) { p.Relay = "127.0.0.1:65536" },
			func(_ Run, p *Placement) { p.Relay = "127.0.0.1:022" },
			func(_ Run, p *Placement) { p.Relay = ":22" },
			func(_ Run, p *Placement) { p.Relay = "Relay.Example:22" },
			func(_ Run, p *Placement) { p.Relay = "relay..example:22" },
			func(_ Run, p *Placement) { p.Relay = "-relay.example:22" },
			func(_ Run, p *Placement) { p.Relay = "relay example:22" },
			func(_ Run, p *Placement) { p.Relay = "[fe80::1%en0]:22" },
			func(_ Run, p *Placement) { p.Relay = "ssh://relay.example:22" },
		}},
		{"the relay keys are not 1 to 16 distinct canonical plain SSH public keys", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.Trust.Keys = nil },
			func(_ Run, p *Placement) { p.Trust.Keys = [][]byte{p.Trust.Keys[0], p.Trust.Keys[0]} },
			func(_ Run, p *Placement) { p.Trust.Keys = [][]byte{[]byte("not a key")} },
		}},
		{"the guest address is not 1 to 255 letters, digits, '.', '_', '+' or '-', starting with a letter or digit", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.GuestAddress = "" },
			func(_ Run, p *Placement) { p.GuestAddress = "-work" },
			func(_ Run, p *Placement) { p.GuestAddress = ".work" },
			func(_ Run, p *Placement) { p.GuestAddress = "wo rk" },
			func(_ Run, p *Placement) { p.GuestAddress = "work@relay" },
			func(_ Run, p *Placement) { p.GuestAddress = "work;rm" },
			func(_ Run, p *Placement) { p.GuestAddress = "wörk" },
			func(_ Run, p *Placement) { p.GuestAddress = strings.Repeat("w", 256) },
		}},
		{"the service is not an https URL of at most 2048 bytes, with no userinfo or control characters", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.Association.Service = "http://authority.test" },
			func(_ Run, p *Placement) { p.Association.Service = "https:///s" },
			func(_ Run, p *Placement) { p.Association.Service = "https://:443/" },
			func(_ Run, p *Placement) {
				p.Association.Service = "https://authority.test/" + strings.Repeat("s", 2049-len("https://authority.test/"))
			},
			// Bytes, not runes: 1036 of them.
			func(_ Run, p *Placement) {
				p.Association.Service = "https://authority.test/" + strings.Repeat("é", (2049-len("https://authority.test/"))/2)
			},
			// A placement carries no credential, and a password is one.
			func(_ Run, p *Placement) { p.Association.Service = "https://user:secret@authority.test/" },
			func(_ Run, p *Placement) { p.Association.Service = "https://user@authority.test/" },
			func(_ Run, p *Placement) { p.Association.Service = "https://@authority.test/" },
			func(_ Run, p *Placement) { p.Association.Service = "https://authority.test/s\x1b" },
			// url.Parse takes U+009B in a host or a path: only the
			// control-character test refuses it.
			func(_ Run, p *Placement) { p.Association.Service = "https://author\u009bity.test" },
			func(_ Run, p *Placement) { p.Association.Service = "https://authority.test/s\u009b" },
			func(_ Run, p *Placement) { p.Association.Service = "https://authority.test/s\n" },
			func(_ Run, p *Placement) { p.Association.Service = "https://authority.test/s\xff" },
		}},
		{"the account is not 1 to 256 bytes of UTF-8 with no control characters", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.Association.Account = "" },
			func(_ Run, p *Placement) { p.Association.Account = strings.Repeat("a", 257) },
			func(_ Run, p *Placement) { p.Association.Account = strings.Repeat("é", 129) },
			func(_ Run, p *Placement) { p.Association.Account = "acc\xffount" },
			func(_ Run, p *Placement) { p.Association.Account = "acc\u009bount" },
			func(_ Run, p *Placement) { p.Association.Account = "acc\nount" },
		}},
		{"the login is not 1 to 256 bytes of UTF-8 with no control characters", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.Association.Login = "" },
			func(_ Run, p *Placement) { p.Association.Login = strings.Repeat("l", 257) },
			func(_ Run, p *Placement) { p.Association.Login = strings.Repeat("é", 129) },
			func(_ Run, p *Placement) { p.Association.Login = "log\xffin" },
			func(_ Run, p *Placement) { p.Association.Login = "log\u009bin" },
			func(_ Run, p *Placement) { p.Association.Login = "log\nin" },
		}},
		{"the superseded session ID is not a canonical UUID", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.Association.SupersededSessionID = "not-a-uuid" },
			func(_ Run, p *Placement) { p.Association.SupersededSessionID = "0123ABCD-4567-89EF-0123-456789ABCDEF" },
			func(_ Run, p *Placement) { p.Association.SupersededSessionID = "00000000-0000-0000-0000-000000000000" },
		}},
		{"the authority's name is longer than 64 bytes", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.Display.Authority = strings.Repeat("a", 65) },
			// Sanitized first: one control byte becomes three.
			func(_ Run, p *Placement) { p.Display.Authority = strings.Repeat("a", 62) + "\x1b" },
		}},
		{"there are more than 8 links", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.Display.Links = links(9) },
		}},
		{"a link's label is longer than 64 bytes", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.Display.Links[0].Label = strings.Repeat("l", 65) },
		}},
		{"a link's URL is not an https URL of at most 2048 bytes", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.Display.Links[0].URL = "http://authority.test/s" },
			func(_ Run, p *Placement) { p.Display.Links[0].URL = "https:///s" },
			func(_ Run, p *Placement) { p.Display.Links[0].URL = "authority.test/s" },
			func(_ Run, p *Placement) {
				p.Display.Links[0].URL = "https://authority.test/" + strings.Repeat("s", 2049-len("https://authority.test/"))
			},
		}},
		{"there are more than 16 notes", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.Display.Notes = notes(17, 4) },
		}},
		{"a note is longer than 256 bytes", []func(Run, *Placement){
			func(_ Run, p *Placement) { p.Display.Notes[0] = strings.Repeat("n", 257) },
		}},
	}
}

// A placement that isn't this run's, or isn't well formed, ends the run with
// the reason for the first check it fails, in the order the checks are made,
// before anything is dialled; the broker is told it is through all the same,
// once. Each case breaks one check's field and every field checked after it,
// so a check made out of order would give another reason.
func TestPlacementChecksEndTheRunInOrder(t *testing.T) {
	checks := placementChecks()
	for i, check := range checks {
		for j, brk := range check.breaks {
			t.Run(fmt.Sprintf("%d/%s/%d", i, check.reason, j), func(t *testing.T) {
				p := newPlacedHost(t)
				err := p.run(t, func(run Run, pl *Placement) {
					for _, later := range checks[i+1:] {
						later.breaks[0](run, pl)
					}
					brk(run, pl)
				})
				require.EqualError(t, err, "the placement for this run is invalid: "+check.reason)
				require.Zero(t, p.fake.Connections(), "a refused placement was dialled")
				require.Equal(t, int32(1), p.published.Load(), "the broker was not told exactly once")
				rec, err := sessiondir.ReadRecord(p.stateRoot, p.h.Name)
				require.NoError(t, err)
				require.Nil(t, rec.Delegation, "a refused placement was recorded")
			})
		}
	}

	// And the edges that are allowed, each of which goes on to dial the
	// fake relay, unless it moved the relay elsewhere.
	for name, tc := range map[string]struct {
		mutate func(Run, *Placement)
		dials  bool
	}{
		"no display":           {func(_ Run, p *Placement) { p.Display = sessiondir.DelegationDisplay{} }, true},
		"64-byte protocol":     {func(_ Run, p *Placement) { p.Protocol = strings.Repeat("p", 64) }, true},
		"16 relay keys":        {func(_ Run, p *Placement) { p.Trust.Keys = append(p.Trust.Keys, freshKeys(t, 15)...) }, true},
		"255-byte address":     {func(_ Run, p *Placement) { p.GuestAddress = strings.Repeat("w", 255) }, true},
		"a dotted address":     {func(_ Run, p *Placement) { p.GuestAddress = "work_1.dev-a" }, true},
		"a 64-byte name":       {func(_ Run, p *Placement) { p.Display.Authority = strings.Repeat("a", 64) }, true},
		"8 links":              {func(_ Run, p *Placement) { p.Display.Links = links(8) }, true},
		"a 64-byte link label": {func(_ Run, p *Placement) { p.Display.Links[0].Label = strings.Repeat("l", 64) }, true},
		"a 2048-byte URL": {func(_ Run, p *Placement) {
			p.Display.Links[0].URL = "https://a.test/" + strings.Repeat("s", 2048-len("https://a.test/"))
		}, true},
		"16 notes of 256 bytes": {func(_ Run, p *Placement) { p.Display.Notes = notes(16, 256) }, true},
		"an IPv6 relay":         {func(_ Run, p *Placement) { p.Relay = "[::1]:" + portOf(t, p.Relay) }, false},
		"a named relay":         {func(_ Run, p *Placement) { p.Relay = "localhost:" + portOf(t, p.Relay) }, false},
		"a 2048-byte service": {func(_ Run, p *Placement) {
			p.Association.Service = "https://a.test/" + strings.Repeat("s", 2048-len("https://a.test/"))
		}, true},
		"a 256-byte account":           {func(_ Run, p *Placement) { p.Association.Account = strings.Repeat("a", 256) }, true},
		"a 256-byte login":             {func(_ Run, p *Placement) { p.Association.Login = strings.Repeat("l", 256) }, true},
		"a 256-byte non-ASCII account": {func(_ Run, p *Placement) { p.Association.Account = strings.Repeat("é", 128) }, true},
		"a 256-byte non-ASCII login":   {func(_ Run, p *Placement) { p.Association.Login = strings.Repeat("é", 128) }, true},
		"a non-ASCII service":          {func(_ Run, p *Placement) { p.Association.Service = "https://authority.test/é" }, true},
		"a non-ASCII account":          {func(_ Run, p *Placement) { p.Association.Account = "compte-é" }, true},
		"a non-ASCII login":            {func(_ Run, p *Placement) { p.Association.Login = "用户" }, true},
		"a superseded session":         {func(_ Run, p *Placement) { p.Association.SupersededSessionID = "77777777-7777-4777-8777-777777777777" }, true},
	} {
		t.Run("allowed/"+name, func(t *testing.T) {
			p := newPlacedHost(t)
			var given sessiondir.DelegationAssociation
			err := p.run(t, func(run Run, pl *Placement) {
				tc.mutate(run, pl)
				given = pl.Association
			})
			require.Error(t, err, "the fake relay acknowledges no delegated registration")
			require.NotContains(t, err.Error(), "the placement for this run is invalid")
			if tc.dials {
				require.ErrorIs(t, err, internal.ErrDelegatedRelayUnsupported)
				require.NotZero(t, p.fake.Connections(), "an allowed placement was never dialled")
			}
			require.Equal(t, int32(1), p.published.Load())
			rec, err := sessiondir.ReadRecord(p.stateRoot, p.h.Name)
			require.NoError(t, err)
			require.NotNil(t, rec.Delegation, "an allowed placement was not recorded")
			require.Equal(t, given, rec.Delegation.DelegationAssociation, "the association was not recorded as given")
		})
	}
}

func freshKeys(t *testing.T, n int) [][]byte {
	t.Helper()
	keys := make([][]byte, n)
	for i, s := range freshSigners(t, n) {
		keys[i] = s.PublicKey().Marshal()
	}
	return keys
}

func links(n int) []sessiondir.DelegationLink {
	l := make([]sessiondir.DelegationLink, n)
	for i := range l {
		l[i] = sessiondir.DelegationLink{Label: "link", URL: "https://authority.test/l"}
	}
	return l
}

func notes(n, size int) []string {
	l := make([]string, n)
	for i := range l {
		l[i] = strings.Repeat("n", size)
	}
	return l
}

func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	return port
}

// The record holds the delegation, as the placement gave it with its display
// sanitized, before the relay sees the first byte of the run's connection.
// A record that can't be written ends the run before anything is dialled,
// and the broker is told all the same.
func TestRecordHoldsTheDelegationBeforeAnyDial(t *testing.T) {
	t.Run("recorded", func(t *testing.T) {
		p := newPlacedHost(t)
		// Read as the relay accepts the connection, before it has read a
		// byte of it.
		atAccept := make(chan *sessiondir.Record, 1)
		p.fake.OnAccept(func() {
			rec, err := sessiondir.ReadRecord(p.stateRoot, p.h.Name)
			if err != nil {
				rec = nil
			}
			select {
			case atAccept <- rec:
			default:
			}
		})
		var routingID string
		err := p.run(t, func(run Run, pl *Placement) {
			routingID = run.RoutingID
			pl.Association.SupersededSessionID = "77777777-7777-4777-8777-777777777777"
			pl.Display = sessiondir.DelegationDisplay{
				Authority: "Ex\x1b[31mample\r\nupterm: x",
				Links:     []sessiondir.DelegationLink{{Label: "Dash\x07board\nupterm: x", URL: "https://authority.test/s"}},
				Notes:     []string{"line one\nline\x9btwo"},
			}
		})
		require.ErrorIs(t, err, internal.ErrDelegatedRelayUnsupported, "the fake relay acknowledges no delegated registration")

		var rec *sessiondir.Record
		select {
		case rec = <-atAccept:
		default:
			t.Fatal("the relay was never dialled")
		}
		require.NotNil(t, rec, "no record when the relay was dialled")
		require.Equal(t, &sessiondir.Delegation{
			DelegationAssociation: sessiondir.DelegationAssociation{Service: testService, Account: testAccount, Login: testLogin, SupersededSessionID: "77777777-7777-4777-8777-777777777777"},
			DelegationDisplay: sessiondir.DelegationDisplay{
				Authority: "Ex�[31mample��upterm: x",
				Links:     []sessiondir.DelegationLink{{Label: "Dash�board�upterm: x", URL: "https://authority.test/s"}},
				Notes:     []string{"line one�line�two"},
			},
			ExternalSessionID: testExternalID,
			RoutingID:         routingID,
			Relay:             p.fake.Addr,
			GuestAddress:      testGuestAddress,
		}, rec.Delegation, "the delegation, field for field, was not in the record before the dial")
		require.Equal(t, int32(1), p.published.Load())
	})

	t.Run("unwritable", func(t *testing.T) {
		p := newPlacedHost(t)
		var dir string
		var chmodErr error
		err := p.run(t, func(_ Run, pl *Placement) {
			// The broker runs once the name is claimed: the record is there
			// to make read-only.
			dir = filepath.Dir(p.h.SessionDir.RecordPath())
			chmodErr = os.Chmod(dir, 0o500)
		})
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		require.NoError(t, chmodErr)
		require.True(t, strings.HasPrefix(err.Error(), "failed to record the session's delegation: "), err.Error())
		require.Zero(t, p.fake.Connections(), "a delegation that wasn't recorded was dialled")
		require.Equal(t, int32(1), p.published.Load())
	})
}

// staticTrust is a TrustSource that refreshes to the keys it was given.
type staticTrust struct{ keys [][]byte }

func (s staticTrust) Refresh(context.Context, []byte) ([][]byte, uint64, []byte, error) {
	return s.keys, 1, nil, nil
}
func (staticTrust) Interval() time.Duration { return time.Minute }
func (staticTrust) Lifetime() time.Duration { return time.Hour }

// A placement that needs its relay keys refreshed ends the run before
// anything is dialled, rather than having its refresh ignored, and the broker
// is told all the same.
func TestRefreshIsRefusedUntilItIsBuilt(t *testing.T) {
	p := newPlacedHost(t)
	err := p.run(t, func(_ Run, pl *Placement) { pl.Refresh = staticTrust{keys: pl.Trust.Keys} })
	require.EqualError(t, err, "this upterm can't refresh relay keys, and the placement for this run needs that")
	require.Zero(t, p.fake.Connections(), "a placement that needs a refresh was dialled")
	require.Equal(t, int32(1), p.published.Load())
}

// A broker's error ends the run before anything is dialled, as it is.
func TestBrokerErrorEndsTheRun(t *testing.T) {
	p := newPlacedHost(t)
	refused := &NameTakenError{Text: "taken here"}
	p.h.Broker = brokerFunc(func(context.Context, Run) (Placement, error) { return Placement{}, refused })
	err := p.h.Run(context.Background())
	require.Same(t, refused, err)
	require.ErrorIs(t, err, ErrNameTaken)
	require.Equal(t, "taken here", err.Error())
	require.Zero(t, p.fake.Connections())
	rec, rerr := sessiondir.ReadRecord(p.stateRoot, p.h.Name)
	require.NoError(t, rerr)
	require.Equal(t, sessiondir.ReasonStartupFailed, rec.Reason)
	require.Nil(t, rec.Delegation)
}

// A delegated run's authority decides who joins it, so a run handed
// authorized keys as well is refused before anything is done for it: no name
// is claimed, nothing is placed or recorded, and nothing is dialled.
func TestDelegatedRunRefusesAuthorizedKeys(t *testing.T) {
	p := newPlacedHost(t)
	guest, err := NewHostKey()
	require.NoError(t, err)
	p.h.AuthorizedKeys = []*AuthorizedKey{{PublicKeys: []ssh.PublicKey{guest.PublicKey()}, Comment: "a guest"}}
	var places atomic.Int32
	err = p.run(t, func(Run, *Placement) { places.Add(1) })
	require.EqualError(t, err, "a delegated run takes no authorized keys: its authority decides who joins")
	require.Zero(t, places.Load(), "the run was placed")
	require.Zero(t, p.published.Load(), "the broker was told the run was published")
	require.Zero(t, p.fake.Connections(), "the run dialled the relay")
	_, err = sessiondir.ReadRecord(p.stateRoot, p.h.Name)
	require.ErrorIs(t, err, fs.ErrNotExist, "the run claimed its name and wrote a record")
}
