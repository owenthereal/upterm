package ftests

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/testhelpers/testauthority"
	"github.com/owenthereal/upterm/internal/testhelpers/testbroker"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	delegatedService = "https://authority.test"
	delegatedAccount = "11111111-1111-4111-8111-111111111111"
	delegatedLogin   = "66666666-6666-4666-8666-666666666666"
)

// runtimeLifecycle is a Lifecycle that hands over the relay's Runtime once it
// starts.
type runtimeLifecycle struct{ rt chan server.Runtime }

func (l runtimeLifecycle) Start(_ context.Context, rt server.Runtime) error {
	l.rt <- rt
	return nil
}

func (runtimeLifecycle) Stop() {}

// withLifecycle adds lifecycle to the extensions an earlier option composed.
func withLifecycle(lifecycle server.Lifecycle) func(*Server) {
	return func(s *Server) {
		base := s.beforeServe
		s.beforeServe = func(s *Server) {
			if base != nil {
				base(s)
			}
			s.Server.Extensions.Lifecycle = lifecycle
		}
	}
}

// delegatedRun is one delegated host run: the real Host, placed by the test
// broker on a real relay whose test authority decides it. The authority
// answers a ready report current and an exit withdrawn, as an authority
// answers a normal exit, and tells reported each time it answers one.
type delegatedRun struct {
	host      *host.Host
	name      string
	stateRoot string
	relay     *Server
	runtime   server.Runtime
	authority *testauthority.Authority
	broker    *testbroker.Broker
	reported  chan struct{}
	ready     chan string
	decided   chan host.Decision
	done      chan error
}

func newDelegatedRun(t *testing.T, command []string) *delegatedRun {
	t.Helper()
	dir := shortXDGDir(t)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("XDG_STATE_HOME", dir)

	authority := testauthority.New()
	reported := make(chan struct{}, 1)
	authority.Reply(func(r server.Report) (*server.DelegatedControlReply, error) {
		defer func() {
			select {
			case reported <- struct{}{}:
			default:
			}
		}()
		d, revision := server.DelegatedDisposition_DELEGATED_CURRENT, uint64(1)
		if r.Request.GetExit() != nil {
			d, revision = server.DelegatedDisposition_DELEGATED_WITHDRAWN, 3
		}
		return &server.DelegatedControlReply{ExternalSessionId: r.Request.ExternalSessionId, Generation: r.Request.Generation,
			AcknowledgedSequence: r.Request.Sequence, Disposition: d, DecisionRevision: revision}, nil
	})
	lifecycle := runtimeLifecycle{rt: make(chan server.Runtime, 1)}
	relay := newRedialRelay(t, routing.ModeEmbedded, withAuthority(authority, true), withLifecycle(lifecycle))
	var runtime server.Runtime
	select {
	case runtime = <-lifecycle.rt:
	case <-time.After(serverStartupTimeout):
		t.Fatal("the relay never started its lifecycle")
	}
	relayKey, err := utils.CreateSigners([][]byte{[]byte(ServerPrivateKeyContent)})
	require.NoError(t, err)

	identity, err := host.NewHostKey()
	require.NoError(t, err)
	r := &delegatedRun{
		name: uniqueSessionName(t), stateRoot: utils.UptermStateDir(), relay: relay, runtime: runtime, authority: authority,
		broker: testbroker.New(host.Placement{
			Relay:        relay.SSHAddr(),
			Trust:        host.InitialTrust{Keys: [][]byte{relayKey[0].PublicKey().Marshal()}},
			Protocol:     delegatedProtocol,
			ExternalID:   delegatedSessionID,
			GuestAddress: "work",
			Association:  sessiondir.DelegationAssociation{Service: delegatedService, Account: delegatedAccount, Login: delegatedLogin},
			Display:      sessiondir.DelegationDisplay{Authority: "Example"},
		}),
		reported: reported,
		ready:    make(chan string, 1), decided: make(chan host.Decision, 2), done: make(chan error, 1),
	}
	r.host = &host.Host{
		Name:              r.name,
		Command:           command,
		KeepAliveDuration: keepAliveDuration,
		Signers:           []ssh.Signer{identity},
		Logger:            testLogger,
		StopGrace:         100 * time.Millisecond,
		Broker:            r.broker,
		DecisionCallback:  func(d host.Decision) { r.decided <- d },
		SessionReadyCallback: func(status string) {
			r.ready <- status
		},
	}
	return r
}

func (r *delegatedRun) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		r.done <- r.host.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(outcomeTimeout):
			t.Error("Host.Run did not return after its context was cancelled")
		}
	})
}

func (r *delegatedRun) awaitReady(t *testing.T) {
	t.Helper()
	select {
	case status := <-r.ready:
		require.Equal(t, sessiondir.StatusReady, status)
	case err := <-r.done:
		t.Fatalf("Host.Run returned before the session was ready: %v", err)
	case <-time.After(outcomeTimeout):
		t.Fatal("the delegated session never became ready")
	}
}

func (r *delegatedRun) awaitRun(t *testing.T) error {
	t.Helper()
	select {
	case err := <-r.done:
		return err
	case <-time.After(outcomeTimeout):
		t.Fatal("Host.Run did not return")
		return nil
	}
}

// awaitDecided is what DecisionCallback was told.
func (r *delegatedRun) awaitDecided(t *testing.T) host.Decision {
	t.Helper()
	select {
	case d := <-r.decided:
		return d
	case <-time.After(outcomeTimeout):
		t.Fatal("the host was never told what the authority decided")
		return 0
	}
}

func (r *delegatedRun) record(t *testing.T) *sessiondir.Record {
	t.Helper()
	rec, err := sessiondir.ReadRecord(r.stateRoot, r.name)
	require.NoError(t, err)
	return rec
}

// controls is every report the authority was asked to answer, in order.
func (r *delegatedRun) controls() []*server.DelegatedControlRequest {
	var controls []*server.DelegatedControlRequest
	for _, c := range r.authority.Calls() {
		if c.Method == "Control" {
			controls = append(controls, c.Request)
		}
	}
	return controls
}

// awaitControls waits for the authority to have answered n reports, reading
// them again each time it answers one.
func (r *delegatedRun) awaitControls(t *testing.T, n int) []*server.DelegatedControlRequest {
	t.Helper()
	deadline := time.After(outcomeTimeout)
	for {
		if controls := r.controls(); len(controls) >= n {
			return controls
		}
		select {
		case <-r.reported:
		case <-deadline:
			t.Fatalf("the authority answered %d reports, not %d", len(r.controls()), n)
		}
	}
}

func (r *delegatedRun) push(t *testing.T, d server.DelegatedDisposition, revision uint64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ack, err := r.runtime.PushDecision(ctx, &server.DelegatedDecision{ExternalSessionId: delegatedSessionID, Generation: 1, Disposition: d, DecisionRevision: revision})
	require.NoError(t, err)
	require.Equal(t, revision, ack.DecisionRevision)
}

// requireStarted checks what the run was placed and registered as: one
// placement, for the run's own key and routing ID, and one registration of
// that external session, proving that key, at the relay the placement named,
// recorded before it was dialled.
func (r *delegatedRun) requireStarted(t *testing.T) {
	t.Helper()
	runs := r.broker.Runs()
	require.Len(t, runs, 1)
	var registrations []server.DelegatedRegistration
	for _, c := range r.authority.Calls() {
		if c.Method == "Register" {
			registrations = append(registrations, c.Registration)
		}
	}
	require.Len(t, registrations, 1)
	reg := registrations[0]
	require.Equal(t, delegatedSessionID, reg.Session.GetExternalSessionId())
	require.Equal(t, delegatedProtocol, reg.Session.GetProtocol())
	require.Equal(t, runs[0].RunKey.Marshal(), reg.RunPublicKey.Marshal())
	require.Equal(t, runs[0].RoutingID, reg.RoutingID)
	require.Equal(t, r.name, runs[0].Name)
	require.Equal(t, []string{"shell", "exec", "sftp", "direct-tcpip"}, runs[0].Capabilities)
	rec := r.record(t)
	require.Equal(t, &sessiondir.Delegation{
		DelegationAssociation: sessiondir.DelegationAssociation{Service: delegatedService, Account: delegatedAccount, Login: delegatedLogin},
		DelegationDisplay:     sessiondir.DelegationDisplay{Authority: "Example", Links: []sessiondir.DelegationLink{}, Notes: []string{}},
		ExternalSessionID:     delegatedSessionID,
		RoutingID:             runs[0].RoutingID,
		Relay:                 r.relay.SSHAddr(),
		GuestAddress:          "work",
	}, rec.Delegation)
}

// untilGate is a command, in this platform's shell, that runs until it is
// stopped, or, given a gate, until the gate exists and then exits 3.
func untilGate(gate string) []string {
	if runtime.GOOS == "windows" {
		script := "while ($true) { Start-Sleep -Milliseconds 50 }"
		if gate != "" {
			script = "while (-not (Test-Path -LiteralPath '" + gate + "')) { Start-Sleep -Milliseconds 50 }; exit 3"
		}
		return append(getTestShell(), "-Command", script)
	}
	if gate != "" {
		return []string{"sh", "-c", "while [ ! -e " + gate + " ]; do sleep 0.05; done; exit 3"}
	}
	return []string{"sh", "-c", "while :; do sleep 0.05; done"}
}

// A delegated host's whole life against a relay whose authority decides it:
// a placement by its broker, a connection pinned to the keys the placement
// listed, a current registration, ready once the command runs, and the
// command's own exit reported when it ends. Stopped, the command is
// terminated and its exit reported; withdrawn, the command goes on running
// locally, its admin socket answers, and no exit is reported.
func TestDelegatedHostLifecycle(t *testing.T) {
	t.Run("exit", func(t *testing.T) {
		gate := filepath.Join(shortXDGDir(t), "gate")
		r := newDelegatedRun(t, untilGate(gate))
		r.start(t)
		r.awaitReady(t)
		r.requireStarted(t)
		ready := r.awaitControls(t, 1)[0]
		require.NotNil(t, ready.GetReady())
		require.Equal(t, uint64(1), ready.GetSequence())

		require.NoError(t, os.WriteFile(gate, nil, 0o600))
		// The report and the record carry the command's status; Run reports
		// the host's.
		t.Logf("host completed: %v", r.awaitRun(t))
		controls := r.awaitControls(t, 2)
		require.Len(t, controls, 2)
		exit := controls[1].GetExit()
		require.NotNil(t, exit, "the command's exit is reported")
		require.Equal(t, uint64(2), controls[1].GetSequence())
		require.True(t, exit.GetStatusKnown())
		require.Equal(t, int32(3), exit.GetExitStatus())
		rec := r.record(t)
		require.Equal(t, sessiondir.ReasonExited, rec.Reason)
		require.Equal(t, 3, *rec.ExitCode)
		require.Empty(t, rec.Delegation.Decision, "an exit answered as withdrawn is not the authority's withdrawal")
		select {
		case d := <-r.decided:
			t.Fatalf("an exit answered as withdrawn was taken for a withdrawal (%d)", d)
		default:
		}
	})

	t.Run("stopped", func(t *testing.T) {
		r := newDelegatedRun(t, untilGate(""))
		r.start(t)
		r.awaitReady(t)
		r.requireStarted(t)
		r.awaitControls(t, 1)

		r.push(t, server.DelegatedDisposition_DELEGATED_STOPPED, 2)
		require.Equal(t, host.DecisionStopped, r.awaitDecided(t))
		require.Error(t, r.awaitRun(t))
		rec := r.record(t)
		require.Equal(t, sessiondir.ReasonStopped, rec.Reason)
		require.Equal(t, sessiondir.DecisionStopped, rec.Delegation.Decision)
		controls := r.awaitControls(t, 2)
		require.NotNil(t, controls[1].GetExit(), "a stopped command's exit is reported")
		require.Equal(t, uint64(2), controls[1].GetSequence())
	})

	t.Run("withdrawn", func(t *testing.T) {
		r := newDelegatedRun(t, untilGate(""))
		r.start(t)
		r.awaitReady(t)
		r.requireStarted(t)
		r.awaitControls(t, 1)

		r.push(t, server.DelegatedDisposition_DELEGATED_WITHDRAWN, 2)
		require.Equal(t, host.DecisionWithdrawn, r.awaitDecided(t))
		var rec *sessiondir.Record
		require.Eventually(t, func() bool {
			rec = r.record(t)
			return rec.Status == sessiondir.StatusDisconnected
		}, outcomeTimeout, 10*time.Millisecond)
		require.Equal(t, sessiondir.TunnelReasonWithdrawn, rec.TunnelReason)
		require.Equal(t, sessiondir.DecisionWithdrawn, rec.Delegation.Decision)

		// Still running: the admin socket answers for it, and it stops as
		// any local session does.
		conn, err := host.AdminConn(rec.AdminSocket)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		admin := api.NewAdminServiceClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sess, err := admin.GetSession(ctx, &api.GetSessionRequest{})
		require.NoError(t, err)
		require.Equal(t, sessiondir.StatusDisconnected, sess.GetStatus())
		require.Equal(t, "work", sess.GetSshUser())
		select {
		case err := <-r.done:
			t.Fatalf("the withdrawn session ended: %v", err)
		default:
		}
		_, err = admin.StopSession(ctx, &api.StopSessionRequest{LaunchId: rec.LaunchID})
		require.NoError(t, err)
		require.Error(t, r.awaitRun(t))
		require.Equal(t, sessiondir.ReasonStopped, r.record(t).Reason)
		require.Len(t, r.controls(), 1, "no exit is reported after a withdrawal")
	})
}
