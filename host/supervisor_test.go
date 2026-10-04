package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/internal/version"
	"github.com/owenthereal/upterm/server"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// lateWake is how late a woken goroutine may run on a loaded CI runner under
// -race (server/lease_test.go). A close is asserted never to come before its
// deadline, and at most this long after it.
const lateWake = 150 * time.Millisecond

// supervisorTiming is the reconnect timing, test-sized: fast waits of tens of
// milliseconds, and a slow one ten times the longest of them.
var supervisorTiming = ReconnectTiming{
	AttemptDeadline: 200 * time.Millisecond,
	FastBase:        10 * time.Millisecond,
	FastCap:         40 * time.Millisecond,
	SlowWait:        300 * time.Millisecond,
	SlowJitter:      30 * time.Millisecond,
	ResetAfter:      300 * time.Millisecond,
}

const supervisorSessionID = "session-1"

// idleListener is a forwarded listener no guest dials: Accept waits for Close.
type idleListener struct {
	done chan struct{}
	once sync.Once
}

func (l *idleListener) Accept() (net.Conn, error) {
	<-l.done
	return nil, net.ErrClosed
}

func (l *idleListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *idleListener) Addr() net.Addr { return &net.UnixAddr{Name: "idle", Net: "unix"} }

// fakeTunnel is a tunnel whose loss the test decides.
type fakeTunnel struct {
	ln     *idleListener
	lost   chan struct{}
	err    error
	closed atomic.Bool
	redial bool

	endOnce sync.Once
	// watched is closed by the first Wait: the supervisor has installed the
	// tunnel, published it as up, and is watching it.
	watched   chan struct{}
	watchOnce sync.Once
}

func newFakeTunnel(t *testing.T, redial bool) *fakeTunnel {
	t.Helper()
	return &fakeTunnel{
		ln:      &idleListener{done: make(chan struct{})},
		lost:    make(chan struct{}),
		redial:  redial,
		watched: make(chan struct{}),
	}
}

// drop ends the tunnel's connection: Wait returns err, and the forwarded
// listener fails, as it does when a real tunnel's connection ends.
func (f *fakeTunnel) drop(err error) { f.end(err) }

func (f *fakeTunnel) end(err error) {
	f.endOnce.Do(func() {
		f.err = err
		close(f.lost)
	})
	_ = f.ln.Close()
}

func (f *fakeTunnel) Listener() net.Listener { return f.ln }

func (f *fakeTunnel) Wait() error {
	f.watchOnce.Do(func() { close(f.watched) })
	<-f.lost
	return f.err
}

func (f *fakeTunnel) Close() {
	f.closed.Store(true)
	f.end(net.ErrClosed)
}

func (f *fakeTunnel) ServerVersion() []byte  { return []byte(version.ServerSSHVersion()) }
func (f *fakeTunnel) SessionKeyRedial() bool { return f.redial }

// awaitWatched waits until the supervisor is watching tun, which it does only
// once tun is the current tunnel and has been published as up.
func awaitWatched(t *testing.T, tun *fakeTunnel) {
	t.Helper()
	select {
	case <-tun.watched:
	case <-time.After(5 * time.Second):
		t.Fatal("the supervisor never installed the tunnel")
	}
}

// script answers attempts in order and records what each was given, under mu.
type script struct {
	t          *testing.T
	sessionID  string
	sessionKey ssh.Signer

	mu    sync.Mutex
	steps []func(ctx context.Context) (tunnel, error)
	every func(ctx context.Context) (tunnel, error)
	// response is the registration a successful attempt reports. Nil reports
	// the session's own ID, at a node and user named for the generation.
	response func(generation uint64) *server.CreateSessionResponse
	gens     []uint64
	keyFirst []bool
	// When each attempt began, and when it returned.
	began, ended []time.Time
}

// repeat answers every attempt with step.
func (s *script) repeat(step func(ctx context.Context) (tunnel, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.every = step
}

func (s *script) generations() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint64(nil), s.gens...)
}

func (s *script) attempt(ctx context.Context, generation uint64, signers []ssh.Signer) (tunnel, *server.CreateSessionResponse, error) {
	s.mu.Lock()
	n := len(s.gens)
	s.gens = append(s.gens, generation)
	s.keyFirst = append(s.keyFirst, len(signers) > 0 && signers[0] == s.sessionKey)
	s.began = append(s.began, time.Now())
	step := s.every
	if step == nil && n < len(s.steps) {
		step = s.steps[n]
	}
	response := s.response
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.ended = append(s.ended, time.Now())
		s.mu.Unlock()
	}()

	if step == nil {
		s.t.Errorf("attempt %d, generation %d, has no answer scripted", n+1, generation)
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	tun, err := step(ctx)
	if err != nil {
		return nil, nil, err
	}
	if response != nil {
		return tun, response(generation), nil
	}
	return tun, &server.CreateSessionResponse{
		SessionID: s.sessionID,
		NodeAddr:  fmt.Sprintf("node-%d:22", generation),
		SshUser:   fmt.Sprintf("user-%d", generation),
	}, nil
}

// fakeAgent is one attempt's agent connection, closed by the closeAgent the
// supervisor is handed with the attempt's identities.
type fakeAgent struct {
	closed chan struct{}
	once   sync.Once
	closes atomic.Int32
}

func (a *fakeAgent) close() {
	a.closes.Add(1)
	a.once.Do(func() { close(a.closed) })
}

// jitterLog is a jitter that waits the whole bound, and records each bound it
// was given: the schedule's position, readable after the fact.
type jitterLog struct {
	mu     sync.Mutex
	bounds []time.Duration
}

func (j *jitterLog) jitter(max time.Duration) time.Duration {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.bounds = append(j.bounds, max)
	return atMost(max)
}

func (j *jitterLog) got() []time.Duration {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]time.Duration(nil), j.bounds...)
}

type supervisorFixture struct {
	sup      *supervisor
	first    *fakeTunnel
	script   *script
	listener *internal.TunnelListener
	route    *internal.SessionRoute
	dir      *sessiondir.Dir
	jitters  *jitterLog
	cancel   context.CancelFunc
	done     chan struct{}

	agentsMu sync.Mutex
	agents   []*fakeAgent
}

func newSupervisorSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer
}

// newSupervisorFixture runs a supervisor over a first tunnel the test drops,
// with scripted attempts, test-sized timing, a running session's state and a
// real record. Its status is "starting" until the supervisor first publishes.
func newSupervisorFixture(t *testing.T, supported bool) *supervisorFixture {
	t.Helper()
	sessionKey, recorded := newSupervisorSigner(t), newSupervisorSigner(t)
	f := &supervisorFixture{
		first:   newFakeTunnel(t, true),
		script:  &script{t: t, sessionID: supervisorSessionID, sessionKey: sessionKey},
		route:   &internal.SessionRoute{},
		dir:     claimTestDir(t),
		jitters: &jitterLog{},
		done:    make(chan struct{}),
	}
	f.listener = internal.NewTunnelListener(f.first.ln)
	f.route.Set("node-1:22", "user-1")
	state := &sessionState{}
	state.setPhase(phaseRunning)
	state.setReconnect(supported)
	f.sup = &supervisor{
		timing:  supervisorTiming,
		attempt: f.script.attempt,
		identities: func(ctx context.Context, sessionKeyFirst bool) ([]ssh.Signer, func()) {
			signers := []ssh.Signer{recorded}
			if sessionKeyFirst {
				signers = append([]ssh.Signer{sessionKey}, signers...)
			}
			a := &fakeAgent{closed: make(chan struct{})}
			f.agentsMu.Lock()
			f.agents = append(f.agents, a)
			f.agentsMu.Unlock()
			return signers, a.close
		},
		listener: f.listener,
		route:    f.route,
		state:    state,
		publish: func() {
			if err := f.dir.Update(state.apply); err != nil {
				t.Errorf("publishing the record: %v", err)
			}
		},
		sessionID:  supervisorSessionID,
		generation: 1,
		supported:  supported,
		jitter:     f.jitters.jitter,
		logger:     testLogger(),
	}

	ctx, cancel := context.WithCancel(t.Context())
	f.cancel = cancel
	go func() {
		defer close(f.done)
		f.sup.run(ctx, f.first)
	}()
	t.Cleanup(func() {
		f.cancel()
		f.awaitReturn(t)
		// As Run does once the guest door has drained.
		f.sup.current().Close()
		_ = f.listener.Close()
	})
	return f
}

func (f *supervisorFixture) record(t *testing.T) sessiondir.Record {
	t.Helper()
	return f.dir.Record()
}

// awaitStatus polls the record until its status is want, and returns it.
func (f *supervisorFixture) awaitStatus(t *testing.T, want string, within time.Duration) sessiondir.Record {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		rec := f.dir.Record()
		if rec.Status == want {
			return rec
		}
		if time.Now().After(deadline) {
			t.Fatalf("the status is %q, not %q, after %s: %+v", rec.Status, want, within, rec)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// awaitReturn waits for run to return.
func (f *supervisorFixture) awaitReturn(t *testing.T) {
	t.Helper()
	select {
	case <-f.done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after its context ended")
	}
}

// agent is attempt i's agent connection, counting from 0, once that attempt
// has asked for its identities.
func (f *supervisorFixture) agent(i int) *fakeAgent {
	f.agentsMu.Lock()
	defer f.agentsMu.Unlock()
	return f.agents[i]
}

func (f *supervisorFixture) allAgents() []*fakeAgent {
	f.agentsMu.Lock()
	defer f.agentsMu.Unlock()
	return append([]*fakeAgent(nil), f.agents...)
}

func TestSupervisorRedialsWithTheNextGenerationEveryTime(t *testing.T) {
	f := newSupervisorFixture(t, true /* supported */)
	next := newFakeTunnel(t, true)
	f.script.steps = []func(context.Context) (tunnel, error){
		func(context.Context) (tunnel, error) {
			return nil, &net.OpError{Op: "dial", Err: errors.New("refused")}
		},
		func(context.Context) (tunnel, error) {
			return nil, &internal.CreateSessionRefusedError{Body: registration.Superseded}
		},
		func(context.Context) (tunnel, error) { return next, nil },
	}
	f.first.drop(io.EOF)
	f.awaitStatus(t, sessiondir.StatusReady, 2*time.Second)
	require.Equal(t, []uint64{2, 3, 4}, f.script.gens, "a generation per attempt, never reused")
	rec := f.record(t)
	require.Zero(t, rec.TunnelReason, "cleared when the tunnel is up")
	require.True(t, f.first.closed.Load())
}

func TestSupervisorDropsTheSessionKeyAfterAuthRefused(t *testing.T) {
	f := newSupervisorFixture(t, true)
	f.sup.sessionKeyFirst = true
	f.script.steps = []func(context.Context) (tunnel, error){
		func(context.Context) (tunnel, error) { return nil, &internal.PermissionDeniedError{} },
		func(context.Context) (tunnel, error) { return newFakeTunnel(t, true), nil },
	}
	f.first.drop(io.EOF)
	f.awaitStatus(t, sessiondir.StatusReady, 2*time.Second)
	require.Equal(t, []bool{true, false}, f.script.keyFirst, "the session key isn't offered again")
}

// supervisorStopBound is how long a stopped supervisor may take to return.
// It is shorter than the slow wait, so a supervisor that sat the wait out
// before noticing the stop overruns it.
const supervisorStopBound = 200 * time.Millisecond

// requireStopsPromptly runs stop, which ends f's supervisor, and requires that
// run returns within supervisorStopBound of it.
func requireStopsPromptly(t *testing.T, f *supervisorFixture, stop func()) {
	t.Helper()
	start := time.Now()
	stop()
	f.awaitReturn(t)
	require.Less(t, time.Since(start), supervisorStopBound)
}

func TestSupervisorStopsPromptly(t *testing.T) {
	t.Run("waiting slowly", func(t *testing.T) {
		f := newSupervisorFixture(t, true)
		f.script.repeat(func(context.Context) (tunnel, error) { return nil, &internal.RelayKeyChangedError{} })
		f.first.drop(io.EOF)
		// The first blocked error is retried on the fast schedule and the
		// second starts the slow wait, so stop only once the record shows a
		// wait that long with nearly all of it still to run. Anything less
		// could be a fast wait, or a slow one the stop would outlast by too
		// little to tell from a prompt return. The script goes on failing the
		// same way, so a poll that missed one slow wait finds the next.
		deadline := time.Now().Add(5 * time.Second)
		for {
			rec := f.record(t)
			// After the read: Record can wait on the lock an Update holds across
			// a write, so a stamp taken before it would overstate what remains.
			readAt := time.Now()
			if rec.TunnelReason == sessiondir.TunnelReasonRelayKeyChanged &&
				rec.NextAttemptAt.Sub(readAt) >= supervisorTiming.SlowWait-50*time.Millisecond {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the supervisor never began a slow wait: %+v", rec)
			}
			time.Sleep(5 * time.Millisecond)
		}
		requireStopsPromptly(t, f, f.cancel)
	})

	t.Run("mid-attempt", func(t *testing.T) {
		f := newSupervisorFixture(t, true)
		entered := make(chan struct{})
		var once sync.Once
		f.script.repeat(func(ctx context.Context) (tunnel, error) {
			once.Do(func() { close(entered) })
			<-ctx.Done()
			return nil, ctx.Err()
		})
		f.first.drop(io.EOF)
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("no attempt was made")
		}
		requireStopsPromptly(t, f, f.cancel)
	})
}

// The live tunnel outlives the supervisor: Run closes it after the guest door
// has drained, so a stopped session's guests still get their output and exit
// status.
func TestSupervisorLeavesTheLiveTunnelToRun(t *testing.T) {
	f := newSupervisorFixture(t, true)
	next := newFakeTunnel(t, true)
	f.script.steps = []func(context.Context) (tunnel, error){func(context.Context) (tunnel, error) { return next, nil }}
	f.first.drop(io.EOF)
	f.awaitStatus(t, sessiondir.StatusReady, 2*time.Second)
	f.cancel()
	f.awaitReturn(t)
	require.True(t, f.first.closed.Load(), "a replaced tunnel is the supervisor's to close")
	require.False(t, next.closed.Load(), "the live tunnel was closed under the draining guest door")
	require.Same(t, next, f.sup.current())
}

func TestSupervisorBlockedThenRecovered(t *testing.T) {
	f := newSupervisorFixture(t, true)
	keyChanged := &internal.RelayKeyChangedError{}
	var waiting sessiondir.Record
	f.script.steps = []func(context.Context) (tunnel, error){
		func(context.Context) (tunnel, error) { return nil, keyChanged },
		func(context.Context) (tunnel, error) { return nil, keyChanged },
		func(context.Context) (tunnel, error) {
			// Nothing is published between a wait and the attempt it was
			// for, so this is the record the slow wait left.
			waiting = f.record(t)
			return newFakeTunnel(t, true), nil
		},
	}
	droppedAt := time.Now()
	f.first.drop(io.EOF)
	f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)

	timing := supervisorTiming
	require.Equal(t, []time.Duration{timing.FastBase, 2 * timing.FastBase, timing.SlowJitter}, f.jitters.got(),
		"fast after the loss, fast after the first refusal, slow after the second")
	began, ended := f.script.began, f.script.ended
	require.Len(t, began, 3)
	require.Less(t, began[0].Sub(droppedAt), timing.SlowWait, "the first wait after a loss is fast")
	require.Less(t, began[1].Sub(ended[0]), timing.SlowWait, "the first blocked error gets one more fast wait")
	slow := began[2].Sub(ended[1])
	require.GreaterOrEqual(t, slow, timing.SlowWait+timing.SlowJitter, "the second waits slowly, never less")
	// ended[1] is taken before the record write that publishes the slow wait,
	// so the span holds a temp-file write and a rename as well as the timer's
	// wake.
	require.LessOrEqual(t, slow, timing.SlowWait+timing.SlowJitter+2*lateWake)

	require.Equal(t, sessiondir.StatusReconnecting, waiting.Status)
	require.Equal(t, sessiondir.TunnelReasonRelayKeyChanged, waiting.TunnelReason)
	require.Equal(t, keyChanged.Error(), waiting.TunnelError, "the raw error")
	require.False(t, waiting.TunnelLostAt.IsZero())
	require.False(t, waiting.TunnelLostAt.After(began[0]), "the outage began with the loss")
	require.GreaterOrEqual(t, waiting.NextAttemptAt.Sub(ended[1]), timing.SlowWait, "next_attempt_at is when the slow wait ends")
}

func TestSupervisorOnAnUnsupportedRelay(t *testing.T) {
	f := newSupervisorFixture(t, false)
	accepted := make(chan error, 1)
	go func() {
		_, err := f.listener.Accept()
		accepted <- err
	}()
	dropped := errors.New("the relay went away")
	f.first.drop(dropped)

	rec := f.awaitStatus(t, sessiondir.StatusDisconnected, 5*time.Second)
	require.Equal(t, sessiondir.TunnelReasonReconnectUnsupported, rec.TunnelReason)
	require.Equal(t, dropped.Error(), rec.TunnelError)
	require.True(t, rec.NextAttemptAt.IsZero(), "there is no next attempt")
	select {
	case err := <-accepted:
		require.ErrorIs(t, err, dropped, "the guest door ends, and says why")
	case <-time.After(5 * time.Second):
		t.Fatal("the guest door's Accept never failed")
	}

	// It neither redials nor returns. A redial would come within FastBase;
	// the window is ten of them.
	select {
	case <-f.done:
		t.Fatal("run returned before its context ended")
	case <-time.After(10 * supervisorTiming.FastBase):
	}
	require.Empty(t, f.script.generations(), "no attempt is made")
	f.cancel()
	f.awaitReturn(t)
}

func TestSupervisorResetsOnlyAfterTheTunnelWasUp(t *testing.T) {
	f := newSupervisorFixture(t, true)
	second, third, fourth := newFakeTunnel(t, true), newFakeTunnel(t, true), newFakeTunnel(t, true)
	f.script.steps = []func(context.Context) (tunnel, error){
		func(context.Context) (tunnel, error) { return second, nil },
		func(context.Context) (tunnel, error) { return third, nil },
		func(context.Context) (tunnel, error) { return fourth, nil },
	}
	f.first.drop(io.EOF)
	awaitWatched(t, second)

	// Lost as soon as it was up: the schedule goes on where it was.
	second.drop(io.EOF)
	awaitWatched(t, third)

	// Lost after ResetAfter up: the schedule starts over.
	time.Sleep(supervisorTiming.ResetAfter)
	third.drop(io.EOF)
	awaitWatched(t, fourth)

	base := supervisorTiming.FastBase
	require.Equal(t, []time.Duration{base, 2 * base, base}, f.jitters.got())
}

func TestSupervisorUpdatesTheRoute(t *testing.T) {
	f := newSupervisorFixture(t, true)
	getSession := serveAdmin(t, f.dir, &api.GetSessionResponse{
		SessionId: supervisorSessionID,
		NodeAddr:  "node-1:22",
		SshUser:   "user-1",
	}, f.route)
	before := getSession()
	require.Equal(t, "node-1:22", before.GetNodeAddr())
	require.Equal(t, "user-1", before.GetSshUser())

	next := newFakeTunnel(t, true)
	f.script.steps = []func(context.Context) (tunnel, error){func(context.Context) (tunnel, error) { return next, nil }}
	f.first.drop(io.EOF)
	awaitWatched(t, next)

	after := getSession()
	require.Equal(t, "node-2:22", after.GetNodeAddr(), "guests reach the session through the latest registration's node")
	require.Equal(t, "user-2", after.GetSshUser())
	require.Equal(t, supervisorSessionID, after.GetSessionId(), "the session ID never changes")
}

// serveAdmin serves the admin RPCs for session on dir's admin socket, its
// route read from route as Run's is, and returns a GetSession call.
func serveAdmin(t *testing.T, dir *sessiondir.Dir, session *api.GetSessionResponse, route *internal.SessionRoute) func() *api.GetSessionResponse {
	t.Helper()
	admin := &internal.AdminServer{Session: session, ClientRepo: internal.NewClientRepo(), Route: route}
	require.NoError(t, admin.Listen(dir.AdminSocket()))
	served := make(chan error, 1)
	go func() { served <- admin.Serve(t.Context()) }()
	conn, err := grpc.NewClient("passthrough:///unix",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", dir.AdminSocket())
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = admin.Shutdown(ctx)
		<-served
	})
	client := api.NewAdminServiceClient(conn)
	return func() *api.GetSessionResponse {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		resp, err := client.GetSession(ctx, &api.GetSessionRequest{})
		require.NoError(t, err)
		return resp
	}
}

func TestSupervisorClearsSessionKeyFirstOnAGatedAnswer(t *testing.T) {
	for name, tc := range map[string]struct {
		redial bool
		want   []bool
	}{
		"a relay that no longer admits the session key alone": {redial: false, want: []bool{true, false}},
		"a relay that still does":                             {redial: true, want: []bool{true, true}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newSupervisorFixture(t, true)
			f.sup.sessionKeyFirst = true
			second, third := newFakeTunnel(t, tc.redial), newFakeTunnel(t, true)
			f.script.steps = []func(context.Context) (tunnel, error){
				func(context.Context) (tunnel, error) { return second, nil },
				func(context.Context) (tunnel, error) { return third, nil },
			}
			f.first.drop(io.EOF)
			awaitWatched(t, second)
			second.drop(io.EOF)
			awaitWatched(t, third)
			require.Equal(t, tc.want, f.script.keyFirst)
		})
	}
}

func TestSupervisorRefusesARegistrationUnderAnotherSessionID(t *testing.T) {
	f := newSupervisorFixture(t, true)
	stray, next := newFakeTunnel(t, true), newFakeTunnel(t, true)
	f.script.response = func(generation uint64) *server.CreateSessionResponse {
		id := supervisorSessionID
		if generation == 2 {
			id = "another-session"
		}
		return &server.CreateSessionResponse{
			SessionID: id,
			NodeAddr:  fmt.Sprintf("node-%d:22", generation),
			SshUser:   fmt.Sprintf("user-%d", generation),
		}
	}
	var waiting sessiondir.Record
	f.script.steps = []func(context.Context) (tunnel, error){
		func(context.Context) (tunnel, error) { return stray, nil },
		func(context.Context) (tunnel, error) {
			waiting = f.record(t)
			return next, nil
		},
	}
	f.first.drop(io.EOF)
	awaitWatched(t, next)

	require.True(t, stray.closed.Load(), "a tunnel no guest can find is closed")
	require.Same(t, next, f.sup.current())
	require.Equal(t, sessiondir.TunnelReasonRelayUnsupported, waiting.TunnelReason)
	require.Contains(t, waiting.TunnelError, "another-session", "the error names the ID the relay answered with")
	nodeAddr, sshUser := f.route.Get()
	require.Equal(t, "node-3:22", nodeAddr, "the route never takes the other session's")
	require.Equal(t, "user-3", sshUser)
	require.Equal(t, []uint64{2, 3}, f.script.gens)
}

func TestSupervisorBoundsEachAttemptAndClosesItsAgent(t *testing.T) {
	f := newSupervisorFixture(t, true)
	next := newFakeTunnel(t, true)
	var began, deadline, released time.Time
	f.script.steps = []func(context.Context) (tunnel, error){
		func(ctx context.Context) (tunnel, error) {
			// A signature waiting on an approval prompt: only closing the
			// attempt's agent connection releases it.
			began = time.Now()
			deadline, _ = ctx.Deadline()
			select {
			case <-f.agent(0).closed:
			case <-time.After(5 * time.Second):
			}
			released = time.Now()
			return nil, ctx.Err()
		},
		func(context.Context) (tunnel, error) { return next, nil },
	}
	f.first.drop(io.EOF)
	awaitWatched(t, next)

	require.WithinDuration(t, began.Add(supervisorTiming.AttemptDeadline), deadline, lateWake, "each attempt has AttemptDeadline")
	require.False(t, released.Before(deadline), "the agent was closed before the attempt's deadline")
	require.LessOrEqual(t, released.Sub(deadline), lateWake, "the agent was closed long after the attempt's deadline")
	agents := f.allAgents()
	require.Len(t, agents, 2)
	for i, a := range agents {
		require.NotZero(t, a.closes.Load(), "attempt %d's agent connection outlived it", i+1)
	}
}

func TestSupervisorDoesNotRecordAnAttemptTheStopCutShort(t *testing.T) {
	f := newSupervisorFixture(t, true)
	entered := make(chan struct{})
	f.script.steps = []func(context.Context) (tunnel, error){
		func(ctx context.Context) (tunnel, error) {
			close(entered)
			<-ctx.Done()
			// What a signature cut off by the attempt's end says, and a
			// refusal that would be recorded as blocked.
			return nil, &AgentRefusedError{Key: "SHA256:test", Err: errAttemptOver}
		},
	}
	f.first.drop(io.EOF)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no attempt was made")
	}
	f.cancel()
	f.awaitReturn(t)

	rec := f.record(t)
	require.Equal(t, sessiondir.StatusReconnecting, rec.Status)
	require.Equal(t, sessiondir.TunnelReasonNetwork, rec.TunnelReason, "the stop isn't the relay's failure")
	require.Equal(t, io.EOF.Error(), rec.TunnelError, "the record still says why the tunnel was lost")
	require.NotZero(t, f.agent(0).closes.Load(), "the attempt's agent connection outlived it")
}

// An attempt can succeed in the moment the stop lands. The tunnel it returns
// has nothing to serve, and is the supervisor's to close: nobody else knows it
// exists.
func TestSupervisorClosesATunnelAnAttemptReturnsAsTheStopLands(t *testing.T) {
	f := newSupervisorFixture(t, true)
	late := newFakeTunnel(t, true)
	entered, stopped := make(chan struct{}), make(chan struct{})
	f.script.steps = []func(context.Context) (tunnel, error){
		func(ctx context.Context) (tunnel, error) {
			close(entered)
			<-ctx.Done()
			// Whatever ended the attempt's context, answer only once the stop
			// has been requested: the attempt succeeds into a session that is
			// ending, never into one that is merely out of time.
			<-stopped
			return late, nil
		},
	}
	f.first.drop(io.EOF)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no attempt was made")
	}
	requireStopsPromptly(t, f, func() {
		f.cancel()
		close(stopped)
	})

	require.True(t, late.closed.Load(), "a tunnel the supervisor didn't install is closed")
	select {
	case <-late.watched:
		t.Fatal("a tunnel from an attempt the stop cut short was watched as the current one")
	default:
	}
	require.Same(t, f.first, f.sup.current(), "the tunnel the guest door is served on is unchanged")
	require.False(t, f.first.closed.Load(), "nothing replaced the lost tunnel")
	nodeAddr, sshUser := f.route.Get()
	require.Equal(t, "node-1:22", nodeAddr, "the route is unchanged")
	require.Equal(t, "user-1", sshUser)
}

// A guest door that has already closed can't be swapped onto a new tunnel. The
// supervisor closes the tunnel, and has nothing more to do but wait for the
// stop.
func TestSupervisorClosesATunnelWhenTheGuestDoorHasClosed(t *testing.T) {
	f := newSupervisorFixture(t, true)
	next := newFakeTunnel(t, true)
	f.script.steps = []func(context.Context) (tunnel, error){
		func(context.Context) (tunnel, error) { return next, nil },
	}
	require.NoError(t, f.listener.Close())
	f.first.drop(io.EOF)

	// Closing a fakeTunnel ends its connection, which is what releases lost.
	select {
	case <-next.lost:
	case <-time.After(5 * time.Second):
		t.Fatal("the attempt's tunnel was never closed")
	}
	require.True(t, next.closed.Load(), "a tunnel that can't serve the guest door is closed")

	// It doesn't return, and it doesn't redial. A redial would come within
	// FastCap of the attempt; the window is ten of them.
	select {
	case <-f.done:
		t.Fatal("run returned before its context ended")
	case <-time.After(10 * supervisorTiming.FastCap):
	}
	require.Equal(t, []uint64{2}, f.script.generations(), "no second attempt is made")
	require.Same(t, f.first, f.sup.current(), "the tunnel the guest door is served on is unchanged")
	select {
	case <-next.watched:
		t.Fatal("the closed tunnel was watched as the current one")
	default:
	}

	f.cancel()
	f.awaitReturn(t)
}
