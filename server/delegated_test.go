package server

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/ws"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const (
	fixtureAccountID  = "44444444-4444-4444-8444-444444444444"
	externalSessionID = "33333333-3333-4333-8333-333333333333"
	testProtocol      = "test_v1"
)

// fakeAuthority records every call and answers with register and control,
// or with a current decision at revision 1 when they are nil. A call to
// Register or Control it is told to hold, by gate or hang, waits there until
// released, or until its context ends. It claims the users that start with
// claimPrefix, answers Admit with admit, or a refusal when that is nil, and
// Unreachable with unreachable, or a fixed line.
type fakeAuthority struct {
	mu            sync.Mutex
	registrations []DelegatedRegistration
	controls      []Report
	register      func(DelegatedRegistration) (RegistrationResult, error)
	control       func(Report) (*DelegatedControlReply, error)
	gates         []*fakeGate
	hang          bool

	claimed     []string
	admissions  []admitCall
	unreached   []Target
	admit       func(context.Context, *Guest, GuestRequest) (Admission, error)
	unreachable func(*Guest, Target) []byte
	// asIs leaves an allow's sequence and allowance as admit gave them.
	asIs bool
}

// claimPrefix starts every user fakeAuthority claims.
const claimPrefix = "claim-"

// admitCall is one question Admit was asked.
type admitCall struct {
	guest   *Guest
	request GuestRequest
}

func (f *fakeAuthority) Claims(user string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claimed = append(f.claimed, user)
	return strings.HasPrefix(user, claimPrefix)
}

// Admit fills in an allow's binding when admit leaves it out: a sequence and
// an allowance, unless asIs is set, and the registration the target's routing
// ID registered.
func (f *fakeAuthority) Admit(ctx context.Context, g *Guest, req GuestRequest) (Admission, error) {
	f.mu.Lock()
	f.admissions = append(f.admissions, admitCall{g, req})
	answer, asIs := f.admit, f.asIs
	f.mu.Unlock()
	if answer == nil {
		return Admission{}, nil
	}
	admission, err := answer(ctx, g, req)
	if admission.Verdict == VerdictAllow {
		if admission.Sequence == 0 && !asIs {
			admission.Sequence = 1
			admission.AllowUntil = time.Now().Add(45 * time.Second)
		}
		if admission.Target.Registration.Authority == "" {
			f.mu.Lock()
			for _, reg := range f.registrations {
				if reg.RoutingID == admission.Target.RoutingID {
					target := admission.Target
					var keys [][]byte
					if target.RunPublicKey != nil {
						keys = [][]byte{target.RunPublicKey.Marshal()}
					}
					admission.Target.Registration = RegistrationRef{Authority: AuthorityDelegated, AccountID: target.AccountID, SessionID: target.SessionID, Generation: reg.Generation, RoutingID: target.RoutingID, RunPublicKeys: keys, RegistrationID: reg.RegistrationID, HomeNode: reg.HomeNode, HomeNodeID: reg.HomeNodeID, HomeBootID: reg.HomeBootID}
				}
			}
			f.mu.Unlock()
		}
	}
	return admission, err
}

// unreachableLine is what fakeAuthority shows a guest whose allowed target
// the relay couldn't reach.
const unreachableLine = "the session is unreachable\n"

func (f *fakeAuthority) Unreachable(_ context.Context, g *Guest, t Target) []byte {
	f.mu.Lock()
	f.unreached = append(f.unreached, t)
	answer := f.unreachable
	f.mu.Unlock()
	if answer == nil {
		return []byte(unreachableLine)
	}
	return answer(g, t)
}

func (f *fakeAuthority) admitWith(fn func(context.Context, *Guest, GuestRequest) (Admission, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.admit = fn
}

// guests is every question Admit was asked, and every target Unreachable was.
func (f *fakeAuthority) guests() ([]admitCall, []Target) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]admitCall(nil), f.admissions...), append([]Target(nil), f.unreached...)
}

// claims is every user Claims was asked about, in order.
func (f *fakeAuthority) claims() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.claimed...)
}

type fakeGate struct {
	arrived, released chan struct{}
	release           sync.Once
}

// gate holds the next call until release is called, or its context ends.
// arrived is closed once the call is held.
func (f *fakeAuthority) gate() (arrived <-chan struct{}, release func()) {
	g := &fakeGate{arrived: make(chan struct{}), released: make(chan struct{})}
	f.mu.Lock()
	f.gates = append(f.gates, g)
	f.mu.Unlock()
	return g.arrived, func() { g.release.Do(func() { close(g.released) }) }
}

// hangs has every later call block until its context ends.
func (f *fakeAuthority) hangs() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hang = true
}

func (f *fakeAuthority) wait(ctx context.Context) error {
	f.mu.Lock()
	hang := f.hang
	var g *fakeGate
	if len(f.gates) > 0 {
		g, f.gates = f.gates[0], f.gates[1:]
	}
	f.mu.Unlock()
	if g != nil {
		close(g.arrived)
	}
	switch {
	case hang:
		<-ctx.Done()
		return ctx.Err()
	case g != nil:
		select {
		case <-g.released:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (f *fakeAuthority) Register(ctx context.Context, r DelegatedRegistration) (RegistrationResult, error) {
	f.mu.Lock()
	f.registrations = append(f.registrations, r)
	answer := f.register
	f.mu.Unlock()
	if err := f.wait(ctx); err != nil {
		return RegistrationResult{}, err
	}
	if answer == nil {
		return RegistrationResult{AccountID: fixtureAccountID, Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, nil
	}
	return answer(r)
}

func (f *fakeAuthority) Control(ctx context.Context, r Report) (*DelegatedControlReply, error) {
	f.mu.Lock()
	f.controls = append(f.controls, r)
	answer := f.control
	f.mu.Unlock()
	if err := f.wait(ctx); err != nil {
		return nil, err
	}
	if answer == nil {
		return &DelegatedControlReply{ExternalSessionId: r.Request.ExternalSessionId, Generation: r.Request.Generation, AcknowledgedSequence: r.Request.Sequence, Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, nil
	}
	return answer(r)
}

func (f *fakeAuthority) answer(register func(DelegatedRegistration) (RegistrationResult, error), control func(Report) (*DelegatedControlReply, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.register, f.control = register, control
}

func (f *fakeAuthority) seen() ([]DelegatedRegistration, []Report) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]DelegatedRegistration(nil), f.registrations...), append([]Report(nil), f.controls...)
}

// calls is how many calls the authority was asked, of any method.
func (f *fakeAuthority) calls() int {
	r, c := f.seen()
	admitted, unreached := f.guests()
	return len(r) + len(c) + len(f.claims()) + len(admitted) + len(unreached)
}

func decided(d DelegatedDisposition, revision uint64) func(DelegatedRegistration) (RegistrationResult, error) {
	return func(DelegatedRegistration) (RegistrationResult, error) {
		return RegistrationResult{AccountID: fixtureAccountID, Disposition: d, DecisionRevision: revision}, nil
	}
}

// delegatedTestServer is a Server composed with an authority, serving a
// public SSH listener and an internal one, with every prerequisite of an
// enabled authority.
type delegatedTestServer struct {
	*Server
	addr   string
	wsAddr string
	signer ssh.Signer
}

func newDelegatedTestServer(t *testing.T, authority Authority, opts ...func(*Server)) *delegatedTestServer {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	network := &MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))
	sshln, wsln, internalln := listenLoopback(t), listenLoopback(t), listenLoopback(t)
	s := &Server{
		NodeAddr:         internalln.Addr().String(),
		NodeID:           "test-machine",
		BootID:           fixtureBootID,
		RefuseLegacyHops: true,
		HostSigners:      []ssh.Signer{signer},
		Signers:          []ssh.Signer{signer},
		NetworkProvider:  network,
		MetricsProvider:  provider.NewDiscardProvider(),
		SessionManager:   newEmbeddedSessionManager(logger),
		Logger:           logger,
		Extensions:       Extensions{Authority: authority, Enabled: true, Protocols: []string{testProtocol}},
	}
	for _, opt := range opts {
		opt(s)
	}
	served := make(chan error, 1)
	go func() {
		served <- s.ServeListeners(context.Background(), Listeners{SSH: sshln, WS: wsln, Internal: internalln})
	}()
	t.Cleanup(func() {
		_ = s.Shutdown()
		select {
		case err := <-served:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("the relay did not stop")
		}
	})
	requireSSHDServing(t, network)
	return &delegatedTestServer{Server: s, addr: sshln.Addr().String(), wsAddr: wsln.Addr().String(), signer: signer}
}

// runtime is the serving relay's Runtime.
func (s *Server) runtime() *delegatedHosts {
	s.mux.Lock()
	defer s.mux.Unlock()
	return s.delegated
}

// sshd is the sshd the relay serves with.
func (s *Server) sshd() *sshd {
	s.mux.Lock()
	defer s.mux.Unlock()
	return s.daemon
}

// forwarded reports whether the relay holds a bound forward for id.
func (s *Server) forwarded(id string) bool {
	h := s.sshd().forwardHandler
	h.Lock()
	defer h.Unlock()
	_, ok := h.forwards[id]
	return ok
}

// requireServed requires the relay to serve id: its route, its home and its
// forward.
func (s *Server) requireServed(t *testing.T, id string) {
	t.Helper()
	_, err := s.SessionManager.GetSession(id)
	require.NoError(t, err, "the route went")
	home, found := s.sshd().Lookup(id)
	require.True(t, found, "the home went")
	require.True(t, home.Held())
	require.True(t, s.forwarded(id), "the forward went")
}

// requireWithdrawn requires the relay to serve nothing of id.
func (s *Server) requireWithdrawn(t *testing.T, id string) {
	t.Helper()
	_, err := s.SessionManager.GetSession(id)
	require.Error(t, err, "the route stayed")
	_, found := s.sshd().Lookup(id)
	require.False(t, found, "the home stayed")
	require.False(t, s.forwarded(id), "the forward stayed")
}

// dialHost connects to addr as a host does, through the relay's proxy.
// decisions, when set, receives the relay's decision requests; the rest of
// the relay's requests get the stock refusal.
func dialHost(t *testing.T, addr string, signer ssh.Signer, decisions func(*ssh.Request)) *ssh.Client {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	return hostOver(t, conn, addr, signer, decisions)
}

// dialWSHost connects to the WebSocket listener at addr as a host does.
func dialWSHost(t *testing.T, addr string, signer ssh.Signer) *ssh.Client {
	t.Helper()
	conn, err := ws.NewWSConn(&url.URL{Scheme: "ws", Host: addr, User: url.UserPassword("host", "")}, true, nil)
	require.NoError(t, err)
	return hostOver(t, conn, addr, signer, nil)
}

func hostOver(t *testing.T, conn net.Conn, addr string, signer ssh.Signer, decisions func(*ssh.Request)) *ssh.Client {
	t.Helper()
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            "host",
		ClientVersion:   upterm.HostSSHClientVersion,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	require.NoError(t, err)
	rest := make(chan *ssh.Request)
	go func() {
		defer close(rest)
		for r := range reqs {
			if decisions != nil && r.Type == upterm.HostDelegatedDecisionRequestType {
				decisions(r)
				continue
			}
			rest <- r
		}
	}()
	client := ssh.NewClient(c, chans, rest)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func delegatedSession() *DelegatedSession {
	return &DelegatedSession{Protocol: testProtocol, ExternalSessionId: externalSessionID}
}

// delegatedRequest is p's proven registration at gen over client, carrying m.
func (p proven) delegatedRequest(t *testing.T, client *ssh.Client, gen uint64, m *DelegatedSession) *CreateSessionRequest {
	t.Helper()
	proof, err := registration.Sign(p.key, client.SessionID(), p.secret, gen)
	require.NoError(t, err)
	return &CreateSessionRequest{HostUser: "host-user", HostPublicKeys: p.hostKeys(), SessionSecret: p.secret, Generation: gen, HostKeyProof: proof, DelegatedSession: m}
}

func sendCreate(t *testing.T, client *ssh.Client, req *CreateSessionRequest) (bool, []byte) {
	t.Helper()
	b, err := proto.Marshal(req)
	require.NoError(t, err)
	ok, body, err := client.SendRequest(upterm.ServerCreateSessionRequestType, true, b)
	require.NoError(t, err)
	return ok, body
}

func requireDelegatedError(t *testing.T, ok bool, body []byte, code DelegatedErrorCode) {
	t.Helper()
	require.False(t, ok, "accepted")
	refused, parsed := DecodeDelegatedError(body)
	require.True(t, parsed, "the refusal is not a DelegatedError: %q", body)
	require.Equal(t, code, refused.Code)
}

func sendControl(t *testing.T, client *ssh.Client, req *DelegatedControlRequest) (bool, []byte) {
	t.Helper()
	b, err := proto.Marshal(req)
	require.NoError(t, err)
	ok, body, err := client.SendRequest(upterm.ServerDelegatedControlRequestType, true, b)
	require.NoError(t, err)
	return ok, body
}

func ready(sequence uint64) *DelegatedControlRequest {
	return &DelegatedControlRequest{ExternalSessionId: externalSessionID, Generation: 1, Sequence: sequence, Event: &DelegatedControlRequest_Ready{Ready: &DelegatedReady{}}}
}

// An enabled authority's prerequisites are the server's to check: the
// in-memory network and an internal listener. WebSocket and neighbour routing
// stay available. Opt.Validate is the same whatever is composed, and a dark
// authority needs none of them.
func TestEnabledAuthorityPrerequisites(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	internal := Listeners{Internal: listenLoopback(t)}
	srv := &Server{Extensions: Extensions{Authority: &fakeAuthority{}, Enabled: true}, NetworkProvider: &UnixProvider{}, RefuseLegacyHops: true, NodeID: "node", BootID: fixtureBootID}
	require.ErrorIs(t, srv.checkAuthority(internal), errAuthorityNeedsMemoryNetwork)
	srv.Extensions.Enabled = false
	require.NoError(t, srv.checkAuthority(Listeners{}))
	srv.Extensions.Enabled = true
	srv.NetworkProvider = &MemoryProvider{}
	require.NoError(t, srv.checkAuthority(Listeners{WS: listenLoopback(t), Internal: internal.Internal}))
	srv.SessionManager = newSessionManagerWithStore(newMemorySessionStore(logger), routing.NewEncodeDecoder(routing.ModeConsul))
	require.NoError(t, srv.checkAuthority(internal))
	require.Equal(t, tcpConnDialer{}, srv.neighbourDialer(tcpConnDialer{}))

	valid := Opt{SSHAddr: "127.0.0.1:0", InternalAddr: "127.0.0.1:0", Network: "mem", SSHNetwork: "tcp4", SSHProxyProtocolRequired: true, Extensions: Extensions{Authority: &fakeAuthority{}, Enabled: true}}
	require.NoError(t, valid.Validate())
	for _, change := range []func(*Opt){func(o *Opt) { o.Network = "unix" }, func(o *Opt) { o.InternalAddr = "" }, func(o *Opt) { o.SSHNetwork = "tcp" }, func(o *Opt) { o.SSHProxyProtocolRequired = false }} {
		opt := valid
		change(&opt)
		stock := opt
		stock.Extensions = Extensions{}
		require.Equal(t, stock.Validate(), opt.Validate(), "an enabled authority must leave the stock validation alone")
		opt.Extensions.Enabled = false
		require.Equal(t, stock.Validate(), opt.Validate(), "a dark authority must leave the stock validation alone")
	}
}

// A relay with an authority keeps the local registration path, and asks the
// authority nothing about it.
func TestAuthorityLeavesLocalRegistrationsAlone(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	host := newProven(t)
	for _, proven := range []bool{false, true} {
		client := dialHost(t, ts.addr, ts.signer, nil)
		req := &CreateSessionRequest{HostUser: "host-user", HostPublicKeys: host.hostKeys()}
		if proven {
			req = host.delegatedRequest(t, client, 1, nil)
		}
		ok, body := sendCreate(t, client, req)
		require.True(t, ok, "%q", body)
	}
	require.Zero(t, authority.calls())
}

// Only a proven, well-formed delegated registration reaches the authority,
// and only its current decision publishes a route. A stopped or withdrawn
// one is answered with the derived ID and no user, and keeps its connection
// for reports.
func TestDelegatedRegistrationDecisions(t *testing.T) {
	t.Run("current", func(t *testing.T) {
		authority := &fakeAuthority{}
		ts := newDelegatedTestServer(t, authority)
		host := newProven(t)
		client := dialHost(t, ts.addr, ts.signer, nil)
		ok, body := sendCreate(t, client, host.delegatedRequest(t, client, 1, delegatedSession()))
		require.True(t, ok, "%q", body)
		var resp CreateSessionResponse
		require.NoError(t, proto.Unmarshal(body, &resp))
		require.Equal(t, host.id(), resp.SessionID)
		require.NotEmpty(t, resp.SshUser)
		require.True(t, proto.Equal(&DelegatedSession{Protocol: testProtocol, ExternalSessionId: externalSessionID, Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, resp.DelegatedSession), "%v", resp.DelegatedSession)

		registrations, _ := authority.seen()
		require.Len(t, registrations, 1)
		require.True(t, proto.Equal(delegatedSession(), registrations[0].Session))
		require.Equal(t, host.key.PublicKey().Marshal(), registrations[0].RunPublicKey.Marshal())
		require.Equal(t, host.id(), registrations[0].RoutingID)
		require.Equal(t, client.SessionID(), registrations[0].RegistrationID)

		route, err := ts.SessionManager.GetSession(host.id())
		require.NoError(t, err, "a current registration has a route")
		require.Equal(t, AuthorityDelegated, route.AuthorityHint)
		ok, msg := forwardRequest(t, client, streamlocalForwardChannelType, host.id())
		require.True(t, ok, msg)

		// One delegated registration per connection.
		ok, body = sendCreate(t, client, host.delegatedRequest(t, client, 2, delegatedSession()))
		requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
	})

	for _, d := range []DelegatedDisposition{DelegatedDisposition_DELEGATED_STOPPED, DelegatedDisposition_DELEGATED_WITHDRAWN} {
		t.Run(d.String(), func(t *testing.T) {
			authority := &fakeAuthority{register: decided(d, 4)}
			ts := newDelegatedTestServer(t, authority)
			host := newProven(t)
			client := dialHost(t, ts.addr, ts.signer, nil)
			ok, body := sendCreate(t, client, host.delegatedRequest(t, client, 1, delegatedSession()))
			require.True(t, ok, "%q", body)
			var resp CreateSessionResponse
			require.NoError(t, proto.Unmarshal(body, &resp))
			require.Equal(t, host.id(), resp.SessionID)
			require.Empty(t, resp.SshUser)
			require.True(t, proto.Equal(&DelegatedSession{Protocol: testProtocol, ExternalSessionId: externalSessionID, Disposition: d, DecisionRevision: 4}, resp.DelegatedSession))

			_, err := ts.SessionManager.GetSession(host.id())
			require.Error(t, err, "a final registration stored a route")
			ok, _ = forwardRequest(t, client, streamlocalForwardChannelType, host.id())
			require.False(t, ok, "a final registration opened a forward")

			// Its final reports still go through.
			ok, body = sendControl(t, client, ready(1))
			require.True(t, ok, "%q", body)
			_, controls := authority.seen()
			require.Len(t, controls, 1)
		})
	}

	t.Run("refused before the authority", func(t *testing.T) {
		authority := &fakeAuthority{}
		ts := newDelegatedTestServer(t, authority)
		host := newProven(t)
		for name, change := range map[string]func(*CreateSessionRequest){
			"protocol":    func(r *CreateSessionRequest) { r.DelegatedSession.Protocol = "test_v2" },
			"session ID":  func(r *CreateSessionRequest) { r.DelegatedSession.ExternalSessionId = "external-session-1" },
			"disposition": func(r *CreateSessionRequest) { r.DelegatedSession.Disposition = DelegatedDisposition_DELEGATED_CURRENT },
			"revision":    func(r *CreateSessionRequest) { r.DelegatedSession.DecisionRevision = 1 },
			"no proof":    func(r *CreateSessionRequest) { r.HostKeyProof, r.SessionSecret, r.Generation = nil, nil, 0 },
			"bad proof":   func(r *CreateSessionRequest) { r.Generation = 2 },
			"guest keys":  func(r *CreateSessionRequest) { r.ClientAuthorizedKeys = [][]byte{[]byte(TestPublicKeyContent)} },
			"two host keys": func(r *CreateSessionRequest) {
				r.HostPublicKeys = append(r.HostPublicKeys, []byte(TestPublicKeyContent))
			},
		} {
			t.Run(name, func(t *testing.T) {
				client := dialHost(t, ts.addr, ts.signer, nil)
				req := host.delegatedRequest(t, client, 1, delegatedSession())
				change(req)
				ok, body := sendCreate(t, client, req)
				requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
			})
		}
		require.Zero(t, authority.calls(), "the authority saw an unproven or malformed registration")
		_, err := ts.SessionManager.GetSession(host.id())
		require.Error(t, err)
	})

	t.Run("the authority's refusals", func(t *testing.T) {
		for name, tc := range map[string]struct {
			register func(DelegatedRegistration) (RegistrationResult, error)
			want     DelegatedErrorCode
		}{
			"stale": {func(DelegatedRegistration) (RegistrationResult, error) {
				return RegistrationResult{}, &DelegatedRefusedError{Code: DelegatedErrorCode_DELEGATED_STALE_GENERATION}
			}, DelegatedErrorCode_DELEGATED_STALE_GENERATION},
			"invalid": {func(DelegatedRegistration) (RegistrationResult, error) {
				return RegistrationResult{}, &DelegatedRefusedError{Code: DelegatedErrorCode_DELEGATED_INVALID_REQUEST}
			}, DelegatedErrorCode_DELEGATED_INVALID_REQUEST},
			"any other error": {func(DelegatedRegistration) (RegistrationResult, error) {
				return RegistrationResult{}, errors.New("authority timed out")
			}, DelegatedErrorCode_DELEGATED_UNAVAILABLE},
			"the unspecified code": {func(DelegatedRegistration) (RegistrationResult, error) {
				return RegistrationResult{}, &DelegatedRefusedError{Code: DelegatedErrorCode_DELEGATED_ERROR_UNSPECIFIED}
			}, DelegatedErrorCode_DELEGATED_UNAVAILABLE},
			"an unknown code": {func(DelegatedRegistration) (RegistrationResult, error) {
				return RegistrationResult{}, &DelegatedRefusedError{Code: 99}
			}, DelegatedErrorCode_DELEGATED_UNAVAILABLE},
			"no disposition": {decided(DelegatedDisposition_DELEGATED_UNSPECIFIED, 1), DelegatedErrorCode_DELEGATED_UNAVAILABLE},
			"an unknown one": {decided(DelegatedDisposition(9), 1), DelegatedErrorCode_DELEGATED_UNAVAILABLE},
			"no revision":    {decided(DelegatedDisposition_DELEGATED_CURRENT, 0), DelegatedErrorCode_DELEGATED_UNAVAILABLE},
		} {
			t.Run(name, func(t *testing.T) {
				ts := newDelegatedTestServer(t, &fakeAuthority{register: tc.register})
				host := newProven(t)
				client := dialHost(t, ts.addr, ts.signer, nil)
				ok, body := sendCreate(t, client, host.delegatedRequest(t, client, 1, delegatedSession()))
				requireDelegatedError(t, ok, body, tc.want)
				_, err := ts.SessionManager.GetSession(host.id())
				require.Error(t, err, "a refused registration stored a route")
			})
		}
	})
}

// A report goes to the authority only on the connection of the registration
// it is about, and well formed; the authority's answer goes back only if it
// answers that report.
func TestDelegatedControl(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	host := newProven(t)

	unregistered := dialHost(t, ts.addr, ts.signer, nil)
	ok, body := sendControl(t, unregistered, ready(1))
	requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_INVALID_REQUEST)

	client := dialHost(t, ts.addr, ts.signer, nil)
	ok, body = sendCreate(t, client, host.delegatedRequest(t, client, 1, delegatedSession()))
	require.True(t, ok, "%q", body)

	for name, req := range map[string]*DelegatedControlRequest{
		"another session":    {ExternalSessionId: "44444444-4444-4444-8444-444444444444", Generation: 1, Sequence: 1, Event: &DelegatedControlRequest_Ready{Ready: &DelegatedReady{}}},
		"another generation": {ExternalSessionId: externalSessionID, Generation: 2, Sequence: 1, Event: &DelegatedControlRequest_Ready{Ready: &DelegatedReady{}}},
		"no sequence":        {ExternalSessionId: externalSessionID, Generation: 1, Event: &DelegatedControlRequest_Ready{Ready: &DelegatedReady{}}},
		"no event":           {ExternalSessionId: externalSessionID, Generation: 1, Sequence: 1},
		"an unknown status":  {ExternalSessionId: externalSessionID, Generation: 1, Sequence: 1, Event: &DelegatedControlRequest_Exit{Exit: &DelegatedExit{ExitStatus: 3}}},
	} {
		t.Run(name, func(t *testing.T) {
			ok, body := sendControl(t, client, req)
			requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
		})
	}
	ok, body, err := client.SendRequest(upterm.ServerDelegatedControlRequestType, true, []byte("not protobuf \xff\xff"))
	require.NoError(t, err)
	requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
	_, controls := authority.seen()
	require.Empty(t, controls, "the authority saw a malformed report")

	// A current reply leaves the registration served.
	ok, msg := forwardRequest(t, client, streamlocalForwardChannelType, host.id())
	require.True(t, ok, msg)
	ok, body = sendControl(t, client, ready(1))
	require.True(t, ok, "%q", body)
	var current DelegatedControlReply
	require.NoError(t, proto.Unmarshal(body, &current))
	require.Equal(t, DelegatedDisposition_DELEGATED_CURRENT, current.Disposition)
	ts.requireServed(t, host.id())

	exit := &DelegatedControlRequest{ExternalSessionId: externalSessionID, Generation: 1, Sequence: 2, Event: &DelegatedControlRequest_Exit{Exit: &DelegatedExit{ExitStatus: -9, StatusKnown: true}}}
	authority.answer(nil, func(c Report) (*DelegatedControlReply, error) {
		return &DelegatedControlReply{ExternalSessionId: externalSessionID, Generation: 1, AcknowledgedSequence: c.Request.Sequence, Disposition: DelegatedDisposition_DELEGATED_WITHDRAWN, DecisionRevision: 2}, nil
	})
	ok, body = sendControl(t, client, exit)
	require.True(t, ok, "%q", body)
	var reply DelegatedControlReply
	require.NoError(t, proto.Unmarshal(body, &reply))
	require.True(t, proto.Equal(&DelegatedControlReply{ExternalSessionId: externalSessionID, Generation: 1, AcknowledgedSequence: 2, Disposition: DelegatedDisposition_DELEGATED_WITHDRAWN, DecisionRevision: 2}, &reply))
	ts.requireWithdrawn(t, host.id())
	_, controls = authority.seen()
	require.Len(t, controls, 2)
	require.True(t, proto.Equal(ready(1), controls[0].Request))
	require.True(t, proto.Equal(exit, controls[1].Request))
	require.Equal(t, host.id(), controls[1].Registration.RoutingID)
	require.Equal(t, client.SessionID(), controls[1].Registration.RegistrationID)

	for name, control := range map[string]func(Report) (*DelegatedControlReply, error){
		"a reply for another session": func(c Report) (*DelegatedControlReply, error) {
			return &DelegatedControlReply{ExternalSessionId: "44444444-4444-4444-8444-444444444444", Generation: 1, AcknowledgedSequence: c.Request.Sequence, Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, nil
		},
		"a reply for another generation": func(c Report) (*DelegatedControlReply, error) {
			return &DelegatedControlReply{ExternalSessionId: externalSessionID, Generation: 2, AcknowledgedSequence: c.Request.Sequence, Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, nil
		},
		"another sequence": func(c Report) (*DelegatedControlReply, error) {
			return &DelegatedControlReply{ExternalSessionId: externalSessionID, Generation: 1, AcknowledgedSequence: 9, Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, nil
		},
		"no disposition": func(c Report) (*DelegatedControlReply, error) {
			return &DelegatedControlReply{ExternalSessionId: externalSessionID, Generation: 1, AcknowledgedSequence: c.Request.Sequence, DecisionRevision: 1}, nil
		},
		"nothing": func(Report) (*DelegatedControlReply, error) { return nil, nil },
		"an error": func(Report) (*DelegatedControlReply, error) {
			return nil, errors.New("authority timed out")
		},
	} {
		t.Run(name, func(t *testing.T) {
			authority.answer(nil, control)
			ok, body := sendControl(t, client, ready(3))
			requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_UNAVAILABLE)
		})
	}

	t.Run("no authority", func(t *testing.T) {
		standalone := newServingTestServer(t, slog.New(slog.DiscardHandler))
		client := dialHost(t, standalone.sshAddr, ts.signer, nil)
		b, err := proto.Marshal(ready(1))
		require.NoError(t, err)
		ok, body, err := client.SendRequest(upterm.ServerDelegatedControlRequestType, true, b)
		require.NoError(t, err)
		require.False(t, ok)
		require.Empty(t, body, "a relay with no authority interpreted a report")
	})
}

// A decision reaches the connection that registered its session and
// generation, and only the host's own acknowledgment of it counts as one.
func TestPushDecision(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	host := newProven(t)
	rt := ts.runtime()

	var (
		mu       sync.Mutex
		answer   func(*DelegatedDecision) (bool, []byte)
		received []*DelegatedDecision
	)
	setAnswer := func(fn func(*DelegatedDecision) (bool, []byte)) {
		mu.Lock()
		defer mu.Unlock()
		answer = fn
	}
	acks := func(d *DelegatedDecision) (bool, []byte) {
		b, _ := proto.Marshal(&DelegatedDecisionAck{ExternalSessionId: d.ExternalSessionId, Generation: d.Generation, DecisionRevision: d.DecisionRevision})
		return true, b
	}
	setAnswer(acks)
	client := dialHost(t, ts.addr, ts.signer, func(r *ssh.Request) {
		var d DelegatedDecision
		if err := proto.Unmarshal(r.Payload, &d); err != nil {
			t.Error(err)
			_ = r.Reply(false, nil)
			return
		}
		mu.Lock()
		received = append(received, &d)
		fn := answer
		mu.Unlock()
		ok, body := fn(&d)
		if ok || body != nil {
			_ = r.Reply(ok, body)
		}
	})
	ok, body := sendCreate(t, client, host.delegatedRequest(t, client, 1, delegatedSession()))
	require.True(t, ok, "%q", body)
	ok, msg := forwardRequest(t, client, streamlocalForwardChannelType, host.id())
	require.True(t, ok, msg)

	// A current decision leaves the registration served.
	current := &DelegatedDecision{ExternalSessionId: externalSessionID, Generation: 1, Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}
	ack, err := rt.PushDecision(t.Context(), current)
	require.NoError(t, err)
	require.True(t, proto.Equal(&DelegatedDecisionAck{ExternalSessionId: externalSessionID, Generation: 1, DecisionRevision: 1}, ack))
	ts.requireServed(t, host.id())

	decision := &DelegatedDecision{ExternalSessionId: externalSessionID, Generation: 1, Disposition: DelegatedDisposition_DELEGATED_STOPPED, DecisionRevision: 2}
	ack, err = rt.PushDecision(t.Context(), decision)
	require.NoError(t, err)
	require.True(t, proto.Equal(&DelegatedDecisionAck{ExternalSessionId: externalSessionID, Generation: 1, DecisionRevision: 2}, ack))
	mu.Lock()
	require.Len(t, received, 2)
	require.True(t, proto.Equal(current, received[0]))
	require.True(t, proto.Equal(decision, received[1]))
	mu.Unlock()
	ts.requireWithdrawn(t, host.id())

	for name, tc := range map[string]struct {
		answer func(*DelegatedDecision) (bool, []byte)
		want   DelegatedErrorCode
	}{
		"refused": {func(*DelegatedDecision) (bool, []byte) {
			b, _ := proto.Marshal(&DelegatedError{Code: DelegatedErrorCode_DELEGATED_STALE_GENERATION})
			return false, b
		}, DelegatedErrorCode_DELEGATED_STALE_GENERATION},
		"refused in text": {func(*DelegatedDecision) (bool, []byte) { return false, []byte("no") }, DelegatedErrorCode_DELEGATED_UNSUPPORTED},
		"another revision": {func(d *DelegatedDecision) (bool, []byte) {
			b, _ := proto.Marshal(&DelegatedDecisionAck{ExternalSessionId: d.ExternalSessionId, Generation: d.Generation, DecisionRevision: 1})
			return true, b
		}, DelegatedErrorCode_DELEGATED_UNSUPPORTED},
		"no ack": {func(*DelegatedDecision) (bool, []byte) { return true, nil }, DelegatedErrorCode_DELEGATED_UNSUPPORTED},
		"an ack over the bound": {func(d *DelegatedDecision) (bool, []byte) {
			return true, padded(t, &DelegatedDecisionAck{ExternalSessionId: d.ExternalSessionId, Generation: d.Generation, DecisionRevision: d.DecisionRevision}, maxDelegatedPayload+1)
		}, DelegatedErrorCode_DELEGATED_UNSUPPORTED},
	} {
		t.Run(name, func(t *testing.T) {
			setAnswer(tc.answer)
			_, err := rt.PushDecision(t.Context(), decision)
			var refused *DelegatedRefusedError
			require.ErrorAs(t, err, &refused)
			require.Equal(t, tc.want, refused.Code)
		})
	}

	t.Run("an ack at the bound", func(t *testing.T) {
		setAnswer(func(d *DelegatedDecision) (bool, []byte) {
			return true, padded(t, &DelegatedDecisionAck{ExternalSessionId: d.ExternalSessionId, Generation: d.Generation, DecisionRevision: d.DecisionRevision}, maxDelegatedPayload)
		})
		ack, err := rt.PushDecision(t.Context(), decision)
		require.NoError(t, err)
		require.Equal(t, decision.DecisionRevision, ack.DecisionRevision)
	})

	t.Run("an unanswered push gives up", func(t *testing.T) {
		setAnswer(func(*DelegatedDecision) (bool, []byte) { return false, nil })
		ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		defer cancel()
		_, err := rt.PushDecision(ctx, decision)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})

	// The relay's own bound, with a caller that sets none.
	t.Run("an unanswered push gives up at the relay's bound", func(t *testing.T) {
		require.Equal(t, 10*time.Second, delegatedDecisionTimeout)
		setAnswer(func(*DelegatedDecision) (bool, []byte) { return false, nil })
		rt.mu.Lock()
		rt.decisionTimeout = 50 * time.Millisecond
		rt.mu.Unlock()
		defer func() {
			rt.mu.Lock()
			rt.decisionTimeout = 0
			rt.mu.Unlock()
		}()
		done := make(chan error, 1)
		go func() {
			_, err := rt.PushDecision(context.Background(), decision)
			done <- err
		}()
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.DeadlineExceeded)
		case <-time.After(5 * time.Second):
			t.Fatal("the push waited past the relay's bound")
		}
	})

	for name, d := range map[string]*DelegatedDecision{
		"another generation": {ExternalSessionId: externalSessionID, Generation: 2, Disposition: DelegatedDisposition_DELEGATED_STOPPED, DecisionRevision: 2},
		"another session":    {ExternalSessionId: "44444444-4444-4444-8444-444444444444", Generation: 1, Disposition: DelegatedDisposition_DELEGATED_STOPPED, DecisionRevision: 2},
	} {
		_, err := rt.PushDecision(t.Context(), d)
		require.ErrorIs(t, err, ErrDelegatedHostNotFound, name)
		require.EqualError(t, err, "no delegated host connection for that external session and generation")
	}
	for name, d := range map[string]*DelegatedDecision{
		"no disposition": {ExternalSessionId: externalSessionID, Generation: 1, DecisionRevision: 2},
		"no revision":    {ExternalSessionId: externalSessionID, Generation: 1, Disposition: DelegatedDisposition_DELEGATED_STOPPED},
		"no generation":  {ExternalSessionId: externalSessionID, Disposition: DelegatedDisposition_DELEGATED_STOPPED, DecisionRevision: 2},
		"nil":            nil,
	} {
		_, err := rt.PushDecision(t.Context(), d)
		require.EqualError(t, err, "a delegated decision needs an external session ID, a generation and a disposition with its revision", name)
		require.NotErrorIs(t, err, ErrDelegatedHostNotFound, name)
	}

	// Gone with its connection.
	require.NoError(t, client.Close())
	require.Eventually(t, func() bool {
		_, err := rt.PushDecision(t.Context(), decision)
		return errors.Is(err, ErrDelegatedHostNotFound)
	}, 5*time.Second, 10*time.Millisecond)
}

// The authority can tell, of each registration, whether its host is still
// connected and when the host last sent anything, from the traffic the relay
// already reads; once the host has gone it says so, and its last contact
// stays as it was.
func TestDelegatedHostContact(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	host := newProven(t)
	client := dialHost(t, ts.addr, ts.signer, nil)
	ok, body := sendCreate(t, client, host.delegatedRequest(t, client, 1, delegatedSession()))
	require.True(t, ok, "%q", body)
	registrations, _ := authority.seen()
	require.Len(t, registrations, 1)
	contact := registrations[0].Contact
	require.NotNil(t, contact)
	first := contact()
	require.True(t, first.Connected)
	require.False(t, first.LastContact.IsZero())

	time.Sleep(10 * time.Millisecond)
	ok, body = sendControl(t, client, ready(1))
	require.True(t, ok, "%q", body)
	moved := contact()
	require.True(t, moved.Connected)
	require.True(t, moved.LastContact.After(first.LastContact), "the host's traffic did not count as contact")

	require.NoError(t, client.Close())
	require.Eventually(t, func() bool { return !contact().Connected }, 5*time.Second, 10*time.Millisecond)
	gone := contact()
	require.False(t, gone.LastContact.Before(moved.LastContact))
	time.Sleep(20 * time.Millisecond)
	require.Equal(t, gone.LastContact, contact().LastContact, "a gone host's last contact moved")
}

// Without an enabled authority, a delegated registration is refused before
// any route is stored, and never registered as a local session instead.
func TestDelegatedRegistrationNeverDowngrades(t *testing.T) {
	for _, tc := range []struct {
		name      string
		authority bool
	}{{"no authority", false}, {"dark", true}} {
		t.Run(tc.name, func(t *testing.T) {
			authority := &fakeAuthority{}
			ts := newDelegatedTestServer(t, authority, func(s *Server) {
				s.Extensions.Enabled = false
				if !tc.authority {
					s.Extensions = Extensions{}
				}
			})
			host := newProven(t)
			client := dialHost(t, ts.addr, ts.signer, nil)
			ok, body := sendCreate(t, client, host.delegatedRequest(t, client, 1, delegatedSession()))
			if tc.authority {
				requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_UNAVAILABLE)
			} else {
				require.False(t, ok)
				require.Equal(t, "delegated registration is not supported by this relay", string(body))
			}
			sessions, err := ts.SessionManager.GetStore().List()
			require.NoError(t, err)
			require.Empty(t, sessions, "a refused delegated registration stored a route")
			ok, _ = forwardRequest(t, client, streamlocalForwardChannelType, host.id())
			require.False(t, ok, "a refused delegated registration opened a forward")
			if tc.authority {
				require.Zero(t, authority.calls(), "a dark authority was asked")
			}
		})
	}
}

// delegatedDefects are the requests a relay refuses as invalid before any
// authority could see them, each one well-formed request with one defect.
var delegatedDefects = map[string]func(*CreateSessionRequest){
	"a protocol the authority doesn't accept": func(r *CreateSessionRequest) { r.DelegatedSession.Protocol = "test_v2" },
	"an external ID that isn't a UUID": func(r *CreateSessionRequest) {
		r.DelegatedSession.ExternalSessionId = "3333333A-3333-4333-8333-333333333333"
	},
	"a disposition":         func(r *CreateSessionRequest) { r.DelegatedSession.Disposition = DelegatedDisposition_DELEGATED_CURRENT },
	"a revision":            func(r *CreateSessionRequest) { r.DelegatedSession.DecisionRevision = 1 },
	"no proof":              func(r *CreateSessionRequest) { r.HostKeyProof = nil },
	"a failed proof":        func(r *CreateSessionRequest) { r.Generation++ },
	"authorized keys":       func(r *CreateSessionRequest) { r.ClientAuthorizedKeys = [][]byte{[]byte(TestPublicKeyContent)} },
	"a payload over 64 KiB": func(r *CreateSessionRequest) { r.HostUser = strings.Repeat("x", maxDelegatedPayload) },
}

func TestMalformedDelegatedRequestsNeverReachTheAuthority(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "enabled", false: "dark"}[enabled], func(t *testing.T) {
			authority := &fakeAuthority{}
			ts := newDelegatedTestServer(t, authority, func(s *Server) { s.Extensions.Enabled = enabled })
			for name, defect := range delegatedDefects {
				t.Run(name, func(t *testing.T) {
					host := newProven(t)
					client := dialHost(t, ts.addr, ts.signer, nil)
					req := host.delegatedRequest(t, client, 1, delegatedSession())
					defect(req)
					ok, body := sendCreate(t, client, req)
					requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
					_, err := ts.SessionManager.GetSession(host.id())
					require.Error(t, err)
				})
			}
			require.Zero(t, authority.calls(), "the authority saw a malformed registration")
		})
	}
	t.Run("an empty protocol, even one listed", func(t *testing.T) {
		authority := &fakeAuthority{}
		ts := newDelegatedTestServer(t, authority, func(s *Server) { s.Extensions.Protocols = []string{""} })
		host := newProven(t)
		client := dialHost(t, ts.addr, ts.signer, nil)
		ok, body := sendCreate(t, client, host.delegatedRequest(t, client, 1, &DelegatedSession{ExternalSessionId: externalSessionID}))
		requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
		require.Zero(t, authority.calls())
	})
}

// padded is m's encoding with an unknown field appended, size bytes in all.
func padded(t *testing.T, m proto.Message, size int) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	require.NoError(t, err)
	for n := size - len(b); n >= 0; n-- {
		field := protowire.AppendBytes(protowire.AppendTag(nil, 15, protowire.BytesType), make([]byte, n))
		if len(b)+len(field) == size {
			return append(b, field...)
		}
	}
	t.Fatalf("no padding makes %d bytes", size)
	return nil
}

// sizedRequest is req with its host user grown until it encodes to size
// bytes.
func sizedRequest(t *testing.T, req *CreateSessionRequest, size int) *CreateSessionRequest {
	t.Helper()
	req = proto.Clone(req).(*CreateSessionRequest)
	req.HostUser = ""
	for n := size - proto.Size(req); n >= 0; n-- {
		req.HostUser = strings.Repeat("x", n)
		if proto.Size(req) == size {
			return req
		}
	}
	t.Fatalf("no host user makes %d bytes", size)
	return nil
}

// A delegated request or report is taken at exactly the bound, and refused as
// invalid one byte over it, before the authority could see it.
func TestDelegatedPayloadBound(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)

	over := newProven(t)
	client := dialHost(t, ts.addr, ts.signer, nil)
	ok, body := sendCreate(t, client, sizedRequest(t, over.delegatedRequest(t, client, 1, delegatedSession()), maxDelegatedPayload+1))
	requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
	require.Zero(t, authority.calls())

	at := newProven(t)
	client = dialHost(t, ts.addr, ts.signer, nil)
	ok, body = sendCreate(t, client, sizedRequest(t, at.delegatedRequest(t, client, 1, delegatedSession()), maxDelegatedPayload))
	require.True(t, ok, "%q", body)
	registrations, _ := authority.seen()
	require.Len(t, registrations, 1)

	ok, body, err := client.SendRequest(upterm.ServerDelegatedControlRequestType, true, padded(t, ready(1), maxDelegatedPayload+1))
	require.NoError(t, err)
	requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
	_, controls := authority.seen()
	require.Empty(t, controls, "the authority saw an oversized report")
	ok, body, err = client.SendRequest(upterm.ServerDelegatedControlRequestType, true, padded(t, ready(1), maxDelegatedPayload))
	require.NoError(t, err)
	require.True(t, ok, "%q", body)
	_, controls = authority.seen()
	require.Len(t, controls, 1)
}

// Every line of testdata/uuid-vectors.txt is a quoted string the UUID check
// accepts or refuses, as the line says.
func TestUUIDVectors(t *testing.T) {
	f, err := os.Open("testdata/uuid-vectors.txt")
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
		require.Equal(t, want, validUUID(value), "%q", line)
		seen[want]++
	}
	require.NoError(t, scanner.Err())
	require.NotZero(t, seen[true])
	require.NotZero(t, seen[false])
}

// A delegated registration's host must have come in by the public SSH
// listener; one a WebSocket listener bridged is refused before the authority
// sees it.
func TestDelegatedRegistrationOrigin(t *testing.T) {
	authority := &fakeAuthority{}
	ts := newDelegatedTestServer(t, authority)
	host := newProven(t)
	client := dialWSHost(t, ts.wsAddr, ts.signer)
	ok, body := sendCreate(t, client, host.delegatedRequest(t, client, 1, delegatedSession()))
	requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
	require.Zero(t, authority.calls(), "origin must be checked before the authority is asked")
}

// originHost sends the certificate an ingress proxy would mint for a host
// whose own connection has the SSH session ID original, entering by ingress.
func originHost(t *testing.T, srv *testSSHD, original string, ingress Ingress) *ssh.Client {
	t.Helper()
	return originHostWith(t, srv, original, func(a *AuthRequest) { a.Ingress = ingress })
}

// originHostWith is originHost, its certificate's AuthRequest changed by
// change: entering by the public SSH listener of srv, from a source of its
// own, unless change says otherwise.
func originHostWith(t *testing.T, srv *testSSHD, original string, change func(*AuthRequest)) *ssh.Client {
	t.Helper()
	auth := &AuthRequest{
		ClientVersion: upterm.HostSSHClientVersion, AuthorizedKey: ssh.MarshalAuthorizedKey(srv.signer.PublicKey()),
		RemoteAddr: "203.0.113.8:41234", Ingress: Ingress_INGRESS_SSH, IngressNode: srv.sshd.NodeAddr, IngressConnection: []byte(original),
	}
	change(auth)
	cert, err := (&UserCertSigner{SessionID: original, User: "host", AuthRequest: auth}).SignCert(srv.signer)
	require.NoError(t, err)
	c, ch, requests, err := ssh.NewClientConn(srv.rawConn(t), srv.addr, &ssh.ClientConfig{User: "host", Auth: []ssh.AuthMethod{ssh.PublicKeys(cert)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	require.NoError(t, err)
	client := ssh.NewClient(c, ch, requests)
	t.Cleanup(func() { _ = client.Close(); _ = client.Wait() })
	return client
}

// originRequest is p's delegated registration at generation, with a proof
// bound to original.
func originRequest(t *testing.T, p proven, original string, generation uint64) *CreateSessionRequest {
	t.Helper()
	proof, err := registration.Sign(p.key, []byte(original), p.secret, generation)
	require.NoError(t, err)
	return &CreateSessionRequest{HostUser: "host", HostPublicKeys: p.hostKeys(), SessionSecret: p.secret, Generation: generation, HostKeyProof: proof, DelegatedSession: delegatedSession()}
}

// delegatedSSHD is an sshd with authority composed and enabled.
func delegatedSSHD(t *testing.T, authority Authority, opts ...func(*sshd)) *testSSHD {
	t.Helper()
	return newTestSSHD(t, append([]func(*sshd){withAuthority(authority)}, opts...)...)
}

// withAuthority composes and enables authority on an sshd.
func withAuthority(authority Authority) func(*sshd) {
	return func(s *sshd) {
		s.Authority = authority
		s.AuthorityEnabled = true
		s.Protocols = []string{testProtocol}
		s.NodeID = "home-machine"
		s.BootID = fixtureBootID
		s.delegated = newDelegatedHosts(s.NodeID, s.BootID, s.NodeAddr)
	}
}

// slotOf is the slot srv's sshd holds for id, if any.
func slotOf(srv *testSSHD, id string) *localRegistration {
	srv.sshd.sessions.mu.Lock()
	defer srv.sshd.sessions.mu.Unlock()
	return srv.sshd.sessions.regs[id]
}

func TestDelegatedRefIsImmutable(t *testing.T) {
	var retained DelegatedRegistration
	authority := &fakeAuthority{register: func(r DelegatedRegistration) (RegistrationResult, error) {
		retained = r
		return RegistrationResult{AccountID: fixtureAccountID, Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, nil
	}}
	srv := delegatedSSHD(t, authority)
	p := newProven(t)
	host := originHost(t, srv, "host-original", Ingress_INGRESS_SSH)
	ok, body := sendCreate(t, host, originRequest(t, p, "host-original", 1))
	require.True(t, ok, "%q", body)
	home, exists := srv.sshd.Lookup(p.id())
	require.True(t, exists)
	want := RegistrationRef{Authority: AuthorityDelegated, AccountID: fixtureAccountID, SessionID: externalSessionID, Generation: 1, RoutingID: p.id(), RunPublicKeys: [][]byte{p.key.PublicKey().Marshal()}, RegistrationID: []byte("host-original"), HomeNode: srv.sshd.NodeAddr, HomeNodeID: "home-machine", HomeBootID: fixtureBootID}
	require.Equal(t, want, home.Ref())
	require.Equal(t, GuestOrigin{Ingress: Ingress_INGRESS_SSH, NodeAddr: srv.sshd.NodeAddr, SSHSessionID: []byte("host-original"), NodeID: "home-machine", Source: "203.0.113.8"}, retained.Origin)
	retained.RunPublicKey.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)[0] ^= 1
	retained.Session.ExternalSessionId = "changed"
	retained.RegistrationID[0] = 'x'
	retained.Origin.SSHSessionID[0] = 'x'
	ref := home.Ref()
	ref.RunPublicKeys[0][0] ^= 1
	ref.RegistrationID[0] = 'x'
	route, err := srv.sshd.SessionManager.GetSession(p.id())
	require.NoError(t, err)
	route.AuthorityHint = AuthorityLocal
	afterHint, found := srv.sshd.Lookup(p.id())
	require.True(t, found)
	require.Same(t, home, afterHint)
	require.Equal(t, AuthorityDelegated, afterHint.Ref().Authority)
	require.Equal(t, want, home.Ref(), "route hints and retained arguments cannot rewrite authority")
	// A successor has a new object; an old handle never starts describing it.
	next := originHost(t, srv, "new-host-original", Ingress_INGRESS_SSH)
	ok, body = sendCreate(t, next, originRequest(t, p, "new-host-original", 2))
	require.True(t, ok, "%q", body)
	fresh, exists := srv.sshd.Lookup(p.id())
	require.True(t, exists)
	require.True(t, home != fresh, "a redial must create a distinct home lifetime")
	require.Equal(t, want, home.Ref())
	require.True(t, homeRetired(home), "the replaced registration's home stayed held")
	registrations, _ := authority.seen()
	require.Len(t, registrations, 2, "a redial must obtain a fresh decision")
	require.Equal(t, uint64(2), fresh.Ref().Generation)
}

func TestDelegatedRefusals(t *testing.T) {
	origins := map[string]func(*AuthRequest){
		Ingress_INGRESS_UNSPECIFIED.String(): func(a *AuthRequest) { a.Ingress = Ingress_INGRESS_UNSPECIFIED },
		Ingress_INGRESS_WEBSOCKET.String():   func(a *AuthRequest) { a.Ingress = Ingress_INGRESS_WEBSOCKET },
		"another ingress node":               func(a *AuthRequest) { a.IngressNode = "another-node:2222" },
		"another ingress connection":         func(a *AuthRequest) { a.IngressConnection = []byte("another-connection") },
		"no source":                          func(a *AuthRequest) { a.RemoteAddr = "" },
	}
	for name, origin := range origins {
		t.Run(name, func(t *testing.T) {
			authority := &fakeAuthority{}
			srv := delegatedSSHD(t, authority)
			p := newProven(t)
			host := originHostWith(t, srv, "origin", origin)
			ok, body := sendCreate(t, host, originRequest(t, p, "origin", 1))
			requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
			_, exists := srv.sshd.Lookup(p.id())
			require.False(t, exists)
			_, err := srv.sshd.SessionManager.GetSession(p.id())
			require.Error(t, err)
			require.Zero(t, authority.calls())
		})
	}
	for _, result := range []string{"unreachable", "deny", "wrong_echo", "no_account", "invalid_account", "no_home_node", "no_home_boot"} {
		t.Run(result, func(t *testing.T) {
			authority := &fakeAuthority{register: func(DelegatedRegistration) (RegistrationResult, error) {
				switch result {
				case "unreachable", "wrong_echo":
					return RegistrationResult{}, errors.New(result)
				case "deny":
					return RegistrationResult{}, &DelegatedRefusedError{Code: DelegatedErrorCode_DELEGATED_INVALID_REQUEST}
				case "no_account":
					return RegistrationResult{Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, nil
				case "invalid_account":
					return RegistrationResult{AccountID: "bad", Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, nil
				}
				return RegistrationResult{AccountID: fixtureAccountID, Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, nil
			}}
			srv := delegatedSSHD(t, authority, func(s *sshd) {
				if result == "no_home_node" {
					s.NodeID = ""
				}
				if result == "no_home_boot" {
					s.BootID = ""
				}
			})
			p := newProven(t)
			host := originHost(t, srv, "origin", Ingress_INGRESS_SSH)
			ok, _ := sendCreate(t, host, originRequest(t, p, "origin", 1))
			require.False(t, ok)
			_, exists := srv.sshd.Lookup(p.id())
			require.False(t, exists)
			_, err := srv.sshd.SessionManager.GetSession(p.id())
			require.Error(t, err)
			ok, _ = forwardRequest(t, host, streamlocalForwardChannelType, p.id())
			require.False(t, ok)
		})
	}
}

func TestRetirementFencesBeforeRelease(t *testing.T) {
	store := newReleaseWitnessStore(1)
	store.SessionStore = newMemorySessionStore(slog.New(slog.DiscardHandler))
	t.Cleanup(store.releaseHolds)
	srv := delegatedSSHD(t, &fakeAuthority{}, func(s *sshd) {
		s.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	})
	p := newProven(t)
	host := originHost(t, srv, "original", Ingress_INGRESS_SSH)
	ok, body := sendCreate(t, host, originRequest(t, p, "original", 1))
	require.True(t, ok, "%q", body)
	home, exists := srv.sshd.Lookup(p.id())
	require.True(t, exists)
	reg := slotOf(srv, p.id()).reg
	ended := make(chan struct{})
	go func() { srv.sshd.sessions.end(reg); close(ended) }()
	store.call(t, 1)
	require.True(t, homeRetired(home), "Done must close before the blocked store release")
	_, exists = srv.sshd.Lookup(p.id())
	require.False(t, exists)
	ok, _ = forwardRequest(t, host, streamlocalForwardChannelType, p.id())
	require.False(t, ok, "no join after retirement")
	store.releaseHolds()
	require.True(t, ownershipJoin(t, ended, "delegated retirement"))
}

// publishStore holds the first Register it is asked until resume is closed,
// once it has closed arrived, and then fails it with failure, if set.
type publishStore struct {
	SessionStore
	arrived chan struct{}
	resume  chan struct{}
	first   atomic.Bool
	failure error
}

func (s *publishStore) Register(ctx context.Context, session *Session) (*Registration, error) {
	if s.first.CompareAndSwap(false, true) {
		close(s.arrived)
		<-s.resume
		if s.failure != nil {
			return nil, s.failure
		}
	}
	return s.SessionStore.Register(ctx, session)
}

func TestPublicationIsFenced(t *testing.T) {
	for _, ending := range []string{"success", "failure", "retirement", "takeover"} {
		t.Run(ending, func(t *testing.T) {
			store := &publishStore{SessionStore: newMemorySessionStore(slog.New(slog.DiscardHandler)), arrived: make(chan struct{}), resume: make(chan struct{})}
			var release sync.Once
			open := func() { release.Do(func() { close(store.resume) }) }
			if ending == "failure" {
				store.failure = errors.New("publication failed")
			}
			srv := delegatedSSHD(t, &fakeAuthority{}, func(s *sshd) {
				s.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
			})
			t.Cleanup(open)
			p := newProven(t)
			host := originHost(t, srv, "first-original", Ingress_INGRESS_SSH)
			done := createAsync(t, host, originRequest(t, p, "first-original", 1))
			require.True(t, ownershipJoin(t, store.arrived, "publication barrier"))
			local := slotOf(srv, p.id())
			require.NotNil(t, local, "the home's slot must exist before the route is published")
			require.True(t, local.reg.pending)
			require.Nil(t, local.stopLease, "a pending registration cannot renew or rebuild")
			home := local.home
			require.Equal(t, AuthorityDelegated, home.Ref().Authority)
			_, found := srv.sshd.Lookup(p.id())
			require.False(t, found, "an unpublished reservation is not joinable")
			require.False(t, srv.sshd.sessions.active(local.reg), "an unpublished reservation has no live forwarding target")
			_, err := srv.sshd.SessionManager.GetSession(p.id())
			require.Error(t, err)
			var successor Home
			switch ending {
			case "retirement":
				srv.sshd.sessions.discardPending(local.reg)
				require.False(t, home.Held())
			case "takeover":
				next := originHost(t, srv, "second-original", Ingress_INGRESS_SSH)
				ok, body := sendCreate(t, next, originRequest(t, p, "second-original", 2))
				require.True(t, ok, "%q", body)
				successor, found = srv.sshd.Lookup(p.id())
				require.True(t, found)
				require.False(t, home.Held())
			}
			open()
			result := awaitSignal(t, done, "publication")
			if ending == "success" {
				require.NoError(t, result.err)
				require.True(t, result.ok, "%q", result.body)
				current, ok := srv.sshd.Lookup(p.id())
				require.True(t, ok)
				require.Same(t, home, current)
				return
			}
			// The store's failure is unavailable, and a discarded reservation
			// stale. A takeover closes the replaced host's connection, so its
			// reply never arrives.
			switch ending {
			case "takeover":
				require.Error(t, result.err, "the replaced host was answered: ok=%v %q", result.ok, result.body)
			case "failure":
				require.NoError(t, result.err)
				requireDelegatedError(t, result.ok, result.body, DelegatedErrorCode_DELEGATED_UNAVAILABLE)
			default:
				require.NoError(t, result.err)
				requireDelegatedError(t, result.ok, result.body, DelegatedErrorCode_DELEGATED_STALE_GENERATION)
			}
			require.True(t, homeRetired(home), "a failed reservation did not fence Done")
			current, ok := srv.sshd.Lookup(p.id())
			if ending == "takeover" {
				require.True(t, ok)
				require.Same(t, successor, current)
				require.Equal(t, uint64(2), current.Ref().Generation)
				return
			}
			require.False(t, ok)
			_, err = srv.sshd.SessionManager.GetSession(p.id())
			require.Error(t, err, "a late publication must be released")
		})
	}
}

func TestRebuildKeepsHome(t *testing.T) {
	fake := newFakeConsul(t, monotonicIndexes)
	store := newFakeConsulStore(t, fake)
	srv := delegatedSSHD(t, &fakeAuthority{}, func(s *sshd) {
		s.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeConsul))
	})
	p := newProven(t)
	host := originHost(t, srv, "original", Ingress_INGRESS_SSH)
	ok, body := sendCreate(t, host, originRequest(t, p, "original", 1))
	require.True(t, ok, "%q", body)
	home, found := srv.sshd.Lookup(p.id())
	require.True(t, found)
	want := home.Ref()
	// Read through the serialized store representation, not the process's cache.
	pair := fake.entry()
	require.NotNil(t, pair)
	var persisted Session
	require.NoError(t, json.Unmarshal(pair.Value, &persisted))
	require.Equal(t, AuthorityDelegated, persisted.AuthorityHint)
	reg := slotOf(srv, p.id()).reg
	next, err := srv.sshd.SessionManager.Reregister(t.Context(), reg)
	require.NoError(t, err)
	require.True(t, srv.sshd.sessions.replace(next))
	current, found := srv.sshd.Lookup(p.id())
	require.True(t, found)
	require.Same(t, home, current)
	require.Equal(t, want, current.Ref())
}

// A local home stays local with an authority composed: delegated metadata the
// relay can't honour is refused, and the authority hears nothing of it.
func TestDelegatedMetadataOnALocalHome(t *testing.T) {
	authority := &fakeAuthority{}
	srv := delegatedSSHD(t, authority)
	p := newProven(t)
	host := originHost(t, srv, "local-original", Ingress_INGRESS_SSH)
	req := originRequest(t, p, "local-original", 1)
	req.DelegatedSession = nil
	ok, body := sendCreate(t, host, req)
	require.True(t, ok, "%q", body)
	home, found := srv.sshd.Lookup(p.id())
	require.True(t, found)
	want := RegistrationRef{Authority: AuthorityLocal, SessionID: p.id(), Generation: 1, RoutingID: p.id(), RunPublicKeys: [][]byte{p.key.PublicKey().Marshal()}, RegistrationID: []byte("local-original"), HomeNode: srv.sshd.NodeAddr, HomeNodeID: "home-machine", HomeBootID: fixtureBootID}
	require.Equal(t, want, home.Ref())
	for _, metadata := range []*DelegatedSession{{}, {Protocol: "future"}} {
		peer := originHost(t, srv, "malformed-original", Ingress_INGRESS_SSH)
		req := originRequest(t, newProven(t), "malformed-original", 1)
		req.DelegatedSession = metadata
		ok, body := sendCreate(t, peer, req)
		requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
	}
	require.Zero(t, authority.calls())
	current, found := srv.sshd.Lookup(p.id())
	require.True(t, found)
	require.Same(t, home, current)
	require.Equal(t, want, current.Ref())
}

func TestFinalRegistrationHasNoHome(t *testing.T) {
	for _, disposition := range []DelegatedDisposition{DelegatedDisposition_DELEGATED_STOPPED, DelegatedDisposition_DELEGATED_WITHDRAWN} {
		t.Run(disposition.String(), func(t *testing.T) {
			srv := delegatedSSHD(t, &fakeAuthority{register: decided(disposition, 4)})
			p := newProven(t)
			host := originHost(t, srv, "final-original", Ingress_INGRESS_SSH)
			ok, body := sendCreate(t, host, originRequest(t, p, "final-original", 1))
			require.True(t, ok, "%q", body)
			_, found := srv.sshd.Lookup(p.id())
			require.False(t, found)
			require.Nil(t, slotOf(srv, p.id()), "a final registration holds its ID")
			_, err := srv.sshd.SessionManager.GetSession(p.id())
			require.Error(t, err)
			ok, body = sendControl(t, host, ready(1))
			require.True(t, ok, "%q", body)
		})
	}
}

func TestConsulSerializationRebuild(t *testing.T) {
	if !testhelpers.IsConsulAvailable() {
		t.Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
	}
	location, err := suiteConsulURL("delegated")
	require.NoError(t, err)
	store, err := newConsulSessionStore(location, time.Minute, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	client := ownedConsulTestClient(t)
	t.Cleanup(func() {
		require.NoError(t, store.Close())
		require.NoError(t, removeSuiteConsulData(client, store))
	})
	srv := delegatedSSHD(t, &fakeAuthority{}, func(s *sshd) {
		s.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeConsul))
	})
	p := newProven(t)
	host := originHost(t, srv, "original", Ingress_INGRESS_SSH)
	ok, body := sendCreate(t, host, originRequest(t, p, "original", 1))
	require.True(t, ok, "%q", body)
	home, found := srv.sshd.Lookup(p.id())
	require.True(t, found)
	want := home.Ref()
	pair, _, err := store.client.KV().Get(store.SessionKey(p.id()), nil)
	require.NoError(t, err)
	require.NotNil(t, pair)
	var persisted Session
	require.NoError(t, json.Unmarshal(pair.Value, &persisted))
	require.Equal(t, AuthorityDelegated, persisted.AuthorityHint)
	reg := slotOf(srv, p.id()).reg
	next, err := srv.sshd.SessionManager.Reregister(t.Context(), reg)
	require.NoError(t, err)
	require.True(t, srv.sshd.sessions.replace(next))
	current, found := srv.sshd.Lookup(p.id())
	require.True(t, found)
	require.Same(t, home, current)
	require.Equal(t, want, current.Ref())
}

// However a delegated registration ends while its host is connected, its
// home is retired before its listener closes.
func TestHostRetirementPaths(t *testing.T) {
	for _, ending := range []string{"cancel", "disconnect", "stopped", "withdrawn"} {
		t.Run(ending, func(t *testing.T) {
			authority := &fakeAuthority{control: func(c Report) (*DelegatedControlReply, error) {
				disposition := DelegatedDisposition_DELEGATED_STOPPED
				if ending == "withdrawn" {
					disposition = DelegatedDisposition_DELEGATED_WITHDRAWN
				}
				return &DelegatedControlReply{ExternalSessionId: externalSessionID, Generation: 1, AcknowledgedSequence: c.Request.Sequence, Disposition: disposition, DecisionRevision: 2}, nil
			}}
			srv := delegatedSSHD(t, authority)
			p := newProven(t)
			host := originHost(t, srv, "original", Ingress_INGRESS_SSH)
			ok, body := sendCreate(t, host, originRequest(t, p, "original", 1))
			require.True(t, ok, "%q", body)
			home, found := srv.sshd.Lookup(p.id())
			require.True(t, found)
			ok, msg := forwardRequest(t, host, streamlocalForwardChannelType, p.id())
			require.True(t, ok, "%q", msg)
			handler := srv.sshd.forwardHandler
			fenced := make(chan bool, 1)
			handler.Lock()
			forward := handler.forwards[p.id()]
			forward.ln = &fenceProbeListener{Listener: forward.ln, closed: func() { fenced <- !home.Held() }}
			handler.forwards[p.id()] = forward
			handler.Unlock()
			switch ending {
			case "cancel":
				ok, msg = forwardRequest(t, host, cancelStreamlocalForwardChannelType, p.id())
				require.True(t, ok, "%q", msg)
			case "disconnect":
				require.NoError(t, host.Close())
			default:
				ok, body = sendControl(t, host, ready(1))
				require.True(t, ok, "%q", body)
			}
			require.True(t, awaitSignal(t, fenced, "the listener's close"), "the listener closed before the home was fenced")
			require.False(t, home.Held())
			_, found = srv.sshd.Lookup(p.id())
			require.False(t, found)
		})
	}
}

func TestReplicaCannotAuthorizeHome(t *testing.T) {
	srv := delegatedSSHD(t, &fakeAuthority{})
	originHost(t, srv, "original", Ingress_INGRESS_SSH)
	for _, hint := range []SessionAuthority{AuthorityLocal, AuthorityDelegated, ""} {
		reg, _, err := srv.sshd.SessionManager.Register(t.Context(), &Session{ID: "remote-" + string(hint), NodeAddr: "other:22", AuthorityHint: hint})
		require.NoError(t, err)
		_, found := srv.sshd.Lookup(reg.ID())
		require.False(t, found, "a route replica cannot create local authority")
		require.NoError(t, srv.sshd.SessionManager.Release(t.Context(), reg))
	}
}

// A relay with an authority composed makes no authority call for anything
// but a delegated registration.
func TestAuthorityFixedAtRegistration(t *testing.T) {
	authority := &fakeAuthority{}
	srv := newDelegatedTestServer(t, authority)
	p := newProven(t)
	host := dialHost(t, srv.addr, srv.signer, nil)
	ok, body := sendCreate(t, host, p.delegatedRequest(t, host, 1, nil))
	require.True(t, ok, "a local registration must take the local path even with an authority: %q", body)
	require.Zero(t, authority.calls(), "a local registration must make no authority calls")
}
