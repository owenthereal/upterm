package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/routing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// sessionRoute is a home fixture's routing ID when a guest is to type it: a
// relay session ID, 20 letters and digits.
const sessionRoute = "route000000000000000"

// delegatedGateHome is a home node's internal listener holding a delegated
// registration of sessionRoute, as newHopGateFixture holds a local one.
func delegatedGateHome(t *testing.T, options ...func(*sshProxy)) *hopGateFixture {
	t.Helper()
	f := newHopGateFixtureFor(t, sessionRoute, options...)
	f.delegatedHome(t)
	return f
}

// enabledIngress makes a proxy a public listener's, on a node with authority
// composed and enabled, that refuses legacy hops and hops to home's node.
func enabledIngress(authority Authority, home *hopGateFixture) func(*sshProxy) {
	return func(p *sshProxy) {
		p.authorities = &gateFixtureRegistry{}
		p.authority, p.AuthorityEnabled, p.AuthorityComposed = authority, true, true
		p.listener = listenerPublic
		p.RefuseLegacyHops = true
		p.NodeID = "ingress-machine"
		if home != nil {
			p.HopSigners = []ssh.Signer{home.authority}
		}
	}
}

// allowingHome allows every guest to home's registration.
func allowingHome(home *hopGateFixture) func(context.Context, *Guest, GuestRequest) (Admission, error) {
	return func(context.Context, *Guest, GuestRequest) (Admission, error) {
		return homeAllow(home, time.Now().Add(45*time.Second)), nil
	}
}

func homeAllow(home *hopGateFixture, until time.Time) Admission {
	ref := home.home.Ref()
	return Admission{Verdict: VerdictAllow, Sequence: 1, AllowUntil: until, Target: Target{Registration: ref, AccountID: ref.AccountID, SessionID: ref.SessionID, RoutingID: ref.RoutingID, RunPublicKey: home.signer.PublicKey(), Capabilities: []string{"shell"}}}
}

func TestDelegatedHomeCloseDuringHandshake(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	client, err := net.Dial("tcp4", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	raw, err := ln.Accept()
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()
	g := newGuestConn(context.Background(), raw)
	guest := &Guest{conn: g}
	guest.Close()
	require.NoError(t, client.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	_, err = client.Read(make([]byte, 1))
	if e, ok := err.(net.Error); err == nil || ok && e.Timeout() {
		t.Fatalf("ending an authenticating guest did not close its raw transport: %v", err)
	}
}

// A guest of a local session goes there without the authority, on every
// listener, whatever the authority would have said.
func TestDelegatedHomeLocalBypassesTheAuthority(t *testing.T) {
	for _, listener := range []listenerKind{listenerPublic, listenerBridge, listenerInternal} {
		t.Run(fmt.Sprint(listener), func(t *testing.T) {
			home := newHopGateFixtureFor(t, sessionRoute)
			authority := &fakeAuthority{}
			authority.admitWith(allowingHome(home))
			_, addr, _, signer := stockTestProxy(t, 4*time.Second, &stockTestDialer{addr: home.addr}, func(p *sshProxy) {
				enabledIngress(authority, home)(p)
				p.listener = listener
			})
			user := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode(sessionRoute, "home:2222")
			c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(home.guest)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: time.Second})
			require.NoError(t, err)
			defer func() { _ = c.Close() }()
			ok, _, err := c.SendRequest("application-probe", true, nil)
			require.NoError(t, err)
			require.True(t, ok)
			require.Zero(t, authority.calls(), "a local session's guest reached the authority")
		})
	}
}

// A delegated home serves the hop only once the ingress asserts the allow.
func TestDelegatedHomeRequiresAssertion(t *testing.T) {
	home := delegatedGateHome(t)
	authority := &fakeAuthority{}
	authority.admitWith(allowingHome(home))
	_, addr, _, signer := stockTestProxy(t, 4*time.Second, &stockTestDialer{addr: home.addr}, enabledIngress(authority, home))
	user := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode(sessionRoute, "home:2222")
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(home.guest)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: time.Second})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	ch, reqs, err := c.OpenChannel("session", nil)
	require.NoError(t, err)
	defer func() { _ = ch.Close() }()
	go ssh.DiscardRequests(reqs)
	require.EqualValues(t, 1, home.dialer.calls.Load(), "the home reached its host without the assertion")
	admissions, _ := authority.guests()
	require.Len(t, admissions, 1)
	require.NotNil(t, admissions[0].request.Home)
	require.Equal(t, home.home.Ref(), admissions[0].request.Home.Ref(), "the authority was asked about another home than the one reported")
}

func TestDelegatedHomeBindingIsTerminal(t *testing.T) {
	key := certTestSigner(t)
	ref := RegistrationRef{Authority: AuthorityDelegated, AccountID: fixtureAccountID, SessionID: externalSessionID, Generation: 1, RoutingID: sessionRoute, RunPublicKeys: [][]byte{key.PublicKey().Marshal()}, RegistrationID: []byte("original"), HomeNode: "home:2222", HomeNodeID: "home", HomeBootID: fixtureBootID}
	for _, fault := range []string{"nil", "retired", "changed", "ended", "rebind"} {
		t.Run(fault, func(t *testing.T) {
			g := newGuestConn(context.Background(), nil)
			defer g.cancel()
			home := newLocalHome(ref)
			switch fault {
			case "nil":
				require.False(t, g.bindHome(nil, ref), "nil home bound")
				return
			case "retired":
				home.retire()
			case "changed":
				ref := home.ref
				ref.RegistrationID = []byte("another")
				home = newLocalHome(ref)
			case "ended":
				g.cancel()
			case "rebind":
				require.True(t, g.bindHome(home, ref), "initial binding refused")
				home = newLocalHome(ref)
			}
			require.False(t, g.bindHome(home, ref), "a %s home was allowed to bind", fault)
		})
	}
}

// A delegated guest is admitted only on SSH ingress: on any other listener
// the authority is never asked.
func TestDelegatedHomeUnknownOrigin(t *testing.T) {
	for _, listener := range []listenerKind{listenerShared, listenerBridge, listenerInternal} {
		t.Run(fmt.Sprint(listener), func(t *testing.T) {
			authority := &fakeAuthority{}
			authority.admitWith(showing("unexpected authority call\n"))
			_, addr, _, signer := stockTestProxy(t, 2*time.Second, &stockTestDialer{}, func(p *sshProxy) {
				enabledIngress(authority, nil)(p)
				p.listener = listener
			})
			client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: claimPrefix + "work", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey())})
			if err == nil {
				_ = client.Close()
				t.Fatal("unknown origin admitted")
			}
			admissions, _ := authority.guests()
			require.Empty(t, admissions, "an unknown origin reached the authority")
		})
	}
}

// With a dark authority and legacy hops accepted, a session ID's guest hops
// to a node from before the gate as today, and the authority is never asked.
func TestDelegatedHomeLegacyDark(t *testing.T) {
	upstream, _ := stockTestUpstream(t, false, TestPrivateKeyContent)
	authority := &fakeAuthority{}
	_, addr, _, key := stockTestProxy(t, 2*time.Second, &stockTestDialer{addr: upstream}, func(p *sshProxy) {
		p.authority, p.AuthorityComposed = authority, true
		p.authorities = &gateFixtureRegistry{}
		p.listener = listenerPublic
		p.NodeID = "ingress"
		p.SessionManager = newSessionManagerWithStore(newMemorySessionStore(p.Logger), routing.NewEncodeDecoder(routing.ModeConsul))
		_, err := p.SessionManager.CreateSession(&Session{ID: sessionRoute, NodeAddr: "legacy:2222", HostPublicKeys: []ssh.PublicKey{p.HostSigners[0].PublicKey()}})
		require.NoError(t, err)
	})
	guest, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: sessionRoute, Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.FixedHostKey(key.PublicKey())})
	require.NoError(t, err)
	defer func() { _ = guest.Close() }()
	require.Zero(t, authority.calls())
}

// A session ID's guest whose route moved is routed again on the fresh one,
// and still never reaches the authority for a local home.
func TestDelegatedHomeRouteRetry(t *testing.T) {
	home := newHopGateFixtureFor(t, sessionRoute)
	authority := &fakeAuthority{}
	store := &staleStore{memorySessionStore: newMemorySessionStore(home.proxy.Logger)}
	fresh := &Session{ID: sessionRoute, NodeAddr: "home:2222", Generation: 7, HostPublicKeys: []ssh.PublicKey{home.signer.PublicKey()}}
	_, err := store.Register(context.Background(), fresh)
	require.NoError(t, err)
	store.stale = &Session{ID: sessionRoute, NodeAddr: "old:2222", Generation: 6, HostPublicKeys: fresh.HostPublicKeys}
	dialer := &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){"old:2222": func(context.Context) (net.Conn, error) { return nil, errors.New("old route gone") }, "home:2222": dialTo(home.addr)}}
	_, addr, _, key := stockTestProxy(t, 4*time.Second, dialer, func(p *sshProxy) {
		enabledIngress(authority, home)(p)
		p.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeConsul))
	})
	guest, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: sessionRoute, Auth: []ssh.AuthMethod{ssh.PublicKeys(home.guest)}, HostKeyCallback: ssh.FixedHostKey(key.PublicKey())})
	require.NoError(t, err)
	defer func() { _ = guest.Close() }()
	ok, _, err := guest.SendRequest("application-probe", true, nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 2, dialer.calls.Load())
	require.Zero(t, authority.calls())
}

func TestDelegatedHomeCloseCancelsForwarding(t *testing.T) {
	g := newGuestConn(context.Background(), nil)
	g.authenticated = true
	defer g.cancel()
	(&Guest{conn: g}).Close()
	select {
	case <-g.ctx.Done():
	default:
		t.Fatal("closing the guest did not cancel its forwarding")
	}
}

// An allow that has expired, a guest closed as it is decided, and a home
// retired as it is decided each refuse the guest before its home reaches its
// host.
func TestDelegatedHomeRefusesExpiredOrRetiredAllow(t *testing.T) {
	for _, state := range []string{"expired", "ended", "retired"} {
		t.Run(state, func(t *testing.T) {
			home := delegatedGateHome(t)
			authority := &fakeAuthority{}
			authority.admitWith(func(ctx context.Context, g *Guest, _ GuestRequest) (Admission, error) {
				until := time.Now().Add(45 * time.Second)
				switch state {
				case "expired":
					until = time.Now().Add(-time.Second)
				case "ended":
					g.Close()
				case "retired":
					home.home.retire()
				}
				return homeAllow(home, until), nil
			})
			_, addr, _, signer := stockTestProxy(t, 4*time.Second, &stockTestDialer{addr: home.addr}, enabledIngress(authority, home))
			user := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode(sessionRoute, "home:2222")
			guest, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(home.guest)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: time.Second})
			if err == nil {
				_ = guest.Close()
				t.Fatal("a stale allow opened ingress traffic")
			}
			require.Zero(t, home.dialer.calls.Load(), "the home reached its host before a current allow and its assertion")
		})
	}
}

// localCompositions are the ways a relay can be composed when a guest joins
// one of its local sessions: with nothing, with an authority dark, and with
// one enabled.
var localCompositions = []string{"none", "dark", "enabled"}

// localIngress is a public listener on the node that holds home's local
// registration, composed as composition names, whose handshake timeout is
// handshake and which reaches the registration's host with dialer. It returns
// the listener's address, its metrics, its host key, and the authority it
// composes, which would allow every guest.
func localIngress(t *testing.T, home *hopGateFixture, composition string, handshake time.Duration, dialer connDialer) (string, *prometheus.Registry, ssh.Signer, *fakeAuthority) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return localIngressOn(t, ln, home, composition, handshake, dialer)
}

// localIngressOn is localIngress serving ln.
func localIngressOn(t *testing.T, ln net.Listener, home *hopGateFixture, composition string, handshake time.Duration, dialer connDialer) (string, *prometheus.Registry, ssh.Signer, *fakeAuthority) {
	t.Helper()
	authority := &fakeAuthority{}
	authority.admitWith(allowingHome(home))
	ref := home.home.Ref()
	_, addr, reg, signer := stockTestProxyOn(t, ln, handshake, dialer, func(p *sshProxy) {
		p.NodeAddr, p.NodeID = ref.HomeNode, ref.HomeNodeID
		p.authorities = home.registry
		p.SessionManager = home.proxy.SessionManager
		p.listener = listenerPublic
		switch composition {
		case "dark":
			p.authority, p.AuthorityComposed = authority, true
		case "enabled":
			p.authority, p.AuthorityComposed, p.AuthorityEnabled, p.RefuseLegacyHops = authority, true, true, true
		}
	})
	return addr, reg, signer, authority
}

// joinLocal joins home's local registration at addr as its guest, and
// returns nil once the guest has reached the registration's host.
func joinLocal(t *testing.T, home *hopGateFixture, addr string, hostKey ssh.PublicKey) error {
	t.Helper()
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: home.route, Auth: []ssh.AuthMethod{ssh.PublicKeys(home.guest)}, HostKeyCallback: ssh.FixedHostKey(hostKey), Timeout: 5 * time.Second})
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	ok, _, err := c.SendRequest("application-probe", true, nil)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("the guest's request never reached the host")
	}
	return nil
}

// slowHost dials a host at addr that takes takes to answer. It stands in for
// the wait rather than sleeping it: an attempt whose context ends sooner
// fails at once, as it would have once its context ended, and any other
// reaches the host at once.
type slowHost struct {
	addr  string
	takes time.Duration
}

func (d *slowHost) Dial(id *api.Identifier) (net.Conn, error) {
	return d.DialContext(context.Background(), id)
}

func (d *slowHost) DialContext(ctx context.Context, _ *api.Identifier) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < d.takes {
		return nil, context.DeadlineExceeded
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.addr)
}

// A local session's host is reached on the same budget whatever the relay
// composes: half the handshake timeout, as the stock path gives it, and not
// the authority's, which bounds only what the authority decides. So a host
// slower than the authority's budget but within that one takes its guest,
// and one slower than that refuses it, with nothing composed, with an
// authority dark, and with one enabled.
func TestLocalHostBudgetWhateverIsComposed(t *testing.T) {
	const handshake = 40 * time.Second
	for _, tc := range []struct {
		takes time.Duration
		joins bool
	}{{admitTimeout + time.Second, true}, {handshake/2 + time.Second, false}} {
		for _, composition := range localCompositions {
			t.Run(fmt.Sprintf("%v/%s", tc.takes, composition), func(t *testing.T) {
				home := newHopGateFixtureFor(t, sessionRoute)
				addr, _, signer, authority := localIngress(t, home, composition, handshake, &slowHost{addr: home.dialer.addr, takes: tc.takes})
				err := joinLocal(t, home, addr, signer.PublicKey())
				if tc.joins {
					require.NoError(t, err, "a host %v slow to answer lost its guest", tc.takes)
				} else {
					require.Error(t, err, "a host %v slow to answer took its guest", tc.takes)
				}
				require.Zero(t, authority.calls(), "a local session's guest reached the authority")
			})
		}
	}
}

// A local session's guest is counted once as an authenticated client
// whatever the relay composes, as it is with nothing composed.
func TestLocalGuestCountedWhateverIsComposed(t *testing.T) {
	counted := map[string]float64{}
	for _, composition := range localCompositions {
		home := newHopGateFixtureFor(t, sessionRoute)
		addr, reg, signer, _ := localIngress(t, home, composition, 4*time.Second, &stockTestDialer{addr: home.dialer.addr})
		require.NoError(t, joinLocal(t, home, addr, signer.PublicKey()), "with %s composed", composition)
		value, ok := gatherValue(t, reg, "test_server_routing_authenticated_connections_count", map[string]string{"kind": "client"})
		require.True(t, ok)
		counted[composition] = value
	}
	require.Equal(t, map[string]float64{"none": 1, "dark": 1, "enabled": 1}, counted)
}

// remoteIngress is a public listener on another node than home's, composed
// as composition names, which reads sessions with sm and reaches other nodes
// with dialer. It returns the listener's address, its host key, and the
// authority it composes, which would allow every guest.
func remoteIngress(t *testing.T, home *hopGateFixture, composition string, handshake time.Duration, dialer connDialer, sm *SessionManager) (string, ssh.Signer, *fakeAuthority) {
	t.Helper()
	authority := &fakeAuthority{}
	authority.admitWith(allowingHome(home))
	_, addr, _, signer := stockTestProxy(t, handshake, dialer, func(p *sshProxy) {
		p.NodeAddr, p.NodeID = "ingress:2222", "ingress-machine"
		p.authorities = &gateFixtureRegistry{}
		p.SessionManager = sm
		p.listener = listenerPublic
		p.HopSigners = []ssh.Signer{home.authority}
		switch composition {
		case "dark":
			p.authority, p.AuthorityComposed = authority, true
		case "enabled":
			p.authority, p.AuthorityComposed, p.AuthorityEnabled, p.RefuseLegacyHops = authority, true, true, true
		}
	})
	return addr, signer, authority
}

// legacyHome is a home node holding a local registration of sessionRoute that
// takes legacy hops as well as gate hops, as a node with nothing composed
// does.
func legacyHome(t *testing.T) *hopGateFixture {
	t.Helper()
	return newHopGateFixtureFor(t, sessionRoute, func(p *sshProxy) { p.RefuseLegacyHops = false })
}

// A hop to a local session on another node is made on the stock path's
// budget whatever the relay composes: its first attempt within half of half
// the handshake timeout, as the route can be refreshed, and not within the
// authority's budget. So a hop slower than the authority's budget but within
// that one takes the guest, and one slower than that refuses it.
func TestRemoteLocalHopBudgetWhateverIsComposed(t *testing.T) {
	const handshake = 40 * time.Second
	for _, tc := range []struct {
		takes time.Duration
		joins bool
	}{{admitTimeout + time.Second, true}, {handshake/4 + time.Second, false}} {
		for _, composition := range localCompositions {
			t.Run(fmt.Sprintf("%v/%s", tc.takes, composition), func(t *testing.T) {
				home := legacyHome(t)
				addr, signer, authority := remoteIngress(t, home, composition, handshake, &slowHost{addr: home.addr, takes: tc.takes}, home.proxy.SessionManager)
				err := joinLocal(t, home, addr, signer.PublicKey())
				if tc.joins {
					require.NoError(t, err, "a hop %v slow to answer lost its guest", tc.takes)
				} else {
					require.Error(t, err, "a hop %v slow to answer took its guest", tc.takes)
				}
				require.Zero(t, authority.calls(), "a local session's guest reached the authority")
			})
		}
	}
}

// A guest routed from a stale cache, which still places a local session on
// this node after its host redialled to another one, is retried once on the
// refreshed route, and joins there whatever the relay composes, even while
// the cache still trails the move.
func TestStaleLocalRouteRetriedWhateverIsComposed(t *testing.T) {
	for _, composition := range localCompositions {
		t.Run(composition, func(t *testing.T) {
			home := legacyHome(t)
			store := &staleStore{memorySessionStore: newMemorySessionStore(home.proxy.Logger)}
			fresh := &Session{ID: sessionRoute, NodeAddr: "home:2222", Generation: 7, HostPublicKeys: []ssh.PublicKey{home.signer.PublicKey()}, ClientAuthorizedKeys: []ssh.PublicKey{home.guest.PublicKey()}}
			_, err := store.Register(context.Background(), fresh)
			require.NoError(t, err)
			stale := &Session{ID: sessionRoute, NodeAddr: "ingress:2222", Generation: 6, HostPublicKeys: fresh.HostPublicKeys, ClientAuthorizedKeys: fresh.ClientAuthorizedKeys}
			store.stale = stale
			// The watch still trails the move once the store has been read.
			store.afterFresh = func(s *staleStore) { s.stale = stale }
			dialer := &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){
				"ingress:2222": func(context.Context) (net.Conn, error) { return nil, errors.New("the host left this node") },
				"home:2222":    dialTo(home.addr),
			}}
			addr, signer, authority := remoteIngress(t, home, composition, 4*time.Second, dialer, newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeConsul)))
			require.NoError(t, joinLocal(t, home, addr, signer.PublicKey()), "a guest of a session that moved wasn't retried on its new route")
			require.Zero(t, authority.calls(), "a local session's guest reached the authority")
		})
	}
}

// deadlineListener records every deadline set on the last connection it
// accepted.
type deadlineListener struct {
	net.Listener
	mu        sync.Mutex
	deadlines []time.Time
}

func (l *deadlineListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.deadlines = nil
	l.mu.Unlock()
	return &deadlineConn{Conn: c, owner: l}, nil
}

// set is every deadline set so far on the last connection accepted.
func (l *deadlineListener) set() []time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Time(nil), l.deadlines...)
}

type deadlineConn struct {
	net.Conn
	owner *deadlineListener
}

func (c *deadlineConn) SetDeadline(t time.Time) error {
	c.owner.mu.Lock()
	c.owner.deadlines = append(c.owner.deadlines, t)
	c.owner.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

// heldDialer dials a host at addr, unless fail is set, once it has reported
// the deadline of the attempt's context and the guest transport's deadline
// at that moment, as set on ln.
type heldDialer struct {
	addr string
	ln   *deadlineListener
	fail bool
	seen chan [2]time.Time
}

func (d *heldDialer) Dial(id *api.Identifier) (net.Conn, error) {
	return d.DialContext(context.Background(), id)
}

func (d *heldDialer) DialContext(ctx context.Context, _ *api.Identifier) (net.Conn, error) {
	attempt, _ := ctx.Deadline()
	var transport time.Time
	if set := d.ln.set(); len(set) > 0 {
		transport = set[len(set)-1]
	}
	d.seen <- [2]time.Time{attempt, transport}
	if d.fail {
		return nil, errors.New("the host is gone")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.addr)
}

// With an authority composed, the guest's handshake waits while its session's
// host is reached, which can outlast the handshake's own budget; so the
// guest's transport is given as long as the attempt, and once the guest is
// refused, no longer than the handshake's budget.
func TestGuestTransportWaitsForItsHost(t *testing.T) {
	for _, composition := range []string{"dark", "enabled"} {
		for _, refused := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/refused=%v", composition, refused), func(t *testing.T) {
				home := newHopGateFixtureFor(t, sessionRoute)
				raw, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				ln := &deadlineListener{Listener: raw}
				dialer := &heldDialer{addr: home.dialer.addr, ln: ln, fail: refused, seen: make(chan [2]time.Time, 1)}
				addr, _, signer, _ := localIngressOn(t, ln, home, composition, 40*time.Second, dialer)
				err = joinLocal(t, home, addr, signer.PublicKey())
				seen := <-dialer.seen
				attempt, transport := seen[0], seen[1]
				handshake := ln.set()[0]
				require.True(t, attempt.After(handshake), "the attempt was given no more than the handshake's budget")
				require.True(t, transport.Equal(attempt), "the guest's transport was given %v less than the attempt on its host", attempt.Sub(transport))
				if !refused {
					require.NoError(t, err)
					// Kept until the handshake is done, and then cleared.
					set := ln.set()
					require.Len(t, set, 3, "the deadlines set on an admitted guest's transport")
					require.True(t, set[1].Equal(attempt), "an admitted guest's transport was cut back before its handshake was done")
					require.True(t, set[2].IsZero(), "an admitted guest's transport kept a deadline")
					return
				}
				require.Error(t, err)
				set := ln.set()
				require.True(t, set[len(set)-1].Equal(handshake), "a refused guest's transport kept %v more than the handshake's budget", set[len(set)-1].Sub(handshake))
			})
		}
	}
}

// A local session's host that answers with a key other than the one its
// session registered is not retried on a refreshed route, whatever the relay
// composes: a host failing to prove who it is is not a stale route.
func TestHostKeyMismatchNotRetriedWhateverIsComposed(t *testing.T) {
	for _, composition := range localCompositions {
		t.Run(composition, func(t *testing.T) {
			home := newHopGateFixtureFor(t, sessionRoute)
			wrong, _ := stockTestUpstream(t, false, HostPrivateKeyContent)
			store := &staleStore{memorySessionStore: newMemorySessionStore(home.proxy.Logger)}
			fresh := &Session{ID: sessionRoute, NodeAddr: "other:2222", Generation: 8, HostPublicKeys: []ssh.PublicKey{home.signer.PublicKey()}, ClientAuthorizedKeys: []ssh.PublicKey{home.guest.PublicKey()}}
			_, err := store.Register(context.Background(), fresh)
			require.NoError(t, err)
			store.stale = &Session{ID: sessionRoute, NodeAddr: "home:2222", Generation: 7, HostPublicKeys: fresh.HostPublicKeys, ClientAuthorizedKeys: fresh.ClientAuthorizedKeys}
			dialer := &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){"home:2222": dialTo(wrong), "other:2222": dialTo(home.addr)}}
			authority := &fakeAuthority{}
			ref := home.home.Ref()
			_, addr, _, signer := stockTestProxy(t, 4*time.Second, dialer, func(p *sshProxy) {
				p.NodeAddr, p.NodeID = ref.HomeNode, ref.HomeNodeID
				p.authorities = home.registry
				p.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeConsul))
				p.listener = listenerPublic
				p.HopSigners = []ssh.Signer{home.authority}
				switch composition {
				case "dark":
					p.authority, p.AuthorityComposed = authority, true
				case "enabled":
					p.authority, p.AuthorityComposed, p.AuthorityEnabled, p.RefuseLegacyHops = authority, true, true, true
				}
			})
			require.Error(t, joinLocal(t, home, addr, signer.PublicKey()), "a host with the wrong key took a guest")
			require.EqualValues(t, 1, dialer.calls.Load(), "a host-key mismatch was retried on a refreshed route")
			require.Zero(t, authority.calls(), "a local session's guest reached the authority")
		})
	}
}

// For a session ID, Admit's context ends no later than its guest's
// transport, which was given the time its home was reached in: half the
// handshake timeout from when the guest signed, not from when it came in.
func TestAdmitKeepsTheTransportBudgetForASessionID(t *testing.T) {
	home := delegatedGateHome(t)
	deadlines := make(chan time.Time, 1)
	authority := &fakeAuthority{}
	authority.admitWith(func(ctx context.Context, _ *Guest, _ GuestRequest) (Admission, error) {
		deadline, _ := ctx.Deadline()
		deadlines <- deadline
		return Admission{}, nil
	})
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln := &deadlineListener{Listener: raw}
	// Half of 6 s is less than the authority's 5 s, so the transport bounds Admit.
	_, addr, _, signer := stockTestProxyOn(t, ln, 6*time.Second, &stockTestDialer{addr: home.addr}, enabledIngress(authority, home))
	user := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode(sessionRoute, "home:2222")
	_, err = ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(home.guest)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 5 * time.Second})
	require.Error(t, err, "a guest Admit refused was let in")
	admit := <-deadlines
	set := ln.set()
	require.GreaterOrEqual(t, len(set), 2, "the guest's transport wasn't given the time its home was reached in")
	handshake, transport := set[0], set[1]
	require.True(t, transport.After(handshake))
	require.True(t, admit.Equal(transport), "Admit's context ends %v after the guest's transport", admit.Sub(transport))
}
