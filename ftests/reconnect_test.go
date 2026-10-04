package ftests

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// redialTiming paces the redialling hosts here.
//
// Pings at 500 ms are long enough that the ftests running in parallel, under
// -race, don't stall a healthy tunnel into a redial, and short enough that a
// silent one is given up on within a second. The fast waits are capped at
// 200 ms, so a gap held open for a while doesn't grow the next wait past a
// scenario's budget. An attempt gets 2 s, an SSH handshake's budget under
// -race. SlowJitter is set too: left at its default, a slow wait could last
// half a minute.
var redialTiming = host.ReconnectTiming{
	PingInterval:    500 * time.Millisecond,
	PingBound:       500 * time.Millisecond,
	AttemptDeadline: 2 * time.Second,
	FastBase:        50 * time.Millisecond,
	FastCap:         200 * time.Millisecond,
	SlowWait:        time.Second,
	SlowJitter:      100 * time.Millisecond,
}

const (
	// redialTimeout bounds each step a scenario waits on: a status change, a
	// redial, a relay letting a registration go. Each is an SSH handshake or
	// a store call at most, under -race.
	redialTimeout = 5 * time.Second
	// redialPoll is how often those waits look.
	redialPoll = 10 * time.Millisecond
	// deployBudget is how soon a host whose node shuts down is ready on
	// another: at most one first wait of the fast schedule's, 1 s, and one
	// handshake, which under -race gets the rest.
	deployBudget = 2500 * time.Millisecond
	// reachTimeout bounds a guest's command reaching the host's shell and its
	// output coming back, through the relay.
	reachTimeout = 5 * time.Second
	// relayShutdownTimeout bounds a relay's Shutdown: its wait for serving to
	// stop and its session cleanup are bounded at 8 s and 3 s.
	relayShutdownTimeout = 15 * time.Second
)

// TestReconnect runs each scenario of a host that redials its relay, over
// ssh:// and ws://, one at a time, on relays of its own: the scenarios cut,
// silence, restart and shut down relays, and the suite's ts1 and ts2 are
// shared by tests running in parallel. A scenario that only one routing mode
// can show runs in that mode's suite alone.
func (suite *FtestSuite) TestReconnect() {
	scenarios := []struct {
		name string
		// only, when set, is the one routing mode the scenario runs in.
		only routing.Mode
		run  func(t *testing.T, mode routing.Mode, protocol string)
	}{
		{"TunnelCutOnTheSameNode", "", testRedialAfterACut},
		// A store in memory dies with its relay, so a restart starts empty;
		// Consul outlives it.
		{"RelayRestartedWithAnEmptyStore", routing.ModeEmbedded, testRedialAfterARelayRestart},
		// Only a shared store lets a guest on one node reach a host on another.
		{"MovedToAnotherNodeAfterACut", routing.ModeConsul, redialToAnotherNode((*testhelpers.Forwarder).Cut)},
		{"MovedToAnotherNodeAfterABlackhole", routing.ModeConsul, redialToAnotherNode((*testhelpers.Forwarder).Blackhole)},
		{"NodeShutDownForADeploy", "", testRedialWhenANodeShutsDown},
		{"TunnelBlackholed", "", testRedialAfterABlackhole},
	}
	for _, sc := range scenarios {
		if sc.only != "" && sc.only != suite.mode {
			continue
		}
		for _, protocol := range []string{"ssh", "ws"} {
			suite.T().Run(sc.name+"/"+protocol, func(t *testing.T) {
				sc.run(t, suite.mode, protocol)
			})
		}
	}
}

// A tunnel cut on the same node comes back under the same ID: the status goes
// ready, reconnecting, ready, and a guest joins with the command it was first
// given. While the host is away, a guest who joins is told, once, that no host
// is connected.
func testRedialAfterACut(t *testing.T, mode routing.Mode, protocol string) {
	relay := newRedialRelay(t, mode)
	h := shareRedialling(t, protocol, relay, redialTiming)
	id := h.first.SessionId
	first := h.awaitRegistered(t, relay)

	h.fwd.Redirect(closedAddr(t)) // hold the gap open
	h.fwd.Cut()
	h.awaitStatus(t, sessiondir.StatusReconnecting)

	// The relay lets the registration go once it sees the connection end,
	// and only then is there no session for a guest to find.
	require.Eventually(t, func() bool { return relay.registered(id) == nil }, redialTimeout, redialPoll,
		"the relay kept the registration of a host whose tunnel was cut")
	requireNoHostBanner(t, h.first, relay.joinURL(protocol))

	h.fwd.Redirect(relay.addr(protocol))
	h.awaitStatus(t, sessiondir.StatusReady)
	again := h.awaitRegistered(t, relay)
	require.Greater(t, again.Generation, first.Generation, "registered again, under a later generation")
	joinAndReachHost(t, h.first, relay.joinURL(protocol))
}

// A relay restarted where it was, with the same key and nothing in its store,
// takes the session back under the same ID, and a guest joins with the
// command it was first given.
func testRedialAfterARelayRestart(t *testing.T, mode routing.Mode, protocol string) {
	relay := newRedialRelay(t, mode)
	h := shareRedialling(t, protocol, relay, redialTiming)
	first := h.awaitRegistered(t, relay)

	sshAddr, wsAddr := relay.SSHAddr(), relay.WSAddr()
	require.NoError(t, relay.Shutdown())
	// Nothing listens until the restart, so the gap holds.
	h.awaitStatus(t, sessiondir.StatusReconnecting)

	restarted := newRedialRelay(t, mode, listenOn(sshAddr, wsAddr))
	h.awaitStatus(t, sessiondir.StatusReady)
	again := h.awaitRegistered(t, restarted)
	require.Greater(t, again.Generation, first.Generation, "registered again, under a later generation")
	joinAndReachHost(t, h.first, restarted.joinURL(protocol))
}

// redialToAnotherNode is testRedialToAnotherNode with the tunnel to node 1
// dropped by drop.
func redialToAnotherNode(drop func(*testhelpers.Forwarder)) func(t *testing.T, mode routing.Mode, protocol string) {
	return func(t *testing.T, mode routing.Mode, protocol string) {
		testRedialToAnotherNode(t, mode, protocol, drop)
	}
}

// A host whose tunnel to node 1 is dropped, and whose redial lands on node 2,
// is reached through either node with the command it was first given. Node 1's
// cleanup of its own registration, its delete and its lease, leaves node 2's
// entry, at the later generation, in place.
//
// After a cut, node 1 sees the connection end at once and usually cleans up
// before the redial lands, so its cleanup meets its own entry. After a
// blackhole, node 1 sees nothing end: it learns from its watch that node 2's
// registration has taken the entry over, and its cleanup then runs against
// node 2's entry.
func testRedialToAnotherNode(t *testing.T, mode routing.Mode, protocol string, drop func(*testhelpers.Forwarder)) {
	node1, node2 := newRedialRelay(t, mode), newRedialRelay(t, mode)
	h := shareRedialling(t, protocol, node1, redialTiming)
	id := h.first.SessionId

	pair := consulPair(t, id)
	require.NotNil(t, pair, "the session has no entry in Consul")
	firstLease := pair.Session
	require.NotEmpty(t, firstLease, "node 1's entry isn't held by a lease")
	first := consulEntry(t, id)
	require.NotNil(t, first)
	require.Equal(t, node1.NodeAddr(), first.NodeAddr)

	h.fwd.Redirect(node2.addr(protocol))
	drop(h.fwd)
	h.awaitServedBy(t, node2, redialTimeout)

	// Node 1 has ended its registration once the lease it held the entry
	// under is gone: whichever way it ended it, the connection's own cleanup
	// or the watch showing the entry taken over, the release destroys it.
	require.Eventually(t, func() bool { return consulLeaseGone(t, firstLease) }, redialTimeout, redialPoll,
		"node 1 never ended its registration")
	entry := consulEntry(t, id)
	require.NotNil(t, entry, "node 1's cleanup removed node 2's entry")
	require.Equal(t, node2.NodeAddr(), entry.NodeAddr, "the entry no longer names node 2")
	require.Greater(t, entry.Generation, first.Generation, "node 2's entry isn't from a later generation")

	joinAndReachHost(t, h.first, node1.joinURL(protocol))
	joinAndReachHost(t, h.first, node2.joinURL(protocol))
}

// A node shut down gracefully, as a deploy does, has its host ready on another
// node within deployBudget, on the fast schedule a host runs with in
// production. A shared store routes the command guests were first given to
// the new node; with a store in memory the command names the node, so guests
// need the one the host's admin socket now gives.
func testRedialWhenANodeShutsDown(t *testing.T, mode routing.Mode, protocol string) {
	timing := redialTiming
	timing.FastBase, timing.FastCap = 0, 0 // the production fast schedule
	node1, node2 := newRedialRelay(t, mode), newRedialRelay(t, mode)
	h := shareRedialling(t, protocol, node1, timing)

	h.fwd.Redirect(node2.addr(protocol))
	shutDown := make(chan error, 1)
	started := time.Now()
	go func() { shutDown <- node1.Shutdown() }()
	moved := h.awaitServedBy(t, node2, deployBudget-time.Since(started))
	t.Logf("ready on node 2 %s after node 1 began shutting down", time.Since(started))

	select {
	case err := <-shutDown:
		require.NoError(t, err, "node 1's shutdown")
	case <-time.After(relayShutdownTimeout):
		t.Fatalf("node 1's shutdown did not return within %s", relayShutdownTimeout)
	}

	if mode == routing.ModeConsul {
		joinAndReachHost(t, h.first, node2.joinURL(protocol))
		return
	}
	require.NotEqual(t, h.first.SshUser, moved.SshUser, "the command names the node the host is on")
	joinAndReachHost(t, moved, node2.joinURL(protocol))
}

// A tunnel gone silent, with both ends still open, is noticed by the host's
// own liveness, and the host registers again. The relay then closes the old
// registration's connection, and with it the guests left frozen on it, long
// before its own pings would have; and a new guest joins.
func testRedialAfterABlackhole(t *testing.T, mode routing.Mode, protocol string) {
	relay := newRedialRelay(t, mode)
	h := shareRedialling(t, protocol, relay, redialTiming)
	first := h.awaitRegistered(t, relay)
	frozen := joinAndReachHost(t, h.first, relay.joinURL(protocol))
	left := make(chan error, 1)
	go func() { left <- frozen.sshClient.Wait() }()

	// The gap is held open, so the guest can be seen still there until the
	// host registers again: nothing else is going to drop it. The relay pings
	// a silent host only after 15 s, and the forwarder keeps the relay's end
	// of the blackholed connection open however the host's end goes.
	h.fwd.Redirect(closedAddr(t))
	h.fwd.Blackhole()
	h.awaitStatus(t, sessiondir.StatusReconnecting)
	select {
	case err := <-left:
		t.Fatalf("the guest was dropped before the host registered again: %v", err)
	default:
	}

	h.fwd.Redirect(relay.addr(protocol))
	h.awaitStatus(t, sessiondir.StatusReady)
	require.Eventually(t, func() bool {
		again := relay.registered(h.first.SessionId)
		return again != nil && again.Generation > first.Generation
	}, redialTimeout, redialPoll, "the host never registered again")
	select {
	case err := <-left:
		t.Logf("the frozen guest was dropped: %v", err)
	case <-time.After(redialTimeout):
		t.Fatalf("the frozen guest was still connected %s after the host registered again", redialTimeout)
	}

	joinAndReachHost(t, h.first, relay.joinURL(protocol))
}

// newRedialRelay starts a relay in mode for one scenario, with opts applied,
// and shuts it down when the scenario ends. Every relay in Consul mode shares
// the one Consul, so two of them are two nodes of one deployment.
func newRedialRelay(t *testing.T, mode routing.Mode, opts ...func(*Server)) *Server {
	t.Helper()
	ts, err := NewServerWithOptions(ServerPrivateKeyContent, mode, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ts.Shutdown() })
	return ts.(*Server)
}

// addr is the relay's listener for protocol: ssh or ws.
func (s *Server) addr(protocol string) string {
	if protocol == "ws" {
		return s.WSAddr()
	}
	return s.SSHAddr()
}

// joinURL is where a guest joins the relay over protocol.
func (s *Server) joinURL(protocol string) string { return protocol + "://" + s.addr(protocol) }

// registered is the registration the relay's store gives for id, or nil if it
// gives none.
func (s *Server) registered(id string) *server.Session {
	s.mu.RLock()
	srv := s.Server
	s.mu.RUnlock()
	if srv == nil {
		return nil
	}
	sess, err := srv.SessionManager.GetSession(id)
	if err != nil {
		return nil
	}
	return sess
}

// closedAddr is a loopback address with nothing listening on it: a forwarder
// redirected there holds a gap open, since every redial through it fails.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// redialHost is a Host that reaches its relay through a forwarder, so that a
// scenario can cut its tunnel, silence it, or send its next dial to another
// node. Guests join the relays directly.
type redialHost struct {
	*Host
	fwd   *testhelpers.Forwarder
	admin api.AdminServiceClient
	// first is the session as the host was first given it: the command its
	// guests were told to run.
	first *api.GetSessionResponse
}

// shareRedialling shares a session through a forwarder to relay's protocol
// listener, paced by timing, and returns once the session is ready.
func shareRedialling(t *testing.T, protocol string, relay *Server, timing host.ReconnectTiming) *redialHost {
	t.Helper()
	fwd := testhelpers.NewForwarder(t, relay.addr(protocol))
	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          setupAdminSocket(t),
		PermittedClientPublicKey: ClientPublicKeyContent,
		Reconnect:                timing,
	}
	r := &redialHost{Host: h, fwd: fwd}
	r.first = shareHost(t, h, protocol+"://"+fwd.Addr(), relay.NodeAddr())
	admin, err := host.AdminClient(h.AdminSocketFile)
	require.NoError(t, err)
	r.admin = admin
	r.awaitStatus(t, sessiondir.StatusReady)
	return r
}

// session is the session as the host's admin socket gives it now.
func (r *redialHost) session() (*api.GetSessionResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), redialTimeout)
	defer cancel()
	return r.admin.GetSession(ctx, &api.GetSessionRequest{})
}

// awaitStatus waits until the host reports want.
func (r *redialHost) awaitStatus(t *testing.T, want string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, want, r.Status(), "the host's status")
	}, redialTimeout, redialPoll)
}

// awaitRegistered waits until relay holds a registration of the host's
// session, and returns it.
func (r *redialHost) awaitRegistered(t *testing.T, relay *Server) *server.Session {
	t.Helper()
	require.Eventually(t, func() bool { return relay.registered(r.first.SessionId) != nil }, redialTimeout, redialPoll,
		"the relay holds no registration of the session")
	sess := relay.registered(r.first.SessionId)
	require.NotNil(t, sess, "the relay let the registration go")
	return sess
}

// awaitServedBy waits, until within, for the host to be ready on node, as its
// admin socket gives the node, and returns the session as the admin socket
// gives it then. The route is set before the status says ready, so the two
// together are a redial that has landed there.
func (r *redialHost) awaitServedBy(t *testing.T, node *Server, within time.Duration) *api.GetSessionResponse {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		sess, err := r.session()
		if !assert.NoError(c, err) {
			return
		}
		assert.Equal(c, node.NodeAddr(), sess.NodeAddr, "the node the admin socket gives")
		assert.Equal(c, sessiondir.StatusReady, r.Status(), "the host's status")
	}, within, redialPoll)
	sess, err := r.session()
	require.NoError(t, err)
	require.Equal(t, node.NodeAddr(), sess.NodeAddr)
	require.Equal(t, r.first.SessionId, sess.SessionId, "the ID survives the move")
	return sess
}

// joinAndReachHost joins a guest with session's command at joinURL, and
// requires a command it types to run in the host's shell and its output to
// come back. The guest stays joined until the test ends.
func joinAndReachHost(t *testing.T, session *api.GetSessionResponse, joinURL string) *Client {
	t.Helper()
	c := &Client{PrivateKeys: []string{ClientPrivateKey}}
	t.Cleanup(c.Close)
	require.NoError(t, c.Join(session, joinURL), "a guest joining as %s at %s", session.SshUser, joinURL)
	requireReachesHost(t, c)
	return c
}

// markers keeps each guest's probe of the host apart from the others'.
var markers atomic.Int64

// requireReachesHost has c echo a marker in the host's shell, and fails unless
// the echoed line comes back within reachTimeout. The terminal's echo of the
// command typed is a line of its own, never the marker alone.
func requireReachesHost(t *testing.T, c *Client) {
	t.Helper()
	marker := fmt.Sprintf("reached-%d", markers.Add(1))
	in, out := c.InputOutput()
	timeout := time.After(reachTimeout)
	select {
	case in <- `echo "` + marker + `"`:
	case <-timeout:
		t.Fatalf("the guest's input wasn't taken within %s", reachTimeout)
	}
	var seen strings.Builder
	for {
		select {
		case s := <-out:
			seen.WriteString(s)
			for _, line := range strings.Split(seen.String(), "\n") {
				if stripShellPrompt(strings.TrimSpace(line)) == marker {
					return
				}
			}
		case <-timeout:
			t.Fatalf("the host's shell never answered the guest: no line %q within %s; the guest saw %q",
				marker, reachTimeout, seen.String())
		}
	}
}

// requireNoHostBanner requires a guest joining with session's command at
// joinURL to be refused, and told once that no host is connected.
func requireNoHostBanner(t *testing.T, session *api.GetSessionResponse, joinURL string) {
	t.Helper()
	var banners []string
	c := &Client{PrivateKeys: []string{ClientPrivateKey}, BannerCallback: func(m string) error {
		banners = append(banners, m)
		return nil
	}}
	t.Cleanup(c.Close)
	require.Error(t, c.Join(session, joinURL), "a guest joined a session with no host connected")
	require.Len(t, banners, 1, "%q", banners)
	require.Contains(t, banners[0], "no host is connected for session "+session.SessionId)
}

// consulTestClient is the one client these tests read Consul with: each client
// keeps connections of its own open, and Consul refuses a client address that
// holds too many.
var consulTestClient = sync.OnceValues(testhelpers.ConsulClient)

// consulPair reads id's entry straight from Consul, past every relay's cache;
// nil if it's absent or can't be read. It doesn't fail the test itself, so it
// can serve a require.Eventually condition, which runs on another goroutine.
func consulPair(t *testing.T, id string) *consulapi.KVPair {
	client, err := consulTestClient()
	if err != nil {
		t.Logf("consul client: %v", err)
		return nil
	}
	pair, _, err := client.KV().Get(server.DefaultKeyPrefix+"/sessions/"+id, nil)
	if err != nil {
		t.Logf("reading %s: %v", id, err)
		return nil
	}
	return pair
}

// consulEntry is id's entry as consulPair reads it, decoded; nil if it's
// absent or can't be read or decoded.
func consulEntry(t *testing.T, id string) *server.Session {
	pair := consulPair(t, id)
	if pair == nil {
		return nil
	}
	var s server.Session
	if err := json.Unmarshal(pair.Value, &s); err != nil {
		t.Logf("decoding %s: %v", id, err)
		return nil
	}
	return &s
}

// consulLeaseGone reports whether Consul no longer has the lock session lease,
// which a relay's release of the registration holding it destroys. False if
// Consul can't be asked.
func consulLeaseGone(t *testing.T, lease string) bool {
	client, err := consulTestClient()
	if err != nil {
		t.Logf("consul client: %v", err)
		return false
	}
	entry, _, err := client.Session().Info(lease, nil)
	if err != nil {
		t.Logf("reading lease %s: %v", lease, err)
		return false
	}
	return entry == nil
}
