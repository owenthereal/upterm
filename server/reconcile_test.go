package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// gatedStore holds its Register and Reregister calls while armed, so a test
// decides which node wins a race it would otherwise leave to chance. A lease
// keeper's re-assertion is a Reregister.
type gatedStore struct {
	SessionStore
	mu   sync.Mutex
	gate chan struct{}
}

func (s *gatedStore) arm() {
	s.mu.Lock()
	s.gate = make(chan struct{})
	s.mu.Unlock()
}

func (s *gatedStore) open() {
	s.mu.Lock()
	close(s.gate)
	s.gate = nil
	s.mu.Unlock()
}

// pass waits for the gate, if it's armed.
func (s *gatedStore) pass(ctx context.Context) error {
	s.mu.Lock()
	g := s.gate
	s.mu.Unlock()
	if g == nil {
		return nil
	}
	select {
	case <-g:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *gatedStore) Register(ctx context.Context, sess *Session) (*Registration, error) {
	if err := s.pass(ctx); err != nil {
		return nil, err
	}
	return s.SessionStore.Register(ctx, sess)
}

func (s *gatedStore) Reregister(ctx context.Context, reg *Registration) (*Registration, error) {
	if err := s.pass(ctx); err != nil {
		return nil, err
	}
	return s.SessionStore.Reregister(ctx, reg)
}

// reconcileNode is one relay node's sessions on a shared Consul, reconciled
// from its store's watch.
type reconcileNode struct {
	sm       *SessionManager
	sessions *localSessions
	gated    *gatedStore
	store    *consulSessionStore
	metrics  *prometheus.Registry
	addr     string
}

func newReconcileNode(t *testing.T, addr string) *reconcileNode {
	t.Helper()
	if !testhelpers.IsConsulAvailable() {
		t.Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
	}
	consulURL, err := url.Parse(testhelpers.ConsulURL())
	require.NoError(t, err)
	logger := logging.Must(logging.Console(), logging.Debug()).Logger.With("node", addr)
	store, err := newConsulSessionStore(consulURL, time.Minute, logger)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	gated := &gatedStore{SessionStore: store}
	sm := newSessionManagerWithStore(gated, routing.NewEncodeDecoder(routing.ModeConsul))
	mp, metrics := newTestMetrics(t)
	sessions := newLocalSessions(mp, sm, logger)
	sm.Observe(sessions.reconcile)
	return &reconcileNode{sm: sm, sessions: sessions, gated: gated, store: store, metrics: metrics, addr: addr}
}

// register registers id at gen on n and adopts it as adopt does, over a
// connection of its own. The registration ends at cleanup, while the store is
// still open: its keeper would otherwise go on to rebuild a key the test has
// deleted.
func (n *reconcileNode) register(t *testing.T, id string, gen uint64) (*Registration, *closer) {
	t.Helper()
	reg, _, err := n.sm.Register(context.Background(), &Session{ID: id, NodeAddr: n.addr, Generation: gen})
	require.NoError(t, err)
	t.Cleanup(func() { n.sessions.end(reg) })
	conn := newCloser()
	_, err = n.sessions.add(reg, conn)
	require.NoError(t, err)
	require.NoError(t, n.sessions.confirm(reg))
	return reg, conn
}

func (n *reconcileNode) gauge(t *testing.T) float64 {
	t.Helper()
	v, _ := gatherValue(t, n.metrics, "test_server_sessions_active_count", nil)
	return v
}

// consulTestClient is the one client these tests read and write Consul with
// directly: each client keeps connections of its own open, and Consul refuses
// a client address that holds too many.
var consulTestClient = sync.OnceValues(testhelpers.ConsulClient)

// consulEntry reads id's entry straight from Consul, past every cache; nil if
// it's absent or can't be read. It doesn't fail the test itself, because
// require.Eventually runs its condition on another goroutine.
func consulEntry(t *testing.T, id string) *Session {
	client, err := consulTestClient()
	if err != nil {
		t.Logf("consul client: %v", err)
		return nil
	}
	pair, _, err := client.KV().Get(fmt.Sprintf("%s/sessions/%s", DefaultKeyPrefix, id), nil)
	if err != nil {
		t.Logf("reading %s: %v", id, err)
		return nil
	}
	if pair == nil {
		return nil
	}
	var s Session
	if err := json.Unmarshal(pair.Value, &s); err != nil {
		t.Logf("decoding %s: %v", id, err)
		return nil
	}
	return &s
}

// waitClosedCloser fails with what unless c is closed within 5 s.
func waitClosedCloser(t *testing.T, c *closer, what string) {
	t.Helper()
	select {
	case <-c.closed:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s stayed open", what)
	}
}

func TestReconcileAcrossNodes(t *testing.T) {
	a, b := newReconcileNode(t, "node-a:22"), newReconcileNode(t, "node-b:22")
	id := fmt.Sprintf("reconcile-%d", time.Now().UnixNano())
	client, err := consulTestClient()
	require.NoError(t, err)
	key := fmt.Sprintf("%s/sessions/%s", DefaultKeyPrefix, id)
	t.Cleanup(func() { _, _ = client.KV().Delete(key, nil) })

	_, connA := a.register(t, id, 1)
	_, _ = b.register(t, id, 2)
	waitClosedCloser(t, connA, "node A's superseded registration")

	// Deleted behind B's back: B re-asserts.
	_, err = client.KV().Delete(key, nil)
	require.NoError(t, err)
	require.Eventually(t, func() bool { s := consulEntry(t, id); return s != nil && s.Generation == 2 }, 5*time.Second, 50*time.Millisecond)

	// A stale write landing on the absent entry, made deterministic: hold B's
	// re-assertion, delete, let A's stale generation 1 land, then release B.
	b.gated.arm()
	_, err = client.KV().Delete(key, nil)
	require.NoError(t, err)
	_, connA1 := a.register(t, id, 1)
	b.gated.open()
	waitClosedCloser(t, connA1, "the stale registration")
	require.Eventually(t, func() bool {
		s := consulEntry(t, id)
		return s != nil && s.Generation == 2 && s.NodeAddr == "node-b:22"
	}, 5*time.Second, 50*time.Millisecond)
}

// Watch deliveries race registrations and releases. Run it with -race: a map
// shared between the cache and the observers is what it detects.
func TestReplicaObserverIsRaceFree(t *testing.T) {
	a := newReconcileNode(t, "node-a:22")
	var seen atomic.Int32
	a.sm.Observe(func(_, _ uint64, entries map[string]StoreEntry) {
		for range entries { // read it all, as reconcile does
		}
		seen.Add(1)
	})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 20 {
				reg, _, err := a.sm.Register(context.Background(), &Session{ID: fmt.Sprintf("race-%d-%d-%d", time.Now().UnixNano(), i, j), NodeAddr: "node-a:22", Generation: 1})
				if err == nil {
					_ = a.sm.Release(context.Background(), reg)
				}
			}
		})
	}
	wg.Wait()
	require.Greater(t, seen.Load(), int32(0))
}

// The watch delivery showing a newer registration can be processed before this
// node adopts an older one, when there's no slot yet to reconcile. Adoption
// checks the store's view again, and refuses a registration it already shows
// superseded, rather than serving it until the next delivery or renewal.
func TestAdoptionRefusesARegistrationAlreadySuperseded(t *testing.T) {
	a, b := newReconcileNode(t, "node-a:22"), newReconcileNode(t, "node-b:22")
	ctx, id := context.Background(), fmt.Sprintf("late-adoption-%d", time.Now().UnixNano())
	client, err := consulTestClient()
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = client.KV().Delete(fmt.Sprintf("%s/sessions/%s", DefaultKeyPrefix, id), nil) })

	reg, _, err := a.sm.Register(ctx, &Session{ID: id, NodeAddr: a.addr, Generation: 1})
	require.NoError(t, err)
	t.Cleanup(func() { a.sessions.end(reg) })
	_, _ = b.register(t, id, 2)
	require.Eventually(t, func() bool { return cachedGeneration(a.store, id) == 2 },
		5*time.Second, 10*time.Millisecond, "node A's watch never delivered generation 2")

	conn := newCloser()
	_, err = a.sessions.add(reg, conn)
	require.NoError(t, err)
	require.ErrorIs(t, a.sessions.confirm(reg), ErrSuperseded)
	require.True(t, conn.isClosed(), "the superseded registration's connection was left open")
	require.False(t, a.sessions.active(reg))
	require.Equal(t, 0.0, a.gauge(t))

	// Its lease is released, and B's entry outlives that release.
	require.Eventually(t, func() bool {
		se, _, err := client.Session().Info(reg.lease, nil)
		return err == nil && se == nil
	}, 5*time.Second, 10*time.Millisecond, "the superseded registration's lease was never released")
	s := consulEntry(t, id)
	require.NotNil(t, s, "releasing the superseded registration removed its successor's entry")
	require.Equal(t, uint64(2), s.Generation)
	require.Equal(t, b.addr, s.NodeAddr)
}

// End to end on one node: generation 1 commits and is held before adoption
// while generation 2 commits. When 1 adopts, the store already shows 2, so 1
// is refused and its connection closed, and 2 then adopts as usual.
func Test_sshd_AdoptionChecksTheStoreAgain(t *testing.T) {
	registered := make(chan uint64, 2)
	resume := map[uint64]chan struct{}{1: make(chan struct{}), 2: make(chan struct{})}
	s := newTestSSHD(t, func(d *sshd) {
		d.onRegistered = func(_ context.Context, reg *Registration) {
			registered <- reg.Generation()
			<-resume[reg.Generation()]
		}
	})
	host := newProven(t)
	type reply struct {
		ok   bool
		body []byte
		err  error
	}
	send := func(client *ssh.Client, keyID string, gen uint64) <-chan reply {
		// Signed here: require must not run on the goroutine below.
		proof, err := registration.Sign(host.key, []byte(keyID), host.secret, gen)
		require.NoError(t, err)
		req, err := proto.Marshal(&CreateSessionRequest{HostUser: "owen", HostPublicKeys: host.hostKeys(),
			SessionSecret: host.secret, Generation: gen, HostKeyProof: proof})
		require.NoError(t, err)
		result := make(chan reply, 1)
		go func() {
			ok, body, err := client.SendRequest(upterm.ServerCreateSessionRequestType, true, req)
			result <- reply{ok, body, err}
		}()
		select {
		case got := <-registered:
			require.Equal(t, gen, got)
		case <-time.After(5 * time.Second):
			t.Fatalf("generation %d never reached the store", gen)
		}
		return result
	}
	awaitReply := func(result <-chan reply, gen uint64) reply {
		select {
		case r := <-result:
			return r
		case <-time.After(5 * time.Second):
			t.Fatalf("generation %d never got a reply", gen)
			return reply{}
		}
	}

	first := s.dialAs(t, "conn-1")
	firstResult := send(first, "conn-1", 1)
	second := s.dialAs(t, "conn-2")
	secondResult := send(second, "conn-2", 2)

	close(resume[1])
	r := awaitReply(firstResult, 1)
	require.False(t, r.ok && r.err == nil, "generation 1 was adopted though the store had generation 2")
	waitClosed(t, first, "the superseded registration's connection")
	require.Equal(t, 0.0, s.gauge(t))

	close(resume[2])
	r = awaitReply(secondResult, 2)
	require.NoError(t, r.err)
	require.True(t, r.ok, string(r.body))
	require.Equal(t, 1.0, s.gauge(t))
}

// Consul's index can go backwards, and a delivery after the drop doesn't order
// against a registration written before it. That registration is reconciled
// against the delivery whatever their indexes, so one the delivery shows
// superseded is closed.
func TestReconcileAcrossAnIndexDrop(t *testing.T) {
	consul := newFakeConsul(t)
	store := newFakeConsulStore(t, consul)
	sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeConsul))
	mp, _ := newTestMetrics(t)
	sessions := newLocalSessions(mp, sm, slog.New(slog.DiscardHandler))
	sm.Observe(sessions.reconcile)

	reg, _, err := sm.Register(context.Background(), &Session{ID: "id", NodeAddr: "node-a:22", Generation: 1})
	require.NoError(t, err)
	t.Cleanup(func() { sessions.end(reg) })
	conn := newCloser()
	_, err = sessions.add(reg, conn)
	require.NoError(t, err)
	store.updateSessionReplica(reg.index, api.KVPairs{consul.entry()})
	require.False(t, conn.isClosed(), "a delivery showing the registration itself closed it")

	// After the drop, another node's newer registration, at an index below the
	// one this registration was written at.
	newer, err := json.Marshal(&Session{ID: "id", NodeAddr: "node-b:22", Generation: 2})
	require.NoError(t, err)
	store.updateSessionReplica(reg.index-1, api.KVPairs{{Key: store.SessionKey("id"), Value: newer, Session: "lease-b", ModifyIndex: reg.index - 1}})
	require.True(t, conn.isClosed(), "a registration from before the index drop wasn't reconciled")
	require.False(t, sessions.active(reg))
}

// A plain write into a held key keeps its lock session, and every
// registration moves the lock to its own lease, so a key a registration's own
// lease holds is still its entry, whatever was written into it. Another
// registration's value there is a loss for the keeper to rebuild, not a
// supersession: before reconnect, no write to the store closed a legacy host,
// and nothing newer has replaced this one.
func TestAForeignValueInAKeyItsOwnLeaseHoldsIsALoss(t *testing.T) {
	for _, tc := range []struct {
		name          string
		gen, forgedAt uint64
	}{
		{"legacy", 0, 1},
		{"capable", 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			consul := newFakeConsul(t)
			store := newFakeConsulStore(t, consul)
			sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeConsul))
			mp, metrics := newTestMetrics(t)
			sessions := newLocalSessions(mp, sm, slog.New(slog.DiscardHandler))
			sm.Observe(sessions.reconcile)

			own := &Session{ID: "id", NodeAddr: "node-a:22", Generation: tc.gen}
			reg, _, err := sm.Register(context.Background(), own)
			require.NoError(t, err)
			t.Cleanup(func() { sessions.end(reg) })
			conn := newCloser()
			_, err = sessions.add(reg, conn)
			require.NoError(t, err)

			// A higher generation from another node, written into the key
			// without acquiring it: reg's lease still holds it.
			forged, err := json.Marshal(&Session{ID: "id", NodeAddr: "node-b:22", Generation: tc.forgedAt})
			require.NoError(t, err)
			consul.mu.Lock()
			consul.pair = &api.KVPair{Key: consul.pair.Key, Value: forged, Session: reg.lease, ModifyIndex: reg.index + 1}
			consul.mu.Unlock()
			store.updateSessionReplica(reg.index+1, api.KVPairs{consul.entry()})

			require.False(t, conn.isClosed(), "a foreign value in the key its own lease holds closed the host")
			require.Eventually(t, func() bool {
				e := consul.entry()
				var s Session
				return e != nil && e.Session != reg.lease && json.Unmarshal(e.Value, &s) == nil && sameIdentity(&s, own)
			}, 5*time.Second, 10*time.Millisecond, "the keeper never restored the entry under a new lease")
			require.False(t, conn.isClosed())
			require.True(t, sessions.active(reg))
			v, _ := gatherValue(t, metrics, "test_server_sessions_active_count", nil)
			require.Equal(t, 1.0, v)
		})
	}
}

// End to end on Consul: another registration's value written into a legacy
// host's key with a plain PUT keeps the host's lock, so the watch shows the key
// still held by its own lease. The host stays connected, and its keeper
// restores the value.
func TestAPlainWriteIntoAHeldKeyLeavesTheHostConnected(t *testing.T) {
	a := newReconcileNode(t, "node-a:22")
	id := fmt.Sprintf("plain-write-%d", time.Now().UnixNano())
	client, err := consulTestClient()
	require.NoError(t, err)
	key := fmt.Sprintf("%s/sessions/%s", DefaultKeyPrefix, id)
	t.Cleanup(func() { _, _ = client.KV().Delete(key, nil) })

	reg, conn := a.register(t, id, 0)
	forged, err := json.Marshal(&Session{ID: id, NodeAddr: "node-b:22", Generation: 1})
	require.NoError(t, err)
	_, err = client.KV().Put(&api.KVPair{Key: key, Value: forged}, nil)
	require.NoError(t, err)

	require.Eventually(t, func() bool { s := consulEntry(t, id); return s != nil && sameIdentity(s, reg.Session) },
		5*time.Second, 50*time.Millisecond, "the keeper never restored the entry")
	require.False(t, conn.isClosed(), "a plain write into the host's own key closed it")
	require.True(t, a.sessions.active(reg))
}

// Without leases there is no lock to tell a registration's own key by, and an
// unlocked entry is held by no one: a newer registration's entry still
// supersedes a registration that has no lease.
func TestANewerEntrySupersedesARegistrationWithoutALease(t *testing.T) {
	sessions, reg, conn := newKeeperFixture(t, &leaseStore{ttl: time.Hour}, 1)
	require.Empty(t, reg.lease)

	sessions.reconcile(0, 0, map[string]StoreEntry{"id": {Session: &Session{ID: "id", NodeAddr: "elsewhere:22", Generation: 2}}})

	require.True(t, conn.isClosed(), "a newer unlocked entry didn't supersede a registration without a lease")
	require.False(t, sessions.active(reg))
}

// The keeper takes the watch's report of a loss as a known loss wherever it
// waits: for its next renewal, and between renewals that keep failing.
func TestLeaseKeeperRebuildsALossTheWatchReports(t *testing.T) {
	absent := map[string]StoreEntry{}
	rebuilding := func(store *leaseStore) <-chan struct{} {
		rebuilt := make(chan struct{}, 1)
		store.reregister = func(ctx context.Context, reg *Registration) (*Registration, error) {
			select {
			case rebuilt <- struct{}{}:
			default:
			}
			return store.memorySessionStore.Reregister(ctx, reg)
		}
		return rebuilt
	}

	t.Run("waiting to renew", func(t *testing.T) {
		store := &leaseStore{ttl: time.Hour} // the first renewal falls due in 30 minutes
		rebuilt := rebuilding(store)
		sessions, _, conn := newKeeperFixture(t, store, 1)
		sessions.reconcile(0, 0, absent)
		select {
		case <-rebuilt:
		case <-time.After(5 * time.Second):
			t.Fatal("the keeper waited for its renewal to rebuild a known loss")
		}
		require.Zero(t, store.renews.Load())
		require.False(t, conn.isClosed())
	})

	t.Run("between renewal retries", func(t *testing.T) {
		// A legacy registration, so failed renewals are retried indefinitely
		// and nothing but the loss can lead to a rebuild.
		store := &leaseStore{ttl: 100 * time.Millisecond, renew: func(context.Context, *Registration) error { return errConsulDown }}
		rebuilt := rebuilding(store)
		sessions, _, _ := newKeeperFixture(t, store, 0)
		require.Eventually(t, func() bool { return store.renews.Load() > 0 }, 5*time.Second, 10*time.Millisecond)
		sessions.reconcile(0, 0, absent)
		select {
		case <-rebuilt:
		case <-time.After(5 * time.Second):
			t.Fatal("the keeper went on retrying renewals after a known loss")
		}
	})
}

// A loss the watch reports while the keeper is already rebuilding was judged
// against the handle the rebuild replaces. Installing the rebuilt handle
// discards it, rather than rebuilding a second time.
func TestALossReportedDuringARebuildIsNotRebuiltAgain(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var rebuilds atomic.Int32
	// Legacy, so no rebuild bound closes the connection while the test holds
	// the rebuild.
	store := &leaseStore{ttl: time.Hour}
	store.reregister = func(ctx context.Context, reg *Registration) (*Registration, error) {
		if rebuilds.Add(1) == 1 {
			close(entered)
			<-release
		}
		return store.memorySessionStore.Reregister(ctx, reg)
	}
	sessions, reg, conn := newKeeperFixture(t, store, 0)
	absent := map[string]StoreEntry{}

	sessions.reconcile(0, 0, absent)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the keeper never rebuilt the loss")
	}
	sessions.reconcile(0, 0, absent) // the same loss, delivered again mid-rebuild
	close(release)

	require.Eventually(t, func() bool {
		sessions.mu.Lock()
		defer sessions.mu.Unlock()
		cur, ok := sessions.regs[reg.ID()]
		return ok && cur.reg != reg
	}, 5*time.Second, 10*time.Millisecond, "the rebuilt handle was never installed")
	require.Never(t, func() bool { return rebuilds.Load() > 1 }, 300*time.Millisecond, 10*time.Millisecond,
		"a loss reported against the replaced handle was rebuilt again")
	require.False(t, conn.isClosed())
}

// A loss the rebuild didn't answer outlasts the installation of its handle,
// and is rebuilt again rather than left until the next renewal: one from a
// delivery after the rebuild's write, which can show a delete landing before
// the handle is installed, or from another epoch, which doesn't order against
// that write.
func TestALossTheRebuildDidNotAnswerIsRebuiltAgain(t *testing.T) {
	for _, tc := range []struct {
		name         string
		epoch, index uint64
	}{
		{"a later delivery", 0, 6},
		{"another epoch", 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var rebuilds atomic.Int32
			// Legacy, so no rebuild bound closes the connection while the test
			// holds the rebuild.
			store := &leaseStore{ttl: time.Hour}
			store.reregister = func(ctx context.Context, reg *Registration) (*Registration, error) {
				if rebuilds.Add(1) == 1 {
					close(entered)
					<-release
				}
				next, err := store.memorySessionStore.Reregister(ctx, reg)
				if next != nil {
					next.index = 5 // where Consul would have written it
				}
				return next, err
			}
			sessions, _, conn := newKeeperFixture(t, store, 0)
			absent := map[string]StoreEntry{}

			sessions.reconcile(0, 0, absent)
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("the keeper never rebuilt the loss")
			}
			sessions.reconcile(tc.epoch, tc.index, absent)
			close(release)

			require.Eventually(t, func() bool { return rebuilds.Load() == 2 }, 5*time.Second, 10*time.Millisecond,
				"a loss the rebuild didn't answer was discarded")
			require.Never(t, func() bool { return rebuilds.Load() > 2 }, 300*time.Millisecond, 10*time.Millisecond,
				"one loss was rebuilt more than once more")
			require.False(t, conn.isClosed())
		})
	}
}
