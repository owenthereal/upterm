package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/routing"
	"github.com/stretchr/testify/require"
)

// leaseStore is a memory store with a lease lifetime and scripted calls.
type leaseStore struct {
	*memorySessionStore
	ttl      time.Duration
	renews   atomic.Int32
	renew    func(ctx context.Context, reg *Registration) error
	register func(ctx context.Context, s *Session) (*Registration, error)
}

func (s *leaseStore) LeaseTTL() time.Duration { return s.ttl }

func (s *leaseStore) Renew(ctx context.Context, reg *Registration) error {
	s.renews.Add(1)
	if s.renew != nil {
		return s.renew(ctx, reg)
	}
	return s.memorySessionStore.Renew(ctx, reg)
}

func (s *leaseStore) Register(ctx context.Context, sess *Session) (*Registration, error) {
	if s.register != nil {
		return s.register(ctx, sess)
	}
	return s.memorySessionStore.Register(ctx, sess)
}

var errConsulDown = errors.New("consul unreachable")

var testLeaseTiming = leaseTiming{retryBase: 10 * time.Millisecond, retryMax: 40 * time.Millisecond, rebuildBound: 200 * time.Millisecond}

// testTTL leaves a capable keeper several lateWakes between a renewal falling
// due and its budget running out, so a slow runner doesn't close a connection
// that should stay open.
const testTTL = time.Second // renew at 500 ms; budget at 900 ms

// lateWake is how late a woken goroutine may run on a loaded CI runner under
// -race; GitHub's Windows runners have woken them more than 100 ms late. A
// close is asserted never to come before its deadline, which the keeper
// guarantees, and at most this long after it.
const lateWake = 150 * time.Millisecond

// awaitClose waits for conn to close until well past deadline, and returns
// when it closed; false if it didn't.
func awaitClose(conn *closer, deadline time.Time) (time.Time, bool) {
	select {
	case <-conn.closed:
		return conn.at, true
	case <-time.After(time.Until(deadline.Add(2 * lateWake))):
		return time.Time{}, false
	}
}

// requireClosedAt asserts a close at deadline: never before it, and no more
// than lateWake after it.
func requireClosedAt(t *testing.T, at, deadline time.Time, what string) {
	t.Helper()
	require.False(t, at.Before(deadline), "closed %v before %s", deadline.Sub(at), what)
	require.LessOrEqual(t, at.Sub(deadline), lateWake, "closed %v after %s", at.Sub(deadline), what)
}

// blockUntil stands in for a store call that hangs until its context ends, or
// until release fires, returning its result.
func blockUntil(ctx context.Context, release <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-release:
		return nil
	}
}

func newKeeperFixture(t *testing.T, store *leaseStore, gen uint64) (*localSessions, *Registration, *closer) {
	t.Helper()
	logger := logging.Must(logging.Console(), logging.Debug()).Logger
	store.memorySessionStore = newMemorySessionStore(logger)
	sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	mp, _ := newTestMetrics(t)
	sessions := newLocalSessions(mp, sm, logger)
	sessions.timing = testLeaseTiming
	reg, err := store.memorySessionStore.Register(context.Background(), &Session{ID: "id", NodeAddr: "node", Generation: gen})
	require.NoError(t, err)
	conn := newCloser()
	_, err = sessions.add(reg, conn)
	require.NoError(t, err)
	t.Cleanup(func() { sessions.end(reg) })
	return sessions, reg, conn
}

func TestLeaseKeeperRenewsAtHalfItsTTL(t *testing.T) {
	store := &leaseStore{ttl: testTTL}
	_, _, conn := newKeeperFixture(t, store, 1)
	// Renewals fall due at 0.5, 1 and 1.5 × testTTL; the rest is room for late
	// wakes.
	require.Eventually(t, func() bool { return store.renews.Load() >= 3 }, 4*testTTL, 10*time.Millisecond)
	require.False(t, conn.isClosed())
}

// A renewal that hangs is cut off at the budget: the tunnel closes on time,
// not whenever the call gives up. That holds whether the call honours its
// context or, like a stuck HTTP request, ignores it. A legacy host's tunnel
// is never closed.
func TestLeaseKeeperBudgetHoldsAcrossASlowRenewal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		gen     uint64
		closes  bool
		honours bool
	}{
		{"capable, honours ctx", 1, true, true},
		{"capable, ignores ctx", 1, true, false},
		{"legacy", 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			never := make(chan struct{})
			t.Cleanup(func() { close(never) })
			store := &leaseStore{ttl: testTTL, renew: func(ctx context.Context, _ *Registration) error {
				if tc.honours {
					return blockUntil(ctx, never)
				}
				<-never
				return nil
			}}
			_, reg, conn := newKeeperFixture(t, store, tc.gen)
			budget := reg.ConfirmedAt.Add(testTTL - leaseMargin(testTTL))
			at, closed := awaitClose(conn, budget)
			if !tc.closes {
				require.False(t, closed, "a legacy host's tunnel must not be closed")
				return
			}
			require.True(t, closed, "a capable tunnel was held past its budget by a slow renewal")
			requireClosedAt(t, at, budget, "the budget")
		})
	}
}

func TestLeaseKeeperClosesACapableTunnelWhenRenewalsKeepFailing(t *testing.T) {
	store := &leaseStore{ttl: testTTL, renew: func(context.Context, *Registration) error { return errConsulDown }}
	_, reg, conn := newKeeperFixture(t, store, 1)
	budget := reg.ConfirmedAt.Add(testTTL - leaseMargin(testTTL))
	at, closed := awaitClose(conn, budget)
	require.True(t, closed, "left open past the budget")
	requireClosedAt(t, at, budget, "the budget")
}

// gatedReleaseStore holds Release until opened, standing in for a cleanup
// that blocks.
type gatedReleaseStore struct {
	*leaseStore
	gate chan struct{}
}

func (s *gatedReleaseStore) Release(ctx context.Context, reg *Registration) error {
	<-s.gate
	return s.leaseStore.Release(ctx, reg)
}

// A rebuild that is still running at its bound doesn't hold the close.
// 1. The rebuild's Register hangs, ignoring its context, and then succeeds.
// 2. The release of that late result is held too.
// 3. The connection must close at the bound, before either gate opens.
// 4. Once the gates open, the late registration is released after all.
func TestLeaseKeeperClosesAtTheRebuildBoundWhateverCleanupIsDoing(t *testing.T) {
	registerGate, releaseGate := make(chan struct{}), make(chan struct{})
	lostAt := make(chan time.Time, 1)
	base := &leaseStore{ttl: testTTL, renew: func(context.Context, *Registration) error {
		// The keeper learns of the loss after this, so its bound can't be
		// earlier than this plus rebuildBound.
		select {
		case lostAt <- time.Now():
		default:
		}
		return ErrLeaseLost
	}}
	base.register = func(_ context.Context, s *Session) (*Registration, error) {
		<-registerGate // ignores ctx, as a stuck HTTP call would
		return base.memorySessionStore.Register(context.Background(), s)
	}
	store := &gatedReleaseStore{leaseStore: base, gate: releaseGate}

	logger := logging.Must(logging.Console(), logging.Debug()).Logger
	base.memorySessionStore = newMemorySessionStore(logger)
	sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	mp, _ := newTestMetrics(t)
	sessions := newLocalSessions(mp, sm, logger)
	sessions.timing = testLeaseTiming
	reg, err := base.memorySessionStore.Register(context.Background(), &Session{ID: "id", NodeAddr: "node", Generation: 1})
	require.NoError(t, err)
	conn := newCloser()
	_, err = sessions.add(reg, conn)
	require.NoError(t, err)

	bound := (<-lostAt).Add(testLeaseTiming.rebuildBound)
	at, closed := awaitClose(conn, bound)
	require.True(t, closed, "the close waited on a store call")
	requireClosedAt(t, at, bound, "the rebuild bound")

	close(registerGate) // the late success arrives
	close(releaseGate)  // and its cleanup may proceed
	require.Eventually(t, func() bool {
		_, err := base.Get("id")
		return err != nil
	}, time.Second, 10*time.Millisecond, "the late registration is released, conditionally")
	sessions.end(reg)
}

func TestLeaseKeeperRebuildBoundSparesLegacyHosts(t *testing.T) {
	store := &leaseStore{
		ttl:      testTTL,
		renew:    func(context.Context, *Registration) error { return ErrLeaseLost },
		register: func(context.Context, *Session) (*Registration, error) { return nil, errConsulDown },
	}
	_, _, conn := newKeeperFixture(t, store, 0)
	// Past where a capable registration's connection closes, with room for
	// the renewal and the close both to wake late.
	time.Sleep(testTTL/2 + testLeaseTiming.rebuildBound + 3*lateWake)
	require.False(t, conn.isClosed())
}

func TestLeaseKeeperRebuildsAKnownLossAndStopsWhenSuperseded(t *testing.T) {
	var lost atomic.Bool
	lost.Store(true)
	store := &leaseStore{ttl: testTTL, renew: func(context.Context, *Registration) error {
		if lost.CompareAndSwap(true, false) {
			return ErrLeaseLost
		}
		return nil
	}}
	sessions, reg, conn := newKeeperFixture(t, store, 1)
	// The third renewal falls due at 1.5 × testTTL; the rest is room for late
	// wakes.
	require.Eventually(t, func() bool { return store.renews.Load() >= 3 }, 3*testTTL, 10*time.Millisecond)
	require.True(t, sessions.active(reg))
	require.False(t, conn.isClosed())

	store2 := &leaseStore{ttl: testTTL,
		renew:    func(context.Context, *Registration) error { return ErrLeaseLost },
		register: func(context.Context, *Session) (*Registration, error) { return nil, ErrSuperseded }}
	_, _, conn2 := newKeeperFixture(t, store2, 1)
	select {
	case <-conn2.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("superseded while rebuilding, but kept its connection")
	}
}

// A legacy host is spared the lease deadlines, not supersession: once a newer
// registration holds its ID, its connection is closed like any other.
func TestLeaseKeeperClosesASupersededLegacyHost(t *testing.T) {
	store := &leaseStore{ttl: testTTL,
		renew:    func(context.Context, *Registration) error { return ErrLeaseLost },
		register: func(context.Context, *Session) (*Registration, error) { return nil, ErrSuperseded }}
	_, _, conn := newKeeperFixture(t, store, 0)
	select {
	case <-conn.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("a legacy registration superseded while rebuilding kept its connection")
	}
}

// A rebuild that finishes after its registration ended leaves no entry behind.
func TestLeaseKeeperNeverResurrectsAnEndedRegistration(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	store := &leaseStore{ttl: testTTL, renew: func(context.Context, *Registration) error { return ErrLeaseLost }}
	store.register = func(_ context.Context, s *Session) (*Registration, error) {
		close(entered)
		<-release
		return store.memorySessionStore.Register(context.Background(), s)
	}
	sessions, reg, _ := newKeeperFixture(t, store, 1)
	<-entered
	sessions.end(reg)
	close(release)
	present := func() bool { _, err := store.Get("id"); return err == nil }
	require.Eventually(t, func() bool { return !present() }, time.Second, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.Never(t, present, 200*time.Millisecond, 10*time.Millisecond)
}

// newConsulLeaseFixture is a node's sessions on a Consul store whose leases
// last 10 s, the shortest TTL Consul accepts, and a client that reads Consul
// directly, past the store's cache.
func newConsulLeaseFixture(t *testing.T) (*localSessions, *consulSessionStore, *api.Client) {
	t.Helper()
	if !testhelpers.IsConsulAvailable() {
		t.Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
	}
	consulURL, err := url.Parse(testhelpers.ConsulURL())
	require.NoError(t, err)
	logger := logging.Must(logging.Console(), logging.Debug()).Logger
	sm, err := newConsulSessionManager(consulURL, 10*time.Second, logger)
	require.NoError(t, err)
	store := sm.GetStore().(*consulSessionStore)
	t.Cleanup(func() { _ = store.Close() })
	client, err := testhelpers.ConsulClient()
	require.NoError(t, err)
	mp, _ := newTestMetrics(t)
	return newLocalSessions(mp, sm, logger), store, client
}

// consulHolder returns the lock session holding id's entry in Consul, and
// whether the entry exists. It doesn't fail the test itself, because
// require.Eventually runs its condition on another goroutine.
func consulHolder(client *api.Client, store *consulSessionStore, id string) (holder string, exists bool, err error) {
	pair, _, err := client.KV().Get(store.SessionKey(id), nil)
	if err != nil || pair == nil {
		return "", false, err
	}
	return pair.Session, true, nil
}

// Consul expires an unrenewed entry within twice its TTL. A kept one outlives
// that, and goes when its registration ends.
func TestLeaseKeeperKeepsAConsulEntryPastItsTTL(t *testing.T) {
	sessions, store, client := newConsulLeaseFixture(t)
	id := fmt.Sprintf("lease-kept-%d", time.Now().UnixNano())
	reg, _, err := sessions.sessionManager.Register(context.Background(), &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	require.NoError(t, err)
	conn := newCloser()
	_, err = sessions.add(reg, conn)
	require.NoError(t, err)

	time.Sleep(25 * time.Second)
	_, exists, err := consulHolder(client, store, id)
	require.NoError(t, err)
	require.True(t, exists, "the entry expired while its registration lived")
	require.False(t, conn.isClosed())

	sessions.end(reg)
	require.Eventually(t, func() bool {
		_, exists, err := consulHolder(client, store, id)
		return err == nil && !exists
	}, 2*time.Second, 50*time.Millisecond, "the entry outlived its registration")
}

// A rebuild stores the registration again under a new lease, but every path
// that ends a registration holds the handle it was adopted with. Ending that
// handle still removes the rebuilt entry, rather than leaving it to route
// guests to a gone host until its lease expires.
func TestLeaseKeeperRebuiltEntryGoesWithItsRegistration(t *testing.T) {
	sessions, store, client := newConsulLeaseFixture(t)
	id := fmt.Sprintf("lease-rebuilt-%d", time.Now().UnixNano())
	reg, _, err := sessions.sessionManager.Register(context.Background(), &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	require.NoError(t, err)
	conn := newCloser()
	_, err = sessions.add(reg, conn)
	require.NoError(t, err)

	// Lost behind the keeper's back: the entry goes with the lease, and the
	// next renewal learns of the loss.
	_, err = client.Session().Destroy(reg.lease, nil)
	require.NoError(t, err)
	// Wait for the slot, not just Consul: Consul shows the new holder before
	// the keeper swaps its handle in, and an end in between leaves the keeper
	// to release the rebuild itself, which would hide a missing release here.
	slotLease := func() string {
		sessions.mu.Lock()
		defer sessions.mu.Unlock()
		if cur, ok := sessions.regs[id]; ok {
			return cur.reg.lease
		}
		return ""
	}
	require.Eventually(t, func() bool {
		holder, exists, err := consulHolder(client, store, id)
		lease := slotLease()
		return err == nil && exists && lease != "" && lease != reg.lease && holder == lease
	}, 10*time.Second, 50*time.Millisecond, "the lost lease was never rebuilt")
	require.False(t, conn.isClosed())

	sessions.end(reg)
	require.Eventually(t, func() bool {
		_, exists, err := consulHolder(client, store, id)
		return err == nil && !exists
	}, 2*time.Second, 50*time.Millisecond, "the rebuilt entry outlived its registration")
}
