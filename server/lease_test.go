package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/routing"
	"github.com/stretchr/testify/require"
)

// The memory-store keeper tests run in a synctest bubble, where time is fake:
// it moves only when every goroutine in the bubble is blocked, and a timer
// fires exactly at its deadline. They use production's retry timing and
// rebuild bound, defaultLeaseTiming, with a 10 s TTL, keeperTTL. Each close
// is asserted at its exact time, and each deadline is checked a nanosecond
// before it and at it.

// keeperTTL is the fake-time tests' lease lifetime. With defaultLeaseTiming a
// keeper renews at 5 s, and a capable tunnel's budget runs out at 9 s, between
// the retries of a failing renewal that wake at 8 s and at 12 s; a rebuild is
// bound to 60 s after its loss.
const keeperTTL = 10 * time.Second

// maxStoreCalls is how many times a keeper may call Renew, and Reregister,
// before its store fails the test; no test needs more than a few.
const maxStoreCalls = 100

// leaseStore is a memory store with a lease lifetime and scripted calls.
//
// A broken keeper can renew or rebuild in a loop at one fake instant, and fake
// time doesn't move while it does, so the test would hang rather than fail. So
// past maxStoreCalls of either call, the store fails the test and parks the
// call until its context ends. Parked, the keeper is durably blocked, so the
// test's own assertions run and report; ending the registration, as the
// test's cleanup does, ends that context. Once the test's context is done,
// the test may have completed, and failing a completed test panics, so then
// the call only returns that context's error.
type leaseStore struct {
	*memorySessionStore
	t           *testing.T // the test whose keeper calls the store; the fixture sets it
	ttl         time.Duration
	renews      atomic.Int32
	reregisters atomic.Int32
	renew       func(ctx context.Context, reg *Registration) error
	reregister  func(ctx context.Context, reg *Registration) (*Registration, error)
}

func (s *leaseStore) LeaseTTL() time.Duration { return s.ttl }

func (s *leaseStore) Renew(ctx context.Context, reg *Registration) error {
	if n := s.renews.Add(1); n > maxStoreCalls {
		return s.park(ctx, "Renew", n)
	}
	if s.renew != nil {
		return s.renew(ctx, reg)
	}
	return s.memorySessionStore.Renew(ctx, reg)
}

func (s *leaseStore) Reregister(ctx context.Context, reg *Registration) (*Registration, error) {
	if n := s.reregisters.Add(1); n > maxStoreCalls {
		return nil, s.park(ctx, "Reregister", n)
	}
	if s.reregister != nil {
		return s.reregister(ctx, reg)
	}
	return s.memorySessionStore.Reregister(ctx, reg)
}

// park fails the test the first time a call passes maxStoreCalls, and holds
// every call past it until ctx ends. Once the test's context is done, it does
// neither and returns that context's error.
func (s *leaseStore) park(ctx context.Context, call string, n int32) error {
	if err := s.t.Context().Err(); err != nil {
		return err
	}
	if n == maxStoreCalls+1 {
		s.t.Errorf("the keeper called %s %d times, more than any test here needs: it is likely looping", call, n)
	}
	<-ctx.Done()
	return ctx.Err()
}

var errConsulDown = errors.New("consul unreachable")

var testLeaseTiming = leaseTiming{retryBase: 10 * time.Millisecond, retryMax: 40 * time.Millisecond, rebuildBound: 200 * time.Millisecond}

// lateWake is how late a woken goroutine may run on a loaded CI runner under
// -race; GitHub's Windows runners have woken them more than 100 ms late. A
// close is asserted never to come before its deadline, which the code under
// test guarantees, and at most this long after it.
const lateWake = 150 * time.Millisecond

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

// newGate returns a gate and the func that opens it. The gate opens when the
// test ends, too, so that nothing parked on it outlives the test.
func newGate(t *testing.T) (gate <-chan struct{}, open func()) {
	c := make(chan struct{})
	open = sync.OnceFunc(func() { close(c) })
	t.Cleanup(open)
	return c, open
}

func newKeeperFixture(t *testing.T, store *leaseStore, gen uint64) (*localSessions, *Registration, *closer) {
	t.Helper()
	return newKeeperFixtureWith(t, store, gen, testLeaseTiming)
}

// newKeeperFixtureWith adopts a registration of generation gen on store, whose
// keeper is paced by timing, and ends it in a cleanup. The keeper copies its
// timing when the registration is adopted, so timing is set before that.
func newKeeperFixtureWith(t *testing.T, store *leaseStore, gen uint64, timing leaseTiming) (*localSessions, *Registration, *closer) {
	t.Helper()
	logger := logging.Must(logging.Console(), logging.Debug()).Logger
	store.t = t
	store.memorySessionStore = newMemorySessionStore(logger)
	sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	mp, _ := newTestMetrics(t)
	sessions := newLocalSessions(mp, sm, logger)
	sessions.timing = timing
	reg, err := store.Register(context.Background(), &Session{ID: "id", NodeAddr: "node", Generation: gen})
	require.NoError(t, err)
	conn := newCloser()
	_, err = sessions.add(reg, conn)
	require.NoError(t, err)
	t.Cleanup(func() { sessions.end(reg) })
	return sessions, reg, conn
}

// Renewing at half the TTL (5 s) < the budget, at 0.9 of it (9 s): each
// renewal comes well inside the lease it extends, and the next is due half a
// TTL after it, at 10 s and then 15 s. A keeper renewing at 0.6 of the TTL
// would still beat the budget, but miss each of these.
func TestLeaseKeeperRenewsAtHalfItsTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &leaseStore{ttl: keeperTTL}
		_, reg, conn := newKeeperFixtureWith(t, store, 1, defaultLeaseTiming)
		for n := int32(1); n <= 3; n++ {
			due := reg.ConfirmedAt.Add(time.Duration(n) * keeperTTL / 2)
			time.Sleep(time.Until(due) - time.Nanosecond)
			synctest.Wait() // every wake due before renewal n has run
			require.Equal(t, n-1, store.renews.Load(), "renewal %d came before half a TTL after the last", n)
			time.Sleep(time.Nanosecond)
			synctest.Wait() // renewal n, due half a TTL after the last, has run
			require.Equal(t, n, store.renews.Load(), "renewal %d didn't come half a TTL after the last", n)
		}
		require.False(t, conn.isClosed())
	})
}

// A renewal that hangs is cut off at the budget: the tunnel closes on time,
// not whenever the call gives up. That holds whether the call honours its
// context or, like a stuck HTTP request, ignores it. A legacy host's tunnel
// is never closed.
//
// The renewal goes out at half the TTL (5 s) < the budget (9 s), and still
// hangs at the budget, so a close then is the keeper's, not the call's. The
// legacy host is watched to 20 s, past the budget and the TTL both.
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
			synctest.Test(t, func(t *testing.T) {
				never, _ := newGate(t)
				store := &leaseStore{ttl: keeperTTL, renew: func(ctx context.Context, _ *Registration) error {
					if tc.honours {
						return blockUntil(ctx, never)
					}
					<-never
					return nil
				}}
				_, reg, conn := newKeeperFixtureWith(t, store, tc.gen, defaultLeaseTiming)
				if !tc.closes {
					time.Sleep(20 * time.Second)
					synctest.Wait() // every wake due in the first 20 s has run
					require.False(t, conn.isClosed(), "a legacy host's tunnel must not be closed")
					return
				}
				budget := reg.ConfirmedAt.Add(keeperTTL - leaseMargin(keeperTTL))
				time.Sleep(time.Until(budget) - time.Nanosecond)
				synctest.Wait() // every wake due before the budget has run
				require.False(t, conn.isClosed(), "closed before the budget")
				time.Sleep(time.Nanosecond)
				synctest.Wait() // the budget's own close has run
				require.True(t, conn.isClosed(), "a capable tunnel was held past its budget by a slow renewal")
				require.Equal(t, budget, conn.at, "closed other than at the budget")
			})
		})
	}
}

// Renewals fail from half the TTL on, and are retried 1, 2 and then 4 s apart:
// at 5, 6 and 8 s, and next at 12 s. The budget (9 s) falls between the last
// two, so a keeper that slept out its retry rather than only to the budget
// would close the tunnel at 12 s, past it.
func TestLeaseKeeperClosesACapableTunnelWhenRenewalsKeepFailing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &leaseStore{ttl: keeperTTL, renew: func(context.Context, *Registration) error { return errConsulDown }}
		_, reg, conn := newKeeperFixtureWith(t, store, 1, defaultLeaseTiming)
		budget := reg.ConfirmedAt.Add(keeperTTL - leaseMargin(keeperTTL))
		time.Sleep(time.Until(budget) - time.Nanosecond)
		synctest.Wait() // every renewal and retry due before the budget has run
		require.Equal(t, int32(3), store.renews.Load(), "the renewal at 5 s wasn't retried at 6 and 8 s")
		require.False(t, conn.isClosed(), "closed before the budget")
		time.Sleep(time.Nanosecond)
		synctest.Wait() // the budget's own close has run
		require.True(t, conn.isClosed(), "left open past the budget")
		require.Equal(t, budget, conn.at, "closed other than at the budget")
	})
}

// gatedReleaseStore holds Release until opened, standing in for a cleanup
// that blocks.
type gatedReleaseStore struct {
	*leaseStore
	gate <-chan struct{}
}

func (s *gatedReleaseStore) Release(ctx context.Context, reg *Registration) error {
	<-s.gate
	return s.leaseStore.Release(ctx, reg)
}

// A rebuild that is still running at its bound doesn't hold the close.
// 1. The rebuild's Reregister hangs, ignoring its context, and then succeeds.
// 2. The release of that late result is held too.
// 3. The connection must close at the bound, before either gate opens.
// 4. Once the gates open, the late registration is released after all.
//
// The loss is known at the first renewal (5 s), and the bound is 60 s after
// that, at 65 s. Reregister and Release are both held past it, so a close at
// 65 s is the keeper's own.
func TestLeaseKeeperClosesAtTheRebuildBoundWhateverCleanupIsDoing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rebuildGate, openRebuild := newGate(t)
		releaseGate, openRelease := newGate(t)
		lostAt := make(chan time.Time, 1)
		base := &leaseStore{t: t, ttl: keeperTTL, renew: func(context.Context, *Registration) error {
			// The keeper learns of the loss as this returns, at the same fake
			// instant, so its bound is this plus rebuildBound.
			select {
			case lostAt <- time.Now():
			default:
			}
			return ErrLeaseLost
		}}
		base.reregister = func(_ context.Context, reg *Registration) (*Registration, error) {
			<-rebuildGate // ignores ctx, as a stuck HTTP call would
			return base.memorySessionStore.Reregister(context.Background(), reg)
		}
		store := &gatedReleaseStore{leaseStore: base, gate: releaseGate}

		logger := logging.Must(logging.Console(), logging.Debug()).Logger
		base.memorySessionStore = newMemorySessionStore(logger)
		sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
		mp, _ := newTestMetrics(t)
		sessions := newLocalSessions(mp, sm, logger)
		sessions.timing = defaultLeaseTiming
		reg, err := base.Register(context.Background(), &Session{ID: "id", NodeAddr: "node", Generation: 1})
		require.NoError(t, err)
		conn := newCloser()
		_, err = sessions.add(reg, conn)
		require.NoError(t, err)
		// Ending the registration releases it, which waits on the release
		// gate, so the gates open first.
		t.Cleanup(func() {
			openRebuild()
			openRelease()
			sessions.end(reg)
		})

		var lost time.Time
		select {
		case lost = <-lostAt:
		case <-time.After(keeperTTL): // the first renewal is due at half of it
			t.Fatal("the first renewal never came")
		}
		bound := lost.Add(defaultLeaseTiming.rebuildBound)
		time.Sleep(time.Until(bound) - time.Nanosecond)
		synctest.Wait() // every wake due before the rebuild bound has run
		require.False(t, conn.isClosed(), "closed before the rebuild bound")
		time.Sleep(time.Nanosecond)
		synctest.Wait() // the rebuild bound's own close has run
		require.True(t, conn.isClosed(), "the close waited on a store call")
		require.Equal(t, bound, conn.at, "closed other than at the rebuild bound")

		openRebuild()   // the late success arrives
		openRelease()   // and its cleanup may proceed
		synctest.Wait() // the late registration's release has run
		_, err = base.Get("id")
		require.Error(t, err, "the late registration is released, conditionally")
	})
}

// A legacy host can't redial, so its connection stays open while the keeper
// rebuilds its lost lease: the rebuild bound, which closes a capable
// registration's connection 60 s after the loss its first renewal (5 s)
// reports, leaves it open, and so does a rebuild that fails. Each case is
// watched to just past 65 s, where a capable one closes.
func TestLeaseKeeperRebuildBoundSparesLegacyHosts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		reregister func(ctx context.Context, reg *Registration) (*Registration, error)
		msg        string
	}{
		// The rebuild hangs until its context ends, which for a legacy host
		// comes only when the registration does. A bound, 60 s after the loss
		// (65 s) < the end of the watch, would end the rebuild there, and the
		// keeper would close the connection as it gave up.
		{"hangs", func(ctx context.Context, _ *Registration) (*Registration, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}, "the rebuild bound closed a legacy host's connection"},
		// The rebuild fails at the loss (5 s) < the end of the watch, and on
		// every retry, so a keeper that closed the connection on a failed
		// rebuild would close it at 5 s. This case can't show a bound: the
		// retries come 55 s and 65 s after the loss, so a bound 60 s after it
		// would only cut a retry delay short, and a keeper cut short there
		// doesn't close a legacy host's connection either.
		{"keeps failing", func(context.Context, *Registration) (*Registration, error) {
			return nil, errConsulDown
		}, "a failed rebuild closed a legacy host's connection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				store := &leaseStore{
					ttl:        keeperTTL,
					renew:      func(context.Context, *Registration) error { return ErrLeaseLost },
					reregister: tc.reregister,
				}
				_, reg, conn := newKeeperFixtureWith(t, store, 0, defaultLeaseTiming)
				time.Sleep(time.Until(reg.ConfirmedAt.Add(keeperTTL/2 + defaultLeaseTiming.rebuildBound)))
				synctest.Wait() // every wake due by 65 s, where a capable registration's connection would close, has run
				time.Sleep(time.Nanosecond)
				synctest.Wait() // and every wake due a nanosecond after it
				require.False(t, conn.isClosed(), tc.msg)
			})
		})
	}
}

// A loss the first renewal (5 s) reports is rebuilt at once, before any retry
// delay, and the keeper goes on renewing the rebuilt lease half a TTL apart:
// at 10 s and then 15 s. A rebuild that waited out a retry (1 s) first would
// put those at 11 s and 16 s. A rebuild the store answers with ErrSuperseded
// closes the connection, at that registration's own first renewal.
func TestLeaseKeeperRebuildsAKnownLossAndStopsWhenSuperseded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var lost atomic.Bool
		lost.Store(true)
		store := &leaseStore{ttl: keeperTTL, renew: func(context.Context, *Registration) error {
			if lost.CompareAndSwap(true, false) {
				return ErrLeaseLost
			}
			return nil
		}}
		sessions, reg, conn := newKeeperFixtureWith(t, store, 1, defaultLeaseTiming)
		time.Sleep(time.Until(reg.ConfirmedAt.Add(keeperTTL / 2)))
		synctest.Wait() // the renewal at half the TTL, which reports the loss, and the rebuild it leads to have run
		require.Equal(t, int32(1), store.renews.Load(), "didn't renew at half its TTL")
		require.Equal(t, int32(1), store.reregisters.Load(), "the loss wasn't rebuilt at once")
		for n := int32(2); n <= 3; n++ {
			due := reg.ConfirmedAt.Add(time.Duration(n) * keeperTTL / 2)
			time.Sleep(time.Until(due) - time.Nanosecond)
			synctest.Wait() // every wake due before renewal n has run
			require.Equal(t, n-1, store.renews.Load(), "renewal %d came before half a TTL after the last", n)
			time.Sleep(time.Nanosecond)
			synctest.Wait() // renewal n, due half a TTL after the last, has run
			require.Equal(t, n, store.renews.Load(), "renewal %d didn't come half a TTL after the last", n)
		}
		require.True(t, sessions.active(reg))
		require.False(t, conn.isClosed())

		store2 := &leaseStore{ttl: keeperTTL,
			renew:      func(context.Context, *Registration) error { return ErrLeaseLost },
			reregister: func(context.Context, *Registration) (*Registration, error) { return nil, ErrSuperseded }}
		_, reg2, conn2 := newKeeperFixtureWith(t, store2, 1, defaultLeaseTiming)
		superseded := reg2.ConfirmedAt.Add(keeperTTL / 2)
		time.Sleep(time.Until(superseded) - time.Nanosecond)
		synctest.Wait() // every wake due before its first renewal has run
		require.False(t, conn2.isClosed(), "closed before its first renewal")
		time.Sleep(time.Nanosecond)
		synctest.Wait() // its first renewal, and the rebuild the store refuses, have run
		require.True(t, conn2.isClosed(), "superseded while rebuilding, but kept its connection")
		require.Equal(t, superseded, conn2.at, "closed other than at its first renewal")
	})
}

// A legacy host is spared the lease deadlines, not supersession: once a newer
// registration holds its ID, its connection is closed like any other, as soon
// as the renewal at half its TTL (5 s) leads to a rebuild the store refuses.
func TestLeaseKeeperClosesASupersededLegacyHost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &leaseStore{ttl: keeperTTL,
			renew:      func(context.Context, *Registration) error { return ErrLeaseLost },
			reregister: func(context.Context, *Registration) (*Registration, error) { return nil, ErrSuperseded }}
		_, reg, conn := newKeeperFixtureWith(t, store, 0, defaultLeaseTiming)
		superseded := reg.ConfirmedAt.Add(keeperTTL / 2)
		time.Sleep(time.Until(superseded) - time.Nanosecond)
		synctest.Wait() // every wake due before the renewal at half its TTL has run
		require.False(t, conn.isClosed(), "closed before its first renewal")
		time.Sleep(time.Nanosecond)
		synctest.Wait() // the renewal at half its TTL, and the rebuild the store refuses, have run
		require.True(t, conn.isClosed(), "a legacy registration superseded while rebuilding kept its connection")
		require.Equal(t, superseded, conn.at, "closed other than at its first renewal")
	})
}

// A rebuild that finishes after its registration ended leaves no entry behind.
// The rebuild starts at the first renewal (5 s), and is held there while the
// registration ends. The keeper has given up on it before its result arrives,
// so only the cleanup of an abandoned call can release that result; the
// cleanup of a result handed back to the keeper never sees it.
func TestLeaseKeeperNeverResurrectsAnEndedRegistration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		enter := sync.OnceFunc(func() { close(entered) })
		release, open := newGate(t)
		store := &leaseStore{ttl: keeperTTL, renew: func(context.Context, *Registration) error { return ErrLeaseLost }}
		store.reregister = func(_ context.Context, reg *Registration) (*Registration, error) {
			enter()
			<-release
			return store.memorySessionStore.Reregister(context.Background(), reg)
		}
		sessions, reg, _ := newKeeperFixtureWith(t, store, 1, defaultLeaseTiming)
		select {
		case <-entered:
		case <-time.After(keeperTTL): // the rebuild is due at the first renewal, at half of it
			t.Fatal("the rebuild never started")
		}
		sessions.end(reg)
		synctest.Wait() // the keeper has given up on the held rebuild
		open()
		synctest.Wait() // the rebuild has stored the entry again, and its result has been released
		_, err := store.Get("id")
		require.Error(t, err, "a rebuild that finished after its registration ended left its entry behind")
	})
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

// A capable registration taken over from another node is closed by its own
// keeper. The takeover leaves its lock session alive, so only the entry can
// tell the keeper it has lost the ID.
func TestLeaseKeeperClosesARegistrationTakenOverFromAnotherNode(t *testing.T) {
	sessions, _, _ := newConsulLeaseFixture(t)
	ctx, id := context.Background(), fmt.Sprintf("lease-taken-over-%d", time.Now().UnixNano())
	reg, _, err := sessions.sessionManager.Register(ctx, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	require.NoError(t, err)
	conn := newCloser()
	_, err = sessions.add(reg, conn)
	require.NoError(t, err)
	t.Cleanup(func() { sessions.end(reg) })

	consulURL, err := url.Parse(testhelpers.ConsulURL())
	require.NoError(t, err)
	other, err := newConsulSessionStore(consulURL, 10*time.Second, logging.Must(logging.Console(), logging.Debug()).Logger)
	require.NoError(t, err)
	t.Cleanup(func() { _ = other.Close() })
	next, err := other.Register(ctx, &Session{ID: id, NodeAddr: "b:22", Generation: 2})
	require.NoError(t, err)
	t.Cleanup(func() { _ = other.Release(context.Background(), next) })

	// The keeper renews at half the 10 s TTL.
	select {
	case <-conn.closed:
	case <-time.After(15 * time.Second):
		t.Fatal("a registration taken over by another node kept its connection")
	}
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
