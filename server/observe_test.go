package server

import (
	"context"
	"maps"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snapshots holds the latest view a store's watch delivered to an observer.
// The observer only stores it and pokes notify, and never blocks: observers
// run in turn on the watch's goroutine, holding up its next delivery, and a
// store a suite shares keeps every observer its tests subscribe. Keeping only
// the latest loses nothing a wait needs, since await is only for a state that
// lasts: each delivery is the whole state, so once one shows such a state,
// every later one does too until the test changes it.
type snapshots struct {
	mu      sync.Mutex
	entries map[string]StoreEntry
	seen    bool          // a delivery has arrived; until then entries says nothing
	notify  chan struct{} // cap 1: one wakeup stands for every delivery since the last
}

// observe subscribes to o's deliveries. Observe doesn't replay, so call it
// before the act whose result the test waits for.
func observe(t *testing.T, o interface {
	Observe(func(epoch, index uint64, entries map[string]StoreEntry))
}) *snapshots {
	t.Helper()
	s := &snapshots{notify: make(chan struct{}, 1)}
	o.Observe(func(_, _ uint64, entries map[string]StoreEntry) {
		s.mu.Lock()
		s.entries, s.seen = entries, true
		s.mu.Unlock()
		select {
		case s.notify <- struct{}{}:
		default:
		}
	})
	return s
}

// await returns the latest snapshot once ok accepts it, and fails the test if
// that takes longer than within. It judges the latest when called, and again
// after each wakeup. A state that a later delivery replaced between wakeups
// can be missed, so wait only for a state that lasts: an entry that stays
// until the test removes it, or its absence after that. ok reads only the
// entries, so a delivery from a new epoch is judged like any other.
func (s *snapshots) await(t *testing.T, within time.Duration, ok func(map[string]StoreEntry) bool) map[string]StoreEntry {
	t.Helper()
	deadline := time.NewTimer(within)
	defer deadline.Stop()
	for {
		s.mu.Lock()
		entries, seen := s.entries, s.seen
		s.mu.Unlock()
		if seen && ok(entries) {
			return entries
		}
		select {
		case <-s.notify:
		case <-deadline.C:
			s.mu.Lock()
			entries, seen = s.entries, s.seen
			s.mu.Unlock()
			if seen && ok(entries) {
				return entries
			}
			t.Fatalf("no delivery within %v showed the state waited for (any delivery: %v; the latest held %q)",
				within, seen, slices.Sorted(maps.Keys(entries)))
		}
	}
}

// present accepts a snapshot holding id at generation gen.
func present(id string, gen uint64) func(map[string]StoreEntry) bool {
	return func(entries map[string]StoreEntry) bool {
		e, ok := entries[id]
		return ok && e.Session.Generation == gen
	}
}

// presentRegistration accepts the exact registration, including its lease.
func presentRegistration(reg *Registration) func(map[string]StoreEntry) bool {
	return func(entries map[string]StoreEntry) bool {
		return present(reg.ID(), reg.Generation())(entries) && entries[reg.ID()].Lease == reg.lease
	}
}

// absent accepts a snapshot without id. A snapshot from before the act that
// removes id lacks it too, so await its presence on the same observer first.
func absent(id string) func(map[string]StoreEntry) bool {
	return func(entries map[string]StoreEntry) bool {
		_, ok := entries[id]
		return !ok
	}
}

// An observer subscribed before a registration sees the watch deliver it, and
// then deliver its release.
func TestObserveSeesPresenceThenAbsence(t *testing.T) {
	client := ownedConsulTestClient(t)
	consulURL, err := suiteConsulURL("observe")
	require.NoError(t, err)
	store, err := newConsulSessionStore(consulURL, time.Minute, sessionTestLogger)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, store.Close())
		assert.NoError(t, removeSuiteConsulData(client, store))
	})

	ctx := context.Background()
	deliveries := observe(t, store)
	reg, err := store.Register(ctx, &Session{ID: "id", NodeAddr: "node-a:22", Generation: 1})
	require.NoError(t, err)
	deliveries.await(t, 5*time.Second, present("id", 1))

	require.NoError(t, store.Release(ctx, reg))
	deliveries.await(t, 5*time.Second, absent("id"))
}

// Observers run one after another on the watch's goroutine, and a store a
// suite shares keeps every observer its tests subscribe. An observer nobody
// waits on must not hold up the deliveries that reach the ones after it.
//
// Each delivery runs off the test's goroutine, as the watch's do, so an
// observer that blocks stalls only its delivery's goroutine, and the await
// below fails at its bound rather than this test hanging inside the delivery.
// The two deliveries differ, present then absent, because the latest replaces
// whatever came before it.
func TestAnAbandonedObserverDoesNotStallLaterWaits(t *testing.T) {
	consul := newFakeConsul(t)
	store := newFakeConsulStore(t, consul)
	observe(t, store) // never awaited
	later := observe(t, store)

	ctx := context.Background()
	reg, err := store.Register(ctx, &Session{ID: "id", NodeAddr: "node-a:22", Generation: 1})
	require.NoError(t, err)
	go store.updateSessionReplica(consul.snapshot())
	later.await(t, 5*time.Second, present("id", 1))

	require.NoError(t, store.Release(ctx, reg))
	go store.updateSessionReplica(consul.snapshot())
	later.await(t, 5*time.Second, absent("id"))
}

// The first judgment predates the delivery, but the delivery is acknowledged
// before await selects an already expired deadline. Consume its notification
// so only the deadline is selectable: the last snapshot must still be judged.
func TestSnapshotAwaitRechecksDeliveryAtDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &snapshots{seen: true, notify: make(chan struct{}, 1)}
		checked, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		release := sync.OnceFunc(func() { close(resume) })
		t.Cleanup(release)
		first := true
		go func() {
			defer close(done)
			s.await(t, time.Second, func(entries map[string]StoreEntry) bool {
				if first {
					first = false
					close(checked)
					<-resume
					return false
				}
				return present("id", 1)(entries)
			})
		}()
		synctest.Wait()
		require.True(t, isDone(checked), "await never judged the first snapshot")
		time.Sleep(time.Second - time.Nanosecond)
		synctest.Wait()
		require.False(t, isDone(done), "await finished before its deadline")
		time.Sleep(time.Nanosecond)
		s.mu.Lock()
		s.entries = map[string]StoreEntry{"id": {Session: &Session{ID: "id", Generation: 1}}}
		s.mu.Unlock()
		s.notify <- struct{}{}
		<-s.notify
		release()
		synctest.Wait()
		require.True(t, isDone(done), "await did not finish at its deadline")
	})
}
