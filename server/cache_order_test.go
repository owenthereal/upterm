package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/api/watch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A snapshot captured before a successful local delete must not bring the
// entry back. The fake's default indexes repeat across a delete; monotonic
// mode models a delete advancing the Consul index.
func TestLocalDeleteRejectsCapturedSnapshot(t *testing.T) {
	for _, monotonic := range []bool{false, true} {
		for _, operation := range []string{"Release", "Delete", "BatchDelete"} {
			for _, uncached := range []bool{false, true} {
				t.Run(fmt.Sprintf("monotonic=%t/%s/uncached=%t", monotonic, operation, uncached), func(t *testing.T) {
					var options []func(*fakeConsul)
					if monotonic {
						options = append(options, monotonicIndexes)
					}
					f := newFakeConsul(t, options...)
					store := newFakeConsulStore(t, f)
					reg, err := store.Register(context.Background(), &Session{ID: "captured", NodeAddr: "node:22", Generation: 1})
					if reg != nil {
						t.Cleanup(func() { assert.NoError(t, store.Release(context.Background(), reg)) })
					}
					require.NoError(t, err)
					index, pairs := f.snapshot()
					require.Len(t, pairs, 1)
					epoch := store.cache.Epoch()
					if uncached {
						store.cache.Evict(reg.ID(), reg.index, epoch)
						require.False(t, store.HasInCache(reg.ID()))
					}
					switch operation {
					case "Release":
						err = store.Release(context.Background(), reg)
					case "Delete":
						err = store.Delete(reg.ID())
					case "BatchDelete":
						err = store.BatchDelete([]string{reg.ID()})
					}
					require.NoError(t, err)
					require.Nil(t, f.entry())
					require.False(t, store.HasInCache(reg.ID()), "local deletion boundary")
					t.Logf("checkpoint=post-delete captured_index=%d delete_index=%d lease=%s epoch=%d uncached=%t", index, f.index(), reg.lease, epoch, uncached)
					if monotonic {
						require.Greater(t, f.index(), index)
					} else {
						require.Equal(t, index, f.index())
					}
					store.updateSessionReplica(index, pairs)
					require.False(t, store.HasInCache(reg.ID()), "captured pre-delete snapshot resurrected a locally removed registration before Get")
					_, err = store.Get(reg.ID())
					var missing *ErrSessionNotFound
					require.ErrorAs(t, err, &missing)
				})
			}
		}
	}
	t.Run("distinct-lease-uncached-floor", func(t *testing.T) {
		f := newFakeConsul(t, monotonicIndexes)
		store := newFakeConsulStore(t, f)
		reg1, err := store.Register(context.Background(), &Session{ID: "floor", NodeAddr: "node:22", Generation: 1})
		if reg1 != nil {
			t.Cleanup(func() { assert.NoError(t, store.Release(context.Background(), reg1)) })
		}
		require.NoError(t, err)
		index, pairs := f.snapshot()
		reg2, err := store.Register(context.Background(), &Session{ID: reg1.ID(), NodeAddr: "node:22", Generation: 2})
		if reg2 != nil {
			t.Cleanup(func() { assert.NoError(t, store.Release(context.Background(), reg2)) })
		}
		require.NoError(t, err)
		require.NotEqual(t, reg1.lease, reg2.lease)
		store.cache.Evict(reg2.ID(), reg2.index, store.cache.Epoch())
		require.False(t, store.HasInCache(reg2.ID()))
		require.NoError(t, store.Release(context.Background(), reg2))
		require.Nil(t, f.entry())
		require.False(t, store.HasInCache(reg2.ID()))
		t.Logf("checkpoint=uncached-floor captured_index=%d released_index=%d captured_lease=%s released_lease=%s epoch=%d", index, reg2.index, reg1.lease, reg2.lease, store.cache.Epoch())
		store.updateSessionReplica(index, pairs)
		require.False(t, store.HasInCache(reg2.ID()), "older distinct lease crossed the uncached local removal floor before Get")
		_, err = store.Get(reg2.ID())
		var missing *ErrSessionNotFound
		require.ErrorAs(t, err, &missing)
	})
}

// A read-through reply that completed before a local delete, but reaches the
// cache after it, must not bring the entry back.
func TestLocalDeleteRejectsHeldReadReply(t *testing.T) {
	for _, uncached := range []bool{false, true} {
		t.Run(fmt.Sprintf("uncached=%t", uncached), func(t *testing.T) {
			f := newFakeConsul(t, monotonicIndexes)
			next := ownedHTTPTransport(t)
			entered, resume := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(resume) })
			var armed atomic.Bool
			rt := closeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				response, err := next.RoundTrip(r)
				if r.Method == http.MethodGet && r.URL.Path == "/v1/kv/fake/sessions/held-read" && armed.CompareAndSwap(true, false) {
					close(entered) // The fake has completed this particular read.
					<-resume
				}
				return response, err
			})
			store := newFakeConsulStoreWith(t, f, rt)
			var done chan struct{}
			// Cleanup runs before store.Close and the fake server's close, even on Fatal.
			t.Cleanup(func() {
				release()
				if done != nil {
					receiveWithin(t, done, "held GetFresh did not join")
				}
			})
			reg, err := store.Register(context.Background(), &Session{ID: "held-read", NodeAddr: "node:22", Generation: 1})
			if reg != nil {
				t.Cleanup(func() {
					release()
					if done != nil {
						receiveWithin(t, done, "held GetFresh did not join")
					}
					assert.NoError(t, store.Release(context.Background(), reg))
				})
			}
			require.NoError(t, err)
			if uncached {
				store.cache.Evict(reg.ID(), reg.index, store.cache.Epoch())
				require.False(t, store.HasInCache(reg.ID()))
			}
			var got *Session
			var readErr error
			done = make(chan struct{})
			armed.Store(true)
			go func() { defer close(done); got, readErr = store.GetFresh(context.Background(), reg.ID()) }()
			receiveWithin(t, entered, "intended GET response never completed")
			require.NoError(t, store.Release(context.Background(), reg))
			require.Nil(t, f.entry())
			require.False(t, store.HasInCache(reg.ID()), "local deletion boundary")
			t.Logf("checkpoint=read-held-after-delete index=%d lease=%s epoch=%d uncached=%t", reg.index, reg.lease, store.cache.Epoch(), uncached)
			release()
			receiveWithin(t, done, "held GetFresh never returned")
			require.NoError(t, readErr)
			require.NotNil(t, got)
			require.Equal(t, uint64(1), got.Generation, "the completed read may return its captured value")
			require.False(t, store.HasInCache(reg.ID()), "held successful read resurrected a locally removed registration")
		})
	}
}

// This assembles the production watcher, Plan, replica and observer. It does
// not test startSessionWatch's client construction or prove service freshness.
func TestConsulCacheWatchDeliveryBoundaries(t *testing.T) {
	for _, equalIndex := range []bool{true, false} {
		t.Run(fmt.Sprintf("equal-index=%t", equalIndex), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				logger := slog.New(slog.DiscardHandler)
				store := &consulSessionStore{logger: logger, cache: newSessionCache(logger), held: map[string]map[string]heldWrite{"watch": {"lease-watch": {index: 100, epoch: 0}}}}
				session := &Session{ID: "watch", NodeAddr: "node:22", Generation: 1}
				store.cache.Set(session.ID, cachedSession{session: session, index: 100, lease: "lease-watch"}, store.cache.Epoch())
				value, err := json.Marshal(session)
				require.NoError(t, err)
				present, err := json.Marshal(api.KVPairs{&api.KVPair{Key: "fake/sessions/watch", Value: value, ModifyIndex: 100, Session: "lease-watch"}})
				require.NoError(t, err)
				// Query 1 is captured before the local delete. Query 2 is empty. Queries
				// 3 and 4 exercise healthy dedup. Query 5 is a later-started stale changed
				// response, as a default read may return during a leader election.
				indexes := []uint64{100, 101, 101, 101, 104}
				if !equalIndex {
					indexes = []uint64{100, 101, 102, 103, 104}
				}
				bodies := []string{string(present), "[]", "[]", "[]", string(present)}
				entered := make(chan int, 8)
				returned := make(chan int, 8)
				captured := make(chan int, 8)
				gates := make([]chan struct{}, len(bodies))
				releases := make([]func(), len(bodies))
				for i := range gates {
					gates[i] = make(chan struct{})
					releases[i] = sync.OnceFunc(func() { close(gates[i]) })
				}
				observerEntered, observerResume := make(chan struct{}), make(chan struct{})
				releaseObserver := sync.OnceFunc(func() { close(observerResume) })
				var handlers, observers, queries int
				var rawViews []map[string]StoreEntry
				store.Observe(func(epoch, index uint64, entries map[string]StoreEntry) {
					observers++
					rawViews = append(rawViews, entries)
					t.Logf("checkpoint=observer ordinal=%d index=%d epoch=%d entries=%d", observers, index, epoch, len(entries))
					if observers == 1 {
						close(observerEntered)
						<-observerResume
					}
				})
				cfg := api.DefaultConfig()
				cfg.Address = "127.0.0.1:1"
				cfg.HttpClient = &http.Client{Timeout: 0, Transport: closeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					i := queries - 1
					if i >= len(bodies) {
						<-r.Context().Done()
						return nil, r.Context().Err()
					}
					captured <- i + 1
					select {
					case <-gates[i]:
					case <-r.Context().Done():
						return nil, r.Context().Err()
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"X-Consul-Index": {fmt.Sprint(indexes[i])}}, Body: io.NopCloser(strings.NewReader(bodies[i]))}, nil
				})}
				client, err := api.NewClient(cfg)
				require.NoError(t, err)
				plan, err := watch.Parse(map[string]interface{}{"type": "keyprefix", "prefix": "fake/sessions/"})
				require.NoError(t, err)
				watcher := consulSessionWatcher(ctx, client, "fake/sessions/")
				plan.Watcher = func(p *watch.Plan) (watch.BlockingParamVal, interface{}, error) {
					queries++
					n := queries
					entered <- n
					index, data, err := watcher(p)
					returned <- n
					return index, data, err
				}
				plan.Handler = func(index uint64, data interface{}) {
					handlers++
					store.updateSessionReplica(index, data.(api.KVPairs))
				}
				finished := make(chan error, 1)
				t.Cleanup(func() {
					for _, release := range releases {
						release()
					}
					releaseObserver()
					plan.Stop()
					cancel()
					require.NoError(t, <-finished)
				})
				go func() { finished <- plan.RunWithClientAndHclog(client, nil) }()
				require.Equal(t, 1, <-entered)
				require.Equal(t, 1, <-captured)
				// forget is the held-map and cache transition a successful release makes;
				// calling it directly keeps the release off the scripted transport.
				store.forget(session.ID, "lease-watch")
				require.False(t, store.HasInCache(session.ID))
				require.Empty(t, store.held)
				releases[0]()
				require.Equal(t, 1, <-returned)
				<-observerEntered
				synctest.Wait()
				require.Equal(t, 1, queries, "query 2 entered while synchronous observer was held")
				require.False(t, store.HasInCache(session.ID), "captured snapshot crossed local deletion before observer entry")
				require.Equal(t, "lease-watch", rawViews[0][session.ID].Lease)
				require.Equal(t, uint64(1), rawViews[0][session.ID].Session.Generation)
				releaseObserver()
				require.Equal(t, 2, <-entered)
				for ordinal := 2; ordinal <= 4; ordinal++ {
					require.Equal(t, ordinal, <-captured)
					releases[ordinal-1]()
					require.Equal(t, ordinal, <-returned)
					require.Equal(t, ordinal+1, <-entered) // Plan processed the preceding result.
					synctest.Wait()
					require.Equal(t, 2, handlers, "healthy unchanged result unexpectedly delivered")
					require.Equal(t, 2, observers, "healthy unchanged result unexpectedly notified")
					require.False(t, store.HasInCache(session.ID))
				}
				require.Equal(t, 5, <-captured)
				releases[4]()
				require.Equal(t, 5, <-returned)
				require.Equal(t, 6, <-entered)
				synctest.Wait()
				require.Equal(t, 3, handlers)
				require.Equal(t, 3, observers)
				require.False(t, store.HasInCache(session.ID), "changed stale content crossed local deletion")
				require.Equal(t, "lease-watch", rawViews[2][session.ID].Lease)
				require.Equal(t, uint64(1), rawViews[2][session.ID].Session.Generation)
			})
		})
	}
}

// Each row distinguishes the local release floor from the released lease.
// The two insertion paths use independent caches, so one cannot repair the other.
func TestSessionCacheLocalDeleteFiltering(t *testing.T) {
	rows := []struct {
		name, id, lease   string
		index, generation uint64
		present           bool
	}{
		{"older-other-lease", "A", "L1", 100, 1, false},
		{"equal-index-other-lease", "A", "L1", 101, 1, false},
		{"released-lease-higher-index", "A", "L2", 110, 2, false},
		{"newer-different-lease", "A", "L3", 102, 3, true},
		{"unrelated-id", "B", "lease-B", 100, 1, true},
		{"uncached-held-floor", "A", "L1", 100, 1, false},
		{"matching-cache-strengthens-floor", "A", "L1", 105, 1, false},
		{"foreign-cache-does-not-strengthen-floor", "A", "L4", 110, 4, true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			for _, snapshot := range []bool{false, true} {
				c := newSessionCache(slog.New(slog.DiscardHandler))
				epoch := c.Epoch()
				floor := uint64(101)
				switch row.name {
				case "uncached-held-floor":
					c.Set("A", cachedSession{session: &Session{ID: "A", Generation: 2}, index: 101, lease: "L2"}, epoch)
					c.Evict("A", 101, epoch)
					require.False(t, c.Has("A"))
				case "matching-cache-strengthens-floor":
					c.Set("A", cachedSession{session: &Session{ID: "A", Generation: 2}, index: 110, lease: "L2"}, epoch)
					floor = 110
				case "foreign-cache-does-not-strengthen-floor":
					c.Set("A", cachedSession{session: &Session{ID: "A", Generation: 3}, index: 120, lease: "L3"}, epoch)
				}
				c.Delete("A", "L2", heldWrite{index: 101, epoch: epoch})
				if row.name == "foreign-cache-does-not-strengthen-floor" {
					entry, ok := c.lookup("A")
					if assert.True(t, ok, "release removed newer different lease") {
						assert.Equal(t, "L3", entry.lease)
						if assert.NotNil(t, entry.session) {
							assert.Equal(t, uint64(3), entry.session.Generation)
						}
					}
					c.Evict("A", 120, epoch)
				}
				candidate := cachedSession{session: &Session{ID: row.id, Generation: row.generation}, index: row.index, lease: row.lease}
				if snapshot {
					c.ReplaceAll(130, map[string]cachedSession{row.id: candidate})
				} else {
					c.Set(row.id, candidate, epoch)
				}
				entry, ok := c.lookup(row.id)
				require.Equal(t, row.present, ok, "snapshot=%t", snapshot)
				if row.present {
					require.Equal(t, candidate, entry, "snapshot=%t", snapshot)
				}
				require.Equal(t, floor, c.removed["A"].index)
				require.Contains(t, c.removed["A"].leases, "L2")
			}
		})
	}
	t.Run("delete-prunes-already-cached-older-lease", func(t *testing.T) {
		c := newSessionCache(slog.New(slog.DiscardHandler))
		epoch := c.Epoch()
		c.Set("A", cachedSession{session: &Session{ID: "A", Generation: 1}, index: 100, lease: "L1"}, epoch)
		require.True(t, c.Has("A"))
		c.Delete("A", "L2", heldWrite{index: 101, epoch: epoch})
		require.False(t, c.Has("A"), "Delete left an already-cached older different lease")
		require.Equal(t, uint64(101), c.removed["A"].index)
		require.Contains(t, c.removed["A"].leases, "L2")
	})
}

// A release record lasts until an observed index drop starts a new epoch:
// ordinary deliveries, Evict and a first low snapshot keep it, and a held
// write from an older epoch contributes no floor.
func TestSessionCacheDeletionEvidenceLifecycle(t *testing.T) {
	entry := func(lease string, index, generation uint64) cachedSession {
		return cachedSession{session: &Session{ID: "A", Generation: generation}, index: index, lease: lease}
	}
	for _, name := range []string{"first-low-absence", "ordinary-deliveries-retain", "coalesced-leases", "observed-drop", "old-epoch-held-index", "evict-retains", "unknown-held-write"} {
		t.Run(name, func(t *testing.T) {
			c := newSessionCache(slog.New(slog.DiscardHandler))
			epoch := c.Epoch()
			switch name {
			case "first-low-absence":
				c.Delete("A", "L2", heldWrite{index: 101, epoch: epoch})
				c.ReplaceAll(5, map[string]cachedSession{})
				require.Equal(t, epoch, c.Epoch())
				require.Len(t, c.removed, 1)
				c.Set("A", entry("L1", 100, 1), epoch)
				require.False(t, c.Has("A"))
			case "ordinary-deliveries-retain":
				c.Delete("A", "L2", heldWrite{index: 101, epoch: epoch})
				for i := 0; i < 2; i++ {
					c.ReplaceAll(102, map[string]cachedSession{})
					require.Len(t, c.removed, 1)
					require.Contains(t, c.removed["A"].leases, "L2")
				}
				c.ReplaceAll(111, map[string]cachedSession{"A": entry("L2", 110, 2)})
				require.False(t, c.Has("A"))
				require.Len(t, c.removed, 1)
			case "coalesced-leases":
				c.Delete("A", "L2", heldWrite{index: 101, epoch: epoch})
				c.Delete("A", "L3", heldWrite{index: 103, epoch: epoch})
				c.Delete("B", "LB", heldWrite{index: 104, epoch: epoch})
				c.Delete("A", "L2", heldWrite{index: 101, epoch: epoch})
				require.Len(t, c.removed, 2)
				require.Equal(t, uint64(103), c.removed["A"].index)
				require.Equal(t, map[string]struct{}{"L2": {}, "L3": {}}, c.removed["A"].leases)
				for _, candidate := range []cachedSession{entry("L2", 110, 2), entry("L3", 111, 3), entry("L1", 102, 1)} {
					c.Set("A", candidate, epoch)
					require.False(t, c.Has("A"), "coalesced exclusion lost %s@%d", candidate.lease, candidate.index)
				}
			case "observed-drop":
				c.ReplaceAll(200, map[string]cachedSession{})
				c.Delete("A", "L2", heldWrite{index: 201, epoch: epoch})
				low := entry("L2", 4, 2)
				c.ReplaceAll(5, map[string]cachedSession{"A": low})
				require.Equal(t, epoch+1, c.Epoch())
				require.Empty(t, c.removed)
				got, ok := c.lookup("A")
				require.True(t, ok)
				require.Equal(t, low, got)
				for _, candidate := range []cachedSession{entry("L2", 6, 3), entry("L3", 7, 4)} {
					c.Set("A", candidate, c.Epoch())
					got, ok = c.lookup("A")
					require.True(t, ok)
					require.Equal(t, candidate, got)
				}
			case "old-epoch-held-index":
				c.ReplaceAll(200, map[string]cachedSession{})
				c.ReplaceAll(5, map[string]cachedSession{})
				c.Delete("A", "L2", heldWrite{index: 200, epoch: epoch})
				require.Zero(t, c.removed["A"].index)
				c.Set("A", entry("L2", 6, 2), c.Epoch())
				require.False(t, c.Has("A"), "old-epoch release lost its identity")
				candidate := entry("L3", 6, 3)
				c.Set("A", candidate, c.Epoch())
				got, ok := c.lookup("A")
				require.True(t, ok)
				require.Equal(t, candidate, got)
				c.Set("A", entry("L4", 7, 4), epoch)
				got, _ = c.lookup("A")
				require.Equal(t, candidate, got, "old epoch Set crossed reset")
			case "evict-retains":
				c.Delete("A", "L2", heldWrite{index: 101, epoch: epoch})
				c.Set("A", entry("L3", 110, 3), epoch)
				require.True(t, c.Has("A"))
				c.Evict("A", 110, epoch)
				require.False(t, c.Has("A"))
				assert.Contains(t, c.removed["A"].leases, "L2")
				c.Set("A", entry("L2", 120, 2), epoch)
				require.False(t, c.Has("A"))
			case "unknown-held-write":
				c.Delete("A", "L2", heldWrite{})
				require.Zero(t, c.removed["A"].index)
				require.Contains(t, c.removed["A"].leases, "L2")
				candidate := entry("L1", 1, 1)
				c.Set("A", candidate, epoch)
				got, ok := c.lookup("A")
				require.True(t, ok)
				require.Equal(t, candidate, got)
				c.Set("A", entry("L2", 2, 2), epoch)
				got, _ = c.lookup("A")
				require.Equal(t, candidate, got)
			}
		})
	}
}

// Releasing an older lease keeps a newer registration cached and held.
// Releases made while nothing is cached coalesce into one record that still
// excludes a captured older snapshot, and a failed release records nothing.
func TestLocalDeletePreservesSuccessor(t *testing.T) {
	for _, name := range []string{"release-older-held-lease", "coalesce-uncached-releases", "failed-release"} {
		t.Run(name, func(t *testing.T) {
			f := newFakeConsul(t, monotonicIndexes)
			store := newFakeConsulStore(t, f)
			var regs []*Registration
			t.Cleanup(func() {
				for _, reg := range regs {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					assert.NoError(t, store.Release(ctx, reg))
					cancel()
				}
			})
			register := func(generation uint64) *Registration {
				reg, err := store.Register(context.Background(), &Session{ID: "successor", NodeAddr: "node:22", Generation: generation})
				if reg != nil {
					regs = append(regs, reg)
				}
				require.NoError(t, err)
				return reg
			}
			first := register(1)
			index, pairs := f.snapshot()
			switch name {
			case "release-older-held-lease":
				second := register(2)
				index, pairs = f.snapshot()
				require.NoError(t, store.Release(context.Background(), first))
				for delivery := 0; delivery < 2; delivery++ {
					if delivery == 1 {
						store.updateSessionReplica(index, pairs)
					}
					cached, ok := store.cache.lookup(second.ID())
					require.True(t, ok, "release lost successor before Get; delivery=%d", delivery)
					require.Equal(t, second.lease, cached.lease)
					require.Equal(t, uint64(2), cached.session.Generation)
					require.True(t, holdsLease(store, second.ID(), second.lease))
					require.False(t, holdsLease(store, first.ID(), first.lease))
					pair := f.entry()
					require.NotNil(t, pair)
					require.Equal(t, second.lease, pair.Session)
					var backend Session
					require.NoError(t, json.Unmarshal(pair.Value, &backend))
					require.Equal(t, uint64(2), backend.Generation)
					got, err := store.Get(second.ID())
					require.NoError(t, err)
					require.Equal(t, second.Session, got)
				}
			case "coalesce-uncached-releases":
				second, third := register(2), register(3)
				store.cache.Evict(third.ID(), third.index, store.cache.Epoch())
				require.False(t, store.HasInCache(third.ID()))
				require.NoError(t, store.Release(context.Background(), second))
				require.NoError(t, store.Release(context.Background(), third))
				require.Equal(t, third.index, store.cache.removed[first.ID()].index)
				require.Equal(t, map[string]struct{}{second.lease: {}, third.lease: {}}, store.cache.removed[first.ID()].leases)
				require.Nil(t, f.entry())
				require.False(t, store.HasInCache(first.ID()))
				store.updateSessionReplica(index, pairs)
				require.False(t, store.HasInCache(first.ID()), "captured oldest lease crossed coalesced releases")
				_, err := store.Get(first.ID())
				var missing *ErrSessionNotFound
				require.ErrorAs(t, err, &missing)
			case "failed-release":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				require.Error(t, store.Release(ctx, first))
				require.True(t, holdsLease(store, first.ID(), first.lease))
				cached, ok := store.cache.lookup(first.ID())
				require.True(t, ok)
				require.Equal(t, first.lease, cached.lease)
				require.Equal(t, first.Session, cached.session)
				require.Equal(t, pairs[0], f.entry())
				require.Empty(t, store.cache.removed)
			}
		})
	}
}

// Equal results suppress Plan callbacks even as successful local releases
// accumulate. A later changed result must still pass through those exclusions.
func TestLocalDeleteRetainsEvidenceThroughDeduplicatedQueries(t *testing.T) {
	for _, equalIndex := range []bool{true, false} {
		t.Run(fmt.Sprintf("equal-index=%t", equalIndex), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				logger := slog.New(slog.DiscardHandler)
				store := &consulSessionStore{logger: logger, cache: newSessionCache(logger), held: make(map[string]map[string]heldWrite)}
				pair := func(id, lease string, generation, index uint64) *api.KVPair {
					value, err := json.Marshal(&Session{ID: id, NodeAddr: "node:22", Generation: generation})
					require.NoError(t, err)
					return &api.KVPair{Key: "fake/sessions/" + id, Value: value, ModifyIndex: index, Session: lease}
				}
				stale := api.KVPairs{pair("A", "LA1", 1, 190), pair("C", "LC", 3, 191)}
				low := api.KVPairs{pair("A", "LA1", 1, 4)}
				results := []api.KVPairs{{}, {}, {}, stale, low}
				bodies := make([]string, len(results))
				for i, result := range results {
					body, err := json.Marshal(result)
					require.NoError(t, err)
					bodies[i] = string(body)
				}
				indexes := []uint64{100, 100, 100, 200, 5}
				if !equalIndex {
					indexes[1], indexes[2] = 101, 102
				}
				gates := make([]chan struct{}, len(results))
				releases := make([]func(), len(results))
				for i := range gates {
					gates[i] = make(chan struct{})
					releases[i] = sync.OnceFunc(func() { close(gates[i]) })
				}
				entered := make(chan int, 8)
				observerEntered, observerResume := make(chan struct{}), make(chan struct{})
				releaseObserver := sync.OnceFunc(func() { close(observerResume) })
				var queries, handlers int
				var views []map[string]StoreEntry
				var epochs []uint64
				store.Observe(func(epoch, index uint64, entries map[string]StoreEntry) {
					views = append(views, entries)
					epochs = append(epochs, epoch)
					if len(views) == 1 {
						close(observerEntered)
						<-observerResume
					}
				})
				cfg := api.DefaultConfig()
				cfg.Address = "127.0.0.1:1"
				cfg.HttpClient = &http.Client{Transport: closeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					i := queries - 1
					if i >= len(bodies) {
						<-r.Context().Done()
						return nil, r.Context().Err()
					}
					select {
					case <-gates[i]:
					case <-r.Context().Done():
						return nil, r.Context().Err()
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"X-Consul-Index": {fmt.Sprint(indexes[i])}}, Body: io.NopCloser(strings.NewReader(bodies[i]))}, nil
				})}
				client, err := api.NewClient(cfg)
				require.NoError(t, err)
				plan, err := watch.Parse(map[string]interface{}{"type": "keyprefix", "prefix": "fake/sessions/"})
				require.NoError(t, err)
				watcher := consulSessionWatcher(ctx, client, "fake/sessions/")
				plan.Watcher = func(p *watch.Plan) (watch.BlockingParamVal, interface{}, error) {
					queries++
					entered <- queries
					return watcher(p)
				}
				plan.Handler = func(index uint64, data interface{}) {
					handlers++
					store.updateSessionReplica(index, data.(api.KVPairs))
				}
				finished := make(chan error, 1)
				t.Cleanup(func() {
					for _, release := range releases {
						release()
					}
					releaseObserver()
					plan.Stop()
					cancel()
					require.NoError(t, <-finished)
				})
				go func() { finished <- plan.RunWithClientAndHclog(client, nil) }()
				require.Equal(t, 1, <-entered)
				releases[0]()
				<-observerEntered
				synctest.Wait() // The initial observer is parked and no next query can enter.
				require.Equal(t, 1, queries)
				releaseObserver()
				require.Equal(t, 2, <-entered)
				// These apply the held-map and cache transitions of successful local
				// registrations and releases; a scripted response never stands in for one.
				remove := func(id, lease string, index uint64) {
					write := heldWrite{index: index, epoch: store.cache.Epoch()}
					store.heldMu.Lock()
					if store.held[id] == nil {
						store.held[id] = make(map[string]heldWrite)
					}
					store.held[id][lease] = write
					store.cache.Set(id, cachedSession{session: &Session{ID: id, Generation: 1}, index: index, lease: lease}, write.epoch)
					store.heldMu.Unlock()
					store.forget(id, lease)
					require.False(t, store.HasInCache(id))
				}
				remove("A", "LA1", 110)
				remove("B", "LB", 111)
				releases[1]()
				require.Equal(t, 3, <-entered)
				synctest.Wait() // Plan has deduplicated query 2 and parked in query 3.
				require.Equal(t, 1, handlers)
				require.Len(t, views, 1)
				remove("A", "LA2", 112)
				releases[2]()
				require.Equal(t, 4, <-entered)
				synctest.Wait() // Plan has deduplicated query 3 and parked in query 4.
				require.Equal(t, 1, handlers)
				require.Len(t, views, 1)
				require.Empty(t, store.held)
				require.Len(t, store.cache.removed, 2)
				require.Equal(t, map[string]struct{}{"LA1": {}, "LA2": {}}, store.cache.removed["A"].leases)
				require.Equal(t, map[string]struct{}{"LB": {}}, store.cache.removed["B"].leases)
				releases[3]()
				require.Equal(t, 5, <-entered)
				synctest.Wait() // The changed result and its raw observer delivery are complete.
				require.Equal(t, 2, handlers)
				require.Len(t, views, 2)
				require.False(t, store.HasInCache("A"), "deduplicated responses forgot released identity")
				cached, ok := store.cache.lookup("C")
				require.True(t, ok)
				require.Equal(t, "LC", cached.lease)
				require.Equal(t, uint64(3), cached.session.Generation)
				require.Len(t, views[1], 2)
				require.Equal(t, "LA1", views[1]["A"].Lease)
				require.Equal(t, uint64(1), views[1]["A"].Session.Generation)
				require.Equal(t, StoreEntry{Session: cached.session, Lease: "LC"}, views[1]["C"])
				require.Len(t, store.cache.removed, 2)
				releases[4]()
				require.Equal(t, 6, <-entered)
				synctest.Wait() // The drop result and its new-epoch observer delivery are complete.
				require.Equal(t, 3, handlers)
				require.Len(t, views, 3)
				require.Equal(t, []uint64{0, 0, 1}, epochs)
				require.Equal(t, uint64(1), store.cache.Epoch())
				require.Empty(t, store.cache.removed)
				cached, ok = store.cache.lookup("A")
				require.True(t, ok)
				require.Equal(t, "LA1", cached.lease)
				require.Equal(t, uint64(1), cached.session.Generation)
				require.Equal(t, uint64(4), cached.index)
				require.Len(t, views[2], 1)
				require.Equal(t, StoreEntry{Session: cached.session, Lease: "LA1"}, views[2]["A"])
			})
		})
	}
}
