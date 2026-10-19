package server

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A Register's reply can reach its store late (#612): after a newer
// registration of the same ID has committed, after this store has cached that
// newer one, from its own reply or from the watch, or after the newer one has
// gone again. These tests take a late reply through its checkpoints, on a
// fakeConsul whose indexes rise with every change to the entry (lease
// creates, and destroys of a lease that doesn't hold the entry, take no
// index), with the watch's deliveries made by hand: the generated table in
// every order of A to D the code admits, and the hand rows past it. The
// checkpoints:
//
//	A    T1, generation 1, commits from this store: index 100, its own lease.
//	B    T1's reply is held, by this store's delayedTxnReply as its
//	     transaction 1. A and B are one step: the transport holds the reply
//	     once Consul has applied the transaction.
//	Cc   T2, generation 2 of the same ID, commits at index 101, from this
//	     store or from another store on the same Consul. Its reply is held,
//	     by this store's delayedTxnReply as its transaction 2, or by the
//	     other store's as its transaction 1.
//	Cr   T2's reply is released from that hold, and T2's Register returns.
//	W    This store's watch delivers the fake's current state, which shows T2.
//	D    T1's reply is released from its hold, and T1's Register returns.
//
// and, in the hand rows:
//
//	W1   A delivery of T1's own write, before anything else commits.
//	X    T2's entry goes: the other store's Release of T2.
//	WX   The delivery that shows X.
//	Δ    An empty delivery at an index below the last one: a new epoch.
//	lost In place of B: this store's lostTxnReply holds T1's reply, and
//	     retry lets it go. The reply is lost, and T1's Register tries again
//	     and returns.
//
// Every delivery, W, W1, WX and Δ, is a call to this store's
// updateSessionReplica, made by hand; no watch runs.
//
// Each step returns only once its checkpoint has been reached: a held reply's
// entered channel closing, a Register returning, or the call that makes the
// step, a delivery or the other store's release, returning.
//
// The orders the code doesn't admit, which neither table runs:
//   - B before A, or Cr before Cc: Consul replies only once it has applied
//     the transaction.
//   - Cc before A: T1's transaction is conditional on the entry T1 read
//     (absent, or at the index it read), so T2 committing first has T1
//     refused. That is a refusal, not a late reply.
//   - W showing T2 before Cc, or WX before X: a delivery shows only what has
//     committed.

// TestALateRegisterReplyInEveryOrder runs every order of Cc, Cr, W and D, after
// A B, that has Cc before Cr and before W, with T2 on this store and on
// another: 8 orders, 16 runs.
//
// At D, as soon as T1's Register returns, a late reply mustn't have replaced
// a newer write this store had already cached. Where W, or Cr on this store,
// came before D, the cache holds T2. Otherwise this store hasn't seen T2 (Cr
// on another store doesn't reach this cache), and it holds T1. The check runs
// at D, not at the end, because a later W or a later Cr on this store would
// repair an overwrite and hide it.
//
// Each run then ends with a final delivery and T1's release, as T1's node
// releases a registration it has refused, and T2 must keep everything: this
// store's cache, the entry under T2's lease, and Get. T1's lease is destroyed.
func TestALateRegisterReplyInEveryOrder(t *testing.T) {
	base := orders([]string{"Cc", "Cr", "W", "D"}, map[string][]string{"Cc": {"Cr", "W"}})
	require.Len(t, base, 8)
	for _, order := range base {
		for _, sameStore := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/sameStore=%t", strings.Join(order, " "), sameStore), func(t *testing.T) {
				h := newLateReply(t)
				h.commitHeld()
				h.run(order, sameStore)
				h.deliver()
				h.release1()
				h.requireKeepsT2()
			})
		}
	}
}

// TestALateRegisterReplyHandRows are the orders outside the generated table:
// T2 removed, an index drop, T1's own write delivered first, and a reply
// lost. Where a row needs T2, T2 registers on another store, so X, that
// store's release of T2, leaves this store's cache as it was.
func TestALateRegisterReplyHandRows(t *testing.T) {
	// Feasible: T1's reply can be held up past any number of watch
	// deliveries. The last one has already left T1's write out, so the reply
	// mustn't cache it: nothing would correct it before the next delivery.
	t.Run("A B Cc Cr W X WX D", func(t *testing.T) {
		h := newLateReply(t)
		h.commitHeld()
		h.commit2(false)
		h.return2()
		h.deliver()
		h.remove()
		h.deliver()
		h.resume()
		h.requireNotCached("the late reply cached a registration that was superseded and removed")
		h.requireNotFound()
	})

	// Feasible: the watch reports a state, not each change, so T2's commit
	// and its removal can reach this store as one delivery.
	t.Run("A B Cc Cr X WX D", func(t *testing.T) {
		h := newLateReply(t)
		h.commitHeld()
		h.commit2(false)
		h.return2()
		h.remove()
		h.deliver()
		h.resume()
		h.requireNotCached("the late reply cached a registration the last delivery had left out")
		h.requireNotFound()
	})

	// Feasible: T1's reply arrives after T2's removal commits and before the
	// watch delivers it. The cache still holds T2 at D, and the reply mustn't
	// replace it. The check is at D, because WX would remove an overwrite too,
	// and hide it.
	t.Run("A B Cc Cr W X D WX", func(t *testing.T) {
		h := newLateReply(t)
		h.commitHeld()
		h.commit2(false)
		h.return2()
		h.deliver()
		h.remove()
		h.resume()
		h.requireCached(2, h.reg2.lease, "the late reply replaced generation 2, which this store had cached")
		h.deliver()
		h.requireNotCached("a removed registration is still cached after the delivery that shows its removal")
	})

	// Feasible: the watch delivers T1's own write, then its index drops below
	// it, as it does when the entry with the highest index goes, or after a
	// restore, all before T1's reply arrives. The fake still holds T1, so Get
	// has something to read through to. D's index doesn't order against the
	// new epoch's, so the reply isn't cached: the empty delivery removed W1's
	// entry, and D can't put it back. Get's read-through, in the new epoch,
	// may cache it, so the cache is checked first.
	t.Run("A B W1 Δ D", func(t *testing.T) {
		h := newLateReply(t)
		h.commitHeld()
		h.deliver()
		h.requireCached(1, h.lease1, "the delivery of T1's write didn't cache it")
		h.deliverDrop()
		h.resume()
		h.requireNotCached("a reply from before the index drop was cached")
		s, err := h.store.Get(h.id)
		require.NoError(t, err, "the entry the store holds wasn't found")
		assert.Equal(t, uint64(1), s.Generation)
	})

	// Feasible: the watch can deliver T1's write before T1's reply arrives.
	// The reply describes the write the cache already holds, and leaves it.
	t.Run("A B W1 D", func(t *testing.T) {
		h := newLateReply(t)
		h.commitHeld()
		h.deliver()
		before, ok := h.store.cache.lookup(h.id)
		require.True(t, ok, "the delivery of T1's write didn't cache it")
		h.resume()
		h.requireCached(1, h.reg1.lease, "T1's own reply lost its entry")
		after, _ := h.store.cache.lookup(h.id)
		assert.Equal(t, before, after, "T1's reply changed the entry the watch had delivered")
		assert.Equal(t, h.reg1.index, after.index)
	})

	// Feasible: a transaction can commit and its reply still be lost, to a
	// client timeout or a dropped connection. The retry finds the entry under
	// its own lease (one lease serves every attempt), and takes that write as
	// its own.
	t.Run("A lost retry", func(t *testing.T) {
		h := newLateReply(t)
		h.loseReply()
		r := h.retry()
		require.NoError(t, r.err, "a registration whose reply was lost failed")
		assert.Equal(t, h.lease1, r.reg.lease, "the retry registered under another lease")
		pair := h.consul.entry()
		require.NotNil(t, pair, "the committed entry is gone")
		assert.Equal(t, r.reg.lease, pair.Session)
		assert.Equal(t, pair.ModifyIndex, r.reg.index)
	})

	// Feasible: T2 can register between the lost reply and T1's retry. The
	// retry finds T2's newer entry and is refused, and destroys its lease,
	// T1's own; T2's entry stays.
	t.Run("A lost Cc Cr retry", func(t *testing.T) {
		h := newLateReply(t)
		h.loseReply()
		h.commit2(false)
		h.return2()
		r := h.retry()
		require.ErrorIs(t, r.err, ErrSuperseded)
		assert.Contains(t, h.consul.destroyed(), h.lease1, "the refused retry didn't destroy its lease")
		assert.False(t, h.consul.live(h.lease1), "the refused retry's lease is live")
		pair := h.consul.entry()
		require.NotNil(t, pair, "T2's entry is gone")
		assert.Equal(t, h.reg2.lease, pair.Session, "T2's entry isn't under T2's lease")
		assert.Equal(t, uint64(2), storedSession(pair.Value).Generation)
		assert.True(t, h.consul.live(h.reg2.lease), "T2's lease isn't live")
	})
}

// orders returns every sequence of steps that respects before, where
// before[a] lists the steps a must precede. They come in the order steps
// lists its steps, so every run gets them in the same order. A constraint
// naming something that isn't a step panics: the constraint would quietly be
// ignored, admitting orders it forbids.
func orders(steps []string, before map[string][]string) [][]string {
	for a, bs := range before {
		for _, s := range append([]string{a}, bs...) {
			if !slices.Contains(steps, s) {
				panic(fmt.Sprintf("orders: %q isn't one of the steps %q", s, steps))
			}
		}
	}
	var all [][]string
	var walk func(order, rest []string)
	walk = func(order, rest []string) {
		if len(rest) == 0 {
			all = append(all, order)
			return
		}
		for i, s := range rest {
			// s can come next only if no step still to come must precede it.
			if slices.ContainsFunc(rest, func(p string) bool { return slices.Contains(before[p], s) }) {
				continue
			}
			walk(append(slices.Clone(order), s), slices.Delete(slices.Clone(rest), i, i+1))
		}
	}
	walk(nil, steps)
	return all
}

// lateReply is one run's fixture: a fakeConsul in monotonic mode, this store,
// which T1 registers from and whose cache the checks read, and another store
// on the same fake. No watch runs on either: a delivery is a call to
// updateSessionReplica, and the call returning is its acknowledgement.
type lateReply struct {
	t      *testing.T
	consul *fakeConsul
	id     string

	// store is this store, made by A on one of two transports: delay holds
	// the replies to its first and second transactions, T1's and, when T2
	// registers here too, T2's; lost holds T1's reply and then loses it.
	store      *consulSessionStore
	delay      *delayedTxnReply
	lost       *lostTxnReply
	resumeLost func()

	// other is the other store. Its transport holds its first transaction's
	// reply, T2's when T2 registers there.
	other      *consulSessionStore
	otherDelay *delayedTxnReply

	first, second <-chan registered // T1's and T2's Register results
	release2      func()            // releases T2's held reply
	reg1, reg2    *Registration
	// lease1 and lease2 are the leases T1 and T2 committed under, read from
	// the fake at A and Cc, before either reply.
	lease1, lease2 string
	delivered      uint64 // the index of this store's last delivery
}

func newLateReply(t *testing.T) *lateReply {
	consul := newFakeConsul(t, monotonicIndexes)
	h := &lateReply{
		t:          t,
		consul:     consul,
		id:         "late-reply",
		delay:      newDelayedTxnReply(http.DefaultTransport, 1, 2),
		lost:       &lostTxnReply{next: http.DefaultTransport, entered: make(chan struct{}), resume: make(chan struct{})},
		otherDelay: newDelayedTxnReply(http.DefaultTransport, 1),
	}
	h.resumeLost = sync.OnceFunc(func() { close(h.lost.resume) })
	h.other = newFakeConsulStoreWith(t, consul, h.otherDelay)
	// However the run ends, no Register is left waiting on a hold. This runs
	// before the fake's own cleanup closes it.
	t.Cleanup(func() {
		h.delay.release(1)
		h.delay.release(2)
		h.otherDelay.release(1)
		h.resumeLost()
	})
	return h
}

// commitHeld is A B: T1 registers from this store, and it returns once Consul
// has applied T1 and its reply is held.
func (h *lateReply) commitHeld() {
	h.t.Helper()
	h.begin(h.delay)
	receiveWithin(h.t, h.delay.entered(1), "T1 never committed")
	h.lease1 = h.committed(1)
}

// loseReply is A with the reply to be lost: T1 registers from this store, and
// it returns once Consul has applied T1 and its reply is held. retry loses
// the reply.
func (h *lateReply) loseReply() {
	h.t.Helper()
	h.begin(h.lost)
	receiveWithin(h.t, h.lost.entered, "T1 never committed")
	h.lease1 = h.committed(1)
}

// begin makes this store on rt and starts T1's Register from it.
func (h *lateReply) begin(rt http.RoundTripper) {
	h.t.Helper()
	require.Nil(h.t, h.store, "T1 registers once")
	h.store = newFakeConsulStoreWith(h.t, h.consul, rt)
	h.first = h.register(h.store, "node-a:22", 1)
}

// commit2 is Cc: T2, generation 2 of the same ID, registers from this store or
// the other, and it returns once Consul has applied T2 and T2's reply is held.
func (h *lateReply) commit2(sameStore bool) {
	h.t.Helper()
	store, node, entered, release := h.other, "node-b:22", h.otherDelay.entered(1), func() { h.otherDelay.release(1) }
	if sameStore {
		store, node, entered, release = h.store, "node-a:22", h.delay.entered(2), func() { h.delay.release(2) }
	}
	h.second, h.release2 = h.register(store, node, 2), release
	receiveWithin(h.t, entered, "T2 never committed")
	h.lease2 = h.committed(2)
}

// return2 is Cr: T2's reply is released, and it returns once T2's Register
// has.
func (h *lateReply) return2() {
	h.t.Helper()
	h.release2()
	r := receiveWithin(h.t, h.second, "T2's Register never returned")
	require.NoError(h.t, r.err, "T2 wasn't registered")
	h.reg2 = r.reg
}

// deliver is a delivery from this store's watch: the fake's current state,
// its entry if it has one, at its latest index.
func (h *lateReply) deliver() {
	index, pairs := h.consul.snapshot()
	h.store.updateSessionReplica(index, pairs)
	h.delivered = index
}

// remove is X: the other store releases T2, and the fake deletes the entry
// with T2's lease. This store hears of it only from a delivery.
func (h *lateReply) remove() {
	h.t.Helper()
	require.NotNil(h.t, h.reg2, "T2 hasn't returned, so there's nothing to release")
	require.NoError(h.t, h.other.Release(context.Background(), h.reg2))
	require.Nil(h.t, h.consul.entry(), "releasing T2 left its entry")
}

// deliverDrop is Δ: this store's watch delivers an empty snapshot at an index
// below its last delivery's, which starts a new epoch. The fake keeps what it
// holds.
func (h *lateReply) deliverDrop() {
	h.t.Helper()
	const dropped = 6
	require.Less(h.t, uint64(dropped), h.delivered, "the index didn't drop")
	h.store.updateSessionReplica(dropped, nil)
	h.delivered = dropped
}

// resume is D: T1's held reply is released, and it returns once T1's Register
// has.
func (h *lateReply) resume() {
	h.t.Helper()
	h.delay.release(1)
	r := receiveWithin(h.t, h.first, "T1's Register never returned")
	require.NoError(h.t, r.err, "T1 wasn't registered")
	h.reg1 = r.reg
}

// retry lets T1's held reply be lost, and returns the result of T1's
// Register, which tries again.
func (h *lateReply) retry() registered {
	h.t.Helper()
	h.resumeLost()
	return receiveWithin(h.t, h.first, "T1's Register never returned")
}

// release1 releases T1 from this store.
func (h *lateReply) release1() {
	h.t.Helper()
	require.NoError(h.t, h.store.Release(context.Background(), h.reg1))
}

// run takes the steps of order in turn, each acknowledged before the next,
// and checks the cache as soon as D returns.
func (h *lateReply) run(order []string, sameStore bool) {
	h.t.Helper()
	seen := make(map[string]bool)
	for _, step := range order {
		switch step {
		case "Cc":
			h.commit2(sameStore)
		case "Cr":
			h.return2()
		case "W":
			h.deliver()
		case "D":
			h.resume()
			h.requireAtD(seen, sameStore)
		default:
			h.t.Fatalf("no step %q", step)
		}
		seen[step] = true
	}
}

// requireAtD is the check at D, given the steps that came before it.
func (h *lateReply) requireAtD(seen map[string]bool, sameStore bool) {
	h.t.Helper()
	if seen["W"] || (sameStore && seen["Cr"]) {
		h.requireCached(2, h.lease2, "the late reply replaced generation 2, which this store had cached")
		return
	}
	h.requireCached(1, h.lease1, "this store hadn't seen generation 2, and didn't cache the reply")
}

// requireKeepsT2 is the end check, after the final delivery and T1's release.
func (h *lateReply) requireKeepsT2() {
	h.t.Helper()
	h.requireCached(2, h.reg2.lease, "T1's release dropped generation 2 from this store's cache")
	pair := h.consul.entry()
	require.NotNil(h.t, pair, "T2's entry is gone")
	assert.Equal(h.t, h.reg2.lease, pair.Session, "T2's entry isn't under T2's lease")
	assert.Equal(h.t, uint64(2), storedSession(pair.Value).Generation)
	assert.Contains(h.t, h.consul.destroyed(), h.reg1.lease, "T1's release didn't destroy its lease")
	assert.False(h.t, h.consul.live(h.reg1.lease), "T1's lease is live")
	s, err := h.store.Get(h.id)
	require.NoError(h.t, err)
	assert.Equal(h.t, uint64(2), s.Generation, "Get didn't find generation 2")
}

// requireCached requires this store's cache to hold gen under lease.
func (h *lateReply) requireCached(gen uint64, lease, msg string) {
	h.t.Helper()
	e, ok := h.store.cache.lookup(h.id)
	require.True(h.t, ok, "%s: nothing is cached", msg)
	require.Equal(h.t, gen, e.session.Generation, msg)
	require.Equal(h.t, lease, e.lease, msg)
}

func (h *lateReply) requireNotCached(msg string) {
	h.t.Helper()
	require.False(h.t, h.store.HasInCache(h.id), msg)
}

// requireNotFound requires Get to find no entry, in the cache or the fake.
func (h *lateReply) requireNotFound() {
	h.t.Helper()
	_, err := h.store.Get(h.id)
	var missing *ErrSessionNotFound
	require.ErrorAs(h.t, err, &missing, "a removed registration is still found")
}

// committed is the lease the fake's entry is held under, which has to be
// generation gen's.
func (h *lateReply) committed(gen uint64) string {
	h.t.Helper()
	pair := h.consul.entry()
	require.NotNil(h.t, pair, "generation %d committed no entry", gen)
	require.Equal(h.t, gen, storedSession(pair.Value).Generation, "the entry isn't generation %d's", gen)
	return pair.Session
}

// register starts a Register of generation gen of the ID from store, on node.
func (h *lateReply) register(store *consulSessionStore, node string, gen uint64) <-chan registered {
	done := make(chan registered, 1)
	go func() {
		reg, err := store.Register(context.Background(), &Session{ID: h.id, NodeAddr: node, Generation: gen})
		done <- registered{reg, err}
	}()
	return done
}

// receiveWithin is the next value from ch, or the zero value at once if ch is
// closed. It fails the test with what unless one comes within 5 s.
func receiveWithin[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	var v T
	select {
	case v = <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal(what)
	}
	return v
}
