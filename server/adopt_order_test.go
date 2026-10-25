package server

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// Adoption is where a registration the store has taken becomes the one this
// node serves: add gives it a slot, and confirm then checks the store's view
// of it again. A watch delivery can be processed anywhere around those two
// steps, and so can the write it shows. These tests take adoption through its
// checkpoints, on an sshd over a fakeConsul whose indexes rise with every
// change to the entry (lease creates, and destroys of a lease that doesn't
// hold the entry, take no index), with the watch's deliveries made by hand, in
// every order the code admits: against a newer registration of the same ID
// from another node (#613), and against a plain write into the key the
// registration's own lease holds (#618). The checkpoints:
//
//	A    Generation 1 of the host's session commits from this node: index
//	     100, under lease 1.
//	R    Its Register has returned, and its request is held at onRegistered.
//	C    Generation 2 of the same ID commits from another node's store on the
//	     same Consul, at index 101 under a lease of its own, and its Register
//	     returns. This node's cache doesn't hear of it.
//	P    A plain write into the key: another node's value, of generation 2,
//	     written without acquiring the key, so lease 1 still holds it. Index
//	     101.
//	W_c  A delivery of the fake's current state reaches this node's cache, and
//	     is held at an observer that runs before reconcile.
//	W_r  The delivery is let go, and reconcile acts on it.
//	S    The request is let go from onRegistered: add gives generation 1 its
//	     slot, and adoption is held at beforeConfirm.
//	F    Adoption is let go from beforeConfirm: confirm checks the store's view
//	     again, and the host has its reply.
//
// and, in the hand rows:
//
//	D    Generation 1's reply, held since A, is let go, and R follows.
//	W    W_c and W_r as one step.
//
// Each step returns only once its checkpoint has acknowledged: a hook reached
// (onRegistered, beforeConfirm, the observer), a held reply's entered channel
// closing, a call returning (the other store's Register, writeOver, a
// delivery), or the host's reply. F's acknowledgement is beforeConfirm letting
// adoption go, then the reply. Where reconcile closed the host's connection
// before F, the reply came then, and confirm, finding no slot left to end,
// changes nothing.
//
// The orders the code doesn't admit, which no table runs:
//   - S before R: adoption runs on the request's goroutine, after Register
//     has returned and onRegistered has run.
//   - F before S: confirm runs in adoption once add has returned, on the same
//     goroutine.
//   - W_r before W_c: a delivery reaches the cache before reconcile sees it.
//   - C before A: generation 1's transaction is conditional on the entry it
//     read, so generation 2 committing first has it refused at the store,
//     which is a refusal, not an adoption.
//   - P before A: until A, no lease of generation 1's holds the key, so P is
//     no write into its key; generation 1 would read P's value and be ordered
//     against it at the store.
//   - A delivery showing C before C, or P before P: a delivery shows only
//     what has committed.

// TestAdoptionAgainstANewerRegistrationInEveryOrder runs every order of S, F,
// W_c and W_r with S before F and W_c before W_r, after A R C: 6 orders. Two of
// them, S W_c W_r F and S W_c F W_r, have the delivery reach the cache after
// the slot exists and before confirm.
//
// Generation 2 is on another node, so W_c is when this node first sees it. C
// is fixed right after R, though the code also lets it come after S or F: this
// node's store doesn't see generation 2 until a delivery shows it, and
// adoption reads that store, so C anywhere before W_c is the same order to
// this node.
//
// Generation 1's reply depends on the order. With F before W_c, this node's
// store hasn't shown generation 2, so generation 1 is adopted, and reconcile
// ends it at W_r. With W_c first, F's reply isn't a success.
//
// After the last step, generation 1 has no slot and its connection is closed,
// this node's gauge is 0, and lease 1 isn't live; generation 2's entry is
// untouched, at its index under its lease, which is live. The end state is
// awaited whole. The fake's changes wake the wait, and so does generation 1's
// connection ending: ending a superseded registration starts its release
// before closing its connection, so the close can be the last change.
func TestAdoptionAgainstANewerRegistrationInEveryOrder(t *testing.T) {
	all := orders([]string{"S", "F", "W_c", "W_r"}, map[string][]string{"S": {"F"}, "W_c": {"W_r"}})
	require.Len(t, all, 6)
	for _, order := range all {
		t.Run(strings.Join(order, " "), func(t *testing.T) {
			h := newAdoptRace(t, adoptRaceConfig{hold: []uint64{1}, confirm: []uint64{1}})
			h.begin()
			h.returned1()
			h.commit2()
			h.run(order, func(before map[string]bool, r hostReply) {
				if before["W_c"] {
					require.False(t, r.ok && r.err == nil, "generation 1 was adopted though this node's store showed generation 2")
					return
				}
				require.NoError(t, r.err, "this node's store hadn't shown generation 2, and generation 1's connection ended before its reply")
				require.True(t, r.ok, "this node's store hadn't shown generation 2, and generation 1 was refused: %s", r.body)
			})
			h.awaitEnd("generation 1 outlived generation 2's registration", h.firstEnded, func() []string {
				return h.supersededUnmet(supersededState{closed: true})
			})
		})
	}
}

// TestAdoptionAgainstAPlainWriteInEveryOrder expands the ten orders of
// P<W_c<W_r and S<F with rebuild commit B_c and reply B_r. L is the first
// acknowledged F after W_c, or W_r after S: the first step that reports loss.
// Insert L<B_c<B_r while preserving each base order: four have one placement,
// six have three, for 22 rows. In particular B_c after both F and W_r prevents
// a rebuild from masking either decision in those six rows.
//
// B_c acknowledges entry before transaction 2 reaches Consul, releases it,
// then acknowledges its committed, held reply. B_r releases that reply and
// awaits successor installation and original-lease retirement. Before B_c the
// original handle must stay adopted and eligible steps must record loss;
// between B_c/B_r the committed write is distinct from the installed handle.
// After B_r and at the end, the live host, gauge, restored entry and retired
// original lease are checked together. Later rebuilds pass through uncounted.
// These are orders of acknowledged steps, not an enumeration of instructions
// inside confirm or replacement; goroutines retain their normal scheduling.
func TestAdoptionAgainstAPlainWriteInEveryOrder(t *testing.T) {
	base := orders([]string{"P", "W_c", "W_r", "S", "F"}, map[string][]string{"P": {"W_c"}, "W_c": {"W_r"}, "S": {"F"}})
	require.Len(t, base, 10)
	var all [][]string
	placements := map[int]int{}
	for _, order := range base {
		seen := make(map[string]bool)
		loss := -1
		for i, step := range order {
			if (step == "F" && seen["W_c"]) || (step == "W_r" && seen["S"]) {
				loss = i
				break
			}
			seen[step] = true
		}
		require.NotEqual(t, -1, loss)
		count := 0
		for commit := loss + 1; commit <= len(order); commit++ {
			for reply := commit; reply <= len(order); reply++ {
				row := append([]string{}, order[:commit]...)
				row = append(row, "B_c")
				row = append(row, order[commit:reply]...)
				row = append(row, "B_r")
				row = append(row, order[reply:]...)
				all = append(all, row)
				count++
			}
		}
		placements[count]++
	}
	require.Equal(t, map[int]int{1: 4, 3: 6}, placements)
	require.Len(t, all, 22)
	for _, order := range all {
		t.Run(strings.Join(order, " "), func(t *testing.T) {
			h := newAdoptRace(t, adoptRaceConfig{hold: []uint64{1}, confirm: []uint64{1}, holdRebuild: true})
			h.begin()
			h.returned1()
			seen := make(map[string]bool)
			for _, step := range order {
				switch step {
				case "B_c":
					h.commitRebuild()
				case "B_r":
					h.returnRebuild()
				default:
					h.run([]string{step}, func(_ map[string]bool, r hostReply) {
						require.NoError(t, r.err, "generation 1's connection ended before its reply")
						require.True(t, r.ok, "a plain write into its own key had generation 1 refused: %s", r.body)
					})
				}
				// Check each decision before waiting for a rebuild a mutant may never
				// start, and while the pre-transaction gate prevents an early repair.
				if !seen["B_c"] && step != "B_c" && (seen["S"] || step == "S") {
					h.requireOriginalSlot()
				}
				if !seen["B_c"] && ((step == "F" && seen["W_c"]) || (step == "W_r" && seen["S"])) {
					_, index := h.lostReport()
					require.NotZero(t, index, "%s did not record the plain-write loss", step)
				}
				seen[step] = true
				if seen["B_c"] && !seen["B_r"] {
					h.requireCommittedRebuild()
				}
			}
			h.awaitEnd("the keeper never restored the entry", h.firstEnded, h.restoredUnmet)
		})
	}
}

// TestAdoptionHandRows are the orders outside the generated tables: the
// one-node orders of Test_sshd_AdoptionChecksTheStoreAgain and
// Test_sshd_DelayedAdoptionCannotEvictItsReplacement, where C is generation 2
// registering on this node rather than another, and a late Register reply
// (#612) crossed with each of #613 and #618. The #612 rows end in the end
// state of the #613 or #618 table they cross. The one-node rows end in #613's
// with generation 2 on this node instead: generation 2 holds the slot, its
// connection is open, and the gauge is 1; and the row where add refuses
// generation 1 doesn't ask for generation 1's connection to be closed, since
// the host reads its refusal on it. Each end state is awaited whole.
func TestAdoptionHandRows(t *testing.T) {
	// Feasible, Test_sshd_AdoptionChecksTheStoreAgain's order: generation 1 is
	// held after R while generation 2 registers on this node, whose reply
	// caches it here, and is held after its own R.
	// Generation 1's adoption finds generation 2 in the store's view, and is
	// refused with its connection closed; generation 2 then adopts. The gauge
	// counts only generation 2's connection.
	t.Run("one node: A R C S F, then generation 2 adopts", func(t *testing.T) {
		releases := newReleaseWitnessStore()
		h := newAdoptRace(t, adoptRaceConfig{hold: []uint64{1, 2}, configure: func(h *adoptRace, d *sshd) {
			releases.SessionStore = h.store
			d.SessionManager = newSessionManagerWithStore(releases, routing.NewEncodeDecoder(routing.ModeConsul))
		}})
		h.begin()
		h.returned1()
		second, secondEnded := h.dial("conn-2")
		secondReply := h.send(second, "conn-2", 2)
		receiveWithin(h.t, h.registered[2].entered, "generation 2's Register never returned")
		h.reg2 = h.registered[2].reg
		require.Equal(t, uint64(2), cachedGeneration(h.store, h.id), "generation 2's reply didn't cache it on this node")

		h.registered[1].release()
		r := receiveWithin(h.t, h.firstReply, "generation 1 never had a reply")
		require.False(t, r.ok && r.err == nil, "generation 1 was adopted though this node's store had generation 2")
		retired := releases.call(t, 1)
		receiveWithin(t, retired.returned, "confirm refusal's Release delegate never returned")
		require.True(t, retired.reg.Same(h.reg1))
		require.NoError(t, retired.err)
		// A request error remains permitted: this is not a guaranteed handler reply witness.
		h.registered[2].release()
		r = receiveWithin(h.t, secondReply, "generation 2 never had a reply")
		require.NoError(t, r.err)
		require.True(t, r.ok, string(r.body))
		h.awaitEnd("generation 1 outlived generation 2's registration", h.firstEnded, func() []string {
			return h.supersededUnmet(supersededState{closed: true, here: secondEnded})
		})
	})

	// Feasible, Test_sshd_DelayedAdoptionCannotEvictItsReplacement's order:
	// generation 1 is held after R while generation 2 registers and adopts on
	// this node. Generation 1's add then finds generation 2 holding
	// the ID here and refuses it before confirm, releasing lease 1. The host
	// reads a Superseded reply on a connection left open for it.
	t.Run("one node: A R C, generation 2 adopts, then S", func(t *testing.T) {
		releases := newReleaseWitnessStore()
		h := newAdoptRace(t, adoptRaceConfig{hold: []uint64{1, 2}, configure: func(h *adoptRace, d *sshd) {
			releases.SessionStore = h.store
			d.SessionManager = newSessionManagerWithStore(releases, routing.NewEncodeDecoder(routing.ModeConsul))
		}})
		h.begin()
		h.returned1()
		second, secondEnded := h.dial("conn-2")
		h.registered[2].release() // generation 2 is only recorded, not held
		r := receiveWithin(h.t, h.send(second, "conn-2", 2), "generation 2 never had a reply")
		require.NoError(t, r.err)
		require.True(t, r.ok, string(r.body))
		receiveWithin(h.t, h.registered[2].entered, "generation 2 never reached onRegistered")
		h.reg2 = h.registered[2].reg

		h.registered[1].release()
		r = receiveWithin(h.t, h.firstReply, "generation 1 never had a reply")
		require.NoError(t, r.err, "the refused registration's connection was closed before its reply")
		require.False(t, r.ok)
		require.Equal(t, registration.Superseded, string(r.body))
		refused := releases.call(t, 1)
		receiveWithin(t, refused.returned, "add refusal's Release delegate never returned")
		require.True(t, refused.reg.Same(h.reg1))
		require.NoError(t, refused.err)
		// Together, this actual nil-error Superseded reply and delegate return
		// cover the live handler invocation; EOF would not supply that boundary.
		h.awaitEnd("generation 1's refusal left something behind", nil, func() []string {
			return h.supersededUnmet(supersededState{here: secondEnded})
		})
	})

	// Feasible: generation 1's reply can be held up past generation 2's commit
	// elsewhere and the delivery that shows it. The reply describes a write
	// the delivery has superseded, so the cache drops it (D), and adoption
	// finds generation 2 and refuses generation 1 (F).
	t.Run("A C W D S F", func(t *testing.T) {
		h := newAdoptRace(t, adoptRaceConfig{delay: true, hold: []uint64{1}, confirm: []uint64{1}})
		h.begin()
		h.commit1()
		h.commit2()
		h.deliverWhole()
		h.resume1()
		e, ok := h.store.cache.lookup(h.id)
		require.True(t, ok, "the late reply removed the delivered entry")
		require.Equal(t, uint64(2), e.session.Generation, "the late reply replaced generation 2, which this node had cached")
		require.Equal(t, h.reg2.lease, e.lease)
		h.adopt()
		r := h.confirm()
		require.False(t, r.ok && r.err == nil, "generation 1 was adopted though this node's store showed generation 2")
		h.awaitEnd("generation 1 outlived generation 2's registration", h.firstEnded, func() []string {
			return h.supersededUnmet(supersededState{closed: true})
		})
	})

	// Feasible: the plain write can land while generation 1's reply is held,
	// and the delivery showing it come before the reply. The reply describes
	// an earlier write than the cache holds, so the cache keeps P's value, and
	// confirm takes that value, in the key lease 1 holds, as a loss.
	t.Run("A P W D S F", func(t *testing.T) {
		h := newAdoptRace(t, adoptRaceConfig{delay: true, hold: []uint64{1}, confirm: []uint64{1}})
		h.begin()
		h.commit1()
		h.write()
		h.deliverWhole()
		h.resume1()
		e, ok := h.store.cache.lookup(h.id)
		require.True(t, ok, "the late reply removed the delivered entry")
		require.Equal(t, uint64(2), e.session.Generation, "the late reply replaced the plain write's value, which this node had cached")
		require.Equal(t, h.lease1, e.lease)
		h.adopt()
		r := h.confirm()
		require.NoError(t, r.err, "generation 1's connection ended before its reply")
		require.True(t, r.ok, "a plain write into its own key had generation 1 refused: %s", r.body)
		h.awaitEnd("the keeper never restored the entry", h.firstEnded, h.restoredUnmet)
	})
}

// TestAdoptionOfAnAbsentEntryToday is the order where a delivery shows the
// entry absent before S. After A R, the fake loses the entry, as a restore can,
// and a delivery of that, at an index past generation 1's write, empties this
// node's cache. confirm's lookup then reads through to Consul and finds no
// entry.
//
// This is today's behaviour, pinned as it stands: confirm returns nil, the
// slot stays active, and no loss is reported to the keeper. A definitive
// not-found is meant to become a known loss that keeps the host adopted, as
// reconcile already takes a missing entry; when that follow-up lands, it
// rewrites this test. The report is read from the slot's record of the last
// one, not from the keeper's channel, which the keeper drains at once.
func TestAdoptionOfAnAbsentEntryToday(t *testing.T) {
	h := newAdoptRace(t, adoptRaceConfig{hold: []uint64{1}, confirm: []uint64{1}})
	h.begin()
	h.returned1()
	h.consul.reset()
	h.deliverWhole()
	h.adopt()
	r := h.confirm()
	require.NoError(t, r.err, "generation 1's connection ended before its reply")
	require.True(t, r.ok, "confirm refused a registration whose entry it found absent: %s", r.body)

	// confirm runs before the reply, so all of this is settled.
	require.True(t, h.served().Same(h.reg1), "generation 1 lost its slot")
	require.Equal(t, 1.0, h.s.gauge(t))
	require.False(t, isDone(h.firstEnded), "generation 1's connection was closed")
	// A loss confirm reported would record generation 1's write, at index 100.
	// Its epoch is 0 whether or not one was reported, since no delivery's
	// index drops here, so only the index tells.
	_, index := h.lostReport()
	require.Zero(t, index, "a loss was reported")
	_, err := h.s.sshd.SessionManager.GetEntry(h.id)
	var missing *ErrSessionNotFound
	require.ErrorAs(t, err, &missing, "a lookup now isn't a not-found, as confirm's should have been")
}

// adoptRace is one run's fixture: an sshd over a fakeConsul in monotonic mode,
// through this node's store, which no watch runs on, and another store on the
// same fake for another node's registration. onRegistered and beforeConfirm
// hold the generations the run names, and an observer added before reconcile
// holds each delivery. A delivery is a call to updateSessionReplica, made on a
// goroutine of its own, since the observer holds it.
type adoptRace struct {
	t       *testing.T
	consul  *fakeConsul
	store   *consulSessionStore // this node's
	other   *consulSessionStore // another node's, for generation 2 at C
	delay   *delayedTxnReply    // holds the configured transaction replies; nil if none
	rebuild *rebuildTxnGate     // holds transaction 2 before Consul sees it
	s       *testSSHD
	host    proven
	id      string

	// registered and confirming are the checkpoints onRegistered and
	// beforeConfirm hold, by generation; a generation with none passes. Fixed
	// before the sshd serves.
	registered, confirming map[uint64]*checkpoint
	// delivery is the one the observer holds, set before it is made.
	delivery   atomic.Pointer[heldDelivery]
	deliveries []*heldDelivery // every one made, for cleanup
	pending    *heldDelivery   // the one between W_c and W_r

	firstEnded <-chan struct{} // closed once generation 1's connection has ended
	firstReply <-chan hostReply
	reg1, reg2 *Registration
	lease1     string // the lease generation 1 committed under
}

// adoptRaceConfig is what a run holds.
type adoptRaceConfig struct {
	// delay holds the reply to this node's first transaction, generation 1's,
	// until resume1.
	delay bool
	// holdRebuild holds transaction 2 before submission and after commit.
	holdRebuild bool
	// hold names the generations onRegistered holds, and confirm those
	// beforeConfirm holds.
	hold, confirm []uint64
	// Optional per-instance ownership diagnostics, installed before Serve.
	transport   func(http.RoundTripper) http.RoundTripper
	beforeClose func()
	configure   func(*adoptRace, *sshd)
}

// hostReply is the host's reply to its registration.
type hostReply struct {
	ok   bool
	body []byte
	err  error
}

// checkpoint is a point a hook stops at. entered closes once the hook has
// reached it, with reg the registration it was called for; it then waits for
// release, and left closes once it goes on. A nil checkpoint holds nothing.
type checkpoint struct {
	entered, resume, left chan struct{}
	reg                   *Registration
	arrived, released     sync.Once
}

func newCheckpoint() *checkpoint {
	return &checkpoint{entered: make(chan struct{}), resume: make(chan struct{}), left: make(chan struct{})}
}

// stop is the hook's side. Only the first arrival is held; a later one
// passes.
func (c *checkpoint) stop(reg *Registration) {
	if c == nil {
		return
	}
	first := false
	c.arrived.Do(func() {
		first = true
		c.reg = reg
		close(c.entered)
	})
	if !first {
		return
	}
	<-c.resume
	close(c.left)
}

// release lets the hook go on. It is idempotent.
func (c *checkpoint) release() {
	c.released.Do(func() { close(c.resume) })
}

// heldDelivery is one delivery: its checkpoint is the observer, and done closes
// once updateSessionReplica has returned, reconcile having acted on it.
type heldDelivery struct {
	*checkpoint
	done chan struct{}
}

func newAdoptRace(t *testing.T, cfg adoptRaceConfig) *adoptRace {
	t.Helper()
	consul := newFakeConsul(t, monotonicIndexes)
	h := &adoptRace{
		t:          t,
		consul:     consul,
		other:      newFakeConsulStore(t, consul),
		host:       newProven(t),
		registered: make(map[uint64]*checkpoint),
		confirming: make(map[uint64]*checkpoint),
	}
	h.id = h.host.id()
	var rt http.RoundTripper
	if cfg.delay || cfg.holdRebuild {
		rt = ownedHTTPTransport(t)
		var holds []int
		if cfg.delay {
			holds = append(holds, 1)
		}
		if cfg.holdRebuild {
			h.rebuild = &rebuildTxnGate{next: rt, entered: make(chan struct{}), resume: make(chan struct{}), left: make(chan struct{})}
			rt = h.rebuild
			holds = append(holds, 2)
		}
		h.delay = newDelayedTxnReply(rt, holds...)
		rt = h.delay
	}
	if cfg.transport != nil {
		if rt == nil {
			rt = ownedHTTPTransport(t)
		}
		rt = cfg.transport(rt)
	}
	h.store = newFakeConsulStoreWithCleanup(t, consul, rt, cfg.beforeClose)
	for _, gen := range cfg.hold {
		h.registered[gen] = newCheckpoint()
	}
	for _, gen := range cfg.confirm {
		h.confirming[gen] = newCheckpoint()
	}
	h.s = newTestSSHD(t, func(d *sshd) {
		d.SessionManager = newSessionManagerWithStore(h.store, routing.NewEncodeDecoder(routing.ModeConsul))
		d.onRegistered = func(_ context.Context, reg *Registration) { h.registered[reg.Generation()].stop(reg) }
		d.beforeConfirm = func(reg *Registration) { h.confirming[reg.Generation()].stop(reg) }
		if cfg.configure != nil {
			cfg.configure(h, d)
		}
	}, withObserverFirst(h.observe))
	// However the run ends, nothing is left held. dial registers this again,
	// so it runs before each connection's own cleanup closes it.
	t.Cleanup(h.releaseAll)
	return h
}

// rebuildTxnGate holds only transaction 2 before the underlying transport
// sends it. Later transactions pass through, even while this one is held.
// The delayed reply outside it independently holds the same write after commit.
type rebuildTxnGate struct {
	next                  http.RoundTripper
	txns                  atomic.Int64
	entered, resume, left chan struct{}
	released              sync.Once
}

func (g *rebuildTxnGate) release()              { g.released.Do(func() { close(g.resume) }) }
func (g *rebuildTxnGate) CloseIdleConnections() { closeTestIdleConnections(g.next) }
func (g *rebuildTxnGate) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/v1/txn" && g.txns.Add(1) == 2 {
		close(g.entered)
		<-g.resume
		resp, err := g.next.RoundTrip(r)
		close(g.left)
		return resp, err
	}
	return g.next.RoundTrip(r)
}

func (h *adoptRace) requireOriginalSlot() {
	h.t.Helper()
	served := h.served()
	require.NotNil(h.t, served, "the original slot was removed before rebuild commit")
	require.True(h.t, served.Same(h.reg1), "the original registration lost its slot before rebuild commit")
	require.Equal(h.t, h.lease1, served.lease, "the original handle was replaced before rebuild commit")
	require.True(h.t, h.consul.live(h.lease1), "the original lease was retired before rebuild commit")
	require.False(h.t, isDone(h.firstEnded), "the host's connection was closed before rebuild commit")
	require.Equal(h.t, 1.0, h.s.gauge(h.t))
}

func (h *adoptRace) commitRebuild() {
	h.t.Helper()
	receiveWithin(h.t, h.rebuild.entered, "the keeper never entered its rebuild transaction")
	h.requireOriginalSlot()
	pair := h.consul.entry()
	require.NotNil(h.t, pair)
	require.Equal(h.t, uint64(2), storedSession(pair.Value).Generation, "the rebuild committed before its release")
	require.Equal(h.t, h.lease1, pair.Session)
	h.rebuild.release()
	receiveWithin(h.t, h.delay.entered(2), "the rebuild never committed")
	receiveWithin(h.t, h.rebuild.left, "the rebuild transport never returned")
	h.requireCommittedRebuild()
}

func (h *adoptRace) requireCommittedRebuild() {
	h.t.Helper()
	h.requireOriginalSlot()
	pair := h.consul.entry()
	require.NotNil(h.t, pair)
	require.True(h.t, sameIdentity(storedSession(pair.Value), h.reg1.Session), "the committed rebuild did not restore the entry")
	require.NotEqual(h.t, h.lease1, pair.Session, "the committed rebuild still uses the original lease")
	require.True(h.t, h.consul.live(pair.Session), "the committed successor lease is not live")
}

func (h *adoptRace) returnRebuild() {
	h.t.Helper()
	h.delay.release(2)
	h.awaitEnd("the rebuild never installed and retired the original lease", h.firstEnded, h.restoredUnmet)
}

// observe holds each delivery after the cache has taken it, and before
// reconcile.
func (h *adoptRace) observe(_, _ uint64, _ map[string]StoreEntry) {
	if d := h.delivery.Load(); d != nil {
		d.stop(nil)
	}
}

func (h *adoptRace) releaseAll() {
	for _, c := range h.registered {
		c.release()
	}
	for _, c := range h.confirming {
		c.release()
	}
	for _, d := range h.deliveries {
		d.release()
	}
	if h.rebuild != nil {
		h.rebuild.release()
	}
	if h.delay != nil {
		for n := range h.delay.holds {
			h.delay.release(n)
		}
	}
}

// dial connects for the host as the proxy does, over the SSH session keyID,
// and returns the client and a channel closed once its connection has ended.
func (h *adoptRace) dial(keyID string) (*ssh.Client, <-chan struct{}) {
	h.t.Helper()
	client := h.s.dialAs(h.t, keyID)
	h.t.Cleanup(h.releaseAll)
	ended := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(ended)
	}()
	return client, ended
}

// send has the host register generation gen over client, with a proof bound
// to keyID, and returns the channel its reply comes on.
func (h *adoptRace) send(client *ssh.Client, keyID string, gen uint64) <-chan hostReply {
	h.t.Helper()
	// Signed here: require must not run on the goroutine below.
	proof, err := registration.Sign(h.host.key, []byte(keyID), h.host.secret, gen)
	require.NoError(h.t, err)
	req, err := proto.Marshal(&CreateSessionRequest{HostUser: "owen", HostPublicKeys: h.host.hostKeys(),
		SessionSecret: h.host.secret, Generation: gen, HostKeyProof: proof})
	require.NoError(h.t, err)
	result := make(chan hostReply, 1)
	go func() {
		ok, body, err := client.SendRequest(upterm.ServerCreateSessionRequestType, true, req)
		result <- hostReply{ok, body, err}
	}()
	return result
}

// begin has the host register generation 1 from this node, over a connection
// of its own. A follows; R is held.
func (h *adoptRace) begin() {
	h.t.Helper()
	var first *ssh.Client
	first, h.firstEnded = h.dial("conn-1")
	h.firstReply = h.send(first, "conn-1", 1)
}

// commit1 is A where the reply is held: it returns once Consul has applied
// generation 1's transaction.
func (h *adoptRace) commit1() {
	h.t.Helper()
	receiveWithin(h.t, h.delay.entered(1), "generation 1 never committed")
	pair := h.consul.entry()
	require.NotNil(h.t, pair, "generation 1 committed no entry")
	require.Equal(h.t, uint64(1), storedSession(pair.Value).Generation, "the entry isn't generation 1's")
	h.lease1 = pair.Session
}

// returned1 is R: it returns once generation 1's request is held at
// onRegistered, its Register having returned. Without commit1, A and R are one
// step, and nothing else has written yet.
func (h *adoptRace) returned1() {
	h.t.Helper()
	c := h.registered[1]
	receiveWithin(h.t, c.entered, "generation 1's Register never returned")
	h.reg1 = c.reg
	if h.lease1 == "" {
		pair := h.consul.entry()
		require.NotNil(h.t, pair, "generation 1 committed no entry")
		h.lease1 = pair.Session
	}
	require.Equal(h.t, h.lease1, h.reg1.lease, "generation 1's Register returned another lease than it committed under")
}

// resume1 is D: generation 1's held reply is let go, and it returns at R.
func (h *adoptRace) resume1() {
	h.t.Helper()
	h.delay.release(1)
	h.returned1()
}

// commit2 is C: generation 2 of the ID registers from the other store, as
// another node, and it returns once that Register has.
func (h *adoptRace) commit2() {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reg, err := h.other.Register(ctx, &Session{ID: h.id, NodeAddr: "node-b:22", Generation: 2})
	require.NoError(h.t, err, "generation 2 wasn't registered")
	h.reg2 = reg
	require.NotEqual(h.t, uint64(2), cachedGeneration(h.store, h.id), "another node's registration reached this node's cache")
}

// write is P: another node's value, of generation 2, written into the key as a
// plain write does, so the lease that holds it keeps it.
func (h *adoptRace) write() {
	h.t.Helper()
	pair := writeOver(h.t, h.consul, h.reg1, &Session{ID: h.id, NodeAddr: "node-b:22", Generation: 2})
	require.Equal(h.t, h.lease1, pair.Session, "the plain write moved the lock")
}

// deliver is W_c: a delivery of the fake's current state, which returns once
// this node's cache has taken it and the observer holds it.
func (h *adoptRace) deliver() {
	h.t.Helper()
	require.Nil(h.t, h.pending, "a delivery is already in flight")
	index, pairs := h.consul.snapshot()
	d := &heldDelivery{checkpoint: newCheckpoint(), done: make(chan struct{})}
	h.deliveries = append(h.deliveries, d)
	h.delivery.Store(d)
	h.pending = d
	go func() {
		h.store.updateSessionReplica(index, pairs)
		close(d.done)
	}()
	receiveWithin(h.t, d.entered, "the delivery never reached the observer")
	e, ok := h.store.cache.lookup(h.id)
	if len(pairs) == 0 {
		require.False(h.t, ok, "the cache kept an entry the delivery left out")
		return
	}
	require.True(h.t, ok, "the cache didn't take the delivery")
	require.Equal(h.t, index, e.index, "the cache didn't take the delivery")
}

// reconcile is W_r: the held delivery is let go, and it returns once reconcile
// has acted on it.
func (h *adoptRace) reconcile() {
	h.t.Helper()
	d := h.pending
	require.NotNil(h.t, d, "no delivery is held")
	d.release()
	receiveWithin(h.t, d.done, "reconcile never finished with the delivery")
	h.pending = nil
}

// deliverWhole is W.
func (h *adoptRace) deliverWhole() {
	h.t.Helper()
	h.deliver()
	h.reconcile()
}

// adopt is S: generation 1's request is let go from onRegistered, and it
// returns once add has given it its slot and adoption is held at
// beforeConfirm.
func (h *adoptRace) adopt() {
	h.t.Helper()
	h.registered[1].release()
	receiveWithin(h.t, h.confirming[1].entered, "generation 1's adoption never reached beforeConfirm")
	require.True(h.t, h.served().Same(h.reg1), "add didn't give generation 1 its slot")
}

// confirm is F: adoption is let go from beforeConfirm, and it returns the
// host's reply.
func (h *adoptRace) confirm() hostReply {
	h.t.Helper()
	c := h.confirming[1]
	c.release()
	receiveWithin(h.t, c.left, "beforeConfirm never let adoption go")
	return receiveWithin(h.t, h.firstReply, "generation 1 never had a reply")
}

// run takes the steps of order in turn, each acknowledged before the next,
// and hands F's reply to atF with the steps that came before it.
func (h *adoptRace) run(order []string, atF func(before map[string]bool, r hostReply)) {
	h.t.Helper()
	seen := make(map[string]bool)
	for _, step := range order {
		switch step {
		case "P":
			h.write()
		case "W_c":
			h.deliver()
		case "W_r":
			h.reconcile()
		case "S":
			h.adopt()
		case "F":
			atF(seen, h.confirm())
		default:
			h.t.Fatalf("no step %q", step)
		}
		seen[step] = true
	}
}

// supersededState is what a #613 end state asks beyond what every one does:
// generation 1 has no slot, and lease 1 isn't live; generation 2's entry is
// untouched, and its lease live.
type supersededState struct {
	// closed asks for generation 1's connection to be closed. Only add
	// refusing it leaves it open, for the host to read its reply.
	closed bool
	// here is generation 2's connection's end where generation 2 is on this
	// node: it then holds the slot, its connection is open, and the gauge is
	// 1. Nil where it is on another node: no slot is left, and the gauge is 0.
	here <-chan struct{}
}

// supersededUnmet is what the #613 end state still lacks; nothing once it
// holds whole.
func (h *adoptRace) supersededUnmet(want supersededState) []string {
	var unmet []string
	served := h.served()
	gauge := 0.0
	switch {
	case served.Same(h.reg1):
		unmet = append(unmet, "generation 1 has a slot")
	case want.here != nil && !served.Same(h.reg2):
		unmet = append(unmet, "generation 2 has no slot")
	case want.here == nil && served != nil:
		unmet = append(unmet, "a slot is left for the ID")
	}
	if want.here != nil {
		gauge = 1
		if isDone(want.here) {
			unmet = append(unmet, "generation 2's connection was closed")
		}
	}
	if want.closed && !isDone(h.firstEnded) {
		unmet = append(unmet, "generation 1's connection is open")
	}
	if g := h.s.gauge(h.t); g != gauge {
		unmet = append(unmet, fmt.Sprintf("the gauge is %v, not %v", g, gauge))
	}
	if h.consul.live(h.lease1) {
		unmet = append(unmet, "lease 1 is live")
	}
	switch e := h.consul.entry(); {
	case e == nil:
		unmet = append(unmet, "generation 2's entry is gone")
	case e.Session != h.reg2.lease || e.ModifyIndex != h.reg2.index || !sameIdentity(storedSession(e.Value), h.reg2.Session):
		unmet = append(unmet, fmt.Sprintf("generation 2's entry was touched: %s at %d under %q", e.Value, e.ModifyIndex, e.Session))
	}
	if !h.consul.live(h.reg2.lease) {
		unmet = append(unmet, "generation 2's lease isn't live")
	}
	return unmet
}

// restoredUnmet is what the #618 end state still lacks; nothing once it holds
// whole. A closed connection fails the test at once, since it can't reopen.
func (h *adoptRace) restoredUnmet() []string {
	if isDone(h.firstEnded) {
		h.t.Fatal("the host's connection was closed")
	}
	var unmet []string
	served := h.served()
	if !served.Same(h.reg1) {
		unmet = append(unmet, "generation 1 has no slot")
	} else if served.lease == h.lease1 || !h.consul.live(served.lease) {
		unmet = append(unmet, "a live successor is not installed")
	}
	if g := h.s.gauge(h.t); g != 1 {
		unmet = append(unmet, fmt.Sprintf("the gauge is %v, not 1", g))
	}
	if h.consul.live(h.lease1) {
		unmet = append(unmet, "lease 1 is live")
	}
	if !slices.Contains(h.consul.destroyed(), h.lease1) {
		unmet = append(unmet, "lease 1 has not been destroyed")
	}
	switch e := h.consul.entry(); {
	case e == nil:
		unmet = append(unmet, "the entry is gone")
	case !sameIdentity(storedSession(e.Value), h.reg1.Session):
		unmet = append(unmet, fmt.Sprintf("the entry isn't generation 1's: %s", e.Value))
	case e.Session == h.lease1:
		unmet = append(unmet, "the entry is still under lease 1")
	case !h.consul.live(e.Session):
		unmet = append(unmet, fmt.Sprintf("the entry's lease %q isn't live", e.Session))
	}
	return unmet
}

// awaitEnd waits for an end state whole. unmet names what it still lacks: it
// is read once at the start and again on each wakeup, and the wait ends only
// once it lacks nothing, since a state that holds in part can be one the code
// passes through. The fake's changes wake it, and so does ended closing, where
// one isn't nil. 5 s is only the failure bound.
func (h *adoptRace) awaitEnd(what string, ended <-chan struct{}, unmet func() []string) {
	h.t.Helper()
	guard := time.After(5 * time.Second)
	for {
		if len(unmet()) == 0 {
			return
		}
		select {
		case <-h.consul.changed():
		case <-ended:
			ended = nil
		case <-guard:
			h.t.Fatalf("%s: after 5 s, %s", what, strings.Join(unmet(), "; "))
		}
	}
}

// served is the registration this node's slot for the ID holds, read under
// the lock a rebuild replaces it under; nil if there is no slot.
func (h *adoptRace) served() *Registration {
	sessions := h.sessions()
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	if lr, ok := sessions.regs[h.id]; ok {
		return lr.reg
	}
	return nil
}

func (h *adoptRace) sessions() *localSessions {
	h.s.sshd.mux.Lock()
	defer h.s.sshd.mux.Unlock()
	return h.s.sshd.sessions
}

// lostReport is the epoch and index attached to the latest loss report,
// from a watch delivery or confirm's own registration: zero if none has.
func (h *adoptRace) lostReport() (epoch, index uint64) {
	h.t.Helper()
	sessions := h.sessions()
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	lr := sessions.regs[h.id]
	require.NotNil(h.t, lr, "generation 1 has no slot")
	return lr.lostEpoch, lr.lostIndex
}

// isDone reports whether ch is closed.
func isDone(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
