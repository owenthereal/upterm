package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/avast/retry-go/v4"
	"github.com/owenthereal/upterm/routing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// scriptedEntryStore is a memory store whose Entry answers what the test
// scripts, so confirm's lookup can fail as a Consul read can. Its entries
// don't expire, so add starts no keeper for the registration, and a loss
// confirm reports stays on the slot's channel for the test to read.
type scriptedEntryStore struct {
	*memorySessionStore
	entry func(id string) (StoreEntry, error)
}

func (s *scriptedEntryStore) Entry(id string) (StoreEntry, error) { return s.entry(id) }

// confirmFixture is one node's sessions over a scriptedEntryStore, with reg
// adopted over conn as adopt adopts one, for confirm to check next.
type confirmFixture struct {
	sessions *localSessions
	metrics  *prometheus.Registry
	reg      *Registration
	conn     *closer
}

// newConfirmFixture adopts generation 1 of "id", written at index 100 in
// epoch 3, so a loss reported as of its write carries an epoch and index no
// slot starts with. The registration ends at cleanup.
func newConfirmFixture(t *testing.T, entry func(id string) (StoreEntry, error)) *confirmFixture {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	store := &scriptedEntryStore{memorySessionStore: newMemorySessionStore(logger), entry: entry}
	sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	mp, metrics := newTestMetrics(t)
	f := &confirmFixture{
		sessions: newLocalSessions(newTestSSHWork(t).owner, mp, sm, logger),
		metrics:  metrics,
		reg: &Registration{Session: &Session{ID: "id", NodeAddr: "node-a:22", Generation: 1},
			lease: "lease-1", index: 100, epoch: 3},
		conn: newCloser(),
	}
	t.Cleanup(func() { f.sessions.end(f.reg) })
	_, err := f.sessions.add(testSSHWork(t, f.sessions.work), f.reg, f.conn)
	require.NoError(t, err)
	return f
}

// reportedLoss is what a slot records of the latest loss reported to its
// keeper, and how many reports wait on the keeper's channel.
type reportedLoss struct {
	epoch, index uint64
	pending      int
}

// slotState is the slot for "id", read under the lock confirm reports
// under; zero if there is no slot.
type slotState struct {
	slot *localRegistration
	reg  *Registration
	loss reportedLoss
}

func (f *confirmFixture) state() slotState {
	f.sessions.mu.Lock()
	defer f.sessions.mu.Unlock()
	lr, ok := f.sessions.regs[f.reg.ID()]
	if !ok {
		return slotState{}
	}
	return slotState{slot: lr, reg: lr.reg, loss: reportedLoss{lr.lostEpoch, lr.lostIndex, len(lr.lost)}}
}

func (f *confirmFixture) gauge(t *testing.T) float64 {
	t.Helper()
	v, _ := gatherValue(t, f.metrics, "test_server_sessions_active_count", nil)
	return v
}

// A lookup that answers the entry is absent is definitive, however the store
// wraps the answer: a Consul read that retried reports it after its earlier
// attempts' errors. confirm takes it as reconcile takes a missing entry: the
// host stays adopted, and its keeper is told of the loss as of its
// registration's own write. Any other failure says nothing of the entry, even
// one that reads as a not-found, and the host stays adopted with nothing
// reported: the next delivery, or its keeper's next renewal, still finds it.
func TestConfirmReportsDefinitiveAbsenceAsLoss(t *testing.T) {
	notFound := &ErrSessionNotFound{SessionID: "id"}
	transport := fmt.Errorf("failed to get session data: %w", errors.New("connection refused"))
	for _, tc := range []struct {
		name string
		err  error
		loss bool
	}{
		{"not found", notFound, true},
		{"wrapped not found", fmt.Errorf("reading the entry: %w", notFound), true},
		{"not found after a transport failure", retry.Error{transport, notFound}, true},
		{"transport failures on every attempt", retry.Error{transport, transport}, false},
		{"a transport failure", transport, false},
		{"deadline exceeded", context.DeadlineExceeded, false},
		{"canceled", context.Canceled, false},
		{"not-found text without the type", errors.New(notFound.Error()), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newConfirmFixture(t, func(string) (StoreEntry, error) { return StoreEntry{}, tc.err })
			adopted := f.state()
			require.Same(t, f.reg, adopted.reg, "add didn't give the registration its slot")

			require.NoError(t, f.sessions.confirm(testSSHWork(t, f.sessions.work), f.reg),
				"confirm refused a registration over a lookup that found no other")
			after := f.state()
			require.Same(t, adopted.slot, after.slot, "confirm took the registration's slot")
			require.Same(t, f.reg, after.reg, "confirm replaced the slot's handle")
			require.False(t, f.conn.isClosed(), "confirm closed the host's connection")
			require.Equal(t, 1.0, f.gauge(t))
			want, msg := reportedLoss{}, "a lookup that said nothing of the entry was reported as a loss"
			if tc.loss {
				want, msg = reportedLoss{f.reg.epoch, f.reg.index, 1}, "an absent entry wasn't reported once, as a loss of the registration's own write"
			}
			require.Equal(t, want, after.loss, msg)
		})
	}
}

// A lookup's answer belongs to the registration confirm was checking. By the
// time it comes, that registration's slot can have gone to another of the
// same ID: here the lookup itself hands it to generation 2 from another
// connection, as a takeover on this node would, before answering that the
// entry is absent. Generation 1 no longer has a slot to report the loss to,
// and generation 2's slot, its keeper's channel, its connection and the
// count are left as add left them.
func TestConfirmReportsAbsenceOnlyToItsOwnRegistration(t *testing.T) {
	next := &Registration{Session: &Session{ID: "id", NodeAddr: "node-a:22", Generation: 2},
		lease: "lease-2", index: 200, epoch: 3}
	nextConn := newCloser()
	var (
		f       *confirmFixture
		addWork *sshWorkRef
		addErr  error
		took    slotState
	)
	f = newConfirmFixture(t, func(id string) (StoreEntry, error) {
		_, addErr = f.sessions.add(addWork, next, nextConn)
		took = f.state()
		return StoreEntry{}, &ErrSessionNotFound{SessionID: id}
	})
	t.Cleanup(func() { f.sessions.end(next) })
	addWork = testSSHWork(t, f.sessions.work)

	require.NoError(t, f.sessions.confirm(testSSHWork(t, f.sessions.work), f.reg),
		"confirm refused a registration whose entry it found absent")
	require.NoError(t, addErr, "generation 2 wasn't adopted")
	require.Same(t, next, took.reg, "generation 2 didn't take the slot")
	require.Equal(t, reportedLoss{}, took.loss, "generation 2's slot started with a loss")

	after := f.state()
	require.Same(t, took.slot, after.slot, "confirm replaced generation 2's slot")
	require.Same(t, next, after.reg, "confirm replaced generation 2's handle")
	require.False(t, nextConn.isClosed(), "confirm closed generation 2's connection")
	require.Equal(t, 1.0, f.gauge(t))
	require.Equal(t, reportedLoss{}, after.loss, "generation 1's absent entry was reported to generation 2's keeper")
}

// The slot can also change handles within one registration: a rebuild its
// keeper finishes while the lookup is in flight installs a new handle for the
// same registration, under a lease of its own. That is still the registration
// confirm was checking, so the absence is reported to its slot, as of the
// write confirm checked rather than the rebuild's, and the rebuilt handle
// stays installed. Here the lookup itself installs the rebuild, through
// replace, before answering that the entry is absent.
func TestConfirmReportsAbsenceToARebuildOfItsRegistration(t *testing.T) {
	var (
		f        *confirmFixture
		rebuilt  *Registration
		replaced bool
		took     slotState
	)
	f = newConfirmFixture(t, func(id string) (StoreEntry, error) {
		session := *f.reg.Session
		rebuilt = &Registration{Session: &session, lease: "lease-1b", index: 150, epoch: 3}
		replaced = f.sessions.replace(rebuilt)
		took = f.state()
		return StoreEntry{}, &ErrSessionNotFound{SessionID: id}
	})
	adopted := f.state()

	require.NoError(t, f.sessions.confirm(testSSHWork(t, f.sessions.work), f.reg),
		"confirm refused a registration whose entry it found absent")
	require.True(t, replaced, "the rebuilt handle wasn't installed")
	require.Same(t, adopted.slot, took.slot, "the rebuild took another slot")
	require.Same(t, rebuilt, took.reg, "the slot doesn't hold the rebuilt handle")
	require.Equal(t, reportedLoss{}, took.loss, "the slot started with a loss")

	after := f.state()
	require.Same(t, adopted.slot, after.slot, "confirm took the registration's slot")
	require.Same(t, rebuilt, after.reg, "confirm replaced the rebuilt handle")
	require.False(t, f.conn.isClosed(), "confirm closed the host's connection")
	require.Equal(t, 1.0, f.gauge(t))
	want := reportedLoss{f.reg.epoch, f.reg.index, 1}
	require.Equal(t, want, after.loss, "an absent entry wasn't reported once to a rebuild of its registration")
}
