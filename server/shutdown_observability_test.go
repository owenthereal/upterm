package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owenthereal/upterm/routing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// hangingListStore blocks in List, the first call SessionManager.Shutdown makes,
// until the test releases it, and records whether a delete followed.
type hangingListStore struct {
	SessionStore
	entered chan struct{}
	release chan struct{}
	deleted chan []string
}

func (s hangingListStore) List() ([]*Session, error) {
	close(s.entered)
	<-s.release
	return s.SessionStore.List()
}

func (s hangingListStore) BatchDelete(sessionIDs []string) error {
	select {
	case s.deleted <- sessionIDs:
	default:
	}
	return s.SessionStore.BatchDelete(sessionIDs)
}

func newHangingListStore(logger *slog.Logger) hangingListStore {
	return hangingListStore{
		SessionStore: newMemorySessionStore(logger),
		entered:      make(chan struct{}),
		release:      make(chan struct{}),
		deleted:      make(chan []string, 1),
	}
}

// Session cleanup reaches Consul over the network and carries no deadline of
// its own: List walks every session in the store, BatchDelete deletes this
// node's in serial 64-key transactions, and Close stops the watches. Shutdown
// therefore has to bound it. Until it did, the whole of Shutdown had a floor
// but no ceiling, and a supervisor's grace period cannot be set against an
// unbounded shutdown -- fly.toml's kill_timeout is set against this one.
func TestServerShutdownBoundsSessionCleanup(t *testing.T) {
	restore := sessionCleanupDeadline
	sessionCleanupDeadline = 50 * time.Millisecond
	t.Cleanup(func() { sessionCleanupDeadline = restore })

	logger := slog.New(slog.DiscardHandler)
	store := newHangingListStore(logger)
	// Let the abandoned goroutine finish so it does not outlive the test.
	t.Cleanup(func() { close(store.release) })

	s := &Server{
		NodeAddr:       "127.0.0.1:0",
		SessionManager: newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded)),
		Logger:         logger,
		cancel:         func() {},
		// served is nil: this Server never served, so the wait before the
		// cleanup is skipped and only the cleanup's own bound is under test.
	}

	done := make(chan error, 1)
	go func() { done <- s.Shutdown() }()

	select {
	case <-store.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("session cleanup never started, so its deadline proves nothing")
	}

	select {
	case err := <-done:
		require.ErrorIs(t, err, errSessionCleanupTimeout)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return while session cleanup was stuck")
	}
}

// Bounding the cleanup means it can still be running after Shutdown has given
// up on it, and what it was about to do is delete every session carrying this
// node's address. That listing is stale by then, and the address identifies the
// node rather than the process: a server that took the same address after this
// one gave up owns the sessions the abandoned cleanup would delete, in a store
// both of them share. Giving up therefore has to revoke its permission to
// delete, not merely stop waiting for it.
func TestAbandonedSessionCleanupDoesNotDelete(t *testing.T) {
	restore := sessionCleanupDeadline
	sessionCleanupDeadline = 50 * time.Millisecond
	t.Cleanup(func() { sessionCleanupDeadline = restore })

	logger := slog.New(slog.DiscardHandler)
	store := newHangingListStore(logger)

	nodeAddr := "127.0.0.1:2222"
	sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	_, err := sm.CreateSession(NewSession("doomed", nodeAddr, "owen", nil, nil))
	require.NoError(t, err)

	s := &Server{
		NodeAddr:       nodeAddr,
		SessionManager: sm,
		Logger:         logger,
		cancel:         func() {},
	}

	done := make(chan error, 1)
	go func() { done <- s.Shutdown() }()

	select {
	case <-store.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("session cleanup never started")
	}

	select {
	case err := <-done:
		require.ErrorIs(t, err, errSessionCleanupTimeout)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return while session cleanup was stuck")
	}

	// Shutdown has given up. Unblock the cleanup and stand in for the server
	// that took this node address next: its session must survive.
	close(store.release)

	select {
	case ids := <-store.deleted:
		t.Fatalf("abandoned cleanup deleted %v after Shutdown had given up", ids)
	case <-time.After(time.Second):
	}

	// Read through the embedded store: the override closes entered, and would
	// panic on a second call.
	surviving, err := store.SessionStore.List()
	require.NoError(t, err)
	require.Len(t, surviving, 1, "abandoned cleanup emptied the store it no longer owned")
}

// run.Group's interrupt signature is func(error), so a failing Shutdown had
// nowhere to report to: it was logged and dropped, Start returned g.Run's
// error -- nil on a requested stop -- and the process exited 0. A deploy that
// could not delete this node's sessions looked successful to the supervisor,
// which is the blind spot #573 was about, one layer in.
//
// The failure has to be the session cleanup rather than the wait for serving to
// stop. An earlier version of this test raced the two actors so that Shutdown's
// wait would time out, and Windows CI showed why that cannot be relied on: when
// the interrupt runs before ServeWithContext has recorded its channel, Shutdown
// finds a nil served, skips the wait and reports nothing. The cleanup runs on
// every path, so failing it is the arrangement with no ordering in it.
//
// A Consul that answers during startup and is gone by shutdown produces exactly
// that: registration succeeds, so Start comes up, and the deletes afterwards
// have nowhere to go.
func TestStartReportsAShutdownThatFailed(t *testing.T) {
	// Start registers its metrics on prometheus.DefaultRegisterer with
	// MustRegister, which panics on a duplicate. A registry of our own keeps
	// this test hermetic and lets it run under -count=2.
	restoreReg := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	t.Cleanup(func() { prometheus.DefaultRegisterer = restoreReg })

	t.Setenv("PRIVATE_KEY", "")
	keyPath := filepath.Join(t.TempDir(), "host_key")
	require.NoError(t, os.WriteFile(keyPath, []byte(TestPrivateKeyContent), 0600))

	// Enough of Consul's HTTP API for newConsulSessionStore to come up: an
	// empty JSON array reads as "no sessions", which every call this makes
	// during startup accepts.
	consul := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Consul-Index", "1")
		_, _ = w.Write([]byte("[]"))
	}))
	consulStopped := false
	t.Cleanup(func() {
		if !consulStopped {
			consul.Close()
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() {
		done <- Start(ctx, Opt{
			SSHAddr:          "127.0.0.1:0",
			WSAddr:           "127.0.0.1:0",
			HandshakeTimeout: 4 * time.Second,
			PrivateKeys:      []string{keyPath},
			Network:          "mem",
			Routing:          routing.ModeConsul,
			ConsulURL:        consul.URL,
		}, slog.New(slog.DiscardHandler))
	}()

	// Fail fast if startup itself failed, rather than reading a startup error
	// as the shutdown error under test.
	select {
	case err := <-done:
		t.Fatalf("Start returned before it was asked to stop: %v", err)
	case <-time.After(time.Second):
	}

	// Take Consul away, then ask for the stop the cleanup will fail during.
	consul.Close()
	consulStopped = true
	cancel()

	select {
	case err := <-done:
		require.Error(t, err, "Start reported success for a shutdown that could not clean up")
		// Matches both ways the cleanup can fail here, so which one a platform
		// produces does not matter: Shutdown's own wrapper ("session cleanup:
		// ...") when the deletes are refused outright, and
		// errSessionCleanupTimeout ("session cleanup did not finish within its
		// deadline") if they hang until the bound instead.
		require.Contains(t, err.Error(), "session cleanup",
			"Start dropped the error from a Shutdown that did not complete")
	case <-time.After(30 * time.Second):
		t.Fatal("Start did not return after its context was cancelled")
	}
}
