package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/owenthereal/upterm/routing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hangingListStore blocks in List, the first call SessionManager.Shutdown makes,
// until the test releases it, and records whether a delete followed.
type hangingListStore struct {
	SessionStore
	entered     chan struct{}
	gate        chan struct{}
	release     func() // opens gate; safe to call more than once
	deleted     chan []string
	closed      chan struct{}
	closeSignal func()
}

func (s hangingListStore) List() ([]*Session, error) {
	close(s.entered)
	<-s.gate
	return s.SessionStore.List()
}

func (s hangingListStore) BatchDelete(sessionIDs []string) error {
	select {
	case s.deleted <- sessionIDs:
	default:
	}
	return s.SessionStore.BatchDelete(sessionIDs)
}

func (s hangingListStore) Close() error {
	s.closeSignal()
	return s.SessionStore.Close()
}

func newHangingListStore(logger *slog.Logger) hangingListStore {
	gate, closed := make(chan struct{}), make(chan struct{})
	return hangingListStore{
		SessionStore: newMemorySessionStore(logger),
		entered:      make(chan struct{}),
		gate:         gate,
		release:      sync.OnceFunc(func() { close(gate) }),
		deleted:      make(chan []string, 1),
		closed:       closed,
		closeSignal:  sync.OnceFunc(func() { close(closed) }),
	}
}

// A legacy contextless List can remain parked after cleanup cancellation.
// Shutdown must bound its wait even though the call cannot be interrupted;
// a supervisor's grace period is set against that bound.
//
// It runs in a synctest bubble, where time is fake, with the cleanup's bound
// set to 50 ms. The bound is checked on both sides of it, and against the
// default: 50 ms - 1 ns (still waiting) < 50 ms (returned) <
// defaultSessionCleanupDeadline (3 s), where a Shutdown that ignored the
// setting would return.
func TestServerShutdownBoundsSessionCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const deadline = 50 * time.Millisecond
		logger := slog.New(slog.DiscardHandler)
		store := newHangingListStore(logger)
		// Let the abandoned goroutine finish so it does not outlive the test.
		t.Cleanup(store.release)

		s := &Server{
			NodeAddr:       "127.0.0.1:0",
			SessionManager: newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded)),
			Logger:         logger,
			cancel:         func() {},
			// served is nil: this Server never served, so the wait before the
			// cleanup is skipped and only the cleanup's own bound is under test.
			sessionCleanupDeadline: deadline,
		}

		done := make(chan error, 1)
		go func() { done <- s.Shutdown() }()

		synctest.Wait() // the cleanup has reached List, which holds it
		select {
		case <-store.entered:
		default:
			t.Fatal("session cleanup never started, so its deadline proves nothing")
		}

		time.Sleep(deadline - time.Nanosecond)
		synctest.Wait() // every wake due before the deadline has run
		select {
		case err := <-done:
			t.Fatalf("Shutdown returned before its cleanup deadline: %v", err)
		default:
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait() // the deadline's own expiry, and Shutdown's return on it, have run
		select {
		case err := <-done:
			require.ErrorIs(t, err, errSessionCleanupTimeout)
		default:
			t.Fatal("Shutdown was still waiting on the stuck cleanup at its deadline")
		}
	})
}

// Bounding the cleanup means it can still be running after Shutdown has given
// up on it, and what it was about to do is delete every session carrying this
// node's address. That listing is stale by then, and the address identifies the
// node rather than the process: a server that took the same address after this
// one gave up may own sessions that listing names. Consul's deletes are
// conditional on this process's leases, which spares them there, but a store
// without that check would delete them. Giving up therefore has to revoke its
// permission to delete, not merely stop waiting for it.
//
// It runs in a synctest bubble, where time is fake, with the cleanup's bound
// set to 50 ms. The bound is checked on both sides of it, and against the
// default: 50 ms - 1 ns (still waiting) < 50 ms (returned) <
// defaultSessionCleanupDeadline (3 s), where a Shutdown that ignored the
// setting would return. Released after that, the cleanup runs to its end
// with no time passing, so what it did is settled, not waited for.
func TestAbandonedSessionCleanupDoesNotDelete(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const deadline = 50 * time.Millisecond
		logger := slog.New(slog.DiscardHandler)
		store := newHangingListStore(logger)
		// Let the abandoned goroutine finish so it does not outlive the test,
		// should the test fail before it releases List itself.
		t.Cleanup(store.release)

		nodeAddr := "127.0.0.1:2222"
		sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
		_, err := sm.CreateSession(NewSession("doomed", nodeAddr, "owen", nil, nil))
		require.NoError(t, err)

		s := &Server{
			NodeAddr:               nodeAddr,
			SessionManager:         sm,
			Logger:                 logger,
			cancel:                 func() {},
			sessionCleanupDeadline: deadline,
		}

		done := make(chan error, 1)
		go func() { done <- s.Shutdown() }()

		synctest.Wait() // the cleanup has reached List, which holds it
		select {
		case <-store.entered:
		default:
			t.Fatal("session cleanup never started")
		}

		time.Sleep(deadline - time.Nanosecond)
		synctest.Wait() // every wake due before the deadline has run
		select {
		case err := <-done:
			t.Fatalf("Shutdown returned before its cleanup deadline: %v", err)
		default:
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait() // the deadline's own expiry, and Shutdown's return on it, have run
		select {
		case err := <-done:
			require.ErrorIs(t, err, errSessionCleanupTimeout)
		default:
			t.Fatal("Shutdown was still waiting on the stuck cleanup at its deadline")
		}

		select {
		case <-store.closed:
		default:
			t.Fatal("abandoned legacy cleanup did not enter Close before List release")
		}

		// Shutdown has given up. Unblock the cleanup and stand in for the server
		// that took this node address next: its session must survive.
		store.release()
		synctest.Wait() // the released cleanup has run to its end
		select {
		case ids := <-store.deleted:
			t.Fatalf("abandoned cleanup deleted %v after Shutdown had given up", ids)
		default:
		}

		// Read through the embedded store: the override closes entered, and would
		// panic on a second call.
		surviving, err := store.SessionStore.List()
		require.NoError(t, err)
		require.Len(t, surviving, 1, "abandoned cleanup emptied the store it no longer owned")
	})
}

// Start must retain the cleanup failure that its run.Group interrupt observes.
// Catalog success and a real WS health response establish that startup finished
// before the test makes the later cleanup List fail. The first watch request
// remains held until cancellation so it cannot consume the cleanup responses.
func TestStartReportsAShutdownThatFailed(t *testing.T) {
	restoreReg := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	t.Cleanup(func() { prometheus.DefaultRegisterer = restoreReg })

	t.Setenv("PRIVATE_KEY", "")
	keyPath := filepath.Join(t.TempDir(), "host_key")
	require.NoError(t, os.WriteFile(keyPath, []byte(TestPrivateKeyContent), 0600))

	const cleanupFailure = "injected cleanup List failure"
	catalogDone := make(chan struct{})
	watchEntered, watchCancelled, watchDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	watchGate := make(chan struct{})
	releaseWatch := sync.OnceFunc(func() { close(watchGate) })
	var kvRequests, cleanupRequests atomic.Int64
	var failCleanup atomic.Bool
	consul, connections := newCloseServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Consul-Index", "1")
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/v1/catalog/register":
			_, _ = io.WriteString(w, "true")
			close(catalogDone)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/kv/"):
			if kvRequests.Add(1) == 1 {
				defer close(watchDone)
				close(watchEntered)
				select {
				case <-r.Context().Done():
					close(watchCancelled)
				case <-watchGate:
				}
				return
			}
			if failCleanup.Load() {
				cleanupRequests.Add(1)
				http.Error(w, cleanupFailure, http.StatusInternalServerError)
				return
			}
			_, _ = io.WriteString(w, "[]")
		default:
			t.Errorf("unexpected Consul request: %s %s", r.Method, r.URL)
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	t.Cleanup(releaseWatch)

	logs := make(proxyProtocolTestLogs, 128)
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	// The closed channel publishes this one stored result to both the test and
	// cleanup; neither observer consumes the other's completion notification.
	done := make(chan struct{})
	var result error
	go func() {
		result = Start(ctx, Opt{
			SSHAddr:          "127.0.0.1:0",
			WSAddr:           "127.0.0.1:0",
			HandshakeTimeout: 4 * time.Second,
			PrivateKeys:      []string{keyPath},
			Network:          "mem",
			Routing:          routing.ModeConsul,
			ConsulURL:        consul.URL,
		}, logger)
		close(done)
	}()
	t.Cleanup(func() {
		// Release held handlers before joining even when an assertion failed.
		// Keep the endpoint alive until Start and the remote handler are joined.
		releaseWatch()
		cancel()
		receiveWithin(t, done, "Start survived failure cleanup")
		if kvRequests.Load() != 0 {
			receiveWithin(t, watchDone, "remote watch survived failure cleanup")
		}
		awaitShutdownConnectionsClosed(t, connections)
	})

	receiveWithin(t, catalogDone, "catalog registration never succeeded")
	receiveWithin(t, watchEntered, "first watch request never entered")
	var wsAddr string
	startupGuard := time.NewTimer(5 * time.Second)
	defer startupGuard.Stop()
	for wsAddr == "" {
		select {
		case record := <-logs:
			if record["msg"] == "starting server" {
				wsAddr, _ = record["ws_addr"].(string)
				require.NotEmpty(t, wsAddr, "startup log omitted WS address")
			}
		case <-done:
			t.Fatalf("Start returned before its startup witness: %v", result)
		case <-startupGuard.C:
			t.Fatal("Start never published its startup address")
		}
	}

	healthTransport := &http.Transport{}
	t.Cleanup(healthTransport.CloseIdleConnections)
	healthClient := &http.Client{Transport: healthTransport, Timeout: 5 * time.Second}
	response, err := healthClient.Get("http://" + wsAddr + "/health")
	require.NoError(t, err, "WS listener never served its health response")
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	require.NoError(t, readErr)
	require.NoError(t, closeErr)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "OK", string(body))
	healthTransport.CloseIdleConnections()

	// The positive serving witness precedes both the injected failure and stop.
	failCleanup.Store(true)
	cancel()
	receiveWithin(t, done, "Start did not return after cancellation")
	require.Positive(t, cleanupRequests.Load(), "Shutdown never attempted the failing cleanup List")
	require.Error(t, result, "Start reported success for a shutdown that could not clean up")
	require.ErrorContains(t, result, "session cleanup", "Start dropped its Shutdown error")
	require.ErrorContains(t, result, cleanupFailure, "Start did not retain the actual cleanup failure")
	// Client completion and remote request cancellation are separate joins; the
	// fixture requires both without assuming which is observed first.
	receiveWithin(t, watchCancelled, "remote watch context was not cancelled")
	receiveWithin(t, watchDone, "remote watch handler did not finish")
	awaitShutdownConnectionsClosed(t, connections)
}

func TestServerShutdownPreservesAvailableCleanupErrors(t *testing.T) {
	for _, row := range []struct {
		name                                           string
		expired, published, nilResult, managerDeadline bool
	}{
		{name: "both_ready", expired: true, published: true},
		{name: "expired_nil_result", expired: true, published: true, nilResult: true},
		{name: "expired_no_result", expired: true},
		{name: "live_result", published: true},
		{name: "live_nil_result", published: true, nilResult: true},
		{name: "manager_deadline_with_live_server", published: true, managerDeadline: true},
	} {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				if row.expired {
					var cancel context.CancelFunc
					ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Nanosecond))
					t.Cleanup(cancel)
				}
				cleanupErr, closeErr := errors.New("cleanup failed"), errors.New("close failed")
				cleaned := make(chan error, 1)
				if row.published {
					switch {
					case row.nilResult:
						cleaned <- nil
					case row.managerDeadline:
						cleaned <- context.DeadlineExceeded
					default:
						cleaned <- errors.Join(cleanupErr, closeErr)
					}
				}
				before := time.Now()
				err := waitForServerSessionCleanup(ctx, cleaned)
				assert.Equal(t, before, time.Now(), "Server added a grace wait for cleanup")
				if row.expired {
					assert.ErrorIs(t, err, errSessionCleanupTimeout)
				} else {
					assert.NotErrorIs(t, err, errSessionCleanupTimeout)
				}
				if row.published && !row.nilResult {
					assert.ErrorContains(t, err, "session cleanup:")
					if row.managerDeadline {
						assert.ErrorIs(t, err, context.DeadlineExceeded)
					} else {
						assert.ErrorIs(t, err, cleanupErr)
						assert.ErrorIs(t, err, closeErr)
					}
				} else if !row.expired {
					assert.NoError(t, err)
				}
			})
		})
	}
}

func TestServerShutdownJoinsServingAndCleanupErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const deadline = 50 * time.Millisecond
		listErr, closeErr := errors.New("List failed during shutdown"), errors.New("Close failed during shutdown")
		served, done := make(chan struct{}), make(chan struct{})
		release := sync.OnceFunc(func() { close(served) })
		store := &shutdownProbeStore{
			listFn:   func() ([]*Session, error) { return nil, listErr },
			closeErr: closeErr,
		}
		s := &Server{NodeAddr: "node", SessionManager: newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded)), Logger: slog.New(slog.DiscardHandler), served: served, serveStopDeadline: deadline}
		var result error
		go func() { result = s.Shutdown(); close(done) }()
		t.Cleanup(func() {
			release()
			synctest.Wait() // Releasing serving lets even a broken deadline path finish before the join.
			receiveWithin(t, done, "Server survived released serving fixture")
			if store.closeCalls.Load() == 0 {
				_ = store.Close()
			}
		})
		synctest.Wait() // Server is waiting for the held serving completion channel.
		// 50ms - 1ns < the instance deadline < the unchanged production default.
		time.Sleep(deadline - time.Nanosecond)
		synctest.Wait() // Every wake before the instance serving deadline has settled.
		select {
		case <-done:
			t.Fatal("Server returned before its serving deadline")
		default:
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait() // Serving timeout and immediate cleanup/Close errors have completed.
		select {
		case <-done:
			assert.ErrorIs(t, result, errShutdownIncomplete)
			assert.ErrorIs(t, result, listErr)
			assert.ErrorIs(t, result, closeErr)
			assert.ErrorContains(t, result, "session cleanup:")
			assert.Equal(t, int64(1), store.closeCalls.Load())
		default:
			t.Fatal("Server did not return serving and cleanup failures at its deadline")
		}
	})
}
