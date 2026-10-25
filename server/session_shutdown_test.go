package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/owenthereal/upterm/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Embed the exported interface so the fake cannot inherit Consul-only methods.
type shutdownProbeStore struct {
	SessionStore
	listFn       func() ([]*Session, error)
	deleteFn     func([]string) error
	closeErr     error
	closeCalls   atomic.Int64
	closeEntered chan struct{}
	closeSignal  sync.Once
}

func (s *shutdownProbeStore) List() ([]*Session, error)      { return s.listFn() }
func (s *shutdownProbeStore) BatchDelete(ids []string) error { return s.deleteFn(ids) }
func (s *shutdownProbeStore) Close() error {
	s.closeCalls.Add(1)
	if s.closeEntered != nil {
		s.closeSignal.Do(func() { close(s.closeEntered) })
	}
	return s.closeErr
}

type shutdownProbeTransport struct{ next *http.Transport }

func (s shutdownProbeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.Header.Set("X-Upterm-Cleanup-Probe", "true")
	return s.next.RoundTrip(copy)
}
func (s shutdownProbeTransport) CloseIdleConnections() { s.next.CloseIdleConnections() }

// Every failed cleanup exit still owns the store's finalization and its error.
func TestSessionManagerShutdownClosesOnCleanupFailure(t *testing.T) {
	for _, test := range []struct {
		name                                                   string
		listFails, deleteFails, cancelBeforeDelete, closeFails bool
	}{
		{name: "list", listFails: true},
		{name: "delete", deleteFails: true},
		{name: "canceled_pre_delete", cancelBeforeDelete: true},
		{name: "close", closeFails: true},
		{name: "list_and_close", listFails: true, closeFails: true},
		{name: "delete_and_close", deleteFails: true, closeFails: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				listErr, deleteErr, closeErr := errors.New("list failed"), errors.New("delete failed"), errors.New("close failed")
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				store := &shutdownProbeStore{}
				store.listFn = func() ([]*Session, error) {
					if test.listFails {
						return nil, listErr
					}
					if test.cancelBeforeDelete {
						cancel()
					}
					return []*Session{{ID: "owned", NodeAddr: "node"}}, nil
				}
				store.deleteFn = func(ids []string) error {
					assert.Equal(t, []string{"owned"}, ids)
					if test.deleteFails {
						return deleteErr
					}
					return nil
				}
				if test.closeFails {
					store.closeErr = closeErr
				}
				t.Cleanup(func() {
					synctest.Wait() // Any immediately runnable legacy worker finishes before fallback store cleanup.
					if store.closeCalls.Load() == 0 {
						_ = store.Close()
					}
				})
				manager := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
				err := manager.Shutdown(ctx, "node")
				synctest.Wait() // Complete an immediately runnable legacy worker before checking finalization.
				assert.Equal(t, int64(1), store.closeCalls.Load(), "cleanup exit bypassed store Close")
				if test.listFails {
					assert.ErrorIs(t, err, listErr)
				}
				if test.deleteFails {
					assert.ErrorIs(t, err, deleteErr)
				}
				if test.cancelBeforeDelete {
					assert.ErrorIs(t, err, context.Canceled)
				}
				if test.closeFails {
					assert.ErrorIs(t, err, closeErr)
				}
			})
		})
	}
}

func TestSessionManagerShutdownClosesAfterCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		release := sync.OnceFunc(func() { close(resume) })
		store := &shutdownProbeStore{closeEntered: make(chan struct{})}
		store.listFn = func() ([]*Session, error) {
			close(entered)
			<-resume
			return []*Session{{ID: "owned", NodeAddr: "node"}}, nil
		}
		store.deleteFn = func([]string) error { t.Error("cleanup deleted a listing returned after cancellation"); return nil }
		manager := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
		var result error
		go func() { result = manager.Shutdown(ctx, "node"); close(done) }()
		t.Cleanup(func() {
			cancel()
			release()
			synctest.Wait() // Released legacy List and its cleanup worker can now finish before the join.
			<-done
			if store.closeCalls.Load() == 0 {
				_ = store.Close()
			}
		})
		synctest.Wait() // Manager has entered the held legacy List boundary.
		select {
		case <-entered:
		default:
			t.Fatal("legacy List never entered")
		}
		cancel()
		synctest.Wait() // Cancellation can finalize the manager while legacy List remains held.
		// Cancellation must cross the held legacy call without advancing time.
		select {
		case <-store.closeEntered:
		default:
			t.Error("cancellation did not reach Close before List release")
		}
		select {
		case <-done:
			assert.ErrorIs(t, result, context.Canceled)
		default:
			t.Error("manager still waits for legacy List after cancellation")
		}
	})
}

// Hold actual API requests, separately from the watch, before cancellation.
// The 2s guard is below the existing 5s client timeout, so a natural request
// timeout cannot satisfy the cancellation witness.
func TestConsulShutdownCancelsCleanupRequests(t *testing.T) {
	for _, boundary := range []string{"list", "transaction", "lost_hold"} {
		t.Run(boundary, func(t *testing.T) {
			entered, cancelled, handlerDone := make(chan time.Time, 1), make(chan time.Time, 1), make(chan struct{})
			watchEntered, watchCancelled, watchHandlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
			resume := make(chan struct{})
			release := sync.OnceFunc(func() { close(resume) })
			var watchOnce sync.Once
			var heldOnce sync.Once
			value, err := json.Marshal(&Session{ID: "owned", NodeAddr: "node"})
			require.NoError(t, err)
			pairs := api.KVPairs{{Key: "uptermd/sessions/owned", Value: value, Session: "owned-lease", ModifyIndex: 1}}
			srv, connections := newCloseServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Consul-Index", "1")
				if r.Header.Get("X-Upterm-Cleanup-Probe") == "" {
					first := false
					watchOnce.Do(func() { first = true; close(watchEntered) })
					if first {
						defer close(watchHandlerDone)
					}
					<-r.Context().Done()
					if first {
						close(watchCancelled)
					}
					return
				}
				isList := r.URL.Path == "/v1/kv/uptermd/sessions"
				isTxn := r.URL.Path == "/v1/txn"
				isHeld := (boundary == "list" && isList) || (boundary == "transaction" && isTxn) || (boundary == "lost_hold" && !isList && !isTxn)
				if isHeld {
					first := false
					heldOnce.Do(func() { first = true })
					if first {
						defer close(handlerDone)
						entered <- time.Now()
						select {
						case <-r.Context().Done():
							cancelled <- time.Now()
						case <-resume:
						}
					}
					select {
					case <-r.Context().Done():
						return
					default:
					}
				}
				if isList {
					_ = json.NewEncoder(w).Encode(pairs)
					return
				}
				if isTxn {
					if boundary == "lost_hold" {
						w.WriteHeader(http.StatusConflict)
						_, _ = io.WriteString(w, `{"Errors":[{"OpIndex":0,"What":"session check failed"}]}`)
					} else {
						_, _ = io.WriteString(w, `{"Results":[]}`)
					}
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			logger := slog.New(slog.DiscardHandler)
			transport := &http.Transport{}
			client := &http.Client{Timeout: DefaultConsulTimeout, Transport: shutdownProbeTransport{next: transport}}
			// This wrapper deliberately owns the underlying transport too.
			t.Cleanup(transport.CloseIdleConnections)
			cfg := api.DefaultConfig()
			cfg.Address, cfg.HttpClient = srv.URL, client
			apiClient, err := api.NewClient(cfg)
			require.NoError(t, err)
			store := &consulSessionStore{client: apiClient, apiHTTP: client, logger: logger, keyPrefix: DefaultKeyPrefix, cache: newSessionCache(logger), held: map[string]map[string]struct{}{"owned": {"owned-lease": {}}}}
			t.Cleanup(func() { release(); assert.NoError(t, store.Close()); transport.CloseIdleConnections() })
			require.NoError(t, store.startSessionWatch(cfg))
			receiveWithin(t, watchEntered, "watch never entered")
			ctx, cancel := context.WithCancel(context.Background())
			probe := &shutdownCleanupProbe{consulSessionStore: store, closeEntered: make(chan struct{})}
			manager := newSessionManagerWithStore(probe, routing.NewEncodeDecoder(routing.ModeEmbedded))
			done := make(chan struct{})
			var result error
			go func() { result = manager.Shutdown(ctx, "node"); close(done) }()
			t.Cleanup(func() {
				release()
				cancel()
				receiveWithin(t, done, "manager survived released cleanup request")
				assert.NoError(t, store.Close())
				receiveWithin(t, store.watchDone, "watch survived explicit Close")
				receiveWithin(t, watchHandlerDone, "remote watch handler survived cleanup")
				transport.CloseIdleConnections()
			})
			entryAt := receiveWithin(t, entered, "cleanup request never entered")
			cancelAt := time.Now()
			cancel()
			guard := time.NewTimer(2 * time.Second)
			defer guard.Stop()
			select {
			case observedAt := <-cancelled:
				t.Logf("boundary=%s entry=%s cancel=%s observed=%s elapsed=%s", boundary, entryAt.Format(time.RFC3339Nano), cancelAt.Format(time.RFC3339Nano), observedAt.Format(time.RFC3339Nano), observedAt.Sub(cancelAt))
			case <-guard.C:
				guardAt := time.Now()
				t.Errorf("cleanup request remained active after cancellation: boundary=%s entry=%s cancel=%s guard=%s elapsed=%s client_timeout=%s", boundary, entryAt.Format(time.RFC3339Nano), cancelAt.Format(time.RFC3339Nano), guardAt.Format(time.RFC3339Nano), guardAt.Sub(cancelAt), DefaultConsulTimeout)
			}
			release()
			receiveWithin(t, handlerDone, "released API handler survived")
			receiveWithin(t, done, "released manager survived")
			require.ErrorIs(t, result, context.Canceled)
			assert.Equal(t, int64(1), probe.closeCalls.Load())
			assert.False(t, probe.closedWhileActive.Load(), "store Close raced a cleanup helper")
			wantReturns := int64(2)
			if boundary == "list" {
				wantReturns = 1
			}
			assert.Equal(t, wantReturns, probe.returns.Load())
			assert.Equal(t, wantReturns, probe.returnsAtClose.Load(), "Close preceded cleanup helper return")
			receiveWithin(t, store.watchDone, "watch survived manager finalization")
			receiveWithin(t, watchCancelled, "remote watch context was not cancelled")
			receiveWithin(t, watchHandlerDone, "remote watch handler survived finalization")
			awaitShutdownConnectionsClosed(t, connections)
		})
	}
}

// shutdownCleanupProbe explicitly intercepts the private capability. Embedding
// Consul alone would promote its helpers and bypass exported-method overrides.
type shutdownCleanupProbe struct {
	*consulSessionStore
	active            atomic.Int64
	returns           atomic.Int64
	closeCalls        atomic.Int64
	returnsAtClose    atomic.Int64
	closedWhileActive atomic.Bool
	closeEntered      chan struct{}
	closeSignal       sync.Once
}

func (s *shutdownCleanupProbe) list(ctx context.Context) ([]*Session, error) {
	s.active.Add(1)
	defer func() { s.returns.Add(1); s.active.Add(-1) }()
	return s.consulSessionStore.list(ctx)
}

func (s *shutdownCleanupProbe) batchDelete(ctx context.Context, ids []string) error {
	s.active.Add(1)
	defer func() { s.returns.Add(1); s.active.Add(-1) }()
	return s.consulSessionStore.batchDelete(ctx, ids)
}

func (s *shutdownCleanupProbe) Close() error {
	s.closeCalls.Add(1)
	s.returnsAtClose.Store(s.returns.Load())
	if s.active.Load() != 0 {
		s.closedWhileActive.Store(true)
	}
	if s.closeEntered != nil {
		s.closeSignal.Do(func() { close(s.closeEntered) })
	}
	return s.consulSessionStore.Close()
}

// An active survivor can also have zero idle connections. Require every owned
// connection to have closed before httptest.Server.Close can conceal one.
func awaitShutdownConnectionsClosed(t *testing.T, connections *closeConnections) {
	t.Helper()
	guard := time.NewTimer(2 * time.Second)
	defer guard.Stop()
	for {
		connections.mu.Lock()
		states := make([]http.ConnState, 0, len(connections.states))
		allClosed := len(connections.states) > 0
		for _, state := range connections.states {
			states = append(states, state)
			if state != http.StateClosed {
				allClosed = false
			}
		}
		connections.mu.Unlock()
		if allClosed {
			t.Logf("all %d owned HTTP connections closed", len(states))
			return
		}
		select {
		case <-connections.changed:
		case <-guard.C:
			t.Fatalf("owned HTTP connections still open before fake teardown: %v", states)
		}
	}
}

type shutdownPrivateProbeStore struct {
	*shutdownProbeStore
	cleanupList func(context.Context) ([]*Session, error)
}

func (s shutdownPrivateProbeStore) list(ctx context.Context) ([]*Session, error) {
	return s.cleanupList(ctx)
}
func (s shutdownPrivateProbeStore) batchDelete(context.Context, []string) error {
	return errors.New("unexpected delete after empty listing")
}

func TestSessionManagerShutdownPreservesAvailableErrors(t *testing.T) {
	for _, row := range []struct {
		name                string
		canceled, published bool
	}{
		{"both_ready", true, true}, {"result_only", false, true}, {"cancellation_only", true, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				cleanupErr := errors.New("published cleanup failure")
				cleaned := make(chan error, 1)
				if row.published {
					cleaned <- cleanupErr
				}
				if row.canceled {
					cancel()
				}
				before := time.Now()
				err := waitForSessionCleanup(ctx, cleaned)
				assert.Equal(t, before, time.Now(), "selection waited for an unavailable future result")
				if row.published {
					assert.ErrorIs(t, err, cleanupErr)
				}
				if row.canceled {
					assert.ErrorIs(t, err, context.Canceled)
				} else {
					assert.NotErrorIs(t, err, context.Canceled)
				}
			})
		})
	}
	t.Run("private_empty_list_cancels_before_return", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			closeErr := errors.New("close failed after empty listing")
			base := &shutdownProbeStore{closeErr: closeErr}
			store := shutdownPrivateProbeStore{shutdownProbeStore: base, cleanupList: func(context.Context) ([]*Session, error) {
				cancel()
				return nil, nil
			}}
			t.Cleanup(func() {
				if base.closeCalls.Load() == 0 {
					_ = base.Close()
				}
			})
			manager := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
			err := manager.Shutdown(ctx, "node")
			assert.ErrorIs(t, err, context.Canceled)
			assert.ErrorIs(t, err, closeErr)
			assert.Equal(t, int64(1), base.closeCalls.Load())
		})
	})
}

func TestSessionManagerShutdownLegacyLateCalls(t *testing.T) {
	for _, boundary := range []string{"list", "already_entered_delete"} {
		t.Run(boundary, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				entered, resume, returned, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
				release := sync.OnceFunc(func() { close(resume) })
				var deletes atomic.Int64
				store := &shutdownProbeStore{closeEntered: make(chan struct{})}
				store.listFn = func() ([]*Session, error) {
					if boundary == "list" {
						close(entered)
						<-resume
						close(returned)
					}
					return []*Session{{ID: "owned", NodeAddr: "node"}}, nil
				}
				store.deleteFn = func(ids []string) error {
					deletes.Add(1)
					assert.Equal(t, []string{"owned"}, ids)
					if boundary == "already_entered_delete" {
						close(entered)
						<-resume
						close(returned)
					}
					return nil
				}
				manager := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
				var result error
				go func() { result = manager.Shutdown(ctx, "node"); close(done) }()
				t.Cleanup(func() {
					cancel()
					release()
					synctest.Wait() // Released contextless call and its cleanup worker can now finish.
					receiveWithin(t, done, "legacy manager survived release")
					receiveWithin(t, returned, "legacy call survived release")
					if store.closeCalls.Load() == 0 {
						_ = store.Close()
					}
				})
				synctest.Wait() // Cleanup has entered the held List or BatchDelete boundary.
				select {
				case <-entered:
				default:
					t.Fatal("legacy call never entered")
				}
				cancel()
				synctest.Wait() // Manager can finalize, although the contextless call remains held.
				select {
				case <-done:
					assert.ErrorIs(t, result, context.Canceled)
				default:
					t.Error("legacy call held manager after cancellation")
				}
				select {
				case <-store.closeEntered:
				default:
					t.Error("Close did not cross legacy cancellation")
				}
				select {
				case <-returned:
					t.Error("test released its held call before the cancellation assertion")
				default:
				}
				// The fence rejects a late listing, but cannot cancel an entered
				// BatchDelete or make its check-to-call interval atomic.
				release()
				synctest.Wait() // The returned listing reaches the fence, or the entered delete completes.
				wantDeletes := int64(0)
				if boundary == "already_entered_delete" {
					wantDeletes = 1
				}
				assert.Equal(t, wantDeletes, deletes.Load())
				assert.Equal(t, int64(1), store.closeCalls.Load())
			})
		})
	}
}

// Construct this only inside its caller's bubble. It has no real sockets,
// client timeout or watch goroutine to keep fake time from settling.
func newShutdownSocketStore(t *testing.T, roundTrip closeRoundTripFunc) *consulSessionStore {
	t.Helper()
	cfg := api.DefaultConfig()
	cfg.Address = "127.0.0.1:1"
	cfg.HttpClient = &http.Client{Transport: roundTrip}
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	logger := slog.New(slog.DiscardHandler)
	return &consulSessionStore{client: client, apiHTTP: cfg.HttpClient, logger: logger, keyPrefix: DefaultKeyPrefix, cache: newSessionCache(logger), held: make(map[string]map[string]struct{})}
}

func shutdownSocketResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"X-Consul-Index": {"1"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestConsulShutdownStopsCleanupRetries(t *testing.T) {
	for _, boundary := range []string{"list", "transaction"} {
		t.Run(boundary, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				failed, done := make(chan struct{}), make(chan struct{})
				var first sync.Once
				var attempts atomic.Int64
				value, err := json.Marshal(&Session{ID: "owned", NodeAddr: "node"})
				require.NoError(t, err)
				pairs, err := json.Marshal(api.KVPairs{{Key: "uptermd/sessions/owned", Value: value, Session: "owned-lease", ModifyIndex: 1}})
				require.NoError(t, err)
				store := newShutdownSocketStore(t, func(r *http.Request) (*http.Response, error) {
					if boundary == "transaction" && r.URL.Path != "/v1/txn" {
						return shutdownSocketResponse(http.StatusOK, string(pairs)), nil
					}
					if n := attempts.Add(1); n > int64(DefaultMaxRetries) {
						t.Errorf("cleanup exceeded bounded retry attempts: %d", n)
					}
					first.Do(func() { close(failed) })
					// Every attempt, including failure cleanup after release, is
					// nonblocking. Production's bounded retry loop owns its waits.
					return nil, errors.New("retryable cleanup request failure")
				})
				store.held["owned"] = map[string]struct{}{"owned-lease": {}}
				probe := &shutdownCleanupProbe{consulSessionStore: store, closeEntered: make(chan struct{})}
				manager := newSessionManagerWithStore(probe, routing.NewEncodeDecoder(routing.ModeEmbedded))
				var result error
				t.Cleanup(func() { assert.NoError(t, store.Close()) })
				go func() { result = manager.Shutdown(ctx, "node"); close(done) }()
				t.Cleanup(func() {
					cancel()
					// On a failed same-time assertion this bounded wait permits
					// the remaining retry timers to run and joins their owner.
					receiveWithin(t, done, "bounded cleanup retries survived failure cleanup")
				})
				synctest.Wait() // First retryable failure has returned; cleanup is parked in its retry delay.
				select {
				case <-failed:
				default:
					t.Fatal("first retryable failure was not acknowledged")
				}
				before := time.Now()
				cancel()
				synctest.Wait() // Cancellation must wake the retry wait at the current fake time.
				select {
				case <-done:
					assert.ErrorIs(t, result, context.Canceled)
				default:
					t.Error("cleanup retry wait did not stop at cancellation")
				}
				select {
				case <-probe.closeEntered:
				default:
					t.Error("retry wait delayed Close after cancellation")
				}
				assert.Equal(t, before, time.Now(), "assertion advanced through the retry delay")
				assert.GreaterOrEqual(t, attempts.Load(), int64(1))
				assert.LessOrEqual(t, attempts.Load(), int64(DefaultMaxRetries))
			})
		})
	}
}

func TestConsulShutdownStopsNextBatch(t *testing.T) {
	t.Run("successful_first_batch", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			var transactions int
			var committed []string
			store := newShutdownSocketStore(t, func(r *http.Request) (*http.Response, error) {
				transactions++
				if transactions > 1 {
					return nil, errors.New("unexpected next batch after cancellation")
				}
				var ops api.TxnOps
				if err := json.NewDecoder(r.Body).Decode(&ops); err != nil {
					return nil, err
				}
				assert.Len(t, ops, 64, "first batch must use 32 conditional check/delete pairs")
				for i := 0; i+1 < len(ops); i += 2 {
					assert.Equal(t, api.KVCheckSession, ops[i].KV.Verb)
					assert.Equal(t, api.KVDelete, ops[i+1].KV.Verb)
					assert.Equal(t, "owned-lease", ops[i].KV.Session)
					committed = append(committed, strings.TrimPrefix(ops[i].KV.Key, "uptermd/sessions/"))
				}
				// The transaction committed. Cancellation before its successful
				// reply must stop the next batch without undoing its forgets.
				cancel()
				return shutdownSocketResponse(http.StatusOK, `{"Results":[]}`), nil
			})
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
			var ids []string
			for i := range 33 {
				id := fmt.Sprintf("owned-%02d", i)
				ids = append(ids, id)
				store.held[id] = map[string]struct{}{"owned-lease": {}}
				store.cache.Set(id, cachedSession{session: &Session{ID: id, NodeAddr: "node"}, index: 1, lease: "owned-lease"}, store.cache.Epoch())
			}
			err := store.batchDelete(ctx, ids)
			assert.ErrorIs(t, err, context.Canceled)
			assert.Equal(t, 1, transactions)
			require.Len(t, committed, 32)
			for _, id := range committed {
				assert.NotContains(t, store.held, id)
				assert.False(t, store.cache.Has(id), "committed delete remained cached: %s", id)
			}
			assert.Contains(t, store.held, "owned-32")
			assert.True(t, store.cache.Has("owned-32"), "unattempted next batch was forgotten")
		})
	})
	t.Run("canceled_lost_hold_response", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			var transactions, lookups int
			var logs bytes.Buffer
			store := newShutdownSocketStore(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/v1/txn" {
					transactions++
					return shutdownSocketResponse(http.StatusConflict, `{"Errors":[{"OpIndex":0,"What":"session check failed"}]}`), nil
				}
				lookups++
				cancel() // Acknowledge the lost-hold reply boundary before returning it.
				return shutdownSocketResponse(http.StatusNotFound, ""), nil
			})
			store.logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
			entries := []heldEntry{{id: "owned-a", lease: "owned-lease"}, {id: "owned-b", lease: "owned-lease"}}
			done, err := store.deleteBatch(ctx, entries)
			assert.ErrorIs(t, err, context.Canceled)
			assert.Empty(t, done)
			assert.Equal(t, 1, transactions, "cancellation started another rollback round")
			assert.Equal(t, 1, lookups)
			assert.NotContains(t, logs.String(), "skipping sessions", "canceled lookup was classified as a lost hold")
		})
	})
}

func TestConsulShutdownLeavesOrdinaryLateCallsUsable(t *testing.T) {
	watchEntered, watchDone := make(chan struct{}), make(chan struct{})
	var firstWatch atomic.Bool
	var mu sync.Mutex
	var stored *api.KVPair
	srv, connections := newCloseServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Consul-Index", "1")
		switch r.URL.Path {
		case "/v1/catalog/register":
			_, _ = io.WriteString(w, "true")
		case "/v1/session/create":
			_, _ = io.WriteString(w, `{"ID":"late-lease"}`)
		case "/v1/session/destroy/late-lease":
			mu.Lock()
			stored = nil
			mu.Unlock()
			_, _ = io.WriteString(w, "true")
		case "/v1/kv/uptermd/sessions":
			if firstWatch.CompareAndSwap(false, true) {
				defer close(watchDone)
				close(watchEntered)
				<-r.Context().Done()
				return
			}
			mu.Lock()
			defer mu.Unlock()
			pairs := api.KVPairs{}
			if stored != nil {
				pairs = append(pairs, stored)
			}
			_ = json.NewEncoder(w).Encode(pairs)
		case "/v1/kv/uptermd/sessions/late":
			w.WriteHeader(http.StatusNotFound)
		case "/v1/txn":
			var ops api.TxnOps
			if err := json.NewDecoder(r.Body).Decode(&ops); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if len(ops) != 2 || ops[1].KV == nil || ops[1].KV.Verb != api.KVLock || ops[1].KV.Session != "late-lease" {
				http.Error(w, "unexpected registration transaction", http.StatusBadRequest)
				return
			}
			pair := &api.KVPair{Key: ops[1].KV.Key, Value: ops[1].KV.Value, Session: "late-lease", ModifyIndex: 2}
			mu.Lock()
			stored = pair
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(&api.TxnResponse{Results: api.TxnResults{{KV: pair}, {KV: pair}}})
		default:
			http.Error(w, "unexpected API operation", http.StatusBadRequest)
		}
	}))
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	store, err := newConsulSessionStore(u, time.Minute, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()); store.apiHTTP.CloseIdleConnections() })
	receiveWithin(t, watchEntered, "watch never entered before Shutdown")
	manager := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	require.NoError(t, manager.Shutdown(context.Background(), "node"))
	receiveWithin(t, store.watchDone, "watch survived Shutdown")
	receiveWithin(t, watchDone, "remote watch handler survived Shutdown")
	awaitShutdownConnectionsClosed(t, connections)
	sessions, err := store.List()
	require.NoError(t, err)
	require.Empty(t, sessions)
	reg, err := store.Register(context.Background(), &Session{ID: "late", NodeAddr: "node"})
	require.NoError(t, err)
	require.Equal(t, "late-lease", reg.lease)
	sessions, err = store.List()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.Equal(t, "late", sessions[0].ID)
	require.NoError(t, store.Release(context.Background(), reg))
	sessions, err = store.List()
	require.NoError(t, err)
	require.Empty(t, sessions)
	// Close's cached result does not own transport use after it returned.
	// This fixture explicitly releases its ordinary late API connections.
	store.apiHTTP.CloseIdleConnections()
	awaitShutdownConnectionsClosed(t, connections)
}
