package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestConsulCloseBoundsAStuckObserver(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})
		release := sync.OnceFunc(func() { close(done) })
		t.Cleanup(release)
		store := &consulSessionStore{watchDone: done, closeTimeout: 50 * time.Millisecond}
		// Buffer every result so a failed assertion cannot strand a sender.
		closed := make(chan error, 8)
		go func() { closed <- store.Close() }()
		synctest.Wait()
		time.Sleep(50*time.Millisecond - time.Nanosecond)
		synctest.Wait()
		select {
		case err := <-closed:
			t.Fatalf("Close returned before its observer deadline: %v", err)
		default:
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		// Release before failing so an unbounded join mutation also exits.
		select {
		case err := <-closed:
			require.ErrorIs(t, err, context.DeadlineExceeded)
			release()
			for range 8 {
				go func() { closed <- store.Close() }()
			}
			for range 8 {
				require.Equal(t, err, <-closed, "concurrent Close must retain the first result")
			}
		default:
			release()
			synctest.Wait()
			err := <-closed
			t.Fatalf("Close did not return at its observer deadline: %v", err)
		}
	})
}

func TestConsulCloseUsesDefaultBound(t *testing.T) {
	for _, test := range []struct {
		name    string
		timeout time.Duration
	}{
		{"zero", 0}, {"negative", -time.Nanosecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				done := make(chan struct{})
				release := sync.OnceFunc(func() { close(done) })
				t.Cleanup(release)
				store := &consulSessionStore{watchDone: done, closeTimeout: test.timeout}
				closed := make(chan error, 1)
				go func() { closed <- store.Close() }()
				synctest.Wait()
				time.Sleep(5*time.Second - time.Nanosecond)
				synctest.Wait()
				select {
				case err := <-closed:
					t.Fatalf("Close returned before the default bound: %v", err)
				default:
				}
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				select {
				case err := <-closed:
					require.ErrorIs(t, err, context.DeadlineExceeded)
				default:
					release()
					synctest.Wait()
					err := <-closed
					t.Fatalf("Close did not return at the default bound: %v", err)
				}
			})
		})
	}
}

func TestConsulCloseWaitsForWatchDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})
		release := sync.OnceFunc(func() { close(done) })
		t.Cleanup(release)
		store := &consulSessionStore{watchDone: done}
		closed := make(chan error, 1)
		go func() { closed <- store.Close() }()
		synctest.Wait()
		select {
		case err := <-closed:
			t.Fatalf("Close returned before the watch exited: %v", err)
		default:
		}
		release()
		synctest.Wait()
		require.NoError(t, <-closed)
	})
}

func TestConsulCloseWaitsForAnEnteredObserver(t *testing.T) {
	entered, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(release)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Consul-Index", "1")
		_, _ = io.WriteString(w, "[]")
	}))
	t.Cleanup(srv.Close)
	store := &consulSessionStore{logger: slog.New(slog.DiscardHandler), cache: newSessionCache(slog.New(slog.DiscardHandler))}
	var calls atomic.Int64
	store.Observe(func(_, _ uint64, _ map[string]StoreEntry) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-resume
	})
	cfg := api.DefaultConfig()
	cfg.Address = srv.URL
	require.NoError(t, store.startSessionWatch(cfg))
	t.Cleanup(func() {
		release()
		assert.NoError(t, store.Close())
		if store.watchDone != nil {
			receiveWithin(t, store.watchDone, "watch run survived cleanup")
		}
	})
	receiveWithin(t, entered, "observer never entered")
	closed := make(chan error, 1)
	go func() { closed <- store.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned while an observer was entered: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	release()
	require.NoError(t, receiveWithin(t, closed, "Close never joined the observer"))
	before := calls.Load()
	// Once the run has exited, no handler can deliver another callback.
	require.NotNil(t, store.watchDone)
	receiveWithin(t, store.watchDone, "watch run survived Close")
	require.Equal(t, int64(1), before)
	require.Equal(t, before, calls.Load())
}

// closeConnections records real server-side transport state before server
// cleanup can close a connection and conceal a client's missing idle close.
type closeConnections struct {
	mu      sync.Mutex
	states  map[net.Conn]http.ConnState
	changed chan struct{}
}

func newCloseServer(t *testing.T, handler http.Handler) (*httptest.Server, *closeConnections) {
	t.Helper()
	connections := &closeConnections{states: make(map[net.Conn]http.ConnState), changed: make(chan struct{}, 100)}
	srv := httptest.NewUnstartedServer(handler)
	srv.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		connections.mu.Lock()
		connections.states[conn] = state
		connections.mu.Unlock()
		select {
		case connections.changed <- struct{}{}:
		default:
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, connections
}

func (c *closeConnections) await(t *testing.T, idle, closed int) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		c.mu.Lock()
		var gotIdle, gotClosed int
		for _, state := range c.states {
			if state == http.StateIdle {
				gotIdle++
			}
			if state == http.StateClosed {
				gotClosed++
			}
		}
		c.mu.Unlock()
		if gotIdle == idle && gotClosed == closed {
			t.Logf("connections: idle=%d closed=%d", gotIdle, gotClosed)
			return
		}
		select {
		case <-c.changed:
		case <-deadline.C:
			t.Fatalf("connections: idle=%d closed=%d; want idle=%d closed=%d", gotIdle, gotClosed, idle, closed)
		}
	}
}

func TestConsulCloseReleasesBothHTTPTransports(t *testing.T) {
	for _, wrapper := range []string{"plain", "delayed", "lost"} {
		for _, stuck := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stuck=%v", wrapper, stuck), func(t *testing.T) {
				entered := make(chan struct{})
				resume := make(chan struct{})
				release := sync.OnceFunc(func() { close(resume) })
				srv, connections := newCloseServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasPrefix(r.URL.Path, "/v1/kv/") {
						close(entered)
						select {
						case <-r.Context().Done():
						case <-resume:
						}
						return
					}
					_, _ = io.WriteString(w, "true")
				}))
				t.Cleanup(release)
				u, err := url.Parse(srv.URL)
				require.NoError(t, err)
				store, err := newConsulSessionStore(u, time.Minute, slog.New(slog.DiscardHandler))
				require.NoError(t, err)
				t.Cleanup(func() { release(); _ = store.Close() })
				receiveWithin(t, entered, "watch request never entered")
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				require.NoError(t, store.stopWatch(ctx))
				connections.await(t, 1, 1)
				for _, client := range []*http.Client{store.apiHTTP, store.watchHTTP} {
					require.NotNil(t, client)
					switch wrapper {
					case "delayed":
						client.Transport = newDelayedTxnReply(client.Transport, 1)
					case "lost":
						client.Transport = &lostTxnReply{next: client.Transport}
					}
					resp, err := client.Get(srv.URL + "/probe")
					require.NoError(t, err)
					_, err = io.Copy(io.Discard, resp.Body)
					require.NoError(t, err)
					require.NoError(t, resp.Body.Close())
				}
				connections.await(t, 2, 1)
				var want error
				if stuck {
					done := make(chan struct{})
					t.Cleanup(func() { close(done) })
					store.watchDone = done
					store.closeTimeout = 50 * time.Millisecond
					want = context.DeadlineExceeded
				}
				var wg sync.WaitGroup
				for range 8 {
					wg.Go(func() { assert.ErrorIs(t, store.Close(), want) })
				}
				wg.Wait()
				require.ErrorIs(t, store.Close(), want)
				connections.await(t, 0, 3)
			})
		}
	}
}

func TestConsulConstructorFailureReleasesHTTPTransport(t *testing.T) {
	srv, connections := newCloseServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "registration rejected")
	}))
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	store, err := newConsulSessionStore(u, time.Minute, slog.New(slog.DiscardHandler))
	require.Nil(t, store)
	require.ErrorContains(t, err, "failed to register node with consul")
	connections.await(t, 0, 1)
}

func TestConsulCloseCancelsAnInFlightWatchRequest(t *testing.T) {
	entered, cancelled := make(chan struct{}), make(chan struct{})
	resume := make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/catalog/register" {
			_, _ = io.WriteString(w, "true")
			return
		}
		close(entered)
		select {
		case <-r.Context().Done():
			close(cancelled)
		case <-resume:
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(release)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	store, err := newConsulSessionStore(u, time.Minute, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	t.Cleanup(func() { release(); assert.NoError(t, store.Close()) })
	receiveWithin(t, entered, "watch request never entered")
	require.NoError(t, store.Close())
	receiveWithin(t, cancelled, "watch request was not cancelled")
	require.NotNil(t, store.watchDone, "watch exit has no completion signal")
	receiveWithin(t, store.watchDone, "watch request survived Close")
}

type closeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f closeRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestConsulCloseBeforeFirstWatchRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		plan, err := watch.Parse(map[string]interface{}{"type": "keyprefix", "prefix": "sessions"})
		require.NoError(t, err)
		var requests atomic.Int64
		cfg := api.DefaultConfig()
		cfg.HttpClient = &http.Client{Transport: closeRoundTripFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			return nil, errors.New("unexpected request after stop")
		})}
		run, done := make(chan struct{}), make(chan struct{})
		release := sync.OnceFunc(func() { close(run) })
		t.Cleanup(release)
		store := &consulSessionStore{watchPlan: plan, watchHTTP: cfg.HttpClient, watchDone: done}
		runErr := make(chan error, 1)
		go func() {
			<-run
			defer close(done)
			runErr <- plan.RunWithConfig(cfg.Address, cfg)
		}()
		t.Cleanup(func() {
			plan.Stop()
			release()
			receiveWithin(t, done, "gated watch survived cleanup")
		})
		closed := make(chan error, 1)
		go func() { closed <- store.Close() }()
		synctest.Wait()
		require.True(t, plan.IsStopped(), "Close did not stop the watch before launch")
		select {
		case err := <-closed:
			t.Fatalf("Close returned before the gated watch exited: %v", err)
		default:
		}
		release()
		synctest.Wait()
		require.NoError(t, receiveWithin(t, closed, "Close never joined the gated watch"))
		require.NoError(t, <-runErr)
		require.Zero(t, requests.Load(), "stopped watch started a request")
	})
}
