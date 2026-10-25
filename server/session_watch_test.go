package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/api/watch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConsulCloseDuringFirstWatchQuerySetup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, resume := make(chan struct{}), make(chan struct{})
		release := sync.OnceFunc(func() { close(resume) })
		logger := slog.New(slog.DiscardHandler)
		store := &consulSessionStore{logger: logger, cache: newSessionCache(logger)}
		store.beforeWatchQuery = func() {
			close(entered)
			<-resume
		}
		// Release first, even if an assertion fails while the callback is held.
		t.Cleanup(func() { release(); assert.NoError(t, store.Close()) })
		cfg := api.DefaultConfig()
		cfg.Address = "127.0.0.1:1"
		require.NoError(t, store.startSessionWatch(cfg))
		<-entered
		closed := make(chan error, 1)
		go func() { closed <- store.Close() }()
		synctest.Wait() // Close has stopped Plan and is waiting for held query setup.
		require.True(t, store.watchPlan.IsStopped())
		select {
		case err := <-closed:
			t.Fatalf("Close returned while query setup was held: %v", err)
		default:
		}
		release()
		synctest.Wait() // The released query has returned and Close has joined the watch.
		require.NoError(t, <-closed)
		select {
		case <-store.watchDone:
		default:
			t.Fatal("watch survived Close")
		}
	})
}

type watchResponseBody struct {
	io.Reader
	closed bool
}

func (b *watchResponseBody) Close() error { b.closed = true; return nil }

func TestConsulSessionWatcherPreservesQueryIndexes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queryErr := errors.New("watch query rejected")
	var requests []*http.Request
	var bodies []*watchResponseBody
	indexes := []uint64{5, 5, 2, 0, 3}
	cfg := api.DefaultConfig()
	cfg.Address = "127.0.0.1:1"
	cfg.Token = "watch-token"
	cfg.Datacenter = ""
	cfg.HttpClient = &http.Client{Timeout: 0, Transport: closeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		i := len(requests)
		requests = append(requests, r)
		require.Less(t, i, len(indexes))
		if i == 3 {
			return nil, queryErr
		}
		body := &watchResponseBody{Reader: strings.NewReader(`[{"Key":"sessions/a","Value":"e30=","ModifyIndex":1}]`)}
		bodies = append(bodies, body)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"X-Consul-Index": {fmt.Sprint(indexes[i])}}, Body: body}, nil
	})}
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	watcher := consulSessionWatcher(ctx, client, "sessions/")
	for i, index := range indexes {
		block, data, err := watcher(nil)
		if i == 3 {
			require.ErrorIs(t, err, queryErr)
			require.Nil(t, block)
			require.Nil(t, data)
		} else {
			require.NoError(t, err)
			require.Equal(t, watch.WaitIndexVal(index), block)
			pairs, ok := data.(api.KVPairs)
			require.True(t, ok, "watch data must remain api.KVPairs")
			require.Equal(t, api.KVPairs{&api.KVPair{Key: "sessions/a", Value: []byte("{}"), ModifyIndex: 1}}, pairs)
			require.True(t, bodies[len(bodies)-1].closed, "query response body was not closed")
		}
		// Check before parent cleanup, without an HTTP timeout context that
		// body closure could cancel on the callback's behalf.
		require.ErrorIs(t, requests[i].Context().Err(), context.Canceled, "finished query retained its context")
		require.NoError(t, ctx.Err())
	}
	var gotIndexes []string
	for _, r := range requests {
		require.Equal(t, "/v1/kv/sessions/", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		require.True(t, r.URL.Query().Has("recurse"))
		require.False(t, r.URL.Query().Has("stale"))
		require.False(t, r.URL.Query().Has("consistent"))
		require.Equal(t, "watch-token", r.Header.Get("X-Consul-Token"))
		index := r.URL.Query().Get("index")
		if index == "" {
			index = "0"
		}
		gotIndexes = append(gotIndexes, index)
	}
	require.Equal(t, []string{"0", "5", "5", "2", "0"}, gotIndexes)
}

func TestConsulSessionWatcherHonorsCancellation(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(fmt.Sprintf("before=%v", before), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				entered, released := make(chan struct{}), make(chan struct{})
				release := sync.OnceFunc(func() { close(released) })
				t.Cleanup(release)
				cfg := api.DefaultConfig()
				cfg.Address = "127.0.0.1:1"
				cfg.HttpClient = &http.Client{Timeout: 0, Transport: closeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					close(entered)
					select {
					case <-r.Context().Done():
						return nil, r.Context().Err()
					case <-released:
						return nil, errors.New("watch request released by fixture cleanup")
					}
				})}
				client, err := api.NewClient(cfg)
				require.NoError(t, err)
				watcher := consulSessionWatcher(ctx, client, "sessions/")
				if before {
					cancel()
				}
				finished := make(chan error, 1)
				go func() {
					block, data, err := watcher(nil)
					assert.Nil(t, block)
					assert.Nil(t, data)
					finished <- err
				}()
				if !before {
					<-entered
					synctest.Wait() // The entered fake request is blocked before cancellation.
					select {
					case err := <-finished:
						t.Fatalf("query returned before cancellation: %v", err)
					default:
					}
					cancel()
				}
				synctest.Wait() // Settle work made ready by parent cancellation before checking completion.
				select {
				case err := <-finished:
					require.ErrorIs(t, err, context.Canceled)
				default:
					t.Fatal("watch query did not finish after parent cancellation")
				}
			})
		})
	}
}

func TestConsulWatchClientSetupFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &consulSessionStore{logger: slog.New(slog.DiscardHandler)}
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		cfg := api.DefaultConfig()
		cfg.Address = "unsupported://127.0.0.1:1"
		err := store.startSessionWatch(cfg)
		require.ErrorContains(t, err, "failed to create watch client")
		require.Nil(t, store.watchDone, "setup failure published an unstarted worker")
		require.Nil(t, store.watchCancel, "setup failure acquired an unnecessary context")
		require.NotNil(t, store.watchHTTP, "store lost its acquired HTTP client")
		started := time.Now()
		require.NoError(t, store.Close())
		require.Equal(t, time.Duration(0), time.Since(started), "Close waited for an unstarted worker")
	})
}
