package logging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/getsentry/sentry-go"
	"github.com/stretchr/testify/require"
)

func TestSentryCreatesErrorIssues(t *testing.T) {
	logger, events := sentryTestLogger(t)
	logger.Debug("debug")
	logger.Info("info")
	logger.Warn("warning")
	logger.With("component", "server").Error("failed to start uptermd", "error", errors.New("listen failed"), "port", 2222)
	logger.Error("error without exception")
	logger.Log(context.Background(), slog.Level(12), "fatal error")
	require.NoError(t, logger.Close())

	captured := events()
	require.Len(t, captured, 3, "only error and fatal records should create Sentry issues")
	byMessage := make(map[string]*sentry.Event)
	for _, event := range captured {
		byMessage[event.Message] = event
	}
	startup := byMessage["failed to start uptermd"]
	require.NotNil(t, startup)
	require.Equal(t, sentry.LevelError, startup.Level)
	require.Equal(t, "production", startup.Environment)
	require.Equal(t, "server", startup.Tags["component"])
	require.Equal(t, "2222", startup.Tags["port"])
	require.Len(t, startup.Exception, 1)
	require.Equal(t, "listen failed", startup.Exception[0].Value)
	require.NotNil(t, startup.Exception[0].Stacktrace)
	messageOnly := byMessage["error without exception"]
	require.NotNil(t, messageOnly)
	require.Empty(t, messageOnly.Exception)
	require.NotNil(t, byMessage["fatal error"])
	require.Equal(t, sentry.LevelFatal, byMessage["fatal error"].Level)
}

func TestSentryPreservesGroupedAttrsAndContext(t *testing.T) {
	logger, events := sentryTestLogger(t)
	hub := sentry.CurrentHub().Clone()
	hub.Scope().SetTag("context", "request")
	ctx := sentry.SetHubOnContext(context.Background(), hub)
	logger.With("component", "server").WithGroup("session").With("id", "abc").WithGroup("").ErrorContext(ctx,
		"session failed", "err", fmt.Errorf("connect: %w", errors.New("connection refused")),
		slog.Group("peer", slog.String("addr", "localhost")),
		slog.Group("", slog.Bool("retry", true)),
		slog.Any("token", redactedValue{}), slog.Attr{},
	)
	require.NoError(t, logger.Close())
	captured := events()
	require.Len(t, captured, 1)
	require.Equal(t, map[string]string{
		"context": "request", "component": "server", "session.id": "abc",
		"session.peer.addr": "localhost", "session.retry": "true", "session.token": "[redacted]",
	}, captured[0].Tags)
	require.Len(t, captured[0].Exception, 2)
	require.Equal(t, "connection refused", captured[0].Exception[0].Value)
	require.Equal(t, "connect: connection refused", captured[0].Exception[1].Value)
}

func TestSentryKeepsConcurrentLoggerAttrsSeparate(t *testing.T) {
	logger, events := sentryTestLogger(t)
	parent := logger.With("component", "server")
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			parent.WithGroup("worker").With("id", i).Error(fmt.Sprint(i), "err", errors.New("worker failed"))
		})
	}
	wg.Wait()
	parent.Error("parent")
	require.NoError(t, logger.Close())
	captured := events()
	require.Len(t, captured, 9)
	for _, event := range captured {
		require.Equal(t, "server", event.Tags["component"])
		if event.Message == "parent" {
			require.NotContains(t, event.Tags, "worker.id")
			require.Empty(t, event.Exception)
		} else {
			require.Equal(t, event.Message, event.Tags["worker.id"])
			require.Len(t, event.Exception, 1)
		}
	}
}

type redactedValue struct{}

func (redactedValue) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// Exercise the real Sentry transport and flush without contacting Sentry.
func sentryTestLogger(t *testing.T) (*Logger, func() []*sentry.Event) {
	t.Helper()
	var mu sync.Mutex
	var captured []*sentry.Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var header json.RawMessage
		if err := decoder.Decode(&header); err != nil {
			t.Error(err)
			return
		}
		for {
			var item struct{ Type string }
			if err := decoder.Decode(&item); err != nil {
				if !errors.Is(err, io.EOF) {
					t.Error(err)
				}
				break
			}
			var payload json.RawMessage
			if err := decoder.Decode(&payload); err != nil {
				t.Error(err)
				break
			}
			if item.Type == "event" {
				var event sentry.Event
				if err := json.Unmarshal(payload, &event); err != nil {
					t.Error(err)
					break
				}
				mu.Lock()
				captured = append(captured, &event)
				mu.Unlock()
			}
		}
	}))
	t.Cleanup(server.Close)

	hub := sentry.CurrentHub()
	previousClient := hub.Client()
	hub.PushScope()
	t.Cleanup(func() {
		hub.PopScope()
		hub.BindClient(previousClient)
	})
	logger, err := New(Debug(), Sentry(strings.Replace(server.URL, "http://", "http://public@", 1)+"/1"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logger.Close()) })
	return logger, func() []*sentry.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]*sentry.Event(nil), captured...)
	}
}
