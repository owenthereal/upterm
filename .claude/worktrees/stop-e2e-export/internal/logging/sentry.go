package logging

import (
	"context"
	"fmt"
	"log/slog"
	"maps"

	"github.com/getsentry/sentry-go"
	slogsentry "github.com/getsentry/sentry-go/slog"
)

type sentryIssueHandler struct {
	tags  map[string]string
	group string
	err   error
}

func (h *sentryIssueHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelError
}

func (h *sentryIssueHandler) Handle(ctx context.Context, record slog.Record) error {
	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = sentry.CurrentHub()
	}
	client := hub.Client()
	if client == nil {
		return nil
	}

	entry := *h
	entry.tags = maps.Clone(h.tags)
	record.Attrs(func(attr slog.Attr) bool {
		entry.addAttr(entry.group, attr)
		return true
	})

	event := sentry.NewEvent()
	event.Timestamp = record.Time.UTC()
	event.Logger = "slog"
	event.Message = record.Message
	event.Level = sentry.LevelError
	if record.Level >= slogsentry.LevelFatal {
		event.Level = sentry.LevelFatal
	}
	event.Tags = entry.tags
	event.SetException(entry.err, client.Options().MaxErrorDepth)
	hub.CaptureEventWithHint(event, &sentry.EventHint{Context: ctx, OriginalException: entry.err})
	return nil
}

func (h *sentryIssueHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.tags = maps.Clone(h.tags)
	for _, attr := range attrs {
		clone.addAttr(clone.group, attr)
	}
	return &clone
}

func (h *sentryIssueHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	clone := *h
	clone.group += name + "."
	return &clone
}

func (h *sentryIssueHandler) addAttr(prefix string, attr slog.Attr) {
	attr.Value = attr.Value.Resolve()
	if attr.Equal(slog.Attr{}) {
		return
	}
	if attr.Value.Kind() == slog.KindGroup {
		if attr.Key != "" {
			prefix += attr.Key + "."
		}
		for _, child := range attr.Value.Group() {
			h.addAttr(prefix, child)
		}
		return
	}
	if attr.Key == "error" || attr.Key == "err" {
		if err, ok := attr.Value.Any().(error); ok {
			h.err = err
			return
		}
	}
	h.tags[prefix+attr.Key] = fmt.Sprint(attr.Value.Any())
}
