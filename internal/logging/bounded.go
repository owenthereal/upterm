package logging

import (
	"context"
	"io"
	"log/slog"
	"time"
)

// Within runs fn on its own goroutine and waits at most timeout for it. A
// bounded wait that ends with a diagnostic must not be made unbounded by the
// diagnostic: a log handler blocked on a stopped terminal, or a message
// written to that same terminal, would otherwise hold the caller exactly
// where the bound was meant to release it. Fire-and-forget would lose the
// line at process exit; waiting under a bound loses it only when it was
// never going to be written. The goroutine is abandoned on timeout.
func Within(timeout time.Duration, fn func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// LogWithin logs at level under Within's bound. A nil logger logs nothing.
func LogWithin(logger *slog.Logger, level slog.Level, timeout time.Duration, msg string, args ...any) {
	if logger == nil {
		return
	}
	Within(timeout, func() { logger.Log(context.Background(), level, msg, args...) })
}

// WarnWithin is LogWithin at Warn, the level every caller so far wants.
func WarnWithin(logger *slog.Logger, timeout time.Duration, msg string, args ...any) {
	LogWithin(logger, slog.LevelWarn, timeout, msg, args...)
}

// WriteWithin writes s to w under Within's bound: for a diagnostic to stderr,
// which may be the very terminal that stopped.
func WriteWithin(w io.Writer, timeout time.Duration, s string) {
	Within(timeout, func() { _, _ = io.WriteString(w, s) })
}

// LogBound is what callers in this module pass: long enough for any handler
// that is working, short enough that one that is not cannot hold an exit.
const LogBound = 100 * time.Millisecond
