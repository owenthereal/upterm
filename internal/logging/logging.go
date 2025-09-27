package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/getsentry/sentry-go"
	slogsentry "github.com/getsentry/sentry-go/slog"
	"github.com/owenthereal/upterm/internal/version"
	slogmulti "github.com/samber/slog-multi"
)

const (
	sentryFlushTimeout = 2 * time.Second
)

// Logger wraps slog.Logger with cleanup capability and dynamic handlers
type Logger struct {
	*slog.Logger
	cleanupFuncs []func() error
}

// Close cleans up resources
func (l *Logger) Close() error {
	for _, cleanup := range l.cleanupFuncs {
		if err := cleanup(); err != nil {
			return err
		}
	}
	return nil
}

// With returns a new logger with additional attributes
func (l *Logger) With(args ...any) *Logger {
	return &Logger{
		Logger:       l.Logger.With(args...),
		cleanupFuncs: l.cleanupFuncs,
	}
}

// WithGroup returns a new logger with a group
func (l *Logger) WithGroup(name string) *Logger {
	return &Logger{
		Logger:       l.Logger.WithGroup(name),
		cleanupFuncs: l.cleanupFuncs,
	}
}

// Option configures a logger
type Option func(*config) error

type config struct {
	level        slog.Level
	outputs      []io.Writer
	handlers     []slog.Handler
	cleanupFuncs []func() error
}

// New creates a logger with options (for upterm client)
func New(opts ...Option) (*Logger, error) {
	cfg := &config{
		level: slog.LevelInfo,
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	// Default to stderr if no outputs specified
	if len(cfg.outputs) == 0 {
		cfg.outputs = []io.Writer{os.Stderr}
	}

	// Always add JSON handler for normal logging
	cfg.handlers = append(cfg.handlers, slog.NewJSONHandler(io.MultiWriter(cfg.outputs...), &slog.HandlerOptions{Level: cfg.level}))

	return &Logger{
		Logger:       slog.New(slogmulti.Fanout(cfg.handlers...)),
		cleanupFuncs: cfg.cleanupFuncs,
	}, nil
}

// Must wraps NewWithOptions and panics on error
func Must(opts ...Option) *Logger {
	logger, err := New(opts...)
	if err != nil {
		panic(err)
	}
	return logger
}

// Level sets the log level
func Level(level slog.Level) Option {
	return func(c *config) error {
		c.level = level
		return nil
	}
}

// Debug sets debug level
func Debug() Option {
	return Level(slog.LevelDebug)
}

// Console logs to stderr
func Console() Option {
	return func(c *config) error {
		c.outputs = append(c.outputs, os.Stderr)
		return nil
	}
}

// File logs to a file (path is required)
func File(path string) Option {
	return func(c *config) error {
		if path == "" {
			return fmt.Errorf("log file path is required")
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}

		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file %q: %w", path, err)
		}

		c.outputs = append(c.outputs, file)
		c.cleanupFuncs = append(c.cleanupFuncs, file.Close)
		return nil
	}
}

// Sentry enables Sentry error reporting
func Sentry(dsn string) Option {
	return func(c *config) error {
		if dsn == "" {
			return nil
		}

		sentryHandler, cleanup, err := newSentryHandler(dsn)
		if err != nil {
			return err
		}
		c.handlers = append(c.handlers, sentryHandler)
		c.cleanupFuncs = append(c.cleanupFuncs, cleanup)
		return nil
	}
}

func newSentryHandler(dsn string) (slog.Handler, func() error, error) {
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Environment:      "production",
		Release:          version.Version,
		AttachStacktrace: true,
	})
	if err != nil {
		return nil, nil, err
	}

	handler := slogsentry.Option{
		Level: slog.LevelError,
	}.NewSentryHandler(context.Background())

	cleanup := func() error {
		ok := sentry.Flush(sentryFlushTimeout)
		if !ok {
			return fmt.Errorf("sentry flush timeout")
		}
		return nil
	}

	return handler, cleanup, nil
}
