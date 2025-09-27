package context

import (
	"context"

	"github.com/owenthereal/upterm/internal/logging"
)

type contextKey string

const loggerKey contextKey = "logger"

func WithLogger(ctx context.Context, logger *logging.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

func Logger(ctx context.Context) *logging.Logger {
	if logger, ok := ctx.Value(loggerKey).(*logging.Logger); ok {
		return logger
	}
	return nil
}
