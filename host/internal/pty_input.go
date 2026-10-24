package internal

import (
	"context"
	"errors"
	"io"
	"os"
	"time"
)

// contextPTYWriter is an optional capability; other platforms and PTY fakes
// retain their ordinary Write behavior.
type contextPTYWriter interface {
	WriteContext(context.Context, []byte) (int, error)
}

type inputWriter struct {
	ctx context.Context
	dst PTY
}

// Keep this adapter Write-only: promoted ReadFrom would bypass cancellation.
func ptyInputWriter(ctx context.Context, ptmx PTY) io.Writer {
	return inputWriter{ctx: ctx, dst: ptmx}
}

func (w inputWriter) Write(b []byte) (int, error) {
	if dst, ok := w.dst.(contextPTYWriter); ok {
		return dst.WriteContext(w.ctx, b)
	}
	return w.dst.Write(b)
}

type deadlineWriter interface {
	io.Writer
	SetWriteDeadline(time.Time) error
}

// ptyInput serializes complete writes, including their cancellation callbacks,
// so only the current writer can install or clear the file's write deadline.
type ptyInput struct {
	dst    deadlineWriter
	permit chan struct{}
}

func newPTYInput(dst deadlineWriter) *ptyInput {
	return &ptyInput{dst: dst, permit: make(chan struct{}, 1)}
}

func (w *ptyInput) WriteContext(ctx context.Context, b []byte) (int, error) {
	select {
	case w.permit <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	defer func() { <-w.permit }()
	// A ready permit and canceled context can both win the select above.
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(joined)
		_ = w.dst.SetWriteDeadline(time.Now())
	})
	n, err := w.dst.Write(b)
	if !stop() {
		<-joined
	}
	_ = w.dst.SetWriteDeadline(time.Time{})
	// Preserve successful writes and unrelated I/O errors, including Close.
	if errors.Is(err, os.ErrDeadlineExceeded) && ctx.Err() != nil {
		err = ctx.Err()
	}
	return n, err
}
