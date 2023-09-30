package io

import (
	"context"
	"io"
)

func NewContextReader(ctx context.Context, r io.Reader) io.Reader {
	return contextReader{
		Reader: r,
		ctx:    ctx,
	}
}

type contextReader struct {
	io.Reader
	ctx context.Context
}

type readResult struct {
	n   int
	err error
}

func (r contextReader) Read(p []byte) (n int, err error) {
	c := make(chan readResult, 1)

	go func(ctx context.Context, reader io.Reader) {
		// close by the sender
		defer close(c)

		// return early if context is done
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := reader.Read(p)
		c <- readResult{n, err}
	}(r.ctx, r.Reader)

	select {
	case rr := <-c:
		return rr.n, rr.err
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	}
}
