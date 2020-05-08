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

	go func() {
		// close by the sender
		defer close(c)

		// return early if context is done
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		n, err := r.Reader.Read(p)
		c <- readResult{n, err}
	}()

	select {
	case rr := <-c:
		return rr.n, rr.err
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	}
}
