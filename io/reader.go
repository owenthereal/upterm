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

// Read reads from the underlying reader, abandoning the read if the context is
// cancelled first.
//
// The read runs in a goroutine because the underlying reader has no way to be
// interrupted. That goroutine outlives an abandoned Read, so it must not touch
// anything the caller owns: it reads into its own buffer, and the bytes are
// copied into p only if the result arrives in time. It used to read straight
// into p, which meant a read that completed after its Read call had already
// returned wrote into a buffer io.Copy had moved on and reused.
//
// The channel is buffered so the abandoned goroutine can finish and exit rather
// than blocking forever on a send nobody is waiting for. It previously also
// closed the channel on the way out, so a Read racing a cancelled context could
// receive the zero value and report (0, nil) -- which io.Copy treats as neither
// data nor EOF, and spins on.
func (r contextReader) Read(p []byte) (int, error) {
	// Never start a read the caller has already given up on.
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
	}

	c := make(chan readResult, 1)
	buf := make([]byte, len(p))

	go func(reader io.Reader) {
		n, err := reader.Read(buf)
		c <- readResult{n, err}
	}(r.Reader)

	select {
	case rr := <-c:
		copy(p, buf[:rr.n])
		return rr.n, rr.err
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	}
}
