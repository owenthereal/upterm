package upterm

import (
	"context"
	"io"
	"sync"
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
	var wg sync.WaitGroup
	c := make(chan *readResult, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()

		// return early if context is done
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		n, err := r.Reader.Read(p)
		select {
		case c <- &readResult{n, err}:
		// return if context is done before sending back the result
		case <-r.ctx.Done():
			return
		}
	}()

	go func() {
		wg.Wait()
		close(c)
	}()

	select {
	case rr := <-c:
		return rr.n, rr.err
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	}

	return 0, io.EOF
}
