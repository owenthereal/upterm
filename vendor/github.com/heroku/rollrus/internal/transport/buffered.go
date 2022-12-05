package transport

import (
	"context"
	"errors"
	"sync"

	"github.com/rollbar/rollbar-go"
)

var (
	errBufferFull = errors.New("rollbar message buffer full")
	errClosed     = errors.New("rollbar transport closed")
)

// Buffered is an alternative to rollbar's AsyncTransport, providing
// threadsafe and predictable message delivery built on top of the SyncTransport.
type Buffered struct {
	queue chan op
	once  sync.Once
	ctx   context.Context

	rollbar.Transport
}

// op represents an operation queued for transport. It is only valid
// to set a single field in the struct to represent the operation that should
// be performed.
type op struct {
	send  map[string]interface{}
	wait  chan struct{}
	close bool
}

// NewBuffered wraps the provided transport for async delivery.
func NewBuffered(inner rollbar.Transport, bufSize int) *Buffered {
	ctx, cancel := context.WithCancel(context.Background())

	t := &Buffered{
		queue:     make(chan op, bufSize),
		ctx:       ctx,
		Transport: inner,
	}

	go t.run(cancel)

	return t
}

// Send enqueues delivery of the message body to Rollbar without waiting for
// the result. If the buffer is full, it will immediately return an error.
func (t *Buffered) Send(body map[string]interface{}) error {
	select {
	case t.queue <- op{send: body}:
		return nil
	case <-t.ctx.Done():
		return errClosed
	default:
		return errBufferFull
	}
}

// Wait blocks until all messages buffered before calling Wait are
// delivered.
func (t *Buffered) Wait() {
	done := make(chan struct{})
	select {
	case t.queue <- op{wait: done}:
	case <-t.ctx.Done():
		return
	}

	select {
	case <-done:
	case <-t.ctx.Done():
	}
}

// Close shuts down the transport and waits for queued messages to be
// delivered.
func (t *Buffered) Close() error {
	t.once.Do(func() {
		t.queue <- op{close: true}
	})

	<-t.ctx.Done()
	return nil
}

func (t *Buffered) run(cancel func()) {
	defer cancel()

	for m := range t.queue {
		switch {
		case m.send != nil:
			_ = t.Transport.Send(m.send)
		case m.wait != nil:
			close(m.wait)
		case m.close:
			t.Transport.Close()
			return
		}
	}
}
