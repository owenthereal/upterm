package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/owenthereal/upterm/internal/liveness"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

// pingConn holds the probe until its owner replies or closes the connection.
// Closing also releases a probe that outlives pingHost on cancellation.
type pingConn struct {
	entered, release, closed chan struct{}
	enter, reply, close      func()
	onReply                  func()
	mu                       sync.Mutex
	name                     string
	wantReply                bool
	payload                  []byte
	requests, closes, active atomic.Int32
}

var _ gossh.Conn = (*pingConn)(nil)

func newPingConn(t *testing.T) *pingConn {
	t.Helper()
	c := &pingConn{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	c.enter = sync.OnceFunc(func() { close(c.entered) })
	c.reply = sync.OnceFunc(func() { close(c.release) })
	c.close = sync.OnceFunc(func() { close(c.closed) })
	return c
}

func (c *pingConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	c.active.Add(1)
	defer c.active.Add(-1)
	c.mu.Lock()
	c.name, c.wantReply, c.payload = name, wantReply, payload
	c.mu.Unlock()
	c.requests.Add(1)
	c.enter()
	select {
	case <-c.closed:
		return false, nil, io.EOF
	case <-c.release:
		if c.onReply != nil {
			c.onReply()
		}
		return false, nil, nil // an unsupported request is refused, but is activity
	}
}

func (c *pingConn) Close() error { c.closes.Add(1); c.close(); return nil }
func (c *pingConn) Wait() error  { <-c.closed; return nil }
func (*pingConn) OpenChannel(string, []byte) (gossh.Channel, <-chan *gossh.Request, error) {
	return nil, nil, io.EOF
}
func (*pingConn) User() string          { return "host" }
func (*pingConn) SessionID() []byte     { return nil }
func (*pingConn) ClientVersion() []byte { return nil }
func (*pingConn) ServerVersion() []byte { return nil }
func (*pingConn) RemoteAddr() net.Addr  { return nil }
func (*pingConn) LocalAddr() net.Addr   { return nil }

// pingRead keeps its clock base inside the bubble and advances only when the
// test supplies host bytes, including the bytes of a refused probe's reply.
type pingRead struct {
	base time.Time
	last atomic.Int64
}

func (r *pingRead) touch()          { r.last.Store(int64(time.Since(r.base))) }
func (r *pingRead) read() time.Time { return r.base.Add(time.Duration(r.last.Load())) }

func startPingHost(t *testing.T, c *pingConn, r *pingRead) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	// Registered before starting any worker, so Fatal also releases the probe.
	t.Cleanup(func() {
		cancel()
		_ = c.Close()
		synctest.Wait()
		require.True(t, pingSignaled(done), "pingHost did not return during cleanup")
		require.Zero(t, c.active.Load(), "an owned SendRequest outlived cleanup")
	})
	go func() {
		defer close(done)
		pingHost(ctx, c, r.read, liveness.Timing{Interval: 100 * time.Millisecond, Bound: 400 * time.Millisecond}, slog.New(slog.DiscardHandler))
	}()
	synctest.Wait()
	return cancel, done
}

func pingSignaled(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestPingHostClosesASilentHost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newPingConn(t)
		r := &pingRead{base: time.Now()}
		_, done := startPingHost(t, c, r)

		time.Sleep(100*time.Millisecond - time.Nanosecond)
		synctest.Wait()
		require.False(t, pingSignaled(c.entered), "probed before 100 ms of silence")
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		require.True(t, pingSignaled(c.entered), "did not probe at 100 ms of silence")
		c.mu.Lock()
		name, wantReply, payload := c.name, c.wantReply, c.payload
		c.mu.Unlock()
		require.Equal(t, "keepalive@openssh.com", name)
		require.True(t, wantReply)
		require.Empty(t, payload)
		require.Equal(t, int32(1), c.requests.Load())

		time.Sleep(400*time.Millisecond - time.Nanosecond)
		synctest.Wait()
		require.Zero(t, c.closes.Load(), "closed before 500 ms of silence")
		require.False(t, pingSignaled(done))
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		require.Equal(t, int32(1), c.closes.Load(), "did not close at 500 ms of silence")
		require.True(t, pingSignaled(c.closed))
		require.True(t, pingSignaled(done))
		require.Zero(t, c.active.Load(), "Close did not release the blocked probe")
	})
}

func TestPingHostKeepsAHostWhoseReadAdvances(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newPingConn(t)
		r := &pingRead{base: time.Now()}
		startPingHost(t, c, r)
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		require.True(t, pingSignaled(c.entered))
		// Reads every 300 ms outlast the original 500 ms silence budget,
		// while the first probe stays unanswered throughout.
		for range 3 {
			time.Sleep(300 * time.Millisecond)
			r.touch()
			synctest.Wait()
			require.Zero(t, c.closes.Load(), "closed while host bytes were arriving")
		}
		require.Equal(t, int32(1), c.requests.Load(), "piled another probe behind the held reply")
		time.Sleep(500*time.Millisecond - time.Nanosecond)
		synctest.Wait()
		require.Zero(t, c.closes.Load(), "closed before the last read's silence budget")
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		require.Equal(t, int32(1), c.closes.Load(), "kept a host after its last read's silence budget")
	})
}

func TestPingHostAcceptsARefusedProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newPingConn(t)
		r := &pingRead{base: time.Now()}
		c.onReply = r.touch
		_, done := startPingHost(t, c, r)
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		require.True(t, pingSignaled(c.entered))
		time.Sleep(300 * time.Millisecond)
		c.reply()
		synctest.Wait()
		require.Zero(t, c.closes.Load(), "treated a refused probe as a dead host")
		require.False(t, pingSignaled(done))
		time.Sleep(600 * time.Millisecond)
		synctest.Wait()
		require.Zero(t, c.closes.Load(), "refused probes did not keep the host alive past its original budget")
		require.False(t, pingSignaled(done))
		require.GreaterOrEqual(t, c.requests.Load(), int32(2), "never probed again after a refusal")
	})
}

func TestPingHostCancellationDoesNotReportDeath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newPingConn(t)
		r := &pingRead{base: time.Now()}
		cancel, done := startPingHost(t, c, r)
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		require.True(t, pingSignaled(c.entered))
		cancel()
		synctest.Wait()
		require.True(t, pingSignaled(done), "cancellation did not stop pingHost")
		require.Zero(t, c.closes.Load(), "caller cancellation reported a dead host")
		require.Equal(t, int32(1), c.active.Load(), "probe should remain owned by the connection until Close")
		_ = c.Close()
		synctest.Wait()
		require.Zero(t, c.active.Load(), "owner Close did not release the outstanding probe")
	})
}
