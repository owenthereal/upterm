package internal

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// tunnelListenerHangGuard only turns a hang into a failure; nothing asserts
// on how much of it a call used.
const tunnelListenerHangGuard = 10 * time.Second

// listen is a loopback listener that is closed with the test.
func listen(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// countedListener stands in for a forwarded listener. Closing it ends its
// Accept before anything else, as x/crypto's does, and the rest of Close —
// the request to the relay — can then be held open by release.
type countedListener struct {
	net.Listener

	closes atomic.Int32
	// accepting is signalled when Accept is entered.
	accepting chan struct{}
	// closing is closed once Close has ended Accept and is on its way to
	// returning.
	closing     chan struct{}
	closingOnce sync.Once
	// release holds Close open until it is closed; nil returns at once.
	release <-chan struct{}
}

func newCountedListener(l net.Listener) *countedListener {
	return &countedListener{
		Listener:  l,
		accepting: make(chan struct{}, 1),
		closing:   make(chan struct{}),
	}
}

func (c *countedListener) Accept() (net.Conn, error) {
	select {
	case c.accepting <- struct{}{}:
	default:
	}
	return c.Listener.Accept()
}

func (c *countedListener) Close() error {
	c.closes.Add(1)
	err := c.Listener.Close()
	c.closingOnce.Do(func() { close(c.closing) })
	if c.release != nil {
		<-c.release
	}
	return err
}

// lose ends the listener the way a dead tunnel does: its Accept fails, and
// nobody has called Close.
func (c *countedListener) lose() { _ = c.Listener.Close() }

type acceptResult struct {
	conn net.Conn
	err  error
}

func acceptAsync(l net.Listener) <-chan acceptResult {
	ch := make(chan acceptResult, 1)
	go func() {
		c, err := l.Accept()
		ch <- acceptResult{conn: c, err: err}
	}()
	return ch
}

func receiveAccept(t *testing.T, ch <-chan acceptResult) acceptResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(tunnelListenerHangGuard):
		t.Fatal("Accept did not return")
		return acceptResult{}
	}
}

// await receives from ch, failing the test instead of hanging when nothing
// arrives.
func await[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(tunnelListenerHangGuard):
		t.Fatalf("never happened: %s", what)
		var zero T
		return zero
	}
}

func TestTunnelListenerBlocksAcrossASwap(t *testing.T) {
	l1, l2 := listen(t), listen(t)
	tl := NewTunnelListener(l1)
	got := make(chan error, 1)
	go func() {
		c, err := tl.Accept()
		if err == nil {
			_ = c.Close()
		}
		got <- err
	}()
	_ = l1.Close() // the tunnel is lost
	select {
	case err := <-got:
		t.Fatalf("Accept returned across a swap: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	require.True(t, tl.Swap(l2))
	c, err := net.Dial("tcp", l2.Addr().String())
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, <-got)
}

func TestTunnelListenerServesWhicheverListenerIsCurrent(t *testing.T) {
	l1, l2 := listen(t), listen(t)
	tl := NewTunnelListener(l1)
	t.Cleanup(func() { _ = tl.Close() })

	through := func(l net.Listener) {
		t.Helper()
		got := acceptAsync(tl)
		c, err := net.Dial("tcp", l.Addr().String())
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		r := receiveAccept(t, got)
		require.NoError(t, r.err)
		defer func() { _ = r.conn.Close() }()
		require.Equal(t, c.LocalAddr().String(), r.conn.RemoteAddr().String())
	}

	through(l1)
	require.True(t, tl.Swap(l2))
	through(l2)
}

func TestTunnelListenerFailsOnlyWhenLostOrClosed(t *testing.T) {
	errLost := errors.New("relay gone for good")

	t.Run("fail wakes an Accept whose listener is healthy", func(t *testing.T) {
		inner := newCountedListener(listen(t))
		tl := NewTunnelListener(inner)
		t.Cleanup(func() { _ = tl.Close() })
		await(t, inner.accepting, "the inner listener was never accepted from")

		got := acceptAsync(tl)
		tl.Fail(errLost)

		r := receiveAccept(t, got)
		require.ErrorIs(t, r.err, errLost)
		require.NotErrorIs(t, r.err, net.ErrClosed)
		require.Nil(t, r.conn)
		require.Zero(t, inner.closes.Load(), "Fail leaves closing to Close")

		_, err := tl.Accept()
		require.ErrorIs(t, err, errLost, "every later Accept fails the same way")
	})

	t.Run("fail after the tunnel was lost", func(t *testing.T) {
		inner := newCountedListener(listen(t))
		tl := NewTunnelListener(inner)
		t.Cleanup(func() { _ = tl.Close() })

		got := acceptAsync(tl)
		inner.lose()
		tl.Fail(errLost)

		require.ErrorIs(t, receiveAccept(t, got).err, errLost)
	})

	t.Run("close on a fresh listener", func(t *testing.T) {
		inner := newCountedListener(listen(t))
		tl := NewTunnelListener(inner)

		require.NoError(t, tl.Close())

		_, err := tl.Accept()
		require.ErrorIs(t, err, net.ErrClosed)
		require.EqualValues(t, 1, inner.closes.Load())
	})

	t.Run("close during the wait returns at once", func(t *testing.T) {
		inner := newCountedListener(listen(t))
		release := make(chan struct{})
		inner.release = release
		tl := NewTunnelListener(inner)
		var unblock sync.Once
		t.Cleanup(func() { unblock.Do(func() { close(release) }) })

		inner.lose()
		got := acceptAsync(tl)
		closed := make(chan error, 1)
		go func() { closed <- tl.Close() }()

		// Close is held inside the inner listener's Close, which the
		// Accept must not be waiting behind.
		await(t, inner.closing, "Close never reached the inner listener")
		r := receiveAccept(t, got)
		require.ErrorIs(t, r.err, net.ErrClosed)
		select {
		case <-closed:
			t.Fatal("Close returned before the inner listener's Close did")
		default:
		}

		unblock.Do(func() { close(release) })
		// The tunnel was already lost, so its listener says it is closed:
		// Close passes on what the inner Close returned.
		require.ErrorIs(t, await(t, closed, "Close never returned"), net.ErrClosed)
	})
}

func TestTunnelListenerFirstOfFailAndCloseWins(t *testing.T) {
	errLost := errors.New("relay gone for good")

	t.Run("fail then close", func(t *testing.T) {
		inner := newCountedListener(listen(t))
		tl := NewTunnelListener(inner)

		tl.Fail(errLost)
		tl.Fail(errors.New("a later reason"))
		require.NoError(t, tl.Close())
		require.NoError(t, tl.Close())

		_, err := tl.Accept()
		require.ErrorIs(t, err, errLost)
		require.NotErrorIs(t, err, net.ErrClosed)
		require.EqualValues(t, 1, inner.closes.Load(), "Close still releases the listener it owns, once")
	})

	t.Run("close then fail", func(t *testing.T) {
		inner := newCountedListener(listen(t))
		tl := NewTunnelListener(inner)

		require.NoError(t, tl.Close())
		tl.Fail(errLost)

		_, err := tl.Accept()
		require.ErrorIs(t, err, net.ErrClosed)
		require.NotErrorIs(t, err, errLost)
		require.EqualValues(t, 1, inner.closes.Load())
	})

	t.Run("concurrent closes close the inner listener once and agree on the result", func(t *testing.T) {
		inner := newCountedListener(listen(t))
		release := make(chan struct{})
		inner.release = release
		tl := NewTunnelListener(inner)
		var unblock sync.Once
		t.Cleanup(func() { unblock.Do(func() { close(release) }) })

		results := make(chan error, 2)
		go func() { results <- tl.Close() }()
		go func() { results <- tl.Close() }()

		await(t, inner.closing, "Close never reached the inner listener")
		select {
		case err := <-results:
			t.Fatalf("a Close returned before the inner listener's Close did: %v", err)
		default:
		}
		unblock.Do(func() { close(release) })
		require.NoError(t, await(t, results, "the first Close never returned"))
		require.NoError(t, await(t, results, "the second Close never returned"))
		require.EqualValues(t, 1, inner.closes.Load())
	})
}

func TestTunnelListenerSwapAfterClose(t *testing.T) {
	first := newCountedListener(listen(t))
	next := newCountedListener(listen(t))
	tl := NewTunnelListener(first)
	require.NoError(t, tl.Close())

	require.False(t, tl.Swap(next))

	require.Zero(t, next.closes.Load(), "the caller still owns the listener it offered")
	c, err := net.Dial("tcp", next.Addr().String())
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	accepted, err := next.Accept()
	require.NoError(t, err, "next is still open")
	_ = accepted.Close()

	_, err = tl.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestTunnelListenerSwapAfterFail(t *testing.T) {
	first := newCountedListener(listen(t))
	next := newCountedListener(listen(t))
	tl := NewTunnelListener(first)
	t.Cleanup(func() { _ = tl.Close() })
	errLost := errors.New("relay gone for good")
	tl.Fail(errLost)

	require.False(t, tl.Swap(next), "nothing will accept from a listener installed after the loss")

	require.Zero(t, next.closes.Load())
	require.Zero(t, first.closes.Load(), "a refused Swap leaves the current listener alone")
	_, err := tl.Accept()
	require.ErrorIs(t, err, errLost)
}

func TestTunnelListenerSwapClosesThePreviousListener(t *testing.T) {
	first := newCountedListener(listen(t))
	second := newCountedListener(listen(t))
	third := newCountedListener(listen(t))
	tl := NewTunnelListener(first)

	require.True(t, tl.Swap(second))
	require.EqualValues(t, 1, first.closes.Load())
	require.Zero(t, second.closes.Load())

	second.lose() // the tunnel died; closing its listener is still harmless
	require.True(t, tl.Swap(third))
	require.EqualValues(t, 1, second.closes.Load())

	require.NoError(t, tl.Close())
	require.EqualValues(t, 1, first.closes.Load(), "an earlier listener is not closed again")
	require.EqualValues(t, 1, second.closes.Load())
	require.EqualValues(t, 1, third.closes.Load())
}

func TestTunnelListenerSwapDoesNotBlockBehindASlowClose(t *testing.T) {
	old := newCountedListener(listen(t))
	release := make(chan struct{})
	old.release = release
	next := listen(t)
	tl := NewTunnelListener(old)
	t.Cleanup(func() { _ = tl.Close() })
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(release) }) })

	// The old listener is healthy and its Accept is parked: only Swap's
	// close ends it, and that close is held open as a slow relay would hold it.
	await(t, old.accepting, "the old listener was never accepted from")
	swapped := make(chan bool, 1)
	go func() { swapped <- tl.Swap(next) }()
	await(t, old.closing, "Swap never closed the old listener")

	got := acceptAsync(tl)
	c, err := net.Dial("tcp", next.Addr().String())
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	r := receiveAccept(t, got)
	require.NoError(t, r.err, "Accept moved on to the new listener while the old one was still closing")
	_ = r.conn.Close()

	select {
	case <-swapped:
		t.Fatal("Swap returned before the old listener's Close did")
	default:
	}

	// Close does not wait behind it either.
	closed := make(chan error, 1)
	go func() { closed <- tl.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(tunnelListenerHangGuard):
		t.Fatal("Close is stuck behind Swap's close of the old listener")
	}
	_, err = tl.Accept()
	require.ErrorIs(t, err, net.ErrClosed)

	unblock.Do(func() { close(release) })
	require.True(t, await(t, swapped, "Swap never returned"))
}

func TestTunnelListenerAddrIsTheFirstListeners(t *testing.T) {
	l1, l2 := listen(t), listen(t)
	tl := NewTunnelListener(l1)
	t.Cleanup(func() { _ = tl.Close() })
	require.Equal(t, l1.Addr(), tl.Addr())

	require.True(t, tl.Swap(l2))
	require.Equal(t, l1.Addr(), tl.Addr())
}

func TestTunnelListenerUnderRace(t *testing.T) {
	const (
		acceptors = 4
		dialers   = 3
		swaps     = 40
	)

	var (
		mu        sync.Mutex
		installed []*countedListener
	)
	newInner := func() *countedListener {
		l := newCountedListener(listen(t))
		mu.Lock()
		installed = append(installed, l)
		mu.Unlock()
		return l
	}

	first := newInner()
	tl := NewTunnelListener(first)

	var current atomic.Value // the address dialers aim at
	current.Store(first.Addr().String())

	var (
		acceptWG   sync.WaitGroup
		acceptErrs = make(chan error, acceptors)
	)
	for range acceptors {
		acceptWG.Add(1)
		go func() {
			defer acceptWG.Done()
			for {
				c, err := tl.Accept()
				if err != nil {
					acceptErrs <- err
					return
				}
				_ = c.Close()
			}
		}()
	}

	stopDialers := make(chan struct{})
	var dialWG sync.WaitGroup
	for range dialers {
		dialWG.Add(1)
		go func() {
			defer dialWG.Done()
			for {
				select {
				case <-stopDialers:
					return
				default:
				}
				if c, err := net.Dial("tcp", current.Load().(string)); err == nil {
					_ = c.Close()
				}
			}
		}()
	}

	// Close races the swaps from the middle of them.
	midway := make(chan struct{})
	closed := make(chan error, 1)
	go func() {
		<-midway
		closed <- tl.Close()
	}()

	prev := first
	for i := range swaps {
		if i == swaps/2 {
			close(midway)
		}
		next := newInner()
		if i%2 == 0 {
			prev.lose() // the tunnel dies before it is replaced
		}
		if tl.Swap(next) {
			current.Store(next.Addr().String())
			prev = next
			continue
		}
		_ = next.Close() // not installed, so still its owner's to close
	}

	done := make(chan struct{})
	go func() {
		acceptWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(tunnelListenerHangGuard):
		t.Fatal("an Accept never returned after Close")
	}
	_ = await(t, closed, "Close never returned") // the inner Close's own answer depends on which listener was current
	close(stopDialers)
	dialWG.Wait()

	close(acceptErrs)
	for err := range acceptErrs {
		require.ErrorIs(t, err, net.ErrClosed, "a swap must never surface as an Accept error")
	}
	mu.Lock()
	defer mu.Unlock()
	for i, l := range installed {
		require.EqualValues(t, 1, l.closes.Load(), "listener %d is closed exactly once, by whoever owns it", i)
	}
}
