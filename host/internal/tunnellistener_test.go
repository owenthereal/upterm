package internal

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

// tunnelListenerHangGuard only turns a hang into a failure; nothing asserts
// on how much of it a call used.
const tunnelListenerHangGuard = 10 * time.Second

// tunnelTestListen is a loopback listener that is closed with the test.
func tunnelTestListen(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// tunnelTestCountedListener stands in for a forwarded listener. Closing it ends its
// Accept before anything else, as x/crypto's does, and the rest of Close —
// the request to the relay — can then be held open by release.
type tunnelTestCountedListener struct {
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

func tunnelTestNewCountedListener(l net.Listener) *tunnelTestCountedListener {
	return &tunnelTestCountedListener{
		Listener:  l,
		accepting: make(chan struct{}, 1),
		closing:   make(chan struct{}),
	}
}

func (c *tunnelTestCountedListener) Accept() (net.Conn, error) {
	select {
	case c.accepting <- struct{}{}:
	default:
	}
	return c.Listener.Accept()
}

func (c *tunnelTestCountedListener) Close() error {
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
func (c *tunnelTestCountedListener) lose() { _ = c.Listener.Close() }

type tunnelTestAcceptResult struct {
	conn net.Conn
	err  error
}

func tunnelTestAcceptAsync(l net.Listener) <-chan tunnelTestAcceptResult {
	ch := make(chan tunnelTestAcceptResult, 1)
	go func() {
		c, err := l.Accept()
		ch <- tunnelTestAcceptResult{conn: c, err: err}
	}()
	return ch
}

func tunnelTestReceiveAccept(t *testing.T, ch <-chan tunnelTestAcceptResult) tunnelTestAcceptResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(tunnelListenerHangGuard):
		t.Fatal("Accept did not return")
		return tunnelTestAcceptResult{}
	}
}

// tunnelTestParkedListener is a forwarded listener that lives entirely on channels, so
// that inside a synctest bubble an Accept parked on it — or on the
// TunnelListener in front of it — is durably blocked, and synctest.Wait
// returns only once every such Accept is. It delivers only the connections a
// test sends on conns.
type tunnelTestParkedListener struct {
	// gone is closed when the tunnel ends, by lose or by Close.
	gone     chan struct{}
	goneOnce sync.Once

	// conns is where a test hands the listener a connection to accept.
	conns chan net.Conn
	// hold, when non-nil, keeps an Accept that has taken a connection from
	// returning it until hold is closed: the connection is accepted from the
	// tunnel's side, and the caller has not yet been told.
	hold <-chan struct{}

	closes atomic.Int32
	// closing is closed once Close has ended Accept and is on its way to
	// returning.
	closing     chan struct{}
	closingOnce sync.Once
	// release holds Close open until it is closed; nil returns at once.
	release <-chan struct{}
}

func tunnelTestNewParkedListener() *tunnelTestParkedListener {
	return &tunnelTestParkedListener{
		gone:    make(chan struct{}),
		conns:   make(chan net.Conn),
		closing: make(chan struct{}),
	}
}

func (p *tunnelTestParkedListener) Accept() (net.Conn, error) {
	select {
	case c := <-p.conns:
		if p.hold != nil {
			<-p.hold
		}
		return c, nil
	case <-p.gone:
		return nil, net.ErrClosed
	}
}

// Close ends Accept before anything else, as x/crypto's forwarded listener
// does, and says it is closed if the tunnel had already ended.
func (p *tunnelTestParkedListener) Close() error {
	p.closes.Add(1)
	err := net.ErrClosed
	p.goneOnce.Do(func() {
		err = nil
		close(p.gone)
	})
	p.closingOnce.Do(func() { close(p.closing) })
	if p.release != nil {
		<-p.release
	}
	return err
}

// lose ends the listener the way a dead tunnel does: its Accept fails, and
// nobody has called Close.
func (p *tunnelTestParkedListener) lose() { p.goneOnce.Do(func() { close(p.gone) }) }

func (p *tunnelTestParkedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

// tunnelTestRequireAcceptParked fails if an Accept has returned. Inside a bubble, after
// synctest.Wait, it proves the Accept is blocked rather than merely not
// finished yet.
func tunnelTestRequireAcceptParked(t *testing.T, ch <-chan tunnelTestAcceptResult) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("Accept returned before anything ended it: %v", r.err)
	default:
	}
}

// tunnelTestAcceptReturned is what a finished Accept returned, failing at once if it is
// still blocked. Inside a bubble, after synctest.Wait, nothing that could
// still wake it is left running.
func tunnelTestAcceptReturned(t *testing.T, ch <-chan tunnelTestAcceptResult) tunnelTestAcceptResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	default:
		t.Fatal("Accept is still blocked")
		return tunnelTestAcceptResult{}
	}
}

// tunnelTestAwait receives from ch, failing the test instead of hanging when
// nothing arrives.
func tunnelTestAwait[T any](t *testing.T, ch <-chan T, what string) T {
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
	l1, l2 := tunnelTestListen(t), tunnelTestListen(t)
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
	l1, l2 := tunnelTestListen(t), tunnelTestListen(t)
	tl := NewTunnelListener(l1)
	t.Cleanup(func() { _ = tl.Close() })

	through := func(l net.Listener) {
		t.Helper()
		got := tunnelTestAcceptAsync(tl)
		c, err := net.Dial("tcp", l.Addr().String())
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		r := tunnelTestReceiveAccept(t, got)
		require.NoError(t, r.err)
		defer func() { _ = r.conn.Close() }()
		require.Equal(t, c.LocalAddr().String(), r.conn.RemoteAddr().String())
	}

	through(l1)
	require.True(t, tl.Swap(l2))
	through(l2)
}

// The three tests that follow run in a synctest bubble: synctest.Wait returns
// only once every goroutine in it is durably blocked, so an Accept that has
// not returned by then is parked on its select, and what wakes it afterwards
// is what the test is about.

func TestTunnelListenerFailWakesAParkedAccept(t *testing.T) {
	errLost := errors.New("relay gone for good")
	synctest.Test(t, func(t *testing.T) {
		inner := tunnelTestNewParkedListener()
		tl := NewTunnelListener(inner)
		t.Cleanup(func() { _ = tl.Close() })

		got := tunnelTestAcceptAsync(tl)
		synctest.Wait()
		tunnelTestRequireAcceptParked(t, got)

		tl.Fail(errLost)
		synctest.Wait()

		r := tunnelTestAcceptReturned(t, got)
		require.ErrorIs(t, r.err, errLost)
		require.NotErrorIs(t, r.err, net.ErrClosed)
		require.Nil(t, r.conn)
		require.Zero(t, inner.closes.Load(), "Fail leaves closing to Close")

		_, err := tl.Accept()
		require.ErrorIs(t, err, errLost, "every later Accept fails the same way")
	})
}

func TestTunnelListenerFailWakesAnAcceptParkedAfterTheTunnelWasLost(t *testing.T) {
	errLost := errors.New("relay gone for good")
	synctest.Test(t, func(t *testing.T) {
		inner := tunnelTestNewParkedListener()
		tl := NewTunnelListener(inner)
		t.Cleanup(func() { _ = tl.Close() })

		inner.lose()
		got := tunnelTestAcceptAsync(tl)
		synctest.Wait()
		tunnelTestRequireAcceptParked(t, got)

		tl.Fail(errLost)
		synctest.Wait()

		require.ErrorIs(t, tunnelTestAcceptReturned(t, got).err, errLost)
	})
}

func TestTunnelListenerCloseWakesAParkedAcceptWithoutWaitingOnTheInnerClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		inner := tunnelTestNewParkedListener()
		release := make(chan struct{})
		inner.release = release
		tl := NewTunnelListener(inner)
		var unblock sync.Once
		t.Cleanup(func() { unblock.Do(func() { close(release) }) })

		inner.lose()
		got := tunnelTestAcceptAsync(tl)
		synctest.Wait()
		tunnelTestRequireAcceptParked(t, got)

		closed := make(chan error, 1)
		go func() { closed <- tl.Close() }()
		synctest.Wait()

		// Close is still held inside the inner listener's Close, which the
		// Accept must not have waited behind.
		<-inner.closing
		require.ErrorIs(t, tunnelTestAcceptReturned(t, got).err, net.ErrClosed)
		select {
		case <-closed:
			t.Fatal("Close returned before the inner listener's Close did")
		default:
		}

		unblock.Do(func() { close(release) })
		// The tunnel was already lost, so its listener says it is closed:
		// Close passes on what the inner Close returned.
		require.ErrorIs(t, <-closed, net.ErrClosed)
	})
}

// tunnelTestRequirePipeClosed fails if the other end of a net.Pipe has not been closed.
// Inside a bubble the read deadline runs on the bubble's clock, so an open
// connection costs no real time.
func tunnelTestRequirePipeClosed(t *testing.T, peer net.Conn) {
	t.Helper()
	// A pipe whose far end is closed refuses the deadline itself.
	err := peer.SetReadDeadline(time.Now().Add(time.Second))
	if err == nil {
		_, err = peer.Read(make([]byte, 1))
	}
	require.True(t, errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe),
		"a connection from the replaced tunnel was left open: %v", err)
}

// A connection the old tunnel's goroutine holds, waiting for an Accept, when
// the tunnel is replaced is closed, and the Accept that follows serves the new
// tunnel.
func TestTunnelListenerClosesAHeldConnectionWhenItsTunnelIsReplaced(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for range 50 {
			first := tunnelTestNewParkedListener()
			tl := NewTunnelListener(first)
			t.Cleanup(func() { _ = tl.Close() })

			old, oldPeer := net.Pipe()
			first.conns <- old
			synctest.Wait() // the old tunnel's goroutine holds old, and nothing accepts

			second := tunnelTestNewParkedListener()
			require.True(t, tl.Swap(second))
			fresh, freshPeer := net.Pipe()
			second.conns <- fresh

			c, err := tl.Accept()
			require.NoError(t, err)
			require.True(t, c == fresh, "Accept returned a connection from the replaced tunnel")
			tunnelTestRequirePipeClosed(t, oldPeer)
			_, _ = c.Close(), freshPeer.Close()
		}
	})
}

// A connection that reaches the pump's hand-off after its tunnel was replaced
// is never returned by an Accept that is already waiting for one: the select
// that hands it over has the send and the replacement both ready, and left to
// chance it would pick either. Each iteration is that coin flip.
func TestTunnelListenerNeverReturnsAConnectionFromAReplacedTunnel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for range 50 {
			hold := make(chan struct{})
			first := tunnelTestNewParkedListener()
			first.hold = hold
			tl := NewTunnelListener(first)
			t.Cleanup(func() { _ = tl.Close() })

			got := tunnelTestAcceptAsync(tl)
			synctest.Wait()
			tunnelTestRequireAcceptParked(t, got)

			// The old tunnel's listener has taken a connection and not yet
			// returned it to the pump; the tunnel is replaced meanwhile.
			old, oldPeer := net.Pipe()
			first.conns <- old
			synctest.Wait()
			second := tunnelTestNewParkedListener()
			require.True(t, tl.Swap(second))
			close(hold)
			synctest.Wait()

			tunnelTestRequireAcceptParked(t, got) // the old connection is not what Accept returns
			tunnelTestRequirePipeClosed(t, oldPeer)

			fresh, freshPeer := net.Pipe()
			second.conns <- fresh
			synctest.Wait()
			r := tunnelTestAcceptReturned(t, got)
			require.NoError(t, r.err)
			require.True(t, r.conn == fresh, "Accept returned a connection from the replaced tunnel")
			_, _ = r.conn.Close(), freshPeer.Close()
		}
	})
}

func TestTunnelListenerFailsOnlyWhenLostOrClosed(t *testing.T) {
	errLost := errors.New("relay gone for good")

	t.Run("fail before any Accept", func(t *testing.T) {
		inner := tunnelTestNewCountedListener(tunnelTestListen(t))
		tl := NewTunnelListener(inner)
		t.Cleanup(func() { _ = tl.Close() })

		tl.Fail(errLost)

		_, err := tl.Accept()
		require.ErrorIs(t, err, errLost)
		require.NotErrorIs(t, err, net.ErrClosed)
	})

	t.Run("close on a fresh listener", func(t *testing.T) {
		inner := tunnelTestNewCountedListener(tunnelTestListen(t))
		tl := NewTunnelListener(inner)

		require.NoError(t, tl.Close())

		_, err := tl.Accept()
		require.ErrorIs(t, err, net.ErrClosed)
		require.EqualValues(t, 1, inner.closes.Load())
	})
}

func TestTunnelListenerFirstOfFailAndCloseWins(t *testing.T) {
	errLost := errors.New("relay gone for good")

	t.Run("fail then close", func(t *testing.T) {
		inner := tunnelTestNewCountedListener(tunnelTestListen(t))
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
		inner := tunnelTestNewCountedListener(tunnelTestListen(t))
		tl := NewTunnelListener(inner)

		require.NoError(t, tl.Close())
		tl.Fail(errLost)

		_, err := tl.Accept()
		require.ErrorIs(t, err, net.ErrClosed)
		require.NotErrorIs(t, err, errLost)
		require.EqualValues(t, 1, inner.closes.Load())
	})

	t.Run("concurrent closes close the inner listener once and agree on the result", func(t *testing.T) {
		inner := tunnelTestNewCountedListener(tunnelTestListen(t))
		release := make(chan struct{})
		inner.release = release
		tl := NewTunnelListener(inner)
		var unblock sync.Once
		t.Cleanup(func() { unblock.Do(func() { close(release) }) })

		results := make(chan error, 2)
		go func() { results <- tl.Close() }()
		go func() { results <- tl.Close() }()

		tunnelTestAwait(t, inner.closing, "Close never reached the inner listener")
		select {
		case err := <-results:
			t.Fatalf("a Close returned before the inner listener's Close did: %v", err)
		default:
		}
		unblock.Do(func() { close(release) })
		require.NoError(t, tunnelTestAwait(t, results, "the first Close never returned"))
		require.NoError(t, tunnelTestAwait(t, results, "the second Close never returned"))
		require.EqualValues(t, 1, inner.closes.Load())
	})
}

func TestTunnelListenerSwapAfterClose(t *testing.T) {
	first := tunnelTestNewCountedListener(tunnelTestListen(t))
	next := tunnelTestNewCountedListener(tunnelTestListen(t))
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
	first := tunnelTestNewCountedListener(tunnelTestListen(t))
	next := tunnelTestNewCountedListener(tunnelTestListen(t))
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
	first := tunnelTestNewCountedListener(tunnelTestListen(t))
	second := tunnelTestNewCountedListener(tunnelTestListen(t))
	third := tunnelTestNewCountedListener(tunnelTestListen(t))
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
	old := tunnelTestNewCountedListener(tunnelTestListen(t))
	release := make(chan struct{})
	old.release = release
	next := tunnelTestListen(t)
	tl := NewTunnelListener(old)
	t.Cleanup(func() { _ = tl.Close() })
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(release) }) })

	// The old listener is healthy and its Accept is parked: only Swap's
	// close ends it, and that close is held open as a slow relay would hold it.
	tunnelTestAwait(t, old.accepting, "the old listener was never accepted from")
	swapped := make(chan bool, 1)
	go func() { swapped <- tl.Swap(next) }()
	tunnelTestAwait(t, old.closing, "Swap never closed the old listener")

	got := tunnelTestAcceptAsync(tl)
	c, err := net.Dial("tcp", next.Addr().String())
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	r := tunnelTestReceiveAccept(t, got)
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
	require.True(t, tunnelTestAwait(t, swapped, "Swap never returned"))
}

func TestTunnelListenerAddrIsTheFirstListeners(t *testing.T) {
	l1, l2 := tunnelTestListen(t), tunnelTestListen(t)
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
		installed []*tunnelTestCountedListener
	)
	newInner := func() *tunnelTestCountedListener {
		l := tunnelTestNewCountedListener(tunnelTestListen(t))
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
	_ = tunnelTestAwait(t, closed, "Close never returned") // the inner Close's own answer depends on which listener was current
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
