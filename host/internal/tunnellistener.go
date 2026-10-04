package internal

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

// TunnelListener is the guest door's listener: one net.Listener that keeps
// serving while the tunnel behind it is replaced.
//
// The guest door is a single ssh.Server.Serve call for the whole session, and
// Serve returns on any Accept error that is not temporary, so an error from a
// tunnel that went away would end the door for good. TunnelListener therefore
// never returns one: when the listener it is serving from fails, Accept waits
// for Swap to install the next tunnel's listener, and only Fail and Close end
// it.
//
// Every inner listener is accepted from on a goroutine of its own, so Accept,
// Swap, Fail and Close never wait on one another or on an inner listener. A
// forwarded listener's Close is a request to the relay, and an unresponsive
// relay holds it for seconds.
type TunnelListener struct {
	// addr is the first listener's, taken once so Addr needs no lock and
	// stays the same across swaps.
	addr net.Addr
	// conns hands a connection from the current listener's goroutine to
	// Accept. It is unbuffered: nothing is accepted from a tunnel until
	// Accept is ready for it.
	conns chan net.Conn
	// done is closed by the first of Fail and Close.
	done chan struct{}

	closeOnce sync.Once
	closeErr  error

	mu  sync.Mutex
	cur tunnelSource
	// err is what Accept fails with once done is closed. It is written under
	// mu before done is closed and never again, so a reader that has seen
	// done closed needs no lock.
	err error
}

// tunnelSource is one tunnel's listener, and the signal that it has been
// replaced.
type tunnelSource struct {
	ln      net.Listener
	retired chan struct{}
}

// NewTunnelListener serves from first until Swap replaces it. From here on
// first is the TunnelListener's to close, in Swap or in Close.
func NewTunnelListener(first net.Listener) *TunnelListener {
	l := &TunnelListener{
		addr:  first.Addr(),
		conns: make(chan net.Conn),
		done:  make(chan struct{}),
		cur:   tunnelSource{ln: first, retired: make(chan struct{})},
	}
	go l.pump(l.cur)
	return l
}

// pump accepts from one tunnel's listener and hands each connection to
// Accept, until the listener fails, the tunnel is replaced or the
// TunnelListener ends. A listener failing is not reported: it means the
// tunnel is gone, and what happens next is the supervisor's to decide.
func (l *TunnelListener) pump(src tunnelSource) {
	for {
		c, err := src.ln.Accept()
		if err != nil {
			return
		}
		select {
		case l.conns <- c:
		case <-src.retired:
			// This tunnel was replaced while the connection was in hand:
			// the guest that made it will redial through the new one.
			_ = c.Close()
			return
		case <-l.done:
			_ = c.Close()
			return
		}
	}
}

// Accept returns a connection from the current tunnel. It blocks across a
// Swap, and fails only once Fail or Close has been called: with an error
// wrapping Fail's, or with net.ErrClosed.
func (l *TunnelListener) Accept() (net.Conn, error) {
	// A select picks at random among its ready cases, so a listener that
	// has ended must not be left to chance against a connection that is
	// also ready.
	select {
	case <-l.done:
		return nil, l.err
	default:
	}

	select {
	case c := <-l.conns:
		select {
		case <-l.done:
			_ = c.Close()
			return nil, l.err
		default:
		}
		return c, nil
	case <-l.done:
		return nil, l.err
	}
}

// Swap makes next the listener Accept serves from, and closes the one it
// replaces. Accept is already serving from next by the time that Close
// starts, so a slow Close delays only Swap's return.
//
// Swap returns false, and installs nothing, once Fail or Close has ended the
// listener: nothing would ever accept from next, so closing it, and whatever
// tunnel it belongs to, is the caller's. The listener Swap does install is
// the TunnelListener's to close from then on.
func (l *TunnelListener) Swap(next net.Listener) bool {
	l.mu.Lock()
	if l.err != nil {
		l.mu.Unlock()
		return false
	}
	prev := l.cur
	l.cur = tunnelSource{ln: next, retired: make(chan struct{})}
	close(prev.retired)
	go l.pump(l.cur)
	l.mu.Unlock()

	// The error is the listener telling a tunnel that has already ended
	// that it is closed: there is nothing left to do about it.
	_ = prev.ln.Close()
	return true
}

// Fail ends the listener because the tunnel is lost for good: every current
// and later Accept returns an error wrapping err. It closes nothing; Close
// still releases the current listener, and has to be called.
//
// Fail has no effect once Fail or Close has already ended the listener: the
// first of the two sets what Accept returns.
func (l *TunnelListener) Fail(err error) {
	if err == nil {
		err = errors.New("tunnel lost")
	} else {
		err = fmt.Errorf("tunnel lost: %w", err)
	}
	l.mu.Lock()
	l.end(err)
	l.mu.Unlock()
}

// Close ends the listener — every current and later Accept returns
// net.ErrClosed, unless Fail got there first — and closes the current inner
// listener, which can take as long as that listener's own Close does. A
// second Close waits for the first to finish and returns what it returned.
func (l *TunnelListener) Close() error {
	l.mu.Lock()
	l.end(net.ErrClosed)
	cur := l.cur
	l.mu.Unlock()

	// Outside the lock: nothing else may wait behind a slow Close. cur is
	// the last listener Swap installed, since Swap installs nothing once the
	// listener has ended.
	l.closeOnce.Do(func() { l.closeErr = cur.ln.Close() })
	return l.closeErr
}

// end records why Accept fails, unless it already does. Callers hold mu.
func (l *TunnelListener) end(err error) {
	if l.err != nil {
		return
	}
	l.err = err
	close(l.done)
}

// Addr is the first listener's address, whichever tunnel is current.
func (l *TunnelListener) Addr() net.Addr {
	return l.addr
}
