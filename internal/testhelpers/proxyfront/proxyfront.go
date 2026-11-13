// Package proxyfront is a TCP front for tests: it forwards each connection it
// accepts to a target, with a PROXY protocol v2 header ahead of it naming the
// connection's own addresses, as a load balancer in front of a relay does.
package proxyfront

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// Front is a running front.
type Front struct {
	ln     net.Listener
	target string
	wg     sync.WaitGroup
	mu     sync.Mutex
	conns  map[net.Conn]bool
	closed bool
}

// Start listens on addr, over TCP on IPv4, and forwards each connection to
// target.
func Start(addr, target string) (*Front, error) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, err
	}
	f := &Front{ln: ln, target: target, conns: make(map[net.Conn]bool)}
	f.wg.Add(1)
	go f.serve()
	return f, nil
}

// Addr is the address the front listens on.
func (f *Front) Addr() string { return f.ln.Addr().String() }

// Close stops the front and every connection through it, and waits for them.
func (f *Front) Close() error {
	f.mu.Lock()
	f.closed = true
	for c := range f.conns {
		_ = c.Close()
	}
	f.mu.Unlock()
	err := f.ln.Close()
	f.wg.Wait()
	return err
}

// track records c until untrack, and is false once the front is closed.
func (f *Front) track(c net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.conns[c] = true
	return true
}

func (f *Front) untrack(c net.Conn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.conns, c)
}

func (f *Front) serve() {
	defer f.wg.Done()
	for {
		c, err := f.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Another error may last, as running out of descriptors does:
			// wait before trying again rather than spin.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.forward(c)
		}()
	}
}

func (f *Front) forward(c net.Conn) {
	defer func() { _ = c.Close() }()
	if !f.track(c) {
		return
	}
	defer f.untrack(c)
	up, err := net.Dial("tcp4", f.target)
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }()
	if !f.track(up) {
		return
	}
	defer f.untrack(up)
	if _, err := proxyproto.HeaderProxyFromAddrs(2, c.RemoteAddr(), c.LocalAddr()).WriteTo(up); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go pipe(up, c)
	go pipe(c, up)
	// Either direction ending ends both.
	<-done
	_ = c.Close()
	_ = up.Close()
	<-done
}
