package testhelpers

import (
	"net"
	"sync"
	"sync/atomic"
)

// TB is the part of *testing.T this package uses. Depending on an interface
// keeps the testing package, and the flags it registers, out of a non-test
// import graph.
type TB interface {
	Helper()
	Cleanup(func())
	Fatalf(format string, args ...any)
}

// Forwarder is a TCP forwarder a test can switch: it stands between a host and
// its relay, so a test can cut the tunnel, silence it, or send the next
// connection somewhere else, the way a network does.
type Forwarder struct {
	ln net.Listener

	mu     sync.Mutex
	target string
	links  map[*link]struct{}
	closed bool

	wg sync.WaitGroup
}

// link is one forwarded connection: what was accepted, and what was dialled
// for it.
type link struct {
	down, up net.Conn
	// blackholed links drop whatever arrives, in both directions, and keep
	// both halves open however either end leaves.
	blackholed atomic.Bool
}

func (l *link) close() {
	_ = l.down.Close()
	_ = l.up.Close()
}

// NewForwarder forwards every connection to its address on to target, until the
// test ends.
func NewForwarder(t TB, target string) *Forwarder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("forwarder: listen: %v", err)
	}
	f := &Forwarder{ln: ln, target: target, links: make(map[*link]struct{})}
	t.Cleanup(f.close)
	f.wg.Add(1)
	go f.accept()
	return f
}

// Addr is the address to dial in place of the target.
func (f *Forwarder) Addr() string { return f.ln.Addr().String() }

// Redirect sends the connections accepted from now on to target. Those already
// forwarded keep the target they were dialled to.
func (f *Forwarder) Redirect(target string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.target = target
}

// Cut closes every forwarded connection, both halves, as a dropped link would
// be seen by an end that notices. Later connections pass.
func (f *Forwarder) Cut() {
	f.mu.Lock()
	links := f.links
	f.links = make(map[*link]struct{})
	f.mu.Unlock()
	for l := range links {
		l.close()
	}
}

// Blackhole makes every connection forwarded so far pass nothing more, in either
// direction, while staying open at both ends, as a link that went silent
// without either end hearing so. Connections accepted afterwards pass
// normally, so a host can redial past a blackholed one.
func (f *Forwarder) Blackhole() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for l := range f.links {
		l.blackholed.Store(true)
	}
}

func (f *Forwarder) accept() {
	defer f.wg.Done()
	for {
		down, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		target := f.target
		f.mu.Unlock()

		// A target that refuses is a connection that ends at once, the way
		// one dialled to a closed port does.
		up, err := net.Dial("tcp", target)
		if err != nil {
			_ = down.Close()
			continue
		}
		l := &link{down: down, up: up}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			l.close()
			return
		}
		f.links[l] = struct{}{}
		f.wg.Add(2)
		f.mu.Unlock()
		go f.pipe(l, l.up, l.down)
		go f.pipe(l, l.down, l.up)
	}
}

// pipe copies src to dst until src ends. Once l is blackholed, what it reads is
// dropped, and its end is kept from dst: a blackholed link ends only on Cut or
// cleanup.
func (f *Forwarder) pipe(l *link, dst, src net.Conn) {
	defer f.wg.Done()
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 && !l.blackholed.Load() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				err = werr
			}
		}
		if err == nil {
			continue
		}
		if l.blackholed.Load() {
			return
		}
		// Whatever ended this direction, an end leaving or a failed write,
		// ends the link.
		l.close()
		f.mu.Lock()
		delete(f.links, l)
		f.mu.Unlock()
		return
	}
}

func (f *Forwarder) close() {
	_ = f.ln.Close()
	f.mu.Lock()
	f.closed = true
	links := f.links
	f.links = make(map[*link]struct{})
	f.mu.Unlock()
	for l := range links {
		l.close()
	}
	f.wg.Wait()
}
