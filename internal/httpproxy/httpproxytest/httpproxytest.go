// Package httpproxytest provides a stub HTTP CONNECT proxy for tests.
//
// It is a package rather than a helper in a _test.go file because three
// packages need the same stub — internal/httpproxy, host/internal and ws — and
// test files cannot be imported.
package httpproxytest

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
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

// Proxy is a minimal HTTP CONNECT proxy.
type Proxy struct {
	// URL addresses the proxy and carries no credentials. A test that wants
	// Proxy-Authorization copies it and sets User.
	URL *url.URL

	// status is the answer to CONNECT; 200 establishes the tunnel.
	status int
	// rawReply, when set, is written verbatim in answer to CONNECT and no
	// target is dialed, standing in for a proxy that does not conform.
	rawReply string

	tunnels    atomic.Int32
	lastAuth   atomic.Value // string
	lastTarget atomic.Value // string
}

// Start runs a proxy answering CONNECT with status. A 200 splices the tunnel
// through to the requested target; any other status refuses it.
func Start(t TB, status int) *Proxy {
	t.Helper()
	return serve(t, &Proxy{status: status})
}

// StartRaw runs a proxy answering every CONNECT with reply, written verbatim,
// dialing no target. Whatever follows the header in reply becomes the tunnel's
// first bytes, which is how a non-conformant proxy is simulated.
func StartRaw(t TB, reply string) *Proxy {
	t.Helper()
	return serve(t, &Proxy{rawReply: reply})
}

func serve(t TB, p *Proxy) *Proxy {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("httpproxytest: listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	p.URL = &url.URL{Scheme: "http", Host: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(conn)
		}
	}()
	return p
}

// Tunnels reports how many CONNECTs were accepted.
func (p *Proxy) Tunnels() int32 { return p.tunnels.Load() }

// LastTarget reports the authority of the most recent CONNECT, or "" if the
// proxy was never asked for a tunnel.
func (p *Proxy) LastTarget() string { return loadString(&p.lastTarget) }

// LastAuth reports the Proxy-Authorization header of the most recent CONNECT,
// which is "" both when none was sent and when there was no CONNECT at all.
func (p *Proxy) LastAuth() string { return loadString(&p.lastAuth) }

func loadString(v *atomic.Value) string {
	s, _ := v.Load().(string)
	return s
}

func (p *Proxy) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	p.lastAuth.Store(req.Header.Get("Proxy-Authorization"))
	p.lastTarget.Store(req.Host)

	if p.rawReply != "" {
		// Not counted as a tunnel: reply may carry any status, and nothing
		// here checks that what it announces is what it then sends.
		_, _ = io.WriteString(conn, p.rawReply)
		// Stay open so the client reads its tunnel from a live socket rather
		// than from a closed one, which would mask a lost banner as an EOF.
		_, _ = io.Copy(io.Discard, br)
		return
	}

	if p.status != http.StatusOK {
		_ = (&http.Response{StatusCode: p.status, ProtoMajor: 1, ProtoMinor: 1}).Write(conn)
		return
	}

	target, err := net.Dial("tcp", req.Host)
	if err != nil {
		_ = (&http.Response{StatusCode: http.StatusBadGateway, ProtoMajor: 1, ProtoMinor: 1}).Write(conn)
		return
	}
	defer func() { _ = target.Close() }()

	// Counted before the reply is written, so a client that has read the reply
	// is guaranteed to see the count that goes with it.
	p.tunnels.Add(1)
	_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	go func() {
		_, _ = io.Copy(target, br)
		_ = target.Close()
	}()
	_, _ = io.Copy(conn, target)
}
