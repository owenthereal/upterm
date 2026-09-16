package internal

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connectProxy is a minimal HTTP CONNECT proxy for tests.
type connectProxy struct {
	URL *url.URL

	// status is the response to CONNECT; 200 establishes the tunnel.
	status int
	// rawReply, when set, is written verbatim in answer to CONNECT and no
	// target is dialed, standing in for a proxy that does not conform.
	rawReply string

	tunnels    atomic.Int32
	lastAuth   atomic.Value // string
	lastTarget atomic.Value // string
}

func startConnectProxy(t *testing.T, status int) *connectProxy {
	t.Helper()
	return serveConnectProxy(t, &connectProxy{status: status})
}

// startRawConnectProxy answers every CONNECT with reply and writes nothing
// more. Whatever follows the header in reply is the tunnel's first bytes.
func startRawConnectProxy(t *testing.T, reply string) *connectProxy {
	t.Helper()
	return serveConnectProxy(t, &connectProxy{rawReply: reply})
}

func serveConnectProxy(t *testing.T, p *connectProxy) *connectProxy {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	p.URL = &url.URL{Scheme: "http", Host: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(conn)
		}
	}()
	return p
}

func (p *connectProxy) serve(conn net.Conn) {
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

func TestDialHTTPProxy(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(conn, conn)
	}()

	proxy := startConnectProxy(t, http.StatusOK)
	proxyURL := *proxy.URL
	proxyURL.User = url.UserPassword("user", "s3cret")

	conn, err := dialHTTPProxy(t.Context(), &proxyURL, echo.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))

	assert.Equal(t, echo.Addr().String(), proxy.lastTarget.Load())
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("user:s3cret")), proxy.lastAuth.Load())
}

func TestDialHTTPProxyRefused(t *testing.T) {
	proxy := startConnectProxy(t, http.StatusProxyAuthRequired)

	_, err := dialHTTPProxy(t.Context(), proxy.URL, "uptermd.example.com:22")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "407")
}

// A 2xx answer to CONNECT has no body: everything after its header belongs to
// the tunnel. Squid answers CONNECT with a Content-Length and keep-alive, and
// an ssh:// server speaks first, so reading those bytes as a body swallows the
// banner and the handshake then fails with an opaque version error.
func TestDialHTTPProxyKeepsBytesAfterANonConformantOK(t *testing.T) {
	const banner = "SSH-2.0-Upterm\r\n"
	proxy := startRawConnectProxy(t, "HTTP/1.1 200 Connection Established\r\nContent-Length: 4\r\n\r\n"+banner)

	conn, err := dialHTTPProxy(t.Context(), proxy.URL, "uptermd.example.com:22")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// A deadline rather than a bare read: once the announced length has been
	// eaten the rest of the banner never arrives, and this reports what was
	// left instead of hanging until the package timeout.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, len(banner))
	n, err := io.ReadFull(conn, buf)
	require.NoError(t, err, "banner truncated to %q", buf[:n])
	assert.Equal(t, banner, string(buf[:n]))
}

func TestProxyHostPort(t *testing.T) {
	for raw, want := range map[string]string{
		"http://proxy.example.com":      "proxy.example.com:80",
		"http://proxy.example.com:3128": "proxy.example.com:3128",
		"http://[::1]":                  "[::1]:80",
	} {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		assert.Equal(t, want, proxyHostPort(u), raw)
	}
}
