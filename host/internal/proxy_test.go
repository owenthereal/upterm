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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connectProxy is a minimal HTTP CONNECT proxy for tests.
type connectProxy struct {
	URL *url.URL

	// status is the response to CONNECT; 200 establishes the tunnel.
	status int

	tunnels    atomic.Int32
	lastAuth   atomic.Value // string
	lastTarget atomic.Value // string
}

func startConnectProxy(t *testing.T, status int) *connectProxy {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	p := &connectProxy{URL: &url.URL{Scheme: "http", Host: ln.Addr().String()}, status: status}
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

	_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	p.tunnels.Add(1)

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
