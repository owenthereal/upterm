package internal

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// proxyDialTimeout bounds connecting to the proxy and the CONNECT exchange.
const proxyDialTimeout = 30 * time.Second

// dialHTTPProxy opens a TCP tunnel to addr through the HTTP proxy at
// proxyURL using CONNECT. The ctx deadline bounds the dial and the CONNECT
// exchange, not the lifetime of the returned connection.
func dialHTTPProxy(ctx context.Context, proxyURL *url.URL, addr string) (net.Conn, error) {
	proxyAddr := proxyHostPort(proxyURL)
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing proxy %s: %w", proxyAddr, err)
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if u := proxyURL.User; u != nil {
		password, _ := u.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(u.Username() + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+cred)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("error sending CONNECT to proxy %s: %w", proxyAddr, err)
	}

	// Keep reading through br: it may already hold bytes the server sent
	// right after the CONNECT response.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("error reading CONNECT response from proxy %s: %w", proxyAddr, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy %s refused CONNECT to %s: %s", proxyAddr, addr, resp.Status)
	}

	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, r: br}, nil
}

// proxyHostPort returns the proxy's host:port, defaulting to port 80.
func proxyHostPort(proxyURL *url.URL) string {
	if proxyURL.Port() != "" {
		return proxyURL.Host
	}
	return net.JoinHostPort(proxyURL.Hostname(), "80")
}

// bufferedConn is a net.Conn that reads through r, so bytes r already
// buffered from Conn are not lost.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}
