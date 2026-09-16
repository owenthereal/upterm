// Package httpproxy opens TCP tunnels through an HTTP proxy using CONNECT.
//
// It sits in a neutral package because both callers need it and neither can
// hold it: ws cannot import host/internal, since host/internal imports server
// and server imports ws.
package httpproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dialTimeout bounds connecting to the proxy and the CONNECT exchange, but
// only when the caller's context carries no deadline of its own.
const dialTimeout = 30 * time.Second

// maxResponseHeaderBytes caps what is buffered while reading the CONNECT
// response. Without it, a proxy streaming a header line that never terminates
// is accumulated in memory until the deadline; http.ReadResponse imposes no
// limit of its own. The value is net/http's default for this same read. It is
// a variable so tests can shrink it.
var maxResponseHeaderBytes int64 = 10 << 20

// Dial opens a TCP tunnel to addr through the HTTP proxy at proxyURL. The
// context's deadline bounds the dial and the CONNECT exchange, not the
// lifetime of the returned connection.
func Dial(ctx context.Context, proxyURL *url.URL, addr string) (net.Conn, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dialTimeout)
		defer cancel()
	}

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
		// Sent whenever userinfo is present, with or without a password, which
		// is what net/http's own proxyAuth does. gorilla requires a password to
		// be set, so "http://token@proxy:3128" authenticates on one path and
		// collects a 407 on the other.
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

	// Keep reading through br afterwards: it may already hold bytes the server
	// sent right after the CONNECT response.
	lr := &io.LimitedReader{R: conn, N: maxResponseHeaderBytes}
	br := bufio.NewReader(lr)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("error reading CONNECT response from proxy %s: %w", proxyAddr, err)
	}

	// resp.Body deliberately goes unclosed: it reads through br, which is
	// attached to the live socket, so closing it drains however many bytes the
	// response announced. RFC 9110 9.3.6 requires a client to ignore
	// Content-Length and Transfer-Encoding on a 2xx answer to CONNECT — those
	// bytes are the tunnel's, and on a server-speaks-first protocol they are
	// the SSH banner. Neither net/http's dialConn nor gorilla's dialer closes
	// it either; the branch below closes conn, which is what actually frees it.
	//
	// Any 2xx establishes the tunnel, per the same section. No known proxy
	// sends a non-200 2xx, so this is conformance rather than a live fix.
	if resp.StatusCode/100 != 2 {
		_ = conn.Close()
		return nil, refusedError(proxyAddr, addr, resp)
	}

	// The cap covered the response headers. Lift it before the tunnel is
	// handed over, or the conversation itself would be cut off at 10 MiB.
	lr.N = math.MaxInt64

	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, r: br}, nil
}

// refusedError reports a CONNECT the proxy would not open, naming the likely
// cause when the target is SSH's port.
//
// Stock Squid denies CONNECT to anything outside its SSL_ports ACL, which is
// 443 alone, so the common corporate answer for port 22 is an immediate
// refusal rather than a timeout — and the refusal on its own reads as though
// the upterm server were unreachable.
func refusedError(proxyAddr, addr string, resp *http.Response) error {
	err := fmt.Errorf("proxy %s refused CONNECT to %s: %s", proxyAddr, addr, resp.Status)

	// Only for an answer that means "not to that port". A challenge is
	// answerable with credentials, a 4xx about the request is about the
	// request, and a 5xx is the proxy or its upstream failing — in none of
	// those would a different port be the fix, and the advice would crowd out
	// the status that says what actually is.
	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusMethodNotAllowed, http.StatusNotImplemented:
	default:
		return err
	}

	// The suggestion keeps the host that was being dialled and changes only the
	// transport. Naming upterm's public relay would silently move the session
	// onto a different deployment.
	if host, port, splitErr := net.SplitHostPort(addr); splitErr == nil && port == "22" {
		return fmt.Errorf("%w; many proxies allow CONNECT only to port 443, "+
			"so try a WebSocket server instead, e.g. --server %s", err, WebSocketServerURL(host))
	}
	return err
}

// WebSocketServerURL formats host as a wss:// --server value.
//
// Exported because the CONNECT refusal here and the dial-failure hint in
// host/internal both suggest one, and a bare IPv6 address needs bracketing to
// be a valid authority — "wss://2001:db8::1" is not a URL either of them could
// have accepted back.
func WebSocketServerURL(host string) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "wss://" + host
}

// proxyHostPort returns the address to dial for proxyURL, defaulting the port
// to 80.
//
// parseProxyURL already defaults it, so for --proxy this is a no-op. It is
// repeated here because ws.NewWSConn and ws.NewSSHClient are exported and take
// a proxy URL directly: both accepted portless ones before this dialer existed
// — the ssh path defaulted explicitly, and gorilla's hostPortNoPort did the
// same — and relying on the CLI boundary alone would regress them into
// "missing port in address". The flag keeps normalising so that one canonical
// URL is what reaches http.ProxyURL and the key fetch.
//
// URL.Host and URL.Hostname both exclude userinfo, so proxy credentials cannot
// reach an error message through the result.
func proxyHostPort(proxyURL *url.URL) string {
	if proxyURL.Port() != "" {
		return proxyURL.Host
	}
	return net.JoinHostPort(proxyURL.Hostname(), "80")
}

// bufferedConn is a net.Conn that reads through r, so bytes r already buffered
// from Conn are not lost.
//
// This is what makes the dialer usable for ssh://. gorilla returns the raw
// connection and throws its buffered reader away, which is safe only because
// WebSocket is client-speaks-first; an SSH server sends its banner
// unprompted, and it can arrive in the same segment as the CONNECT response.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}
