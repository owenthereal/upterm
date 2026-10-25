// Package relaydial opens the connection an SSH transport to an upterm relay
// runs over. upterm host and upterm join dial the relay the same way, so the
// dial lives here and neither command owns it.
package relaydial

import (
	"context"
	"net"
	"net/url"
	"strings"

	"github.com/owenthereal/upterm/internal/httpproxy"
	"github.com/owenthereal/upterm/ws"
)

// defaultPorts maps a server URL's scheme to the port dialed when the URL has
// none.
var defaultPorts = map[string]string{
	"ssh": "22",
	"ws":  "80",
	"wss": "443",
}

// Dial opens the connection an SSH transport to server runs over, under ctx,
// and returns the address a host-key check is shown for it: host:port, with
// the scheme's default port when server has none. known_hosts checking
// requires host:port and keys the entry as [host]:443 for wss. Only the dial
// URL inside ws drops a default port, so that the Host header stays "host". The
// address is returned with the dial's error too.
// An already-ended ctx returns its error and the address without dialing.
//
// For ssh:// the connection is plain TCP. For ws:// and wss:// it is a
// WebSocket, which carries user as its credentials: user is split at its first
// colon into the URL's username and password, the session ID and the encoded
// node address ws.NewWSConnContext sends. guest is ws's isUptermClient. proxy,
// when non-nil, is the HTTP proxy to dial through. server is not modified.
func Dial(ctx context.Context, server *url.URL, user string, guest bool, proxy *url.URL) (net.Conn, string, error) {
	addr := hostPort(server)
	if err := ctx.Err(); err != nil {
		return nil, addr, err
	}

	switch server.Scheme {
	case "ws", "wss":
		u := *server // clone
		u.Host = addr
		name, password, _ := strings.Cut(user, ":")
		u.User = url.UserPassword(name, password)
		conn, err := ws.NewWSConnContext(ctx, &u, guest, proxy)
		return conn, addr, err
	}

	if proxy != nil {
		conn, err := httpproxy.Dial(ctx, proxy, addr)
		return conn, addr, err
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	return conn, addr, err
}

// hostPort is u's host with its scheme's default port when u has none. A
// scheme with no default keeps its host as it is.
func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	port, ok := defaultPorts[u.Scheme]
	if !ok {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), port)
}
