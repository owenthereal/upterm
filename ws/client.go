package ws

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	chshare "github.com/jpillora/chisel/share"
	"github.com/owenthereal/upterm/internal/httpproxy"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

// NewSSHClient creates a ssh client via ws.
// The url must include username as session id and password as encoded node address.
// isUptermClient indicates whether the client is host client or client client.
// proxyURL, when non-nil, is the HTTP proxy to dial through (see NewWSConn).
func NewSSHClient(u *url.URL, config *ssh.ClientConfig, isUptermClient bool, proxyURL *url.URL) (*ssh.Client, error) {
	conn, err := NewWSConn(u, isUptermClient, proxyURL)
	if err != nil {
		return nil, err
	}
	// u.Host keeps the port that `upterm host` appends to portless ws/wss
	// server URLs: known_hosts checking requires host:port and keys the
	// entry as [host]:443. Only the dial URL inside NewWSConn drops it.
	c, chans, reqs, err := ssh.NewClientConn(conn, u.Host, config)
	if err != nil {
		return nil, err
	}

	return ssh.NewClient(c, chans, reqs), nil
}

// NewWSConn creates a ws net.Conn.
// The url must include username as session id and password as encoded node address.
// isUptermClient indicates whether the client is host client or client client.
// proxyURL, when non-nil, is the HTTP proxy to dial through; when nil, the
// proxy comes from the environment (HTTPS_PROXY, HTTP_PROXY, NO_PROXY).
func NewWSConn(u *url.URL, isUptermClient bool, proxyURL *url.URL) (net.Conn, error) {
	return NewWSConnContext(context.Background(), u, isUptermClient, proxyURL)
}

// NewWSConnContext is NewWSConn bounded by ctx: its deadline and a cancel both
// end the dial, any proxy's CONNECT, the TLS handshake and the upgrade. The
// returned connection outlives ctx.
func NewWSConnContext(ctx context.Context, u *url.URL, isUptermClient bool, proxyURL *url.URL) (net.Conn, error) {
	u, _ = url.Parse(u.String()) // clone
	user := u.User
	u.User = nil // ws spec doesn't support basic auth
	stripDefaultPort(u)

	encodedNodeAddr, _ := user.Password()
	header := webSocketDialHeader(user.Username(), encodedNodeAddr, isUptermClient)
	// Copied unconditionally: the settings below must not land on the
	// package-level default, and taking the copy here still picks up whatever
	// the process configured on it.
	dialer := *websocket.DefaultDialer
	dial := dialer.NetDialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	if proxyURL != nil {
		// Open the tunnel with upterm's own dialer instead of gorilla's.
		// gorilla throws away the reader it buffered the CONNECT response
		// through, which is safe only because WebSocket is client-speaks-first
		// — and the ssh:// path needs the same dialer, where it is not. Sharing
		// one also means proxy authentication, the default port, the accepted
		// statuses and the error text are defined once.
		//
		// gorilla still runs TLS for wss over the returned tunnel, with
		// ServerName taken from the target URL rather than from the proxy, and
		// then performs the upgrade.
		//
		// Only an explicit --proxy is taken over. The environment path stays
		// with gorilla, which also understands socks5:// in HTTPS_PROXY and
		// honours NO_PROXY; neither is something this dialer does.
		dialer.Proxy = nil
		dial = func(ctx context.Context, _, addr string) (net.Conn, error) {
			return httpproxy.Dial(ctx, proxyURL, addr)
		}
	}

	// gorilla turns only ctx's deadline into a socket deadline, so a plain
	// cancel would leave a read waiting on a silent server or proxy. Every TCP
	// connection the dial opens is therefore closed when ctx ends, until the
	// dial returns. gorilla's environment proxy dials through this same
	// function, so its CONNECT is covered too.
	//
	// The close watches ctx itself, not the context gorilla passes in: gorilla
	// derives that one with its HandshakeTimeout and cancels it as DialContext
	// returns, so a close armed on it would end every connection that
	// succeeded.
	var (
		mu    sync.Mutex
		stops []func() bool
	)
	dialer.NetDialContext = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(dialCtx, network, addr)
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		mu.Lock()
		stops = append(stops, stop)
		mu.Unlock()
		return conn, nil
	}
	wsc, _, err := dialer.DialContext(ctx, u.String(), header)

	// Every stop runs, so none outlives the dial. One that finds its close
	// already started lost the race to ctx: that connection is closing.
	mu.Lock()
	closing := false
	for _, stop := range stops {
		if !stop() {
			closing = true
		}
	}
	mu.Unlock()
	if err != nil {
		return nil, withCause(ctx, closing, err)
	}
	if closing {
		// The close is about to fail the connection the dial returned.
		_ = wsc.Close()
		return nil, ctx.Err()
	}

	return WrapWSConn(wsc), nil
}

// withCause wraps err in ctx's error when ctx is what failed the dial: closed
// says its close-on-cancel ran, and a socket timeout once ctx's deadline has
// passed is the deadline gorilla copied from ctx onto the socket. A failure ctx
// had no part in keeps its own error, so a cancel that merely coincides with
// it cannot hide it.
func withCause(ctx context.Context, closed bool, err error) error {
	cause := ctx.Err()
	if !closed {
		deadline, ok := ctx.Deadline()
		if !ok || !errors.Is(err, os.ErrDeadlineExceeded) || time.Now().Before(deadline) {
			return err
		}
		if cause == nil {
			// The socket's timer can fire before ctx's own does.
			cause = context.DeadlineExceeded
		}
	}
	if errors.Is(err, cause) {
		return err
	}
	return fmt.Errorf("%w: %w", cause, err)
}

func WrapWSConn(ws *websocket.Conn) net.Conn {
	return chshare.NewWebSocketConn(ws)
}

func webSocketDialHeader(sessionID, encodedNodeAddr string, isClient bool) http.Header {
	auth := base64.StdEncoding.EncodeToString([]byte(sessionID + ":" + encodedNodeAddr))
	header := make(http.Header)
	header.Add("Authorization", "Basic "+auth)

	ver := upterm.HostSSHClientVersion
	if isClient {
		ver = upterm.ClientSSHClientVersion
	}
	header.Add(upterm.HeaderUptermClientVersion, ver)

	return header
}

// wsDefaultPorts maps a WebSocket scheme to the port dialed when the URL has none.
var wsDefaultPorts = map[string]int{
	"ws":  80,
	"wss": 443,
}

// stripDefaultPort drops an explicit default port from u's host. The dialer
// copies the host verbatim into the Host header, and some firewalls and
// virtual-host matchers reject "example.com:443" where browsers and curl
// send "example.com". The address actually dialed does not change. The port
// is compared numerically because the dialer resolves ":0443" as 443 too.
func stripDefaultPort(u *url.URL) {
	def, ok := wsDefaultPorts[u.Scheme]
	if !ok || u.Port() == "" {
		return
	}
	if n, err := strconv.Atoi(u.Port()); err != nil || n != def {
		return
	}
	u.Host = strings.TrimSuffix(u.Host, ":"+u.Port())
}
