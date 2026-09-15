package ws

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
	chshare "github.com/jpillora/chisel/share"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

// NewSSHClient creates a ssh client via ws.
// The url must include username as session id and password as encoded node address.
// isUptermClient indicates whether the client is host client or client client.
func NewSSHClient(u *url.URL, config *ssh.ClientConfig, isUptermClient bool) (*ssh.Client, error) {
	conn, err := NewWSConn(u, isUptermClient)
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
func NewWSConn(u *url.URL, isUptermClient bool) (net.Conn, error) {
	u, _ = url.Parse(u.String()) // clone
	user := u.User
	u.User = nil // ws spec doesn't support basic auth
	stripDefaultPort(u)

	encodedNodeAddr, _ := user.Password()
	header := webSocketDialHeader(user.Username(), encodedNodeAddr, isUptermClient)
	wsc, _, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		return nil, err
	}

	return WrapWSConn(wsc), nil
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
