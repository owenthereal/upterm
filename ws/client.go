package ws

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
	chshare "github.com/jpillora/chisel/share"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

// NewSSHClient creates a ssh client via ws.
// The url must include username as session id and password as encoded node address.
// isUptermClient indicates whehter the client is host client or client client.
func NewSSHClient(u *url.URL, config *ssh.ClientConfig, isUptermClient bool) (*ssh.Client, error) {
	conn, err := NewWSConn(u, isUptermClient)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, u.Host, config)
	if err != nil {
		return nil, err
	}

	return ssh.NewClient(c, chans, reqs), nil
}

// NewWSConn creates a ws net.Conn.
// The url must include username as session id and password as encoded node address.
// isUptermClient indicates whehter the client is host client or client client.
func NewWSConn(u *url.URL, isUptermClient bool) (net.Conn, error) {
	u, _ = url.Parse(u.String()) // clone
	user := u.User
	u.User = nil // ws spec doesn't support basic auth

	header := webSocketDialHeader(user.Username(), isUptermClient)
	wsc, _, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		return nil, err
	}

	return WrapWSConn(wsc), nil
}

func WrapWSConn(ws *websocket.Conn) net.Conn {
	return chshare.NewWebSocketConn(ws)
}

func webSocketDialHeader(sessionID string, isClient bool) http.Header {
	auth := base64.StdEncoding.EncodeToString([]byte(sessionID + ":" + "pass"))
	header := make(http.Header)
	header.Add("Authorization", "Basic "+auth)

	ver := upterm.HostSSHClientVersion
	if isClient {
		ver = upterm.ClientSSHClientVersion
	}
	header.Add("Upterm-Client-Version", ver)

	return header
}
