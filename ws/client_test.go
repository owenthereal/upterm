package ws

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handshakeHost dials rawURL through NewWSConn with the network dialer swapped
// for an in-memory pipe and returns the Host header the client put on the wire.
// The server end closes without answering, so the handshake itself fails.
func handshakeHost(t *testing.T, rawURL string) string {
	t.Helper()

	client, server := net.Pipe()
	origDial, origProxy := websocket.DefaultDialer.NetDialContext, websocket.DefaultDialer.Proxy
	websocket.DefaultDialer.NetDialContext = func(context.Context, string, string) (net.Conn, error) {
		return client, nil
	}
	websocket.DefaultDialer.Proxy = nil // an HTTP(S)_PROXY in the environment would send a CONNECT first
	t.Cleanup(func() {
		websocket.DefaultDialer.NetDialContext, websocket.DefaultDialer.Proxy = origDial, origProxy
	})

	hostCh := make(chan string, 1)
	go func() {
		defer func() { _ = server.Close() }()
		req, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			hostCh <- "read error: " + err.Error()
			return
		}
		hostCh <- req.Host
	}()

	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	_, _ = NewWSConn(u, true)
	_ = client.Close() // unblock the reader if the dial never wrote

	return <-hostCh
}

func TestNewWSConnHostHeaderOmitsDefaultPort(t *testing.T) {
	assert.Equal(t, "example.com", handshakeHost(t, "ws://sid:addr@example.com:80"))
}

func TestNewWSConnHostHeaderKeepsNonDefaultPort(t *testing.T) {
	assert.Equal(t, "example.com:8080", handshakeHost(t, "ws://sid:addr@example.com:8080"))
}

func TestStripDefaultPort(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "ws default port", url: "ws://test.com:80", want: "ws://test.com"},
		{name: "wss default port", url: "wss://test.com:443", want: "wss://test.com"},
		{name: "ws non-default port", url: "ws://test.com:4433", want: "ws://test.com:4433"},
		{name: "wss non-default port", url: "wss://test.com:8080", want: "wss://test.com:8080"},
		{name: "ws with the wss default port", url: "ws://test.com:443", want: "ws://test.com:443"},
		{name: "wss with the ws default port", url: "wss://test.com:80", want: "wss://test.com:80"},
		{name: "no port", url: "wss://test.com", want: "wss://test.com"},
		{name: "path and query", url: "ws://test.com:80/foo?bar=baz", want: "ws://test.com/foo?bar=baz"},
		{name: "userinfo", url: "ws://user:pass@test.com:80", want: "ws://user:pass@test.com"},
		{name: "ipv6 default port", url: "ws://[::1]:80", want: "ws://[::1]"},
		{name: "ipv6 non-default port", url: "ws://[::1]:8080", want: "ws://[::1]:8080"},
		{name: "ipv6 no port", url: "ws://[::1]", want: "ws://[::1]"},
		{name: "ipv6 zone default port", url: "wss://[fe80::1%25eth0]:443", want: "wss://[fe80::1%25eth0]"},
		{name: "ws zero-padded default port", url: "ws://test.com:080", want: "ws://test.com"},
		{name: "wss zero-padded default port", url: "wss://test.com:0443", want: "wss://test.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			require.NoError(t, err)
			StripDefaultPort(u)
			assert.Equal(t, tt.want, u.String())
		})
	}
}
