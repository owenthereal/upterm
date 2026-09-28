package ws

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/owenthereal/upterm/internal/httpproxy/httpproxytest"
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
	_, _ = NewWSConn(u, true, nil)
	_ = client.Close() // unblock the reader if the dial never wrote

	return <-hostCh
}

func TestNewWSConnHostHeaderOmitsDefaultPort(t *testing.T) {
	assert.Equal(t, "example.com", handshakeHost(t, "ws://sid:addr@example.com:80"))
}

func TestNewWSConnHostHeaderKeepsNonDefaultPort(t *testing.T) {
	assert.Equal(t, "example.com:8080", handshakeHost(t, "ws://sid:addr@example.com:8080"))
}

// TestNewWSConnDialsThroughProxy verifies an explicit proxy wins over the
// environment: the dial goes to the proxy and opens with a CONNECT to the
// server, carrying the proxy's credentials.
//
// This drives a real listener rather than hooking websocket.DefaultDialer.
// NewWSConn now sets NetDialContext itself, so a hook there is overwritten;
// the old version of this test would have blocked forever waiting for a dial
// that its own hook never saw.
func TestNewWSConnDialsThroughProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://env-proxy.example.com:8080")

	// Refusing keeps the test off DNS entirely: the proxy records the request
	// and answers 407 without ever dialing uptermd.example.com.
	proxy := httpproxytest.Start(t, http.StatusProxyAuthRequired)
	proxyURL := *proxy.URL
	proxyURL.User = url.UserPassword("user", "secret")

	u, err := url.Parse("wss://sid:addr@uptermd.example.com")
	require.NoError(t, err)

	_, err = NewWSConn(u, true, &proxyURL)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "407")
	assert.Equal(t, "uptermd.example.com:443", proxy.LastTarget())
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("user:secret")), proxy.LastAuth())
}

// A username-only proxy URL must authenticate on the ws path too. gorilla
// sends Proxy-Authorization only when a password is set, so this is what pins
// ws to the shared dialer rather than letting it drift back to gorilla's.
func TestNewWSConnSendsCredentialForUsernameOnlyProxy(t *testing.T) {
	proxy := httpproxytest.Start(t, http.StatusProxyAuthRequired)
	proxyURL := *proxy.URL
	proxyURL.User = url.User("token")

	u, err := url.Parse("wss://sid:addr@uptermd.example.com")
	require.NoError(t, err)

	_, err = NewWSConn(u, true, &proxyURL)

	require.Error(t, err)
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("token:")), proxy.LastAuth())
}

// The wss handshake still has to complete end to end once the tunnel is open.
// Taking over NetDialContext means gorilla no longer dials, so this pins down
// that it still wraps the tunnel in TLS with ServerName from the target rather
// than the proxy, and then runs the upgrade over it.
func TestNewWSConnCompletesWSSHandshakeThroughProxy(t *testing.T) {
	var upgrader websocket.Upgrader
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = c.Close()
	}))
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	origTLS := websocket.DefaultDialer.TLSClientConfig
	websocket.DefaultDialer.TLSClientConfig = &tls.Config{RootCAs: pool}
	t.Cleanup(func() { websocket.DefaultDialer.TLSClientConfig = origTLS })

	proxy := httpproxytest.Start(t, http.StatusOK)
	target := strings.TrimPrefix(srv.URL, "https://")

	u, err := url.Parse("wss://sid:addr@" + target)
	require.NoError(t, err)

	conn, err := NewWSConn(u, true, proxy.URL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	assert.Equal(t, target, proxy.LastTarget())
	assert.EqualValues(t, 1, proxy.Tunnels())
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
			stripDefaultPort(u)
			assert.Equal(t, tt.want, u.String())
		})
	}
}
