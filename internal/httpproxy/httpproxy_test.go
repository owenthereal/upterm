package httpproxy_test

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/httpproxy"
	"github.com/owenthereal/upterm/internal/httpproxy/httpproxytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDial(t *testing.T) {
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

	proxy := httpproxytest.Start(t, http.StatusOK)
	proxyURL := *proxy.URL
	proxyURL.User = url.UserPassword("user", "s3cret")

	conn, err := httpproxy.Dial(t.Context(), &proxyURL, echo.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))

	assert.Equal(t, echo.Addr().String(), proxy.LastTarget())
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("user:s3cret")), proxy.LastAuth())
}

// A proxy URL may carry a bare token with no password. net/http sends
// Proxy-Authorization for it and gorilla does not, so the same --proxy value
// authenticated on the ssh:// path and collected a 407 on the ws:// one.
func TestDialSendsCredentialForUsernameOnlyProxy(t *testing.T) {
	proxy := httpproxytest.StartRaw(t, "HTTP/1.1 200 Connection Established\r\n\r\n")
	proxyURL := *proxy.URL
	proxyURL.User = url.User("token")

	conn, err := httpproxy.Dial(t.Context(), &proxyURL, "uptermd.example.com:22")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("token:")), proxy.LastAuth())
}

func TestDialRefused(t *testing.T) {
	proxy := httpproxytest.Start(t, http.StatusProxyAuthRequired)

	_, err := httpproxy.Dial(t.Context(), proxy.URL, "uptermd.example.com:22")

	require.Error(t, err)
	// The proxy and the target both appear. gorilla reports only the reason
	// phrase, which leaves a 407 looking like it came from the upterm server.
	assert.Contains(t, err.Error(), "407")
	assert.Contains(t, err.Error(), proxy.URL.Host)
	assert.Contains(t, err.Error(), "uptermd.example.com:22")
	// A 407 is answerable with credentials, so the port-policy advice would
	// only crowd out the status that says what to do.
	assert.NotContains(t, err.Error(), "wss://")
}

// Squid's SSL_ports ACL allows 443 only, so the usual corporate answer for
// port 22 is a refusal. Without the hint it reads as though the upterm server
// were unreachable, and the way out — a wss:// server on 443 — is not obvious.
func TestDialRefusedOnPort22SuggestsWSS(t *testing.T) {
	proxy := httpproxytest.Start(t, http.StatusForbidden)

	_, err := httpproxy.Dial(t.Context(), proxy.URL, "relay.corp:22")

	require.Error(t, err)
	// The host being dialled, not upterm's public relay: a custom --server was
	// chosen for a reason, and only the transport is in question here.
	assert.Contains(t, err.Error(), "wss://relay.corp")
	assert.NotContains(t, err.Error(), "uptermd.upterm.dev")
}

// The same refusal to a WebSocket port is just a refusal: 443 is what proxies
// already allow, so pointing at wss:// would be noise.
func TestDialRefusedOnPort443OmitsTheHint(t *testing.T) {
	proxy := httpproxytest.Start(t, http.StatusForbidden)

	_, err := httpproxy.Dial(t.Context(), proxy.URL, "uptermd.upterm.dev:443")

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "wss://")
}

// A status line with no reason phrase is legal. gorilla splits on the space
// and indexes [1] unconditionally, so this input panics its dialer.
func TestDialRefusedWithNoReasonPhrase(t *testing.T) {
	proxy := httpproxytest.StartRaw(t, "HTTP/1.1 407\r\n\r\n")

	_, err := httpproxy.Dial(t.Context(), proxy.URL, "uptermd.example.com:22")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "407")
}

// RFC 9110 9.3.6: any 2xx establishes the tunnel, not 200 alone.
func TestDialAcceptsAny2xx(t *testing.T) {
	proxy := httpproxytest.StartRaw(t, "HTTP/1.1 201 Tunnel Established\r\n\r\n")

	conn, err := httpproxy.Dial(t.Context(), proxy.URL, "uptermd.example.com:22")

	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
}

// A 2xx answer to CONNECT has no body: everything after its header belongs to
// the tunnel. Squid answers CONNECT with a Content-Length and keep-alive, and
// an ssh:// server speaks first, so reading those bytes as a body swallows the
// banner and the handshake then fails with an opaque version error.
func TestDialKeepsBytesAfterANonConformantOK(t *testing.T) {
	const banner = "SSH-2.0-Upterm\r\n"
	proxy := httpproxytest.StartRaw(t, "HTTP/1.1 200 Connection Established\r\nContent-Length: 4\r\n\r\n"+banner)

	conn, err := httpproxy.Dial(t.Context(), proxy.URL, "uptermd.example.com:22")
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
