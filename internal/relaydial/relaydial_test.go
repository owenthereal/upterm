package relaydial_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/relaydial"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handshake is what a ws relay saw of the upgrade request.
type handshake struct {
	username, password, clientVersion string
	hasAuth                           bool
}

// TestDialWSSendsUserAsCredentials checks what the relay receives on the
// upgrade: the connect string's user split at its first colon into the
// session ID and the encoded node address, which is where the relay reads them
// from. The server refuses the upgrade, so the dial fails; the request was
// recorded before that.
func TestDialWSSendsUserAsCredentials(t *testing.T) {
	tests := []struct {
		name         string
		user         string
		guest        bool
		wantUsername string
		wantPassword string
		wantVersion  string
	}{
		{
			name:         "a guest's session ID and node",
			user:         "abc:bm9kZTE=",
			guest:        true,
			wantUsername: "abc",
			wantPassword: "bm9kZTE=",
			wantVersion:  upterm.ClientSSHClientVersion,
		},
		{
			name:         "a host's user has no colon, so no password",
			user:         "alice",
			guest:        false,
			wantUsername: "alice",
			wantPassword: "",
			wantVersion:  upterm.HostSSHClientVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := make(chan handshake, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var h handshake
				h.username, h.password, h.hasAuth = r.BasicAuth()
				h.clientVersion = r.Header.Get(upterm.HeaderUptermClientVersion)
				seen <- h
				http.Error(w, "not a relay", http.StatusBadRequest)
			}))
			t.Cleanup(srv.Close)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			server := &url.URL{Scheme: "ws", Host: srv.Listener.Addr().String()}
			conn, _, err := relaydial.Dial(ctx, server, tt.user, tt.guest, nil)
			if conn != nil {
				_ = conn.Close()
			}
			require.Error(t, err, "the server refused the upgrade")

			select {
			case h := <-seen:
				require.True(t, h.hasAuth, "the upgrade carried no Basic Authorization header")
				assert.Equal(t, tt.wantUsername, h.username)
				assert.Equal(t, tt.wantPassword, h.password)
				assert.Equal(t, tt.wantVersion, h.clientVersion)
			case <-time.After(10 * time.Second):
				t.Fatal("the server never saw the upgrade request")
			}
		})
	}
}

// TestDialReturnsHostPort checks the address a host-key check is shown: always
// host:port, with the scheme's default port when the server URL has none.
// known_hosts keys an entry by host:port, so a bare host would never match one.
// The context is cancelled, so nothing is dialed: the address is returned with
// the dial's error.
func TestDialReturnsHostPort(t *testing.T) {
	tests := []struct {
		server string
		want   string
	}{
		{"wss://relay.test", "relay.test:443"},
		{"ws://relay.test", "relay.test:80"},
		{"ssh://relay.test", "relay.test:22"},
		{"wss://[::1]", "[::1]:443"},
		{"wss://relay.test:8443", "relay.test:8443"},
		{"ws://relay.test:8080", "relay.test:8080"},
		{"ssh://relay.test:2222", "relay.test:2222"},
	}

	for _, tt := range tests {
		t.Run(tt.server, func(t *testing.T) {
			server, err := url.Parse(tt.server)
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			conn, addr, err := relaydial.Dial(ctx, server, "abc", true, nil)
			if conn != nil {
				_ = conn.Close()
			}

			require.Error(t, err, "a cancelled context dials nothing")
			assert.Equal(t, tt.want, addr)
			assert.Equal(t, tt.server, server.String(), "the caller's URL is not modified")
		})
	}
}

// TestDialSSHOpensTCP checks the ssh:// path: a plain TCP connection to the
// server, whose address is the one returned.
func TestDialSSHOpensTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, addr, err := relaydial.Dial(ctx, &url.URL{Scheme: "ssh", Host: ln.Addr().String()}, "abc", true, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	assert.Equal(t, ln.Addr().String(), addr)

	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("the server never accepted the connection")
	}
}
