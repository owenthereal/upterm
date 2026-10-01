package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/websocket"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/ws"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/test/bufconn"
)

type testSshdDialListener struct {
	*bufconn.Listener
}

func (l *testSshdDialListener) Dial() (net.Conn, error) {
	return l.Listener.Dial()
}

func (l *testSshdDialListener) Listen() (net.Listener, error) {
	return l.Listener, nil
}

type testSessionDialListener struct {
	*bufconn.Listener
}

func (l *testSessionDialListener) Dial(id string) (net.Conn, error) {
	return l.Listener.Dial()
}

// Declared explicitly: bufconn.Listener promotes a DialContext(ctx) of its own,
// which is the wrong shape for SessionDialListener.
func (l *testSessionDialListener) DialContext(ctx context.Context, id string) (net.Conn, error) {
	return l.Listener.DialContext(ctx)
}

func (l *testSessionDialListener) Listen(id string) (net.Listener, error) {
	return l.Listener, nil
}

func Test_WebSocketProxy_Host(t *testing.T) {
	testLogger := logging.Must(logging.Console(), logging.Debug()).Logger
	cd := sidewayConnDialer{
		SSHDDialListener:    &testSshdDialListener{bufconn.Listen(1024)},
		SessionDialListener: &testSessionDialListener{bufconn.Listen(1024)},
		Logger:              testLogger,
	}
	logger := testLogger
	wsh := &wsHandler{
		ConnDialer:     cd,
		SessionManager: newEmbeddedSessionManager(logger),
		Logger:         logger,
	}
	ts := httptest.NewServer(wsh)
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Scheme = "ws"
	u.User = url.UserPassword("owen", "")

	wsc, err := ws.NewWSConn(u, false, nil)
	if err != nil {
		t.Fatal(err)
	}

	rr, rw := io.Pipe()
	rs := bufio.NewScanner(rr)
	go func(wsc net.Conn, w io.Writer) {
		_, _ = io.Copy(w, wsc)
	}(wsc, rw)

	ln, err := cd.SSHDDialListener.Listen()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}

	wr, ww := io.Pipe()
	ws := bufio.NewScanner(wr)
	go func() {
		_, _ = io.Copy(ww, conn)
	}()

	// test read
	_, _ = conn.Write([]byte("read\n")) // need CR because func scan scans by line
	if diff := cmp.Diff("read", scan(rs)); diff != "" {
		t.Fatal(diff)
	}

	// test write
	if _, err := wsc.Write([]byte("write\n")); err != nil { // need CR because func scan scans by line
		t.Fatal(err)
	}
	if diff := cmp.Diff("write", scan(ws)); diff != "" {
		t.Fatal(diff)
	}
}

// noDialer fails every dial, and counts them.
type noDialer struct{ calls atomic.Int32 }

func (d *noDialer) Dial(id *api.Identifier) (net.Conn, error) {
	return d.DialContext(context.Background(), id)
}

func (d *noDialer) DialContext(context.Context, *api.Identifier) (net.Conn, error) {
	d.calls.Add(1)
	return nil, errors.New("not dialing in this test")
}

// openGuestWS opens the WebSocket a guest of an unknown session would, with
// session as its user.
func openGuestWS(t *testing.T, h *wsHandler, session string) *websocket.Conn {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	header := http.Header{}
	header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(session+":")))
	header.Add(upterm.HeaderUptermClientVersion, upterm.ClientSSHClientVersion)
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), header)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// With no SSH proxy on this node to refuse the guest, a session the handler
// can't resolve ends the WebSocket with the reason, and nothing is dialed.
func Test_WebSocketProxy_UnresolvedGuestWithoutSSHProxy(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cd := &noDialer{}
	c := openGuestWS(t, &wsHandler{
		ConnDialer:     cd,
		SessionManager: newSessionManagerWithStore(newMemorySessionStore(logger), routing.NewEncodeDecoder(routing.ModeConsul)),
		Logger:         logger,
	}, "nosuchsession")

	_, _, err := c.ReadMessage()
	var closed *websocket.CloseError
	require.ErrorAs(t, err, &closed)
	require.Equal(t, websocket.CloseInternalServerErr, closed.Code)
	require.Contains(t, closed.Text, "error resolving SSH user nosuchsession")
	require.Zero(t, cd.calls.Load())
}

// standInSSHProxy listens as this node's SSH proxy would, and greets the first
// connection it accepts.
func standInSSHProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("from the SSH proxy"))
	}()
	return ln.Addr().String()
}

// Fronting the SSH proxy, the handler passes on a guest whose session it can't
// resolve, so the SSH proxy can refuse it with the reason.
func Test_WebSocketProxy_UnresolvedGuestGoesToSSHProxy(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	c := openGuestWS(t, &wsHandler{
		ConnDialer:     sshProxyDialer{sshProxyAddr: standInSSHProxy(t), Logger: logger},
		SessionManager: newSessionManagerWithStore(newMemorySessionStore(logger), routing.NewEncodeDecoder(routing.ModeConsul)),
		Logger:         logger,
	}, "nosuchsession")

	_, msg, err := c.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, "from the SSH proxy", string(msg))
}

// In Consul mode a guest's node comes from a cache that can trail its host's
// reconnect to another node. Fronting the SSH proxy, the handler passes on a
// guest whose node won't take the dial, so the SSH proxy can refresh the route.
func Test_WebSocketProxy_UnreachableNodeGoesToSSHProxy(t *testing.T) {
	gone, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	unreachable := gone.Addr().String()
	require.NoError(t, gone.Close())

	logger := slog.New(slog.DiscardHandler)
	sm := newSessionManagerWithStore(newMemorySessionStore(logger), routing.NewEncodeDecoder(routing.ModeConsul))
	user, err := sm.CreateSession(NewSession("session", unreachable, "host", nil, nil))
	require.NoError(t, err)
	c := openGuestWS(t, &wsHandler{
		ConnDialer:     sshProxyDialer{sshProxyAddr: standInSSHProxy(t), Logger: logger},
		SessionManager: sm,
		Logger:         logger,
	}, user)

	_, msg, err := c.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, "from the SSH proxy", string(msg))
}

func scan(s *bufio.Scanner) string {
	for s.Scan() {
		return s.Text()
	}

	return s.Err().Error()
}
