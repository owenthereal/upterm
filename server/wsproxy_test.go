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
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	// httptest.Server.Close neither closes nor waits for an upgraded
	// connection, so the test owns every end it opens: the handler and both
	// copies would otherwise stay blocked on one past the test. The cleanup
	// closes them all, then the server, after which no handler can start, and
	// only then waits for both copies and every handler that did start.
	var (
		owned                       []func()
		ts                          *httptest.Server
		clientCopied, backendCopied chan struct{}
		handlers                    sync.WaitGroup
	)
	own := func(name string, c io.Closer) {
		owned = append(owned, func() {
			if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("close %s: %v", name, err)
			}
		})
	}
	t.Cleanup(func() {
		for _, closeOwned := range owned {
			closeOwned()
		}
		if ts != nil {
			ts.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		join := func(name string, done <-chan struct{}) {
			if done == nil {
				return // never started
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Errorf("%s did not return", name)
			}
		}
		join("client copy", clientCopied)
		join("backend copy", backendCopied)
		handled := make(chan struct{})
		go func() {
			handlers.Wait()
			close(handled)
		}()
		join("handler", handled)
	})

	sshdLn, sessionLn := bufconn.Listen(1024), bufconn.Listen(1024)
	own("sshd listener", sshdLn)
	own("session listener", sessionLn)
	cd := sidewayConnDialer{
		SSHDDialListener:    &testSshdDialListener{sshdLn},
		SessionDialListener: &testSessionDialListener{sessionLn},
		Logger:              testLogger,
	}
	logger := testLogger
	wsh := &wsHandler{
		ConnDialer:     cd,
		SessionManager: newEmbeddedSessionManager(logger),
		Logger:         logger,
	}
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers.Add(1)
		defer handlers.Done()
		wsh.ServeHTTP(w, r)
	}))

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
	own("client WebSocket", wsc)

	rr, rw := io.Pipe()
	own("client pipe reader", rr)
	own("client pipe writer", rw)
	rs := bufio.NewScanner(rr)
	clientCopied = make(chan struct{})
	go func(wsc net.Conn, w io.Writer) {
		defer close(clientCopied)
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
	own("accepted backend connection", conn)

	wr, ww := io.Pipe()
	own("backend pipe reader", wr)
	own("backend pipe writer", ww)
	ws := bufio.NewScanner(wr)
	backendCopied = make(chan struct{})
	go func() {
		defer close(backendCopied)
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
	return openGuestWSWithAuth(t, h, session, "")
}

// openGuestWSWithAuth is openGuestWS with user and pass as the guest's
// basic-auth credentials, which embedded mode rejoins into one SSH user.
func openGuestWSWithAuth(t *testing.T, h *wsHandler, user, pass string) *websocket.Conn {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	header := http.Header{}
	header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
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
		ConnDialer:     sshProxyDialer{sshProxyAddr: standInSSHProxy(t), nodeAddrFromStore: true, Logger: logger},
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
		ConnDialer:     sshProxyDialer{sshProxyAddr: standInSSHProxy(t), nodeAddrFromStore: true, Logger: logger},
		SessionManager: sm,
		Logger:         logger,
	}, user)

	_, msg, err := c.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, "from the SSH proxy", string(msg))
}

// A node that refuses a dial the hand-off then recovers is a route that needed
// refreshing, not a failure, so it is a warning. An error is what gets
// reported, and a guest that never gets in is still reported, as "error
// dialing".
func Test_WebSocketProxy_ADialTheHandOffRecoversIsAWarning(t *testing.T) {
	gone, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	unreachable := gone.Addr().String()
	require.NoError(t, gone.Close())

	discard := slog.New(slog.DiscardHandler)
	sm := newSessionManagerWithStore(newMemorySessionStore(discard), routing.NewEncodeDecoder(routing.ModeConsul))
	user, err := sm.CreateSession(NewSession("session", unreachable, "host", nil, nil))
	require.NoError(t, err)
	logs := &logRecorder{}
	c := openGuestWS(t, &wsHandler{
		ConnDialer:     sshProxyDialer{sshProxyAddr: standInSSHProxy(t), nodeAddrFromStore: true, Logger: discard},
		SessionManager: sm,
		Logger:         slog.New(logs),
	}, user)

	_, msg, err := c.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, "from the SSH proxy", string(msg))
	require.Equal(t, []string{"WARN error dialing the session's node"}, logs.atLeast(slog.LevelWarn))
}

// A guest the handler can't resolve is handed to the SSH proxy, which refuses
// it with the reason. A session that isn't stored, or a user that names none,
// is the guest's to put right, so it is a warning. A store that couldn't
// answer is the relay's own failure, and stays an error, which is what gets
// reported.
func Test_WebSocketProxy_AGuestsUnresolvedUserIsAWarning(t *testing.T) {
	discard := slog.New(slog.DiscardHandler)
	for _, tc := range []struct {
		name       string
		mode       routing.Mode
		store      SessionStore
		user, pass string
		want       string
	}{
		{"a session that isn't stored", routing.ModeConsul, newMemorySessionStore(discard), "nosuchsession", "", "WARN error resolving SSH user"},
		{"a user that names no session", routing.ModeEmbedded, newMemorySessionStore(discard), "session", "not base64!", "WARN error resolving SSH user"},
		{"a store that can't answer", routing.ModeConsul, failingStore{newMemorySessionStore(discard)}, "session", "", "ERROR error resolving SSH user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &logRecorder{}
			c := openGuestWSWithAuth(t, &wsHandler{
				ConnDialer:     sshProxyDialer{sshProxyAddr: standInSSHProxy(t), nodeAddrFromStore: tc.mode == routing.ModeConsul, Logger: discard},
				SessionManager: newSessionManagerWithStore(tc.store, routing.NewEncodeDecoder(tc.mode)),
				Logger:         slog.New(logs),
			}, tc.user, tc.pass)

			_, msg, err := c.ReadMessage()
			require.NoError(t, err)
			require.Equal(t, "from the SSH proxy", string(msg))
			require.Equal(t, []string{tc.want}, logs.atLeast(slog.LevelWarn))
		})
	}
}

// logRecorder is a slog handler that keeps the level and message of each
// record.
type logRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (r *logRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *logRecorder) Handle(_ context.Context, record slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, record)
	return nil
}

func (r *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }

func (r *logRecorder) WithGroup(string) slog.Handler { return r }

// atLeast is "LEVEL message" for each record at level or above, in order.
func (r *logRecorder) atLeast(level slog.Level) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var lines []string
	for _, record := range r.records {
		if record.Level >= level {
			lines = append(lines, record.Level.String()+" "+record.Message)
		}
	}
	return lines
}

// standInNode listens as some other address would, greeting what it accepts
// and counting it, so a test can tell which address a dial actually reached.
func standInNode(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_, _ = conn.Write([]byte("from the address in the user"))
			_ = conn.Close()
		}
	}()
	return ln.Addr().String(), &accepted
}

// In embedded mode a guest's node address is whatever its own SSH user
// carries, so it names no node the relay resolved. Fronting the SSH proxy, the
// handler sends such a guest there and lets it decode that user itself, which
// keeps one component deciding every guest's upstream.
func Test_WebSocketProxy_EmbeddedGuestGoesToSSHProxy(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	elsewhere, accepted := standInNode(t)
	sm, err := NewSessionManager(routing.ModeEmbedded)
	require.NoError(t, err)

	c := openGuestWSWithAuth(t, &wsHandler{
		ConnDialer:     sshProxyDialer{sshProxyAddr: standInSSHProxy(t), Logger: logger},
		SessionManager: sm,
		Logger:         logger,
	}, "session", base64.URLEncoding.EncodeToString([]byte(elsewhere)))

	_, msg, err := c.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, "from the SSH proxy", string(msg))
	require.Zero(t, accepted.Load(), "the address the guest's user named was dialed")
}

// With an internal listener, this node's NodeAddr is that listener, and the
// store names it for every session on this node. A guest of one still goes to
// the bridge, this node's SSH proxy for its WebSocket guests: on the internal
// listener it would arrive raw and claim no entry.
func Test_WebSocketProxy_ThisNodesGuestGoesToTheBridge(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	internal, dialedInternal := standInNode(t)
	sm := newSessionManagerWithStore(newMemorySessionStore(logger), routing.NewEncodeDecoder(routing.ModeConsul))
	user, err := sm.CreateSession(NewSession("session", internal, "host", nil, nil))
	require.NoError(t, err)
	c := openGuestWS(t, &wsHandler{
		ConnDialer:     sshProxyDialer{sshProxyAddr: standInSSHProxy(t), ownNodeAddr: internal, nodeAddrFromStore: true, Logger: logger},
		SessionManager: sm,
		Logger:         logger,
	}, user)

	_, msg, err := c.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, "from the SSH proxy", string(msg))
	require.Zero(t, dialedInternal.Load(), "this node's internal listener was dialed")
}

// Only another node's address is dialed directly: the neighbour's SSH proxy
// takes the guest raw, as it always has.
func Test_WebSocketProxy_ANeighboursGuestIsDialedDirectly(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	neighbour, dialedNeighbour := standInNode(t)
	internal, dialedInternal := standInNode(t)
	sm := newSessionManagerWithStore(newMemorySessionStore(logger), routing.NewEncodeDecoder(routing.ModeConsul))
	user, err := sm.CreateSession(NewSession("session", neighbour, "host", nil, nil))
	require.NoError(t, err)
	c := openGuestWS(t, &wsHandler{
		ConnDialer:     sshProxyDialer{sshProxyAddr: standInSSHProxy(t), ownNodeAddr: internal, nodeAddrFromStore: true, Logger: logger},
		SessionManager: sm,
		Logger:         logger,
	}, user)

	_, _, err = c.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, int32(1), dialedNeighbour.Load(), "the neighbour was not dialed")
	require.Zero(t, dialedInternal.Load(), "this node's internal listener was dialed")
}

// The page's ssh line names the relay's SSH address: the Host header's own
// port when it has one, and 443 when it doesn't. The wss URLs take the header
// as it is.
func Test_GettingStarted_NamesTheSSHAddress(t *testing.T) {
	for _, tt := range []struct {
		host string
		ssh  string
	}{
		{"uptermd.upterm.dev", "uptermd.upterm.dev:443"},
		{"127.0.0.1:28251", "127.0.0.1:28251"},
		{"[::1]:8080", "[::1]:8080"},
		{"[::1]", "[::1]:443"},
	} {
		t.Run(tt.host, func(t *testing.T) {
			h := webHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("the page fell through to the WebSocket handler")
			}))
			req := httptest.NewRequest(http.MethodGet, "/getting-started", nil)
			req.Host = tt.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			lines := strings.Split(strings.TrimSuffix(rec.Body.String(), "\n"), "\n")
			require.Len(t, lines, 4)
			require.Equal(t, `2. On your machine, host a session with "upterm host --server wss://`+tt.host+` -- YOUR_COMMAND". More details in https://github.com/owenthereal/upterm#quick-start.`, lines[1])
			require.Equal(t, `3. Your pair(s) join the session with "upterm join wss://TOKEN@`+tt.host+`", which rejoins on its own if the connection drops.`, lines[2])
			require.Equal(t, `4. Or with ssh: "ssh -o ProxyCommand='upterm proxy wss://TOKEN@`+tt.host+`' TOKEN@`+tt.ssh+`".`, lines[3])
		})
	}
}

func scan(s *bufio.Scanner) string {
	for s.Scan() {
		return s.Text()
	}

	return s.Err().Error()
}
