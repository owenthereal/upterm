//go:build !windows

package host

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// reconnectTiming is the fixture's pacing. Pings at 500 ms are slow enough
// that a -race scheduling stall doesn't close a healthy tunnel, and the waits
// are short enough that a redial is over in well under a second. SlowJitter
// is set too: left at its default, a slow wait could last half a minute.
var reconnectTiming = ReconnectTiming{
	PingInterval: 500 * time.Millisecond,
	PingBound:    500 * time.Millisecond,
	FastBase:     50 * time.Millisecond,
	FastCap:      200 * time.Millisecond,
	SlowWait:     time.Second,
	SlowJitter:   100 * time.Millisecond,
}

// reconnectTick is what the fixture's command prints, with a counter, every
// 50 ms: a guest that sees it is reading the command's output.
const reconnectTick = "tick"

// reconnectRelay is an in-process relay in embedded mode, listening for ssh://
// and ws:// hosts. It presents a host certificate for 127.0.0.1 signed by its
// own key, so a redial's pinned check runs on the hostname each transport
// hands it.
type reconnectRelay struct {
	key             ssh.Signer
	sshAddr, wsAddr string
	sessions        *server.SessionManager
}

// addr is the relay's listener for scheme: ssh or ws.
func (r *reconnectRelay) addr(scheme string) string {
	if scheme == "ws" {
		return r.wsAddr
	}
	return r.sshAddr
}

// relayOption changes the relay before it serves: its AuthorizedKeysFiles,
// say, to admit as hosts only the identities they name, as uptermd's
// --authorized-keys does.
type relayOption func(*server.Server)

// startRelay starts a relay whose key is key, with opts applied, until the
// test ends.
func startRelay(t *testing.T, key ssh.Signer, opts ...relayOption) *reconnectRelay {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	certSigner := server.HostCertSigner{Hostnames: []string{"127.0.0.1"}}
	cert, err := certSigner.SignCert(key)
	require.NoError(t, err)

	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	wsLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	network := &server.MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))
	sessions, err := server.NewSessionManager(routing.ModeEmbedded, server.WithSessionManagerLogger(logger))
	require.NoError(t, err)
	srv := &server.Server{
		NodeAddr:        sshLn.Addr().String(),
		HostSigners:     []ssh.Signer{cert},
		Signers:         []ssh.Signer{key},
		NetworkProvider: network,
		MetricsProvider: provider.NewDiscardProvider(),
		SessionManager:  sessions,
		Logger:          logger,
	}
	for _, opt := range opts {
		opt(srv)
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.ServeWithContext(ctx, sshLn, wsLn) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-served:
		case <-time.After(10 * time.Second):
			t.Error("the relay did not stop")
		}
	})
	readyCtx, readyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readyCancel()
	require.NoError(t, utils.WaitForServer(readyCtx, sshLn.Addr().String()))

	return &reconnectRelay{key: key, sshAddr: sshLn.Addr().String(), wsAddr: wsLn.Addr().String(), sessions: sessions}
}

// closedAddr is a loopback address with nothing listening on it: a forwarder
// redirected there holds a gap open, since every redial through it fails.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// lockedBuffer is a bytes.Buffer safe for one writer and any number of
// readers.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// reconnectHost runs a real Host, with a session record, against an
// in-process relay that it reaches through a forwarder, so a test can cut the
// tunnel, hold the gap open, and send the redial somewhere else.
type reconnectHost struct {
	h     *Host
	fwd   *testhelpers.Forwarder
	relay *reconnectRelay
	// created is what SessionCreatedCallback was given. Set before
	// newReconnectHost returns.
	created *api.GetSessionResponse
	// root holds the record, the sockets and anything else a test writes.
	root string
	// stateRoot is where the record is, taken when the host started: a test
	// that starts a second host points the environment somewhere else.
	stateRoot string
	// onCreated, when an option sets it, runs inside SessionCreatedCallback
	// once created is set, and its error is the callback's.
	onCreated func() error
	// ready receives the status SessionReadyCallback was given.
	ready chan string
	// done receives Run's error.
	done chan error
	// logs is the host's log, printed when the test fails.
	logs *lockedBuffer
}

// reconnectOption changes the fixture before the host runs.
type reconnectOption func(*reconnectHost)

// withoutRecord makes the host an embedder's that supplies its own admin
// socket, so no name is claimed and no record is written.
func withoutRecord(f *reconnectHost) {
	f.h.AdminSocketFile = filepath.Join(f.root, "admin.sock")
}

// newReconnectHost starts a relay, a forwarder to its scheme listener, and a
// host dialling scheme://<forwarder>, and returns once the session has been
// created. opts run before the host does.
func newReconnectHost(t *testing.T, scheme string, opts ...reconnectOption) *reconnectHost {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "up-rc-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	t.Setenv("XDG_RUNTIME_DIR", root)
	t.Setenv("XDG_STATE_HOME", root)

	relayKey, err := NewHostKey()
	require.NoError(t, err)
	identity, err := NewHostKey()
	require.NoError(t, err)
	relay := startRelay(t, relayKey)

	f := &reconnectHost{
		fwd:       testhelpers.NewForwarder(t, relay.addr(scheme)),
		relay:     relay,
		root:      root,
		stateRoot: utils.UptermStateDir(),
		ready:     make(chan string, 1),
		done:      make(chan error, 1),
		logs:      &lockedBuffer{},
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("host log:\n%s", f.logs.String())
		}
	})
	created := make(chan struct{})
	f.h = &Host{
		Host:              scheme + "://" + f.fwd.Addr(),
		Name:              "reconnect",
		Command:           []string{"sh", "-c", `i=0; while :; do i=$((i+1)); echo "` + reconnectTick + ` $i"; sleep 0.05; done`},
		Signers:           []ssh.Signer{identity},
		HostKeyCallback:   ssh.InsecureIgnoreHostKey(),
		KeepAliveDuration: time.Second,
		StopGrace:         50 * time.Millisecond,
		Reconnect:         reconnectTiming,
		Logger:            slog.New(slog.NewTextHandler(f.logs, nil)),
		SessionCreatedCallback: func(_ context.Context, s *api.GetSessionResponse) error {
			f.created = s
			close(created)
			if f.onCreated != nil {
				return f.onCreated()
			}
			return nil
		},
		SessionReadyCallback: func(status string) { f.ready <- status },
	}
	for _, opt := range opts {
		opt(f)
	}

	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		f.done <- f.h.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("Host.Run did not return after its context was cancelled")
		}
	})

	select {
	case <-created:
	case err := <-f.done:
		t.Fatalf("Host.Run returned before the session was created: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the session was not created")
	}
	return f
}

// record is the session's record as it stands.
func (f *reconnectHost) record(t *testing.T) *sessiondir.Record {
	t.Helper()
	rec, err := sessiondir.ReadRecord(f.stateRoot, f.h.Name)
	require.NoError(t, err)
	return rec
}

// awaitStatus polls the record until it says want, and returns it.
func (f *reconnectHost) awaitStatus(t *testing.T, want string, within time.Duration) *sessiondir.Record {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		rec, err := sessiondir.ReadRecord(f.stateRoot, f.h.Name)
		if err == nil && rec.Status == want {
			return rec
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("the record never said %s within %s: %v", want, within, err)
			}
			t.Fatalf("the record never said %s within %s; it says %s (reason %q, error %q)",
				want, within, rec.Status, rec.TunnelReason, rec.TunnelError)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// awaitLiveStatus polls Host.Status until it says want, for a host with no
// record.
func (f *reconnectHost) awaitLiveStatus(t *testing.T, want string, within time.Duration) {
	t.Helper()
	require.Eventually(t, func() bool { return f.h.Status() == want }, within, 10*time.Millisecond,
		"the host never reported %s; it reports %q", want, f.h.Status())
}

// awaitReady returns the status SessionReadyCallback was given.
func (f *reconnectHost) awaitReady(t *testing.T) string {
	t.Helper()
	select {
	case status := <-f.ready:
		return status
	case <-time.After(5 * time.Second):
		t.Fatal("the session was never reported ready")
		return ""
	}
}

// admin is a client of the session's admin socket.
func (f *reconnectHost) admin(t *testing.T) api.AdminServiceClient {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+f.h.AdminSocketFile, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return api.NewAdminServiceClient(conn)
}

// reconnectGuest is a guest joined to the session with a pty.
type reconnectGuest struct {
	client *ssh.Client
	sess   *ssh.Session
	out    *lockedBuffer
	// exited receives what the guest's session ended with.
	exited chan error
}

// sees reports whether the guest has received s.
func (g *reconnectGuest) sees(s string) bool { return strings.Contains(g.out.String(), s) }

// joinAsGuest joins the session as a guest would, at the relay's ssh listener
// with sshUser and a key of its own, and returns once the guest is receiving
// the command's output. The join is bounded: a guest door that no longer
// serves fails it rather than hanging it.
func (f *reconnectHost) joinAsGuest(t *testing.T, sshUser string) *reconnectGuest {
	t.Helper()
	key, err := NewHostKey()
	require.NoError(t, err)
	conn, err := net.DialTimeout("tcp", f.relay.sshAddr, 3*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, f.relay.sshAddr, &ssh.ClientConfig{User: sshUser,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	require.NoError(t, err, "the guest's handshake through the relay")
	g := &reconnectGuest{client: ssh.NewClient(sshConn, chans, reqs), out: &lockedBuffer{}, exited: make(chan error, 1)}
	t.Cleanup(func() { _ = g.client.Close() })

	g.sess, err = g.client.NewSession()
	require.NoError(t, err)
	require.NoError(t, g.sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	stdout, err := g.sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, g.sess.Shell())
	go func() { _, _ = io.Copy(g.out, stdout) }()
	go func() { g.exited <- g.sess.Wait() }()

	require.Eventually(t, func() bool { return g.sees(reconnectTick) }, 5*time.Second, 10*time.Millisecond,
		"the guest never received the command's output")
	// Joined: from here the connection lives as long as the session does.
	require.NoError(t, conn.SetDeadline(time.Time{}))
	return g
}

// connectProxy is an HTTP proxy that tunnels every CONNECT to target, whatever
// authority it names, and records the authorities named.
func connectProxy(t *testing.T, target string) (proxy *url.URL, named func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var (
		mu    sync.Mutex
		names []string
		conns []net.Conn
	)
	track := func(c net.Conn) {
		mu.Lock()
		defer mu.Unlock()
		conns = append(conns, c)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			down, err := ln.Accept()
			if err != nil {
				return
			}
			track(down)
			go func() {
				br := bufio.NewReader(down)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					_ = down.Close()
					return
				}
				mu.Lock()
				names = append(names, req.Host)
				mu.Unlock()
				up, err := net.Dial("tcp", target)
				if err != nil {
					_ = down.Close()
					return
				}
				track(up)
				if _, err := io.WriteString(down, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
					_ = down.Close()
					_ = up.Close()
					return
				}
				go func() { _, _ = io.Copy(up, br); _ = up.Close(); _ = down.Close() }()
				_, _ = io.Copy(down, up)
				_ = up.Close()
				_ = down.Close()
			}()
		}
	}()
	return &url.URL{Scheme: "http", Host: ln.Addr().String()}, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), names...)
	}
}

// A dropped tunnel comes back under the same session ID, registered again
// under a later generation, and a guest reaches the session again with the
// connect string it was first given.
func TestReconnectComesBackUnderTheSameID(t *testing.T) {
	for _, scheme := range []string{"ssh", "ws"} {
		t.Run(scheme, func(t *testing.T) {
			f := newReconnectHost(t, scheme)
			id := f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second).SessionID
			require.Equal(t, sessiondir.ReconnectSupported, f.record(t).Reconnect)

			f.fwd.Redirect(closedAddr(t)) // hold the gap open
			f.fwd.Cut()
			rec := f.awaitStatus(t, sessiondir.StatusReconnecting, 5*time.Second)
			require.Equal(t, sessiondir.TunnelReasonNetwork, rec.TunnelReason)
			require.False(t, rec.TunnelLostAt.IsZero())

			f.fwd.Redirect(f.relay.addr(scheme))
			rec = f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)
			require.Equal(t, id, rec.SessionID, "the ID survives the reconnect")
			require.Zero(t, rec.TunnelReason)
			require.Equal(t, sessiondir.StatusReady, f.h.Status())
			sess, err := f.relay.sessions.GetSession(id)
			require.NoError(t, err)
			require.GreaterOrEqual(t, sess.Generation, uint64(2), "registered again, under a later generation")
			f.joinAsGuest(t, f.created.SshUser) // the original connect string
		})
	}
}

// An embedder that supplies its own admin socket has no record, and its
// session reconnects all the same: Status follows the tunnel, and the admin
// socket goes on giving the session's ID.
func TestEmbedderWithoutARecordReconnects(t *testing.T) {
	var statusAtReady string
	f := newReconnectHost(t, "ssh", withoutRecord, func(f *reconnectHost) {
		f.h.SessionReadyCallback = func(status string) {
			statusAtReady = f.h.Status()
			f.ready <- status
		}
	})
	require.Equal(t, sessiondir.StatusReady, f.awaitReady(t),
		"with no record, the callback is given the status the session's facts give")
	require.Equal(t, sessiondir.StatusReady, statusAtReady)
	_, err := sessiondir.ReadRecord(f.stateRoot, f.h.Name)
	require.True(t, os.IsNotExist(err), "nothing was claimed, so there is no record: %v", err)
	id := f.created.SessionId

	f.fwd.Redirect(closedAddr(t)) // hold the gap open
	f.fwd.Cut()
	f.awaitLiveStatus(t, sessiondir.StatusReconnecting, 5*time.Second)

	f.fwd.Redirect(f.relay.addr("ssh"))
	f.awaitLiveStatus(t, sessiondir.StatusReady, 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := f.admin(t).GetSession(ctx, &api.GetSessionRequest{})
	require.NoError(t, err)
	require.Equal(t, id, resp.SessionId)
	sess, err := f.relay.sessions.GetSession(id)
	require.NoError(t, err)
	require.GreaterOrEqual(t, sess.Generation, uint64(2), "registered again, under a later generation")
	f.joinAsGuest(t, f.created.SshUser)
}

// A ws:// URL with no port is dialled at the scheme's own, and everything that
// checks the relay's key is handed host:port, as `upterm host` gives it: the
// host key callback, and the check a redial is pinned with, which refuses a
// bare hostname. The proxy stands in for the address no test can listen on.
func TestReconnectWithAPortlessWebSocketURL(t *testing.T) {
	var (
		mu    sync.Mutex
		shown []string
	)
	var named func() []string
	f := newReconnectHost(t, "ws", func(f *reconnectHost) {
		var proxy *url.URL
		proxy, named = connectProxy(t, f.fwd.Addr())
		f.h.Host = "ws://127.0.0.1"
		f.h.ProxyURL = proxy
		f.h.HostKeyCallback = func(hostname string, _ net.Addr, _ ssh.PublicKey) error {
			mu.Lock()
			defer mu.Unlock()
			shown = append(shown, hostname)
			return nil
		}
	})
	id := f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second).SessionID
	require.Equal(t, "ws://127.0.0.1:80", f.created.Host)
	require.Equal(t, []string{"127.0.0.1:80"}, named(), "the CONNECT names the scheme's port")
	require.NotContains(t, f.logs.String(), "isn't valid for")

	f.fwd.Redirect(closedAddr(t)) // hold the gap open
	f.fwd.Cut()
	f.awaitStatus(t, sessiondir.StatusReconnecting, 5*time.Second)
	f.fwd.Redirect(f.relay.addr("ws"))
	rec := f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)
	require.Equal(t, id, rec.SessionID)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"127.0.0.1:80"}, shown,
		"the callback is asked once, about host:port; a redial is checked against the key it accepted")
}

// A relay whose certificate doesn't name the host dialled would refuse every
// redial, and the host says so once, as soon as the first connection is up,
// rather than at the first drop.
func TestRunWarnsAtStartWhenARedialWouldBeRefused(t *testing.T) {
	f := newReconnectHost(t, "ssh", func(f *reconnectHost) {
		_, port, err := net.SplitHostPort(f.fwd.Addr())
		require.NoError(t, err)
		f.h.Host = "ssh://localhost:" + port
	})
	f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)
	want := "the relay's certificate isn't valid for localhost, so a reconnect would be refused; use the relay's own hostname in --server"
	require.Equal(t, 1, strings.Count(f.logs.String(), want), f.logs.String())
}
