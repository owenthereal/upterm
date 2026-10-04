//go:build !windows

package host

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/internal/testhelpers/fakerelay"
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

// withAuthorizedKeysFiles admits as hosts only the identities files name. A
// relay that gates its hosts doesn't let the session key alone in on a
// redial, so a redial signs with the identities the host started with.
func withAuthorizedKeysFiles(files ...string) relayOption {
	return func(s *server.Server) { s.AuthorizedKeysFiles = files }
}

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
	h      *Host
	fwd    *testhelpers.Forwarder
	relay  *reconnectRelay
	scheme string
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

// withRelay sends the host to relay, in place of the fixture's own.
func withRelay(relay *reconnectRelay) reconnectOption {
	return func(f *reconnectHost) {
		f.relay = relay
		f.fwd.Redirect(relay.addr(f.scheme))
	}
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
		scheme:    scheme,
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
	deadline := time.Now().Add(within)
	for {
		got := f.h.Status()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the host never reported %s within %s; it reports %q", want, within, got)
		}
		time.Sleep(10 * time.Millisecond)
	}
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

// stop asks the session to stop over its admin socket, naming this run.
func (f *reconnectHost) stop(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := f.admin(t).StopSession(ctx, &api.StopSessionRequest{LaunchId: f.record(t).LaunchID})
	require.NoError(t, err)
}

// awaitRun returns Run's error, failing the test if Run is still running
// within.
func (f *reconnectHost) awaitRun(t *testing.T, within time.Duration) error {
	t.Helper()
	select {
	case err := <-f.done:
		return err
	case <-time.After(within):
		t.Fatalf("Host.Run did not return within %s", within)
		return nil
	}
}

// tickLine is one whole line of the fixture's command's output. A line still
// arriving isn't one: "tick 1" may yet become "tick 12".
var tickLine = regexp.MustCompile(reconnectTick + ` (\d+)\r?\n`)

// ticks is the counter values in out, in the order they arrived.
func ticks(out string) []int {
	var ns []int
	for _, m := range tickLine.FindAllStringSubmatch(out, -1) {
		n, err := strconv.Atoi(m[1])
		if err == nil {
			ns = append(ns, n)
		}
	}
	return ns
}

// lastTick is the latest counter value in out, or 0 before the first.
func lastTick(out string) int {
	ns := ticks(out)
	if len(ns) == 0 {
		return 0
	}
	return ns[len(ns)-1]
}

// localClient is the host's own terminal, attached at the session's attach
// socket.
type localClient struct {
	out *lockedBuffer
	// ended is closed once the attachment has ended and out holds all it
	// received; result is how it ended.
	ended  chan struct{}
	result attach.Result
}

// requireAttached fails the test if the attachment has already ended.
func (c *localClient) requireAttached(t *testing.T) {
	t.Helper()
	select {
	case <-c.ended:
		t.Fatalf("the local client is no longer attached: %v", c.result.Reason)
	default:
	}
}

// attachLocally attaches the host's own terminal, as `upterm attach` does,
// and returns once it is receiving the command's output. It stays attached
// until the session ends or the test does.
func (f *reconnectHost) attachLocally(t *testing.T) *localClient {
	t.Helper()
	rec := f.record(t)
	require.NotEmpty(t, rec.HostKeys)
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rec.HostKeys[0]))
	require.NoError(t, err)
	c := &localClient{out: &lockedBuffer{}, ended: make(chan struct{})}
	client := &attach.Client{Socket: rec.AttachSocket, HostKeys: []ssh.PublicKey{key}, Stdout: c.out, Pty: &attach.Pty{Term: "xterm"}}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer close(c.ended)
		c.result, _ = client.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-c.ended:
		case <-time.After(5 * time.Second):
			t.Error("the local client did not detach")
		}
	})
	require.Eventually(t, func() bool { return lastTick(c.out.String()) > 0 }, 5*time.Second, 10*time.Millisecond,
		"the local client never received the command's output")
	return c
}

// reconnectGuest is a guest joined to the session with a pty.
type reconnectGuest struct {
	client *ssh.Client
	sess   *ssh.Session
	out    *lockedBuffer
	// exited receives what the guest's session ended with.
	exited chan error
	// drained is closed once out holds everything the session sent the guest.
	drained chan struct{}
}

// sees reports whether the guest has received s.
func (g *reconnectGuest) sees(s string) bool { return strings.Contains(g.out.String(), s) }

// requireJoined fails the test if the guest's session has already ended.
func (g *reconnectGuest) requireJoined(t *testing.T) {
	t.Helper()
	select {
	case err := <-g.exited:
		t.Fatalf("the guest had already left: %v", err)
	default:
	}
}

// awaitEnd returns what the guest's session ended with, once out holds
// everything the session sent before it ended.
func (g *reconnectGuest) awaitEnd(t *testing.T, within time.Duration) error {
	t.Helper()
	var err error
	select {
	case err = <-g.exited:
	case <-time.After(within):
		t.Fatalf("the guest's session did not end within %s", within)
	}
	select {
	case <-g.drained:
	case <-time.After(within):
		t.Fatalf("the guest's output did not end within %s", within)
	}
	return err
}

// joinAsGuest joins the session as a guest would, and returns once the guest
// is receiving the command's output.
func (f *reconnectHost) joinAsGuest(t *testing.T, sshUser string) *reconnectGuest {
	t.Helper()
	g := f.joinGuest(t, sshUser)
	require.Eventually(t, func() bool { return g.sees(reconnectTick) }, 5*time.Second, 10*time.Millisecond,
		"the guest never received the command's output")
	return g
}

// joinGuest joins the session as a guest would, at the relay's ssh listener
// with sshUser and a key of its own, and returns once its shell has been
// granted. The join is bounded: a guest door that no longer serves fails it
// rather than hanging it. The guest's input stays open, as a terminal's does:
// a guest whose input ends leaves.
func (f *reconnectHost) joinGuest(t *testing.T, sshUser string) *reconnectGuest {
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
	g := &reconnectGuest{client: ssh.NewClient(sshConn, chans, reqs), out: &lockedBuffer{},
		exited: make(chan error, 1), drained: make(chan struct{})}
	t.Cleanup(func() { _ = g.client.Close() })

	g.sess, err = g.client.NewSession()
	require.NoError(t, err)
	require.NoError(t, g.sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	stdin, err := g.sess.StdinPipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = stdin.Close() })
	stdout, err := g.sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, g.sess.Shell())
	go func() {
		defer close(g.drained)
		_, _ = io.Copy(g.out, stdout)
	}()
	go func() { g.exited <- g.sess.Wait() }()

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

// A relay that registers sessions under IDs of its own can't take a session
// back, so the host says so as soon as it is up, records the loss as final
// when the tunnel drops, and never redials.
func TestReconnectOnAnUnsupportedRelay(t *testing.T) {
	key, err := NewHostKey()
	require.NoError(t, err)
	fake := fakerelay.Start(t, key, fakerelay.RandomID)
	f := newReconnectHost(t, "ssh", func(f *reconnectHost) { f.fwd.Redirect(fake.Addr) })

	rec := f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)
	require.Equal(t, sessiondir.ReconnectUnsupported, rec.Reconnect)
	warning := `level=WARN msg="this relay doesn't support reconnecting; if the tunnel drops, guests can't reach this session again until it is restarted"`
	require.Equal(t, 1, strings.Count(f.logs.String(), warning), "warned once, at the start:\n%s", f.logs.String())
	require.Equal(t, 1, fake.Connections())

	f.fwd.Cut()
	rec = f.awaitStatus(t, sessiondir.StatusDisconnected, 5*time.Second)
	require.Equal(t, sessiondir.TunnelReasonReconnectUnsupported, rec.TunnelReason)
	require.False(t, rec.TunnelLostAt.IsZero())
	require.Zero(t, rec.NextAttemptAt, "there is no next attempt")
	require.Never(t, func() bool { return fake.Connections() != 1 }, time.Second, 10*time.Millisecond,
		"the host redialled a relay that can't take the session back")
	require.Equal(t, sessiondir.StatusDisconnected, f.record(t).Status)
}

// A dropped tunnel takes the guests with it and nothing else. The command
// runs on, the local terminal goes on receiving it, and a guest who joins once
// the tunnel is back sees the same command. A guest's forced command is that
// guest's, and goes with it.
func TestGuestsAtTheDrop(t *testing.T) {
	t.Run("the shared command", func(t *testing.T) {
		f := newReconnectHost(t, "ssh")
		f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)
		guest := f.joinAsGuest(t, f.created.SshUser)
		local := f.attachLocally(t)

		f.fwd.Redirect(closedAddr(t)) // hold the gap open
		guest.requireJoined(t)
		f.fwd.Cut()
		f.awaitStatus(t, sessiondir.StatusReconnecting, 5*time.Second)
		_ = guest.awaitEnd(t, 5*time.Second) // however it ends: the connection it was on is gone

		afterDrop := lastTick(local.out.String())
		require.Eventually(t, func() bool { return lastTick(local.out.String()) >= afterDrop+3 }, 5*time.Second, 10*time.Millisecond,
			"the local client stopped receiving the command when the tunnel dropped")
		require.Equal(t, sessiondir.StatusReconnecting, f.record(t).Status, "still in the gap")

		f.fwd.Redirect(f.relay.addr("ssh"))
		f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)
		atReady := lastTick(local.out.String())
		rejoined := f.joinAsGuest(t, f.created.SshUser)
		require.Eventually(t, func() bool { return lastTick(rejoined.out.String()) > atReady }, 5*time.Second, 10*time.Millisecond,
			"the guest who rejoined doesn't see the command that ran through the gap")
		local.requireAttached(t)

		seen := ticks(local.out.String())
		for i := 1; i < len(seen); i++ {
			require.Greater(t, seen[i], seen[i-1], "the command started over: %v", seen)
		}
	})

	t.Run("a forced command", func(t *testing.T) {
		pidFile := filepath.Join(t.TempDir(), "pid")
		f := newReconnectHost(t, "ssh", func(f *reconnectHost) {
			f.h.ForceCommand = []string{"sh", "-c", `echo $$ > "$1"; exec sleep 600`, "sh", pidFile}
		})
		f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)
		local := f.attachLocally(t)
		guest := f.joinGuest(t, f.created.SshUser)
		readPID := func() int {
			b, err := os.ReadFile(pidFile)
			if err != nil {
				return 0
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil {
				return 0
			}
			return pid
		}
		require.Eventually(t, func() bool { return readPID() > 0 }, 5*time.Second, 10*time.Millisecond,
			"the guest's forced command never started")
		pid := readPID()
		// A forced command that outlived its guest is not left running after
		// the test. One seen gone is not signalled: its PID may be another's.
		var gone bool
		t.Cleanup(func() {
			if pid > 0 && !gone {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		})
		require.NoError(t, syscall.Kill(pid, 0), "the guest's forced command is running")

		f.fwd.Redirect(closedAddr(t)) // hold the gap open
		guest.requireJoined(t)
		f.fwd.Cut()
		_ = guest.awaitEnd(t, 5*time.Second) // however it ends: the connection it was on is gone
		require.Eventually(t, func() bool { return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) }, 5*time.Second, 10*time.Millisecond,
			"the guest's forced command outlived the guest")
		gone = true

		afterDrop := lastTick(local.out.String())
		require.Eventually(t, func() bool { return lastTick(local.out.String()) >= afterDrop+3 }, 5*time.Second, 10*time.Millisecond,
			"the host's own command stopped when the tunnel dropped")
		require.Equal(t, sessiondir.StatusReconnecting, f.record(t).Status, "still in the gap")
	})
}

// A stopped session's guests are told how it ended, as they would be had the
// tunnel never dropped: a real exit status, not a dropped connection, and none
// of their output cut off. The tunnel they reach the session through is the
// one a redial installed, and it stays up until the guest door has drained.
func TestAStoppedSessionsGuestsStillGetTheirExitStatus(t *testing.T) {
	f := newReconnectHost(t, "ssh", func(f *reconnectHost) {
		// The fixture's counter, taking a moment to go once it is hung up,
		// as a shell hanging up its jobs does, and then going by the hangup.
		// A tunnel closed as soon as the session began ending would be gone
		// well before the guest's exit status is sent.
		f.h.Command = []string{"sh", "-c", `trap 'sleep 0.5; trap - HUP; kill -HUP $$' HUP; ` +
			`i=0; while :; do i=$((i+1)); echo "` + reconnectTick + ` $i"; sleep 0.05; done`}
	})
	f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)
	f.fwd.Redirect(closedAddr(t)) // hold the gap open
	f.fwd.Cut()
	f.awaitStatus(t, sessiondir.StatusReconnecting, 5*time.Second)
	f.fwd.Redirect(f.relay.addr("ssh"))
	f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)
	guest := f.joinAsGuest(t, f.created.SshUser)
	// The local terminal is fed by the same output, over no tunnel: the
	// guest's output, untruncated, ends where the local terminal's does.
	local := f.attachLocally(t)

	f.stop(t)
	err := guest.awaitEnd(t, 5*time.Second)
	var missing *ssh.ExitMissingError
	require.NotErrorAs(t, err, &missing, "the guest's connection was dropped before its exit status")
	var exit *ssh.ExitError
	require.ErrorAs(t, err, &exit, "the guest's session ended without an exit status: %v", err)
	// The command is hung up, so it has no exit status of its own to give.
	require.Equal(t, 1, exit.ExitStatus())

	select {
	case <-local.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the local client was not released")
	}
	require.Equal(t, attach.Exited, local.result.Reason)
	last := lastTick(local.out.String())
	require.Positive(t, last)
	require.Equal(t, last, lastTick(guest.out.String()), "the guest's output was truncated:\n%s", guest.out.String())

	require.ErrorIs(t, f.awaitRun(t, 5*time.Second), context.Canceled)
	require.Equal(t, sessiondir.ReasonStopped, f.record(t).Reason)
}

// A session stopped while its tunnel is down stops at once, however the
// redial is placed: waiting out the slow schedule, or waiting on the agent to
// sign.
func TestSessionStopWhileReconnecting(t *testing.T) {
	t.Run("in the slow wait after the relay's key changed", func(t *testing.T) {
		// A slow wait far longer than the stop is given, so a stop that
		// waited it out would be caught.
		f := newReconnectHost(t, "ssh", func(f *reconnectHost) { f.h.Reconnect.SlowWait = time.Minute })
		f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)

		otherKey, err := NewHostKey()
		require.NoError(t, err)
		f.fwd.Redirect(startRelay(t, otherKey).addr("ssh"))
		f.fwd.Cut()
		// A wait no fast one could be is the slow wait, which comes only once
		// the relay's key has been refused twice in a row.
		deadline := time.Now().Add(5 * time.Second)
		for {
			rec, err := sessiondir.ReadRecord(f.stateRoot, f.h.Name)
			readAt := time.Now()
			require.NoError(t, err)
			if rec.TunnelReason == sessiondir.TunnelReasonRelayKeyChanged && rec.NextAttemptAt.Sub(readAt) > reconnectTiming.FastCap {
				require.Equal(t, sessiondir.StatusReconnecting, rec.Status)
				break
			}
			if readAt.After(deadline) {
				t.Fatalf("the host never settled into the slow wait; the record says %s (reason %q, next attempt %s)",
					rec.Status, rec.TunnelReason, rec.NextAttemptAt)
			}
			time.Sleep(10 * time.Millisecond)
		}

		stopped := time.Now()
		f.stop(t)
		require.ErrorIs(t, f.awaitRun(t, 5*time.Second-time.Since(stopped)), context.Canceled)
		rec := f.record(t)
		require.Equal(t, sessiondir.StatusEnding, rec.Status)
		require.Equal(t, sessiondir.ReasonStopped, rec.Reason)
		require.Equal(t, sessiondir.TunnelReasonRelayKeyChanged, rec.TunnelReason, "it ended while reconnecting")
	})

	t.Run("in an attempt waiting on the agent", func(t *testing.T) {
		agentPub, agentPriv := newEd25519(t)
		ag := startTestAgent(t, agentPriv)
		t.Setenv("SSH_AUTH_SOCK", ag.socket)
		signers, closeStart, err := SignersWith(SignerOptions{})
		require.NoError(t, err)
		t.Cleanup(closeStart)
		requireAgentIdentities(t, signers, ag.socket, agentPub)

		relayKey, err := NewHostKey()
		require.NoError(t, err)
		authorized := writeTestFile(t, t.TempDir(), "authorized_keys", ssh.MarshalAuthorizedKey(agentPub))
		gated := startRelay(t, relayKey, withAuthorizedKeysFiles(authorized))
		f := newReconnectHost(t, "ssh", withRelay(gated), func(f *reconnectHost) { f.h.Signers = signers })
		f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)
		require.NotZero(t, ag.signatures.Load(), "the first connection signed through the agent")

		// From here the agent takes a connection and never answers on it.
		ag.stop()
		ag.restartSilent(t)
		accepted := ag.accepts.Load()
		f.fwd.Cut()
		// The redial reaches the agent only to sign.
		require.Eventually(t, func() bool { return ag.accepts.Load() > accepted && ag.open() == 1 }, 5*time.Second, 10*time.Millisecond,
			"the redial never asked the agent to sign")
		require.Equal(t, sessiondir.StatusReconnecting, f.record(t).Status)
		ended := ag.ended.Load()

		stopped := time.Now()
		f.stop(t)
		require.ErrorIs(t, f.awaitRun(t, 5*time.Second-time.Since(stopped)), context.Canceled)
		ag.awaitEnded(t, ended+1)
		require.Zero(t, ag.open(), "the attempt's agent connection was left open")
		rec := f.record(t)
		require.Equal(t, sessiondir.StatusEnding, rec.Status)
		require.Equal(t, sessiondir.ReasonStopped, rec.Reason)
	})
}

// A tunnel lost while the session waits on SessionCreatedCallback -- the
// operator reading the confirmation prompt -- is redialled once the session
// is under way. The record goes from starting to ready, reconnecting at most
// in between, and never says the session is disconnected.
func TestALossDuringTheConfirmationPrompt(t *testing.T) {
	var (
		statuses []string
		first    = make(chan struct{})
		polled   = make(chan struct{})
	)
	f := newReconnectHost(t, "ssh", func(f *reconnectHost) {
		f.onCreated = func() error {
			// The record is polled from before the loss to after the redial.
			go func() {
				defer close(polled)
				deadline := time.Now().Add(10 * time.Second)
				for time.Now().Before(deadline) {
					// Read first: ready seen after a later registration is
					// the redial's ready, not one written before the loss
					// was noticed.
					sess, err := f.relay.sessions.GetSession(f.created.SessionId)
					redialled := err == nil && sess.Generation >= 2
					rec, err := sessiondir.ReadRecord(f.stateRoot, f.h.Name)
					if err == nil && (len(statuses) == 0 || statuses[len(statuses)-1] != rec.Status) {
						statuses = append(statuses, rec.Status)
						if len(statuses) == 1 {
							close(first)
						}
					}
					if err == nil && redialled && rec.Status == sessiondir.StatusReady {
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
			}()
			select {
			case <-first:
			case <-time.After(5 * time.Second):
				return errors.New("the record was never read")
			}
			f.fwd.Cut()
			return nil
		}
	})

	select {
	case <-polled:
	case <-time.After(15 * time.Second):
		t.Fatal("the poll never finished")
	}
	require.NotEmpty(t, statuses)
	require.Equal(t, sessiondir.StatusStarting, statuses[0], "%v", statuses)
	require.Equal(t, sessiondir.StatusReady, statuses[len(statuses)-1], "the session never came back: %v", statuses)
	require.NotContains(t, statuses, sessiondir.StatusDisconnected)
	for _, s := range statuses[1 : len(statuses)-1] {
		require.Contains(t, []string{sessiondir.StatusReconnecting, sessiondir.StatusReady}, s, "%v", statuses)
	}
	// The ready write itself, which a poll might have missed: the status the
	// record was published with as the session became ready.
	require.NotEqual(t, sessiondir.StatusDisconnected, f.awaitReady(t))
	sess, err := f.relay.sessions.GetSession(f.created.SessionId)
	require.NoError(t, err)
	require.GreaterOrEqual(t, sess.Generation, uint64(2), "registered again, under a later generation")
}
