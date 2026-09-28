package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	gliderssh "charm.land/ssh"
	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// servingTestServer is a Server actually serving on two loopback listeners,
// with its serving goroutine's result available to the test.
type servingTestServer struct {
	*Server
	sshAddr string
	wsAddr  string
	served  <-chan error
}

// newServingTestServer starts a Server and does not return until it is proven
// to be serving.
func newServingTestServer(t *testing.T, logger *slog.Logger) *servingTestServer {
	t.Helper()

	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)

	network := &MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))

	sshln := listenLoopback(t)
	wsln := listenLoopback(t)

	s := &Server{
		NodeAddr:        sshln.Addr().String(),
		HostSigners:     []ssh.Signer{signer},
		Signers:         []ssh.Signer{signer},
		NetworkProvider: network,
		MetricsProvider: provider.NewDiscardProvider(),
		SessionManager:  newEmbeddedSessionManager(logger),
		Logger:          logger,
	}

	served := make(chan error, 1)
	go func() { served <- s.ServeWithContext(context.Background(), sshln, wsln) }()
	t.Cleanup(func() { _ = s.Shutdown() })

	ts := &servingTestServer{Server: s, sshAddr: sshln.Addr().String(), wsAddr: wsln.Addr().String(), served: served}
	requireServing(t, ts.wsAddr)

	return ts
}

// requireServing proves the websocket handler is answering. Dialling the port
// would prove nothing: both listeners are bound before serving starts, and the
// kernel completes the handshake from the backlog whether or not anyone ever
// calls Accept.
func requireServing(t *testing.T, addr string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, utils.WaitForServer(ctx, addr))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/health", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "OK", string(body))
}

func requireRefused(t *testing.T, addr string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("%s still accepts connections after Shutdown returned", addr)
	}
}

// Shutdown no longer closes sshln and wsln itself -- each component closes the
// listener it serves -- so this pins the guarantee that gave up nothing: once
// Shutdown returns, nothing is still bound. Anything restarting a node in
// process, or rebinding the port, depends on it.
func TestServerShutdownReleasesListenersBeforeReturning(t *testing.T) {
	ts := newServingTestServer(t, slog.New(slog.DiscardHandler))

	require.NoError(t, ts.Shutdown())

	requireRefused(t, ts.sshAddr)
	requireRefused(t, ts.wsAddr)
}

// A Serve that fails before it reaches its accept loop never takes ownership of
// the listener it was handed, and Shutdown no longer closes listeners itself --
// so without an explicit release, an early failure leaks the descriptor and the
// port stays bound after Shutdown has reported success. uptermd itself exits on
// these errors, but embedders and the ftests harness keep running.
func TestServerReleasesListenersAfterEarlyServeFailure(t *testing.T) {
	for _, tt := range []struct {
		name  string
		apply func(t *testing.T, s *Server)
	}{
		{
			// sshProxy.Serve gives up before routing records the listener.
			name: "authorized keys file cannot be read",
			apply: func(t *testing.T, s *Server) {
				s.AuthorizedKeysFiles = []string{filepath.Join(t.TempDir(), "does-not-exist")}
			},
		},
		{
			// SSHRouting.Serve gives up before serveStock records the listener.
			name:  "handshake timeout is invalid",
			apply: func(t *testing.T, s *Server) { s.HandshakeTimeout = -1 },
		},
		{
			// ServeWithContext gives up before run.Group starts any actor at all.
			name: "the sshd socket cannot be listened on",
			apply: func(t *testing.T, s *Server) {
				p := &UnixProvider{}
				require.NoError(t, p.SetOpts(NetworkOptions{
					"session-socket-dir": t.TempDir(),
					"sshd-socket-path":   filepath.Join(t.TempDir(), "no-such-dir", "sshd.sock"),
				}))
				s.NetworkProvider = p
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.DiscardHandler)

			signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
			require.NoError(t, err)
			network := &MemoryProvider{}
			require.NoError(t, network.SetOpts(nil))

			sshln := listenLoopback(t)
			wsln := listenLoopback(t)

			s := &Server{
				NodeAddr:        sshln.Addr().String(),
				HostSigners:     []ssh.Signer{signer},
				Signers:         []ssh.Signer{signer},
				NetworkProvider: network,
				MetricsProvider: provider.NewDiscardProvider(),
				SessionManager:  newEmbeddedSessionManager(logger),
				Logger:          logger,
			}
			tt.apply(t, s)

			served := make(chan error, 1)
			go func() { served <- s.ServeWithContext(context.Background(), sshln, wsln) }()

			select {
			case err := <-served:
				require.Error(t, err, "this case is supposed to fail serving")
			case <-time.After(10 * time.Second):
				t.Fatal("ServeWithContext did not return after an early failure")
			}

			require.NoError(t, s.Shutdown())

			requireRefused(t, sshln.Addr().String())
			requireRefused(t, wsln.Addr().String())
		})
	}
}

// run.Group fires its interrupts once, at the moment the first actor returns,
// so a component still starting up is told to stop before it has anything to
// stop -- its Shutdown finds no server and does nothing. Serving anyway would
// hold a listener nobody can close and an actor run.Group waits on forever,
// which hung ServeWithContext outright when a sibling failed at startup.
// SSHRouting has always checked this; the rest had to learn.
func TestServeAfterShutdownStopsImmediately(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	network := &MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))

	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	signers := []ssh.Signer{signer}
	discard := provider.NewDiscardProvider()

	type component struct {
		name     string
		shutdown func() error
		serve    func(net.Listener) error
	}

	sd := &sshd{
		SessionManager:      newEmbeddedSessionManager(logger),
		HostSigners:         signers,
		SessionDialListener: network.Session(),
		MetricsProvider:     discard,
		Logger:              logger,
	}
	wsp := &webSocketProxy{SessionManager: newEmbeddedSessionManager(logger), Logger: logger}
	spx := &sshProxy{
		HostSigners:     signers,
		Signers:         signers,
		SessionManager:  newEmbeddedSessionManager(logger),
		MetricsProvider: discard,
		Logger:          logger,
	}
	rt := &SSHRouting{HostSigners: signers, MetricsProvider: discard, Logger: logger}

	for _, tt := range []component{
		{"sshd", sd.Shutdown, sd.Serve},
		{"webSocketProxy", wsp.Shutdown, wsp.Serve},
		{"sshProxy", spx.Shutdown, spx.Serve},
		{"SSHRouting", rt.Shutdown, rt.Serve},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = ln.Close() })
			addr := ln.Addr().String()

			require.NoError(t, tt.shutdown())

			done := make(chan error, 1)
			go func() { done <- tt.serve(ln) }()

			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Serve kept running after Shutdown; nothing is left to stop it")
			}

			requireRefused(t, addr)
		})
	}
}

// The stopped flag alone leaves sshd a narrower version of the same hang.
// ssh.Server only starts tracking a listener inside its own Serve, and it
// clears its done channel when it takes the first one -- so a Shutdown landing
// after sshd.Serve publishes the server but before that tracking finds nothing
// to close, closes a done channel the library then discards, and Accept blocks
// on a listener nobody will close. Verified against charm.land/ssh v0.4.3
// directly: Shutdown on a server with nothing tracked returns nil, and a Serve
// started afterwards never returns.
//
// sshd therefore owns the listener the way routing does. This builds the window
// state exactly -- a published server that has tracked nothing -- rather than
// trying to hit a few instructions by timing.
func TestSSHDShutdownClosesTheListenerItWasHanded(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	addr := ln.Addr().String()

	s := &sshd{
		SessionManager: newEmbeddedSessionManager(logger),
		Logger:         logger,
		// What Serve publishes just before the library would track ln.
		server: &gliderssh.Server{},
		ln:     &closeOnceListener{Listener: ln},
	}

	require.NoError(t, s.Shutdown())

	requireRefused(t, addr)
}

// The end-state check above cannot see the ordering: serving stops so quickly
// that a Shutdown which never waited still looks right. This drives the wait
// directly -- serving is held open, so a Shutdown that returns at all before it
// finishes is the bug.
func TestServerShutdownWaitsForServingToStop(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	served := make(chan struct{})
	s := &Server{
		NodeAddr:       "127.0.0.1:0",
		SessionManager: newEmbeddedSessionManager(logger),
		Logger:         logger,
		cancel:         func() {},
		served:         served,
	}

	done := make(chan error, 1)
	go func() { done <- s.Shutdown() }()

	select {
	case <-done:
		t.Fatal("Shutdown returned while serving was still running")
	case <-time.After(100 * time.Millisecond):
	}

	close(served)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(serveStopDeadline):
		t.Fatal("Shutdown did not return once serving stopped")
	}
}

// Serving that never stops must not hang the daemon: the wait is bounded, and
// what it reports says a listener may still be bound rather than claiming a
// clean shutdown.
func TestServerShutdownReportsServingThatWillNotStop(t *testing.T) {
	restore := serveStopDeadline
	serveStopDeadline = 50 * time.Millisecond
	t.Cleanup(func() { serveStopDeadline = restore })

	logger := slog.New(slog.DiscardHandler)
	s := &Server{
		NodeAddr:       "127.0.0.1:0",
		SessionManager: newEmbeddedSessionManager(logger),
		Logger:         logger,
		cancel:         func() {},
		served:         make(chan struct{}), // never closed
	}

	require.ErrorIs(t, s.Shutdown(), errShutdownIncomplete)
}

// Shutdown waits on a channel ServeWithContext creates, so a Server that never
// served has nothing to wait for. Waiting anyway would block for the whole
// deadline and then report a timeout that never happened.
func TestServerShutdownWithoutServingReturnsImmediately(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	s := &Server{
		NodeAddr:       "127.0.0.1:0",
		SessionManager: newEmbeddedSessionManager(logger),
		Logger:         logger,
	}

	done := make(chan error, 1)
	go func() { done <- s.Shutdown() }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown blocked on a Server that never served")
	}
}

// Shutdown runs twice in the normal path: once from the run.Group interrupt and
// again from a caller's defer.
func TestServerShutdownIsIdempotent(t *testing.T) {
	ts := newServingTestServer(t, slog.New(slog.DiscardHandler))

	require.NoError(t, ts.Shutdown())
	require.NoError(t, ts.Shutdown())
}

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	return ln
}

// ssh.Server closes the listener from its own bookkeeping after sshd has
// already closed it. A second close that reported ErrClosed would come back
// out of ssh.Server.Shutdown as a failed shutdown, and the run.Group interrupt
// logs that at Error -- turning the fix for one piece of shutdown noise into
// another piece of it.
func TestCloseOnceListenerReportsTheFirstResult(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()

	once := &closeOnceListener{Listener: ln}

	require.NoError(t, once.Close())
	require.NoError(t, once.Close(), "a repeated close must not report ErrClosed")
	requireRefused(t, addr)
}
