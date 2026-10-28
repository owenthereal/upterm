package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	gliderssh "charm.land/ssh"
	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/owenthereal/upterm/ws"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// servingTestServer is a Server actually serving on two loopback listeners,
// with its serving goroutine's result available to the test.
type servingTestServer struct {
	*Server
	sshAddr string
	wsAddr  string
	served  <-chan error
	sshln   *closeObservedListener
	wsln    *closeObservedListener
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
	done := make(chan struct{})
	t.Cleanup(func() {
		// Emergency closes bypass the observation and run after the assertions.
		_ = sshln.Listener.Close()
		_ = wsln.Listener.Close()
		_ = s.Shutdown()
		requireFixtureDone(t, done)
	})
	go func() {
		served <- s.ServeWithContext(context.Background(), sshln, wsln)
		close(done)
	}()

	ts := &servingTestServer{Server: s, sshAddr: sshln.Addr().String(), wsAddr: wsln.Addr().String(), served: served, sshln: sshln, wsln: wsln}
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

// A capable host's silence is judged by the proxy's connection from it only if
// the proxy and the sshd were handed the same hostActivity, and each is built
// alone everywhere else, where a nil one is valid and the sshd falls back to the
// node connection without a word: the original defect, with every other test
// green. So this goes through a real Server, which is the only place that wires
// the two together.
//
// The registry is built and handed over inside ServeWithContext, so the test
// can't hold it. It reads what the sshd made of it instead: pingOnce logs which
// connection it judged the host by, and "host-facing" is the sshd finding the
// entry the proxy recorded under the host's SSH session ID. A proxy that
// recorded nowhere, or an sshd that looked nowhere, would log "node".
func TestServerSharesHostActivityBetweenProxyAndSSHD(t *testing.T) {
	logs := &syncBuffer{}
	ts := newServingTestServer(t,
		slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)

	client, err := ssh.Dial("tcp", ts.sshAddr, &ssh.ClientConfig{
		User:            "session",
		ClientVersion:   upterm.HostSSHClientVersion,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// A proof is bound to the host's own SSH session ID, which is the one the
	// proxy records its connection under.
	host := newProven(t)
	ok, body := host.register(t, client, string(client.SessionID()), 1)
	require.True(t, ok, string(body))

	require.Eventually(t, func() bool { return strings.Contains(logs.String(), `"connection":"host-facing"`) },
		5*time.Second, time.Millisecond,
		"the sshd did not find the proxy's connection from the host, so it would judge the host by the proxy's own traffic")
	require.NotContains(t, logs.String(), `"connection":"node"`)
}

// closeObservedListener records successful completion of the original listener's
// Close. Every call still delegates and returns its own underlying result.
// Emergency fixture cleanup closes Listener directly, never this observation.
type closeObservedListener struct {
	net.Listener
	mu        sync.Mutex
	calls     int
	completed int
	errors    []error
	success   chan struct{}
}

func observeListener(ln net.Listener) *closeObservedListener {
	return &closeObservedListener{Listener: ln, success: make(chan struct{})}
}

func (l *closeObservedListener) Close() error {
	l.mu.Lock()
	l.calls++
	l.mu.Unlock()

	err := l.Listener.Close()

	l.mu.Lock()
	l.completed++
	l.errors = append(l.errors, err)
	if err == nil {
		select {
		case <-l.success:
		default:
			close(l.success)
		}
	}
	l.mu.Unlock()
	return err
}

func (l *closeObservedListener) closedSuccessfully() bool {
	select {
	case <-l.success:
		return true
	default:
		return false
	}
}

func (l *closeObservedListener) closeCalls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

func requireListenerClosed(t *testing.T, ln *closeObservedListener) {
	t.Helper()
	if ln.closedSuccessfully() {
		return
	}
	ln.mu.Lock()
	defer ln.mu.Unlock()
	t.Fatalf("original listener has no acknowledged successful Close completion: calls=%d completed=%d errors=%v", ln.calls, ln.completed, ln.errors)
}

func requireFixtureDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("fixture serving goroutine did not stop during cleanup")
	}
}

// Shutdown no longer closes sshln and wsln itself -- each component closes the
// listener it serves -- so this pins the guarantee that once Shutdown returns,
// both original listeners have completed a successful Close. Their former
// addresses may already belong to another listener.
func TestServerShutdownReleasesListenersBeforeReturning(t *testing.T) {
	ts := newServingTestServer(t, slog.New(slog.DiscardHandler))

	require.NoError(t, ts.Shutdown())

	requireListenerClosed(t, ts.sshln)
	requireListenerClosed(t, ts.wsln)
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
			done := make(chan struct{})
			t.Cleanup(func() {
				_ = sshln.Listener.Close()
				_ = wsln.Listener.Close()
				_ = s.Shutdown()
				requireFixtureDone(t, done)
			})
			go func() {
				served <- s.ServeWithContext(context.Background(), sshln, wsln)
				close(done)
			}()

			select {
			case err := <-served:
				require.Error(t, err, "this case is supposed to fail serving")
			case <-time.After(10 * time.Second):
				t.Fatal("ServeWithContext did not return after an early failure")
			}

			require.NoError(t, s.Shutdown())

			requireListenerClosed(t, sshln)
			requireListenerClosed(t, wsln)
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
			ln := listenLoopback(t)

			require.NoError(t, tt.shutdown())

			served := make(chan error, 1)
			done := make(chan struct{})
			t.Cleanup(func() {
				_ = ln.Listener.Close()
				_ = tt.shutdown()
				requireFixtureDone(t, done)
			})
			go func() {
				served <- tt.serve(ln)
				close(done)
			}()

			select {
			case err := <-served:
				require.True(t, isRequestedStop(err), "Serve after Shutdown must report the stop it was asked for, got %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("Serve kept running after Shutdown; nothing is left to stop it")
			}

			requireListenerClosed(t, ln)
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
	ln := listenLoopback(t)

	s := &sshd{
		SessionManager: newEmbeddedSessionManager(logger),
		Logger:         logger,
		// What Serve publishes just before the library would track ln.
		server: &gliderssh.Server{},
		ln:     &closeOnceListener{Listener: ln},
	}

	require.NoError(t, s.Shutdown())

	requireListenerClosed(t, ln)
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
	case err := <-done:
		t.Fatalf("Shutdown returned while serving was still running: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(served)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(defaultServeStopDeadline):
		t.Fatal("Shutdown did not return once serving stopped")
	}
}

// Serving that never stops must not hang the daemon: the wait is bounded, and
// what it reports says a listener may still be bound rather than claiming a
// clean shutdown.
//
// It runs in a synctest bubble, where time is fake, with the wait set to
// 50 ms. The bound is checked on both sides of it, and against the default:
// 50 ms - 1 ns (still waiting) < 50 ms (returned) < defaultServeStopDeadline
// (8 s), where a Shutdown that ignored the setting would return.
func TestServerShutdownReportsServingThatWillNotStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const deadline = 50 * time.Millisecond
		logger := slog.New(slog.DiscardHandler)
		served := make(chan struct{}) // never closed while the test runs
		// Stop serving once the test is over, so a Shutdown still waiting on
		// it, as one that ignored its deadline would be, can return rather
		// than outlive the test.
		t.Cleanup(sync.OnceFunc(func() { close(served) }))
		s := &Server{
			NodeAddr:          "127.0.0.1:0",
			SessionManager:    newEmbeddedSessionManager(logger),
			Logger:            logger,
			cancel:            func() {},
			served:            served,
			serveStopDeadline: deadline,
		}

		done := make(chan error, 1)
		go func() { done <- s.Shutdown() }()

		time.Sleep(deadline - time.Nanosecond)
		synctest.Wait() // every wake due before the deadline has run
		select {
		case err := <-done:
			t.Fatalf("Shutdown returned before its deadline: %v", err)
		default:
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait() // the deadline's own wake, and the session cleanup after it, have run
		select {
		case err := <-done:
			require.ErrorIs(t, err, errShutdownIncomplete)
		default:
			t.Fatal("Shutdown was still waiting for serving at its deadline")
		}
	})
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

func listenLoopback(t *testing.T) *closeObservedListener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	return observeListener(ln)
}

// ssh.Server closes the listener from its own bookkeeping after sshd has
// already closed it. A second close that reported ErrClosed would come back
// out of ssh.Server.Shutdown as a failed shutdown, and the run.Group interrupt
// logs that at Error -- turning the fix for one piece of shutdown noise into
// another piece of it.
func TestCloseOnceListenerReportsTheFirstResult(t *testing.T) {
	ln := listenLoopback(t)

	once := &closeOnceListener{Listener: ln}

	require.NoError(t, once.Close())
	require.NoError(t, once.Close(), "a repeated close must not report ErrClosed")
	requireListenerClosed(t, ln)
	require.Equal(t, 1, ln.closeCalls(), "closeOnceListener must delegate only once")
}

// A controlled underlying Close acknowledges entry, then waits for permission
// to return. Publishing success before that return must fail the held check.
type listenerCloseFunc struct {
	net.Listener
	close func() error
}

func (l listenerCloseFunc) Close() error { return l.close() }

func TestListenerCloseObservationRequiresSuccessfulCompletion(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
	}{
		{"successful Close", nil},
		{"failed Close", net.ErrClosed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				entered := make(chan struct{})
				release := make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				ln := observeListener(listenerCloseFunc{close: func() error {
					close(entered)
					<-release
					return tt.err
				}})
				require.False(t, ln.closedSuccessfully(), "an open listener is not closed")
				done := make(chan struct{})
				var closeErr error
				t.Cleanup(func() {
					unblock()
					requireFixtureDone(t, done)
				})
				go func() {
					closeErr = ln.Close()
					close(done)
				}()
				<-entered
				require.False(t, ln.closedSuccessfully(), "Close entry is not successful completion")
				unblock()
				<-done
				if tt.err != nil {
					require.ErrorIs(t, closeErr, tt.err)
					require.False(t, ln.closedSuccessfully(), "a failed Close is not successful completion")
				} else {
					require.NoError(t, closeErr)
					requireListenerClosed(t, ln)
				}
				require.Equal(t, 1, ln.closeCalls())
			})
		})
	}

	t.Run("concurrent error completes before success", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			var mu sync.Mutex
			calls := 0
			ln := observeListener(listenerCloseFunc{close: func() error {
				mu.Lock()
				calls++
				call := calls
				mu.Unlock()
				if call == 1 {
					close(entered)
					<-release
					return nil
				}
				return net.ErrClosed
			}})
			firstDone := make(chan struct{})
			secondDone := make(chan struct{})
			startSecond := make(chan struct{})
			unblockSecond := sync.OnceFunc(func() { close(startSecond) })
			var firstErr, secondErr error
			t.Cleanup(func() {
				unblock()
				unblockSecond()
				requireFixtureDone(t, firstDone)
				requireFixtureDone(t, secondDone)
			})
			go func() {
				firstErr = ln.Close()
				close(firstDone)
			}()
			go func() {
				<-startSecond
				secondErr = ln.Close()
				close(secondDone)
			}()
			<-entered
			unblockSecond()
			synctest.Wait() // the second Close has returned while the first is held
			select {
			case <-secondDone:
				require.ErrorIs(t, secondErr, net.ErrClosed)
			default:
				t.Fatal("concurrent Close did not delegate while the first call was held")
			}
			require.False(t, ln.closedSuccessfully(), "the completed error must not acknowledge success")
			unblock()
			<-firstDone
			require.NoError(t, firstErr)
			requireListenerClosed(t, ln)
			require.Equal(t, 2, ln.closeCalls(), "each concurrent Close must delegate")
		})
	})
}

// listenersTestServer is a Server serving a Listeners through ServeListeners,
// in embedded mode on a memory network, with what it logged.
type listenersTestServer struct {
	*Server
	network *MemoryProvider
	logs    *syncBuffer
	served  <-chan error
}

// serveListeners starts a Server on ls, with options applied, and returns
// without waiting for it to serve. Its NodeAddr is the internal listener's
// address, or the SSH or the WebSocket listener's without one, as Start
// defaults it.
func serveListeners(t *testing.T, ls Listeners, options ...func(*Server)) *listenersTestServer {
	t.Helper()

	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	network := &MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	nodeAddr := "n1:22"
	for _, ln := range []net.Listener{ls.Internal, ls.SSH, ls.WS} {
		if ln != nil {
			nodeAddr = ln.Addr().String()
			break
		}
	}
	s := &Server{
		NodeAddr:        nodeAddr,
		HostSigners:     []ssh.Signer{signer},
		Signers:         []ssh.Signer{signer},
		NetworkProvider: network,
		MetricsProvider: provider.NewDiscardProvider(),
		SessionManager:  newEmbeddedSessionManager(logger),
		Logger:          logger,
	}
	for _, option := range options {
		option(s)
	}

	served := make(chan error, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		// Emergency closes bypass the observation and run after the assertions.
		for _, ln := range []net.Listener{ls.SSH, ls.WS, ls.Internal} {
			if observed, ok := ln.(*closeObservedListener); ok {
				_ = observed.Listener.Close()
			}
		}
		_ = s.Shutdown()
		requireFixtureDone(t, done)
	})
	go func() {
		served <- s.ServeListeners(context.Background(), ls)
		close(done)
	}()
	return &listenersTestServer{Server: s, network: network, logs: logs, served: served}
}

// result is what ServeListeners returned.
func (ts *listenersTestServer) result(t *testing.T) error {
	t.Helper()
	select {
	case err := <-ts.served:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("ServeListeners did not return")
		return nil
	}
}

// bridgeAddr is where the Server listens for its WebSocket bridge, as it
// logged it.
func (ts *listenersTestServer) bridgeAddr(t *testing.T) string {
	t.Helper()
	var addr string
	require.Eventually(t, func() bool {
		for _, line := range strings.Split(ts.logs.String(), "\n") {
			var record map[string]any
			if json.Unmarshal([]byte(line), &record) != nil {
				continue
			}
			if a, ok := record["bridge_addr"].(string); ok {
				addr = a
				return true
			}
		}
		return false
	}, 5*time.Second, time.Millisecond, "the bridge listener's address was never logged")
	return addr
}

// requireSSHVersion proves an SSH server answers on conn, which it closes: the
// server sends its version first.
func requireSSHVersion(t *testing.T, conn net.Conn) {
	t.Helper()
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	line, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(line, "SSH-2.0-"), "not an SSH server: %q", line)
}

// requireSSHListening proves an SSH server is accepting at addr.
func requireSSHListening(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	requireSSHVersion(t, conn)
}

// requireSSHDServing proves the node's own sshd is accepting on network. It
// listens before serving starts, and a memory dial fails until it does.
func requireSSHDServing(t *testing.T, network *MemoryProvider) {
	t.Helper()
	var conn net.Conn
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := network.SSHD().DialContext(ctx)
		conn = c
		return err == nil
	}, 5*time.Second, time.Millisecond, "the sshd never listened")
	requireSSHVersion(t, conn)
}

// Without an internal listener, ServeListeners is ServeWithContext as it was:
// every combination of the SSH and WebSocket listeners, neither included,
// serves what it was handed alongside the sshd, and releases it on Shutdown.
func TestServeListenersNilCombinations(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ssh, ws bool
	}{
		{"SSH alone", true, false},
		{"SSH and WebSocket", true, true},
		{"WebSocket alone", false, true},
		{"neither", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				ls       Listeners
				observed []*closeObservedListener
			)
			if tc.ssh {
				ln := listenLoopback(t)
				ls.SSH, observed = ln, append(observed, ln)
			}
			if tc.ws {
				ln := listenLoopback(t)
				ls.WS, observed = ln, append(observed, ln)
			}
			ts := serveListeners(t, ls)

			requireSSHDServing(t, ts.network)
			if tc.ssh {
				requireSSHListening(t, ls.SSH.Addr().String())
			}
			if tc.ws {
				requireServing(t, ls.WS.Addr().String())
			}

			require.NoError(t, ts.Shutdown())
			require.NoError(t, ts.result(t), "a requested stop is not a failure")
			for _, ln := range observed {
				requireListenerClosed(t, ln)
			}
			require.NotContains(t, ts.logs.String(), "bridge_addr", "a bridge was opened without an internal listener")
		})
	}
}

// An internal listener takes node hops and bridged guests off the SSH
// listener, so without one it is refused before anything is served. What was
// handed over is released, as a failed start releases it.
func TestServeListenersInternalNeedsSSH(t *testing.T) {
	for _, tc := range []struct {
		name string
		ws   bool
	}{
		{"internal alone", false},
		{"internal and WebSocket", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			internal := listenLoopback(t)
			ls := Listeners{Internal: internal}
			observed := []*closeObservedListener{internal}
			if tc.ws {
				wsln := listenLoopback(t)
				ls.WS, observed = wsln, append(observed, wsln)
			}
			ts := serveListeners(t, ls)

			require.EqualError(t, ts.result(t), "an internal listener needs the SSH listener")
			_, err := ts.network.SSHD().Dial()
			require.Error(t, err, "the sshd was served")
			for _, ln := range observed {
				requireListenerClosed(t, ln)
			}
		})
	}
}

// NodeAddr is where neighbours hop to this node, and with an internal listener
// it defaults to that listener's bound address. A wildcard's is no address
// another machine can dial, so it needs node-addr set.
func TestInternalAddrWildcardNeedsNodeAddr(t *testing.T) {
	for _, addr := range []string{"[::]:2223", "0.0.0.0:2223", ":2223"} {
		t.Run(addr, func(t *testing.T) {
			opt := Opt{SSHAddr: "127.0.0.1:2222", InternalAddr: addr}
			require.EqualError(t, opt.Validate(), "internal-addr is a wildcard; set node-addr to the address neighbours dial")
			opt.NodeAddr = "n1.internal:2223"
			require.NoError(t, opt.Validate())
		})
	}
	// A literal unicast IP or a name.
	for _, addr := range []string{"10.0.0.1:2223", "[fd00::1]:2223", "n1.internal:2223"} {
		t.Run(addr, func(t *testing.T) {
			require.NoError(t, (&Opt{SSHAddr: "127.0.0.1:2222", InternalAddr: addr}).Validate())
		})
	}
}

// Start opens the internal listener and, unless node-addr says otherwise,
// names this node by its bound address: the one the sshd tells a host its
// session is on, and the store tells neighbours.
func TestInternalAddrDefaultsNodeAddr(t *testing.T) {
	for _, tc := range []struct {
		name     string
		nodeAddr string
	}{
		{"by default", ""},
		{"an explicit node-addr", "n1.internal:2223"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PRIVATE_KEY", "")
			keyPath := filepath.Join(t.TempDir(), "host_key")
			require.NoError(t, os.WriteFile(keyPath, []byte(TestPrivateKeyContent), 0600))
			signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
			require.NoError(t, err)

			logs := make(proxyProtocolTestLogs, 128)
			logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- Start(ctx, Opt{
					SSHAddr:          "127.0.0.1:0",
					InternalAddr:     "127.0.0.1:0",
					NodeAddr:         tc.nodeAddr,
					HandshakeTimeout: 4 * time.Second,
					PrivateKeys:      []string{keyPath},
					Network:          "mem",
				}, logger)
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					require.NoError(t, err, "a server told to stop reports a clean stop")
				case <-time.After(10 * time.Second):
					t.Error("server did not stop")
				}
			})
			var started map[string]any
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			for started == nil {
				select {
				case record := <-logs:
					if record["msg"] == "starting server" {
						started = record
					}
				case <-timer.C:
					t.Fatal(`server did not log "starting server"`)
				}
			}

			internal, ok := started["internal_addr"].(string)
			require.True(t, ok, "the internal listener's address was not logged: %v", started)
			host, port, err := net.SplitHostPort(internal)
			require.NoError(t, err)
			require.Equal(t, "127.0.0.1", host)
			require.NotEqual(t, "0", port, "the address logged is not the bound one")
			want := tc.nodeAddr
			if want == "" {
				want = internal
			}
			require.Equal(t, want, started["node_addr"])

			client, err := ssh.Dial("tcp", started["ssh_addr"].(string), &ssh.ClientConfig{
				User:            "node-addr-test",
				ClientVersion:   upterm.HostSSHClientVersion,
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         5 * time.Second,
			})
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			request, err := proto.Marshal(&CreateSessionRequest{
				HostUser:       "node-addr-test",
				HostPublicKeys: [][]byte{[]byte(TestPublicKeyContent)},
			})
			require.NoError(t, err)
			ok, body, err := client.SendRequest(upterm.ServerCreateSessionRequestType, true, request)
			require.NoError(t, err)
			require.True(t, ok, "sshd must create the session: %s", body)
			var response CreateSessionResponse
			require.NoError(t, proto.Unmarshal(body, &response))
			require.Equal(t, want, response.NodeAddr, "the host was told another node")
		})
	}
}

// The bridge listener is the one ServeListeners opens itself, so it is the one
// ServeListeners must see released whichever way it returns: on a requested
// stop, and on a start that fails, wherever it fails.
func TestServeListenersClosesBridgeOnReturn(t *testing.T) {
	connectionRefused := syscall.ECONNREFUSED
	if runtime.GOOS == "windows" {
		connectionRefused = syscall.Errno(10061) // WSAECONNREFUSED
	}
	for _, tc := range []struct {
		name  string
		apply func(t *testing.T, s *Server)
	}{
		{name: "a requested stop"},
		{
			// ServeListeners gives up before run.Group starts any actor.
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
		{
			// Each SSH proxy, the bridge's included, gives up in its Serve.
			name: "the authorized keys file cannot be read",
			apply: func(t *testing.T, s *Server) {
				s.AuthorizedKeysFiles = []string{filepath.Join(t.TempDir(), "does-not-exist")}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sshln, wsln, internal := listenLoopback(t), listenLoopback(t), listenLoopback(t)
			var options []func(*Server)
			if tc.apply != nil {
				options = append(options, func(s *Server) { tc.apply(t, s) })
			}
			ts := serveListeners(t, Listeners{SSH: sshln, WS: wsln, Internal: internal}, options...)

			var bridge string
			if tc.apply == nil {
				bridge = ts.bridgeAddr(t)
				requireSSHListening(t, bridge)
				require.NoError(t, ts.Shutdown())
				require.NoError(t, ts.result(t))
			} else {
				require.Error(t, ts.result(t), "this case is supposed to fail serving")
				bridge = ts.bridgeAddr(t)
			}

			_, err := net.DialTimeout("tcp4", bridge, time.Second)
			require.ErrorIs(t, err, connectionRefused, "the bridge listener outlived ServeListeners")
			for _, ln := range []*closeObservedListener{sshln, wsln, internal} {
				requireListenerClosed(t, ln)
			}
		})
	}
}

// Which proxy serves which listener is told by what each claims of a guest's
// entry, and by whether it takes a host. Each guest here belongs to a session
// its user places on another node, the upstream, which reads the request the
// guest arrives with. A WebSocket guest's request also names the listener it
// was bridged to.
func TestServeListenersKinds(t *testing.T) {
	type origin struct {
		ingress Ingress
		node    bool // IngressNode is this node's NodeAddr, rather than empty
	}
	unspecified := origin{Ingress_INGRESS_UNSPECIFIED, false}
	for _, tc := range []struct {
		name         string
		ws, internal bool
		ssh, bridged origin // an SSH guest's, and a WebSocket guest's
	}{
		{name: "SSH alone", ssh: unspecified},
		{name: "SSH and WebSocket", ws: true, ssh: unspecified, bridged: unspecified},
		{name: "SSH, WebSocket and internal", ws: true, internal: true,
			ssh: origin{Ingress_INGRESS_SSH, true}, bridged: origin{Ingress_INGRESS_WEBSOCKET, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
			user := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode("session", upstream)
			guest := certTestSigner(t)
			ls := Listeners{SSH: listenLoopback(t)}
			if tc.ws {
				ls.WS = listenLoopback(t)
			}
			if tc.internal {
				ls.Internal = listenLoopback(t)
			}
			ts := serveListeners(t, ls)

			guestConfig := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(guest)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second}
			arrives := func(t *testing.T, want origin) *AuthRequest {
				t.Helper()
				_, _, auth := arrived(t, peers)
				require.Equal(t, want.ingress, auth.GetIngress())
				wantNode := ""
				if want.node {
					wantNode = ts.NodeAddr
				}
				require.Equal(t, wantNode, auth.GetIngressNode())
				return auth
			}
			hostDial := func(addr string) error {
				client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "session", ClientVersion: upterm.HostSSHClientVersion,
					Auth: []ssh.AuthMethod{ssh.PublicKeys(guest)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
				if err == nil {
					_ = client.Close()
				}
				return err
			}

			sshGuest, err := ssh.Dial("tcp", ls.SSH.Addr().String(), guestConfig)
			require.NoError(t, err)
			t.Cleanup(func() { _ = sshGuest.Close() })
			require.Equal(t, ls.SSH.Addr().String(), arrives(t, tc.ssh).GetLocalAddr())
			require.NoError(t, hostDial(ls.SSH.Addr().String()), "the SSH listener refused a host")

			if tc.ws {
				u := &url.URL{Scheme: "ws", Host: ls.WS.Addr().String(),
					User: url.UserPassword("session", base64.URLEncoding.EncodeToString([]byte(upstream)))}
				wsGuest, err := ws.NewSSHClient(u, guestConfig, true, nil)
				require.NoError(t, err)
				t.Cleanup(func() { _ = wsGuest.Close() })
				bridgedTo := arrives(t, tc.bridged).GetLocalAddr()
				if tc.internal {
					// Not the SSH listener, nor the internal one: the bridge.
					require.Equal(t, ts.bridgeAddr(t), bridgedTo)
					host, _, err := net.SplitHostPort(bridgedTo)
					require.NoError(t, err)
					require.Equal(t, "127.0.0.1", host)
					require.NotEqual(t, ls.SSH.Addr().String(), bridgedTo)
					require.NotEqual(t, ls.Internal.Addr().String(), bridgedTo)
				} else {
					require.Equal(t, ls.SSH.Addr().String(), bridgedTo, "bridged over the SSH listener")
				}
			}

			if tc.internal {
				rawGuest, err := ssh.Dial("tcp", ls.Internal.Addr().String(), guestConfig)
				require.NoError(t, err)
				t.Cleanup(func() { _ = rawGuest.Close() })
				require.Equal(t, ls.Internal.Addr().String(), arrives(t, unspecified).GetLocalAddr())
				require.ErrorContains(t, hostDial(ls.Internal.Addr().String()), "unable to authenticate",
					"the internal listener took a host")
			}
		})
	}
}

// Every SSH proxy counts into one set of routing metrics, as the one SSH
// listener that took everything did. A set per proxy would register each
// metric again, which a Prometheus registry refuses by panicking.
func TestServeListenersSharesRoutingMetrics(t *testing.T) {
	mp, reg := newTestMetrics(t)
	sshln, internal := listenLoopback(t), listenLoopback(t)
	ts := serveListeners(t, Listeners{SSH: sshln, WS: listenLoopback(t), Internal: internal},
		func(s *Server) { s.MetricsProvider = mp })

	for _, addr := range []string{sshln.Addr().String(), internal.Addr().String(), ts.bridgeAddr(t)} {
		requireSSHListening(t, addr)
	}
	// Each proxy counts a connection before it sends its version.
	v, ok := gatherValue(t, reg, "test_server_routing_connections_count", nil)
	require.True(t, ok)
	require.Equal(t, 3.0, v)
}

// A bind failure must release every socket Start already opened.
func TestInternalListenerStartFailureClosesListeners(t *testing.T) {
	addressInUse := syscall.EADDRINUSE
	if runtime.GOOS == "windows" {
		addressInUse = syscall.Errno(10048) // WSAEADDRINUSE
	}
	for _, failAt := range []string{"WebSocket", "internal"} {
		t.Run(failAt, func(t *testing.T) {
			t.Setenv("PRIVATE_KEY", "")
			keyPath := filepath.Join(t.TempDir(), "host_key")
			require.NoError(t, os.WriteFile(keyPath, []byte(TestPrivateKeyContent), 0600))

			// Reserve addresses together, then release only those Start should
			// open. The retained socket forces a later bind to fail.
			sshln, wsln, internal := listenLoopback(t), listenLoopback(t), listenLoopback(t)
			opt := Opt{SSHAddr: sshln.Addr().String(), WSAddr: wsln.Addr().String(),
				InternalAddr: internal.Addr().String(), PrivateKeys: []string{keyPath}, Network: "mem"}
			require.NoError(t, sshln.Close())
			opened := []string{opt.SSHAddr}
			if failAt == "internal" {
				require.NoError(t, wsln.Close())
				opened = append(opened, opt.WSAddr)
			}

			err := Start(context.Background(), opt, slog.New(slog.DiscardHandler))
			require.ErrorIs(t, err, addressInUse)
			for _, addr := range opened {
				ln, err := net.Listen("tcp", addr)
				if err == nil {
					_ = ln.Close()
				}
				require.NoError(t, err, "Start left %s bound after failing", addr)
			}
		})
	}
}

func TestSSHNetworkValidation(t *testing.T) {
	for _, network := range []string{"", "tcp", "tcp4", "tcp6", "udp"} {
		t.Run(network, func(t *testing.T) {
			opt := Opt{SSHAddr: "127.0.0.1:2222", SSHNetwork: network}
			if network == "udp" {
				require.EqualError(t, opt.Validate(), "ssh-network must be tcp, tcp4 or tcp6")
			} else {
				require.NoError(t, opt.Validate())
			}
		})
	}
}

func TestProxyRequiredNeedsInternal(t *testing.T) {
	opt := Opt{SSHAddr: "127.0.0.1:2222", SSHProxyProtocolRequired: true}
	require.EqualError(t, opt.Validate(), "ssh-proxy-protocol-required needs internal-addr: node hops and WebSocket bridges can't send a PROXY header")
	opt.InternalAddr = "127.0.0.1:2223"
	require.NoError(t, opt.Validate())
}
