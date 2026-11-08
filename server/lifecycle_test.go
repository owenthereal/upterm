package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/routing"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// testLifecycle is a Lifecycle whose Start and Stop the test supplies, and
// which counts its Stops.
type testLifecycle struct {
	start func(context.Context, Runtime) error
	stop  func()
	stops atomic.Int32
}

func (l *testLifecycle) Start(ctx context.Context, rt Runtime) error { return l.start(ctx, rt) }
func (l *testLifecycle) Stop() {
	l.stops.Add(1)
	if l.stop != nil {
		l.stop()
	}
}

var _ Lifecycle = (*testLifecycle)(nil)

// acceptCounter counts the connections its listener has accepted.
type acceptCounter struct {
	net.Listener
	accepted atomic.Int32
}

func (l *acceptCounter) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return conn, err
}

// lifecycleServer is a Server with lifecycle, and nothing else composed.
func lifecycleServer(t *testing.T, nodeAddr string, lifecycle Lifecycle) *Server {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	network := &MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))
	signer := certTestSigner(t)
	return &Server{NodeAddr: nodeAddr, NodeID: "node-a", BootID: fixtureBootID, Extensions: Extensions{Lifecycle: lifecycle}, NetworkProvider: network, SessionManager: newEmbeddedSessionManager(logger), Logger: logger, MetricsProvider: provider.NewDiscardProvider(), Signers: []ssh.Signer{signer}, HostSigners: []ssh.Signer{signer}}
}

// The lifecycle starts locally before anything is served, with the serving
// relay's runtime, and stops once, whether its start failed or the server's
// context ended.
func TestLifecycle(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{true: "configuration error", false: "local startup and shutdown"}[fail], func(t *testing.T) {
			ln := listenLoopback(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan struct{})
			release := make(chan struct{})
			refused := errors.New("invalid extension configuration")
			lifecycle := &testLifecycle{}
			s := lifecycleServer(t, ln.Addr().String(), lifecycle)
			lifecycle.start = func(got context.Context, rt Runtime) error {
				require.Same(t, s.runtime(), rt)
				nodeID, bootID, nodeAddr := rt.Identity()
				require.Equal(t, []string{"node-a", fixtureBootID, ln.Addr().String()}, []string{nodeID, bootID, nodeAddr})
				require.NoError(t, got.Err())
				close(started)
				if fail {
					return refused
				}
				select {
				case <-release:
				case <-got.Done():
					return got.Err()
				}
				return nil
			}
			done := make(chan error, 1)
			go func() { done <- s.ServeListeners(ctx, Listeners{SSH: ln}) }()
			awaitSignal(t, started, "the lifecycle's start")
			if !fail {
				raw, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
				require.NoError(t, err)
				require.NoError(t, raw.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
				var banner [1]byte
				_, err = raw.Read(banner[:])
				_ = raw.Close()
				var ne net.Error
				require.True(t, errors.As(err, &ne) && ne.Timeout(), "SSH served before the lifecycle started")
				close(release)
				client := dialHost(t, ln.Addr().String(), certTestSigner(t), nil)
				_ = client.Close()
				cancel()
			}
			err := awaitSignal(t, done, "ServeListeners' return")
			if fail {
				require.True(t, err == refused, "the start's error came back as %v", err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, int32(1), lifecycle.stops.Load())
			requireListenerClosed(t, ln)
		})
	}
}

func TestLifecycleStartsBeforeTheFirstAccept(t *testing.T) {
	t.Run("a fence it sets refuses the first registration", func(t *testing.T) {
		authority := &fakeAuthority{}
		sshln := &acceptCounter{Listener: listenLoopback(t)}
		acceptedAtStart := make(chan int32, 1)
		lifecycle := &testLifecycle{start: func(_ context.Context, rt Runtime) error {
			acceptedAtStart <- sshln.accepted.Load()
			rt.Fence("x").Set()
			return nil
		}}
		internal := listenLoopback(t)
		ts := serveListeners(t, Listeners{SSH: sshln, Internal: internal}, func(s *Server) {
			s.NodeID, s.BootID, s.RefuseLegacyHops = "node-a", fixtureBootID, true
			s.Extensions = Extensions{Authority: authority, Enabled: true, Protocols: []string{testProtocol}, Lifecycle: lifecycle}
		})
		signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
		require.NoError(t, err)
		host := dialHost(t, sshln.Addr().String(), signer, nil)
		ok, body := sendCreate(t, host, newProven(t).delegatedRequest(t, host, 1, delegatedSession()))
		requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_UNAVAILABLE)
		require.Zero(t, awaitSignal(t, acceptedAtStart, "the lifecycle's start"), "the lifecycle started after a connection was accepted")
		require.Zero(t, authority.calls())
		r, g := ts.runtime().Counts()
		require.Zero(t, r, "the refused registration left work behind")
		require.Zero(t, g)
	})

	t.Run("an error it returns is returned, and nothing is accepted", func(t *testing.T) {
		sshln := &acceptCounter{Listener: listenLoopback(t)}
		refused := errors.New("the extension refused to start")
		s := lifecycleServer(t, sshln.Addr().String(), &testLifecycle{start: func(context.Context, Runtime) error { return refused }})
		err := refusedToServe(t, func() error { return s.ServeListeners(context.Background(), Listeners{SSH: sshln}) }, func() { _ = s.Shutdown() })
		require.True(t, err == refused, "the start's error came back as %v", err)
		require.Zero(t, sshln.accepted.Load())
		requireListenerClosed(t, sshln.Listener.(*closeObservedListener))
	})

	t.Run("it stops while the relay is still cleaning up", func(t *testing.T) {
		store := newReleaseWitnessStore(1)
		store.SessionStore = newMemorySessionStore(slog.New(slog.DiscardHandler))
		t.Cleanup(store.releaseHolds)
		sshln := listenLoopback(t)
		var s *Server
		var joined sync.WaitGroup
		stopped := make(chan error, 1)
		quit := make(chan struct{})
		lifecycle := &testLifecycle{
			start: func(context.Context, Runtime) error {
				joined.Add(1)
				go func() { defer joined.Done(); <-quit }()
				return nil
			},
		}
		lifecycle.stop = func() {
			close(quit)
			joined.Wait()
			// What the relay's own shutdown has reported so far: nothing,
			// while its cleanup is still held.
			s.mux.Lock()
			result := s.stopResult
			s.mux.Unlock()
			stopped <- result.err()
		}
		s = lifecycleServer(t, sshln.Addr().String(), lifecycle)
		s.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- s.ServeListeners(ctx, Listeners{SSH: sshln}) }()
		requireSSHDServing(t, s.NetworkProvider.(*MemoryProvider))
		signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
		require.NoError(t, err)
		host := dialHost(t, sshln.Addr().String(), signer, nil)
		ok, body := sendCreate(t, host, newProven(t).delegatedRequest(t, host, 1, nil))
		require.True(t, ok, "%q", body)

		cancel()
		// The host's connection closes with the relay, and its registration's
		// release is held: the relay's cleanup can't finish.
		store.call(t, 1)
		require.NoError(t, awaitSignal(t, stopped, "the lifecycle's stop"), "the lifecycle stopped only once the relay's cleanup had given up")
		select {
		case err := <-done:
			t.Fatalf("ServeListeners returned while its cleanup was held: %v", err)
		default:
		}
		store.releaseHolds()
		require.NoError(t, awaitSignal(t, done, "ServeListeners' return"))
		require.Equal(t, int32(1), lifecycle.stops.Load())
	})
}

// refusedToServe requires serve, a start that is to be refused, to return
// within a bound, and returns what it returned. One that serves instead is
// stopped with stop.
func refusedToServe(t *testing.T, serve func() error, stop func()) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- serve() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		stop()
		t.Fatalf("served instead of refusing to; stopped, it returned %v", <-done)
		return nil
	}
}

// unixProvider is a unix-socket network provider under a short directory of
// its own: a socket's path must fit in sun_path.
func unixProvider(t *testing.T) *UnixProvider {
	t.Helper()
	dir, err := os.MkdirTemp("", "ud")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	p := &UnixProvider{}
	require.NoError(t, p.SetOpts(NetworkOptions{"session-socket-dir": dir, "sshd-socket-path": filepath.Join(dir, "sshd.sock")}))
	return p
}

// An enabled authority's server-level prerequisites, in the order they are
// checked: whichever are missing, the first of them is named, and nothing is
// served. A dark authority needs none of them.
func TestPrerequisitesNameWhatIsMissing(t *testing.T) {
	prerequisites := []struct {
		missing string
		remove  func(*Server, *Listeners)
	}{
		{"an enabled authority needs the in-memory network provider (--network mem)", func(s *Server, _ *Listeners) { s.NetworkProvider = unixProvider(t) }},
		{"an enabled authority needs an internal listener (--internal-addr)", func(_ *Server, ls *Listeners) { ls.Internal = nil }},
		{"an enabled authority needs --legacy-hops=false", func(s *Server, _ *Listeners) { s.RefuseLegacyHops = false }},
		{"an enabled authority needs a node ID (--node-id)", func(s *Server, _ *Listeners) { s.NodeID = "" }},
		{"an enabled authority needs a UUID boot ID", func(s *Server, _ *Listeners) { s.BootID = "boot-1" }},
	}
	build := func(t *testing.T, enabled bool, missing int) (*Server, Listeners, *closeObservedListener, *closeObservedListener) {
		sshln, internal := listenLoopback(t), listenLoopback(t)
		s := lifecycleServer(t, internal.Addr().String(), nil)
		s.RefuseLegacyHops = true
		s.Extensions = Extensions{Authority: &fakeAuthority{}, Enabled: enabled, Protocols: []string{testProtocol}}
		ls := Listeners{SSH: sshln, Internal: internal}
		for i, p := range prerequisites {
			if missing&(1<<i) != 0 {
				p.remove(s, &ls)
			}
		}
		return s, ls, sshln, internal
	}
	for missing := 1; missing < 1<<len(prerequisites); missing++ {
		first := 0
		for missing&(1<<first) == 0 {
			first++
		}
		want := prerequisites[first].missing
		t.Run(want+"/"+maskName(missing), func(t *testing.T) {
			s, ls, sshln, internal := build(t, true, missing)
			err := refusedToServe(t, func() error { return s.ServeListeners(context.Background(), ls) }, func() { _ = s.Shutdown() })
			require.EqualError(t, err, want)
			requireListenerClosed(t, sshln)
			if ls.Internal != nil {
				requireListenerClosed(t, internal)
			}
		})
	}
	t.Run("dark, with every one missing", func(t *testing.T) {
		s, ls, sshln, _ := build(t, false, 1<<len(prerequisites)-1)
		done := make(chan error, 1)
		go func() { done <- s.ServeListeners(context.Background(), ls) }()
		requireBanner(t, dialSSHListener(t, sshln.Addr().String(), ""))
		require.NoError(t, s.Shutdown())
		require.NoError(t, awaitSignal(t, done, "ServeListeners' return"))
	})
}

// maskName names the prerequisites a mask removes by their positions.
func maskName(mask int) string {
	name := ""
	for i := 0; mask != 0; i, mask = i+1, mask>>1 {
		if mask&1 != 0 {
			name += string(rune('1' + i))
		}
	}
	return name
}

// An enabled authority refuses to start a relay that accepts legacy hops.
func TestEnabledAuthorityRefusesLegacyHops(t *testing.T) {
	t.Setenv("PRIVATE_KEY", "")
	keyPath := filepath.Join(t.TempDir(), "host_key")
	require.NoError(t, os.WriteFile(keyPath, []byte(TestPrivateKeyContent), 0o600))
	opt := Opt{SSHAddr: "127.0.0.1:0", InternalAddr: "127.0.0.1:0", PrivateKeys: []string{keyPath}, Network: "mem", NodeID: "node-a", BootID: fixtureBootID,
		Extensions: Extensions{Authority: &fakeAuthority{}, Enabled: true, Protocols: []string{testProtocol}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := refusedToServe(t, func() error { return Start(ctx, opt, slog.New(slog.DiscardHandler)) }, cancel)
	require.EqualError(t, err, "an enabled authority needs --legacy-hops=false")
}
