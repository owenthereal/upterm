package internal

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/internal/httpproxy/httpproxytest"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestReverseTunnelAuthentication(t *testing.T) {
	good, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	bad, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	allowedKey := filepath.Join(t.TempDir(), "authorized_keys")
	require.NoError(t, os.WriteFile(allowedKey, ssh.MarshalAuthorizedKey(good[0].PublicKey()), 0600))

	sshln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sshln.Close() })
	wsln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = wsln.Close() })
	network := &server.MemoryProvider{}
	require.NoError(t, network.SetOpts(nil))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sessions, err := server.NewSessionManager(routing.ModeEmbedded, server.WithSessionManagerLogger(logger))
	require.NoError(t, err)
	srv := &server.Server{
		NodeAddr:            sshln.Addr().String(),
		AuthorizedKeysFiles: []string{allowedKey},
		HostSigners:         good,
		Signers:             good,
		NetworkProvider:     network,
		MetricsProvider:     provider.NewDiscardProvider(),
		SessionManager:      sessions,
		Logger:              logger,
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.ServeWithContext(ctx, sshln, wsln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	readyCtx, readyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readyCancel()
	require.NoError(t, utils.WaitForServer(readyCtx, sshln.Addr().String()))

	authCases := []struct {
		name    string
		signers []ssh.Signer
		allowed bool
	}{
		{name: "no keys"},
		{name: "rejected key", signers: bad},
		{name: "accepted key", signers: good, allowed: true},
		{name: "rejected then accepted", signers: []ssh.Signer{bad[0], good[0]}, allowed: true},
	}

	proxy := httpproxytest.Start(t, http.StatusOK)
	sshURL := &url.URL{Scheme: "ssh", Host: sshln.Addr().String()}
	wsURL := &url.URL{Scheme: "ws", Host: wsln.Addr().String()}
	for _, endpoint := range []struct {
		name  string
		host  *url.URL
		proxy *url.URL
	}{
		{name: "ssh", host: sshURL},
		{name: "ws", host: wsURL},
		{name: "ssh via proxy", host: sshURL, proxy: proxy.URL},
		{name: "ws via proxy", host: wsURL, proxy: proxy.URL},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, tc := range authCases {
				t.Run(tc.name, func(t *testing.T) {
					tunnel := &ReverseTunnel{
						Host:              endpoint.host,
						ProxyURL:          endpoint.proxy,
						Signers:           tc.signers,
						HostKeyCallback:   ssh.FixedHostKey(good[0].PublicKey()),
						KeepAliveDuration: time.Hour,
					}
					// Counted per subtest rather than totalled at the end: a
					// total makes every nested -run filter fail, because the
					// parent still expects the tunnels of the leaves the
					// filter excluded.
					before := proxy.Tunnels()
					response, err := tunnel.Establish(t.Context())
					if tunnel.Client != nil {
						t.Cleanup(func() { _ = tunnel.Client.Close() })
					}

					// Proxied endpoints go through the proxy in every case,
					// the rejected ones included: authentication happens after
					// the tunnel is up. Direct endpoints must not touch it.
					want := before
					if endpoint.proxy != nil {
						want++
					}
					require.EqualValues(t, want, proxy.Tunnels())

					if !tc.allowed {
						require.Error(t, err)
						if len(tc.signers) == 0 {
							var denied *PermissionDeniedError
							require.ErrorAs(t, err, &denied)
						}
						return
					}
					require.NoError(t, err)
					t.Cleanup(tunnel.Close)
					require.NotEmpty(t, response.SessionID)
					require.NotNil(t, tunnel.Listener())
				})
			}
		})
	}
}

// blockingListener stands in for the SSH forwarded listener, whose Close sends
// cancel-streamlocal-forward and waits for a reply that a relay which stopped
// serving its mux loop will never send. release is what the transport going
// away stands in for here.
type blockingListener struct {
	release  chan struct{}
	closeErr error
}

func (l *blockingListener) Accept() (net.Conn, error) {
	return nil, errors.New("blockingListener: Accept is not part of this test")
}

func (l *blockingListener) Addr() net.Addr { return nil }

func (l *blockingListener) Close() error {
	<-l.release
	return l.closeErr
}

func Test_BoundedListener_CloseForcesTheTransportAfterGrace(t *testing.T) {
	t.Run("a close the relay never answers is forced once the grace expires", func(t *testing.T) {
		// Only the force releases the inner Close, so a wrapper that waits on
		// the relay blocks here rather than losing a race intermittently.
		inner := &blockingListener{release: make(chan struct{}), closeErr: errors.New("ssh: connection lost")}

		forced := make(chan struct{})
		ln := newBoundedListener(inner, 50*time.Millisecond, func() {
			close(forced)
			close(inner.release)
		})

		closed := make(chan error, 1)
		start := time.Now()
		go func() { closed <- ln.Close() }()

		select {
		case err := <-closed:
			require.EqualError(t, err, "ssh: connection lost", "Close reports what the forwarded listener returned")
		case <-time.After(10 * time.Second):
			t.Fatal("Close waited on the relay instead of the grace")
		}

		// The grace is what Close waits, not merely something it waits less
		// than forever: a wrapper that gave the relay minutes would satisfy
		// the deadline above and still hang a teardown.
		require.Less(t, time.Since(start), 2*time.Second, "Close took far longer than the grace it promises")

		select {
		case <-forced:
		default:
			t.Fatal("the grace expired without the transport being forced")
		}
	})

	t.Run("a force that does not free the listener still returns", func(t *testing.T) {
		// x/crypto releases the pending request when the transport goes, but
		// that is its business and not a promise to this package. Nothing here
		// releases the inner Close, so this is what Close does when forcing
		// achieves nothing.
		inner := &blockingListener{release: make(chan struct{})}
		t.Cleanup(func() { close(inner.release) })

		ln := newBoundedListener(inner, 50*time.Millisecond, func() {})

		closed := make(chan error, 1)
		go func() { closed <- ln.Close() }()

		select {
		case err := <-closed:
			require.ErrorContains(t, err, "after its transport was closed",
				"Close says why it gave up rather than reporting a clean close")
		case <-time.After(10 * time.Second):
			t.Fatal("Close waited on a listener that forcing the transport had not freed")
		}
	})

	t.Run("a close that answers leaves the transport alone", func(t *testing.T) {
		inner := &blockingListener{release: make(chan struct{})}
		close(inner.release)

		var forced atomic.Bool
		// A grace nothing in this test can reach: if force runs at all, it is
		// because Close forced a listener that had already returned.
		ln := newBoundedListener(inner, time.Minute, func() { forced.Store(true) })

		require.NoError(t, ln.Close())
		require.False(t, forced.Load(), "a listener that closes on its own must not cost the session its transport")
	})
}

func Test_KeepAlive_GivesUpOnAnUnansweredPing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The relay took the request and will never reply: the ping returns only
	// once the transport is torn down, which is what closing release stands in
	// for. Closed on cleanup so the abandoned goroutine ends with the test.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	var pings atomic.Int32
	dead := make(chan error, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		keepAlive(ctx, 20*time.Millisecond, func() error {
			pings.Add(1)
			<-release
			return nil
		}, func(err error) { dead <- err })
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("keepAlive went on pinging a relay that never answered")
	}

	require.Equal(t, int32(1), pings.Load(), "an unanswered ping must not be piled on by the next tick")
	select {
	case err := <-dead:
		require.Error(t, err, "the tunnel is reported dead with the reason it died of")
	default:
		t.Fatal("keepAlive gave up without saying so")
	}
	require.Empty(t, dead, "a tunnel dies once")
}

func Test_KeepAlive_StopsAfterAFailedPing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wantErr := errors.New("ssh: write: broken pipe")
	var pings atomic.Int32
	dead := make(chan error, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		keepAlive(ctx, 20*time.Millisecond, func() error {
			pings.Add(1)
			return wantErr
		}, func(err error) { dead <- err })
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("keepAlive went on pinging a connection that had already failed")
	}

	require.Equal(t, int32(1), pings.Load(), "a connection that failed a ping will fail the next one too")
	select {
	case err := <-dead:
		require.ErrorIs(t, err, wantErr, "the give-up callback gets the error that killed the tunnel")
	default:
		t.Fatal("keepAlive gave up without saying so")
	}
	require.Empty(t, dead, "a tunnel dies once")
}

// A force close cancels the keepalive before it closes the client (see
// Establish's closeClient), so a ping already in flight fails because ctx
// ended rather than because the relay went quiet. keepAlive has to tell the
// two apart: only the second is a dead relay.
func Test_KeepAlive_DoesNotReportADeadRelayWhenStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// The interval is also pingWithin's own timeout, and a ping that times out
	// is a dead relay -- which is what this test must not produce by accident.
	// A whole second between the ping announcing itself and that timeout is
	// the margin that makes the ordering below a fact rather than a race the
	// test usually wins: with a 20ms interval, a scheduler hiccup between the
	// two lines after started turned this green test red.
	const interval = time.Second

	// Sent from inside the ping, so the cancel below lands on a ping that is
	// provably in flight rather than on one that may not have begun.
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	wantErr := errors.New("ssh: EOF")

	dead := make(chan error, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		keepAlive(ctx, interval, func() error {
			started <- struct{}{}
			<-release
			return wantErr
		}, func(err error) { dead <- err })
	}()

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the ping never started")
	}

	// Cancel while the ping is still in flight, the way the force close's
	// stopKeepAlive runs before it closes the client that would fail this
	// same ping. Only then does the ping resolve, and it resolves with an
	// error -- the one closing the client would produce.
	cancel()
	close(release)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("keepAlive did not return once its context ended")
	}

	require.Empty(t, dead, "a ping that failed only because ctx ended must not be reported as a dead relay")
}
