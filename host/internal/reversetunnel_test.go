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
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/internal/httpproxy/httpproxytest"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/assert"
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
						HostKey:           good[0],
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

// TestReverseTunnelRegistersTheHostKeyNotTheIdentity pins what the relay is
// told to expect on a guest's upstream hop: the session host key, and never
// the identity the tunnel authenticated with. Nothing may read HostPublicKeys
// as who the host is.
func TestReverseTunnelRegistersTheHostKeyNotTheIdentity(t *testing.T) {
	identity, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)

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
		NodeAddr:        sshln.Addr().String(),
		HostSigners:     identity,
		Signers:         identity,
		NetworkProvider: network,
		MetricsProvider: provider.NewDiscardProvider(),
		SessionManager:  sessions,
		Logger:          logger,
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

	tunnel := &ReverseTunnel{
		Host:              &url.URL{Scheme: "ssh", Host: sshln.Addr().String()},
		Signers:           identity,
		HostKey:           hostKey[0],
		HostKeyCallback:   ssh.FixedHostKey(identity[0].PublicKey()),
		KeepAliveDuration: time.Hour,
	}
	response, err := tunnel.Establish(t.Context())
	require.NoError(t, err)
	t.Cleanup(tunnel.Close)

	sess, err := sessions.GetSession(response.SessionID)
	require.NoError(t, err)
	require.Len(t, sess.HostPublicKeys, 1)
	require.Equal(t, hostKey[0].PublicKey().Marshal(), sess.HostPublicKeys[0].Marshal(), "the session key is registered")
	require.NotEqual(t, identity[0].PublicKey().Marshal(), sess.HostPublicKeys[0].Marshal(), "the identity is not")
}

// TestReverseTunnelRequiresAHostKey: a tunnel with nothing to register must
// say so before it dials, since a session with no registered key could never
// admit a guest.
func TestReverseTunnelRequiresAHostKey(t *testing.T) {
	identity, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	tunnel := &ReverseTunnel{
		Host:            &url.URL{Scheme: "ssh", Host: "127.0.0.1:1"},
		Signers:         identity,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	_, err = tunnel.Establish(t.Context())
	require.ErrorContains(t, err, "HostKey is required")
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

// A direct ssh:// dial that fails on a machine which defines a proxy is the
// shape of "egress is proxy-only". upterm deliberately does not read those
// variables for ssh:// servers, the same as OpenSSH, so without this the error
// never connects the failure to the proxy the user knows they are behind.
func TestSSHDialErrorPointsAtTheProxyFlag(t *testing.T) {
	var (
		sshURL   = &url.URL{Scheme: "ssh", Host: "uptermd.upterm.dev:22"}
		wssURL   = &url.URL{Scheme: "wss", Host: "uptermd.upterm.dev:443"}
		flagged  = &url.URL{Scheme: "http", Host: "proxy.example.com:3128"}
		httpEnv  = &url.URL{Scheme: "http", Host: "proxy.example.com:3128"}
		socksEnv = &url.URL{Scheme: "socks5", Host: "proxy.example.com:1080"}
		// A real network failure. The hint is gated on one so that it cannot
		// trail a host-key warning it has nothing to do with.
		dialErr = &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection reset by peer")}
	)

	// stubEnv makes the environment lookup answer with proxy, and sets varName
	// so the message has a spelling to name. A nil proxy stands for every way
	// none applies: nothing set, NO_PROXY exempting the host, a value that does
	// not parse.
	stubEnv := func(t *testing.T, varName string, proxy *url.URL, lookupErr error) *string {
		t.Helper()
		for _, n := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
			t.Setenv(n, "")
		}
		if varName != "" {
			t.Setenv(varName, "set-for-display-only")
		}
		orig := proxyFromEnvironment
		t.Cleanup(func() { proxyFromEnvironment = orig })
		var asked string
		proxyFromEnvironment = func(req *http.Request) (*url.URL, error) {
			asked = req.URL.Host
			return proxy, lookupErr
		}
		return &asked
	}

	t.Run("an http proxy is offered for copying", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", httpEnv, nil)

		err := sshDialError(sshURL, nil, dialErr)

		// Exported, not merely assigned: a bare assignment would not reach the
		// process the user retries with.
		assert.Contains(t, err.Error(), `export UPTERM_PROXY="$HTTPS_PROXY"`)
		assert.Contains(t, err.Error(), "--proxy")
	})

	t.Run("the lowercase spelling is named when it is the one set", func(t *testing.T) {
		// Windows environment variable names are case-insensitive, so setting
		// https_proxy also sets HTTPS_PROXY and the uppercase spelling wins.
		// Naming either is correct there; this pins the Unix behaviour.
		if runtime.GOOS == "windows" {
			t.Skip("environment variable names are case-insensitive on Windows")
		}
		_ = stubEnv(t, "https_proxy", httpEnv, nil)

		err := sshDialError(sshURL, nil, dialErr)

		assert.Contains(t, err.Error(), `export UPTERM_PROXY="$https_proxy"`)
	})

	// socks5:// is a supported way to configure the environment proxy for the
	// ws and wss path, but --proxy takes only http://, so offering the copy
	// would trade this failure for a flag rejection.
	t.Run("a socks5 proxy names the other transport instead", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", socksEnv, nil)

		err := sshDialError(sshURL, nil, dialErr)

		assert.NotContains(t, err.Error(), "UPTERM_PROXY")
		assert.Contains(t, err.Error(), "--server wss://uptermd.upterm.dev")
	})

	// Every way no proxy applies arrives as a nil lookup: NO_PROXY exempting
	// this host, nothing set at all, or a value too malformed to parse. In
	// none of them is routing through a proxy the answer.
	t.Run("a proxy that does not apply gets no advice", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", nil, nil)

		err := sshDialError(sshURL, nil, dialErr)

		assert.Equal(t, "ssh dial error: "+dialErr.Error(), err.Error())
	})

	t.Run("a lookup error gets no advice", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", httpEnv, errors.New("invalid proxy address"))

		err := sshDialError(sshURL, nil, dialErr)

		assert.Equal(t, "ssh dial error: "+dialErr.Error(), err.Error())
	})

	t.Run("a proxy with no host gets no advice", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", &url.URL{Scheme: "http"}, nil)

		err := sshDialError(sshURL, nil, dialErr)

		assert.Equal(t, "ssh dial error: "+dialErr.Error(), err.Error())
	})

	t.Run("--proxy already supplied, no advice", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", httpEnv, nil)

		err := sshDialError(sshURL, flagged, dialErr)

		assert.NotContains(t, err.Error(), "UPTERM_PROXY")
	})

	t.Run("wss already reads the environment, no advice", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", httpEnv, nil)

		err := sshDialError(wssURL, nil, dialErr)

		assert.NotContains(t, err.Error(), "UPTERM_PROXY")
	})

	// Everything the dial wraps other than a network failure happened after
	// the connection succeeded, where a proxy cannot be the cause. A host-key
	// mismatch is the case that matters: the advice would trail a security
	// warning it has nothing to do with.
	t.Run("a failure that is not the network gets no advice", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", httpEnv, nil)

		err := sshDialError(sshURL, nil, errors.New("ssh: handshake failed: host key mismatch"))

		assert.NotContains(t, err.Error(), "UPTERM_PROXY")
		assert.NotContains(t, err.Error(), "wss://")
	})

	// A custom relay was chosen for a reason. Changing the transport is the
	// suggestion; changing whose deployment the session runs on is not.
	t.Run("a custom relay keeps its own host in the suggestion", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", socksEnv, nil)

		err := sshDialError(&url.URL{Scheme: "ssh", Host: "relay.corp:22"}, nil, dialErr)

		assert.Contains(t, err.Error(), "--server wss://relay.corp")
		assert.NotContains(t, err.Error(), "uptermd.upterm.dev")
	})

	// url.URL.Hostname strips the brackets, and an unbracketed IPv6 address is
	// not an authority the suggestion could be pasted back as.
	t.Run("an IPv6 relay is bracketed in the suggestion", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", socksEnv, nil)

		err := sshDialError(&url.URL{Scheme: "ssh", Host: "[2001:db8::1]:22"}, nil, dialErr)

		assert.Contains(t, err.Error(), "--server wss://[2001:db8::1]")
	})

	// NO_PROXY entries may name a port, and the lookup fills in the scheme's
	// default for anything asked without one. Probing the bare hostname would
	// therefore ask about :443 and sail past an exemption written for :22.
	t.Run("the lookup is asked about the port that failed", func(t *testing.T) {
		asked := stubEnv(t, "HTTPS_PROXY", httpEnv, nil)

		_ = sshDialError(sshURL, nil, dialErr)

		assert.Equal(t, "uptermd.upterm.dev:22", *asked)
	})

	t.Run("an auth failure is still a permission denial", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", httpEnv, nil)

		err := sshDialError(sshURL, nil, errors.New(publickeyAuthError))

		var denied *PermissionDeniedError
		require.ErrorAs(t, err, &denied)
		assert.NotContains(t, err.Error(), "UPTERM_PROXY")
	})
}
