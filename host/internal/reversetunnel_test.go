package internal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	"github.com/owenthereal/upterm/internal/liveness"
	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/internal/testhelpers/fakerelay"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
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
		// denial is what a refused tunnel says happened. Both shapes come
		// from a real x/crypto handshake here rather than from a string this
		// test wrote, which is what makes them evidence.
		denial string
	}{
		{name: "no keys", denial: "Permission denied (publickey); no identity was offered."},
		{name: "rejected key", signers: bad, denial: "Permission denied (publickey); the 1 identity offered was refused."},
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
						Host:            endpoint.host,
						ProxyURL:        endpoint.proxy,
						Signers:         tc.signers,
						HostKey:         good[0],
						HostKeyCallback: ssh.FixedHostKey(good[0].PublicKey()),
						KeepAlive:       liveness.Timing{Interval: time.Hour, Bound: time.Hour},
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
						// Both refusals are permission denials. Only the
						// no-key one used to be recognised as such, and the
						// key-offered-and-refused one — what an allowlisting
						// relay produces — surfaced as a raw handshake error
						// (#562).
						var denied *PermissionDeniedError
						require.ErrorAs(t, err, &denied)
						require.ErrorContains(t, err, tc.denial)
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

// testRelay is an in-process relay that admits any key, listening for both
// ssh:// and ws:// hosts.
type testRelay struct {
	url      *url.URL
	wsURL    *url.URL
	identity []ssh.Signer
	sessions *server.SessionManager
}

// withHostCert makes the relay present a host certificate for 127.0.0.1 in
// place of each plain key, signed by the key it certifies, as ftests' relays
// do. Without one, the hostname form a redial checks is never exercised.
func withHostCert(s *server.Server) {
	certified := make([]ssh.Signer, 0, len(s.HostSigners))
	for _, key := range s.HostSigners {
		cs := server.HostCertSigner{Hostnames: []string{"127.0.0.1"}}
		cert, err := cs.SignCert(key)
		if err != nil {
			// An option has no t to fail; signing with a fresh key does not
			// fail short of the system's randomness doing so.
			panic(fmt.Sprintf("withHostCert: %v", err))
		}
		certified = append(certified, cert)
	}
	s.HostSigners = certified
}

// startTestRelay starts the relay, with opts applied to it before it serves.
func startTestRelay(t *testing.T, opts ...func(*server.Server)) testRelay {
	t.Helper()
	identity, err := utils.CreateSigners(nil)
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
	for _, opt := range opts {
		opt(srv)
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

	return testRelay{
		url:      &url.URL{Scheme: "ssh", Host: sshln.Addr().String()},
		wsURL:    &url.URL{Scheme: "ws", Host: wsln.Addr().String()},
		identity: identity,
		sessions: sessions,
	}
}

// tunnel is a host that authenticates with the relay's identity and registers
// hostKey as its session key.
func (r testRelay) tunnel(hostKey ssh.Signer, u *url.URL) *ReverseTunnel {
	return &ReverseTunnel{
		Host:            u,
		Signers:         r.identity,
		HostKey:         hostKey,
		HostKeyCallback: ssh.FixedHostKey(r.identity[0].PublicKey()),
		KeepAlive:       liveness.Timing{Interval: time.Hour, Bound: time.Hour},
	}
}

// TestReverseTunnelRegistersTheHostKeyNotTheIdentity pins what the relay is
// told to expect on a guest's upstream hop: the session host key, and never
// the identity the tunnel authenticated with. Nothing may read HostPublicKeys
// as who the host is.
func TestReverseTunnelRegistersTheHostKeyNotTheIdentity(t *testing.T) {
	relay := startTestRelay(t)
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)

	tunnel := relay.tunnel(hostKey[0], relay.url)
	response, err := tunnel.Establish(t.Context())
	require.NoError(t, err)
	t.Cleanup(tunnel.Close)

	sess, err := relay.sessions.GetSession(response.SessionID)
	require.NoError(t, err)
	require.Len(t, sess.HostPublicKeys, 1)
	require.Equal(t, hostKey[0].PublicKey().Marshal(), sess.HostPublicKeys[0].Marshal(), "the session key is registered")
	require.NotEqual(t, relay.identity[0].PublicKey().Marshal(), sess.HostPublicKeys[0].Marshal(), "the identity is not")
}

// Over ssh:// and ws://: the proxy mints the host↔proxy session ID into the
// certificate, and the host signs over the same value.
func TestReverseTunnelRegistersADerivedID(t *testing.T) {
	relay := startTestRelay(t)
	for _, u := range []*url.URL{relay.url, relay.wsURL} {
		t.Run(u.Scheme, func(t *testing.T) {
			hostKey, err := utils.CreateSigners(nil)
			require.NoError(t, err)
			secret, err := registration.NewSecret()
			require.NoError(t, err)
			tunnel := relay.tunnel(hostKey[0], u)
			tunnel.SessionSecret, tunnel.Generation = secret, 1
			response, err := tunnel.Establish(t.Context())
			require.NoError(t, err)
			t.Cleanup(tunnel.Close)
			require.Equal(t, registration.ID(hostKey[0].PublicKey(), secret), response.SessionID)
			require.True(t, tunnel.ReconnectSupported())
			require.True(t, tunnel.SessionKeyRedial())
			sess, err := relay.sessions.GetSession(response.SessionID)
			require.NoError(t, err)
			require.Equal(t, uint64(1), sess.Generation)
		})
	}
}

// A secret that cannot be signed over fails the establish. Sending the request
// without its proof would register the session under a random ID the host
// believes is its own.
func TestReverseTunnelWithAMalformedSecretDoesNotEstablish(t *testing.T) {
	relay := startTestRelay(t)
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	tunnel := relay.tunnel(hostKey[0], relay.url)
	secret := []byte("too short")
	tunnel.SessionSecret, tunnel.Generation = secret, 1
	t.Cleanup(tunnel.Close)
	_, err = tunnel.Establish(t.Context())
	require.ErrorContains(t, err, "error signing session proof")
	require.ErrorContains(t, err, "session secret must be")
	require.False(t, tunnel.ReconnectSupported())
	require.Nil(t, tunnel.Listener())
	// Nothing reached the relay: not the derived ID, nor a random one issued to
	// a request sent without its proof.
	_, err = relay.sessions.GetSession(registration.ID(hostKey[0].PublicKey(), secret))
	require.Error(t, err)
	sessions, err := relay.sessions.GetStore().List()
	require.NoError(t, err)
	require.Empty(t, sessions)
}

func TestReverseTunnelWithoutASecretGetsARandomID(t *testing.T) {
	relay := startTestRelay(t)
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	tunnel := relay.tunnel(hostKey[0], relay.url)
	response, err := tunnel.Establish(t.Context())
	require.NoError(t, err)
	t.Cleanup(tunnel.Close)
	require.False(t, tunnel.ReconnectSupported())
	sess, err := relay.sessions.GetSession(response.SessionID)
	require.NoError(t, err)
	require.Zero(t, sess.Generation)
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
	require.Error(t, waitWithin(t, tunnel, 2*time.Second), "a tunnel that never connected says so at once")
}

// waitWithin is rt.Wait, failing the test if it hasn't returned within d.
func waitWithin(t *testing.T, rt *ReverseTunnel, d time.Duration) error {
	t.Helper()
	waited := make(chan error, 1)
	go func() { waited <- rt.Wait() }()
	select {
	case err := <-waited:
		return err
	case <-time.After(d):
		t.Fatalf("Wait did not return within %s", d)
		return nil
	}
}

// silentListener accepts TCP connections and never says a word on them.
func silentListener(t *testing.T) (string, <-chan net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
			accepted <- c
		}
	}()
	return ln.Addr().String(), accepted
}

// Nothing an attempt starts outlives its deadline or a cancel, over each
// transport: Establish returns ctx's error, and the connection it opened is
// closed by Establish itself, before anyone calls Close.
func TestReverseTunnelAttemptHonoursItsDeadline(t *testing.T) {
	silent, accepted := silentListener(t)
	proxy := httpproxytest.Start(t, http.StatusOK)
	key, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	silentProxy, proxyAccepted := silentListener(t) // a proxy that never answers CONNECT
	for name, tc := range map[string]struct {
		u, proxy *url.URL
		far      <-chan net.Conn
	}{
		"ssh":            {u: &url.URL{Scheme: "ssh", Host: silent}, far: accepted},
		"ws":             {u: &url.URL{Scheme: "ws", Host: silent}, far: accepted},
		"ssh via proxy":  {u: &url.URL{Scheme: "ssh", Host: silent}, proxy: proxy.URL, far: accepted},
		"ws via proxy":   {u: &url.URL{Scheme: "ws", Host: silent}, proxy: proxy.URL, far: accepted},
		"a silent proxy": {u: &url.URL{Scheme: "ssh", Host: silent}, proxy: &url.URL{Scheme: "http", Host: silentProxy}, far: proxyAccepted},
	} {
		// A deadline, and a plain cancel such as session stop's, which gorilla
		// and the CONNECT exchange don't see on their own.
		for _, how := range []string{"deadline", "cancel"} {
			t.Run(name+"/"+how, func(t *testing.T) {
				rt := &ReverseTunnel{Host: tc.u, ProxyURL: tc.proxy, HostKey: key[0], Signers: key,
					HostKeyCallback: ssh.InsecureIgnoreHostKey()}
				ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
				cause := context.DeadlineExceeded
				if how == "cancel" {
					ctx, cancel = context.WithCancel(t.Context())
					time.AfterFunc(200*time.Millisecond, cancel)
					cause = context.Canceled
				}
				defer cancel()
				start := time.Now()
				_, err := rt.Establish(ctx)
				require.ErrorIs(t, err, cause, "the attempt's failure names its cause")
				require.Less(t, time.Since(start), 2*time.Second, "the attempt outlived its deadline")
				var far net.Conn
				select {
				case far = <-tc.far:
				case <-time.After(5 * time.Second):
					t.Fatal("the attempt never reached the far end")
				}
				require.NoError(t, far.SetReadDeadline(time.Now().Add(2*time.Second)))
				_, err = io.Copy(io.Discard, far)
				require.NoError(t, err, "the attempt's connection was left open")
				rt.Close()
			})
		}
	}
}

// A cancel that lands while the session request waits on the relay fails the
// attempt with the cancel as its cause, not with the EOF the close produced.
func TestReverseTunnelAttemptCancelledMidRequestSaysSo(t *testing.T) {
	relayKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	asked := make(chan struct{})
	release := make(chan struct{})
	fake := fakerelay.Start(t, relayKey[0], func(*server.CreateSessionRequest) (bool, []byte) {
		close(asked)
		<-release
		return false, nil
	})
	// Registered after Start, so it runs first and frees the relay's handler
	// before the relay waits for it to stop.
	t.Cleanup(func() { close(release) })
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	rt := &ReverseTunnel{Host: &url.URL{Scheme: "ssh", Host: fake.Addr}, HostKey: hostKey[0], Signers: hostKey,
		HostKeyCallback: ssh.FixedHostKey(relayKey[0].PublicKey())}
	t.Cleanup(rt.Close)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		select {
		case <-asked:
			cancel()
		case <-ctx.Done():
		}
	}()
	_, err = rt.Establish(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorContains(t, err, "error creating session", "the step the cancel interrupted")
	require.Zero(t, fake.Forwards())
}

// The deadline is the attempt's, not the tunnel's: an established tunnel
// outlives the context it was established under.
func TestReverseTunnelOutlivesItsAttemptContext(t *testing.T) {
	relay := startTestRelay(t)
	key, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	rt := relay.tunnel(key[0], relay.url)
	ctx, cancel := context.WithCancel(t.Context())
	_, err = rt.Establish(ctx)
	require.NoError(t, err)
	t.Cleanup(rt.Close)
	cancel() // the attempt is over; its context ends
	time.Sleep(200 * time.Millisecond)
	_, _, err = rt.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil)
	require.NoError(t, err, "an established tunnel died with its attempt's context")
}

// A relay that ignores the proof and answers with a random ID: a first
// connection carries on without reconnect, and a redial is refused before it
// binds a listener.
func TestReverseTunnelAgainstARelayWithoutProofs(t *testing.T) {
	relayKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	fake := fakerelay.Start(t, relayKey[0], func(*server.CreateSessionRequest) (bool, []byte) {
		b, _ := proto.Marshal(&server.CreateSessionResponse{SessionID: "aRandomSessionID1234", SessionKeyRedial: true})
		return true, b
	})
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	secret, err := registration.NewSecret()
	require.NoError(t, err)
	tunnel := func(redial bool) *ReverseTunnel {
		return &ReverseTunnel{Host: &url.URL{Scheme: "ssh", Host: fake.Addr}, HostKey: hostKey[0], Signers: hostKey,
			HostKeyCallback: ssh.FixedHostKey(relayKey[0].PublicKey()), SessionSecret: secret, Generation: 1,
			RequireDerivedID: redial}
	}

	first := tunnel(false)
	_, err = first.Establish(t.Context())
	require.NoError(t, err)
	t.Cleanup(first.Close)
	require.False(t, first.ReconnectSupported())
	require.False(t, first.SessionKeyRedial(), "only ever true where ReconnectSupported is")
	require.Equal(t, 1, fake.Forwards())

	redial := tunnel(true)
	_, err = redial.Establish(t.Context())
	require.ErrorIs(t, err, ErrRelayUnsupported)
	require.Equal(t, 1, fake.Forwards(), "a redial bound a listener for a registration it was discarding")
	waited := make(chan error, 1)
	go func() { waited <- redial.Wait() }()
	select {
	case err := <-waited:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("the redial's connection was left open")
	}
}

// A relay with --authorized-keys honours the proof, but a redial must still
// present an identity it lists: the session key alone won't do.
func TestReverseTunnelOnAGatedRelay(t *testing.T) {
	gated := func(s *server.Server) {
		// Signers is the identity startTestRelay's tunnels authenticate with.
		file := filepath.Join(t.TempDir(), "authorized_keys")
		require.NoError(t, os.WriteFile(file, ssh.MarshalAuthorizedKey(s.Signers[0].PublicKey()), 0600))
		s.AuthorizedKeysFiles = []string{file}
	}
	relay := startTestRelay(t, gated)
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	secret, err := registration.NewSecret()
	require.NoError(t, err)
	tunnel := relay.tunnel(hostKey[0], relay.url)
	tunnel.SessionSecret, tunnel.Generation = secret, 1
	response, err := tunnel.Establish(t.Context())
	require.NoError(t, err)
	t.Cleanup(tunnel.Close)
	require.Equal(t, registration.ID(hostKey[0].PublicKey(), secret), response.SessionID)
	require.True(t, tunnel.ReconnectSupported())
	require.False(t, tunnel.SessionKeyRedial())
}

// A failed Establish never reports a previous one's flags.
func TestReverseTunnelFlagsResetOnAFailedEstablish(t *testing.T) {
	relay := startTestRelay(t)
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	secret, err := registration.NewSecret()
	require.NoError(t, err)
	tunnel := relay.tunnel(hostKey[0], relay.url)
	tunnel.SessionSecret, tunnel.Generation = secret, 1
	_, err = tunnel.Establish(t.Context())
	require.NoError(t, err)
	t.Cleanup(tunnel.Close)
	require.True(t, tunnel.ReconnectSupported())
	require.True(t, tunnel.SessionKeyRedial())

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, closed.Close())
	tunnel.Host = &url.URL{Scheme: "ssh", Host: closed.Addr().String()}
	_, err = tunnel.Establish(t.Context())
	require.Error(t, err)
	require.False(t, tunnel.ReconnectSupported())
	require.False(t, tunnel.SessionKeyRedial())
}

// A tunnel liveness closed says so, to every waiter, and after Close.
func TestReverseTunnelWaitSaysWhyItEnded(t *testing.T) {
	relay := startTestRelay(t)
	fwd := testhelpers.NewForwarder(t, relay.url.Host)
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	tunnel := relay.tunnel(hostKey[0], &url.URL{Scheme: "ssh", Host: fwd.Addr()})
	// A Bound well past a slow runner's late wake-ups, so a probe's reply is
	// never what the test is timing.
	tunnel.KeepAlive = liveness.Timing{Interval: 100 * time.Millisecond, Bound: 300 * time.Millisecond}
	giveUp := tunnel.KeepAlive.Interval + tunnel.KeepAlive.Bound
	_, err = tunnel.Establish(t.Context())
	require.NoError(t, err)
	t.Cleanup(tunnel.Close)

	waited := make(chan error, 2)
	ended := make(chan struct{})
	go func() {
		err := tunnel.Wait()
		close(ended)
		waited <- err
	}()
	go func() { waited <- tunnel.Wait() }()
	// While the relay answers, the tunnel outlives two silences' worth of
	// Interval+Bound. Watch counts silence from its own start, so a keepalive
	// fed a clock that never advances would give up at the first.
	select {
	case <-ended:
		t.Fatal("the tunnel ended while the relay was answering its probes")
	case <-time.After(2 * giveUp):
	}
	// Once the relay goes silent, Wait returns within Interval+Bound of its
	// last bytes, given a second's margin.
	fwd.Blackhole()
	for range 2 {
		select {
		case err := <-waited:
			require.ErrorIs(t, err, liveness.ErrSilent)
		case <-time.After(giveUp + time.Second):
			t.Fatal("Wait did not return once the relay went silent")
		}
	}
	tunnel.Close()
	require.ErrorIs(t, waitWithin(t, tunnel, giveUp+time.Second), liveness.ErrSilent, "after Close too")
}

// A refused registration is typed, with the relay's body and the text it always had.
func TestReverseTunnelRefusalsAreTyped(t *testing.T) {
	relayKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	for _, body := range []string{registration.RefusedProof + ": x", registration.Superseded, "failed to create session: x"} {
		t.Run(body, func(t *testing.T) {
			fake := fakerelay.Start(t, relayKey[0], func(*server.CreateSessionRequest) (bool, []byte) {
				return false, []byte(body)
			})
			tunnel := &ReverseTunnel{Host: &url.URL{Scheme: "ssh", Host: fake.Addr}, HostKey: hostKey[0], Signers: hostKey,
				HostKeyCallback: ssh.FixedHostKey(relayKey[0].PublicKey())}
			t.Cleanup(tunnel.Close)
			_, err := tunnel.Establish(t.Context())
			var refused *CreateSessionRefusedError
			require.ErrorAs(t, err, &refused)
			require.Equal(t, body, refused.Body)
			require.EqualError(t, err, "error creating session: could not initialize session: "+body)
			require.Zero(t, fake.Forwards())
		})
	}
	// A zero value is printable, as a table of expected errors builds one.
	require.Equal(t, "unable to create reverse tunnel", (&ForwardRefusedError{}).Error())
}

// A test relay can present a host certificate for 127.0.0.1, which a
// certificate checker accepts on the hostname each transport dials it by.
func TestReverseTunnelAgainstARelayWithAHostCert(t *testing.T) {
	relay := startTestRelay(t, withHostCert)
	checker := &ssh.CertChecker{IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
		return bytes.Equal(auth.Marshal(), relay.identity[0].PublicKey().Marshal())
	}}
	hostKey, err := utils.CreateSigners(nil)
	require.NoError(t, err)
	for _, u := range []*url.URL{relay.url, relay.wsURL} {
		t.Run(u.Scheme, func(t *testing.T) {
			tunnel := relay.tunnel(hostKey[0], u)
			tunnel.HostKeyCallback = checker.CheckHostKey
			_, err := tunnel.Establish(t.Context())
			require.NoError(t, err)
			t.Cleanup(tunnel.Close)
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

		err := sshDialError(sshURL, nil, 1, dialErr)

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

		err := sshDialError(sshURL, nil, 1, dialErr)

		assert.Contains(t, err.Error(), `export UPTERM_PROXY="$https_proxy"`)
	})

	// socks5:// is a supported way to configure the environment proxy for the
	// ws and wss path, but --proxy takes only http://, so offering the copy
	// would trade this failure for a flag rejection.
	t.Run("a socks5 proxy names the other transport instead", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", socksEnv, nil)

		err := sshDialError(sshURL, nil, 1, dialErr)

		assert.NotContains(t, err.Error(), "UPTERM_PROXY")
		assert.Contains(t, err.Error(), "--server wss://uptermd.upterm.dev")
	})

	// Every way no proxy applies arrives as a nil lookup: NO_PROXY exempting
	// this host, nothing set at all, or a value too malformed to parse. In
	// none of them is routing through a proxy the answer.
	t.Run("a proxy that does not apply gets no advice", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", nil, nil)

		err := sshDialError(sshURL, nil, 1, dialErr)

		assert.Equal(t, "ssh dial error: "+dialErr.Error(), err.Error())
	})

	t.Run("a lookup error gets no advice", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", httpEnv, errors.New("invalid proxy address"))

		err := sshDialError(sshURL, nil, 1, dialErr)

		assert.Equal(t, "ssh dial error: "+dialErr.Error(), err.Error())
	})

	t.Run("a proxy with no host gets no advice", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", &url.URL{Scheme: "http"}, nil)

		err := sshDialError(sshURL, nil, 1, dialErr)

		assert.Equal(t, "ssh dial error: "+dialErr.Error(), err.Error())
	})

	t.Run("--proxy already supplied, no advice", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", httpEnv, nil)

		err := sshDialError(sshURL, flagged, 1, dialErr)

		assert.NotContains(t, err.Error(), "UPTERM_PROXY")
	})

	t.Run("wss already reads the environment, no advice", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", httpEnv, nil)

		err := sshDialError(wssURL, nil, 1, dialErr)

		assert.NotContains(t, err.Error(), "UPTERM_PROXY")
	})

	// Everything the dial wraps other than a network failure happened after
	// the connection succeeded, where a proxy cannot be the cause. A host-key
	// mismatch is the case that matters: the advice would trail a security
	// warning it has nothing to do with.
	t.Run("a failure that is not the network gets no advice", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", httpEnv, nil)

		err := sshDialError(sshURL, nil, 1, errors.New("ssh: handshake failed: host key mismatch"))

		assert.NotContains(t, err.Error(), "UPTERM_PROXY")
		assert.NotContains(t, err.Error(), "wss://")
	})

	// A custom relay was chosen for a reason. Changing the transport is the
	// suggestion; changing whose deployment the session runs on is not.
	t.Run("a custom relay keeps its own host in the suggestion", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", socksEnv, nil)

		err := sshDialError(&url.URL{Scheme: "ssh", Host: "relay.corp:22"}, nil, 1, dialErr)

		assert.Contains(t, err.Error(), "--server wss://relay.corp")
		assert.NotContains(t, err.Error(), "uptermd.upterm.dev")
	})

	// url.URL.Hostname strips the brackets, and an unbracketed IPv6 address is
	// not an authority the suggestion could be pasted back as.
	t.Run("an IPv6 relay is bracketed in the suggestion", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", socksEnv, nil)

		err := sshDialError(&url.URL{Scheme: "ssh", Host: "[2001:db8::1]:22"}, nil, 1, dialErr)

		assert.Contains(t, err.Error(), "--server wss://[2001:db8::1]")
	})

	// NO_PROXY entries may name a port, and the lookup fills in the scheme's
	// default for anything asked without one. Probing the bare hostname would
	// therefore ask about :443 and sail past an exemption written for :22.
	t.Run("the lookup is asked about the port that failed", func(t *testing.T) {
		asked := stubEnv(t, "HTTPS_PROXY", httpEnv, nil)

		_ = sshDialError(sshURL, nil, 1, dialErr)

		assert.Equal(t, "uptermd.upterm.dev:22", *asked)
	})

	// The proxy hint is for a dial that never reached the relay. An
	// authentication failure reached it and was turned away, so the advice
	// would be beside the point; the denial takes the error instead.
	t.Run("an auth failure is still a permission denial", func(t *testing.T) {
		_ = stubEnv(t, "HTTPS_PROXY", httpEnv, nil)

		err := sshDialError(sshURL, nil, 1, authFailure("[none publickey]"))

		var denied *PermissionDeniedError
		require.ErrorAs(t, err, &denied)
		assert.NotContains(t, err.Error(), "UPTERM_PROXY")
	})
}

// authFailure is x/crypto's out-of-methods error as ssh.Dial delivers it, with
// methods the %v of the ordered list of names it tried.
func authFailure(methods string) error {
	return fmt.Errorf("ssh: handshake failed: ssh: unable to authenticate, attempted methods %s, no supported methods remain", methods)
}

// A refused host is told which of the two refusals it got, because they are
// different problems: nothing was offered, or what was offered was not
// accepted. Until #562 only the first was recognised at all — the second, what
// a relay running with --authorized-keys produces, reached the user as the raw
// handshake error the issue quotes.
func TestSSHDialErrorNamesWhichDenialHappened(t *testing.T) {
	relay := &url.URL{Scheme: "ssh", Host: "relay.corp:22"}

	t.Run("no identity was offered", func(t *testing.T) {
		err := sshDialError(relay, nil, 0, authFailure("[none]"))

		var denied *PermissionDeniedError
		require.ErrorAs(t, err, &denied)
		assert.Equal(t, "ssh://relay.corp:22: Permission denied (publickey); no identity was offered.", err.Error())
	})

	t.Run("one identity was offered and refused", func(t *testing.T) {
		err := sshDialError(relay, nil, 1, authFailure("[none publickey]"))

		var denied *PermissionDeniedError
		require.ErrorAs(t, err, &denied)
		assert.Equal(t, "ssh://relay.corp:22: Permission denied (publickey); the 1 identity offered was refused.", err.Error())
	})

	// The count comes from the caller because x/crypto's list is of methods,
	// not of keys: ssh.PublicKeys is a single "publickey" entry whether it
	// carries one signer or three, so the same error text backs both.
	t.Run("several identities were offered and refused", func(t *testing.T) {
		err := sshDialError(relay, nil, 3, authFailure("[none publickey]"))

		assert.Equal(t, "ssh://relay.corp:22: Permission denied (publickey); the 3 identities offered were refused.", err.Error())
	})

	// Holding keys is not offering them. A server that does not allow
	// publickey leaves the method out of the list, and the list is what is
	// believed — saying an identity was refused when none went out would send
	// the user looking at the wrong key.
	t.Run("keys held but never offered", func(t *testing.T) {
		err := sshDialError(relay, nil, 2, authFailure("[none]"))

		assert.Equal(t, "ssh://relay.corp:22: Permission denied (publickey); no identity was offered.", err.Error())
	})

	// The match is on the head of x/crypto's sentence rather than on either
	// list it is known to produce today, so a list this code has never seen is
	// still classified as the denial it is.
	t.Run("an unfamiliar method list is still a denial", func(t *testing.T) {
		err := sshDialError(relay, nil, 1, authFailure("[none keyboard-interactive]"))

		var denied *PermissionDeniedError
		require.ErrorAs(t, err, &denied)
		assert.Equal(t, "ssh://relay.corp:22: Permission denied (publickey); no identity was offered.", err.Error())
	})

	// The list ends at its bracket. Everything after it is the rest of
	// x/crypto's sentence, or whatever wrapped the error, and a method name
	// found there was not a method that was tried.
	t.Run("a method named after the list is not a key offered", func(t *testing.T) {
		err := sshDialError(relay, nil, 1, fmt.Errorf("%w: publickey", authFailure("[none]")))

		assert.Equal(t, "ssh://relay.corp:22: Permission denied (publickey); no identity was offered.", err.Error())
	})

	// The handshake's own words are what a bug report needs, and replacing
	// them with a summary would lose them.
	t.Run("the x/crypto error stays reachable", func(t *testing.T) {
		cause := authFailure("[none publickey]")

		err := sshDialError(relay, nil, 1, cause)

		var denied *PermissionDeniedError
		require.ErrorAs(t, err, &denied)
		require.Equal(t, cause, denied.Unwrap())
		assert.ErrorIs(t, err, cause)
	})

	// Only authentication is a denial. Everything else the dial can fail with
	// keeps the wrap it had, and the proxy advice that goes with it.
	t.Run("a failure that is not authentication is not a denial", func(t *testing.T) {
		cause := errors.New("ssh: handshake failed: knownhosts: key mismatch")

		err := sshDialError(relay, nil, 1, cause)

		var denied *PermissionDeniedError
		require.NotErrorAs(t, err, &denied)
		assert.Equal(t, "ssh dial error: "+cause.Error(), err.Error())
	})
}
