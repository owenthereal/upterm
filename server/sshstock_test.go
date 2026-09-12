package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type stockTestDialer struct {
	addr  string
	calls atomic.Int32
}

func (d *stockTestDialer) Dial(id *api.Identifier) (net.Conn, error) {
	return d.DialContext(context.Background(), id)
}
func (d *stockTestDialer) DialContext(ctx context.Context, id *api.Identifier) (net.Conn, error) {
	d.calls.Add(1)
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.addr)
}

func stockTestProxy(t *testing.T, timeout time.Duration, dialer connDialer, options ...func(*sshProxy)) (*sshProxy, string, *prometheus.Registry, ssh.Signer) {
	t.Helper()
	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mp, reg := newTestMetrics(t)
	proxy := &sshProxy{HandshakeTimeout: timeout, HostSigners: []ssh.Signer{signer}, Signers: []ssh.Signer{signer}, SessionManager: newEmbeddedSessionManager(logger), NodeAddr: "127.0.0.1:2222", ConnDialer: dialer, Logger: logger, MetricsProvider: mp}
	for _, option := range options {
		option(proxy)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- proxy.Serve(ln) }()
	require.Eventually(t, func() bool {
		_, ok := gatherValue(t, reg, "test_server_routing_authenticated_connections_count", map[string]string{"kind": "host"})
		return ok
	}, time.Second, time.Millisecond)
	t.Cleanup(func() {
		_ = proxy.Shutdown()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("proxy did not stop")
		}
	})
	return proxy, ln.Addr().String(), reg, signer
}

func stockTestUpstream(t *testing.T, reject bool, hostKey string) (string, <-chan *ssh.ServerConn) {
	t.Helper()
	signer, err := ssh.ParsePrivateKey([]byte(hostKey))
	require.NoError(t, err)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if reject {
			return nil, errors.New("upstream denied key")
		}
		cert, ok := k.(*ssh.Certificate)
		if !ok {
			return nil, errors.New("missing certificate")
		}
		checker := ssh.CertChecker{IsUserAuthority: func(ssh.PublicKey) bool { return true }}
		if err := checker.CheckCert(c.User(), cert); err != nil {
			return nil, err
		}
		auth, _, err := (&UserCertChecker{}).Authenticate(c.User(), cert)
		if err != nil {
			return nil, err
		}
		return &ssh.Permissions{Extensions: map[string]string{"key": string(auth.AuthorizedKey)}}, nil
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	peers := make(chan *ssh.ServerConn, 10)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, channels, requests, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					_ = raw.Close()
					return
				}
				defer func() { _ = sc.Close() }()
				peers <- sc
				go func() {
					for req := range requests {
						_ = req.Reply(true, req.Payload)
					}
				}()
				for ch := range channels {
					_ = ch.Reject(ssh.UnknownChannelType, "upstream channel reason")
				}
			}()
		}
	}()
	return ln.Addr().String(), peers
}

func TestStockSSHSuccess(t *testing.T) {
	upstream, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
	dialer := &stockTestDialer{addr: upstream}
	_, addr, reg, signer := stockTestProxy(t, 2*time.Second, dialer)
	for _, kind := range []string{"host", "client"} {
		t.Run(kind, func(t *testing.T) {
			user := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode("session", "127.0.0.1:3333")
			cfg := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second}
			if kind == "host" {
				cfg.User = "session"
				cfg.ClientVersion = upterm.HostSSHClientVersion
			}
			client, err := ssh.Dial("tcp", addr, cfg)
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			select {
			case peer := <-peers:
				require.Equal(t, cfg.User, peer.User())
			case <-time.After(time.Second):
				t.Fatal("upstream did not authenticate")
			}
			time.Sleep(1100 * time.Millisecond) // both stage deadlines must be cleared
			ok, payload, err := client.SendRequest("opaque-global", true, []byte("reply body"))
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, "reply body", string(payload))
			_, err = client.NewSession()
			require.ErrorContains(t, err, "upstream channel reason")
			value, present := gatherValue(t, reg, "test_server_routing_authenticated_connections_count", map[string]string{"kind": kind})
			require.True(t, present)
			require.Equal(t, 1.0, value)
		})
	}
	require.Equal(t, int32(2), dialer.calls.Load())
}

func TestStockSSHUnsignedQueryDoesNotDial(t *testing.T) {
	dialer := &stockTestDialer{addr: "127.0.0.1:1"}
	_, addr, reg, signer := stockTestProxy(t, time.Second, dialer)
	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "session", ClientVersion: upterm.HostSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(refusingSigner{signer})}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	require.Error(t, err)
	require.Zero(t, dialer.calls.Load())
	value, present := gatherValue(t, reg, "test_server_routing_authenticated_connections_count", map[string]string{"kind": "host"})
	require.True(t, present)
	require.Zero(t, value)
}

func TestStockSSHUpstreamFailure(t *testing.T) {
	for _, tc := range []struct {
		name, key, reason string
		reject            bool
	}{
		{name: "authentication", key: TestPrivateKeyContent, reject: true, reason: "unable to authenticate"},
		{name: "host key", key: HostPrivateKeyContent, reason: "host key mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, _ := stockTestUpstream(t, tc.reject, tc.key)
			_, addr, reg, signer := stockTestProxy(t, time.Second, &stockTestDialer{addr: upstream})
			client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "session", ClientVersion: upterm.HostSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			ok, _, err := client.SendRequest("host-first-global", true, nil)
			require.NoError(t, err)
			require.False(t, ok)
			_, err = client.NewSession()
			var rejection *ssh.OpenChannelError
			require.ErrorAs(t, err, &rejection)
			require.Contains(t, rejection.Message, tc.reason)
			value, _ := gatherValue(t, reg, "test_server_routing_authenticated_connections_count", map[string]string{"kind": "host"})
			require.Zero(t, value)
		})
	}
}

// A peer whose downstream authentication succeeded must always learn why the
// upstream did not, including when the failure was the upstream budget expiring
// — the case where the reporting path used to inherit an already-spent context.
func TestStockSSHUpstreamFailureReportsReason(t *testing.T) {
	// An unaccepted memory listener makes DialContext block until the stage
	// deadline, so this exercises the timeout path rather than a fast refusal.
	stalledDialer := func(t *testing.T) connDialer {
		t.Helper()
		network := &MemoryProvider{}
		require.NoError(t, network.SetOpts(nil))
		ln, err := network.SSHD().Listen()
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		return sidewayConnDialer{SSHDDialListener: network.SSHD()}
	}

	t.Run("host global request", func(t *testing.T) {
		_, addr, _, signer := stockTestProxy(t, time.Second, stalledDialer(t))
		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "session", ClientVersion: upterm.HostSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
		require.NoError(t, err)
		defer func() { _ = client.Close() }()
		// A host opens no channel of its own; it speaks first with a global
		// request and reports the failure reply body verbatim.
		ok, body, err := client.SendRequest("host-first-global", true, nil)
		require.NoError(t, err)
		require.False(t, ok)
		require.Equal(t, errUpstreamUnavailable.Error(), string(body))
	})

	t.Run("client channel open", func(t *testing.T) {
		_, addr, _, signer := stockTestProxy(t, time.Second, stalledDialer(t))
		_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "session", ClientVersion: upterm.HostSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
		require.NoError(t, err)
		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "session", ClientVersion: upterm.HostSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
		require.NoError(t, err)
		defer func() { _ = client.Close() }()
		_, err = client.NewSession()
		var rejection *ssh.OpenChannelError
		require.ErrorAs(t, err, &rejection)
		require.Equal(t, errUpstreamUnavailable.Error(), rejection.Message)
	})

	// Only outcomes uptermd recognizes are named. Anything else, including a
	// transport failure whose text carries the upstream's address, is generic.
	t.Run("recognized outcomes only", func(t *testing.T) {
		for _, tc := range []struct {
			name, hostKey, want string
			reject              bool
		}{
			{name: "authentication", hostKey: TestPrivateKeyContent, reject: true, want: errUpstreamAuthFailed.Error()},
			{name: "host key", hostKey: HostPrivateKeyContent, want: errUpstreamHostKeyMismatch.Error()},
		} {
			t.Run(tc.name, func(t *testing.T) {
				upstream, _ := stockTestUpstream(t, tc.reject, tc.hostKey)
				_, addr, _, signer := stockTestProxy(t, time.Second, &stockTestDialer{addr: upstream})
				client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "session", ClientVersion: upterm.HostSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
				require.NoError(t, err)
				defer func() { _ = client.Close() }()
				ok, body, err := client.SendRequest("host-first-global", true, nil)
				require.NoError(t, err)
				require.False(t, ok)
				require.Equal(t, tc.want, string(body))
			})
		}

		// An upstream that accepts TCP and then says nothing fails the handshake
		// at the transport layer, where the error reads "read tcp <local>-><node>".
		t.Run("stalled transport", func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer func() { _ = ln.Close() }()
			go func() {
				if c, err := ln.Accept(); err == nil {
					<-time.After(time.Minute)
					_ = c.Close()
				}
			}()
			_, addr, _, signer := stockTestProxy(t, time.Second, &stockTestDialer{addr: ln.Addr().String()})
			client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "session", ClientVersion: upterm.HostSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			ok, body, err := client.SendRequest("host-first-global", true, nil)
			require.NoError(t, err)
			require.False(t, ok)
			require.Equal(t, errUpstreamUnavailable.Error(), string(body))
			require.NotContains(t, string(body), ln.Addr().String())
		})
	})
}

func TestUpstreamFailureReasonAllowlist(t *testing.T) {
	// A transport error carries the upstream's address and must never be named.
	transport := fmt.Errorf("ssh: handshake failed: %w", &net.OpError{
		Op: "read", Net: "tcp",
		Addr: &net.TCPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 2222},
		Err:  errors.New("i/o timeout"),
	})
	require.Equal(t, errUpstreamUnavailable, upstreamFailureReason(transport))
	require.NotContains(t, upstreamFailureReason(transport).Error(), "10.1.2.3")

	require.Equal(t, errUpstreamHostKeyMismatch,
		upstreamFailureReason(fmt.Errorf("ssh: handshake failed: %w", errUpstreamHostKeyMismatch)))
	require.Equal(t, errUpstreamAuthFailed,
		upstreamFailureReason(errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")))
	// Anything unrecognized, including a dial error naming a session socket.
	require.Equal(t, errUpstreamUnavailable,
		upstreamFailureReason(errors.New("dial unix /var/folders/x/uptermd123/sshd.sock: connect: connection refused")))
	require.Equal(t, errUpstreamUnavailable, upstreamFailureReason(nil))
}

// flakyListener fails Accept a fixed number of times before reporting itself
// closed, so a test can tell a retry apart from a bail-out.
type flakyListener struct {
	failures []error
	calls    atomic.Int32
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if n := int(l.calls.Add(1)); n <= len(l.failures) {
		return nil, l.failures[n-1]
	}
	return nil, net.ErrClosed
}

func (l *flakyListener) Close() error   { return nil }
func (l *flakyListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// Running out of descriptors clears as open connections drain. Accept reports
// it as a net.Error that is not a timeout, so a timeout-only check would take
// the listener -- and with it uptermd -- down over a condition that passes.
func TestStockSSHAcceptRetriesResourceExhaustion(t *testing.T) {
	accept := func(errno syscall.Errno) error {
		return &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept4", errno)}
	}
	ln := &flakyListener{failures: []error{accept(syscall.EMFILE), accept(syscall.ENFILE), accept(syscall.ENOBUFS)}}
	mp, _ := newTestMetrics(t)
	p := &SSHRouting{MetricsProvider: mp}

	require.ErrorIs(t, p.Serve(ln), net.ErrClosed)
	require.Equal(t, int32(len(ln.failures)+1), ln.calls.Load(),
		"every recoverable accept failure should be retried, not returned")
}

// Only the host gets the narrow scope. Swapping these two constants leaves
// every behavioural test in the package green — the forwarder tests hand
// forwardSSH a scope directly — while costing a host every guest attached to
// its session the first time one of them stops reading.
func TestAbortScopeForClientVersion(t *testing.T) {
	for _, tt := range []struct {
		name          string
		clientVersion string
		want          sshAbortScope
	}{
		// A host's transport carries the reverse tunnel; it must survive.
		{"host", upterm.HostSSHClientVersion, abortChannel},
		// Everything else is one guest's own connection.
		{"guest", upterm.ClientSSHClientVersion, abortConnection},
		{"unknown client", "SSH-2.0-OpenSSH_9.6", abortConnection},
		{"empty", "", abortConnection},
		// Near-misses must not be mistaken for the host: the check is exact,
		// and a prefix or suffix match would hand a guest the host's scope.
		{"host prefix", upterm.HostSSHClientVersion + "-2", abortConnection},
		{"host suffix", "x" + upterm.HostSSHClientVersion, abortConnection},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, abortScopeFor(tt.clientVersion))
		})
	}
	// The two scopes must stay distinguishable; a single-valued type would make
	// every assertion above vacuous.
	require.NotEqual(t, abortChannel, abortConnection)
}

func TestRecoverableAcceptErrors(t *testing.T) {
	syscallErr := func(errno syscall.Errno) error {
		return &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept4", errno)}
	}
	for _, errno := range []syscall.Errno{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM} {
		require.True(t, isRecoverableAcceptError(syscallErr(errno)), errno)
	}
	require.True(t, isRecoverableAcceptError(&net.OpError{Op: "accept", Err: os.ErrDeadlineExceeded}))
	// A closed or otherwise broken listener never recovers by retrying.
	require.False(t, isRecoverableAcceptError(net.ErrClosed))
	require.False(t, isRecoverableAcceptError(syscallErr(syscall.EINVAL)))
	require.False(t, isRecoverableAcceptError(errors.New("boom")))
}

func TestHandshakeTimeoutValidation(t *testing.T) {
	require.NoError(t, validateHandshakeTimeout(0)) // selects the default
	require.NoError(t, validateHandshakeTimeout(DefaultHandshakeTimeout))
	require.NoError(t, validateHandshakeTimeout(90*time.Second))
	require.Error(t, validateHandshakeTimeout(-time.Second))
	// Half of this would outlive the user certificate minted while authenticating.
	require.Error(t, validateHandshakeTimeout(maxHandshakeTimeout))
	require.Error(t, validateHandshakeTimeout(5*time.Minute))

	// Operator config adds a floor: a budget too small to finish a handshake
	// would otherwise fail every connection with no explanation.
	base := Opt{SSHAddr: "127.0.0.1:2222", NodeAddr: "127.0.0.1:2222", Routing: routing.ModeEmbedded}
	valid := base
	valid.HandshakeTimeout = minHandshakeTimeout
	require.NoError(t, valid.Validate())
	tooSmall := base
	tooSmall.HandshakeTimeout = time.Millisecond
	require.ErrorContains(t, tooSmall.Validate(), "handshake-timeout must be at least")
	unset := base
	require.NoError(t, unset.Validate())
}

func TestStockSSHKeyGatesAndSelection(t *testing.T) {
	upstream, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
	good, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	bad, err := ssh.ParsePrivateKey([]byte(HostPrivateKeyContent))
	require.NoError(t, err)
	for _, kind := range []string{"host", "client"} {
		t.Run(kind, func(t *testing.T) {
			dialer := &stockTestDialer{addr: upstream}
			proxy, addr, reg, _ := stockTestProxy(t, time.Second, dialer, func(p *sshProxy) {
				p.AuthorizedKeysFiles = []string{writeKeyFile(t, string(ssh.MarshalAuthorizedKey(good.PublicKey())))}
			})
			user := "session"
			cfg := &ssh.ClientConfig{User: user, ClientVersion: upterm.HostSSHClientVersion, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Auth: []ssh.AuthMethod{ssh.PublicKeys(bad)}}
			if kind == "client" {
				user, err = proxy.SessionManager.CreateSession(NewSession("session", proxy.NodeAddr, "host", [][]byte{ssh.MarshalAuthorizedKey(good.PublicKey())}, [][]byte{ssh.MarshalAuthorizedKey(good.PublicKey())}))
				require.NoError(t, err)
				cfg.User = user
				cfg.ClientVersion = ""
			}
			_, err = ssh.Dial("tcp", addr, cfg)
			require.Error(t, err)
			require.Zero(t, dialer.calls.Load())
			value, _ := gatherValue(t, reg, "test_server_routing_authenticated_connections_count", map[string]string{"kind": kind})
			require.Zero(t, value)
			cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(bad, good)}
			client, err := ssh.Dial("tcp", addr, cfg)
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			select {
			case peer := <-peers:
				require.Equal(t, string(ssh.MarshalAuthorizedKey(good.PublicKey())), peer.Permissions.Extensions["key"])
			case <-time.After(time.Second):
				t.Fatal("no authenticated upstream")
			}
			require.Equal(t, int32(1), dialer.calls.Load())
		})
	}
}

func TestStockSSHRejectsInvalidUsers(t *testing.T) {
	for _, tc := range []struct{ user, version string }{{"", upterm.HostSSHClientVersion}, {"invalid", ""}, {"", ""}} {
		t.Run(tc.user+tc.version, func(t *testing.T) {
			dialer := &stockTestDialer{addr: "127.0.0.1:1"}
			_, addr, _, signer := stockTestProxy(t, time.Second, dialer)
			_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: tc.user, ClientVersion: tc.version, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}})
			require.Error(t, err)
			require.Zero(t, dialer.calls.Load())
		})
	}
}

func TestStockSSHDownstreamTimeoutAndShutdown(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(fmt.Sprint(shutdown), func(t *testing.T) {
			timeout := 200 * time.Millisecond
			if shutdown {
				timeout = time.Minute
			}
			dialer := &stockTestDialer{addr: "127.0.0.1:1"}
			proxy, addr, _, _ := stockTestProxy(t, timeout, dialer)
			raw, err := net.Dial("tcp", addr)
			require.NoError(t, err)
			defer func() { _ = raw.Close() }()
			// Wait for the banner so Shutdown races an actual worker, not Accept.
			reader := bufio.NewReader(raw)
			_, err = reader.ReadString('\n')
			require.NoError(t, err)
			if shutdown {
				require.NoError(t, proxy.Shutdown())
			}
			require.NoError(t, raw.SetReadDeadline(time.Now().Add(time.Second)))
			_, err = reader.ReadByte()
			require.Error(t, err)
			var ne net.Error
			require.False(t, errors.As(err, &ne) && ne.Timeout(), "proxy must close the stalled handshake")
			require.Zero(t, dialer.calls.Load())
		})
	}
}

func TestStockSSHUpstreamStagesAreBounded(t *testing.T) {
	for _, stage := range []string{"dial", "handshake", "no channel"} {
		t.Run(stage, func(t *testing.T) {
			var dialer connDialer
			switch stage {
			case "dial":
				network := &MemoryProvider{}
				require.NoError(t, network.SetOpts(nil))
				ln, err := network.SSHD().Listen()
				require.NoError(t, err)
				defer func() { _ = ln.Close() }()
				dialer = sidewayConnDialer{SSHDDialListener: network.SSHD()}
			case "handshake":
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				defer func() { _ = ln.Close() }()
				accepted := make(chan net.Conn, 1)
				go func() {
					c, err := ln.Accept()
					if err == nil {
						accepted <- c
					}
				}()
				t.Cleanup(func() {
					select {
					case c := <-accepted:
						_ = c.Close()
					default:
					}
				})
				dialer = &stockTestDialer{addr: ln.Addr().String()}
			default:
				dialer = &stockTestDialer{addr: "127.0.0.1:1"}
			}
			_, addr, _, signer := stockTestProxy(t, time.Second, dialer)
			client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "session", ClientVersion: upterm.HostSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			done := make(chan error, 1)
			go func() { done <- client.Wait() }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("upstream establishment or error delivery exceeded budget")
			}
		})
	}
}

func TestStockSSHShutdownActiveAndUpstreamHandshake(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprint(active), func(t *testing.T) {
			upstream, peers := stockTestUpstream(t, false, TestPrivateKeyContent)
			if !active {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				defer func() { _ = ln.Close() }()
				upstream = ln.Addr().String()
				go func() {
					c, err := ln.Accept()
					if err == nil {
						defer func() { _ = c.Close() }()
						_, _ = io.Copy(io.Discard, c)
					}
				}()
			}
			dialer := &stockTestDialer{addr: upstream}
			proxy, addr, _, signer := stockTestProxy(t, time.Minute, dialer)
			client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "session", ClientVersion: upterm.HostSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			if active {
				select {
				case <-peers:
				case <-time.After(time.Second):
					t.Fatal("no upstream")
				}
			} else {
				require.Eventually(t, func() bool { return dialer.calls.Load() == 1 }, time.Second, time.Millisecond)
			}
			done := make(chan struct{})
			go func() { _ = proxy.Shutdown(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("shutdown did not join connections")
			}
			require.Error(t, client.Wait())
		})
	}
}

func TestStockSSHShutdownBeforeServe(t *testing.T) {
	mp, _ := newTestMetrics(t)
	p := &SSHRouting{MetricsProvider: mp}
	require.NoError(t, p.Shutdown())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	done := make(chan error, 1)
	go func() { done <- p.Serve(ln) }()
	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrListnerClosed)
	case <-time.After(time.Second):
		t.Fatal("shutdown before Serve must prevent Accept")
	}
}
