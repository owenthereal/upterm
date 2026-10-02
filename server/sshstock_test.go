package server

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
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
		auth, _, err := (&UserCertChecker{
			// This stands in for a host's sshd, which trusts the relay it
			// verified; the CertChecker above already says so.
			IsUserAuthority: func(ssh.PublicKey) bool { return true },
		}).Authenticate(c.User(), cert)
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

	// An embedded-mode guest's user names the node to dial, and the dialer's
	// error can echo it. Whatever it reads, a dial failure stays generic.
	t.Run("dial failure echoing the guest's node", func(t *testing.T) {
		proxy, addr, _, signer := stockTestProxy(t, time.Second, sidewayConnDialer{})
		user := proxy.SessionManager.GetEncodeDecoder().Encode("session", sshAuthFailure)
		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
		require.NoError(t, err)
		defer func() { _ = client.Close() }()
		_, err = client.NewSession()
		var rejection *ssh.OpenChannelError
		require.ErrorAs(t, err, &rejection)
		require.Equal(t, errUpstreamUnavailable.Error(), rejection.Message)
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

// flakyListener fails Accept a fixed number of times before settling on
// terminal, so a test can tell a retry apart from a bail-out. terminal decides
// which way the loop leaves: a closed listener is a shutdown, anything else is
// a real accept failure.
type flakyListener struct {
	failures []error
	terminal error
	calls    atomic.Int32
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if n := int(l.calls.Add(1)); n <= len(l.failures) {
		return nil, l.failures[n-1]
	}
	return nil, l.terminal
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
	recoverable := []error{accept(syscall.EMFILE), accept(syscall.ENFILE), accept(syscall.ENOBUFS)}

	// The two ways out of the accept loop, told apart by what Serve returns and
	// by whether the failure is charged. A closed listener is a shutdown: it
	// leaves by the same door as the loop's other closes and costs nothing. Any
	// other unrecoverable error is a real failure and still surfaces raw and
	// counted -- without this case nothing reaches that branch at all.
	for _, tt := range []struct {
		name      string
		terminal  error
		wantErr   error
		wantCount float64
	}{
		{
			name:      "a closed listener is a shutdown",
			terminal:  net.ErrClosed,
			wantErr:   ErrListnerClosed,
			wantCount: 0,
		},
		{
			name:      "an unrecoverable accept error is a failure",
			terminal:  accept(syscall.EINVAL),
			wantErr:   syscall.EINVAL,
			wantCount: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ln := &flakyListener{failures: recoverable, terminal: tt.terminal}
			mp, reg := newTestMetrics(t)
			p := &SSHRouting{MetricsProvider: mp}

			require.ErrorIs(t, p.Serve(ln), tt.wantErr)
			require.Equal(t, int32(len(ln.failures)+1), ln.calls.Load(),
				"every recoverable accept failure should be retried, not returned")

			// A counter never added to is not exported at all, which reads the
			// same as zero here: the shutdown was not charged as a failure.
			got, _ := gatherValue(t, reg, "test_server_routing_errors_count", nil)
			require.Equal(t, tt.wantCount, got, "routing_errors_count")
		})
	}
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

// TestStockSSHGuestHostKeyMismatch pins the branch a guest's upstream hop is
// checked on: the session's registered HostPublicKeys. The host-connection
// cases in TestStockSSHUpstreamFailure identify as an upterm host, so their
// route has no local session and the relay checks its own HostSigners instead;
// this is the branch the session host key depends on. The session is created
// on the proxy's own NodeAddr, which is what makes resolve treat it as local
// rather than treat the hop as a sideways one to another relay node.
func TestStockSSHGuestHostKeyMismatch(t *testing.T) {
	// A session key of its own. stockTestProxy installs TestPrivateKeyContent
	// as the relay's HostSigners, so registering that key would let a check
	// that wrongly consulted the relay's keys pass both cases below. With a
	// fresh key, accepting it and rejecting the relay's own key is exactly
	// the boundary under test.
	_, sessionPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sessionKey, err := ssh.NewSignerFromKey(sessionPriv)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(sessionPriv, "")
	require.NoError(t, err)
	sessionKeyPEM := string(pem.EncodeToMemory(block))

	for _, tc := range []struct {
		name, presented string
		joins           bool
	}{
		{name: "presents the session key", presented: sessionKeyPEM, joins: true},
		{name: "presents the relay's own key", presented: TestPrivateKeyContent},
		{name: "presents an unrelated key", presented: HostPrivateKeyContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, _ := stockTestUpstream(t, false, tc.presented)
			proxy, addr, _, signer := stockTestProxy(t, time.Second, &stockTestDialer{addr: upstream})
			user, err := proxy.SessionManager.CreateSession(NewSession("session", proxy.NodeAddr, "host",
				[][]byte{ssh.MarshalAuthorizedKey(sessionKey.PublicKey())}, nil))
			require.NoError(t, err)

			client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
			require.NoError(t, err)
			defer func() { _ = client.Close() }()

			_, err = client.NewSession()
			if tc.joins {
				// The stock upstream rejects every channel with its own
				// reason; reaching it is the success, since the handshake it
				// sits behind is what a mismatch would have failed.
				require.ErrorContains(t, err, "upstream channel reason")
				return
			}
			var rejection *ssh.OpenChannelError
			require.ErrorAs(t, err, &rejection)
			require.Equal(t, errUpstreamHostKeyMismatch.Error(), rejection.Message)
		})
	}
}

// staleStore answers Get from a stale cache until something (the "watch", or
// GetFresh) clears it.
type staleStore struct {
	*memorySessionStore
	mu         sync.Mutex
	stale      *Session
	gone       bool                            // Get reports not found: the watch removed the entry
	fresh      func(ctx context.Context) error // optional: stall or fail GetFresh
	afterFresh func(s *staleStore)             // optional: a watch landing right after GetFresh
}

func (s *staleStore) Get(id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gone {
		return nil, &ErrSessionNotFound{SessionID: id}
	}
	if s.stale != nil && s.stale.ID == id {
		return s.stale, nil
	}
	return s.memorySessionStore.Get(id)
}

func (s *staleStore) watchDelivers() {
	s.mu.Lock()
	s.stale = nil
	s.mu.Unlock()
}

func (s *staleStore) GetFresh(ctx context.Context, id string) (*Session, error) {
	if s.fresh != nil {
		if err := s.fresh(ctx); err != nil {
			return nil, err
		}
	}
	s.watchDelivers()
	sess, err := s.memorySessionStore.Get(id)
	if s.afterFresh != nil {
		s.afterFresh(s)
	}
	return sess, err
}

type routeDialer struct {
	routes map[string]func(ctx context.Context) (net.Conn, error)
	calls  atomic.Int32
}

func (d *routeDialer) Dial(id *api.Identifier) (net.Conn, error) {
	return d.DialContext(context.Background(), id)
}

func (d *routeDialer) DialContext(ctx context.Context, id *api.Identifier) (net.Conn, error) {
	d.calls.Add(1)
	if r, ok := d.routes[id.NodeAddr]; ok {
		return r(ctx)
	}
	return nil, fmt.Errorf("no route to %s", id.NodeAddr)
}

// stallingListener accepts TCP connections and never speaks on them.
func stallingListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

// movedSession: the store says node C at generation 2, the cache still says A
// at 1.
func movedSession(t *testing.T, good ssh.Signer) *staleStore {
	logger := slog.New(slog.DiscardHandler)
	store := &staleStore{memorySessionStore: newMemorySessionStore(logger)}
	keys := [][]byte{ssh.MarshalAuthorizedKey(good.PublicKey())}
	fresh := NewSession("session", "node-c:22", "host", keys, nil)
	fresh.Generation = 2
	_, err := store.Register(context.Background(), fresh)
	require.NoError(t, err)
	stale := NewSession("session", "node-a:22", "host", keys, nil)
	stale.Generation = 1
	store.stale = stale
	return store
}

func consulModeProxy(t *testing.T, store SessionStore, dialer connDialer) string {
	return consulModeProxyWithin(t, 4*time.Second, store, dialer)
}

// The tests that must reach node C after a stalled or failed first attempt use
// refreshRoomTimeout. The upstream stage is half the handshake timeout and the
// first attempt takes half of that, so the second attempt has about 2 s for its
// SSH handshake: room for a starved -race runner, where the 1 s a 4 s timeout
// leaves can run out. refreshRoomWait is how long they wait for node C, which
// is longer than the whole stage.
const (
	refreshRoomTimeout = 8 * time.Second
	refreshRoomWait    = 6 * time.Second
)

func consulModeProxyWithin(t *testing.T, timeout time.Duration, store SessionStore, dialer connDialer) string {
	_, addr, _, _ := stockTestProxy(t, timeout, dialer, func(p *sshProxy) {
		p.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeConsul))
	})
	return addr
}

func dialGuest(t *testing.T, addr string, key ssh.Signer) *ssh.Client {
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "session", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestStockSSHRefreshesAStaleRoute(t *testing.T) {
	good, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	nodeC, peersC := stockTestUpstream(t, false, TestPrivateKeyContent)
	refusing, _ := stockTestUpstream(t, true, TestPrivateKeyContent)
	dial := func(a string) func(context.Context) (net.Conn, error) {
		return func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", a) }
	}
	for name, routeA := range map[string]func(store *staleStore) func(context.Context) (net.Conn, error){
		"unreachable": func(*staleStore) func(context.Context) (net.Conn, error) {
			return func(context.Context) (net.Conn, error) { return nil, errors.New("connection refused") }
		},
		"no longer holds the session": func(*staleStore) func(context.Context) (net.Conn, error) { return dial(refusing) },
		"stalls its handshake":        func(*staleStore) func(context.Context) (net.Conn, error) { return dial(stallingListener(t)) },
		// The watch updates the cache to C while A's handshake stalls.
		// Comparing with the cache would see no move; comparing with the
		// attempted route does.
		"watch lands mid-handshake": func(store *staleStore) func(context.Context) (net.Conn, error) {
			stall := dial(stallingListener(t))
			return func(ctx context.Context) (net.Conn, error) {
				c, err := stall(ctx)
				store.watchDelivers()
				return c, err
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := movedSession(t, good)
			dialer := &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){
				"node-a:22": routeA(store), "node-c:22": dial(nodeC),
			}}
			dialGuest(t, consulModeProxyWithin(t, refreshRoomTimeout, store, dialer), good)
			select {
			case <-peersC: // Dial succeeding proves nothing: the guest is authenticated first
			case <-time.After(refreshRoomWait):
				t.Fatal("the refreshed route never reached node C")
			}
			require.Equal(t, int32(2), dialer.calls.Load())
		})
	}
}

// A watch that replaces or removes the cache entry between GetFresh and the
// second attempt changes neither where that attempt goes nor which host key it
// expects. It is prepared from the snapshot GetFresh returned.
func TestStockSSHRefreshUsesOneSnapshot(t *testing.T) {
	good, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	nodeC, peersC := stockTestUpstream(t, false, TestPrivateKeyContent)
	for name, after := range map[string]func(s *staleStore){
		"replaced": func(s *staleStore) {
			d := NewSession("session", "node-d:22", "host", nil, nil)
			d.Generation = 3
			s.mu.Lock()
			s.stale = d
			s.mu.Unlock()
		},
		"removed": func(s *staleStore) {
			s.mu.Lock()
			s.gone = true
			s.mu.Unlock()
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := movedSession(t, good)
			store.afterFresh = after
			dialer := &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){
				"node-a:22": func(context.Context) (net.Conn, error) { return nil, errors.New("connection refused") },
				"node-c:22": func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", nodeC) },
			}}
			dialGuest(t, consulModeProxyWithin(t, refreshRoomTimeout, store, dialer), good)
			select {
			case <-peersC:
			case <-time.After(refreshRoomWait):
				t.Fatal("the second attempt left the snapshot GetFresh returned")
			}
			require.Equal(t, int32(2), dialer.calls.Load(), "node D is never dialed")
		})
	}
}

// A fresh lookup that stalls must not hold the guest past the stage. The
// stage is 2 s here; the guest is rejected, not held.
func TestStockSSHRefreshStaysInsideTheStage(t *testing.T) {
	good, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	store := movedSession(t, good)
	store.fresh = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	dialer := &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){
		"node-a:22": func(context.Context) (net.Conn, error) { return nil, errors.New("connection refused") },
	}}
	client := dialGuest(t, consulModeProxy(t, store, dialer), good)
	start := time.Now()
	// On a goroutine, so a lookup that outlives the stage fails this test
	// instead of hanging the package.
	opened := make(chan error, 1)
	go func() {
		_, err := client.NewSession()
		opened <- err
	}()
	select {
	case err = <-opened:
	case <-time.After(5 * time.Second):
		t.Fatal("held past the upstream stage")
	}
	require.Error(t, err)
	require.Less(t, time.Since(start), 3*time.Second, "held past the upstream stage")
	require.Equal(t, int32(1), dialer.calls.Load())
}

// A host-key mismatch is not a stale route. The store has moved the session on
// here, so a refresh would find somewhere else to go; the guest must not be
// sent there.
func TestStockSSHDoesNotRefreshAHostKeyMismatch(t *testing.T) {
	good, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	wrong, _ := stockTestUpstream(t, false, HostPrivateKeyContent)
	nodeC, _ := stockTestUpstream(t, false, TestPrivateKeyContent)
	store := movedSession(t, good)
	// This node, so the session's own host key is the one expected.
	store.stale.NodeAddr = "127.0.0.1:2222"
	dialer := &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){
		"127.0.0.1:2222": func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", wrong) },
		"node-c:22":      func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", nodeC) },
	}}
	client := dialGuest(t, consulModeProxy(t, store, dialer), good)
	_, err = client.NewSession()
	var rejection *ssh.OpenChannelError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, errUpstreamHostKeyMismatch.Error(), rejection.Message)
	require.Equal(t, int32(1), dialer.calls.Load())
}

// The second attempt is authorized against the snapshot it is planned from,
// as the first is against its own read. The store has moved the session to
// this node, where it admits only another key, so the guest isn't sent there.
func TestStockSSHRefreshChecksTheGuestsKey(t *testing.T) {
	good, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	other, err := ssh.ParsePrivateKey([]byte(HostPrivateKeyContent))
	require.NoError(t, err)
	here, _ := stockTestUpstream(t, false, TestPrivateKeyContent)
	store := &staleStore{memorySessionStore: newMemorySessionStore(slog.New(slog.DiscardHandler))}
	fresh := NewSession("session", "127.0.0.1:2222", "host",
		[][]byte{ssh.MarshalAuthorizedKey(good.PublicKey())}, [][]byte{ssh.MarshalAuthorizedKey(other.PublicKey())})
	fresh.Generation = 2
	_, err = store.Register(context.Background(), fresh)
	require.NoError(t, err)
	store.stale = NewSession("session", "node-a:22", "host", nil, nil)
	store.stale.Generation = 1
	dialer := &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){
		"node-a:22":      func(context.Context) (net.Conn, error) { return nil, errors.New("connection refused") },
		"127.0.0.1:2222": func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", here) },
	}}
	client := dialGuest(t, consulModeProxy(t, store, dialer), good)
	_, err = client.NewSession()
	var rejection *ssh.OpenChannelError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, errUpstreamUnavailable.Error(), rejection.Message)
	require.Equal(t, int32(1), dialer.calls.Load())
}

// Only a Consul-mode guest's route is refreshed. A host's upstream is this
// node's sshd, and an embedded-mode guest's user names its node, so neither is
// retried however the store has moved the session.
func TestStockSSHRefreshesOnlyConsulGuests(t *testing.T) {
	good, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	nodeC, _ := stockTestUpstream(t, false, TestPrivateKeyContent)
	// Only node C, where the store has the session, has a route; every other
	// dial fails.
	toNodeC := func() *routeDialer {
		return &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){
			"node-c:22": func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", nodeC) },
		}}
	}

	t.Run("a host", func(t *testing.T) {
		dialer := toNodeC()
		addr := consulModeProxy(t, movedSession(t, good), dialer)
		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "session", ClientVersion: upterm.HostSSHClientVersion, Auth: []ssh.AuthMethod{ssh.PublicKeys(good)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
		require.NoError(t, err)
		defer func() { _ = client.Close() }()
		ok, _, err := client.SendRequest("host-first-global", true, nil)
		require.NoError(t, err)
		require.False(t, ok)
		require.Equal(t, int32(1), dialer.calls.Load())
	})

	t.Run("an embedded-mode guest", func(t *testing.T) {
		dialer := toNodeC()
		sm := newSessionManagerWithStore(movedSession(t, good), routing.NewEncodeDecoder(routing.ModeEmbedded))
		_, addr, _, _ := stockTestProxy(t, 4*time.Second, dialer, func(p *sshProxy) { p.SessionManager = sm })
		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: sm.GetEncodeDecoder().Encode("session", "node-a:22"), Auth: []ssh.AuthMethod{ssh.PublicKeys(good)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
		require.NoError(t, err)
		defer func() { _ = client.Close() }()
		_, err = client.NewSession()
		var rejection *ssh.OpenChannelError
		require.ErrorAs(t, err, &rejection)
		require.Equal(t, int32(1), dialer.calls.Load())
	})
}

// rejectedAfter opens a session on client, which the relay must reject, and
// returns how long it took to.
func rejectedAfter(t *testing.T, client *ssh.Client) time.Duration {
	t.Helper()
	start := time.Now()
	// On a goroutine, so a guest held past the stage fails the test instead
	// of hanging the package.
	opened := make(chan error, 1)
	go func() {
		_, err := client.NewSession()
		opened <- err
	}()
	select {
	case err := <-opened:
		require.Error(t, err)
		return time.Since(start)
	case <-time.After(5 * time.Second):
		t.Fatal("held past the upstream stage")
		return 0
	}
}

// A legacy route can't move: its host can't redial, and its lease keeper
// rebuilds it on the same node at the same generation. It gets one attempt and
// the whole stage, which is 2 s here, and no refresh, even when the store has
// the session somewhere else.
func TestStockSSHDoesNotRefreshALegacyRoute(t *testing.T) {
	good, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	store := movedSession(t, good)
	store.stale.Generation = 0
	stall := stallingListener(t)
	dialer := &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){
		"node-a:22": func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", stall) },
	}}
	client := dialGuest(t, consulModeProxy(t, store, dialer), good)
	require.GreaterOrEqual(t, rejectedAfter(t, client), 1500*time.Millisecond, "the attempt was cut short of the stage")
	require.Equal(t, int32(1), dialer.calls.Load())
}

// The stalled attempt above spends the whole stage, which refuses a refresh on
// its own, so it can't show that the generation is what does. Here the legacy
// host's node refuses at once, with the stage left and the store holding the
// session on node C, where a refreshed route would be accepted.
func TestStockSSHDoesNotRefreshALegacyRouteThatFailsFast(t *testing.T) {
	good, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	nodeC, _ := stockTestUpstream(t, false, TestPrivateKeyContent)
	store := movedSession(t, good)
	store.stale.Generation = 0
	dialer := &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){
		"node-a:22": func(context.Context) (net.Conn, error) { return nil, errors.New("connection refused") },
		"node-c:22": func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", nodeC) },
	}}
	client := dialGuest(t, consulModeProxyWithin(t, refreshRoomTimeout, store, dialer), good)
	rejectedAfter(t, client)
	require.Equal(t, int32(1), dialer.calls.Load(), "the guest was sent to another node")
}

// A refreshable route whose target is on this node gets the whole stage for
// its first attempt: a local target that stalls is far more likely a slow host
// than a stale route. The stage is 2 s here.
func TestStockSSHGivesALocalTargetTheWholeStage(t *testing.T) {
	good, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	store := &staleStore{memorySessionStore: newMemorySessionStore(slog.New(slog.DiscardHandler))}
	here := NewSession("session", "127.0.0.1:2222", "host", [][]byte{ssh.MarshalAuthorizedKey(good.PublicKey())}, nil)
	here.Generation = 1
	_, err = store.Register(context.Background(), here)
	require.NoError(t, err)
	stall := stallingListener(t)
	dialer := &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){
		"127.0.0.1:2222": func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", stall) },
	}}
	client := dialGuest(t, consulModeProxy(t, store, dialer), good)
	require.GreaterOrEqual(t, rejectedAfter(t, client), 1500*time.Millisecond, "the first attempt was cut short of the stage")
	require.Equal(t, int32(1), dialer.calls.Load())
}

// What lets a local target have the whole stage: a stale route to this node
// fails fast, since the host has left its slot here, and the refresh still
// has the rest of the stage to reach the node the store now names.
func TestStockSSHRefreshesAStaleRouteToThisNode(t *testing.T) {
	good, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	nodeC, peersC := stockTestUpstream(t, false, TestPrivateKeyContent)
	store := movedSession(t, good)
	store.stale.NodeAddr = "127.0.0.1:2222" // this node
	dialer := &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){
		"127.0.0.1:2222": func(context.Context) (net.Conn, error) { return nil, errors.New("connection refused") },
		"node-c:22":      func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", nodeC) },
	}}
	dialGuest(t, consulModeProxyWithin(t, refreshRoomTimeout, store, dialer), good)
	select {
	case <-peersC:
	case <-time.After(refreshRoomWait):
		t.Fatal("the refreshed route never reached node C")
	}
	require.Equal(t, int32(2), dialer.calls.Load())
}

type failingStore struct{ *memorySessionStore }

func (failingStore) Get(string) (*Session, error) { return nil, errors.New("consul unreachable") }

func dialForBanners(t *testing.T, addr, user string, keys ...ssh.Signer) []string {
	var banners []string
	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{ssh.PublicKeys(keys...)}, BannerCallback: func(m string) error { banners = append(banners, m); return nil }})
	require.Error(t, err)
	return banners
}

func TestStockSSHBanner(t *testing.T) {
	k1, _ := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	k2, _ := ssh.ParsePrivateKey([]byte(HostPrivateKeyContent))
	k3, _ := utils.CreateSigners(nil)
	dialer := &stockTestDialer{addr: "127.0.0.1:1"}

	t.Run("missing, once however many keys", func(t *testing.T) {
		proxy, addr, _, _ := stockTestProxy(t, time.Second, dialer)
		b := dialForBanners(t, addr, proxy.SessionManager.GetEncodeDecoder().Encode("missing", proxy.NodeAddr), k1, k2, k3[0])
		require.Len(t, b, 1)
		require.Contains(t, b[0], "no host is connected for session missing")
	})
	t.Run("store unreachable", func(t *testing.T) {
		logger := slog.New(slog.DiscardHandler)
		_, addr, _, _ := stockTestProxy(t, time.Second, dialer, func(p *sshProxy) {
			p.SessionManager = newSessionManagerWithStore(failingStore{newMemorySessionStore(logger)}, routing.NewEncodeDecoder(routing.ModeConsul))
		})
		b := dialForBanners(t, addr, "anything", k1)
		require.Len(t, b, 1)
		require.Contains(t, b[0], "can't look up sessions")
		require.NotContains(t, b[0], "no host is connected")
	})
	// A user that doesn't decode is refused for its format, which is no lookup.
	t.Run("a user that doesn't decode", func(t *testing.T) {
		logger := slog.New(slog.DiscardHandler)
		_, addr, _, _ := stockTestProxy(t, time.Second, dialer, func(p *sshProxy) {
			p.SessionManager = newSessionManagerWithStore(newMemorySessionStore(logger), routing.NewEncodeDecoder(routing.ModeConsul))
		})
		require.Empty(t, dialForBanners(t, addr, ":x", k1))
	})
	t.Run("found, refusing the key", func(t *testing.T) {
		proxy, addr, _, _ := stockTestProxy(t, time.Second, dialer)
		user, err := proxy.SessionManager.CreateSession(NewSession("found", proxy.NodeAddr, "host", nil, [][]byte{ssh.MarshalAuthorizedKey(k1.PublicKey())}))
		require.NoError(t, err)
		require.Empty(t, dialForBanners(t, addr, user, k2))
	})
	// The banner goes to the guest's own terminal, and names the session its
	// user carries.
	t.Run("missing, with a control sequence in the user", func(t *testing.T) {
		proxy, addr, _, _ := stockTestProxy(t, time.Second, dialer)
		b := dialForBanners(t, addr, proxy.SessionManager.GetEncodeDecoder().Encode("mis\x1b[2Jsing", proxy.NodeAddr), k1)
		require.Len(t, b, 1)
		body, ok := strings.CutSuffix(b[0], "\n")
		require.True(t, ok, "%q", b[0])
		require.False(t, strings.ContainsFunc(body, unicode.IsControl), "%q", b[0])
		require.Contains(t, b[0], `no host is connected for session "mis\x1b[2Jsing"`)
	})
	// The session can go, or the store fail, between the key being offered and
	// its signature being verified; the second lookup is the one that fails.
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"missing once the key is verified":     {&ErrSessionNotFound{SessionID: "session"}, "no host is connected for session session"},
		"unreachable once the key is verified": {errors.New("consul unreachable"), "can't look up sessions"},
	} {
		t.Run(name, func(t *testing.T) {
			store := &fickleStore{memorySessionStore: newMemorySessionStore(slog.New(slog.DiscardHandler)), err: tc.err}
			_, err := store.Register(context.Background(), NewSession("session", "node-a:22", "host", nil, nil))
			require.NoError(t, err)
			_, addr, _, _ := stockTestProxy(t, time.Second, dialer, func(p *sshProxy) {
				p.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeConsul))
			})
			b := dialForBanners(t, addr, "session", k1)
			require.Greater(t, store.gets.Load(), int32(1), "the key was never verified")
			require.Len(t, b, 1)
			require.Contains(t, b[0], tc.want)
		})
	}
}

// fickleStore answers the first lookup, and fails every one after it with err.
type fickleStore struct {
	*memorySessionStore
	gets atomic.Int32
	err  error
}

func (s *fickleStore) Get(id string) (*Session, error) {
	if s.gets.Add(1) > 1 {
		return nil, s.err
	}
	return s.memorySessionStore.Get(id)
}

func TestBannerFor(t *testing.T) {
	guest, host := &fakeConnMetadata{}, &fakeConnMetadata{clientVersion: upterm.HostSSHClientVersion}
	notFound := &lookupError{fmt.Errorf("error resolving SSH user: %w", &ErrSessionNotFound{SessionID: "s"})}
	unreachable := &lookupError{errors.New("consul unreachable")}
	for _, tc := range []struct {
		name string
		meta ssh.ConnMetadata
		err  error
		want string
	}{
		{"no error", guest, nil, ""},
		{"a refusal that is not a lookup", guest, errors.New("public key not allowed"), ""},
		{"a session that is not stored", guest, notFound, fmt.Sprintf(bannerNoHost, "s")},
		{"a session not stored, in a wrapped chain", guest, fmt.Errorf("refused: %w", notFound), fmt.Sprintf(bannerNoHost, "s")},
		{"a store that fails", guest, unreachable, bannerLookupFailed},
		{"a host connection", host, notFound, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, bannerFor(tc.meta, "s", tc.err))
		})
	}
}

// Only reading the guest's session marks a refusal as a failed lookup, which
// earns a banner. A user that doesn't decode is the guest's own mistake.
// authenticate refuses such a user before resolve runs, so this pins the
// marking itself.
func TestResolveMarksOnlyAFailedReadAsALookup(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	here := routing.NewEncodeDecoder(routing.ModeEmbedded).Encode("missing", "here:22")
	for _, tc := range []struct {
		name   string
		mode   routing.Mode
		store  SessionStore
		user   string
		lookup bool
	}{
		{"a Consul-mode user that doesn't decode", routing.ModeConsul, newMemorySessionStore(logger), ":x", false},
		{"an embedded-mode user that doesn't decode", routing.ModeEmbedded, newMemorySessionStore(logger), "x", false},
		{"a session the store doesn't have", routing.ModeConsul, newMemorySessionStore(logger), "x", true},
		{"a store that fails", routing.ModeConsul, failingStore{newMemorySessionStore(logger)}, "x", true},
		{"an embedded-mode session this node doesn't have", routing.ModeEmbedded, newMemorySessionStore(logger), here, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sm := newSessionManagerWithStore(tc.store, routing.NewEncodeDecoder(tc.mode))
			a := proxyAuth{NodeAddr: "here:22", SessionManager: sm, Logger: logger}
			_, err := a.resolve(&fakeConnMetadata{user: tc.user})
			require.Error(t, err)
			var lookup *lookupError
			require.Equal(t, tc.lookup, errors.As(err, &lookup), "%v", err)
		})
	}
}

// The session ID is whatever the guest's user carries, so a banner prints it
// as is only when it has an ID's shape, and quoted otherwise.
func TestBannerForQuotesAnOddSessionID(t *testing.T) {
	notFound := &lookupError{&ErrSessionNotFound{SessionID: "s"}}
	long := strings.Repeat("a", 64)
	for id, want := range map[string]string{
		"Ab3":       "Ab3",
		long:        long,
		long + "a":  `"` + long + `a"`,
		"":          `""`,
		"a-b":       `"a-b"`,
		"a\x1b[2Jb": `"a\x1b[2Jb"`,
		"a\u202eb":  `"a\u202eb"`,
	} {
		require.Equal(t, fmt.Sprintf(bannerNoHost, want), bannerFor(&fakeConnMetadata{}, id, notFound), "%q", id)
	}
}
