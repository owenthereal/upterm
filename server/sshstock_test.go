package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
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
	proxy := &sshProxy{StockSSH: true, HandshakeTimeout: timeout, HostSigners: []ssh.Signer{signer}, Signers: []ssh.Signer{signer}, SessionManager: newEmbeddedSessionManager(logger), NodeAddr: "127.0.0.1:2222", ConnDialer: dialer, Logger: logger, MetricsProvider: mp}
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
	p := &SSHRouting{StockSSH: true, MetricsProvider: mp}
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
