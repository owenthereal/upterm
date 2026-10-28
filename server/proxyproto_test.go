package server

import (
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestRequireProxyV2(t *testing.T) {
	for _, tc := range []struct {
		name                string
		version             byte
		command             proxyproto.ProtocolVersionAndCommand
		transport           proxyproto.AddressFamilyAndProtocol
		source, destination net.Addr
		want                string
	}{
		{name: "headerless"},
		{"v1", 1, proxyproto.PROXY, proxyproto.TCPv4, &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4711}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}, ""},
		{"LOCAL", 2, proxyproto.LOCAL, proxyproto.TCPv4, &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4711}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}, ""},
		{"UDPv4", 2, proxyproto.PROXY, proxyproto.UDPv4, &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4711}, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}, ""},
		{"Unix", 2, proxyproto.PROXY, proxyproto.UnixStream, &net.UnixAddr{Name: "/source", Net: "unix"}, &net.UnixAddr{Name: "/destination", Net: "unix"}, ""},
		{"TCPv4", 2, proxyproto.PROXY, proxyproto.TCPv4, &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4711}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}, "203.0.113.7:4711"},
		{"TCPv6", 2, proxyproto.PROXY, proxyproto.TCPv6, &net.TCPAddr{IP: net.ParseIP("2001:db8::7"), Port: 4711}, &net.TCPAddr{IP: net.ParseIP("::1"), Port: 2222}, "[2001:db8::7]:4711"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := serveStrictSSH(t)
			raw := fixture.dial(t)
			if tc.version != 0 {
				_, err := (&proxyproto.Header{Version: tc.version, Command: tc.command, TransportProtocol: tc.transport, SourceAddr: tc.source, DestinationAddr: tc.destination}).WriteTo(raw)
				require.NoError(t, err)
			}
			if tc.want == "" {
				// Supply bytes so a missing header is distinguishable from a silent peer.
				if tc.version == 0 {
					_, err := io.WriteString(raw, "SSH-2.0-probe\r\n")
					require.NoError(t, err)
				}
				var b [1]byte
				n, err := raw.Read(b[:])
				require.Zero(t, n, "invalid headers must not receive an SSH banner")
				require.ErrorIs(t, err, io.EOF)
				return
			}
			conn := strictHandshake(t, raw)
			require.Equal(t, "SSH-2.0-Go", string(conn.ServerVersion()))
			select {
			case remote := <-fixture.remote:
				require.Equal(t, tc.want, remote)
			case <-time.After(2 * time.Second):
				t.Fatal("server did not report ConnMetadata.RemoteAddr")
			}
		})
	}
}

func TestRequireProxyV2HeaderlessProbe(t *testing.T) {
	fixture := serveStrictSSH(t)
	for range 50 {
		raw := fixture.dial(t)
		require.NoError(t, raw.Close())
	}
	raw := fixture.dial(t)
	writeStrictHeader(t, raw)
	strictHandshake(t, raw)
}

func TestRequireProxyV2SilentPeerDoesNotBlockAccept(t *testing.T) {
	fixture := serveStrictSSH(t)
	silent := fixture.dial(t)
	defer func() { _ = silent.Close() }()
	raw := fixture.dial(t)
	writeStrictHeader(t, raw)
	strictHandshake(t, raw)
}

func TestListenSSHNetwork(t *testing.T) {
	// Distinguish an IPv4-only listener from a host without IPv6 loopback.
	ipv6, err := net.Listen("tcp6", "[::1]:0")
	if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Skip("no ::1 on this host")
	}
	require.NoError(t, err)
	require.NoError(t, ipv6.Close())
	ln, err := listenSSH("tcp4", "0.0.0.0:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", port), time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	conn, err = net.DialTimeout("tcp6", net.JoinHostPort("::1", port), time.Second)
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err, "tcp4 must not accept IPv6 loopback")
}

type strictSSHFixture struct {
	ln       net.Listener
	accepted chan struct{}
	remote   chan string
}

func serveStrictSSH(t *testing.T) *strictSSHFixture {
	t.Helper()
	ln, err := listenSSH("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	ln = RequireProxyV2(ln)
	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	f := &strictSSHFixture{ln: ln, accepted: make(chan struct{}, 64), remote: make(chan string, 64)}
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	var handlers sync.WaitGroup
	done := make(chan error, 1)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				done <- err
				return
			}
			mu.Lock()
			active[raw] = true
			mu.Unlock()
			f.accepted <- struct{}{}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer func() { _ = raw.Close(); mu.Lock(); delete(active, raw); mu.Unlock() }()
				conn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				f.remote <- conn.RemoteAddr().String()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "no channels")
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case err := <-done:
			require.True(t, errors.Is(err, net.ErrClosed), "Accept returned an unexpected error: %v", err)
		case <-time.After(2 * time.Second):
			t.Error("Accept did not stop")
		}
		mu.Lock()
		for raw := range active {
			_ = raw.Close()
		}
		mu.Unlock()
		handlers.Wait()
	})
	return f
}

func (f *strictSSHFixture) dial(t *testing.T) net.Conn {
	t.Helper()
	raw, err := net.DialTimeout("tcp4", f.ln.Addr().String(), time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	require.NoError(t, raw.SetDeadline(time.Now().Add(2*time.Second)))
	select {
	case <-f.accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("Accept blocked before returning the connection")
	}
	return raw
}

func writeStrictHeader(t *testing.T, raw net.Conn) {
	t.Helper()
	_, err := (&proxyproto.Header{Version: 2, Command: proxyproto.PROXY, TransportProtocol: proxyproto.TCPv4,
		SourceAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4711}, DestinationAddr: raw.RemoteAddr()}).WriteTo(raw)
	require.NoError(t, err)
}

func strictHandshake(t *testing.T, raw net.Conn) ssh.Conn {
	t.Helper()
	conn, channels, requests, err := ssh.NewClientConn(raw, raw.RemoteAddr().String(), &ssh.ClientConfig{User: "probe", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	go ssh.DiscardRequests(requests)
	go func() {
		for ch := range channels {
			_ = ch.Reject(ssh.Prohibited, "no channels")
		}
	}()
	return conn
}
