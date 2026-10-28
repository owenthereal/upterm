package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/ws"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// Capture the bound address and the connection's observed peer address from
// Start without adding a listener injection hook to production code.
type proxyProtocolTestLogs chan map[string]any

func (logs proxyProtocolTestLogs) Write(p []byte) (int, error) {
	var record map[string]any
	if err := json.Unmarshal(p, &record); err != nil {
		return 0, err
	}
	select {
	case logs <- record:
	default:
	}
	return len(p), nil
}

func TestStartSSHProxyProtocolOptional(t *testing.T) {
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
			WSAddr:           "127.0.0.1:0",
			SSHProxyProtocol: true,
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
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	awaitLog := func(t *testing.T, message string) map[string]any {
		t.Helper()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for {
			select {
			case record := <-logs:
				if record["msg"] == message {
					return record
				}
			case <-timer.C:
				t.Fatalf("server did not log %q", message)
			}
		}
	}
	started := awaitLog(t, "starting server")
	addr := started["ssh_addr"].(string)
	wsAddr := started["ws_addr"].(string)

	for _, transport := range []string{"plain_ssh", "proxy_header", "websocket"} {
		t.Run(transport, func(t *testing.T) {
			var raw net.Conn
			if transport == "websocket" {
				raw, err = ws.NewWSConn(&url.URL{Scheme: "ws", Host: wsAddr, User: url.UserPassword("proxy-policy-test", "")}, false, nil)
			} else {
				raw, err = net.DialTimeout("tcp", addr, time.Second)
			}
			require.NoError(t, err)
			defer func() { _ = raw.Close() }()
			require.NoError(t, raw.SetDeadline(time.Now().Add(5*time.Second)))
			wantAddr := raw.LocalAddr().String()
			if transport == "proxy_header" {
				wantAddr = "203.0.113.42:54321"
				_, err = io.WriteString(raw, "PROXY TCP4 203.0.113.42 127.0.0.1 54321 2222\r\n")
				require.NoError(t, err)
			}
			defer func() {
				_ = raw.Close()
				record := awaitLog(t, "SSH connection ended")
				observed := record["addr"].(map[string]any)
				if transport == "websocket" {
					require.Equal(t, "127.0.0.1", observed["IP"], "WebSocket must reach the SSH listener over loopback")
				} else {
					require.Equal(t, wantAddr, net.JoinHostPort(observed["IP"].(string), fmt.Sprint(observed["Port"])),
						"the server must retain the socket peer or the PROXY header's source address")
				}
			}()
			conn, channels, requests, err := ssh.NewClientConn(raw, addr, &ssh.ClientConfig{
				User:            "proxy-policy-test",
				ClientVersion:   upterm.HostSSHClientVersion,
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			})
			require.NoError(t, err, "SSH must authenticate with or without a PROXY header")
			client := ssh.NewClient(conn, channels, requests)
			defer func() { _ = client.Close() }()
			// Only sshd can successfully create a session; the relay's upstream
			// failure path can reject requests but cannot produce this response.
			request, err := proto.Marshal(&CreateSessionRequest{
				HostUser:       "proxy-policy-test",
				HostPublicKeys: [][]byte{[]byte(TestPublicKeyContent)},
			})
			require.NoError(t, err)
			ok, body, err := client.SendRequest(upterm.ServerCreateSessionRequestType, true, request)
			require.NoError(t, err)
			require.True(t, ok, "sshd must create the session: %s", body)
			var response CreateSessionResponse
			require.NoError(t, proto.Unmarshal(body, &response))
			require.NotEmpty(t, response.SessionID)
			require.NotEmpty(t, response.SshUser)
			require.Equal(t, addr, response.NodeAddr)
			// Disconnecting also removes this connection's session at sshd.
			require.NoError(t, client.Close())
		})
	}
}

func TestStartRequireProxyV2(t *testing.T) {
	t.Setenv("PRIVATE_KEY", "")
	keyPath := filepath.Join(t.TempDir(), "host_key")
	require.NoError(t, os.WriteFile(keyPath, []byte(TestPrivateKeyContent), 0600))
	logs := make(proxyProtocolTestLogs, 128)
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Start(ctx, Opt{SSHAddr: "0.0.0.0:0", SSHNetwork: "tcp4", InternalAddr: "127.0.0.1:0", SSHProxyProtocolRequired: true, PrivateKeys: []string{keyPath}, Network: "mem"}, logger)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	var addr string
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for addr == "" {
		select {
		case record := <-logs:
			if record["msg"] == "starting server" {
				addr = record["ssh_addr"].(string)
			}
		case <-timer.C:
			t.Fatal("server did not start")
		}
	}
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	raw, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", port), time.Second)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()
	require.NoError(t, raw.SetDeadline(time.Now().Add(2*time.Second)))
	_, err = io.WriteString(raw, "SSH-2.0-probe\r\n")
	require.NoError(t, err)
	var b [1]byte
	n, err := raw.Read(b[:])
	require.Zero(t, n, "required mode must imply PROXY support even without ssh-proxy-protocol")
	require.ErrorIs(t, err, io.EOF)
}
