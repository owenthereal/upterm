package internal

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
