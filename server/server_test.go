package server

import (
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// Shutdown races the serving path over the very listeners it closes:
// sshProxy.Shutdown closes sshln by way of SSHRouting and webSocketProxy.Shutdown
// closes wsln by way of http.Server, both from run.Group interrupts that fire
// alongside Server.Shutdown. Losing that race leaves the listener shut, which is
// the outcome Shutdown wanted, so it must not be reported as a failure.
func TestServerShutdownToleratesAlreadyClosedListeners(t *testing.T) {
	tests := []struct {
		name     string
		closeSSH bool
		closeWS  bool
	}{
		{name: "ssh listener already closed", closeSSH: true},
		{name: "websocket listener already closed", closeWS: true},
		{name: "both listeners already closed", closeSSH: true, closeWS: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.DiscardHandler)
			sshln := listenLoopback(t)
			wsln := listenLoopback(t)

			s := &Server{
				NodeAddr:       sshln.Addr().String(),
				SessionManager: newEmbeddedSessionManager(logger),
				Logger:         logger,
				sshln:          sshln,
				wsln:           wsln,
			}

			if tt.closeSSH {
				require.NoError(t, sshln.Close())
			}
			if tt.closeWS {
				require.NoError(t, wsln.Close())
			}

			require.NoError(t, s.Shutdown())
		})
	}
}

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	return ln
}
