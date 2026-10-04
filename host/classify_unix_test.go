//go:build !windows

package host

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// The agent rows of TestClassify need a unix socket, so they live here and
// the portable rows stay where Windows CI runs them. Both go through a real
// Establish: a signing error surfaces from the handshake raw, and the row
// pins that it is still an *AgentRefusedError, and never auth_refused, once
// x/crypto and the dial have wrapped it.
func TestClassifyAgentFailures(t *testing.T) {
	runClassifyCases(t, []classifyCase{
		{
			name: "an agent that is gone by the redial",
			err: func(t *testing.T) error {
				pub, priv := newEd25519(t)
				ag := startTestAgent(t, priv)
				recorded := agentIdentities(t, ag, pub)
				ag.stop()
				relay := sshServer(t, admitting(pub))

				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				signers, closeAgent := redialIdentities(ctx, recorded, nil, false)
				defer closeAgent()
				err := establishFailsUnder(ctx, t, classifyTunnel(t,
					&url.URL{Scheme: "ssh", Host: relay.Addr}, signers, ssh.InsecureIgnoreHostKey()))

				var unavailable *AgentUnavailableError
				require.ErrorAs(t, err, &unavailable)
				return err
			},
			reason: sessiondir.TunnelReasonAgentUnavailable, class: transient,
		},
		{
			name: "an agent whose signature never comes",
			err: func(t *testing.T) error {
				pub, priv := newEd25519(t)
				ag := startTestAgent(t, priv)
				recorded := agentIdentities(t, ag, pub)
				held := ag.holdSignatures(t)
				relay := sshServer(t, admitting(pub))

				// The attempt's own context: its end releases the signature the
				// agent is sitting on. The deadline starts once the signature
				// is pending, not before the handshake that gets it there,
				// which is CPU-bound.
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				signers, closeAgent := redialIdentities(ctx, recorded, nil, false)
				defer context.AfterFunc(ctx, closeAgent)()
				defer closeAgent()

				errc := make(chan error, 1)
				tunnel := classifyTunnel(t, &url.URL{Scheme: "ssh", Host: relay.Addr}, signers, ssh.InsecureIgnoreHostKey())
				go func() {
					_, err := tunnel.Establish(ctx)
					errc <- err
				}()
				receive(t, held, "the agent was never asked to sign")
				time.AfterFunc(200*time.Millisecond, cancel)

				err := receive(t, errc, "the handshake never returned")
				tunnel.Close()
				require.Error(t, err)

				var refused *AgentRefusedError
				require.ErrorAs(t, err, &refused)
				require.Equal(t, utils.FingerprintSHA256(pub), refused.Key)
				var denied *internal.PermissionDeniedError
				require.NotErrorAs(t, err, &denied)
				return err
			},
			reason: sessiondir.TunnelReasonAgentRefused, class: blocked,
		},
	})
}
