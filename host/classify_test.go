package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/httpproxy/httpproxytest"
	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/internal/testhelpers/fakerelay"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// classifyCase is one row of classify's tables. err takes the row's own t
// because the rows that matter most come from a real handshake, which needs a
// relay of its own: x/crypto shapes those errors, and only a real one pins
// that their chains survive "ssh: handshake failed: %w".
type classifyCase struct {
	name   string
	err    func(t *testing.T) error
	reason string
	class  retryClass
}

// fixedErr is a case whose error needs nothing built.
func fixedErr(err error) func(*testing.T) error { return func(*testing.T) error { return err } }

func runClassifyCases(t *testing.T, cases []classifyCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.err(t)
			require.Error(t, err)
			reason, class := classify(err)
			require.Equal(t, tc.reason, reason, "%v", err)
			require.Equal(t, tc.class, class, "%v", err)
		})
	}
}

// classifyTunnel is a redial's tunnel to a relay at host. Its host key is the
// one the relay would be told to expect, and nothing here reaches that far.
func classifyTunnel(t *testing.T, host *url.URL, signers []ssh.Signer, hostKeyCallback ssh.HostKeyCallback) *internal.ReverseTunnel {
	t.Helper()
	sessionKey, err := NewHostKey()
	require.NoError(t, err)
	return &internal.ReverseTunnel{
		Host:            host,
		Signers:         signers,
		HostKey:         sessionKey,
		HostKeyCallback: hostKeyCallback,
	}
}

// establishFails runs one real Establish, and returns the error that it must
// have ended in. It is bounded generously: a CPU-bound handshake under -race
// needs seconds, and the rows that want a short deadline arm their own.
func establishFails(t *testing.T, tunnel *internal.ReverseTunnel) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	return establishFailsUnder(ctx, t, tunnel)
}

func establishFailsUnder(ctx context.Context, t *testing.T, tunnel *internal.ReverseTunnel) error {
	t.Helper()
	_, err := tunnel.Establish(ctx)
	tunnel.Close()
	require.Error(t, err)
	return err
}

func freshSigners(t *testing.T, n int) []ssh.Signer {
	t.Helper()
	signers := make([]ssh.Signer, n)
	for i := range signers {
		signer, err := NewHostKey()
		require.NoError(t, err)
		signers[i] = signer
	}
	return signers
}

// startRefusingServer is an x/crypto SSH server that refuses every key and
// disconnects a client that has been refused maxTries times, as a relay with
// that MaxAuthTries does.
func startRefusingServer(t *testing.T, maxTries int) *url.URL {
	t.Helper()
	hostKey, err := NewHostKey()
	require.NoError(t, err)
	config := &ssh.ServerConfig{
		MaxAuthTries: maxTries,
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("key refused")
		},
	}
	config.AddHostKey(hostKey)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if sconn, _, _, err := ssh.NewServerConn(conn, config); err == nil {
					_ = sconn.Close()
				}
			}()
		}
	}()
	return &url.URL{Scheme: "ssh", Host: ln.Addr().String()}
}

// The reasons are a stable contract for integrations, so they are spelled out
// here, not read back from the constants under test.
func TestClassifyReasonsAreTheDocumentedStrings(t *testing.T) {
	require.Equal(t, "reconnecting", sessiondir.StatusReconnecting)
	require.Equal(t, []string{
		"network", "relay_error", "agent_unavailable", "agent_refused", "auth_refused",
		"relay_key_changed", "relay_unsupported", "proof_refused", "reconnect_unsupported",
	}, []string{
		sessiondir.TunnelReasonNetwork,
		sessiondir.TunnelReasonRelayError,
		sessiondir.TunnelReasonAgentUnavailable,
		sessiondir.TunnelReasonAgentRefused,
		sessiondir.TunnelReasonAuthRefused,
		sessiondir.TunnelReasonRelayKeyChanged,
		sessiondir.TunnelReasonRelayUnsupported,
		sessiondir.TunnelReasonProofRefused,
		sessiondir.TunnelReasonReconnectUnsupported,
	})
	require.Equal(t, "supported", sessiondir.ReconnectSupported)
	require.Equal(t, "unsupported", sessiondir.ReconnectUnsupported)
}

func TestClassify(t *testing.T) {
	runClassifyCases(t, []classifyCase{
		// Real handshakes.
		{
			name: "a relay key other than the recorded one",
			err: func(t *testing.T) error {
				recorded := freshSigners(t, 1)[0].PublicKey()
				var authority internal.RelayAuthority
				require.NoError(t, authority.Wrap(ssh.FixedHostKey(recorded))("relay:22", nil, recorded))

				relayKey, err := NewHostKey()
				require.NoError(t, err)
				relay := fakerelay.Start(t, relayKey, fakerelay.RandomID)
				err = establishFails(t, classifyTunnel(t,
					&url.URL{Scheme: "ssh", Host: relay.Addr}, freshSigners(t, 1), authority.Pinned()))

				var changed *internal.RelayKeyChangedError
				require.ErrorAs(t, err, &changed, "the chain must survive x/crypto's wrapping")
				return err
			},
			reason: sessiondir.TunnelReasonRelayKeyChanged, class: blocked,
		},
		{
			name: "a relay that refuses every key offered",
			err: func(t *testing.T) error {
				// Few keys, so that the refusals stay below the server's limit.
				err := establishFails(t, classifyTunnel(t,
					startRefusingServer(t, 6), freshSigners(t, 2), ssh.InsecureIgnoreHostKey()))

				var denied *internal.PermissionDeniedError
				require.ErrorAs(t, err, &denied)
				return err
			},
			reason: sessiondir.TunnelReasonAuthRefused, class: blocked,
		},
		{
			// x/crypto's disconnect is an unexported type, so only its text
			// says it. A host with more keys than the relay's MaxAuthTries gets
			// this rather than "unable to authenticate".
			name: "a relay that disconnects a host that has offered too many keys",
			err: func(t *testing.T) error {
				err := establishFails(t, classifyTunnel(t,
					startRefusingServer(t, 2), freshSigners(t, 3), ssh.InsecureIgnoreHostKey()))

				var denied *internal.PermissionDeniedError
				require.NotErrorAs(t, err, &denied, "this is the case the permission denial does not cover")
				require.ErrorContains(t, err, "too many authentication failures")
				return err
			},
			reason: sessiondir.TunnelReasonAuthRefused, class: blocked,
		},
		{
			name: "a proxy that wants credentials",
			err: func(t *testing.T) error {
				proxy := httpproxytest.Start(t, 407)
				tunnel := classifyTunnel(t, &url.URL{Scheme: "ssh", Host: "relay.test:22"}, freshSigners(t, 1), ssh.InsecureIgnoreHostKey())
				tunnel.ProxyURL = proxy.URL
				err := establishFails(t, tunnel)
				require.ErrorContains(t, err, "407")
				return err
			},
			reason: sessiondir.TunnelReasonNetwork, class: transient,
		},
		{
			name: "a connection refused",
			err: func(t *testing.T) error {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				addr := ln.Addr().String()
				require.NoError(t, ln.Close())
				return establishFails(t, classifyTunnel(t,
					&url.URL{Scheme: "ssh", Host: addr}, freshSigners(t, 1), ssh.InsecureIgnoreHostKey()))
			},
			reason: sessiondir.TunnelReasonNetwork, class: transient,
		},

		// Errors the rest of the host produces.
		{
			name:   "an agent that cannot be reached",
			err:    fixedErr(fmt.Errorf("ssh dial error: %w", &AgentUnavailableError{Socket: "/run/agent", Err: errors.New("connection refused")})),
			reason: sessiondir.TunnelReasonAgentUnavailable, class: transient,
		},
		{
			name:   "an agent that did not sign",
			err:    fixedErr(fmt.Errorf("ssh dial error: %w", &AgentRefusedError{Key: "SHA256:x", Err: errNoLongerHeld})),
			reason: sessiondir.TunnelReasonAgentRefused, class: blocked,
		},
		{
			// A signing failure is never an authentication refusal, whatever
			// text it carries: the agent's errors are matched before any
			// authentication text.
			name: "an agent failure that reads as too many authentication failures",
			err: fixedErr(&AgentRefusedError{
				Key: "SHA256:x",
				Err: errors.New(`ssh: disconnect, reason 2: "too many authentication failures"`),
			}),
			reason: sessiondir.TunnelReasonAgentRefused, class: blocked,
		},
		{
			name:   "a proof the relay refused",
			err:    fixedErr(fmt.Errorf("error creating session: %w", &internal.CreateSessionRefusedError{Body: registration.RefusedProof + ": bad"})),
			reason: sessiondir.TunnelReasonProofRefused, class: blocked,
		},
		{
			name:   "a registration that lost a race",
			err:    fixedErr(fmt.Errorf("error creating session: %w", &internal.CreateSessionRefusedError{Body: registration.Superseded})),
			reason: sessiondir.TunnelReasonRelayError, class: transient,
		},
		{
			name:   "a relay whose store is down",
			err:    fixedErr(fmt.Errorf("error creating session: %w", &internal.CreateSessionRefusedError{Body: "failed to create session: consul down"})),
			reason: sessiondir.TunnelReasonRelayError, class: transient,
		},
		{
			name:   "a refusal nothing here has seen",
			err:    fixedErr(fmt.Errorf("error creating session: %w", &internal.CreateSessionRefusedError{Body: "something new"})),
			reason: sessiondir.TunnelReasonRelayError, class: transient,
		},
		{
			// Only a body that starts with the refusal is one.
			name:   "a body that merely mentions the proof refusal",
			err:    fixedErr(&internal.CreateSessionRefusedError{Body: "failed to create session: " + registration.RefusedProof}),
			reason: sessiondir.TunnelReasonRelayError, class: transient,
		},
		{
			name:   "a listener the relay refused",
			err:    fixedErr(&internal.ForwardRefusedError{}),
			reason: sessiondir.TunnelReasonRelayError, class: transient,
		},
		{
			name:   "a relay without proofs",
			err:    fixedErr(fmt.Errorf("x: %w", internal.ErrRelayUnsupported)),
			reason: sessiondir.TunnelReasonRelayUnsupported, class: blocked,
		},
		{
			name:   "an attempt that ran out of time",
			err:    fixedErr(context.DeadlineExceeded),
			reason: sessiondir.TunnelReasonNetwork, class: transient,
		},
		{
			name:   "a connection cut off",
			err:    fixedErr(io.EOF),
			reason: sessiondir.TunnelReasonNetwork, class: transient,
		},
		{
			name:   "an error nothing here has seen",
			err:    fixedErr(errors.New("something new")),
			reason: sessiondir.TunnelReasonNetwork, class: transient,
		},
	})
}
