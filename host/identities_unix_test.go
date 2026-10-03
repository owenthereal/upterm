//go:build !windows

package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/testhelpers/fakerelay"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// lateWake is how late a woken goroutine may run on a loaded CI runner under
// -race (server/lease_test.go). A close is asserted never to come before its
// deadline, and at most this long after it.
const lateWake = 150 * time.Millisecond

func newRSA(t *testing.T) (ssh.PublicKey, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return pub, priv
}

// sshServer is an x/crypto SSH server that admits the keys admit accepts, and
// records every key a client offers.
func sshServer(t *testing.T, admit func(ssh.PublicKey) bool) *fakerelay.Relay {
	t.Helper()
	hostKey, err := NewHostKey()
	require.NoError(t, err)
	r := fakerelay.Start(t, hostKey, fakerelay.RandomID)
	r.Admit(admit)
	return r
}

// handshake authenticates to r with ssh.PublicKeys(signers...), the one method
// a redial configures, and returns the handshake's error.
func handshake(t *testing.T, r *fakerelay.Relay, signers []ssh.Signer) error {
	t.Helper()
	client, err := ssh.Dial("tcp", r.Addr, &ssh.ClientConfig{
		User:            "host",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		return err
	}
	_ = client.Close()
	return nil
}

func admitting(keys ...ssh.PublicKey) func(ssh.PublicKey) bool {
	return func(k ssh.PublicKey) bool {
		for _, want := range keys {
			if bytes.Equal(k.Marshal(), want.Marshal()) {
				return true
			}
		}
		return false
	}
}

func refusingAll(ssh.PublicKey) bool { return false }

// publicKeys is each signer's public key, marshalled, in order.
func publicKeys(signers []ssh.Signer) [][]byte {
	var out [][]byte
	for _, s := range signers {
		out = append(out, s.PublicKey().Marshal())
	}
	return out
}

func marshalled(keys ...ssh.PublicKey) [][]byte {
	var out [][]byte
	for _, k := range keys {
		out = append(out, k.Marshal())
	}
	return out
}

// offered is every key r was offered, marshalled, in order.
func offered(r *fakerelay.Relay) [][]byte { return marshalled(r.Offered()...) }

// agentIdentities is what SignersWith records with SSH_AUTH_SOCK at ag: the
// agent's keys, each an *agentIdentity carrying ag's socket. The start
// connection is closed, and the agent has seen it close, when it returns, so
// the agent's counters are settled and a redial can't lean on it.
func agentIdentities(t *testing.T, ag *testAgent, want ...ssh.PublicKey) []ssh.Signer {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", ag.socket)
	ended := ag.ended.Load()
	recorded, closeStart, err := SignersWith(SignerOptions{Passphrase: failingPrompt(t)})
	require.NoError(t, err)
	requireAgentIdentities(t, recorded, ag.socket, want...)
	closeStart()
	ag.awaitEnded(t, ended+1)
	return recorded
}

func requireAgentIdentities(t *testing.T, recorded []ssh.Signer, socket string, want ...ssh.PublicKey) {
	t.Helper()
	require.Equal(t, marshalled(want...), publicKeys(recorded))
	for _, s := range recorded {
		id, ok := s.(*agentIdentity)
		require.True(t, ok, "SignersWith returns an agent's key as an *agentIdentity, not %T", s)
		require.Equal(t, socket, id.socket)
	}
}

// receive is <-ch, failing the test if nothing arrives within 5 s.
func receive[T any](t *testing.T, ch <-chan T, failure string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal(failure)
		panic("unreachable")
	}
}

// sign signs as client authentication does, through SignWithAlgorithm.
func sign(t *testing.T, s ssh.Signer, algorithm string) (*ssh.Signature, error) {
	t.Helper()
	as, ok := s.(ssh.AlgorithmSigner)
	require.True(t, ok, "%T is not an ssh.AlgorithmSigner", s)
	return as.SignWithAlgorithm(rand.Reader, []byte("authenticate"), algorithm)
}

// Spec §5.6's question, answered: an RSA agent key is offered with no agent
// contact, and the one signature asks the agent for the same RSA-SHA2
// algorithm its own signer is asked for.
func TestRedialOffersRecordedAgentKeysWithoutContactingTheAgent(t *testing.T) {
	edPub, edPriv := newEd25519(t)
	rsaPub, rsaPriv := newRSA(t)
	ag := startTestAgent(t, edPriv, rsaPriv)
	t.Setenv("SSH_AUTH_SOCK", ag.socket)
	recorded, closeStart, err := SignersWith(SignerOptions{Passphrase: failingPrompt(t)})
	require.NoError(t, err)
	requireAgentIdentities(t, recorded, ag.socket, edPub, rsaPub)

	// The first connection signs through the wrapper, as before. What the
	// agent is asked for here is what its own signer gets.
	accepting := sshServer(t, admitting(rsaPub))
	require.NoError(t, handshake(t, accepting, recorded))
	eagerFlags := ag.flags.Load()
	require.NotZero(t, eagerFlags, "an RSA-SHA2 algorithm, not ssh-rsa")
	closeStart()
	ag.awaitEnded(t, 1)
	before, signatures := ag.accepts.Load(), ag.signatures.Load()

	refusing := sshServer(t, refusingAll)
	signers, closeAgent := redialIdentities(t.Context(), recorded, nil, false)
	require.Equal(t, publicKeys(recorded), publicKeys(signers), "the recorded public keys, in order")
	for _, s := range signers {
		_, isAlgorithmSigner := s.(ssh.AlgorithmSigner)
		_, isMulti := s.(ssh.MultiAlgorithmSigner)
		require.True(t, isAlgorithmSigner, "%T", s)
		require.False(t, isMulti, "an ssh.AlgorithmSigner and nothing more, as the agent's own signer is")
		_, eager := s.(*agentIdentity)
		require.False(t, eager, "a redial never signs through the start connection")
	}
	require.Error(t, handshake(t, refusing, signers))
	closeAgent()
	require.Equal(t, before, ag.accepts.Load(), "offering made agent contact")
	require.Equal(t, marshalled(edPub, rsaPub), offered(refusing))

	signers, closeAgent = redialIdentities(t.Context(), recorded, nil, false)
	require.NoError(t, handshake(t, accepting, signers))
	closeAgent()
	require.Equal(t, before+1, ag.accepts.Load(), "signing is one fresh agent connection")
	require.Equal(t, signatures+1, ag.signatures.Load())
	require.Equal(t, eagerFlags, ag.flags.Load(), "asked for the algorithm the agent's own signer is")

	// And rsa-sha2-512, when a relay asks for only that.
	signers, closeAgent = redialIdentities(t.Context(), recorded, nil, false)
	defer closeAgent()
	sig, err := sign(t, signers[1], ssh.KeyAlgoRSASHA512)
	require.NoError(t, err)
	require.Equal(t, ssh.KeyAlgoRSASHA512, sig.Format)
	require.EqualValues(t, agent.SignatureFlagRsaSha512, ag.flags.Load())
	require.NoError(t, rsaPub.Verify([]byte("authenticate"), sig))
}

func TestRedialSignsThroughOneAgentConnectionPerAttempt(t *testing.T) {
	edPub, edPriv := newEd25519(t)
	otherPub, otherPriv := newEd25519(t)
	ag := startTestAgent(t, edPriv, otherPriv)
	recorded := agentIdentities(t, ag, edPub, otherPub)
	before := ag.accepts.Load()

	signers, closeAgent := redialIdentities(t.Context(), recorded, nil, false)
	defer closeAgent()
	for i, pub := range []ssh.PublicKey{edPub, otherPub} {
		sig, err := sign(t, signers[i], "")
		require.NoError(t, err)
		require.NoError(t, pub.Verify([]byte("authenticate"), sig), "signed by the recorded key")
	}
	require.Equal(t, before+1, ag.accepts.Load(), "the attempt's signers share one connection")
	require.EqualValues(t, 2, ag.signatures.Load())
}

func TestRedialAfterTheAgentRestartsAtTheSameSocket(t *testing.T) {
	edPub, edPriv := newEd25519(t)
	ag := startTestAgent(t, edPriv)
	recorded := agentIdentities(t, ag, edPub)

	ag.stop()
	ag.restart(t, edPriv)

	accepting := sshServer(t, admitting(edPub))
	signers, closeAgent := redialIdentities(t.Context(), recorded, nil, false)
	defer closeAgent()
	require.NoError(t, handshake(t, accepting, signers))
	require.EqualValues(t, 1, ag.signatures.Load(), "the restarted agent signed")
}

func TestRedialAgentFailures(t *testing.T) {
	t.Run("no agent to reach is AgentUnavailableError", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			socket func(t *testing.T, ag *testAgent) string
		}{
			{"stopped", func(t *testing.T, ag *testAgent) string {
				ag.stop()
				return ag.socket
			}},
			{"a stale socket refuses", func(t *testing.T, ag *testAgent) string {
				ag.stop()
				ln, err := net.Listen("unix", ag.socket)
				require.NoError(t, err)
				ln.(*net.UnixListener).SetUnlinkOnClose(false)
				require.NoError(t, ln.Close())
				return ag.socket
			}},
			{"no SSH_AUTH_SOCK recorded", func(*testing.T, *testAgent) string { return "" }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				edPub, edPriv := newEd25519(t)
				ag := startTestAgent(t, edPriv)
				recorded := agentIdentities(t, ag, edPub)
				socket := tc.socket(t, ag)
				recorded[0].(*agentIdentity).socket = socket

				signers, closeAgent := redialIdentities(t.Context(), recorded, nil, false)
				defer closeAgent()
				err := handshake(t, sshServer(t, admitting(edPub)), signers)
				var unavailable *AgentUnavailableError
				require.ErrorAs(t, err, &unavailable, "the handshake keeps the signer's error")
				require.Equal(t, socket, unavailable.Socket)
				require.Error(t, unavailable.Err)
			})
		}
	})

	t.Run("an agent that never answers is AgentRefusedError at the deadline", func(t *testing.T) {
		edPub, edPriv := newEd25519(t)
		ag := startTestAgent(t, edPriv)
		recorded := agentIdentities(t, ag, edPub)
		ag.stop()
		ag.restartSilent(t)

		for attempt := int32(1); attempt <= 2; attempt++ {
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			deadline, _ := ctx.Deadline()
			signers, closeAgent := redialIdentities(ctx, recorded, nil, false)
			disarm := context.AfterFunc(ctx, closeAgent)

			_, err := sign(t, signers[0], "")
			returned := time.Now()
			var refused *AgentRefusedError
			require.ErrorAs(t, err, &refused)
			require.Equal(t, utils.FingerprintSHA256(edPub), refused.Key)
			require.False(t, returned.Before(deadline), "released before the deadline")
			require.LessOrEqual(t, returned.Sub(deadline), lateWake, "released long after the deadline")

			// The start connection, then one per attempt.
			ag.awaitEnded(t, 1+attempt)
			require.Equal(t, 1+attempt, ag.accepts.Load(), "each attempt opens a new connection")
			require.Zero(t, ag.open(), "the attempt's connection is closed")
			disarm()
			cancel()
		}
	})

	t.Run("closeAgent before the first signature", func(t *testing.T) {
		edPub, edPriv := newEd25519(t)
		ag := startTestAgent(t, edPriv)
		recorded := agentIdentities(t, ag, edPub)
		before := ag.accepts.Load()

		signers, closeAgent := redialIdentities(t.Context(), recorded, nil, false)
		closeAgent()
		closeAgent() // idempotent
		start := time.Now()
		_, err := sign(t, signers[0], "")
		var refused *AgentRefusedError
		require.ErrorAs(t, err, &refused, "the attempt is over")
		require.LessOrEqual(t, time.Since(start), lateWake, "fails at once")
		require.Equal(t, before, ag.accepts.Load(), "never dialled")
		require.Zero(t, ag.open())
	})

	t.Run("closeAgent while the dial is under way", func(t *testing.T) {
		edPub, edPriv := newEd25519(t)
		ag := startTestAgent(t, edPriv)
		recorded := agentIdentities(t, ag, edPub)
		before, ended := ag.accepts.Load(), ag.ended.Load()

		signers, closeAgent := redialIdentities(t.Context(), recorded, nil, false)
		lazy := signers[0].(*lazyIdentity)
		dialed, release := make(chan struct{}), make(chan struct{})
		lazy.agent.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := new(net.Dialer).DialContext(ctx, network, address)
			close(dialed)
			<-release
			return conn, err
		}
		errc := make(chan error, 1)
		go func() {
			_, err := lazy.Sign(rand.Reader, []byte("authenticate"))
			errc <- err
		}()

		// The connection exists, and DialContext hasn't returned it.
		receive(t, dialed, "the dial never ran")
		closed := make(chan struct{})
		go func() {
			closeAgent()
			close(closed)
		}()
		receive(t, closed, "closeAgent waited on the dial")
		close(release)
		var refused *AgentRefusedError
		require.ErrorAs(t, receive(t, errc, "the signature never returned"), &refused, "a dial that completes after closeAgent is over")
		ag.awaitEnded(t, ended+1)
		require.Equal(t, before+1, ag.accepts.Load(), "the dial reached the agent")
		require.Zero(t, ag.open(), "the late connection was closed at once")
		require.Zero(t, ag.signatures.Load())
	})

	// Review Focus 3: a redial offers only the recorded identities, whatever
	// the agent holds now.
	t.Run("an agent restarted without the recorded key", func(t *testing.T) {
		edPub, edPriv := newEd25519(t)
		rsaPub, rsaPriv := newRSA(t)
		newPub, newPriv := newEd25519(t)
		ag := startTestAgent(t, edPriv, rsaPriv)
		recorded := agentIdentities(t, ag, edPub, rsaPub)
		ag.stop()
		ag.restart(t, edPriv, newPriv)

		// The relay would take the recorded RSA key, or the agent's new one.
		either := sshServer(t, admitting(rsaPub, newPub))
		signers, closeAgent := redialIdentities(t.Context(), recorded, nil, false)
		err := handshake(t, either, signers)
		closeAgent()
		var refused *AgentRefusedError
		require.ErrorAs(t, err, &refused)
		require.Equal(t, utils.FingerprintSHA256(rsaPub), refused.Key)
		require.Equal(t, marshalled(edPub, rsaPub), offered(either), "only the recorded keys")

		// A relay that takes only the new key is never offered it.
		before := ag.accepts.Load()
		onlyNew := sshServer(t, admitting(newPub))
		signers, closeAgent = redialIdentities(t.Context(), recorded, nil, false)
		err = handshake(t, onlyNew, signers)
		closeAgent()
		require.ErrorContains(t, err, "unable to authenticate")
		require.Equal(t, marshalled(edPub, rsaPub), offered(onlyNew), "only the recorded keys")
		require.Equal(t, before, ag.accepts.Load(), "nothing to sign, so no agent contact")
		require.Zero(t, ag.signatures.Load())
	})
}

func TestRedialSessionKeyFirst(t *testing.T) {
	agentPub, agentPriv := newEd25519(t)
	ag := startTestAgent(t, agentPriv)
	t.Setenv("SSH_AUTH_SOCK", ag.socket)

	dir := t.TempDir()
	keyFile := func(name string) (string, ssh.PublicKey) {
		pub, priv := newEd25519(t)
		block, err := ssh.MarshalPrivateKey(priv, "")
		require.NoError(t, err)
		return writeTestFile(t, dir, name, pem.EncodeToMemory(block)), pub
	}
	file1, pub1 := keyFile("one")
	file2, pub2 := keyFile("two")
	selector := writeTestFile(t, dir, "agent.pub", ssh.MarshalAuthorizedKey(agentPub))

	// --private-key, in the order given: a file, an agent key, a file.
	recorded, closeStart, err := SignersWith(SignerOptions{
		PrivateKeys:    []string{file1, selector, file2},
		IdentitiesOnly: true,
		Passphrase:     failingPrompt(t),
	})
	require.NoError(t, err)
	closeStart()
	require.Equal(t, marshalled(pub1, agentPub, pub2), publicKeys(recorded))
	requireAgentIdentities(t, recorded[1:2], ag.socket, agentPub)
	for _, i := range []int{0, 2} {
		_, wrapped := recorded[i].(*agentIdentity)
		require.False(t, wrapped, "a file key is returned as it always was")
	}

	sessionKey, err := NewHostKey()
	require.NoError(t, err)
	before := ag.accepts.Load()

	t.Run("with the session key", func(t *testing.T) {
		signers, closeAgent := redialIdentities(t.Context(), recorded, sessionKey, true)
		defer closeAgent()
		require.Equal(t, marshalled(sessionKey.PublicKey(), pub1, agentPub, pub2), publicKeys(signers))
		require.Same(t, sessionKey, signers[0])
		require.Same(t, recorded[0], signers[1], "a file key is offered as is")
		require.Same(t, recorded[2], signers[3], "a file key is offered as is")

		// Such a redial makes no contact with the agent at all.
		require.NoError(t, handshake(t, sshServer(t, admitting(sessionKey.PublicKey())), signers))
		require.Equal(t, before, ag.accepts.Load())
	})

	t.Run("without it", func(t *testing.T) {
		signers, closeAgent := redialIdentities(t.Context(), recorded, sessionKey, false)
		defer closeAgent()
		require.Equal(t, marshalled(pub1, agentPub, pub2), publicKeys(signers))

		relay := sshServer(t, admitting(agentPub))
		require.NoError(t, handshake(t, relay, signers))
		require.Equal(t, marshalled(pub1, agentPub), offered(relay), "in --private-key's order, and no session key")
		require.Equal(t, before+1, ag.accepts.Load(), "the agent key signed")
	})
}
