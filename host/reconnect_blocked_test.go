//go:build !windows

package host

import (
	"encoding/pem"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/testhelpers/fakerelay"
	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// withSigners has the host offer signers, in place of the fixture's one key.
func withSigners(signers []ssh.Signer) reconnectOption {
	return func(f *reconnectHost) { f.h.Signers = signers }
}

// signersWith is what the CLI's host offers with SSH_AUTH_SOCK at ag:
// SignersWith's identities for opts. The connection they came with is closed
// when the test ends, as the CLI closes it when the session does.
func signersWith(t *testing.T, ag *testAgent, opts SignerOptions) []ssh.Signer {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", ag.socket)
	opts.Passphrase = failingPrompt(t)
	signers, closeStart, err := SignersWith(opts)
	require.NoError(t, err)
	if closeStart != nil {
		t.Cleanup(closeStart)
	}
	return signers
}

// fileIdentities writes n unencrypted ed25519 keys, a file each, and returns
// the files and their public keys, in order.
func fileIdentities(t *testing.T, n int) ([]string, []ssh.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	var (
		files []string
		pubs  []ssh.PublicKey
	)
	for i := range n {
		pub, priv := newEd25519(t)
		block, err := ssh.MarshalPrivateKey(priv, "")
		require.NoError(t, err)
		files = append(files, writeTestFile(t, dir, fmt.Sprintf("id%d", i+1), pem.EncodeToMemory(block)))
		pubs = append(pubs, pub)
	}
	return files, pubs
}

// authorizedKeysFile writes keys as an authorized_keys file, for a relay that
// admits only them as hosts.
func authorizedKeysFile(t *testing.T, keys ...ssh.PublicKey) string {
	t.Helper()
	var b []byte
	for _, k := range keys {
		b = append(b, ssh.MarshalAuthorizedKey(k)...)
	}
	return writeTestFile(t, t.TempDir(), "authorized_keys", b)
}

// failedRedial is one attempt the host logged as failed: its generation, why
// it failed, how the next is paced, the wait before the next, and the error.
type failedRedial struct {
	generation uint64
	reason     string
	class      string
	wait       time.Duration
	err        string
}

var failedRedialAttrs = regexp.MustCompile(`\bgeneration=(\d+) reason=(\S+) class=(\S+) wait=(\S+) error=(.*)$`)

// failedRedials is every failed attempt in the host's log, in order.
func (f *reconnectHost) failedRedials(t *testing.T) []failedRedial {
	t.Helper()
	var out []failedRedial
	for _, line := range strings.Split(f.logs.String(), "\n") {
		if !strings.Contains(line, `msg="failed to reconnect the tunnel"`) {
			continue
		}
		m := failedRedialAttrs.FindStringSubmatch(line)
		require.NotNil(t, m, "a failed attempt was logged without its attributes: %s", line)
		generation, err := strconv.ParseUint(m[1], 10, 64)
		require.NoError(t, err)
		wait, err := time.ParseDuration(m[4])
		require.NoError(t, err)
		out = append(out, failedRedial{generation: generation, reason: m[2], class: m[3], wait: wait, err: m[5]})
	}
	return out
}

// requireBlockedTwice checks that exactly two attempts failed, the two after
// the first connection, each refused for reason: the first was retried on the
// fast schedule, and the second waited out on the slow one.
func (f *reconnectHost) requireBlockedTwice(t *testing.T, reason string) {
	t.Helper()
	timing := f.h.Reconnect
	redials := f.failedRedials(t)
	require.Len(t, redials, 2, "%+v", redials)
	for i, r := range redials {
		require.Equal(t, uint64(i+2), r.generation, "%+v", redials)
		require.Equal(t, reason, r.reason, "%+v", redials)
		require.Equal(t, blocked.String(), r.class, "%+v", redials)
	}
	require.LessOrEqual(t, redials[0].wait, timing.FastCap, "the first refusal is retried on the fast schedule")
	require.GreaterOrEqual(t, redials[1].wait, timing.SlowWait, "the second is waited out on the slow schedule")
	require.LessOrEqual(t, redials[1].wait, timing.SlowWait+timing.SlowJitter)
}

// awaitSlowWait polls the record until the host is waiting out the slow
// schedule after an attempt that failed for reason, and returns that record.
// A wait longer than the fast schedule's cap is the slow one: the time is
// taken after the read, so the wait the record was written with is at least
// what is left of it.
func (f *reconnectHost) awaitSlowWait(t *testing.T, reason string, within time.Duration) *sessiondir.Record {
	t.Helper()
	timing := f.h.Reconnect
	deadline := time.Now().Add(within)
	for {
		rec, err := sessiondir.ReadRecord(f.stateRoot, f.h.Name)
		readAt := time.Now()
		if err == nil && rec.Status == sessiondir.StatusReconnecting && rec.TunnelReason == reason &&
			rec.NextAttemptAt.Sub(readAt) > timing.FastCap {
			require.LessOrEqual(t, rec.NextAttemptAt.Sub(readAt), timing.SlowWait+timing.SlowJitter,
				"the next attempt is further out than the slow schedule goes")
			require.NotEmpty(t, rec.TunnelError)
			return rec
		}
		if readAt.After(deadline) {
			if err != nil {
				t.Fatalf("the host never settled into the slow wait within %s: %v", within, err)
			}
			t.Fatalf("the host never settled into the slow wait after %s within %s; the record says %s (reason %q, next attempt %s, error %q)",
				reason, within, rec.Status, rec.TunnelReason, rec.NextAttemptAt, rec.TunnelError)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// awaitRedialled polls until relay holds the session under generation or a
// later one, and the record says ready, and returns the record and the
// generation the relay holds. The generation is read first: a ready read after
// it is the redial's, and not one written before the loss was noticed.
func (f *reconnectHost) awaitRedialled(t *testing.T, relay *reconnectRelay, generation uint64, within time.Duration) (*sessiondir.Record, uint64) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		var held uint64
		if sess, err := relay.sessions.GetSession(f.created.SessionId); err == nil {
			held = sess.Generation
		}
		rec, err := sessiondir.ReadRecord(f.stateRoot, f.h.Name)
		if held >= generation && err == nil && rec.Status == sessiondir.StatusReady {
			return rec, held
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("the session was never redialled within %s (the relay holds generation %d): %v", within, held, err)
			}
			t.Fatalf("the session was never redialled within %s: the relay holds generation %d, not %d, and the record says %s (reason %q, error %q)",
				within, held, generation, rec.Status, rec.TunnelReason, rec.TunnelError)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// requireUp checks a record of a tunnel that is up: nothing of an outage is
// left on it.
func requireUp(t *testing.T, rec *sessiondir.Record) {
	t.Helper()
	require.Equal(t, sessiondir.StatusReady, rec.Status)
	require.Zero(t, rec.TunnelReason)
	require.Zero(t, rec.TunnelError)
	require.Zero(t, rec.NextAttemptAt)
}

// requireNoPrompt checks the host's own callback was asked once, by the first
// connection: a redial is checked against the key it accepted, and never
// prompts.
func (f *reconnectHost) requireNoPrompt(t *testing.T) {
	t.Helper()
	require.EqualValues(t, 1, f.hostKeyChecks.Load(), "a redial asked the host's own host key callback")
}

// A relay that stops admitting the host's key refuses the redial. The host
// retries once on the fast schedule, then waits out the slow one, and never
// prompts. Once the relay admits the key again, the attempt after the wait
// brings the session back under the same ID.
func TestBlockedRedialRecoversOnceTheKeyIsAdmittedAgain(t *testing.T) {
	for _, scheme := range []string{"ssh", "ws"} {
		t.Run(scheme, func(t *testing.T) {
			f := newReconnectHost(t, scheme)
			f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)

			// The same relay key, admitting only a key that isn't the host's.
			stranger, _ := newEd25519(t)
			gated := startRelay(t, f.relay.key, withAuthorizedKeysFiles(authorizedKeysFile(t, stranger)))
			f.fwd.Redirect(gated.addr(scheme))
			f.fwd.Cut()
			waiting := f.awaitSlowWait(t, sessiondir.TunnelReasonAuthRefused, 5*time.Second)

			f.fwd.Redirect(f.relay.addr(scheme))
			rec, generation := f.awaitRedialled(t, f.relay, 4, time.Until(waiting.NextAttemptAt)+2*time.Second)
			require.EqualValues(t, 4, generation, "the attempt after the slow wait is the one that came back")
			requireUp(t, rec)
			f.requireBlockedTwice(t, sessiondir.TunnelReasonAuthRefused)
			f.requireNoPrompt(t)
		})
	}
}

// A node that registers the redial under an ID of its own can't find the
// session again. The host takes nothing forwarded there, retries once on the
// fast schedule and then waits out the slow one; a node that registers it
// under the same ID brings it back.
func TestBlockedRedialRecoversFromANodeThatCantTakeTheSessionBack(t *testing.T) {
	f := newReconnectHost(t, "ssh")
	f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)

	fake := fakerelay.Start(t, f.relay.key, fakerelay.RandomID)
	f.fwd.Redirect(fake.Addr)
	f.fwd.Cut()
	waiting := f.awaitSlowWait(t, sessiondir.TunnelReasonRelayUnsupported, 5*time.Second)

	f.fwd.Redirect(f.relay.addr("ssh"))
	rec, generation := f.awaitRedialled(t, f.relay, 4, time.Until(waiting.NextAttemptAt)+2*time.Second)
	require.EqualValues(t, 4, generation, "the attempt after the slow wait is the one that came back")
	requireUp(t, rec)
	f.requireBlockedTwice(t, sessiondir.TunnelReasonRelayUnsupported)
	require.Equal(t, 2, fake.Connections())
	require.Zero(t, fake.Forwards(), "the session was served on a node that can't find it again")
	f.requireNoPrompt(t)
}

// countingStdin answers a host key prompt from r, and counts every read.
type countingStdin struct {
	r     io.Reader
	reads atomic.Int32
}

func (s *countingStdin) Read(p []byte) (int, error) {
	s.reads.Add(1)
	return s.r.Read(p)
}

// A relay that comes back under another key is never accepted, and never
// asked about: the CLI's own prompt answers the first connection, and no
// redial reads stdin or prompts. The host retries once on the fast schedule,
// then waits out the slow one, and comes back when the original key does.
func TestBlockedRedialNeverAcceptsAnotherRelayKey(t *testing.T) {
	for _, scheme := range []string{"ssh", "ws"} {
		t.Run(scheme, func(t *testing.T) {
			stdin := &countingStdin{r: strings.NewReader("yes\n")}
			prompts := &lockedBuffer{}
			f := newReconnectHost(t, scheme, func(f *reconnectHost) {
				cb, err := NewPromptingHostKeyCallback(stdin, prompts, filepath.Join(t.TempDir(), "known_hosts"), false)
				require.NoError(t, err)
				f.h.HostKeyCallback = cb
			})
			f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)
			const asked = "The authenticity of host"
			require.Equal(t, 1, strings.Count(prompts.String(), asked), "the first connection is asked about")
			readsAtStart := stdin.reads.Load()
			require.Positive(t, readsAtStart, "the first connection's answer was read from stdin")

			otherKey, err := NewHostKey()
			require.NoError(t, err)
			f.fwd.Redirect(startRelay(t, otherKey).addr(scheme))
			f.fwd.Cut()
			waiting := f.awaitSlowWait(t, sessiondir.TunnelReasonRelayKeyChanged, 5*time.Second)
			require.Contains(t, waiting.TunnelError, utils.FingerprintSHA256(otherKey.PublicKey()), "the refusal names the key shown")
			f.requireNoPrompt(t)
			require.Equal(t, readsAtStart, stdin.reads.Load(), "a redial read stdin")
			require.Equal(t, 1, strings.Count(prompts.String(), asked), "a redial prompted")

			f.fwd.Redirect(f.relay.addr(scheme))
			rec, generation := f.awaitRedialled(t, f.relay, 4, time.Until(waiting.NextAttemptAt)+2*time.Second)
			require.EqualValues(t, 4, generation, "the attempt after the slow wait is the one that came back")
			requireUp(t, rec)
			f.requireBlockedTwice(t, sessiondir.TunnelReasonRelayKeyChanged)
			f.requireNoPrompt(t)
			require.Equal(t, readsAtStart, stdin.reads.Load())
		})
	}
}

// An agent restarted at the same socket signs the redial: the redial reaches
// it afresh, once, rather than through the connection it started with, which
// went with the agent.
func TestAgentRestartedAtTheSameSocketSignsTheRedial(t *testing.T) {
	agentPub, agentPriv := newEd25519(t)
	ag := startTestAgent(t, agentPriv)
	signers := signersWith(t, ag, SignerOptions{})
	requireAgentIdentities(t, signers, ag.socket, agentPub)
	relayKey, err := NewHostKey()
	require.NoError(t, err)
	// A relay that admits the agent's key alone, so every redial has the
	// agent sign.
	gated := startRelay(t, relayKey, withAuthorizedKeysFiles(authorizedKeysFile(t, agentPub)))
	f := newReconnectHost(t, "ssh", withRelay(gated), withSigners(signers))
	f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)

	ag.stop()
	ag.restart(t, agentPriv)
	accepts, signatures := ag.accepts.Load(), ag.signatures.Load()
	f.fwd.Cut()
	rec, generation := f.awaitRedialled(t, gated, 2, 5*time.Second)
	require.EqualValues(t, 2, generation, "the first attempt came back")
	requireUp(t, rec)
	require.Empty(t, f.failedRedials(t))
	require.Equal(t, accepts+1, ag.accepts.Load(), "the redial reached the restarted agent, once")
	require.Equal(t, signatures+1, ag.signatures.Load(), "the restarted agent signed the redial")
	f.requireNoPrompt(t)
}

// An agent that takes the connection and never answers fails the attempt at
// its deadline, as a refusal: the host retries once on the fast schedule,
// then waits out the slow one rather than go on asking. Each attempt reaches
// the agent once, and leaves no connection to it open.
func TestAgentThatNeverAnswersIsAskedAgainOnlySlowly(t *testing.T) {
	agentPub, agentPriv := newEd25519(t)
	ag := startTestAgent(t, agentPriv)
	signers := signersWith(t, ag, SignerOptions{})
	requireAgentIdentities(t, signers, ag.socket, agentPub)
	relayKey, err := NewHostKey()
	require.NoError(t, err)
	gated := startRelay(t, relayKey, withAuthorizedKeysFiles(authorizedKeysFile(t, agentPub)))
	f := newReconnectHost(t, "ssh", withRelay(gated), withSigners(signers), func(f *reconnectHost) {
		// An attempt that waits on the agent fails in a second, not 30.
		f.h.Reconnect.AttemptDeadline = time.Second
		// No third attempt comes while the test counts the first two.
		f.h.Reconnect.SlowWait = time.Minute
	})
	f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)

	ag.stop()
	ag.restartSilent(t)
	accepts, ended := ag.accepts.Load(), ag.ended.Load()
	f.fwd.Cut()
	// Two attempts, each held to its deadline, and a fast wait between.
	waiting := f.awaitSlowWait(t, sessiondir.TunnelReasonAgentRefused, 10*time.Second)
	require.Contains(t, waiting.TunnelError, errAttemptOver.Error(), "the agent was given up on at the attempt's deadline")
	f.requireBlockedTwice(t, sessiondir.TunnelReasonAgentRefused)
	require.Equal(t, accepts+2, ag.accepts.Load(), "each attempt reached the agent once")
	ag.awaitEnded(t, ended+2)
	require.Zero(t, ag.open(), "an attempt left its agent connection open")
	f.requireNoPrompt(t)
}

// On a relay that lets the session key alone in, a redial signs with the
// session key and never reaches the agent: not even a connection to it.
func TestAgentIsNotReachedWhereTheSessionKeyIsEnough(t *testing.T) {
	agentPub, agentPriv := newEd25519(t)
	ag := startTestAgent(t, agentPriv)
	signers := signersWith(t, ag, SignerOptions{})
	requireAgentIdentities(t, signers, ag.socket, agentPub)
	accepts := ag.accepts.Load()
	f := newReconnectHost(t, "ssh", withSigners(signers))
	f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)
	require.Positive(t, ag.signatures.Load(), "the first connection signed through the agent")
	signatures := ag.signatures.Load()

	f.fwd.Cut()
	rec, generation := f.awaitRedialled(t, f.relay, 2, 5*time.Second)
	require.EqualValues(t, 2, generation, "the first attempt came back")
	requireUp(t, rec)
	require.Empty(t, f.failedRedials(t))
	require.Equal(t, accepts, ag.accepts.Load(), "something connected to the agent after the session started")
	require.Equal(t, signatures, ag.signatures.Load(), "the agent signed the redial")
	f.requireNoPrompt(t)
}

// With IdentitiesOnly, a redial offers the identities named, in order, and
// nothing else: not the session key, even on a relay that would let it alone
// in.
func TestRedialIdentitiesOnlyOffersNoSessionKey(t *testing.T) {
	ag := startTestAgent(t)
	files, pubs := fileIdentities(t, 2)
	signers := signersWith(t, ag, SignerOptions{PrivateKeys: files, IdentitiesOnly: true})
	require.Equal(t, marshalled(pubs...), publicKeys(signers))
	f := newReconnectHost(t, "ssh", withSigners(signers), func(f *reconnectHost) {
		f.h.IdentitiesOnly = true
		// No third attempt comes while the test counts the first two.
		f.h.Reconnect.SlowWait = time.Minute
	})
	f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)

	// The same relay key, refusing every key it is offered and recording it.
	fake := fakerelay.Start(t, f.relay.key, fakerelay.RandomID)
	fake.Admit(refusingAll)
	f.fwd.Redirect(fake.Addr)
	f.fwd.Cut()
	f.awaitSlowWait(t, sessiondir.TunnelReasonAuthRefused, 5*time.Second)
	f.requireBlockedTwice(t, sessiondir.TunnelReasonAuthRefused)
	require.Equal(t, 2, fake.Connections())
	require.Equal(t, marshalled(pubs[0], pubs[1], pubs[0], pubs[1]), offered(fake),
		"each attempt offers the two identities, in order, and no session key")
	require.Zero(t, ag.accepts.Load(), "the agent was reached for identities that are files")
	f.requireNoPrompt(t)
}

// On a relay that admits only the sixth of six identities, every redial
// reaches it: a relay that gates its hosts isn't offered the session key, which
// would have spent the last of the tries it allows.
func TestRedialIdentitiesOnAGatedRelayReachTheSixth(t *testing.T) {
	ag := startTestAgent(t)
	files, pubs := fileIdentities(t, 6)
	signers := signersWith(t, ag, SignerOptions{PrivateKeys: files})
	require.Equal(t, marshalled(pubs...), publicKeys(signers))
	accepts := ag.accepts.Load()
	relayKey, err := NewHostKey()
	require.NoError(t, err)
	gated := startRelay(t, relayKey, withAuthorizedKeysFiles(authorizedKeysFile(t, pubs[5])))
	f := newReconnectHost(t, "ssh", withRelay(gated), withSigners(signers))
	f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)

	for want := uint64(2); want <= 4; want++ {
		f.fwd.Cut()
		rec, generation := f.awaitRedialled(t, gated, want, 5*time.Second)
		require.Equal(t, want, generation, "the first attempt after the cut came back")
		requireUp(t, rec)
	}
	require.Empty(t, f.failedRedials(t))
	require.Equal(t, accepts, ag.accepts.Load(), "something connected to the agent after the session started")
	f.requireNoPrompt(t)
}

// A relay that let the session key alone in, and now admits only the sixth of
// six identities, refuses one attempt: the session key and the first five
// spend every try it allows, and it disconnects. The next attempt leaves the
// session key out, and reaches the sixth.
func TestRedialIdentitiesWhenARelayGainsAGate(t *testing.T) {
	ag := startTestAgent(t)
	files, pubs := fileIdentities(t, 6)
	signers := signersWith(t, ag, SignerOptions{PrivateKeys: files})
	require.Equal(t, marshalled(pubs...), publicKeys(signers))
	f := newReconnectHost(t, "ssh", withSigners(signers))
	f.awaitStatus(t, sessiondir.StatusReady, 5*time.Second)

	gated := startRelay(t, f.relay.key, withAuthorizedKeysFiles(authorizedKeysFile(t, pubs[5])))
	f.fwd.Redirect(gated.addr("ssh"))
	f.fwd.Cut()
	rec, generation := f.awaitRedialled(t, gated, 3, 5*time.Second)
	require.EqualValues(t, 3, generation, "exactly one attempt failed")
	requireUp(t, rec)
	redials := f.failedRedials(t)
	require.Len(t, redials, 1, "%+v", redials)
	require.EqualValues(t, 2, redials[0].generation)
	require.Equal(t, sessiondir.TunnelReasonAuthRefused, redials[0].reason)
	require.Equal(t, blocked.String(), redials[0].class)
	require.Contains(t, redials[0].err, tooManyAuthFailures, "the relay disconnected at its limit of tries")
	require.LessOrEqual(t, redials[0].wait, f.h.Reconnect.FastCap, "the first refusal is retried on the fast schedule")
	f.requireNoPrompt(t)
}
