package join

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestRefusedOnlyOnADefiniteAnswer(t *testing.T) {
	key := newSigner(t)

	// Every key refused, no banner: a refusal.
	ev, err := connect(t, relayKnobs{refuseAll: true}, []ssh.Signer{key})
	v := classifyConnect(err, ev)
	require.Equal(t, vStop, v.kind)
	require.ErrorIs(t, v.err, ErrKeysRefused)

	// The connection drops after the server reads the publickey request:
	// mid-authentication, nothing definite. Unreachable, never refused.
	ev, err = connect(t, relayKnobs{dropOnPublicKey: true}, []ssh.Signer{key})
	v = classifyConnect(err, ev)
	require.Equal(t, vWait, v.kind)
	require.Equal(t, Unreachable, v.why)

	// A signer that fails: an identity failure, never a refusal. No key is
	// offered after it, so a key the relay would let in doesn't hide it.
	ev, err = connect(t, relayKnobs{}, []ssh.Signer{failingSigner{key}, newSigner(t)})
	require.ErrorContains(t, err, "the agent is gone")
	v = classifyConnect(err, ev)
	require.Equal(t, IdentityFailure, v.why)
	require.ErrorIs(t, v.err, ErrIdentity)
}

func TestTheDisconnectAtMaxAuthTriesRefusesOnlyTheKeysJudgedBeforeIt(t *testing.T) {
	keys := sevenSigners(t)

	// The relay counts each refused key against MaxAuthTries, and not the
	// first, empty request. It answers the first five; the sixth refusal is
	// the one it disconnects at instead of answering, so that key wasn't
	// judged, and the seventh was never offered.
	ev, err := connect(t, relayKnobs{refuseAll: true, maxAuthTries: 6}, keys)
	require.ErrorContains(t, err, textTooMany)
	require.Equal(t, verdict{kind: vTooMany}, classifyConnect(err, ev))
	require.Equal(t, fingerprintsOf(keys[:5]), fingerprints(ev.judged))

	// The disconnect is no more evidence than a refusal is from a relay that
	// predates the no-host banner: before it, a session that isn't there
	// turned every key away too.
	ev, err = connect(t, relayKnobs{refuseAll: true, maxAuthTries: 6, version: oldRelay}, keys)
	require.Equal(t, verdict{kind: vTooMany, ambiguous: true}, classifyConnect(err, ev))
	require.Equal(t, fingerprintsOf(keys[:5]), fingerprints(ev.judged))

	// A relay that disconnects at the first refusal judges no key, and the
	// next connection would end the same way: nothing definite, waited out.
	ev, err = connect(t, relayKnobs{refuseAll: true, maxAuthTries: 1}, keys)
	require.ErrorContains(t, err, textTooMany)
	require.Empty(t, ev.judged)
	v := classifyConnect(err, ev)
	require.Equal(t, vWait, v.kind)
	require.Equal(t, Unreachable, v.why)

	// Every key refused short of MaxAuthTries: every one was judged.
	ev, err = connect(t, relayKnobs{refuseAll: true}, keys[:3])
	require.ErrorContains(t, err, textNoMethods)
	require.Equal(t, fingerprintsOf(keys[:3]), fingerprints(ev.judged))
}

func TestBannersClassify(t *testing.T) {
	ev, err := connect(t, relayKnobs{refuseAll: true, banner: fmt.Sprintf(upterm.BannerNoHostFormat, "abc")}, oneSigner(t))
	require.Equal(t, verdict{kind: vWait, why: NoHost}, stripErr(classifyConnect(err, ev)))
	ev, err = connect(t, relayKnobs{refuseAll: true, banner: upterm.BannerLookupFailed}, oneSigner(t))
	require.Equal(t, verdict{kind: vWait, why: RelayLookup}, stripErr(classifyConnect(err, ev)))
}

func TestARefusalNeedsEvidenceFromTheRelaysVersion(t *testing.T) {
	for version, ambiguous := range map[string]bool{
		"SSH-2.0-uptermd-0.33.2":    true,  // below the cutoff: no no-host banner
		"SSH-2.0-uptermd-0.34.0":    false, // at it
		"SSH-2.0-uptermd-0.37.0":    false,
		"SSH-2.0-uptermd-0.0.0+dev": true, // a dev build, of any age
		"SSH-2.0-uptermd-dev":       true, // unparseable
		"SSH-2.0-uptermd-x.y":       true, // malformed
		"SSH-2.0-OpenSSH_9.6":       true, // not uptermd
	} {
		ev, err := connect(t, relayKnobs{refuseAll: true, version: version}, oneSigner(t))
		var refused *RefusedError
		require.ErrorAs(t, classifyConnect(err, ev).err, &refused, version)
		require.Equal(t, ambiguous, refused.Ambiguous, version)
	}

	// An x/crypto server announces its own default for an empty version, so a
	// relay that says nothing can't be staged. The function itself still has to
	// treat it, and what x/crypto never sends, as no evidence.
	require.False(t, relayHasBanners(""))
	require.True(t, relayHasBanners("SSH-2.0-uptermd-1.0.0"))

	// A connection that ended before authentication began never learned the
	// relay's version.
	var refused *RefusedError
	require.ErrorAs(t, classifyConnect(errors.New("ssh: unable to authenticate, attempted methods [none], no supported methods remain"), &evidence{}).err, &refused)
	require.True(t, refused.Ambiguous)
}

func TestChannelRejectionsClassify(t *testing.T) {
	current, older := "SSH-2.0-uptermd-0.37.0", "SSH-2.0-uptermd-0.36.0"
	for _, tc := range []struct {
		msg, version string
		want         verdict
	}{
		{upterm.UpstreamKeyRefused, current, verdict{kind: vRetryNow}},
		{upterm.UpstreamKeyRefused, older, verdict{kind: vRetryNow}},    // the message is the evidence
		{upterm.UpstreamAuthFailed, current, verdict{kind: vAmbiguous}}, // an older node may have received the banner
		{upterm.UpstreamAuthFailed, older, verdict{kind: vAmbiguous}},
		{upterm.UpstreamNoHost, current, verdict{kind: vWait, why: NoHost}},
		{upterm.UpstreamLookupFailed, current, verdict{kind: vWait, why: RelayLookup}},
		{upterm.UpstreamUnavailable, current, verdict{kind: vWait, why: Upstream}},
		{upterm.UpstreamHostKeyMismatch, current, verdict{kind: vStop}},
		{"something new", current, verdict{kind: vWait, why: Setup}},
	} {
		client := relayKnobs{rejectSession: tc.msg, version: tc.version}.dial(t, oneSigner(t))
		_, err := client.NewSession()
		got := classifySetup(fmt.Errorf("attach: %w", err), &evidence{serverVersion: tc.version})
		require.Equal(t, tc.want.kind, got.kind, "%s from %s", tc.msg, tc.version)
		require.Equal(t, tc.want.why, got.why, "%s from %s", tc.msg, tc.version)
	}
}

func TestChannelRejectionsKeepWhatTheyNeedToExplainThemselves(t *testing.T) {
	reject := func(msg string) error {
		return fmt.Errorf("attach: %w", &ssh.OpenChannelError{Reason: ssh.ConnectionFailed, Message: msg})
	}

	// A relay that stops a join over the host's key has said so; the sentinel is
	// the whole answer.
	require.Equal(t, verdict{kind: vStop, err: ErrUpstreamHostKey}, classifySetup(reject(upterm.UpstreamHostKeyMismatch), &evidence{}))

	// A text nothing here knows is kept, to be told to the guest who waits on it.
	got := classifySetup(reject("something new"), &evidence{})
	require.Equal(t, Setup, got.why)
	require.ErrorContains(t, got.err, "something new")

	// So is an error that isn't a rejection at all: the shell never started.
	cause := errors.New("terminal setup timed out")
	got = classifySetup(fmt.Errorf("attach: %w", cause), &evidence{})
	require.Equal(t, vWait, got.kind)
	require.Equal(t, Setup, got.why)
	require.ErrorIs(t, got.err, cause)
}

func TestHostKeyVerdictsDecideTheAttempt(t *testing.T) {
	unknown := fmt.Errorf("relay.test is not in known_hosts: %w", ErrHostKeyUnknown)
	changed := fmt.Errorf("relay.test has another key: %w", ErrHostKeyChanged)
	broken := errors.New("known_hosts is unreadable")

	for _, tc := range []struct {
		name  string
		check error
		kind  verdictKind
	}{
		{"unknown", unknown, vHostKeyUnknown},
		{"changed", changed, vStop},
		{"unreadable", broken, vStop},
	} {
		// The relay would refuse every key, but the handshake never gets as far
		// as asking.
		_, ev, err := relayKnobs{refuseAll: true}.open(t, oneSigner(t), func(string, net.Addr, ssh.PublicKey) error { return tc.check })
		require.Error(t, err, tc.name)
		require.Equal(t, tc.check, ev.hostKeyErr, tc.name)

		v := classifyConnect(err, ev)
		require.Equal(t, tc.kind, v.kind, tc.name)
		require.ErrorIs(t, v.err, tc.check, tc.name)
	}

	_, ev, err := relayKnobs{refuseAll: true}.open(t, oneSigner(t), func(string, net.Addr, ssh.PublicKey) error { return changed })
	var hostKey *HostKeyError
	require.ErrorAs(t, classifyConnect(err, ev).err, &hostKey)
	require.True(t, hostKey.Changed)
	require.ErrorIs(t, classifyConnect(err, ev).err, ErrHostKey)

	_, ev, err = relayKnobs{refuseAll: true}.open(t, oneSigner(t), func(string, net.Addr, ssh.PublicKey) error { return broken })
	require.ErrorAs(t, classifyConnect(err, ev).err, &hostKey)
	require.False(t, hostKey.Changed)
	require.ErrorIs(t, hostKey, broken)

	// A key the check accepts leaves no verdict behind.
	ev, err = connect(t, relayKnobs{}, oneSigner(t))
	require.NoError(t, err)
	require.NoError(t, ev.hostKeyErr)
}

func TestAnAttemptRecordsWhatTheRelayShowedIt(t *testing.T) {
	knobs := relayKnobs{refuseAll: true, version: "SSH-2.0-uptermd-0.37.0", banner: upterm.BannerLookupFailed}
	ev, err := connect(t, knobs, oneSigner(t))
	require.Error(t, err)
	require.Equal(t, knobs.version, ev.serverVersion)
	require.Equal(t, knobs.banner, ev.banner)
}

func TestClassifyConnectAppliesItsRulesInOrder(t *testing.T) {
	noMethods := errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")
	tooMany := errors.New(`ssh: handshake failed: ssh: disconnect, reason 2: "too many authentication failures"`)
	signErr := &IdentityError{Key: "SHA256:abc", Err: errors.New("the agent is gone")}
	noHost := fmt.Sprintf(upterm.BannerNoHostFormat, "abc")
	judged := []ssh.PublicKey{newSigner(t).PublicKey()}

	for _, tc := range []struct {
		name string
		err  error
		ev   *evidence
		want verdict
	}{
		{"a host key verdict outranks a failed signer",
			noMethods, &evidence{hostKeyErr: ErrHostKeyChanged, signErr: signErr, banner: noHost},
			verdict{kind: vStop}},
		{"a failed signer outranks a banner",
			noMethods, &evidence{signErr: signErr, banner: noHost},
			verdict{kind: vWait, why: IdentityFailure}},
		{"a banner outranks a refusal",
			noMethods, &evidence{banner: noHost, serverVersion: "SSH-2.0-uptermd-0.37.0"},
			verdict{kind: vWait, why: NoHost}},
		{"a banner outranks the disconnect",
			tooMany, &evidence{banner: upterm.BannerLookupFailed, serverVersion: "SSH-2.0-uptermd-0.37.0", judged: judged},
			verdict{kind: vWait, why: RelayLookup}},
		{"a failed signer outranks the disconnect",
			tooMany, &evidence{signErr: signErr, serverVersion: "SSH-2.0-uptermd-0.37.0", judged: judged},
			verdict{kind: vWait, why: IdentityFailure}},
		{"a banner that only starts like the lookup failure is no evidence",
			noMethods, &evidence{banner: upterm.BannerLookupFailed + "more", serverVersion: "SSH-2.0-uptermd-0.37.0"},
			verdict{kind: vStop}},
		{"an end of the connection is no refusal",
			io.EOF, &evidence{serverVersion: "SSH-2.0-uptermd-0.37.0"},
			verdict{kind: vWait, why: Unreachable}},
		{"a timeout is no refusal",
			context.DeadlineExceeded, &evidence{serverVersion: "SSH-2.0-uptermd-0.37.0"},
			verdict{kind: vWait, why: Unreachable}},
		{"a cancelled attempt is no refusal",
			context.Canceled, &evidence{},
			verdict{kind: vWait, why: Unreachable}},
		{"a disconnect with any other text is no refusal",
			errors.New(`ssh: handshake failed: ssh: disconnect, reason 11: "bye"`), &evidence{serverVersion: "SSH-2.0-uptermd-0.37.0"},
			verdict{kind: vWait, why: Unreachable}},
	} {
		got := classifyConnect(tc.err, tc.ev)
		require.Equal(t, tc.want.kind, got.kind, tc.name)
		require.Equal(t, tc.want.why, got.why, tc.name)
		if tc.want.kind == vWait && tc.want.why == Unreachable {
			require.ErrorIs(t, got.err, tc.err, tc.name)
		}
	}
}

func TestTrackRecordsTheSelectedKeyAndKeepsRSAOnSHA2(t *testing.T) {
	refused, accepted := newSigner(t), newRSASigner(t)
	// The server accepts only `accepted`, and only with rsa-sha2-256, which a
	// signer wrapped as a plain ssh.Signer can't offer.
	ev, err := connect(t, relayKnobs{allow: accepted.PublicKey(), pubKeyAlgos: []string{ssh.KeyAlgoRSASHA256}},
		[]ssh.Signer{refused, accepted})
	require.NoError(t, err)
	require.Equal(t, accepted.PublicKey().Marshal(), ev.selected.Marshal())
}

// plainOnly and algorithmOnly hide the interfaces of the signer they embed
// beyond the ones they name.
type (
	plainOnly     struct{ ssh.Signer }
	algorithmOnly struct{ ssh.AlgorithmSigner }
)

func TestTrackKeepsEachSignersInterfaces(t *testing.T) {
	multi := newSigner(t)
	algorithm := algorithmOnly{multi.(ssh.AlgorithmSigner)}
	plain := plainOnly{multi}

	tracked := track([]ssh.Signer{plain, algorithm, multi}, &evidence{})
	require.Len(t, tracked, 3)

	for i, tc := range []struct{ algorithm, multi bool }{
		{false, false},
		{true, false},
		{true, true},
	} {
		_, isAlgorithm := tracked[i].(ssh.AlgorithmSigner)
		_, isMulti := tracked[i].(ssh.MultiAlgorithmSigner)
		require.Equal(t, tc.algorithm, isAlgorithm, "signer %d", i)
		require.Equal(t, tc.multi, isMulti, "signer %d", i)
		require.Equal(t, multi.PublicKey().Marshal(), tracked[i].PublicKey().Marshal(), "signer %d", i)
	}
	require.Equal(t, multi.(ssh.MultiAlgorithmSigner).Algorithms(), tracked[2].(ssh.MultiAlgorithmSigner).Algorithms())
}

// failingAlgorithmSigner fails the way an agent does, through the call x/crypto
// prefers.
type failingAlgorithmSigner struct{ ssh.AlgorithmSigner }

func (failingAlgorithmSigner) SignWithAlgorithm(io.Reader, []byte, string) (*ssh.Signature, error) {
	return nil, errors.New("the agent can't sign with that algorithm")
}

func TestTrackKeepsTheFirstSigningErrorAndTheLastKeyThatSigned(t *testing.T) {
	first, second, failing, failingAlgorithm := newSigner(t), newSigner(t), newSigner(t), newSigner(t)
	ev := &evidence{}
	tracked := track([]ssh.Signer{
		first,
		failingSigner{failing},
		second,
		failingAlgorithmSigner{failingAlgorithm.(ssh.AlgorithmSigner)},
	}, ev)

	sign := func(s ssh.Signer) error {
		_, err := s.Sign(nil, []byte("data"))
		return err
	}

	require.NoError(t, sign(tracked[0]))
	require.Equal(t, first.PublicKey().Marshal(), ev.selected.Marshal())
	require.Nil(t, ev.signErr)

	err := sign(tracked[1])
	require.EqualError(t, err, "the agent is gone", "the signer's own error is passed on")
	require.NotNil(t, ev.signErr)
	require.Equal(t, ssh.FingerprintSHA256(failing.PublicKey()), ev.signErr.Key)
	require.ErrorIs(t, ev.signErr, ErrIdentity)
	require.ErrorIs(t, ev.signErr, err)

	// A later success replaces the selected key, and a later failure, through
	// the other call, leaves the first one in place.
	require.NoError(t, sign(tracked[2]))
	require.Equal(t, second.PublicKey().Marshal(), ev.selected.Marshal())

	_, err = tracked[3].(ssh.AlgorithmSigner).SignWithAlgorithm(nil, []byte("data"), ssh.KeyAlgoED25519)
	require.Error(t, err)
	require.Equal(t, ssh.FingerprintSHA256(failing.PublicKey()), ev.signErr.Key)
	require.Equal(t, second.PublicKey().Marshal(), ev.selected.Marshal())
}
