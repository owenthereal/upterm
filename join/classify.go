package join

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/owenthereal/upterm/internal/version"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

// The texts of x/crypto's own errors that the classifier reads. They are not
// part of its API, so the tests run the real client and server: an upgrade
// that rewords one fails a test instead of quietly reclassifying a refusal as
// an outage, or an outage as a refusal.
const (
	// textNoMethods ends the error of a client that tried every method and
	// every key and was turned down. x/crypto returns it only when the last
	// attempt drew a definitive failure from the server with no error pending.
	// A network error inside an attempt is turned into a failed method, so
	// having tried to authenticate and then failed proves nothing by itself.
	textNoMethods = "no supported methods remain"

	// textTooMany is the server's disconnect at MaxAuthTries.
	textTooMany = "too many authentication failures"
)

// firstRelayWithBanners is the first uptermd release whose relays send the
// no-host banner. Before it a session that isn't there looks the same as a key
// that was refused.
const firstRelayWithBanners = "0.34.0"

// evidence is what one attempt saw on its way to an error or a session. The
// auth, banner and signing callbacks write it on the goroutine that runs the
// handshake, which is the attempt's own, and only during the handshake. The
// host key check is another matter: it runs on x/crypto's key exchange
// goroutine, at the handshake and again at every key exchange after it,
// mid-session included, so what it records is under mu, and read with
// hostKeyVerdict.
type evidence struct {
	banner        string         // the last banner the relay sent while authenticating
	serverVersion string         // the relay's SSH version line, from the AuthCallback
	selected      ssh.PublicKey  // the key whose signature completed authentication
	signErr       *IdentityError // the first signer that failed to sign

	mu         sync.Mutex
	hostKey    ssh.PublicKey // the relay's key at the last key exchange
	hostKeyErr error         // CheckHostKey's verdict on it; nil once accepted
}

// checkedHostKey records CheckHostKey's verdict, err, on the relay's key.
func (ev *evidence) checkedHostKey(key ssh.PublicKey, err error) {
	ev.mu.Lock()
	defer ev.mu.Unlock()
	ev.hostKey, ev.hostKeyErr = key, err
}

// hostKeyVerdict is the relay's key at the last key exchange, and
// CheckHostKey's verdict on it. A refused key ends the connection, so no key
// exchange follows a refusal: a verdict that isn't nil is the one that ended
// it. Once a handshake has succeeded, which it does only with the key
// accepted, a refusal can only come from a key exchange after it.
func (ev *evidence) hostKeyVerdict() (ssh.PublicKey, error) {
	ev.mu.Lock()
	defer ev.mu.Unlock()
	return ev.hostKey, ev.hostKeyErr
}

// clientConfig is the ssh.ClientConfig of one attempt. Its callbacks fill ev,
// which is all classifyConnect and classifySetup judge by. checkHostKey returns
// nil to accept the relay's key, or an error that wraps ErrHostKeyUnknown or
// ErrHostKeyChanged to say why it doesn't. Its verdict is kept in ev, and an
// error also refuses the key, which ends the handshake, or, at a key exchange
// after it, the connection.
//
// The AuthCallback keeps the relay's version line because it is the only place
// x/crypto shows one to a client whose handshake then fails. It runs after the
// first, empty authentication request has been answered, so a handshake that
// ends before that leaves serverVersion empty, which counts as no evidence.
func clientConfig(user string, signers []ssh.Signer, checkHostKey ssh.HostKeyCallback, ev *evidence) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:          user,
		ClientVersion: upterm.JoinSSHClientVersion,
		Auth:          []ssh.AuthMethod{ssh.PublicKeys(track(signers, ev)...)},
		// Returning no method leaves the choice to Auth.
		AuthCallback: func(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
			ev.serverVersion = string(ctx.Metadata.ServerVersion())
			return nil, nil
		},
		BannerCallback: func(message string) error {
			ev.banner = message
			return nil
		},
		HostKeyCallback: func(host string, remote net.Addr, key ssh.PublicKey) error {
			err := checkHostKey(host, remote, key)
			ev.checkedHostKey(key, err)
			return err
		},
	}
}

// track wraps signers so ev learns the selected key and any signing error.
//
// x/crypto signs only after the server has answered a key's query with PK_OK,
// so the last signature that succeeded on a handshake that succeeded is the key
// that got in. A signer's error is its own, never the relay's refusal; x/crypto
// folds it into a failed method like any other.
//
// Each wrapper has exactly the interfaces its signer has, because x/crypto
// chooses the signature algorithm from them: a key that is an AlgorithmSigner
// or a MultiAlgorithmSigner signs RSA with SHA-2, and one wrapped as a plain
// Signer can only sign it with SHA-1, which many servers refuse.
func track(signers []ssh.Signer, ev *evidence) []ssh.Signer {
	tracked := make([]ssh.Signer, len(signers))
	for i, s := range signers {
		base := trackedSigner{Signer: s, ev: ev}
		switch inner := s.(type) {
		case ssh.MultiAlgorithmSigner:
			tracked[i] = trackedMultiAlgorithmSigner{
				trackedAlgorithmSigner: trackedAlgorithmSigner{trackedSigner: base, inner: inner},
				algorithms:             inner,
			}
		case ssh.AlgorithmSigner:
			tracked[i] = trackedAlgorithmSigner{trackedSigner: base, inner: inner}
		default:
			tracked[i] = base
		}
	}
	return tracked
}

// trackedSigner is a plain ssh.Signer that reports to ev.
type trackedSigner struct {
	ssh.Signer
	ev *evidence
}

func (s trackedSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.record(s.Signer.Sign(rand, data))
}

// record notes how a signature went and passes it on.
func (s trackedSigner) record(sig *ssh.Signature, err error) (*ssh.Signature, error) {
	if err != nil {
		if s.ev.signErr == nil {
			s.ev.signErr = &IdentityError{Key: ssh.FingerprintSHA256(s.PublicKey()), Err: err}
		}
		return nil, err
	}
	s.ev.selected = s.PublicKey()
	return sig, nil
}

// trackedAlgorithmSigner is a tracked ssh.AlgorithmSigner.
type trackedAlgorithmSigner struct {
	trackedSigner
	inner ssh.AlgorithmSigner
}

func (s trackedAlgorithmSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	return s.record(s.inner.SignWithAlgorithm(rand, data, algorithm))
}

// trackedMultiAlgorithmSigner is a tracked ssh.MultiAlgorithmSigner.
type trackedMultiAlgorithmSigner struct {
	trackedAlgorithmSigner
	algorithms ssh.MultiAlgorithmSigner
}

func (s trackedMultiAlgorithmSigner) Algorithms() []string { return s.algorithms.Algorithms() }

type verdictKind int

const (
	vWait           verdictKind = iota // wait (why), then attempt
	vRetryNow                          // attempt at once without ev.selected: the session's node refused that key
	vAmbiguous                         // the relay couldn't authenticate upstream: refused, or no session; the caller applies its round rules
	vStop                              // end the join with err
	vHostKeyUnknown                    // the caller decides: ask the guest (before the terminal is taken) or stop
)

// verdict is what an attempt's end means for the join.
type verdict struct {
	kind verdictKind
	why  WaitReason // for vWait
	err  error      // the cause the verdict rests on; nil when kind and why say it all
}

// classifyConnect judges a dial or a handshake that failed. It never calls a
// key refused without positive evidence: the relay's definite answer, from a
// relay new enough that a missing session can't pass for one. Anything else,
// an I/O error in the middle of authentication included, is an unreachable
// relay, which a join waits out.
func classifyConnect(err error, ev *evidence) verdict {
	if _, refusal := ev.hostKeyVerdict(); refusal != nil {
		if errors.Is(refusal, ErrHostKeyUnknown) {
			return verdict{kind: vHostKeyUnknown, err: refusal}
		}
		return verdict{kind: vStop, err: refusedHostKey(refusal)}
	}

	// The signer's own failure is the guest's, whatever the relay then said.
	if ev.signErr != nil {
		return verdict{kind: vWait, why: IdentityFailure, err: ev.signErr}
	}

	switch {
	case strings.HasPrefix(ev.banner, upterm.BannerNoHostPrefix):
		return verdict{kind: vWait, why: NoHost}
	case ev.banner == upterm.BannerLookupFailed:
		return verdict{kind: vWait, why: RelayLookup}
	}

	var text string
	if err != nil {
		text = err.Error()
	}
	switch {
	case strings.Contains(text, textNoMethods):
		return verdict{kind: vStop, err: &RefusedError{Ambiguous: !relayHasBanners(ev.serverVersion)}}
	case strings.Contains(text, textTooMany):
		return verdict{kind: vStop, err: &RefusedError{TooMany: true, Ambiguous: !relayHasBanners(ev.serverVersion)}}
	}
	return verdict{kind: vWait, why: Unreachable, err: err}
}

// classifySetup judges the error Terminal.Run returned for a handshake that
// succeeded, by the text the relay rejected the session channel with. That text
// is evidence in itself, whatever version sent it.
//
// A key exchange during setup that refused the relay's key comes first: the
// refusal ended the connection, whatever error that then made for setup. The
// terminal is taken by then, so an unknown key is not asked about either.
func classifySetup(err error, ev *evidence) verdict {
	if _, refusal := ev.hostKeyVerdict(); refusal != nil {
		return verdict{kind: vStop, err: refusedHostKey(refusal)}
	}
	var rejected *ssh.OpenChannelError
	if !errors.As(err, &rejected) {
		return verdict{kind: vWait, why: Setup, err: err}
	}
	switch rejected.Message {
	case upterm.UpstreamKeyRefused:
		return verdict{kind: vRetryNow, err: err}
	case upterm.UpstreamAuthFailed:
		// A node that predates the refined verdicts says this for a refusal and
		// for a missing session alike.
		return verdict{kind: vAmbiguous}
	case upterm.UpstreamNoHost:
		return verdict{kind: vWait, why: NoHost}
	case upterm.UpstreamLookupFailed:
		return verdict{kind: vWait, why: RelayLookup}
	case upterm.UpstreamUnavailable:
		return verdict{kind: vWait, why: Upstream}
	case upterm.UpstreamHostKeyMismatch:
		return verdict{kind: vStop, err: ErrUpstreamHostKey}
	}
	return verdict{kind: vWait, why: Setup, err: err}
}

// refusedHostKey is the error a join stops with once CheckHostKey has refused
// the relay's key with err and nobody is to be asked about it: a changed key,
// CheckHostKey's own failure, or an unknown key once the terminal is taken.
func refusedHostKey(err error) *HostKeyError {
	return &HostKeyError{Changed: errors.Is(err, ErrHostKeyChanged), Err: err}
}

// relayHasBanners reports whether serverVersion, a relay's SSH version line,
// positively names an uptermd release that sends the no-host banner. Only
// positive evidence counts: a dev build (0.0.0+dev), a line that doesn't parse,
// another server's line and an empty one all say false, and a caller reads
// false as ambiguous.
func relayHasBanners(serverVersion string) bool {
	v, err := version.ParseFromSSHVersion(serverVersion)
	if err != nil {
		return false
	}
	first, err := version.Parse(firstRelayWithBanners)
	return err == nil && v.GreaterThanOrEqual(first)
}
