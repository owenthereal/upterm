package internal

import (
	"bytes"
	"errors"
	"net"
	"sync"

	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
)

// RelayAuthority is the relay key a host verified, and the only key whose
// signature makes a guest certificate's AuthRequest believable.
//
// The relay mints every guest's credential, naming in it the key the guest
// authenticated with, and the host's sshd authorizes that name. For that name
// to mean anything the host has to know which key may sign it. That key is not
// a new thing to configure: it is the relay host key this host already decided
// to trust, in its own host key callback. Wrap records it there.
//
// That bounds the damage to the relay the host chose. A host that skipped
// verification (--skip-host-key-check on a first connection) can still be lied
// to by whoever answered, which is the separate problem of publishing and
// pinning the public relay's key.
//
// The zero value trusts nothing, which is what a host whose handshake has not
// happened yet should do.
type RelayAuthority struct {
	mu  sync.Mutex
	key ssh.PublicKey
	// presented is the key as the relay showed it, a certificate included,
	// where key is what that reduces to. CheckRedial asks Pinned about it.
	presented ssh.PublicKey
}

// errNoHostKeyCallback fails closed for a caller that wrapped nothing. A nil
// callback would otherwise read as "no objection" and record whatever answered.
var errNoHostKeyCallback = errors.New("relay authority: no host key callback")

// Wrap returns cb with the accepted key recorded. Only a key cb accepted is
// recorded: the verdict belongs to the host's trust policy, and this only
// remembers what it decided.
//
// A relay presents a host certificate when the client offers certificate
// algorithms, which ReverseTunnel does, so the key recorded is the
// certificate's SignatureKey -- the same key the relay signs guest
// certificates with, and the same key the prompt and known_hosts already
// reduce a host certificate to. The key as presented is kept too, for
// CheckRedial.
func (r *RelayAuthority) Wrap(cb ssh.HostKeyCallback) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if cb == nil {
			return errNoHostKeyCallback
		}
		if err := cb(hostname, remote, key); err != nil {
			return err
		}

		presented := key
		if cert, ok := key.(*ssh.Certificate); ok {
			key = cert.SignatureKey
		}

		r.mu.Lock()
		r.key = key
		r.presented = presented
		r.mu.Unlock()

		return nil
	}
}

// IsUserAuthority reports whether key is the relay key this host verified. It
// is the predicate server.UserCertChecker asks, and it is false until a
// handshake has recorded one.
//
// The comparison is exact, on the marshalled key, and deliberately not
// utils.KeysEqual: that unwraps a certificate to the key it certifies, so a
// certificate that merely certified the relay's key would be accepted as the
// authority itself. An authority is one specific key. Production only ever asks
// about a cert.SignatureKey, which is always a plain key, so the strictness
// costs nothing.
//
// Locked because Wrap runs on the goroutine dialing the relay while this runs
// on the embedded sshd's handler goroutines. They are ordered today -- the
// server is built after the tunnel is established -- but a redial would not be.
func (r *RelayAuthority) IsUserAuthority(key ssh.PublicKey) bool {
	r.mu.Lock()
	recorded := r.key
	r.mu.Unlock()

	if recorded == nil || key == nil {
		return false
	}

	return bytes.Equal(recorded.Marshal(), key.Marshal())
}

// errNotTheRecordedKey is the plain-key verdict of Pinned: whatever was
// recorded, this is not it, and an authority that recorded nothing is no
// exception.
var errNotTheRecordedKey = errors.New("ssh: host key is not the relay key this session started with")

// Pinned returns the host key callback for a redial: it accepts the relay
// authority the first connection recorded, and nothing else. It never prompts
// and never reads known_hosts, so a redial cannot be talked into trusting
// anything the first connection did not.
//
// It accepts exactly two things: the recorded key itself, and a host
// certificate signed by it that verifies, is within its validity and names the
// dialled hostname (its port dropped) or names none. Every refusal is a
// *RelayKeyChangedError wrapping the checker's reason, including a certificate
// that merely certifies the recorded key: the comparison is IsUserAuthority's,
// exact on the marshalled key, because utils.KeysEqual would unwrap it.
//
// What is recorded is read when the callback runs, not when Pinned is called,
// and is never changed by it.
//
// A first connection under --skip-host-key-check accepts a certificate without
// checking its principals (host.autoAcceptHostKey). If that certificate does not
// name the hostname dialled, as when the public relay is dialled by IP, every
// redial is refused here. That is the verdict known_hosts gives the same host on
// the next run, so it is kept; CheckRedial reports it as soon as the first
// connection is up, for a caller that wants to say so before any redial.
func (r *RelayAuthority) Pinned() ssh.HostKeyCallback {
	checker := &ssh.CertChecker{
		// A relay authority is one key, which is the one IsUserAuthority already
		// compares exactly.
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool { return r.IsUserAuthority(auth) },
		HostKeyFallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !r.IsUserAuthority(key) {
				return errNotTheRecordedKey
			}
			return nil
		},
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := checker.CheckHostKey(hostname, remote, key)
		if err == nil {
			return nil
		}

		// A certificate that names the recorded authority and is refused anyway
		// is not a changed key, and RelayKeyChangedError says so.
		cert, isCert := key.(*ssh.Certificate)
		return &RelayKeyChangedError{
			Hostname:       hostname,
			Key:            key,
			Err:            err,
			namesAuthority: isCert && cert != nil && r.IsUserAuthority(cert.SignatureKey),
		}
	}
}

// CheckRedial reports whether the key the first connection was shown would pass
// Pinned for hostname, given as host:port as the callback is: nil if a redial
// to the same relay would be accepted, and otherwise the *RelayKeyChangedError
// Pinned would refuse it with. A caller can ask as soon as the first connection
// is up, rather than learn it from a failed redial. It records nothing, and a
// connection that recorded nothing fails it.
func (r *RelayAuthority) CheckRedial(hostname string) error {
	r.mu.Lock()
	presented := r.presented
	r.mu.Unlock()

	return r.Pinned()(hostname, nil, presented)
}

// RelayKeyChangedError is a redial shown a relay key other than the one this
// session started with. Key is what the relay showed, and nil when nothing was.
//
// One refusal is not a different key: a certificate that names the authority
// this session started with as its signer, refused anyway (another hostname,
// expired, not a host certificate). That is how a first connection that
// auto-accepted a certificate for another hostname shows up (see Pinned), and
// it reads as what happened, with Err as the reason, instead of calling the
// recorded authority's own key a changed one. It says the
// certificate names the authority, not that the authority signed it: the
// checker verifies the signature last, so a refusal for the principals or the
// validity says nothing of it.
type RelayKeyChangedError struct {
	Hostname string
	Key      ssh.PublicKey
	Err      error

	// namesAuthority is set by Pinned for that certificate: Key's SignatureKey
	// is exactly the recorded key, whether or not its signature was ever
	// verified.
	namesAuthority bool
}

func (e *RelayKeyChangedError) Error() string {
	fingerprint := e.fingerprint()
	if e.namesAuthority && e.Err != nil && fingerprint != "" {
		return "the relay presented a certificate" + e.forHost() +
			" that names the authority this session started with (" + fingerprint +
			"), but it was not accepted: " + e.Err.Error()
	}

	msg := "the relay's key" + e.forHost()
	if fingerprint != "" {
		msg += " (" + fingerprint + ")"
	}
	return msg + " is not the one this session started with"
}

func (e *RelayKeyChangedError) Unwrap() error { return e.Err }

// forHost is " for HOST", or nothing for a zero value.
func (e *RelayKeyChangedError) forHost() string {
	if e.Hostname == "" {
		return ""
	}
	return " for " + e.Hostname
}

// fingerprint names Key, or the signer a certificate names when Key is one, as
// the host key prompt does: a certificate's own digest is not one anyone can
// compare. It is empty when there is no key to name.
func (e *RelayKeyChangedError) fingerprint() string {
	key := e.Key
	if cert, ok := key.(*ssh.Certificate); ok {
		if cert == nil {
			return ""
		}
		key = cert.SignatureKey
	}
	if key == nil {
		return ""
	}
	return utils.FingerprintSHA256(key)
}
