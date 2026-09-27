package internal

import (
	"bytes"
	"errors"
	"net"
	"sync"

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
// reduce a host certificate to.
func (r *RelayAuthority) Wrap(cb ssh.HostKeyCallback) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if cb == nil {
			return errNoHostKeyCallback
		}
		if err := cb(hostname, remote, key); err != nil {
			return err
		}

		if cert, ok := key.(*ssh.Certificate); ok {
			key = cert.SignatureKey
		}

		r.mu.Lock()
		r.key = key
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
