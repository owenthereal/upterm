package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// How a relay's host key came to be trusted, as a session reports it.
const (
	// RelayKeyKnown is a key a line already in the known_hosts file matched,
	// which makes it only as good as that line.
	RelayKeyKnown = "known"
	// RelayKeyPrompted is a key no line trusted, which the person at the
	// prompt accepted, on first use.
	RelayKeyPrompted = "prompted"
	// RelayKeyAutoAccepted is a key no line trusted, accepted without asking
	// (--skip-host-key-check), on first use.
	RelayKeyAutoAccepted = "auto-accepted"
)

// TrustedRelayKey is the relay key a RelayKeyCheck accepted, as a guest pins
// it, and how the check came to trust it.
type TrustedRelayKey struct {
	// KnownHostsLine trusts the key for the host and port it was checked
	// for. It is a plain key line for the key the relay proved it holds,
	// which for a certificate signed by its own key, as every uptermd's is,
	// is the key its authority line names. A certificate an authority other
	// than its own key signs gets an @cert-authority line for that authority
	// only when it lists the host among its principals, as ssh requires of
	// one it accepts by its authority; otherwise its own key's plain line.
	KnownHostsLine string
	// Trust is RelayKeyKnown, RelayKeyPrompted or RelayKeyAutoAccepted.
	Trust string
}

// RelayKeyCheck is upterm host's check of its relay's host key: a line of the
// known_hosts file trusts it, or, for a key no line names, the person at the
// prompt accepts it, or with auto-accept it is accepted without asking, and
// is recorded in the file either way. A key a line for the host contradicts
// is refused.
//
// It remembers what it trusted, so that the session can tell guests which
// key to pin, and whether a line already in the file matched it.
type RelayKeyCheck struct {
	kh         KnownHosts
	stdin      io.Reader
	autoAccept bool

	mu      sync.Mutex
	trusted *TrustedRelayKey
}

// NewPromptingRelayKeyCheck is the check that asks on stdin about a key no
// line names. Set proxied when the transport passes through an HTTP proxy;
// see NewPromptingHostKeyCallback.
func NewPromptingRelayKeyCheck(stdin io.Reader, stdout io.Writer, knownHostsFilename string, proxied bool) (*RelayKeyCheck, error) {
	return newRelayKeyCheck(stdin, stdout, knownHostsFilename, false, proxied)
}

// NewAutoAcceptingRelayKeyCheck is the check that accepts a key no line names
// without asking, as SSH's StrictHostKeyChecking=accept-new does; see
// NewAutoAcceptingHostKeyCallback.
func NewAutoAcceptingRelayKeyCheck(stdout io.Writer, knownHostsFilename string) (*RelayKeyCheck, error) {
	return newRelayKeyCheck(nil, stdout, knownHostsFilename, true, false)
}

func newRelayKeyCheck(stdin io.Reader, stdout io.Writer, knownHostsFilename string, autoAccept, proxied bool) (*RelayKeyCheck, error) {
	if err := createFileIfNotExist(knownHostsFilename); err != nil {
		return nil, err
	}

	// KnownHosts.Check reads the file on every call; parse it once here so that
	// a malformed file fails the command now rather than at the handshake.
	if _, err := knownhosts.New(knownHostsFilename); err != nil {
		return nil, err
	}

	return &RelayKeyCheck{
		kh:         KnownHosts{File: knownHostsFilename, Stdout: stdout, Proxied: proxied},
		stdin:      stdin,
		autoAccept: autoAccept,
	}, nil
}

// HostKeyCallback runs the check on key, the relay's at hostname.
func (c *RelayKeyCheck) HostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	line, err := c.kh.check(hostname, remote, key)
	if err == nil {
		c.trust(line, RelayKeyKnown)
		return nil
	}
	if !errors.Is(err, ErrUnknownHostKey) {
		return err
	}

	// Auto-accept unknown host keys if enabled
	if c.autoAccept {
		if err := c.kh.Record(hostname, key, true); err != nil {
			return err
		}
		c.trust(pinLine(hostname, key), RelayKeyAutoAccepted)
		return nil
	}

	ok, err := c.kh.Confirm(context.Background(), c.stdin, hostname, remote, key)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Host key verification failed")
	}
	c.trust(pinLine(hostname, key), RelayKeyPrompted)
	return nil
}

// trust notes how the check trusted a key, unless it already has: the first
// acceptance is the one that decided. A later check of the same key, as for
// a re-key of the same connection, finds the line recorded then, and is no
// news about how it came to be trusted.
func (c *RelayKeyCheck) trust(line, how string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.trusted == nil {
		c.trusted = &TrustedRelayKey{KnownHostsLine: line, Trust: how}
	}
}

// Trusted is the key the check first accepted, and how it came to trust it;
// false until it has accepted one.
func (c *RelayKeyCheck) Trusted() (TrustedRelayKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.trusted == nil {
		return TrustedRelayKey{}, false
	}
	return *c.trusted, true
}
