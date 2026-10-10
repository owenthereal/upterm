package join

import (
	"errors"
	"strings"
)

// Errors the seams return.
var (
	ErrHostKeyUnknown = errors.New("the relay's key is not known")
	ErrHostKeyChanged = errors.New("the relay's key has changed")
)

// Errors an Outcome wraps.
var (
	ErrKeysRefused     = errors.New("the session refused your keys")
	ErrIdentity        = errors.New("your SSH identity failed")
	ErrHostKey         = errors.New("the relay's key is not trusted")
	ErrUpstreamHostKey = errors.New("the relay couldn't verify the host")
)

// RefusedError is a relay or a host turning the guest's keys away.
type RefusedError struct {
	TooMany   bool // the relay disconnected at MaxAuthTries
	Ambiguous bool // no positive evidence the key itself was refused: an entry refusal without version evidence, or a round of UpstreamAuthFailed exhausted every key
}

func (e *RefusedError) Error() string {
	switch {
	case e.TooMany:
		return "keys refused: too many authentication attempts"
	case e.Ambiguous:
		return "keys refused, though not necessarily the key itself"
	}
	return "keys refused"
}

// Is reports a match with ErrKeysRefused.
func (e *RefusedError) Is(target error) bool { return target == ErrKeysRefused }

// IdentityError is the guest's own SSH identity failing, as opposed to a peer
// refusing it.
type IdentityError struct {
	Key  string   // the fingerprint that failed to sign; "" otherwise
	List bool     // the agent couldn't list its keys, and no key file loaded
	Load []string // "file: error" for key files that exist and didn't load, when nothing else did
	Err  error
}

func (e *IdentityError) Error() string {
	var detail string
	switch {
	case e.Key != "":
		detail = "key " + e.Key + " failed to sign"
	case e.List:
		detail = "the agent couldn't list its keys"
	case len(e.Load) > 0:
		detail = "key files didn't load: " + strings.Join(e.Load, "; ")
	}
	return describe("identity failed", detail, e.Err)
}

// Is reports a match with ErrIdentity.
func (e *IdentityError) Is(target error) bool { return target == ErrIdentity }

func (e *IdentityError) Unwrap() error { return e.Err }

// HostKeyError is the guest not trusting the relay's host key.
type HostKeyError struct {
	Changed  bool // a line names another key
	Declined bool // the guest said no
	Err      error
}

func (e *HostKeyError) Error() string {
	var detail string
	switch {
	case e.Changed:
		detail = "a known_hosts line names another key"
	case e.Declined:
		detail = "declined"
	}
	return describe("relay key not trusted", detail, e.Err)
}

// Is reports a match with ErrHostKey.
func (e *HostKeyError) Is(target error) bool { return target == ErrHostKey }

func (e *HostKeyError) Unwrap() error { return e.Err }

// WaitReason is why the guest is waiting: the Why of a Lost or Waiting
// event, and of a DeadlineError, what a first join was waiting on when its
// time ran out.
type WaitReason int

const (
	NoHost WaitReason = iota + 1
	Unreachable
	RelayLookup
	Upstream
	IdentityFailure // a signer failed (the agent); named apart from the Identity seam type
	Setup
)

// text names the reason for an error message.
func (r WaitReason) text() string {
	switch r {
	case NoHost:
		return "no host"
	case Unreachable:
		return "relay unreachable"
	case RelayLookup:
		return "relay lookup"
	case Upstream:
		return "upstream"
	case IdentityFailure:
		return "identity"
	case Setup:
		return "setup"
	}
	return "unknown"
}

// DeadlineError ends a first join whose Timing.FirstJoin ran out.
type DeadlineError struct {
	Why WaitReason
	Err error
}

func (e *DeadlineError) Error() string {
	return describe("join timed out", "waiting on: "+e.Why.text(), e.Err)
}

func (e *DeadlineError) Unwrap() error { return e.Err }

// describe joins a message, a detail and the error behind them with colons,
// leaving out what is empty.
func describe(msg, detail string, err error) string {
	if detail != "" {
		msg += ": " + detail
	}
	if err != nil {
		msg += ": " + err.Error()
	}
	return msg
}
