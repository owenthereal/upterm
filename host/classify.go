package host

import (
	"errors"
	"strings"

	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/registration"
)

// retryClass says how a caller that retries a failed redial should pace the
// next attempt.
type retryClass int

const (
	// transient is a failure that waiting is likely to clear: the network, a
	// relay that is down or busy, an agent that is not running yet. A caller
	// may retry it promptly.
	transient retryClass = iota
	// blocked is a refusal that waiting out the network does not clear, and
	// that something else has to: an operator authorizing the key, a user
	// approving the signature, a relay that is upgraded. Retrying it promptly
	// would only hammer the relay or the agent, so a caller should retry it at
	// a slow pace.
	blocked
)

// String names the class, for logs.
func (c retryClass) String() string {
	if c == blocked {
		return "blocked"
	}
	return "transient"
}

// tooManyAuthFailures is the text of x/crypto's disconnect from a server whose
// MaxAuthTries the client exceeded (v0.57.0, ssh/server.go): the relay refused
// every key the host offered and stopped listening. The disconnect is an
// unexported type, so its text is all that says it, and a handshake wraps it
// as `ssh: handshake failed: ssh: disconnect, reason 2: "too many
// authentication failures"`.
const tooManyAuthFailures = "too many authentication failures"

// classify says why a redial failed, as one of sessiondir's TunnelReason
// constants, and how a caller should pace the next attempt.
//
// The first rule that matches wins, so the order matters. Every blocked case is
// recognised by what it is, not by what remains once the transient ones are
// ruled out: an error nothing here has seen is a network failure, retried
// quickly, and never a reason to stop trying.
//
// The session ending locally isn't classified: a caller checks its own context
// before it calls this, since an attempt cut short because the host is shutting
// down is not a failure of the relay.
func classify(err error) (reason string, class retryClass) {
	var (
		agentUnavailable *AgentUnavailableError
		agentRefused     *AgentRefusedError
		keyChanged       *internal.RelayKeyChangedError
		createRefused    *internal.CreateSessionRefusedError
		forwardRefused   *internal.ForwardRefusedError
		permissionDenied *internal.PermissionDeniedError
	)
	switch {
	case errors.As(err, &agentUnavailable):
		return sessiondir.TunnelReasonAgentUnavailable, transient

	// Before any authentication rule: a failure to sign is the agent's, and
	// never the relay refusing a key it was shown.
	case errors.As(err, &agentRefused):
		return sessiondir.TunnelReasonAgentRefused, blocked

	case errors.As(err, &keyChanged):
		return sessiondir.TunnelReasonRelayKeyChanged, blocked

	case errors.Is(err, internal.ErrRelayUnsupported):
		return sessiondir.TunnelReasonRelayUnsupported, blocked

	case errors.As(err, &createRefused):
		if strings.HasPrefix(createRefused.Body, registration.RefusedProof) {
			return sessiondir.TunnelReasonProofRefused, blocked
		}
		// registration.Superseded (the attempt lost a race), "failed to create
		// session: ..." (the store is down), or anything else a relay says:
		// none of them is the host's to fix.
		return sessiondir.TunnelReasonRelayError, transient

	case errors.As(err, &forwardRefused):
		return sessiondir.TunnelReasonRelayError, transient

	case errors.As(err, &permissionDenied),
		err != nil && strings.Contains(err.Error(), tooManyAuthFailures):
		return sessiondir.TunnelReasonAuthRefused, blocked
	}

	// DNS, a refused or reset connection, a timeout including the attempt's own
	// deadline, a WebSocket or --proxy failure including a 407, and a handshake
	// cut off by a relay shutting down.
	return sessiondir.TunnelReasonNetwork, transient
}
