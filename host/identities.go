package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentIdentity is an identity the agent holds, as SignersWith returned it. It
// signs through the connection it came with, and remembers the socket so a
// redial can reach the agent afresh. It implements ssh.AlgorithmSigner and
// nothing more, as the agent's own signer does (ssh/agent/client.go:864), so
// x/crypto picks the same signature algorithm for it.
type agentIdentity struct {
	ssh.AlgorithmSigner
	socket string
}

// newAgentIdentity wraps a signer the agent at socket returned. x/crypto's
// agent signers are all ssh.AlgorithmSigners; anything else is returned as
// is, and a redial offers it as it would a file key.
func newAgentIdentity(s ssh.Signer, socket string) ssh.Signer {
	as, ok := s.(ssh.AlgorithmSigner)
	if !ok {
		return s
	}
	return &agentIdentity{AlgorithmSigner: as, socket: socket}
}

// AgentUnavailableError is a redial that couldn't reach the SSH agent to sign:
// no socket, a connection refused, or no SSH_AUTH_SOCK when the session
// started. Socket is the one recorded then.
type AgentUnavailableError struct {
	Socket string
	Err    error
}

func (e *AgentUnavailableError) Error() string {
	if e.Socket == "" {
		return fmt.Sprintf("cannot reach the SSH agent: %v", e.Err)
	}
	return fmt.Sprintf("cannot reach the SSH agent at %s: %v", e.Socket, e.Err)
}

func (e *AgentUnavailableError) Unwrap() error { return e.Err }

// AgentRefusedError is a redial whose SSH agent was reached but didn't sign:
// it couldn't list its keys, no longer holds the key, refused or failed the
// signature, or its connection closed underneath, the attempt's deadline
// among the causes. Key is the identity's SHA256 fingerprint.
type AgentRefusedError struct {
	Key string
	Err error
}

func (e *AgentRefusedError) Error() string {
	return fmt.Sprintf("the SSH agent did not sign with %s: %v", e.Key, e.Err)
}

func (e *AgentRefusedError) Unwrap() error { return e.Err }

var (
	errNoAgentRecorded = errors.New("SSH_AUTH_SOCK was not set when the session started")
	errAttemptOver     = errors.New("the attempt ended before the agent answered")
	errNoLongerHeld    = errors.New("it no longer holds the key")
)

// redialIdentities returns what one redial offers, in order, and the func that
// closes that attempt's agent connection.
//
// The session key goes first only when sessionKeyFirst is set. Then come the
// recorded signers, in order. An agent identity is offered by its recorded
// public key alone, and reaches the agent only to sign: the first signature
// dials the socket under ctx, and the attempt's other agent identities share
// that connection. Anything else, a file key or an embedder's own signer, is
// offered as is. No key that wasn't recorded is ever offered.
//
// closeAgent is idempotent. The caller arms it on ctx, so a signature waiting
// on an approval prompt is released at the attempt's deadline, and calls it
// once the attempt is over.
func redialIdentities(ctx context.Context, recorded []ssh.Signer, sessionKey ssh.Signer, sessionKeyFirst bool) (signers []ssh.Signer, closeAgent func()) {
	signers = make([]ssh.Signer, 0, len(recorded)+1)
	if sessionKeyFirst && sessionKey != nil {
		signers = append(signers, sessionKey)
	}
	agents := make(map[string]*attemptAgent)
	for _, s := range recorded {
		id, ok := s.(*agentIdentity)
		if !ok {
			signers = append(signers, s)
			continue
		}
		a := agents[id.socket]
		if a == nil {
			a = &attemptAgent{ctx: ctx, socket: id.socket, dial: new(net.Dialer).DialContext}
			agents[id.socket] = a
		}
		signers = append(signers, &lazyIdentity{pub: id.PublicKey(), agent: a})
	}
	return signers, func() {
		for _, a := range agents {
			a.close()
		}
	}
}

// lazyIdentity is a recorded agent identity on a redial. Offering it needs
// only its public key; signing goes through the attempt's own connection to
// the agent. Like agentIdentity, it is an ssh.AlgorithmSigner and nothing
// more, so x/crypto picks its algorithm from the recorded key's type alone.
type lazyIdentity struct {
	pub   ssh.PublicKey
	agent *attemptAgent
}

func (s *lazyIdentity) PublicKey() ssh.PublicKey { return s.pub }

func (s *lazyIdentity) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data, "")
}

func (s *lazyIdentity) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	signer, err := s.agent.signerFor(s.pub)
	if err != nil {
		return nil, err
	}
	sig, err := signer.SignWithAlgorithm(rand, data, algorithm)
	if err != nil {
		return nil, s.agent.refused(s.pub, err)
	}
	return sig, nil
}

// attemptAgent is one redial's connection to the agent at socket: dialed by
// the first signature, shared by the rest, and closed by closeAgent.
type attemptAgent struct {
	ctx    context.Context
	socket string
	dial   func(ctx context.Context, network, address string) (net.Conn, error)

	// dialing serializes connect, so the attempt dials once. close doesn't
	// take it, so closeAgent never waits on a dial.
	dialing sync.Mutex

	mu     sync.Mutex // guards closed, conn and client; the dial takes it before and after
	closed bool
	conn   net.Conn
	client agent.ExtendedAgent
}

// signerFor returns the agent's signer for pub, dialing if the attempt hasn't
// yet. It selects as lazyAgent.signerFor does.
func (a *attemptAgent) signerFor(pub ssh.PublicKey) (ssh.AlgorithmSigner, error) {
	client, err := a.connect()
	if err != nil {
		if errors.Is(err, errAttemptOver) {
			return nil, &AgentRefusedError{Key: utils.FingerprintSHA256(pub), Err: err}
		}
		return nil, err
	}
	signers, err := client.Signers()
	if err != nil {
		return nil, a.refused(pub, fmt.Errorf("listing its keys: %w", err))
	}
	// x/crypto's agent signers are all ssh.AlgorithmSigners, so only a key
	// the agent doesn't hold fails this.
	s, ok := agentSignerFor(signers, pub).(ssh.AlgorithmSigner)
	if !ok {
		return nil, a.refused(pub, errNoLongerHeld)
	}
	return s, nil
}

// connect returns the attempt's agent client, dialing it the first time. Its
// errors are *AgentUnavailableError, or errAttemptOver once closeAgent has
// run or ctx is done.
func (a *attemptAgent) connect() (agent.ExtendedAgent, error) {
	a.dialing.Lock()
	defer a.dialing.Unlock()

	a.mu.Lock()
	client, over := a.client, a.closed || a.ctx.Err() != nil
	a.mu.Unlock()
	if over {
		return nil, errAttemptOver
	}
	if client != nil {
		return client, nil
	}
	if a.socket == "" {
		return nil, &AgentUnavailableError{Err: errNoAgentRecorded}
	}

	conn, err := a.dial(a.ctx, "unix", a.socket)

	a.mu.Lock()
	defer a.mu.Unlock()
	// closeAgent may have fired during the dial, or be about to: ctx's
	// AfterFunc runs on a goroutine of its own. Either way the attempt is
	// over, and a connection that arrives now goes with it.
	if a.closed || a.ctx.Err() != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, errAttemptOver
	}
	if err != nil {
		return nil, &AgentUnavailableError{Socket: a.socket, Err: err}
	}
	a.conn = conn
	a.client = agent.NewClient(conn)
	return a.client, nil
}

// refused is a failure after a successful dial, as *AgentRefusedError. Under
// a connection closeAgent closed, it says the attempt ended.
func (a *attemptAgent) refused(pub ssh.PublicKey, err error) error {
	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	if closed {
		err = fmt.Errorf("%w: %w", errAttemptOver, err)
	}
	return &AgentRefusedError{Key: utils.FingerprintSHA256(pub), Err: err}
}

// close is closeAgent for one socket: it marks the attempt's agent closed and
// closes its connection, which releases a signature waiting on it.
func (a *attemptAgent) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	if a.conn != nil {
		_ = a.conn.Close()
		a.conn = nil
	}
}
