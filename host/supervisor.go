package host

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/version"
	"github.com/owenthereal/upterm/server"
	"golang.org/x/crypto/ssh"
)

// tunnel is one registration's connection to the relay, as the supervisor
// uses it.
type tunnel interface {
	// Listener is the forwarded listener guests reach the session on.
	Listener() net.Listener
	// Wait blocks until the connection has ended, and says why. Every call
	// gives the same answer.
	Wait() error
	// Close releases the tunnel. Wait returns once it has.
	Close()
	// ServerVersion is the relay's SSH version string.
	ServerVersion() []byte
	// SessionKeyRedial reports whether the relay lets the session key alone
	// authenticate a redial.
	SessionKeyRedial() bool
}

var _ tunnel = (*internal.ReverseTunnel)(nil)

// attemptFunc registers the session once more, under generation, offering
// signers, and within ctx. It returns the new tunnel and the relay's answer,
// or an error and no tunnel: a failed attempt leaves nothing open.
type attemptFunc func(ctx context.Context, generation uint64, signers []ssh.Signer) (tunnel, *server.CreateSessionResponse, error)

// supervisor keeps the session's tunnel up. When the tunnel is lost it
// redials the relay under the same session ID and the next generation, on the
// schedule its failures call for, and swaps each new tunnel in behind the
// guest door. It is the only writer of the session's tunnel state.
//
// Once run has started, the fields above mu are run's alone.
type supervisor struct {
	timing  ReconnectTiming
	attempt attemptFunc
	// identities returns what one attempt offers, the session key first when
	// sessionKeyFirst is set, and the func that closes the attempt's agent
	// connection.
	identities func(ctx context.Context, sessionKeyFirst bool) ([]ssh.Signer, func())
	listener   *internal.TunnelListener
	route      *internal.SessionRoute
	state      *sessionState
	publish    func() // writes the record through state.apply; a no-op with no record
	sessionID  string
	generation uint64 // the last one used: 1 after the first connection
	// supported says the relay derives session IDs, so a redial finds the
	// session again. Without it a loss is final.
	supported bool
	// sessionKeyFirst says the next attempt offers the session key ahead of
	// the recorded identities. Once false it stays false.
	sessionKeyFirst bool
	// jitter is the schedule's: how much of a bound to wait. Nil waits a
	// uniformly random part of it.
	jitter func(time.Duration) time.Duration
	logger *slog.Logger

	mu  sync.Mutex
	cur tunnel // the tunnel the guest door is served on
}

// run owns first and every tunnel after it, and returns only when ctx ends.
//
// It closes every tunnel it replaces, and every one an attempt returned that
// it didn't install, but never the current one: the session's owner closes
// that, once the guest door served on it has drained, so a stopped session's
// guests still get their output and their exit status. When run returns,
// every goroutine it started has ended except the one waiting on the current
// tunnel, which ends when that tunnel is closed. Nothing is published after
// it returns.
//
// An error never ends it. On a relay that doesn't support reconnecting, the
// first loss is published as final, the guest door is failed, and run waits
// for ctx.
func (s *supervisor) run(ctx context.Context, first tunnel) {
	timing := s.timing.orDefault()
	sched := newSchedule(timing, s.jitter)

	s.mu.Lock()
	s.cur = first
	s.mu.Unlock()
	cur, upAt := first, time.Now()

	for {
		lost := watch(cur)
		var err error
		select {
		case err = <-lost:
		case <-ctx.Done():
			return
		}
		if ctx.Err() != nil {
			return
		}
		lostAt := time.Now()

		if !s.supported {
			s.logger.Warn("lost the tunnel, and this relay doesn't support reconnecting; guests can't reach this session again until it is restarted", "error", err)
			s.state.tunnelLost(lostAt, errString(err))
			s.publish()
			s.listener.Fail(err)
			<-ctx.Done()
			return
		}

		s.logger.Warn("lost the tunnel; reconnecting", "error", err)
		// Only a tunnel that stayed up starts the schedule over; one that
		// keeps dropping as soon as it is up goes on being redialled at the
		// pace its outages have reached.
		if lostAt.Sub(upAt) >= timing.ResetAfter {
			sched.reset()
		}
		next, ok := s.reconnect(ctx, sched, timing.AttemptDeadline, lostAt, err)
		if !ok {
			return
		}
		cur, upAt = next, time.Now()
	}
}

// watch reports t's loss on a channel of its own. The goroutine it starts
// ends when t's connection does, which for a tunnel that is never lost is
// when it is closed.
func watch(t tunnel) <-chan error {
	lost := make(chan error, 1)
	go func() { lost <- t.Wait() }()
	return lost
}

// reconnect redials, starting with the first wait after the loss at lostAt,
// until a new tunnel serves the guest door, and returns it. It returns false
// once ctx has ended, waiting for that if the guest door has already closed.
func (s *supervisor) reconnect(ctx context.Context, sched *schedule, deadline time.Duration, lostAt time.Time, lossErr error) (tunnel, bool) {
	// The loss itself isn't a classified failure: whatever ended the
	// connection, the first wait after it is fast.
	reason, lastErr := sessiondir.TunnelReasonNetwork, errString(lossErr)
	wait := sched.next(transient)
	for {
		s.state.tunnelReconnecting(lostAt, reason, lastErr, time.Now().Add(wait))
		s.publish()
		if !sleepCtx(ctx, wait) {
			return nil, false
		}

		// Taken before anything else, so that no generation is ever used
		// twice, even by an attempt that fails before it sends anything.
		s.generation++
		generation, offered := s.generation, s.sessionKeyFirst
		t, resp, err := s.try(ctx, deadline, generation, offered)
		if ctx.Err() != nil {
			// The session is ending. That is not the relay failing, and a
			// tunnel the attempt did establish has nothing left to serve.
			closeTunnel(t)
			return nil, false
		}
		if err == nil && resp.SessionID != s.sessionID {
			// No guest knows this ID: the relay can't find the session
			// again, whatever it says.
			t.Close()
			t = nil
			err = fmt.Errorf("the relay registered the session as %s, not %s: %w", resp.SessionID, s.sessionID, internal.ErrRelayUnsupported)
			s.logger.Error("the relay answered a reconnect under another session ID", "generation", generation, "error", err)
		}
		if err != nil {
			closeTunnel(t)
			var class retryClass
			reason, class = classify(err)
			lastErr = err.Error()
			// The relay no longer lets the session key alone in, so offering
			// it first would only spend one of the attempts it allows.
			if reason == sessiondir.TunnelReasonAuthRefused && offered {
				s.sessionKeyFirst = false
			}
			wait = sched.next(class)
			s.logger.Warn("failed to reconnect the tunnel", "generation", generation,
				"reason", reason, "class", class.String(), "wait", wait, "error", err)
			continue
		}

		if !s.install(t, resp, generation) {
			<-ctx.Done()
			return nil, false
		}
		return t, true
	}
}

// try is one attempt under its own deadline. The attempt's agent connection is
// closed when the attempt returns, and as soon as its context ends, at the
// deadline or with the session, so that a signature waiting on the agent is
// released then: nothing the attempt started outlives it.
func (s *supervisor) try(ctx context.Context, deadline time.Duration, generation uint64, sessionKeyFirst bool) (tunnel, *server.CreateSessionResponse, error) {
	actx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	signers, closeAgent := s.identities(actx, sessionKeyFirst)
	agentClosed := make(chan struct{})
	stop := context.AfterFunc(actx, func() {
		defer close(agentClosed)
		closeAgent()
	})
	defer func() {
		// Either the close armed on actx never runs, or it has started and
		// is waited for.
		if !stop() {
			<-agentClosed
		}
		closeAgent()
	}()

	return s.attempt(actx, generation, signers)
}

// install swaps t in behind the guest door, makes it the current tunnel, and
// closes the one it replaces. It returns false, having closed t, if the guest
// door has already closed.
func (s *supervisor) install(t tunnel, resp *server.CreateSessionResponse, generation uint64) bool {
	if !s.listener.Swap(t.Listener()) {
		t.Close()
		return false
	}
	s.mu.Lock()
	prev := s.cur
	s.cur = t
	s.mu.Unlock()
	// Its connection has already ended, so this is quick.
	prev.Close()

	s.route.Set(resp.NodeAddr, resp.SshUser)
	s.sessionKeyFirst = s.sessionKeyFirst && t.SessionKeyRedial()
	if result := version.CheckCompatibility(string(t.ServerVersion())); !result.Compatible {
		s.logger.Warn("server version mismatch", "message", result.Message,
			"host_version", result.HostVersion, "server_version", result.ServerVersion)
	}
	s.state.tunnelUp()
	s.publish()
	s.logger.Info("reconnected the tunnel", "generation", generation)
	return true
}

// current is the tunnel the guest door is served on. The session's owner
// closes it once run has returned and the guest door has drained.
func (s *supervisor) current() tunnel {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// closeTunnel closes t, if there is one.
func closeTunnel(t tunnel) {
	if t != nil {
		t.Close()
	}
}

// errString is err's text, or empty for none.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
