package internal

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	gssh "charm.land/ssh"
	"github.com/owenthereal/upterm/host/consent"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

const approvalControlBound = 2 * time.Second

type approvalLocalKey struct{}

// One transport owns one negotiated attachment and one coalescing sender.
// This pointer is installed before authentication and never copied with a handler.
type approvalTransport struct {
	ctx                                 gssh.Context
	conn                                net.Conn
	registered, session, eligible, gone bool // broker.mu
	wake                                chan struct{}
	done                                chan struct{}
	stopWatch                           func() bool
	snapshot                            []byte // broker.mu; newest snapshot replaces the previous one
}
type approvalPending struct {
	ctx     context.Context
	request upterm.ApprovalRequest
	owner   *approvalTransport
	result  chan approvalOutcome
}
type approvalOutcome struct {
	decision consent.Decision
	err      error
}
type approvalBroker struct {
	mu         sync.Mutex
	clients    *hostClients
	logger     *slog.Logger
	closed     bool
	revision   uint64
	transports map[*approvalTransport]struct{}
	pending    []*approvalPending
	workers    sync.WaitGroup
}

var _ consent.Prompter = (*approvalBroker)(nil)

func newApprovalBroker(clients *hostClients, logger *slog.Logger) *approvalBroker {
	b := &approvalBroker{clients: clients, logger: logger, transports: make(map[*approvalTransport]struct{})}
	clients.onApprovalPrimaryChanged = b.primaryChanged
	return b
}

// localConnection must be installed on the local attach door only.
func (b *approvalBroker) localConnection(ctx gssh.Context, conn net.Conn) net.Conn {
	ctx.SetValue(approvalLocalKey{}, &approvalTransport{ctx: ctx, conn: conn})
	return conn
}

// admitSession runs before SSH acknowledges a shell. Registration must precede
// this boundary; a registered transport can never conflate two session channels.
func (b *approvalBroker) admitSession(sess gssh.Session) bool {
	transport, _ := sess.Context().Value(approvalLocalKey{}).(*approvalTransport)
	if transport == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || transport.gone || (transport.registered && transport.session) {
		return false
	}
	transport.session = true
	_, _, pty := sess.Pty()
	transport.eligible = pty && isInteractive(sess)
	return true
}
func (b *approvalBroker) HandleRequest(ctx gssh.Context, _ *gssh.Server, req *ssh.Request) (bool, []byte) {
	accepted, payload := b.handleRequest(ctx, req)
	if req.WantReply {
		// Charm replies after this handler returns. Reply here under an owned
		// timeout instead, then suppress its duplicate reply. No state lock spans I/O.
		transport, _ := ctx.Value(approvalLocalKey{}).(*approvalTransport)
		if transport != nil {
			timer := time.AfterFunc(approvalControlBound, func() { _ = transport.conn.Close() })
			_ = req.Reply(accepted, payload)
			timer.Stop()
			req.WantReply = false
		}
	}
	return accepted, payload
}
func (b *approvalBroker) handleRequest(ctx gssh.Context, req *ssh.Request) (bool, []byte) {
	transport, _ := ctx.Value(approvalLocalKey{}).(*approvalTransport)
	if transport == nil {
		return false, nil
	}
	switch req.Type {
	case upterm.ApprovalRegisterRequest:
		if len(req.Payload) != 0 {
			return false, nil
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.closed || transport.gone || transport.registered || transport.session {
			return false, nil
		}
		transport.registered = true
		transport.wake = make(chan struct{}, 1)
		transport.done = make(chan struct{})
		b.transports[transport] = struct{}{}
		transport.stopWatch = context.AfterFunc(ctx, func() { b.transportLost(transport) })
		b.workers.Add(1)
		go b.sendStates(transport)
		return true, nil
	case upterm.ApprovalAnswerRequest:
		answer, err := upterm.DecodeApprovalAnswer(req.Payload)
		if err != nil {
			return false, nil
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.closed || transport.gone || !transport.registered || !transport.eligible || b.clients.primaryID() != ctx.SessionID() {
			return false, nil
		}
		for _, pending := range b.pending {
			if pending.request.ID == answer.ID && pending.owner == transport {
				if pending.ctx.Err() != nil || time.Now().UnixMilli() >= pending.request.DeadlineUnixMilli {
					b.finishLocked(pending, consent.Deny, consent.ErrStale)
					return false, nil
				}
				decision := consent.Deny
				switch answer.Decision {
				case "connection":
					decision = consent.AllowConnection
				case "guest":
					decision = consent.AllowGuest
				}
				b.finishLocked(pending, decision, nil)
				return true, nil
			}
		}
	}
	return false, nil
}
func (b *approvalBroker) Prompt(ctx context.Context, prompt consent.Prompt) (consent.Decision, error) {
	request := upterm.ApprovalRequest{ID: prompt.ID, Capability: string(prompt.Operation.Capability()), Operation: string(prompt.Operation), Fingerprint: prompt.Client.Fingerprint, DeadlineUnixMilli: prompt.Deadline.UnixMilli()}
	for _, subject := range prompt.Subjects {
		request.Subjects = append(request.Subjects, []byte(subject))
	}
	// The same validation applies to daemon output and client input.
	if _, err := upterm.EncodeApprovalState(upterm.ApprovalState{Revision: 1, Pending: 1, Current: &request}); err != nil {
		return consent.Deny, consent.ErrUnavailable
	}
	if ctx.Err() != nil {
		return consent.Deny, consent.ErrCanceled
	}
	if !time.Now().Before(prompt.Deadline) {
		return consent.Deny, consent.ErrTimeout
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return consent.Deny, consent.ErrUnavailable
	}
	primary := b.clients.primaryID()
	var owner *approvalTransport
	for t := range b.transports {
		if t.ctx.SessionID() == primary && t.eligible && !t.gone && t.ctx.Err() == nil {
			owner = t
			break
		}
	}
	if owner == nil {
		b.mu.Unlock()
		return consent.Deny, consent.ErrUnavailable
	}
	if len(b.pending) >= consent.MaxPending {
		b.mu.Unlock()
		return consent.Deny, consent.ErrOverloaded
	}
	for _, p := range b.pending {
		if p.request.ID == prompt.ID {
			b.mu.Unlock()
			return consent.Deny, consent.ErrStale
		}
	}
	pending := &approvalPending{ctx: ctx, request: request, owner: owner, result: make(chan approvalOutcome, 1)}
	b.pending = append(b.pending, pending)
	b.snapshotLocked(owner)
	b.mu.Unlock()
	timer := time.NewTimer(time.Until(prompt.Deadline))
	defer timer.Stop()
	var result approvalOutcome
	select {
	case result = <-pending.result:
	case <-ctx.Done():
		err := consent.ErrCanceled
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = consent.ErrTimeout
		}
		result = approvalOutcome{consent.Deny, err}
	case <-timer.C:
		result = approvalOutcome{consent.Deny, consent.ErrTimeout}
	}
	b.mu.Lock()
	b.finishLocked(pending, consent.Deny, result.err)
	if result.decision != consent.Deny && (ctx.Err() != nil || !time.Now().Before(prompt.Deadline) || owner.gone || owner.ctx.Err() != nil || b.clients.primaryID() != owner.ctx.SessionID()) {
		result = approvalOutcome{consent.Deny, consent.ErrStale}
	}
	b.mu.Unlock()
	return result.decision, result.err
}
func (b *approvalBroker) finishLocked(pending *approvalPending, decision consent.Decision, err error) {
	for i, p := range b.pending {
		if p == pending {
			b.pending = append(b.pending[:i], b.pending[i+1:]...)
			p.result <- approvalOutcome{decision, err}
			b.snapshotLocked(p.owner)
			return
		}
	}
}
func (b *approvalBroker) snapshotLocked(owner *approvalTransport) {
	if owner.gone {
		return
	}
	b.revision++
	state := upterm.ApprovalState{Revision: b.revision}
	for _, p := range b.pending {
		if p.owner == owner {
			state.Pending++
			if state.Current == nil {
				state.Current = &p.request
			}
		}
	}
	payload, err := upterm.EncodeApprovalState(state)
	if err != nil {
		return
	}
	owner.snapshot = payload
	select {
	case owner.wake <- struct{}{}:
	default:
	}
}
func (b *approvalBroker) primaryChanged() {
	b.mu.Lock()
	defer b.mu.Unlock()
	primary := b.clients.primaryID()
	for i := len(b.pending) - 1; i >= 0; i-- {
		p := b.pending[i]
		if p.owner.ctx.SessionID() != primary {
			b.finishLocked(p, consent.Deny, consent.ErrUnavailable)
		}
	}
}
func (b *approvalBroker) transportLost(owner *approvalTransport) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.loseLocked(owner)
}
func (b *approvalBroker) loseLocked(owner *approvalTransport) {
	if owner.gone {
		return
	}
	owner.gone = true
	delete(b.transports, owner)
	close(owner.done)
	for i := len(b.pending) - 1; i >= 0; i-- {
		p := b.pending[i]
		if p.owner == owner {
			b.finishLocked(p, consent.Deny, consent.ErrUnavailable)
		}
	}
}
func (b *approvalBroker) sendStates(owner *approvalTransport) {
	defer b.workers.Done()
	for {
		select {
		case <-owner.done:
			return
		case <-owner.wake:
			b.mu.Lock()
			payload := owner.snapshot
			owner.snapshot = nil
			gone := owner.gone
			b.mu.Unlock()
			if gone {
				return
			}
			if payload == nil {
				continue
			}
			conn, _ := owner.ctx.Value(gssh.ContextKeyConn).(*ssh.ServerConn)
			if conn == nil {
				b.transportLost(owner)
				return
			}
			// One bounded sender, including the global-request reply. Closing the owned
			// connection releases both writes and x/crypto's global-request mutex.
			timer := time.AfterFunc(approvalControlBound, func() { _ = owner.conn.Close(); b.transportLost(owner) })
			ok, _, err := conn.SendRequest(upterm.ApprovalStateRequest, true, payload)
			timer.Stop()
			if err != nil || !ok {
				_ = owner.conn.Close()
				b.transportLost(owner)
				return
			}
		}
	}
}
func (b *approvalBroker) Close() {
	b.mu.Lock()
	b.closed = true
	transports := make([]*approvalTransport, 0, len(b.transports))
	for owner := range b.transports {
		transports = append(transports, owner)
		b.loseLocked(owner)
	}
	b.mu.Unlock()
	for _, owner := range transports {
		owner.stopWatch()
		_ = owner.conn.Close()
	}
	b.workers.Wait()
}
