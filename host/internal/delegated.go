package internal

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// maxDelegatedPayload bounds every delegated request and reply body.
const maxDelegatedPayload = 64 << 10

// maxDelegatedProtocol bounds a delegated protocol's name.
const maxDelegatedProtocol = 64

// errDelegatedDecision is a decision that cannot be ordered: no disposition
// this host knows, no revision, or the revision already in force with another
// disposition. It is a protocol error, never a stop.
var errDelegatedDecision = errors.New("a delegated decision that cannot be ordered")

// ValidDelegatedProtocol reports whether s can name a delegated protocol: 1
// to 64 printable ASCII bytes, none of them whitespace.
func ValidDelegatedProtocol(s string) bool {
	if s == "" || len(s) > maxDelegatedProtocol {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// ValidUUID reports whether s is a nonzero UUID in lowercase canonical form,
// as the relay requires an external session ID to be.
func ValidUUID(s string) bool {
	if len(s) != 36 || s == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, c := range []byte(s) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// AuthorityName is how the texts about a delegated session name its
// authority: by the name its placement gave, or, with none, as the session's
// authority.
func AuthorityName(name string) string {
	if name == "" {
		return "the session's authority"
	}
	return name
}

// DelegatedDecisions orders what a delegating relay decides about one
// external session: the dispositions its registration and control replies
// carry and the decisions it pushes, across every registration of the run.
// They are ordered by revision, not by arrival, and the first stopped or
// withdrawn decision accepted is final. The zero value holds no decision yet.
type DelegatedDecisions struct {
	mu          sync.Mutex
	disposition server.DelegatedDisposition
	revision    uint64
	terminal    chan struct{}
	announced   bool
}

// Apply orders disposition at revision against what was already accepted. An
// unknown disposition, a zero revision, or the revision in force with another
// disposition is an error and changes nothing. A lower revision is ignored, as
// is the same decision again. A higher one replaces a current decision; a
// stopped or withdrawn one stays in force whatever follows it.
func (d *DelegatedDecisions) Apply(disposition server.DelegatedDisposition, revision uint64) error {
	fresh, err := d.apply(disposition, revision)
	if fresh {
		d.announce()
	}
	return err
}

// apply is Apply without closing Terminal, which a caller with a reply to
// send first does with announce once it has. It reports whether the decision
// is a newly final one.
func (d *DelegatedDecisions) apply(disposition server.DelegatedDisposition, revision uint64) (bool, error) {
	if !server.ValidDelegatedDisposition(disposition, revision) {
		return false, errDelegatedDecision
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case revision < d.revision:
		return false, nil
	case revision == d.revision:
		if disposition != d.disposition {
			return false, errDelegatedDecision
		}
		return false, nil
	case final(d.disposition):
		return false, nil
	}
	d.disposition, d.revision = disposition, revision
	return final(disposition), nil
}

func final(d server.DelegatedDisposition) bool {
	return d == server.DelegatedDisposition_DELEGATED_STOPPED || d == server.DelegatedDisposition_DELEGATED_WITHDRAWN
}

func (d *DelegatedDecisions) announce() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.terminal == nil {
		d.terminal = make(chan struct{})
	}
	if !d.announced {
		d.announced = true
		close(d.terminal)
	}
}

// Current is the decision in force and its revision: DELEGATED_UNSPECIFIED
// and 0 before any.
func (d *DelegatedDecisions) Current() (server.DelegatedDisposition, uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.disposition, d.revision
}

// Terminal is closed once a stopped or withdrawn decision is accepted.
func (d *DelegatedDecisions) Terminal() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.terminal == nil {
		d.terminal = make(chan struct{})
	}
	return d.terminal
}

// DelegatedEvent is one report on a delegated registration: that the host is
// ready, or with Exit, that the command exited, with ExitStatus when
// StatusKnown and zero otherwise.
type DelegatedEvent struct {
	Exit        bool
	ExitStatus  int32
	StatusKnown bool
}

func (e DelegatedEvent) valid() bool {
	if !e.Exit {
		return e.ExitStatus == 0 && !e.StatusKnown
	}
	return e.StatusKnown || e.ExitStatus == 0
}

func (e DelegatedEvent) request(sessionID string, generation, sequence uint64) *server.DelegatedControlRequest {
	req := &server.DelegatedControlRequest{ExternalSessionId: sessionID, Generation: generation, Sequence: sequence}
	if e.Exit {
		req.Event = &server.DelegatedControlRequest_Exit{Exit: &server.DelegatedExit{ExitStatus: e.ExitStatus, StatusKnown: e.StatusKnown}}
	} else {
		req.Event = &server.DelegatedControlRequest_Ready{Ready: &server.DelegatedReady{}}
	}
	return req
}

// delegatedReports numbers one registration's reports: from 1, one more for
// each new event, and the same number and bytes for an event sent again
// before the relay acknowledged it.
type delegatedReports struct {
	mu      sync.Mutex
	last    uint64
	pending map[DelegatedEvent]*pendingReport
}

type pendingReport struct {
	sequence uint64
	payload  []byte
	// sent is the request carrying the report while the relay hasn't
	// answered it, or has and the answer is unread; nil otherwise. x/crypto
	// sends one want-reply global request at a time, so a second sent behind
	// it would only queue: a report is sent again only once its last request
	// has been answered and that answer read.
	sent *sentRequest
}

// sentRequest is a global request on its way, and once done is closed, the
// relay's answer to it.
type sentRequest struct {
	done chan struct{}
	ok   bool
	body []byte
	err  error
}

func (r *delegatedReports) prepare(event DelegatedEvent, sessionID string, generation uint64) (pendingReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.pending[event]; ok {
		return *p, nil
	}
	payload, err := proto.Marshal(event.request(sessionID, generation, r.last+1))
	if err != nil {
		return pendingReport{}, err
	}
	r.last++
	if r.pending == nil {
		r.pending = make(map[DelegatedEvent]*pendingReport)
	}
	p := &pendingReport{sequence: r.last, payload: payload}
	r.pending[event] = p
	return *p, nil
}

// send is the request carrying event's report, numbered sequence: the one
// already sent while it has no read answer, or one send starts now.
func (r *delegatedReports) send(event DelegatedEvent, sequence uint64, send func() *sentRequest) *sentRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.pending[event]
	if !ok || p.sequence != sequence {
		return send()
	}
	if p.sent == nil {
		p.sent = send()
	}
	return p.sent
}

// answered says sent's answer has been read, so the report's next send is a
// new request.
func (r *delegatedReports) answered(event DelegatedEvent, sent *sentRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.pending[event]; ok && p.sent == sent {
		p.sent = nil
	}
}

func (r *delegatedReports) acknowledged(event DelegatedEvent, sequence uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.pending[event]; ok && p.sequence == sequence {
		delete(r.pending, event)
	}
}

// Report sends event on this delegated registration's connection, and
// applies the disposition the relay answers with to Decisions. Any error
// leaves the report unacknowledged, and sending the same event again repeats
// its sequence and bytes exactly; a different event takes the next sequence.
// A report sent again before the answer to its last request has been read
// waits on that request, and takes its answer, rather than send another.
// ctx bounds the wait for the relay's answer. A *server.DelegatedRefusedError
// is the relay's refusal; ErrDelegatedRelayUnsupported an answer outside the
// delegated protocol.
func (c *ReverseTunnel) Report(ctx context.Context, event DelegatedEvent) error {
	if c.Delegated == nil || c.Client == nil || c.reports == nil {
		return errors.New("reverse tunnel: no delegated registration to report on")
	}
	if !event.valid() {
		return errors.New("reverse tunnel: invalid delegated event")
	}
	sessionID, generation := c.Delegated.ExternalSessionId, c.Generation
	report, err := c.reports.prepare(event, sessionID, generation)
	if err != nil {
		return err
	}

	client := c.Client
	sent := c.reports.send(event, report.sequence, func() *sentRequest {
		return sendRequest(client, upterm.ServerDelegatedControlRequestType, report.payload)
	})
	select {
	case <-ctx.Done():
		return fmt.Errorf("delegated report: %w", ctx.Err())
	case <-sent.done:
	}
	c.reports.answered(event, sent)
	if sent.err != nil {
		return fmt.Errorf("delegated report: %w", sent.err)
	}
	if !sent.ok {
		return delegatedRefusal(sent.body)
	}
	body := sent.body
	var reply server.DelegatedControlReply
	if len(body) > maxDelegatedPayload || proto.Unmarshal(body, &reply) != nil ||
		reply.ExternalSessionId != sessionID || reply.Generation != generation || reply.AcknowledgedSequence != report.sequence {
		return ErrDelegatedRelayUnsupported
	}
	if err := c.Decisions.Apply(reply.Disposition, reply.DecisionRevision); err != nil {
		return ErrDelegatedRelayUnsupported
	}
	c.reports.acknowledged(event, report.sequence)
	return nil
}

// sendRequest sends a global request and returns it on its way. x/crypto
// offers no way to abandon a sent request, so a caller can only stop waiting
// for it: the request goes on until the relay answers or the connection
// closes.
func sendRequest(client *ssh.Client, name string, payload []byte) *sentRequest {
	sent := &sentRequest{done: make(chan struct{})}
	go func() {
		sent.ok, sent.body, sent.err = client.SendRequest(name, true, payload)
		close(sent.done)
	}()
	return sent
}

// delegatedRefusal is what a delegated host makes of a relay's refusal: the
// relay's code, or, for anything that is not a well-formed DelegatedError,
// ErrDelegatedRelayUnsupported. The relay's bytes go no further.
func delegatedRefusal(body []byte) error {
	if refused, ok := server.DecodeDelegatedError(body); ok {
		return refused
	}
	return ErrDelegatedRelayUnsupported
}

// delegatedRequests answers the relay's decisions about the registration of
// sessionID at generation, and passes every other request from the relay on
// unchanged, so a keepalive is answered as it always was.
func delegatedRequests(in <-chan *ssh.Request, sessionID string, generation uint64, decisions *DelegatedDecisions) <-chan *ssh.Request {
	out := make(chan *ssh.Request)
	go func() {
		defer close(out)
		for r := range in {
			if r.Type != upterm.HostDelegatedDecisionRequestType {
				out <- r
				continue
			}
			answerDecision(r, sessionID, generation, decisions)
		}
	}()
	return out
}

// answerDecision acknowledges a decision about this registration once
// decisions has ordered it, and refuses one it cannot: another session or a
// later generation, which this connection never registered, an earlier one,
// which it replaced, or one that cannot be ordered. A newly final decision is
// announced only after its acknowledgment is on its way.
func answerDecision(r *ssh.Request, sessionID string, generation uint64, decisions *DelegatedDecisions) {
	refuse := func(code server.DelegatedErrorCode) {
		b, _ := proto.Marshal(&server.DelegatedError{Code: code})
		_ = r.Reply(false, b)
	}
	var d server.DelegatedDecision
	if len(r.Payload) > maxDelegatedPayload || proto.Unmarshal(r.Payload, &d) != nil || d.ExternalSessionId != sessionID || d.Generation > generation {
		refuse(server.DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
		return
	}
	if d.Generation < generation {
		refuse(server.DelegatedErrorCode_DELEGATED_STALE_GENERATION)
		return
	}
	fresh, err := decisions.apply(d.Disposition, d.DecisionRevision)
	if err != nil {
		refuse(server.DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
		return
	}
	b, _ := proto.Marshal(&server.DelegatedDecisionAck{ExternalSessionId: sessionID, Generation: generation, DecisionRevision: d.DecisionRevision})
	_ = r.Reply(true, b)
	if fresh {
		decisions.announce()
	}
}
