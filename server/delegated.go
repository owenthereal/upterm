package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"charm.land/ssh"
	"github.com/owenthereal/upterm/internal/liveness"
	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/upterm"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// Authority decides delegated registrations: the runs whose registration, and
// whose guests, an authority outside the relay decides. A host asks for one
// by setting delegated_session in its request. A local registration, and a
// local session's guest, never reach the authority.
//
// Register and Control run on the host connection's request goroutine, so
// they hold up that connection's other requests; ctx ends with the
// connection. Refusing with a *DelegatedRefusedError sends the host its code.
// Any other error is DELEGATED_UNAVAILABLE, which the host retries and never
// takes as a decision.
//
// A guest whose SSH user is a relay session ID, the 20 letters and digits the
// relay names a session by, optionally followed by a colon and a node
// address in base64url, which may be empty, is a session's guest: it reaches
// Admit only once its home reports a delegated registration. Any other user
// is offered to Claims, and only a user the authority claims reaches Admit. A
// dark authority is asked neither.
type Authority interface {
	// Register decides a delegated registration once its request is well
	// formed, its proof has verified, and its host came in by the public SSH
	// listener.
	Register(ctx context.Context, r DelegatedRegistration) (RegistrationResult, error)
	// Control records a report from the host of a registration Register
	// accepted, on that registration's connection, and answers it.
	Control(ctx context.Context, r Report) (*DelegatedControlReply, error)
	// Claims reports whether user is one of the authority's own, which it
	// decides the guests of. It looks at user alone and does no I/O, since it
	// also answers guests that haven't signed yet. It is never asked about a
	// relay session ID.
	Claims(user string) bool
	// Admit decides a guest once it has signed with its key, and before
	// anything is looked up for a claimed user. ctx lasts at most 5 seconds,
	// and no longer than what is left of the handshake's budget for a claimed
	// user, or, for a session ID, of the time its home was given to be
	// reached: half the handshake timeout from when the guest signed. It ends
	// once the relay has finished admitting the guest, after Admit returns.
	Admit(ctx context.Context, g *Guest, req GuestRequest) (Admission, error)
	// Unreachable is the text a guest Admit allowed is shown instead of its
	// target, when the relay holds no connection to that target as it serves
	// the guest. No admission the relay accepts ends that way today: a guest
	// whose allowed target can't be reached is refused as it authenticates,
	// so the relay never calls Unreachable. ctx would end as Admit's does, or
	// after half the handshake's budget, whichever is first.
	Unreachable(ctx context.Context, g *Guest, t Target) []byte
}

// Lifecycle is what an extension runs beside a serving relay.
type Lifecycle interface {
	// Start runs once the listeners exist and before the first connection is
	// accepted, so a fence it sets is in force for that first connection. It
	// must not wait for the network. An error stops the relay before it
	// accepts anything. ctx ends with the server's context.
	Start(ctx context.Context, rt Runtime) error
	// Stop cancels and joins the extension's workers. It runs once the
	// server's context ends, even while the relay is still cleaning up, and
	// when Start has failed.
	Stop()
}

// Runtime is the control an extension has over a serving relay's delegated
// work.
type Runtime interface {
	// Fence returns the fence called name, the same one each time.
	Fence(name string) Fence
	// Drain raises the drain latch, then closes every delegated registration,
	// hop and guest, without calling the authority. It returns nil once
	// Counts is (0, 0), or ctx's error once ctx ends.
	Drain(ctx context.Context) error
	// Resume clears the drain latch, and no fence.
	Resume()
	// Counts is the delegated work in progress: the registrations, those the
	// authority is still deciding and those whose host's raw transport is
	// still open among them, and the guests, those still being decided and
	// the hops this node serves to its delegated registrations among them.
	// A connection whose delegated registration has a final decision, and
	// which holds a local registration too, is a local session's: it is not
	// counted, and Drain leaves it open.
	Counts() (registrations, guests int)
	// PushDecision sends d to the host connection that registered d's
	// external session at d's generation on this relay, and returns the
	// host's acknowledgment: that the host received it, not that it acted on
	// it. A final decision retires the registration's home before it is
	// sent, so no guest reaches it; the route's store entry is released
	// alongside, and the push waits for that only within ctx, so a push the
	// host acknowledged can return at ctx's end with the release still
	// running.
	// ErrDelegatedHostNotFound is no such connection. A *DelegatedRefusedError
	// is the host refusing the decision, or answering it outside the
	// delegated protocol, which is DELEGATED_UNSUPPORTED.
	PushDecision(ctx context.Context, d *DelegatedDecision) (*DelegatedDecisionAck, error)
	// Identity is this node's ID, its boot ID and its NodeAddr, as it serves.
	Identity() (nodeID, bootID, nodeAddr string)
}

// Fence refuses new delegated work while it is set: registrations, guests and
// the hops to delegated registrations. Work already adopted or admitted is
// left alone. Neither Set nor Clear does I/O or waits on the authority.
type Fence interface {
	Set()
	Clear()
}

// DelegatedRegistration is a delegated registration as the relay verified it.
type DelegatedRegistration struct {
	Origin     GuestOrigin
	HomeNode   string
	HomeNodeID string
	HomeBootID string
	// Session is the request's delegated metadata. It is checked before
	// Register sees it: one of Extensions.Protocols, an external session ID
	// that is a UUID, no disposition, and a proof.
	Session *DelegatedSession
	// RunPublicKey is the key the proof verified, RoutingID the session ID
	// derived from it and the secret, and Generation the one the proof
	// signed.
	RunPublicKey gossh.PublicKey
	RoutingID    string
	Generation   uint64
	// RegistrationID is the SSH session identifier of the host's own
	// connection to this relay, the one its proof is bound to.
	RegistrationID []byte
	// Contact reports, whenever it is called, during the connection or after
	// it, what the relay has observed of the host's connection.
	Contact func() Contact
}

// clone is r with its own delegated metadata, for an authority that may keep
// or change what it is given without changing what the relay acknowledges.
func (r DelegatedRegistration) clone() DelegatedRegistration {
	if r.Session != nil {
		r.Session = proto.Clone(r.Session).(*DelegatedSession)
	}
	r.Origin.SSHSessionID = bytes.Clone(r.Origin.SSHSessionID)
	if r.RunPublicKey != nil {
		r.RunPublicKey, _ = gossh.ParsePublicKey(r.RunPublicKey.Marshal())
	}
	r.RegistrationID = bytes.Clone(r.RegistrationID)
	return r
}

// RegistrationResult is Register's decision. Only DELEGATED_CURRENT publishes
// a route; DELEGATED_STOPPED and DELEGATED_WITHDRAWN keep the connection for
// the host's final reports and nothing else.
type RegistrationResult struct {
	// AccountID is required for a current registration, and is a UUID.
	AccountID   string
	Disposition DelegatedDisposition
	// DecisionRevision is at least 1.
	DecisionRevision uint64
}

// Report is a host's report on its own delegated registration.
type Report struct {
	// Registration is what this connection registered.
	Registration DelegatedRegistration
	// Request is the report, already checked against Registration: its
	// external session and generation, a sequence of at least 1 and exactly
	// one well-formed event.
	Request *DelegatedControlRequest
}

// Contact is what the relay has observed of a host's connection.
type Contact struct {
	// Connected reports whether the connection is still open.
	Connected bool
	// LastContact is when the host last sent anything, judged by the same
	// reads that judge its silence.
	LastContact time.Time
}

// DelegatedRefusedError is a definitive delegated refusal, carried on the
// wire as a DelegatedError: what an Authority returns to refuse with a code,
// and what a host said, or seemed to say, when refusing a pushed decision. Its
// text is fixed per code, so no peer's bytes reach a log or a person.
type DelegatedRefusedError struct{ Code DelegatedErrorCode }

func (e *DelegatedRefusedError) Error() string {
	switch e.Code {
	case DelegatedErrorCode_DELEGATED_UNAVAILABLE:
		return "delegated registration unavailable"
	case DelegatedErrorCode_DELEGATED_INVALID_REQUEST:
		return "delegated request refused as invalid"
	case DelegatedErrorCode_DELEGATED_STALE_GENERATION:
		return "delegated registration replaced by a newer one"
	default:
		return "delegated request unsupported"
	}
}

// Retryable reports whether the same request may succeed later.
func (e *DelegatedRefusedError) Retryable() bool {
	return e.Code == DelegatedErrorCode_DELEGATED_UNAVAILABLE
}

// DecodeDelegatedError reads a refused delegated request's body. It reports
// false for anything but a DelegatedError with a known code and nothing else
// in it, which a delegated peer takes as unsupported, never as success.
func DecodeDelegatedError(body []byte) (*DelegatedRefusedError, bool) {
	var m DelegatedError
	if len(body) > maxDelegatedPayload || proto.Unmarshal(body, &m) != nil || len(m.ProtoReflect().GetUnknown()) != 0 {
		return nil, false
	}
	switch m.Code {
	case DelegatedErrorCode_DELEGATED_UNAVAILABLE, DelegatedErrorCode_DELEGATED_INVALID_REQUEST, DelegatedErrorCode_DELEGATED_STALE_GENERATION, DelegatedErrorCode_DELEGATED_UNSUPPORTED:
		return &DelegatedRefusedError{Code: m.Code}, true
	}
	return nil, false
}

// ValidDelegatedDisposition reports whether d is a decision, with a revision
// that can order it.
func ValidDelegatedDisposition(d DelegatedDisposition, revision uint64) bool {
	switch d {
	case DelegatedDisposition_DELEGATED_CURRENT, DelegatedDisposition_DELEGATED_STOPPED, DelegatedDisposition_DELEGATED_WITHDRAWN:
		return revision >= 1
	}
	return false
}

// validUUID reports whether s is a nonzero UUID in lowercase canonical form.
func validUUID(s string) bool {
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

// maxDelegatedPayload bounds every delegated request and reply body.
const maxDelegatedPayload = 64 << 10

// delegatedDecisionTimeout bounds PushDecision's wait for the host.
const delegatedDecisionTimeout = 10 * time.Second

// delegatedUnsupported is the refusal of a delegated registration by a relay
// with no authority composed.
const delegatedUnsupported = "delegated registration is not supported by this relay"

var (
	// ErrDelegatedHostNotFound is a push for an external session and
	// generation with no host connection registered on this relay.
	ErrDelegatedHostNotFound = errors.New("no delegated host connection for that external session and generation")
	errDelegatedDecision     = errors.New("a delegated decision needs an external session ID, a generation and a disposition with its revision")
)

// The startup refusals of an enabled authority whose prerequisites are
// missing, in the order they are checked.
var (
	errAuthorityNeedsMemoryNetwork = errors.New("an enabled authority needs the in-memory network provider (--network mem)")
	errAuthorityNeedsInternal      = errors.New("an enabled authority needs an internal listener (--internal-addr)")
	errAuthorityNeedsGatedHops     = errors.New("an enabled authority needs --legacy-hops=false")
	errAuthorityNeedsNodeID        = errors.New("an enabled authority needs a node ID (--node-id)")
	errAuthorityNeedsBootID        = errors.New("an enabled authority needs a UUID boot ID")
)

// checkAuthority refuses to serve ls with an enabled authority that lacks
// what keeps a delegated registration's transports in this process and its
// origin trustworthy: hosts and sessions on the in-memory network, public
// and node traffic on separate listeners, every hop through the gate, and an
// identity for its homes. A dark authority, or none, needs none of them.
func (s *Server) checkAuthority(ls Listeners) error {
	if s.Extensions.Authority == nil || !s.Extensions.Enabled {
		return nil
	}
	if _, ok := s.NetworkProvider.(*MemoryProvider); !ok {
		return errAuthorityNeedsMemoryNetwork
	}
	if ls.Internal == nil {
		return errAuthorityNeedsInternal
	}
	if !s.RefuseLegacyHops {
		return errAuthorityNeedsGatedHops
	}
	if s.NodeID == "" {
		return errAuthorityNeedsNodeID
	}
	if !validUUID(s.BootID) {
		return errAuthorityNeedsBootID
	}
	return nil
}

// neighbourDialer is the dialer this node reaches other nodes with: dialer,
// as it is.
func (s *Server) neighbourDialer(dialer connDialer) connDialer { return dialer }

// delegatedHost is one connection's delegated registration.
type delegatedHost struct {
	registration DelegatedRegistration
	conn         *gossh.ServerConn
	// fence retires the home of the route a current registration published,
	// and closes its listener, without waiting on the store; release then
	// releases the route's store entry, which can be slow. Both are nil for a
	// registration that published none.
	fence, release func()
	// obligation is the connection's delegated work.
	obligation *delegatedObligation

	mu sync.Mutex
	// retired is set once a final decision withdrew the route, and from the
	// start for a registration accepted with a final decision, which has none.
	retired bool
	// local is set once the connection holds a local registration as well.
	local bool
}

// registeredLocally is told that the connection now holds a local
// registration.
func (h *delegatedHost) registeredLocally() {
	h.mu.Lock()
	h.local = true
	h.mu.Unlock()
	h.settle()
}

// settle ends the connection's delegated work once its registration has a
// final decision and the connection holds a local registration, in either
// order: the connection is then a local session's, which isn't counted, and
// which a drain leaves alone. Until both hold, it is delegated work.
func (h *delegatedHost) settle() {
	h.mu.Lock()
	settled := h.retired && h.local
	h.mu.Unlock()
	if settled {
		h.obligation.end()
	}
}

// retire is what a final decision does to a registration whose connection is
// still up: its route is withdrawn, so no guest reaches it again. The host
// keeps its connection for its final reports.
func (h *delegatedHost) retire() {
	if release := h.withdraw(); release != nil {
		release()
	}
}

// withdraw is retire's first part: it retires the home, so no guest reaches
// it, and returns the release of the route's store entry still to run, or
// nil when there is none or the route was already withdrawn.
func (h *delegatedHost) withdraw() (release func()) {
	h.mu.Lock()
	if h.retired {
		h.mu.Unlock()
		return nil
	}
	h.retired = true
	fence, release := h.fence, h.release
	h.mu.Unlock()

	if fence != nil {
		fence()
	}
	h.settle()
	return release
}

type contextKeyDelegatedHost struct{}

func delegatedHostOf(ctx ssh.Context) *delegatedHost {
	ctx.Lock()
	defer ctx.Unlock()
	h, _ := ctx.Value(contextKeyDelegatedHost{}).(*delegatedHost)
	return h
}

type delegatedKey struct {
	sessionID  string
	generation uint64
}

// delegatedHosts is a serving relay's delegated work, and its Runtime: the
// host connections of its delegated registrations, by external session and
// generation, for the decisions pushed to them; the work still in progress;
// and the fences and the drain latch that refuse more. epoch changes whenever
// a fence or the latch does, so work taken before the change can tell.
type delegatedHosts struct {
	nodeID, bootID, nodeAddr string

	mu       sync.Mutex
	hosts    map[delegatedKey]*delegatedHost
	fences   map[string]*delegatedFence
	set      int // fences set
	draining bool
	epoch    uint64
	work     map[*delegatedObligation]struct{}

	// decisionTimeout bounds PushDecision's wait for the host; zero is
	// delegatedDecisionTimeout. Tests shorten it, under mu.
	decisionTimeout time.Duration
}

func newDelegatedHosts(nodeID, bootID, nodeAddr string) *delegatedHosts {
	return &delegatedHosts{
		nodeID:   nodeID,
		bootID:   bootID,
		nodeAddr: nodeAddr,
		hosts:    make(map[delegatedKey]*delegatedHost),
		fences:   make(map[string]*delegatedFence),
		work:     make(map[*delegatedObligation]struct{}),
	}
}

// refusedLocked reports whether new delegated work is refused: a fence is
// set, or the drain latch raised. The caller holds m.mu.
func (m *delegatedHosts) refusedLocked() bool {
	return m.set > 0 || m.draining
}

// delegatedFence is one of a runtime's named fences.
type delegatedFence struct {
	owner *delegatedHosts
	on    bool // guarded by owner.mu
}

func (f *delegatedFence) Set()   { f.change(true) }
func (f *delegatedFence) Clear() { f.change(false) }

func (f *delegatedFence) change(on bool) {
	m := f.owner
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.on == on {
		return
	}
	f.on = on
	if on {
		m.set++
	} else {
		m.set--
	}
	m.epoch++
}

func (m *delegatedHosts) Fence(name string) Fence {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.fences[name]
	if !ok {
		f = &delegatedFence{owner: m}
		m.fences[name] = f
	}
	return f
}

// Resume releases only the drain latch. The fences stay as they are.
func (m *delegatedHosts) Resume() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.draining {
		m.draining = false
		m.epoch++
	}
}

// Counts includes work the authority is still deciding, and registrations
// whose raw transport is still open.
func (m *delegatedHosts) Counts() (registrations, guests int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for w := range m.work {
		if w.guest {
			guests++
		} else {
			registrations++
		}
	}
	return registrations, guests
}

// Drain raises the latch before it enumerates the work. The closes run
// outside the lock, and never wait for the authority.
func (m *delegatedHosts) Drain(ctx context.Context) error {
	m.mu.Lock()
	if !m.draining {
		m.draining = true
		m.epoch++
	}
	closers := make([]func(), 0, len(m.work))
	for w := range m.work {
		if w.fence != nil {
			w.fence()
		}
		closers = append(closers, w.close)
	}
	m.mu.Unlock()
	for _, close := range closers {
		close()
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		r, g := m.Counts()
		if r == 0 && g == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func (m *delegatedHosts) Identity() (nodeID, bootID, nodeAddr string) {
	return m.nodeID, m.bootID, m.nodeAddr
}

// delegatedObligation is one piece of delegated work, from before the
// authority is asked until its connection ends. epoch is the runtime's when
// the work began; guest marks a guest's or a hop's; close ends its raw
// transports; fence, once its home exists, retires that home.
type delegatedObligation struct {
	owner *delegatedHosts
	epoch uint64
	guest bool
	close func()
	fence func()
}

// begin takes an obligation for a new registration, unless a fence or the
// latch refuses it, when it returns nil.
func (m *delegatedHosts) begin(close func()) *delegatedObligation {
	return m.take(false, close)
}

// beginGuest takes an obligation for a new guest, or a hop to a delegated
// registration, as begin does a registration's. Without a runtime there is
// none to take.
func (m *delegatedHosts) beginGuest(close func()) *delegatedObligation {
	if m == nil {
		return nil
	}
	return m.take(true, close)
}

func (m *delegatedHosts) take(guest bool, close func()) *delegatedObligation {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refusedLocked() {
		return nil
	}
	w := &delegatedObligation{owner: m, epoch: m.epoch, guest: guest, close: close}
	m.work[w] = struct{}{}
	return w
}

func (w *delegatedObligation) end() {
	w.owner.mu.Lock()
	delete(w.owner.work, w)
	w.owner.mu.Unlock()
}

// publish runs fn under the runtime's lock, and only if w is still held and
// neither a fence nor the latch has changed since w began. fn must never do
// network I/O.
func (w *delegatedObligation) publish(fn func()) bool {
	w.owner.mu.Lock()
	defer w.owner.mu.Unlock()
	_, held := w.owner.work[w]
	if !held || w.owner.refusedLocked() || w.epoch != w.owner.epoch {
		return false
	}
	fn()
	return true
}

func (m *delegatedHosts) add(ctx context.Context, h *delegatedHost) {
	key := delegatedKey{h.registration.Session.ExternalSessionId, h.registration.Generation}
	m.mu.Lock()
	m.hosts[key] = h
	m.mu.Unlock()
	context.AfterFunc(ctx, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.hosts[key] == h {
			delete(m.hosts, key)
		}
	})
}

func (m *delegatedHosts) get(sessionID string, generation uint64) *delegatedHost {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hosts[delegatedKey{sessionID, generation}]
}

func delegatedRefusal(code DelegatedErrorCode) (bool, []byte) {
	b, err := proto.Marshal(&DelegatedError{Code: code})
	if err != nil {
		return false, nil
	}
	return false, b
}

// delegatedCode is the code a host is refused with for err from the
// authority.
func delegatedCode(err error) DelegatedErrorCode {
	var refused *DelegatedRefusedError
	if errors.As(err, &refused) && refused.Code != DelegatedErrorCode_DELEGATED_ERROR_UNSPECIFIED {
		if _, ok := DelegatedErrorCode_name[int32(refused.Code)]; ok {
			return refused.Code
		}
	}
	return DelegatedErrorCode_DELEGATED_UNAVAILABLE
}

// createDelegatedSession registers sessReq, which asks for a delegated
// registration. It is never registered as a local session instead: without
// an authority it is refused. The request must be well formed and proven
// before the authority could see it, and a dark authority is never asked.
// The authority's decision comes before any routing state: only
// DELEGATED_CURRENT goes on to register and adopt as a local registration
// would. The other decisions are answered with the derived session ID and no
// SSH user, and the connection is kept for final reports.
func (s *sshd) createDelegatedSession(work *sshWorkRef, ctx ssh.Context, conn *gossh.ServerConn, size int, sessReq *CreateSessionRequest) (bool, []byte) {
	if s.Authority == nil {
		return false, []byte(delegatedUnsupported)
	}
	delegated := sessReq.DelegatedSession
	if size > maxDelegatedPayload || !s.wellFormedDelegated(sessReq) {
		s.Logger.Warn("refused a malformed delegated registration")
		return delegatedRefusal(DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
	}

	sessionID, generation, err := s.sessionIdentity(ctx, sessReq)
	if err != nil {
		s.Logger.Warn("refused a session proof", "error", err, "node", s.NodeAddr)
		return delegatedRefusal(DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
	}

	// A dark authority decides nothing, and is never asked.
	if !s.AuthorityEnabled {
		return delegatedRefusal(DelegatedErrorCode_DELEGATED_UNAVAILABLE)
	}

	ctx.Lock()
	registrationID, _ := ctx.Value(contextKeyDownstreamSessionID{}).([]byte)
	origin, _ := ctx.Value(contextKeyHostOrigin{}).(GuestOrigin)
	ctx.Unlock()
	origin.NodeID = s.NodeID
	if origin.Ingress != Ingress_INGRESS_SSH || origin.NodeAddr != s.NodeAddr || !bytes.Equal(origin.SSHSessionID, registrationID) || origin.Source == "" {
		return delegatedRefusal(DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
	}
	reg := DelegatedRegistration{Session: delegated, Generation: generation, RegistrationID: bytes.Clone(registrationID), Contact: s.delegatedContact(ctx), Origin: origin, HomeNode: s.NodeAddr, HomeNodeID: s.NodeID, HomeBootID: s.BootID}
	if len(sessReq.HostKeyProof) > 0 {
		// sessionIdentity parsed and verified this very key.
		reg.RunPublicKey, _, _, _, _ = gossh.ParseAuthorizedKey(sessReq.HostPublicKeys[0])
		reg.RoutingID = sessionID
	}

	// One delegated registration per connection: its reports and decisions
	// would otherwise have two registrations to belong to.
	if delegatedHostOf(ctx) != nil {
		return delegatedRefusal(DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
	}

	logger := s.Logger.With("session-id", sessionID, "external-session-id", delegated.ExternalSessionId, "generation", generation)
	obligation := s.delegated.begin(func() {
		if raw := s.hostActivity.lookup(registrationID); raw != nil {
			_ = raw.Close()
		}
		_ = conn.Close()
	})
	if obligation == nil {
		return delegatedRefusal(DelegatedErrorCode_DELEGATED_UNAVAILABLE)
	}
	kept := false
	defer func() {
		if !kept {
			obligation.end()
		}
	}()
	result, err := s.Authority.Register(ctx, reg.clone())
	if err != nil {
		code := delegatedCode(err)
		logger.Warn("the authority refused a registration", "error", err, "code", code)
		return delegatedRefusal(code)
	}
	if !ValidDelegatedDisposition(result.Disposition, result.DecisionRevision) ||
		(result.Disposition == DelegatedDisposition_DELEGATED_CURRENT && (!validUUID(result.AccountID) || reg.HomeNode == "" || reg.HomeNodeID == "" || !validUUID(reg.HomeBootID))) {
		logger.Error("the authority answered a registration with no decision", "disposition", result.Disposition, "revision", result.DecisionRevision)
		return delegatedRefusal(DelegatedErrorCode_DELEGATED_UNAVAILABLE)
	}

	sessResp := &CreateSessionResponse{SessionID: sessionID}
	if result.Disposition == DelegatedDisposition_DELEGATED_CURRENT {
		var refusal []byte
		if sessResp, refusal = s.register(work, ctx, conn, sessReq, sessionID, generation, &RegistrationRef{
			Authority: AuthorityDelegated, AccountID: result.AccountID, SessionID: delegated.ExternalSessionId, Generation: generation, RoutingID: sessionID,
			RunPublicKeys: [][]byte{reg.RunPublicKey.Marshal()}, RegistrationID: reg.RegistrationID, HomeNode: reg.HomeNode, HomeNodeID: reg.HomeNodeID, HomeBootID: reg.HomeBootID,
		}, obligation); sessResp == nil {
			switch {
			case refusal == nil:
				return false, nil
			case bytes.Equal(refusal, []byte(registration.Superseded)):
				return delegatedRefusal(DelegatedErrorCode_DELEGATED_STALE_GENERATION)
			default:
				return delegatedRefusal(DelegatedErrorCode_DELEGATED_UNAVAILABLE)
			}
		}
	}
	sessResp.DelegatedSession = &DelegatedSession{
		Protocol:          delegated.Protocol,
		ExternalSessionId: delegated.ExternalSessionId,
		Disposition:       result.Disposition,
		DecisionRevision:  result.DecisionRevision,
	}
	b, err := proto.Marshal(sessResp)
	if err != nil {
		return delegatedRefusal(DelegatedErrorCode_DELEGATED_UNAVAILABLE)
	}

	host := &delegatedHost{registration: reg, conn: conn, obligation: obligation, retired: result.Disposition != DelegatedDisposition_DELEGATED_CURRENT}
	if published := ownedRegistration(ctx, sessionID); result.Disposition == DelegatedDisposition_DELEGATED_CURRENT && published != nil {
		host.fence = func() {
			// The home goes first, and the listener with it; the forward that
			// bound it can't be opened again: the registration has ended.
			s.sessions.fence(published)
			s.forwardHandler.untrack(published)
		}
		host.release = func() {
			// The store's entry goes last, as sshd work, so that a stop waits
			// for it. A stopping sshd takes no more work, and leaves the
			// release to the end of the host's connection.
			work, ok := s.work.enter()
			if !ok {
				return
			}
			defer work.done()
			s.sessions.end(published)
		}
	}
	ctx.Lock()
	ctx.SetValue(contextKeyDelegatedHost{}, host)
	ctx.Unlock()
	s.delegated.add(ctx, host)
	if s.beforePublish != nil {
		s.beforePublish(ctx)
	}
	if !obligation.publish(func() { kept = true }) {
		host.retire()
		obligation.close()
		return delegatedRefusal(DelegatedErrorCode_DELEGATED_UNAVAILABLE)
	}
	context.AfterFunc(ctx, obligation.end)
	// Only now: a decision pushed before publication must not end the
	// obligation publication needs. The connection's requests are served one
	// at a time, so no local registration is made meanwhile.
	if madeLocalRegistration(ctx) {
		host.registeredLocally()
	}
	// A current registration's connection is pinged once it is adopted. A
	// final one is kept only for the host's final reports, and is pinged
	// alike, so a host that falls silent while its connection stays open
	// ends, and stops being counted.
	if result.Disposition != DelegatedDisposition_DELEGATED_CURRENT {
		s.pingOnce(ctx, sessionID, conn)
	}
	logger.Info("registered a delegated session", "disposition", result.Disposition, "revision", result.DecisionRevision)
	return true, b
}

// delegatedContact reports what the relay observes of the host connection
// ctx is for: whether it is still open, and when the host last sent
// anything, judged by the same reads that judge its silence. See pingOnce.
func (s *sshd) delegatedContact(ctx ssh.Context) func() Contact {
	ctx.Lock()
	nodeConn, _ := ctx.Value(contextKeyActivity{}).(*liveness.Conn)
	downstreamSessionID, _ := ctx.Value(contextKeyDownstreamSessionID{}).([]byte)
	ctx.Unlock()
	activity := s.hostActivity.lookup(downstreamSessionID)
	if activity == nil {
		activity = nodeConn
	}
	return func() Contact {
		contact := Contact{Connected: ctx.Err() == nil}
		if activity != nil {
			contact.LastContact = activity.LastRead()
		}
		return contact
	}
}

// wellFormedDelegated checks a delegated registration's own shape: a protocol
// the authority accepts, an external session ID, no disposition, a proof to
// derive its route from, and no guest keys of its own, since the authority
// decides who joins.
func (s *sshd) wellFormedDelegated(req *CreateSessionRequest) bool {
	d := req.DelegatedSession
	return d.Protocol != "" && slices.Contains(s.Protocols, d.Protocol) && validUUID(d.ExternalSessionId) &&
		d.Disposition == DelegatedDisposition_DELEGATED_UNSPECIFIED && d.DecisionRevision == 0 &&
		len(req.HostKeyProof) > 0 && len(req.ClientAuthorizedKeys) == 0
}

// delegatedControlHandler answers a host's report on the delegated
// registration its connection made, through the authority's Control.
func (s *sshd) delegatedControlHandler(ctx ssh.Context, _ *ssh.Server, req *gossh.Request) (bool, []byte) {
	host := delegatedHostOf(ctx)
	var control DelegatedControlRequest
	if host == nil || len(req.Payload) > maxDelegatedPayload || proto.Unmarshal(req.Payload, &control) != nil {
		return delegatedRefusal(DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
	}
	sessionID, generation := host.registration.Session.ExternalSessionId, host.registration.Generation
	if control.ExternalSessionId != sessionID || control.Generation != generation || control.Sequence == 0 || !wellFormedEvent(&control) {
		return delegatedRefusal(DelegatedErrorCode_DELEGATED_INVALID_REQUEST)
	}

	sequence := control.Sequence
	logger := s.Logger.With("external-session-id", sessionID, "generation", generation, "sequence", sequence)
	reply, err := s.Authority.Control(ctx, Report{Registration: host.registration.clone(), Request: &control})
	if err != nil {
		code := delegatedCode(err)
		logger.Warn("the authority refused a control report", "error", err, "code", code)
		return delegatedRefusal(code)
	}
	if reply == nil || reply.ExternalSessionId != sessionID || reply.Generation != generation || reply.AcknowledgedSequence != sequence || !ValidDelegatedDisposition(reply.Disposition, reply.DecisionRevision) {
		logger.Error("the authority answered a control report for another one")
		return delegatedRefusal(DelegatedErrorCode_DELEGATED_UNAVAILABLE)
	}
	if reply.Disposition != DelegatedDisposition_DELEGATED_CURRENT {
		host.retire()
	}
	b, err := proto.Marshal(reply)
	if err != nil {
		return delegatedRefusal(DelegatedErrorCode_DELEGATED_UNAVAILABLE)
	}
	return true, b
}

// wellFormedEvent reports whether control carries exactly one event, and an
// exit of unknown status carries no status.
func wellFormedEvent(control *DelegatedControlRequest) bool {
	switch event := control.Event.(type) {
	case *DelegatedControlRequest_Ready:
		return event.Ready != nil
	case *DelegatedControlRequest_Exit:
		return event.Exit != nil && (event.Exit.StatusKnown || event.Exit.ExitStatus == 0)
	}
	return false
}

// PushDecision waits for the host, and for the release of a final decision's
// route, at most ctx's life and delegatedDecisionTimeout.
func (m *delegatedHosts) PushDecision(ctx context.Context, decision *DelegatedDecision) (*DelegatedDecisionAck, error) {
	if decision == nil || !validUUID(decision.ExternalSessionId) || decision.Generation == 0 || !ValidDelegatedDisposition(decision.Disposition, decision.DecisionRevision) {
		return nil, errDelegatedDecision
	}
	host := m.get(decision.ExternalSessionId, decision.Generation)
	if host == nil {
		return nil, ErrDelegatedHostNotFound
	}
	// Whatever the host makes of it, a final decision ends the relay's own
	// part: no guest reaches the registration again. The home is retired
	// before the push; the store's release of the route, which can be slow,
	// runs beside it, and is waited for only within the push's bound.
	var released chan struct{}
	if decision.Disposition != DelegatedDisposition_DELEGATED_CURRENT {
		if release := host.withdraw(); release != nil {
			released = make(chan struct{})
			go func() {
				defer close(released)
				release()
			}()
		}
	}
	payload, err := proto.Marshal(decision)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	timeout := m.decisionTimeout
	m.mu.Unlock()
	if timeout <= 0 {
		timeout = delegatedDecisionTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type answer struct {
		ok   bool
		body []byte
		err  error
	}
	// x/crypto offers no way to abandon a sent request's reply, so the wait is
	// abandoned instead: the send ends when the host answers or its
	// connection closes.
	answered := make(chan answer, 1)
	go func() {
		ok, body, err := host.conn.SendRequest(upterm.HostDelegatedDecisionRequestType, true, payload)
		answered <- answer{ok, body, err}
	}()
	var a answer
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case a = <-answered:
	}
	if released != nil {
		select {
		case <-released:
		case <-ctx.Done():
		}
	}
	if a.err != nil {
		return nil, fmt.Errorf("pushing a delegated decision: %w", a.err)
	}
	unsupported := &DelegatedRefusedError{Code: DelegatedErrorCode_DELEGATED_UNSUPPORTED}
	if !a.ok {
		if refused, ok := DecodeDelegatedError(a.body); ok {
			return nil, refused
		}
		return nil, unsupported
	}
	var ack DelegatedDecisionAck
	if len(a.body) > maxDelegatedPayload || proto.Unmarshal(a.body, &ack) != nil ||
		ack.ExternalSessionId != decision.ExternalSessionId || ack.Generation != decision.Generation || ack.DecisionRevision != decision.DecisionRevision {
		return nil, unsupported
	}
	return &ack, nil
}
