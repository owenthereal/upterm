package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/version"
	"github.com/owenthereal/upterm/upterm"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The hop gate, gate-v1. Before a node forwards a guest's hop to another node,
// it can ask that node, over the hop, which registration it holds for the
// session: the gate's mode exchange. The answer binds the hop to the exact
// registration the home node holds, so a hop is never forwarded on a stale
// route. A node advertises that it answers the exchange with the gate-v1
// token, appended to its SSH server version as an RFC 4253 comment.
//
// Gate hops are dormant unless a node refuses legacy hops. Such a node gates
// every hop it starts, and refuses every hop that doesn't use the gate. Any
// other node hops as nodes did before the gate: the guest's own SSH user, as
// the hop's user and its certificate's principal, gate_protocol 0, and no gate
// request. Every node answers the exchange for the registrations it holds, on
// its internal listener, which no host connects to, and on a shared listener
// only once it gates: a host reads the server version too, and releases from
// before the token can't read a version with a comment.

// gateTimeout bounds each gate exchange: an answer is in time at exactly
// gateTimeout after its request was sent, and late a nanosecond after.
const gateTimeout = 5 * time.Second

// maxGatePayload bounds a gate message, and a gate hop's AuthRequest.
const maxGatePayload = 64 * 1024

// gateToken is the server-version comment of a listener that answers the
// gate.
const gateToken = "gate-v1"

var errGateRefused = errors.New("authenticated home gate refused")

// homeLookup finds the registration a node holds for a routing ID.
type homeLookup interface {
	Lookup(string) (Home, bool)
}

// serverVersion is the version a listener identifies itself with: this
// build's, followed by the gate token when the listener advertises the gate.
func serverVersion(advertise bool) string {
	v := version.ServerSSHVersion()
	if advertise {
		v += " " + gateToken
	}
	return v
}

// localSession returns the session this sshd adopted with home, while home is
// held.
func (s *sshd) localSession(home Home) (*Session, bool) {
	s.mux.Lock()
	authorities := s.authorities
	s.mux.Unlock()
	if authorities == nil {
		return nil, false
	}
	return authorities.localSession(home)
}

// localSession returns the session adopted with this exact live home. Route
// caches can lag or be replaced and cannot supply local authorization keys.
func (r *localAuthorityRegistry) localSession(home Home) (*Session, bool) {
	l := r.sessions
	l.mu.Lock()
	defer l.mu.Unlock()
	lr, ok := l.regs[home.Ref().RoutingID]
	if !ok || lr.home != home || !home.Held() {
		return nil, false
	}
	session := *lr.reg.Session
	session.HostPublicKeys = slices.Clone(session.HostPublicKeys)
	session.ClientAuthorizedKeys = slices.Clone(session.ClientAuthorizedKeys)
	return &session, true
}

// localHomeSession is the session registry adopted with home, with home's run
// keys as its host keys, or false if home is no longer what registry holds.
func localHomeSession(registry homeLookup, home Home) (*Session, bool) {
	local, ok := registry.(interface {
		localSession(Home) (*Session, bool)
	})
	if !ok {
		return nil, false
	}
	session, ok := local.localSession(home)
	if !ok || session == nil {
		return nil, false
	}
	ref := home.Ref()
	if session.ID != ref.RoutingID || session.Generation != ref.Generation || session.NodeAddr != ref.HomeNode {
		return nil, false
	}
	copy := *session
	copy.HostPublicKeys = nil
	for _, wire := range ref.RunPublicKeys {
		key, err := ssh.ParsePublicKey(wire)
		if err != nil {
			return nil, false
		}
		copy.HostPublicKeys = append(copy.HostPublicKeys, key)
	}
	return &copy, true
}

// stillHeld reports whether home is still the registration this node holds
// for its routing ID: an attempt bound to it goes on only while it is.
func (a proxyAuth) stillHeld(home Home) bool {
	current, ok := a.authorities.Lookup(home.Ref().RoutingID)
	return ok && current == home && home.Held()
}

// gateName reports whether name is a gate request: the mode request, or the
// admission or held check a delegated session's gate makes. A guest's own
// global requests never pass under such a name, so a node that forwards a
// guest never hands a newer home a gate request the guest made up.
func gateName(name string) bool {
	switch name {
	case upterm.GateModeRequestType, "gate-admit@upterm.dev", "gate-held@upterm.dev":
		return true
	}
	return false
}

// scanGate rejects protobuf ambiguities before unmarshal can discard them.
func scanGate(b []byte, desc protoreflect.MessageDescriptor) error {
	seen := make(map[protowire.Number]bool)
	for len(b) > 0 {
		number, kind, n := protowire.ConsumeTag(b)
		if n < 0 {
			return errGateRefused
		}
		b = b[n:]
		field := desc.Fields().ByNumber(number)
		if field == nil || (!field.IsList() && seen[number]) {
			return errGateRefused
		}
		seen[number] = true
		expected := protowire.BytesType
		switch field.Kind() {
		case protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.EnumKind, protoreflect.BoolKind:
			expected = protowire.VarintType
		}
		if kind != expected {
			return errGateRefused
		}
		if kind == protowire.VarintType {
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return errGateRefused
			}
			if field.Kind() == protoreflect.EnumKind && (v > 1<<31-1 || field.Enum().Values().ByNumber(protoreflect.EnumNumber(v)) == nil) {
				return errGateRefused
			}
			if field.Kind() == protoreflect.Uint32Kind && v > uint64(^uint32(0)) {
				return errGateRefused
			}
			if field.Kind() == protoreflect.BoolKind && v > 1 {
				return errGateRefused
			}
			b = b[n:]
		} else {
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return errGateRefused
			}
			if field.Kind() == protoreflect.MessageKind {
				if err := scanGate(v, field.Message()); err != nil {
					return err
				}
			}
			b = b[n:]
		}
	}
	return nil
}

func decodeGate(b []byte, dst proto.Message) error {
	if len(b) > maxGatePayload {
		return errGateRefused
	}
	if err := scanGate(b, dst.ProtoReflect().Descriptor()); err != nil {
		return err
	}
	if err := proto.Unmarshal(b, dst); err != nil {
		return errGateRefused
	}
	switch v := dst.(type) {
	case *GateModeRequest:
		if v.Protocol != 1 || len(v.Nonce) != 32 || !gateID(v.RoutingId) {
			return errGateRefused
		}
	case *GateModeReply:
		if v.Protocol != 1 || len(v.Nonce) != 32 || validGateRegistration(v.Registration) != nil {
			return errGateRefused
		}
	}
	return nil
}

func gateID(s string) bool {
	return s != "" && len(s) <= 1024 && !strings.ContainsAny(s, "\x00\r\n\t ")
}

// validGateRegistration accepts a local registration: one that answers to no
// account, with its routing ID as its session ID.
func validGateRegistration(r *GateRegistration) error {
	if r == nil || !gateID(r.RoutingId) || !gateID(r.SessionId) || !gateID(r.HomeNode) || len(r.RegistrationId) == 0 || len(r.RunPublicKeys) == 0 {
		return errGateRefused
	}
	switch r.Mode {
	case GateMode_GATE_MODE_LOCAL:
		if r.AccountId != "" || r.SessionId != r.RoutingId {
			return errGateRefused
		}
	default:
		return errGateRefused
	}
	for _, wire := range r.RunPublicKeys {
		key, err := ssh.ParsePublicKey(wire)
		if err != nil || !bytes.Equal(key.Marshal(), wire) {
			return errGateRefused
		}
	}
	return nil
}

func gateRegistration(r RegistrationRef) *GateRegistration {
	mode := GateMode_GATE_MODE_UNSPECIFIED
	switch r.Authority {
	case AuthorityLocal:
		mode = GateMode_GATE_MODE_LOCAL
	case AuthorityDelegated:
		mode = GateMode_GATE_MODE_DELEGATED
	}
	return &GateRegistration{Mode: mode, AccountId: r.AccountID, SessionId: r.SessionID, Generation: r.Generation, RoutingId: r.RoutingID, RunPublicKeys: r.clone().RunPublicKeys, RegistrationId: bytes.Clone(r.RegistrationID), HomeNode: r.HomeNode, HomeNodeId: r.HomeNodeID, HomeBootId: r.HomeBootID}
}

func registrationRef(r *GateRegistration) RegistrationRef {
	authority := AuthorityLocal
	if r.Mode == GateMode_GATE_MODE_DELEGATED {
		authority = AuthorityDelegated
	}
	return (RegistrationRef{Authority: authority, AccountID: r.AccountId, SessionID: r.SessionId, Generation: r.Generation, RoutingID: r.RoutingId, RunPublicKeys: r.RunPublicKeys, RegistrationID: r.RegistrationId, HomeNode: r.HomeNode, HomeNodeID: r.HomeNodeId, HomeBootID: r.HomeBootId}).clone()
}

// gateWithin reports whether now is no later than deadline.
func gateWithin(now, deadline time.Time) bool { return !now.After(deadline) }

// sendGate permits only one in-flight control operation. Cancellation closes
// the transport, releasing x/crypto's synchronous SendRequest wait.
func sendGate(ctx context.Context, u *upstreamConn, name string, request proto.Message) ([]byte, error) {
	if !u.gateBusy.CompareAndSwap(false, true) {
		u.Close()
		return nil, errGateRefused
	}
	defer u.gateBusy.Store(false)
	b, err := proto.Marshal(request)
	if err != nil || len(b) > maxGatePayload {
		return nil, errGateRefused
	}
	sent := u.gateNow()
	deadline := sent.Add(gateTimeout)
	call, cancel := context.WithTimeout(ctx, gateTimeout)
	defer cancel()
	stop := context.AfterFunc(call, u.Close)
	defer stop()
	ok, reply, err := u.conn.SendRequest(name, true, b)
	if err != nil || call.Err() != nil || !gateWithin(u.gateNow(), deadline) || len(reply) > maxGatePayload {
		u.Close()
		return nil, errGateRefused
	}
	if !ok {
		u.Close()
		// This is a stock negative cause, never mode authority or permission
		// to retry without the gate. Only this operation has a no-home verdict.
		if name == upterm.GateModeRequestType && string(reply) == upterm.UpstreamNoHost {
			return nil, errUpstreamNoHost
		}
		return nil, errGateRefused
	}
	return reply, nil
}

func (u *upstreamConn) gateNow() time.Time {
	if u.now != nil {
		return u.now()
	}
	return time.Now()
}

// remoteHome is a snapshot bound to one verified SSH transport: the
// registration the home node answered with, held until that transport ends.
type remoteHome struct {
	ref      RegistrationRef
	nonce    []byte
	upstream *upstreamConn
	done     chan struct{}
	once     sync.Once
	alive    atomic.Bool
}

func (h *remoteHome) Ref() RegistrationRef  { return h.ref.clone() }
func (h *remoteHome) Held() bool            { return h.alive.Load() }
func (h *remoteHome) Done() <-chan struct{} { return h.done }
func (h *remoteHome) retire()               { h.once.Do(func() { h.alive.Store(false); close(h.done) }) }

// negotiateHome runs the mode exchange over upstream, and binds the hop to the
// registration the home answers with.
func negotiateHome(ctx context.Context, upstream *upstreamConn, request *GateModeRequest) (Home, error) {
	body, err := sendGate(ctx, upstream, upterm.GateModeRequestType, request)
	if err != nil {
		return nil, err
	}
	var reply GateModeReply
	if decodeGate(body, &reply) != nil || !bytes.Equal(reply.Nonce, request.Nonce) || reply.Registration.RoutingId != request.RoutingId || (upstream.homeNode != "" && reply.Registration.HomeNode != upstream.homeNode) {
		upstream.Close()
		return nil, errGateRefused
	}
	h := &remoteHome{ref: registrationRef(reply.Registration), nonce: bytes.Clone(request.Nonce), upstream: upstream, done: make(chan struct{})}
	h.alive.Store(true)
	go func() { _ = upstream.conn.Wait(); h.retire() }()
	return h, nil
}

// hasGateCapability reports whether version, a peer's authenticated server
// version, carries the gate token.
func hasGateCapability(version []byte) bool {
	for _, token := range strings.Fields(string(version)) {
		if token == gateToken {
			return true
		}
	}
	return false
}

// hopGate holds all application traffic until the certified peer has named a
// local registration.
type hopGate struct {
	auth     *AuthRequest
	home     Home
	lookup   homeLookup
	nonce    []byte
	deadline time.Time
	mode     bool
	admitted bool
	now      func() time.Time
}

func (g *hopGate) held() bool {
	if g.home == nil || !g.home.Held() {
		return false
	}
	current, ok := g.lookup.Lookup(g.home.Ref().RoutingID)
	return ok && current == g.home
}

func (g *hopGate) request(r *ssh.Request) (bool, []byte, error) {
	if !r.WantReply {
		return false, nil, errGateRefused
	}
	switch r.Type {
	case upterm.GateModeRequestType:
		received := g.now()
		var request GateModeRequest
		if g.mode || decodeGate(r.Payload, &request) != nil || request.RoutingId != g.auth.TargetRoutingId {
			return false, nil, errGateRefused
		}
		home, ok := g.lookup.Lookup(request.RoutingId)
		if !ok {
			return false, []byte(upterm.UpstreamNoHost), errGateRefused
		}
		g.home = home
		g.mode = true
		g.nonce = bytes.Clone(request.Nonce)
		g.deadline = received.Add(gateTimeout)
		ref := gateRegistration(home.Ref())
		if validGateRegistration(ref) != nil || !g.held() {
			return false, nil, errGateRefused
		}
		if ref.Mode == GateMode_GATE_MODE_LOCAL {
			g.admitted = true
		}
		b, _ := proto.Marshal(&GateModeReply{Protocol: 1, Nonce: g.nonce, Registration: ref})
		return true, b, nil
	}
	return false, nil, errGateRefused
}

// serveHopGate serves a gate hop: it answers the ingress's mode exchange,
// holding back the hop's channels and requests until then, and forwards the
// hop to the registration it named only while this node still holds it, with
// the guest's key checked against the keys that registration was adopted
// with.
func (p *SSHRouting) serveHopGate(ctx context.Context, peer sshPeer, auth *AuthRequest, key ssh.PublicKey, stage time.Duration, inst *routingInstruments) error {
	g := &hopGate{auth: auth, lookup: p.Auth.authorities, now: time.Now}
	preCtx, stopPreCtx := context.WithTimeout(ctx, stage)
	defer stopPreCtx()
	// Timers close the transport independently of the request loop: Reply
	// and channel rejection can themselves block on an unresponsive peer.
	timer := time.AfterFunc(min(stage, gateTimeout), func() { _ = peer.conn.Close() })
	defer timer.Stop()
	stopPre := context.AfterFunc(preCtx, func() { _ = peer.conn.Close() })
	defer stopPre()
	for !g.admitted {
		select {
		case <-preCtx.Done():
			return preCtx.Err()
		case ch, ok := <-peer.channels:
			if !ok {
				return errGateRefused
			}
			_ = ch.Reject(ssh.Prohibited, "home admission pending")
		case r, ok := <-peer.requests:
			if !ok {
				return errGateRefused
			}
			if !gateName(r.Type) {
				_ = r.Reply(false, nil)
				continue
			}
			ok, b, err := g.request(r)
			_ = r.Reply(ok, b)
			if err != nil {
				return err
			}
			if g.mode && !g.admitted {
				remaining := time.Until(g.deadline)
				if remaining > stage {
					remaining = stage
				}
				timer.Reset(remaining)
			}
		}
	}
	timer.Stop()
	stopPre()
	stopPreCtx()
	if !g.held() {
		return errGateRefused
	}
	ref := g.home.Ref()
	heldCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	requests := make(chan *ssh.Request, 1)
	filtered := peer
	filtered.requests = requests
	go func() {
		defer close(requests)
		for {
			select {
			case <-heldCtx.Done():
				return
			case r, ok := <-peer.requests:
				if !ok {
					return
				}
				if gateName(r.Type) {
					ok, b, err := g.request(r)
					_ = r.Reply(ok, b)
					if err != nil {
						cancel()
						_ = peer.conn.Close()
						return
					}
					continue
				}
				select {
				case requests <- r:
				case <-heldCtx.Done():
					return
				default:
					cancel()
					_ = peer.conn.Close()
					return
				}
			}
		}
	}()
	session, ok := localHomeSession(p.Auth.authorities, g.home)
	if !ok || session.NodeAddr != p.Auth.NodeAddr {
		return errGateRefused
	}
	if ref.Authority == AuthorityLocal && !session.IsClientKeyAllowed(key) {
		rejectCtx, stopReject := context.WithTimeout(heldCtx, min(stage, maxSSHRejectTimeout))
		defer stopReject()
		return rejectSSHChannels(rejectCtx, filtered, errUpstreamKeyRefused, nil)
	}
	// Host credentials retain the original certified guest and origin, but use
	// this hop's session ID for the relay-to-host certificate.
	signers, err := p.Auth.newUserCertSigners(peer.conn, auth)
	if err != nil {
		return err
	}
	target := &upstreamTarget{id: &api.Identifier{Id: ref.RoutingID, NodeAddr: ref.HomeNode, Type: api.Identifier_CLIENT}, local: session}
	pr := p.Auth.plan(peer.conn, target, routeCreds{relay: []ssh.AuthMethod{ssh.PublicKeys(signers...)}})
	upstreamCtx, stopDial := context.WithTimeout(heldCtx, stage)
	defer stopDial()
	upstream, err := p.upstreamAttempt(upstreamCtx, heldCtx, pr)
	if err != nil {
		// The ingress learns why, as from any other hop, on a fresh budget: a
		// dial or handshake timeout has spent upstreamCtx's.
		rejectCtx, stopReject := context.WithTimeout(heldCtx, min(stage, maxSSHRejectTimeout))
		defer stopReject()
		_ = rejectSSHChannels(rejectCtx, filtered, upstreamFailureReason(err), nil)
		return err
	}
	defer upstream.Close()
	if !g.held() {
		return errGateRefused
	}
	// A retired registration closes its host's upstream; the stock
	// forwarder's bounded drain still delivers what the host already sent.
	go func() {
		select {
		case <-g.home.Done():
			upstream.Close()
		case <-heldCtx.Done():
		}
	}()
	return forwardSSH(heldCtx, filtered, upstream.sshPeer, abortConnection, inst.stalledChannelAborts, nil)
}

func freshModeRequest(id string) *GateModeRequest {
	return &GateModeRequest{Protocol: 1, Nonce: randBytes(32), RoutingId: id}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("random gate nonce: %v", err))
	}
	return b
}

// newConnectionID is a random version 4 UUID, in its lowercase canonical
// form.
func newConnectionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
