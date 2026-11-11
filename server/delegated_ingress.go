package server

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/owenthereal/upterm/routing"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// admitTimeout caps the time Admit is given, whatever is left of the
// handshake's budget.
const admitTimeout = 5 * time.Second

// Home is the one registration the guest's admission is bound to, once an
// allow has bound it: the home its session ID led to, or, for a claimed user,
// the one its allow named. It is nil until then, Admit included: during
// Admit, a session ID's guest's home is the request's GuestRequest.Home. The
// guests of one connection share it, so a key the authority refused reports
// the home of the key it went on to allow.
func (g *Guest) Home() Home {
	g.conn.mu.Lock()
	defer g.conn.mu.Unlock()
	return g.conn.home
}

// Confirm answers as Held does, while ctx lasts.
func (h *localHome) Confirm(ctx context.Context) bool {
	return ctx.Err() == nil && h.Held()
}

// bindHome binds the guest to home, the exact registration allowed names,
// while it is still held. A guest is bound to one home only.
func (g *guestConn) bindHome(home Home, allowed RegistrationRef) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx.Err() != nil || home == nil || !home.Held() || g.home != nil && g.home != home || !proto.Equal(gateRegistration(home.Ref()), gateRegistration(allowed)) {
		return false
	}
	g.home = home
	return true
}

// routedMetadata is a connection's metadata with the user it is routed as.
type routedMetadata struct {
	ssh.ConnMetadata
	user string
}

func (m routedMetadata) User() string { return m.user }

// ingressRoute finds the home of a guest's route, and plans the attempt to
// it: the route meta's user names, or fresh's, a session the store was just
// read for, or ref's, the registration a claimed user's allow named. A home
// on this node is the one this node holds, with nothing dialled. A home on
// another node is reached over a gate hop, which becomes the guest's
// upstream. In embedded routing, a session ID alone names a session on this
// node; that reaches only a delegated registration, since a local session's
// guest is held to the user its host shared, as everywhere else.
//
// A hop on a route that can be refreshed is given at most first, when set;
// for ref's, half of what is left of ctx. A failed attempt returns the route
// it was on, when there is one to refresh: a session on this node that no
// registration here holds any longer is one.
func (p *SSHRouting) ingressRoute(ctx context.Context, g *guestConn, meta ssh.ConnMetadata, key ssh.PublicKey, ref *RegistrationRef, fresh *Session, first time.Duration) (*preparedRoute, Home, error) {
	a := p.Auth
	if a.authorities == nil {
		return nil, nil, errGateRefused
	}
	routeMeta := meta
	if ref != nil {
		user := ref.RoutingID
		if a.SessionManager.GetRoutingMode() == routing.ModeEmbedded {
			user = a.SessionManager.GetEncodeDecoder().Encode(ref.RoutingID, ref.HomeNode)
		}
		routeMeta = routedMetadata{meta, user}
	}
	var (
		target *upstreamTarget
		err    error
	)
	bare := false
	if fresh != nil {
		target = a.targetOf(fresh)
	} else {
		target, err = a.resolve(routeMeta, routeMeta.User())
		if err != nil && ref == nil && a.SessionManager.GetRoutingMode() == routing.ModeEmbedded && !strings.Contains(meta.User(), ":") {
			var session *Session
			session, err = a.SessionManager.GetSession(meta.User())
			if err == nil {
				target = a.targetOf(session)
				routeMeta = routedMetadata{meta, a.SessionManager.GetEncodeDecoder().Encode(session.ID, session.NodeAddr)}
				bare = true
			}
		}
		if err != nil {
			return nil, nil, err
		}
	}
	if target.local != nil {
		home, ok := a.authorities.Lookup(target.id.Id)
		if !ok {
			return &preparedRoute{id: target.id, route: target.route}, nil, errGateRefused
		}
		session, ok := localHomeSession(a.authorities, home)
		if !ok {
			return nil, nil, errGateRefused
		}
		target.local, target.home = session, home
		if home.Ref().Authority == AuthorityLocal && (bare || !target.admits(key)) {
			return nil, nil, errGateRefused
		}
	}
	ingress, node, session := originOf(a.listener, meta, a.NodeAddr)
	auth := &AuthRequest{ClientVersion: string(meta.ClientVersion()), RemoteAddr: meta.RemoteAddr().String(), LocalAddr: meta.LocalAddr().String(), AuthorizedKey: ssh.MarshalAuthorizedKey(key), Ingress: ingress, IngressNode: node, IngressConnection: session, TypedAddress: meta.User(), TargetRoutingId: target.id.Id, IngressNodeId: a.NodeID, ConnectionId: g.guest.ConnectionID, GateProtocol: 1}
	localSigners, err := a.newUserCertSigners(routeMeta, auth)
	if err != nil {
		return nil, nil, err
	}
	signers := a.Signers
	if len(a.HopSigners) > 0 {
		signers = a.HopSigners[:1]
	}
	hopSigners, err := signHopCerts(meta, auth, signers)
	if err != nil {
		return nil, nil, err
	}
	pr := a.plan(routeMeta, target, routeCreds{relay: []ssh.AuthMethod{ssh.PublicKeys(localSigners...)}, hop: []ssh.AuthMethod{ssh.PublicKeys(hopSigners...)}, gate: true})
	pr.delegatedGate = true
	if target.home != nil {
		return pr, target.home, nil
	}
	attempt := ctx
	if pr.route.Generation > 0 && a.canRefresh(meta) {
		within := first
		if deadline, ok := ctx.Deadline(); ok && ref != nil {
			within = time.Until(deadline) / 2
		}
		if within > 0 {
			var cancel context.CancelFunc
			attempt, cancel = context.WithTimeout(ctx, within)
			defer cancel()
		}
	}
	upstream, err := p.upstreamAttempt(attempt, g.ctx, pr)
	if err != nil {
		return pr, nil, err
	}
	if upstream.home == nil && (ref != nil || a.AuthorityEnabled || a.RefuseLegacyHops) {
		upstream.Close()
		return pr, nil, errGateRefused
	}
	g.upstream = upstream
	return pr, upstream.home, nil
}

// admitGuest decides the guest that signed with offered, once it has: a local
// session's guest as the session does, and any other only as the authority
// does, and only once the authority is enabled. Admit is asked with at most
// admitTimeout, within what is left of the handshake's budget for a claimed
// user and of the time its home was reached in for a session ID, and only for
// a claimed user or a session ID whose home reports a delegated registration,
// on SSH ingress whose origin the relay can vouch for. An allow binds the
// guest to the exact registration it names, and is honoured only while it
// lasts, while that registration is held, and once its home has accepted the
// assertion over the hop. The admission is delegated work, which a fence or
// the drain latch refuses.
//
// Until a session ID's home reports a delegated registration, it is reached
// as the stock path reaches its target once the handshake is done: within
// stage, half the handshake timeout, from then on; a first hop on a route
// that can be refreshed within half of that; and a first attempt that fails
// retried once on the route the store then holds. admitTimeout bounds only
// the authority's part, from the authority's first call on.
func (p *SSHRouting) admitGuest(g *guestConn, meta ssh.ConnMetadata, offered ssh.PublicKey, handshakeDeadline time.Time, stage time.Duration) error {
	a := p.Auth
	key, claimed, err := a.guestKey(meta, offered)
	if err != nil {
		return err
	}
	id, err := newConnectionID()
	if err != nil {
		return err
	}
	ingress, node, session := originOf(a.listener, meta, a.NodeAddr)
	origin := originFromAuth(&AuthRequest{Ingress: ingress, IngressNode: node, IngressConnection: session, RemoteAddr: meta.RemoteAddr().String()})
	origin.NodeID, origin.ConnectionID = a.NodeID, id
	guest := &Guest{Origin: origin, Key: key, Fingerprint: publicKeyFingerprint(key), ConnectionID: id, Source: meta.RemoteAddr(), conn: g}
	g.guest = guest
	accepted := false
	defer func() {
		if !accepted {
			if g.upstream != nil {
				g.upstream.Close()
				g.upstream = nil
			}
			g.guest = nil
			guest.refused.Store(true)
		}
	}()
	// The handshake waits for the admission, so the guest's transport is
	// given as long as reaching a session ID's home is, and no longer once the
	// guest is refused.
	transport := handshakeDeadline
	defer func() {
		if !accepted && transport.After(handshakeDeadline) {
			_ = g.raw.SetDeadline(handshakeDeadline)
		}
	}()
	var route *preparedRoute
	var home Home
	if !claimed {
		reach, cancelReach := context.WithTimeout(g.ctx, stage)
		defer cancelReach()
		if deadline, _ := reach.Deadline(); deadline.After(transport) {
			transport = deadline
			_ = g.raw.SetDeadline(transport)
		}
		// One attempt: the home, over a hop if it is on another node, and a
		// local registration's host if it is on this one.
		attempt := func(fresh *Session, first time.Duration) (*preparedRoute, Home, error) {
			route, home, err := p.ingressRoute(reach, g, meta, key, nil, fresh, first)
			if err == nil && home != nil && home.Ref().Authority == AuthorityLocal && g.upstream == nil {
				g.upstream, err = p.upstreamAttempt(reach, g.ctx, route)
			}
			return route, home, err
		}
		route, home, err = attempt(nil, stage/2)
		if err != nil && route != nil && route.route.Generation > 0 && a.canRefresh(meta) && !errors.Is(err, errUpstreamHostKeyMismatch) && reach.Err() == nil {
			if fresh, moved, refreshErr := a.SessionManager.RefreshRoute(reach, meta.User(), route.route); refreshErr == nil && moved {
				route, home, err = attempt(fresh, 0)
			}
		}
		if err != nil {
			return err
		}
		if home == nil {
			if reach.Err() != nil || a.AuthorityEnabled || a.RefuseLegacyHops {
				return errGateRefused
			}
			g.admission = Admission{Verdict: VerdictAllow, Target: Target{Registration: RegistrationRef{Authority: AuthorityLocal}}}
			accepted = true
			return nil
		}
		if home.Ref().Authority == AuthorityLocal {
			if !g.bindHome(home, home.Ref()) || g.ctx.Err() != nil || !home.Held() {
				return errGateRefused
			}
			g.admission = Admission{Verdict: VerdictAllow, Target: Target{Registration: home.Ref()}}
			accepted = true
			return nil
		}
	}
	ctx, cancel := context.WithDeadline(g.ctx, minTime(transport, time.Now().Add(admitTimeout)))
	defer cancel()
	if !a.AuthorityEnabled || origin.Ingress != Ingress_INGRESS_SSH || origin.Source == "" || origin.NodeAddr == "" || origin.NodeID == "" {
		return errGuestRefused
	}
	obligation := a.delegated.beginGuest(g.forceClose)
	if obligation == nil {
		return errGuestRefused
	}
	defer func() {
		if !accepted {
			obligation.end()
		}
	}()
	go func() { <-g.done; obligation.end() }()
	// A verdict returned once Admit's context has ended is refused, whatever
	// it is.
	admission, err := a.authority.Admit(ctx, guest, GuestRequest{User: meta.User(), Home: home})
	if err != nil || ctx.Err() != nil || g.ctx.Err() != nil {
		return errGuestRefused
	}
	switch admission.Verdict {
	case VerdictWaiting:
		now := time.Now()
		if !claimed || !validWaiting(admission.Waiting, meta.User(), guest.Fingerprint, now) {
			return errGuestRefused
		}
		admission.Waiting = frozenWaiting(admission.Waiting, now)
		admission.Message = bytes.Clone(admission.Message)
		if !obligation.publish(func() { g.admission = admission }) {
			return errGuestRefused
		}
		accepted = true
		return nil
	case VerdictMessage:
		if !claimed {
			return errGuestRefused
		}
		if !obligation.publish(func() { g.admission = admission }) {
			return errGuestRefused
		}
		accepted = true
		return nil
	case VerdictAllow:
	default:
		return errGuestRefused
	}
	// An allowed candidate owns its transport until success or exact cleanup.
	failed := true
	defer func() {
		if failed {
			g.forceClose()
		}
	}()
	allowed := admission.Target.Registration
	if !admission.Target.valid() || admission.Sequence == 0 || !time.Now().Before(admission.AllowUntil) {
		return errGuestRefused
	}
	if home == nil {
		route, home, err = p.ingressRoute(ctx, g, meta, key, &allowed, nil, 0)
		if err != nil {
			return err
		}
	}
	if !g.bindHome(home, allowed) {
		return errGateRefused
	}
	if ctx.Err() != nil || !time.Now().Before(admission.AllowUntil) {
		return errGuestClosed
	}
	if remote, ok := home.(*remoteHome); ok {
		assertion := &GateAdmission{Protocol: 1, ModeNonce: bytes.Clone(remote.nonce), Registration: gateRegistration(allowed), IngressNodeId: origin.NodeID, ConnectionId: id, IngressSshSessionId: bytes.Clone(origin.SSHSessionID), KeyFingerprint: guest.Fingerprint, Sequence: admission.Sequence, Capabilities: admission.Target.Capabilities}
		if err = assertHomeAdmission(ctx, home, assertion); err != nil {
			return err
		}
	} else {
		current, ok := a.authorities.Lookup(allowed.RoutingID)
		if !ok || current != home {
			return errGateRefused
		}
		g.upstream, err = p.upstreamAttempt(ctx, g.ctx, route)
		if err != nil {
			return err
		}
	}
	if ctx.Err() != nil || g.ctx.Err() != nil || !home.Held() || !time.Now().Before(admission.AllowUntil) {
		return errGuestClosed
	}
	if !obligation.publish(func() { g.admission = admission }) {
		return errGuestRefused
	}
	go func() {
		select {
		case <-home.Done():
			g.forceClose()
		case <-g.ctx.Done():
		}
	}()
	accepted, failed = true, false
	return nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
