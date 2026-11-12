package server

import (
	"bytes"
	"context"
	"slices"
	"sync/atomic"
)

// SessionAuthority is what a registration answers to, fixed when its home
// node adopts it.
type SessionAuthority string

const (
	// AuthorityLocal is a registration this relay admitted on its own.
	AuthorityLocal SessionAuthority = "local"
	// AuthorityDelegated is a registration an authority outside the relay
	// admitted.
	AuthorityDelegated SessionAuthority = "delegated"
)

// RegistrationRef identifies one adopted registration: what it answers to,
// what it registered, and the node and connection that hold it.
type RegistrationRef struct {
	Authority      SessionAuthority
	AccountID      string // delegated only, from the authority
	SessionID      string // the external session ID if delegated; the routing ID if local
	Generation     uint64 // a legacy local registration may be 0; delegated is at least 1
	RoutingID      string
	RunPublicKeys  [][]byte // canonical SSH wire bytes, in order; exactly one if delegated
	RegistrationID []byte   // the host connection's own SSH session ID
	HomeNode       string   // the NodeAddr the hop reaches
	HomeNodeID     string
	HomeBootID     string
}

// Home is a registration as the node that adopted it holds it. Its reference
// never changes. Held reports whether the node still serves it; once it
// doesn't, Done is closed, and neither changes again. A home is retired before
// its route is released and before its host connection is closed, so nothing
// that finds it held can outlive that.
//
// Confirm checks, within ctx, that the registration is still held: a home on
// this node answers as Held does, and a home on another node is asked over
// the hop, within 2 seconds. A home that fails the check over the hop is
// retired, and its hop closed.
//
// Over the hop, Confirm is answered only once the guest's allow has been
// asserted, so it fails for the home a GuestRequest carries while Admit is
// still deciding. A check that fails, ctx ending first included, retires the
// home and closes its hop, and with it the guest. One check runs at a time:
// a second begun before the first has answered fails both.
type Home interface {
	Ref() RegistrationRef
	Held() bool
	Done() <-chan struct{}
	Confirm(ctx context.Context) bool
}

func (r RegistrationRef) clone() RegistrationRef {
	r.RegistrationID = bytes.Clone(r.RegistrationID)
	r.RunPublicKeys = slices.Clone(r.RunPublicKeys)
	for i := range r.RunPublicKeys {
		r.RunPublicKeys[i] = bytes.Clone(r.RunPublicKeys[i])
	}
	return r
}

// localHome is the home of a registration this node adopted. It survives a
// rebuild of its route, but never a new registration, even of the same ID and
// generation. Its reference is private; callers receive bytes of their own.
type localHome struct {
	ref  RegistrationRef
	held atomic.Bool
	done chan struct{}
}

func newLocalHome(ref RegistrationRef) *localHome {
	h := &localHome{ref: ref.clone(), done: make(chan struct{})}
	h.held.Store(true)
	return h
}

func (h *localHome) Ref() RegistrationRef  { return h.ref.clone() }
func (h *localHome) Held() bool            { return h.held.Load() }
func (h *localHome) Done() <-chan struct{} { return h.done }

// retire ends the home. Only the first call does anything.
func (h *localHome) retire() {
	if h.held.Swap(false) {
		close(h.done)
	}
}

// localAuthorityRegistry finds the homes of the registrations this node has
// adopted. It reads localSessions under its lock, the one adoption and
// retirement take, and never the route store or its cache: a route only says
// where a session was registered, not that the registration is still held. A
// delegated registration's pending reservation has its home, but isn't
// adopted, so isn't found.
type localAuthorityRegistry struct{ sessions *localSessions }

// Lookup returns the home of the registration this node serves for routingID,
// while it is held.
func (r *localAuthorityRegistry) Lookup(routingID string) (Home, bool) {
	l := r.sessions
	l.mu.Lock()
	defer l.mu.Unlock()
	lr, ok := l.regs[routingID]
	if !ok || lr.reg.pending || !lr.home.Held() {
		return nil, false
	}
	return lr.home, true
}

// Lookup returns the home of the registration this sshd serves for
// routingID, while it is held. It reads only this sshd's adopted
// registrations, never a route cache; before Serve there are none.
func (s *sshd) Lookup(routingID string) (Home, bool) {
	s.mux.Lock()
	authorities := s.authorities
	s.mux.Unlock()
	if authorities == nil {
		return nil, false
	}
	return authorities.Lookup(routingID)
}
