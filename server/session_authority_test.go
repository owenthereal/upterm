package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

func TestRouteAuthorityHint(t *testing.T) {
	for _, hint := range []string{`"local"`, `"delegated"`} {
		var session Session
		require.NoError(t, json.Unmarshal([]byte(`{"ID":"route","NodeAddr":"home","mode":`+hint+`}`), &session))
		encoded, err := json.Marshal(&session)
		require.NoError(t, err)
		var fields map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(encoded, &fields))
		require.JSONEq(t, hint, string(fields["mode"]), "a known hint must survive route serialization")
	}
	for _, hint := range []string{`null`, `false`, `42`, `{}`, `[]`, `"future"`} {
		var session Session
		require.NoError(t, json.Unmarshal([]byte(`{"ID":"route","NodeAddr":"home","mode":`+hint+`}`), &session))
		require.Equal(t, "route", session.ID)
		require.Empty(t, session.AuthorityHint)
		require.True(t, session.IsClientKeyAllowed(certTestSigner(t).PublicKey()))
		session.ClientAuthorizedKeys = []ssh.PublicKey{certTestSigner(t).PublicKey()}
		require.False(t, session.IsClientKeyAllowed(certTestSigner(t).PublicKey()))
	}
}

func TestLegacyLifetimeIsNotIdentity(t *testing.T) {
	for _, generation := range []uint64{0, 1} {
		t.Run(fmt.Sprint(generation), func(t *testing.T) {
			logger := slog.New(slog.DiscardHandler)
			store := newReleaseWitnessStore(2)
			store.SessionStore = newMemorySessionStore(logger)
			sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
			work := newTestSSHWork(t, store.releaseHolds)
			sessions := newLocalSessions(work.owner, provider.NewDiscardProvider(), sm, logger)
			registry := &localAuthorityRegistry{sessions: sessions}
			// Fresh registrations reuse identical metadata, even the same Session pointer.
			session := &Session{ID: "same-id", NodeAddr: "home", Generation: generation}
			first, _, err := sm.Register(t.Context(), session)
			require.NoError(t, err)
			_, err = sessions.add(work, first, newCloser())
			require.NoError(t, err)
			old, found := registry.Lookup(session.ID)
			require.True(t, found)
			sessions.end(first)
			_, err = sm.GetSession(session.ID)
			require.Error(t, err)
			delayed := make(chan struct{})
			go func() { sessions.end(first); close(delayed) }()
			t.Cleanup(func() { store.releaseHolds(); ownershipJoin(t, delayed, "delayed old cleanup") })
			store.call(t, 2) // This stale Release starts before its same-identity successor.
			next, _, err := sm.Register(t.Context(), session)
			require.NoError(t, err)
			_, err = sessions.add(work, next, newCloser())
			require.NoError(t, err)
			t.Cleanup(func() { sessions.end(next) })
			fresh, found := registry.Lookup(session.ID)
			require.True(t, found)
			require.True(t, old != fresh, "fresh registration must have a new home lifetime")
			store.releaseHolds()
			require.True(t, ownershipJoin(t, delayed, "delayed old cleanup"))
			route, err := sm.GetSession(session.ID)
			require.NoError(t, err, "old cleanup must not delete its successor's memory route")
			require.Same(t, session, route)
			same, found := registry.Lookup(session.ID)
			require.True(t, found)
			require.True(t, fresh == same)
			require.False(t, old.Held())
			require.True(t, fresh.Held())
			require.NoError(t, sm.Renew(t.Context(), next))
			// A stale callback may also start after the successor is published.
			sessions.end(first)
			lateRoute, err := sm.GetSession(session.ID)
			require.NoError(t, err, "late old cleanup must not delete its successor's route")
			require.Same(t, session, lateRoute)
			late, found := registry.Lookup(session.ID)
			require.True(t, found)
			require.True(t, fresh == late, "late old cleanup must preserve the current home")
			require.True(t, fresh.Held())
			require.NoError(t, sm.Renew(t.Context(), next))
		})
	}
}

// fenceProbeListener reports, as it closes, whatever closed reports.
type fenceProbeListener struct {
	net.Listener
	closed func()
}

func (l *fenceProbeListener) Close() error {
	l.closed()
	if l.Listener != nil {
		return l.Listener.Close()
	}
	return nil
}

// homeRetired reports whether home is retired: not held, and Done closed.
func homeRetired(home Home) bool {
	if home.Held() {
		return false
	}
	select {
	case <-home.Done():
		return true
	default:
		return false
	}
}

func TestFencePrecedesListenerClose(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	sm := newEmbeddedSessionManager(logger)
	work := newSSHSessionWork()
	ref, _ := work.enter()
	defer ref.done()
	sessions := newLocalSessions(work, provider.NewDiscardProvider(), sm, logger)
	reg := &Registration{Session: &Session{ID: "fence", NodeAddr: "home"}}
	_, err := sessions.add(ref, reg, newCloser())
	require.NoError(t, err)
	home, ok := (&localAuthorityRegistry{sessions: sessions}).Lookup("fence")
	require.True(t, ok)
	handler := newStreamlocalForwardHandler(work, sm, nil, sessions, logger)
	fencedAtClose := false
	handler.trackListener(reg, &fenceProbeListener{closed: func() { fencedAtClose = homeRetired(home) }})
	require.True(t, handler.untrack(reg))
	require.True(t, fencedAtClose, "listener close must see the registration already fenced")
	sessions.end(reg)
}

// A listener, and the home it serves, are the registration's that bound it:
// an earlier registration of the same identity can close or fence neither.
func TestUntrackLeavesAnotherHomesListener(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	sm := newEmbeddedSessionManager(logger)
	work := newSSHSessionWork()
	ref, _ := work.enter()
	defer ref.done()
	sessions := newLocalSessions(work, provider.NewDiscardProvider(), sm, logger)
	conn := newCloser()
	earlier := &Registration{Session: &Session{ID: "fence", NodeAddr: "home"}}
	_, err := sessions.add(ref, earlier, conn)
	require.NoError(t, err)
	current := &Registration{Session: &Session{ID: "fence", NodeAddr: "home"}}
	_, err = sessions.add(ref, current, conn)
	require.NoError(t, err)
	home, ok := (&localAuthorityRegistry{sessions: sessions}).Lookup("fence")
	require.True(t, ok)
	handler := newStreamlocalForwardHandler(work, sm, nil, sessions, logger)
	closed := false
	handler.trackListener(current, &fenceProbeListener{closed: func() { closed = true }})

	require.False(t, handler.untrack(earlier))
	require.False(t, closed, "an earlier registration closed its successor's listener")
	sessions.fence(earlier)
	require.True(t, home.Held(), "an earlier registration fenced its successor's home")
	require.True(t, handler.untrack(current))
	require.True(t, closed)
	require.True(t, homeRetired(home))
	sessions.end(current)
}

// fenceProbeConn records, at the transport boundary, whether the home was
// already retired, then blocks so another lookup can observe retirement
// before any disconnect cleanup exists.
type fenceProbeConn struct {
	home    <-chan Home
	entered chan bool
	resume  <-chan struct{}
}

func (c *fenceProbeConn) Close() error {
	home := <-c.home
	c.entered <- homeRetired(home)
	<-c.resume
	return nil
}

func TestLeaseTerminationFencesBeforeClose(t *testing.T) {
	for _, ending := range []string{"superseded", "legacy_superseded", "expiry", "rebuild_bound"} {
		t.Run(ending, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				logger := slog.New(slog.DiscardHandler)
				store := &leaseStore{t: t, ttl: keeperTTL, memorySessionStore: newMemorySessionStore(logger)}
				store.renew = func(context.Context, *Registration) error {
					if ending == "expiry" {
						return errConsulDown
					}
					return ErrLeaseLost
				}
				store.reregister = func(ctx context.Context, _ *Registration) (*Registration, error) {
					if ending == "rebuild_bound" {
						<-ctx.Done()
						return nil, ctx.Err()
					}
					return nil, ErrSuperseded
				}
				sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
				gate, open := newGate(t)
				work := newTestSSHWork(t, open)
				sessions := newLocalSessions(work.owner, provider.NewDiscardProvider(), sm, logger)
				generation := uint64(1)
				if ending == "legacy_superseded" {
					generation = 0
				}
				reg, _, err := sm.Register(t.Context(), &Session{ID: "lease-home", NodeAddr: "home", Generation: generation})
				require.NoError(t, err)
				homeReady := make(chan Home, 1)
				conn := &fenceProbeConn{home: homeReady, entered: make(chan bool, 1), resume: gate}
				_, err = sessions.add(work, reg, conn)
				require.NoError(t, err)
				registry := &localAuthorityRegistry{sessions: sessions}
				home, found := registry.Lookup(reg.ID())
				require.True(t, found)
				homeReady <- home
				t.Cleanup(func() { open(); sessions.end(reg) })
				var fenced bool
				select {
				case fenced = <-conn.entered:
				case <-time.After(keeperTTL + defaultLeaseTiming.rebuildBound):
					t.Fatal("lease terminal close did not occur")
				}
				require.True(t, fenced, "lease terminal Close must observe Held=false and Done closed")
				_, found = registry.Lookup(reg.ID())
				require.False(t, found, "blocked lease transport close must not leave a joinable home")
				require.False(t, home.Held())
				open()
				synctest.Wait()
			})
		})
	}
}

// A local registration's home names it, the node that holds it and the
// connection it came over, and nothing that holds it can change that. Its
// route record names its authority.
func TestLocalHomeAndUnknownMetadata(t *testing.T) {
	const nodeID, bootID = "home-machine", "0b1e2c3d-boot"
	srv := newTestSSHD(t, func(s *sshd) {
		s.NodeID = nodeID
		s.BootID = bootID
	})
	p := newProven(t)
	host := srv.dialAs(t, "local-original")
	ok, body := p.register(t, host, "local-original", 1)
	require.True(t, ok, "%q", body)
	home, found := srv.sshd.Lookup(p.id())
	require.True(t, found)
	want := RegistrationRef{Authority: AuthorityLocal, SessionID: p.id(), Generation: 1, RoutingID: p.id(),
		RunPublicKeys: [][]byte{p.key.PublicKey().Marshal()}, RegistrationID: []byte("local-original"),
		HomeNode: srv.sshd.NodeAddr, HomeNodeID: nodeID, HomeBootID: bootID}
	require.Equal(t, want, home.Ref())
	copied := home.Ref()
	copied.RunPublicKeys[0][0] ^= 0xff
	copied.RegistrationID[0] ^= 0xff
	copied.RunPublicKeys = append(copied.RunPublicKeys, []byte("extra"))
	require.Equal(t, want, home.Ref(), "a caller's copy of the reference must not reach the home's")
	route, err := srv.sshd.SessionManager.GetSession(p.id())
	require.NoError(t, err)
	require.Equal(t, AuthorityLocal, route.AuthorityHint)

	legacy := srv.dialAs(t, "legacy-original")
	id := srv.createSession(t, legacy)
	home, found = srv.sshd.Lookup(id)
	require.True(t, found)
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(TestPublicKeyContent))
	require.NoError(t, err)
	require.Equal(t, RegistrationRef{Authority: AuthorityLocal, SessionID: id, RoutingID: id,
		RunPublicKeys: [][]byte{key.Marshal()}, RegistrationID: []byte("legacy-original"),
		HomeNode: srv.sshd.NodeAddr, HomeNodeID: nodeID, HomeBootID: bootID}, home.Ref())
	route, err = srv.sshd.SessionManager.GetSession(id)
	require.NoError(t, err)
	require.Equal(t, AuthorityLocal, route.AuthorityHint)
}

// A rebuild stores the same registration again: it keeps its home. A rebuilt
// handle of a registration this node no longer serves replaces nothing, even
// when it is identical to the one it does serve.
func TestRebuildKeepsTheHome(t *testing.T) {
	sessions, _, _ := newTestLocalSessions(t)
	registry := &localAuthorityRegistry{sessions: sessions}
	conn := newCloser()
	first := &Registration{Session: &Session{ID: "id", NodeAddr: "node", Generation: 1}, lease: "first"}
	_, err := sessions.add(testSSHWork(t, sessions.work), first, conn)
	require.NoError(t, err)
	firstHome, found := registry.Lookup("id")
	require.True(t, found)
	second := &Registration{Session: &Session{ID: "id", NodeAddr: "node", Generation: 1}, lease: "second"}
	_, err = sessions.add(testSSHWork(t, sessions.work), second, conn)
	require.NoError(t, err)
	t.Cleanup(func() { sessions.end(second) })
	home, found := registry.Lookup("id")
	require.True(t, found)
	want := home.Ref()

	require.False(t, sessions.replace(&Registration{Session: first.Session, lease: "first-rebuilt", home: first.home}),
		"a rebuild of an ended registration must not take its successor's slot")
	rebuilt := &Registration{Session: second.Session, lease: "second-rebuilt", home: second.home}
	require.True(t, sessions.replace(rebuilt))
	current, found := registry.Lookup("id")
	require.True(t, found)
	require.True(t, current == home, "a rebuild keeps the home")
	require.Equal(t, want, current.Ref())
	require.True(t, current != firstHome)
	require.False(t, firstHome.Held())
}

// createResult is a create-session reply, or the error sending it.
type createResult struct {
	ok   bool
	body []byte
	err  error
}

// createAsync sends a create-session request over client and delivers its
// reply, so the test can act while the relay holds the request.
func createAsync(t *testing.T, client *ssh.Client, req *CreateSessionRequest) <-chan createResult {
	t.Helper()
	payload, err := proto.Marshal(req)
	require.NoError(t, err)
	result := make(chan createResult, 1)
	go func() {
		ok, body, err := client.SendRequest(upterm.ServerCreateSessionRequestType, true, payload)
		result <- createResult{ok, body, err}
	}()
	return result
}

// provenRequest is p's create-session request at generation gen, with a proof
// bound to keyID.
func provenRequest(t *testing.T, p proven, keyID string, gen uint64) *CreateSessionRequest {
	t.Helper()
	proof, err := registration.Sign(p.key, []byte(keyID), p.secret, gen)
	require.NoError(t, err)
	return &CreateSessionRequest{HostUser: "owen", HostPublicKeys: p.hostKeys(), SessionSecret: p.secret, Generation: gen, HostKeyProof: proof}
}

func awaitSignal[T any](t *testing.T, c <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("%s never happened", what)
		var zero T
		return zero
	}
}

// Whichever way a local registration ends, its home is retired before its
// route is released: the store's Release is held as it arrives, and the home
// Lookup returned must already be retired then.
func TestLocalHomeRetiresBeforeItsRouteIsReleased(t *testing.T) {
	for _, path := range []string{"disconnect", "context_cancel", "forward_cancel", "takeover", "lease_loss"} {
		t.Run(path, func(t *testing.T) {
			logger := slog.New(slog.DiscardHandler)
			memory := newMemorySessionStore(logger)
			var base SessionStore = memory
			if path == "lease_loss" {
				// A lease the store says is lost, and a rebuild a newer
				// registration refuses: the keeper ends the registration.
				base = &leaseStore{t: t, ttl: keeperTTL, memorySessionStore: memory,
					reregister: func(context.Context, *Registration) (*Registration, error) { return nil, ErrSuperseded }}
			}
			store := newReleaseWitnessStore(1)
			store.SessionStore = base
			hostGone := make(chan *ssh.Client, 1)
			homes := make(chan Home, 1)
			srv := newTestSSHD(t, func(s *sshd) {
				s.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
				if path == "context_cancel" {
					// The host goes after the store takes its registration,
					// and before adoption confirms it.
					// Closing the client ends ctx; the test's -timeout bounds a
					// hang.
					s.onRegistered = func(ctx context.Context, _ *Registration) {
						_ = (<-hostGone).Close()
						<-ctx.Done()
					}
					s.beforeConfirm = func(reg *Registration) {
						home, _ := s.Lookup(reg.ID())
						homes <- home
					}
				}
			})
			t.Cleanup(store.releaseHolds) // before the fixture's shutdown waits on the release
			p := newProven(t)
			host := srv.dialAs(t, "conn-1")
			var home Home
			if path == "context_cancel" {
				hostGone <- host
				reply := awaitSignal(t, createAsync(t, host, provenRequest(t, p, "conn-1", 1)), "the create-session reply")
				require.Error(t, reply.err, "the host went before its reply")
				home = awaitSignal(t, homes, "adoption")
				require.NotNil(t, home)
			} else {
				ok, body := p.register(t, host, "conn-1", 1)
				require.True(t, ok, "%q", body)
				var found bool
				home, found = srv.sshd.Lookup(p.id())
				require.True(t, found)
			}

			var cancelled <-chan bool
			switch path {
			case "disconnect":
				require.NoError(t, host.Close())
			case "forward_cancel":
				ok, msg := forwardRequest(t, host, streamlocalForwardChannelType, p.id())
				require.True(t, ok, "%q", msg)
				replied := make(chan bool, 1)
				cancelled = replied
				go func() {
					// The cancel is answered once the release returns.
					ok, _, err := host.SendRequest(cancelStreamlocalForwardChannelType, true, ssh.Marshal(&streamlocalChannelForwardMsg{SocketPath: p.id()}))
					replied <- ok && err == nil
				}()
			case "takeover":
				ok, body := p.register(t, srv.dialAs(t, "conn-2"), "conn-2", 2)
				require.True(t, ok, "%q", body)
			case "lease_loss":
				// The store's watch shows the entry gone.
				srv.sshd.mux.Lock()
				sessions := srv.sshd.sessions
				srv.sshd.mux.Unlock()
				sessions.observe(1, 1, map[string]StoreEntry{})
			}

			call := store.call(t, 1)
			require.Equal(t, p.id(), call.reg.ID())
			require.Equal(t, uint64(1), call.reg.Generation())
			require.True(t, homeRetired(home), "the route was released while its home was still held")
			if current, found := srv.sshd.Lookup(p.id()); found {
				require.True(t, current != home, "Lookup returned a home whose route is being released")
			}
			store.releaseHolds()
			awaitSignal(t, call.returned, "the release")
			if cancelled != nil {
				require.True(t, awaitSignal(t, cancelled, "the cancel reply"))
			}
		})
	}
}

// Lookup finds only registrations this node has adopted and still holds:
// not one the store has taken but this node has yet to adopt, not one the
// store's cache holds that this node never adopted, and not one that has
// ended.
func TestRegistryHoldsOnlyAdoptedLiveRegistrations(t *testing.T) {
	_, found := (&sshd{}).Lookup("any")
	require.False(t, found, "an sshd that hasn't served holds nothing")

	fake := newFakeConsul(t, monotonicIndexes)
	store := newFakeConsulStore(t, fake)
	arrived, resume := make(chan string, 1), make(chan struct{})
	ended := make(chan struct{}, 1)
	srv := newTestSSHD(t, func(s *sshd) {
		s.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeConsul))
		s.onRegistered = func(_ context.Context, reg *Registration) {
			arrived <- reg.ID()
			<-resume
		}
		s.onEnded = func(*Registration) {
			select {
			case ended <- struct{}{}:
			default:
			}
		}
	})
	open := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(open)

	p := newProven(t)
	host := srv.dialAs(t, "conn-1")
	reply := createAsync(t, host, provenRequest(t, p, "conn-1", 1))
	require.Equal(t, p.id(), awaitSignal(t, arrived, "the registration reaching its adoption"))
	require.True(t, store.HasInCache(p.id()), "the store has taken the registration")
	_, found = srv.sshd.Lookup(p.id())
	require.False(t, found, "a registration this node has yet to adopt has no home")
	open()
	result := awaitSignal(t, reply, "the create-session reply")
	require.NoError(t, result.err)
	require.True(t, result.ok, "%q", result.body)
	home, found := srv.sshd.Lookup(p.id())
	require.True(t, found)
	require.True(t, home.Held())

	// Another registration of this node's, as the store's watch delivers it,
	// that this sshd never adopted.
	cached := &Session{AuthorityHint: AuthorityLocal, ID: "cached-only", NodeAddr: srv.sshd.NodeAddr, Generation: 1}
	store.cache.Set(cached.ID, cachedSession{session: cached, index: 1, lease: "elsewhere"}, store.cache.Epoch())
	require.True(t, store.HasInCache(cached.ID))
	_, err := srv.sshd.SessionManager.GetSession(cached.ID)
	require.NoError(t, err)
	_, found = srv.sshd.Lookup(cached.ID)
	require.False(t, found, "a cached route is not a registration this node holds")

	require.NoError(t, host.Close())
	awaitSignal(t, ended, "the registration's end")
	_, found = srv.sshd.Lookup(p.id())
	require.False(t, found, "an ended registration has no home")
	require.False(t, home.Held())
}

// Two registrations of one ID, generation and node are two homes: the first
// is retired when the second takes its slot, even on the same connection.
func TestSameIDRegistrationIsANewHome(t *testing.T) {
	sessions, _, _ := newTestLocalSessions(t)
	registry := &localAuthorityRegistry{sessions: sessions}
	conn := newCloser()
	first := &Registration{Session: &Session{ID: "legacy", NodeAddr: "home"}}
	_, err := sessions.add(testSSHWork(t, sessions.work), first, conn)
	require.NoError(t, err)
	firstHome, found := registry.Lookup("legacy")
	require.True(t, found)
	second := &Registration{Session: &Session{ID: "legacy", NodeAddr: "home"}}
	_, err = sessions.add(testSSHWork(t, sessions.work), second, conn)
	require.NoError(t, err)
	t.Cleanup(func() { sessions.end(second) })
	secondHome, found := registry.Lookup("legacy")
	require.True(t, found)

	require.True(t, firstHome != secondHome, "a second registration must have a home of its own")
	require.Equal(t, firstHome.Ref(), secondHome.Ref(), "the two differ only in being two")
	require.True(t, homeRetired(firstHome))
	require.True(t, secondHome.Held())
	select {
	case <-secondHome.Done():
		t.Fatal("the second registration's home is done")
	default:
	}
}

// A registration whose home is fenced binds no listener, even while its slot
// and its host connection remain.
func TestFencedRegistrationRefusesForwards(t *testing.T) {
	srv := newTestSSHD(t)
	p := newProven(t)
	host := srv.dialAs(t, "conn-1")
	ok, body := p.register(t, host, "conn-1", 1)
	require.True(t, ok, "%q", body)
	srv.sshd.mux.Lock()
	sessions := srv.sshd.sessions
	srv.sshd.mux.Unlock()
	sessions.mu.Lock()
	reg := sessions.regs[p.id()].reg
	sessions.mu.Unlock()

	sessions.fence(reg)
	require.NotNil(t, srv.slot(p.id()), "the fence leaves the slot for end")
	ok, msg := forwardRequest(t, host, streamlocalForwardChannelType, p.id())
	require.False(t, ok, "a fenced registration bound a listener: %q", msg)
}
