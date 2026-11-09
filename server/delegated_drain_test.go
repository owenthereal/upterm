package server

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// The runtime's drain stands alone: a relay with no delegated work drains at
// once, and counts none.
func TestDrainFenceSeam(t *testing.T) {
	var rt Runtime = newDelegatedHosts("", "", "")
	require.NoError(t, rt.Drain(context.Background()))
	r, g := rt.Counts()
	require.Zero(t, r)
	require.Zero(t, g)
}

// A drain closes a delegated registration's transport, and leaves a local
// one's alone.
func TestRawDrainPreservesLocalSessions(t *testing.T) {
	s := newDelegatedTestServer(t, &fakeAuthority{})
	rt := s.runtime()
	local := dialHost(t, s.addr, s.signer, nil)
	ok, body := sendCreate(t, local, newProven(t).delegatedRequest(t, local, 1, nil))
	require.True(t, ok, "%q", body)
	delegated := dialHost(t, s.addr, s.signer, nil)
	host := newProven(t)
	ok, body = sendCreate(t, delegated, host.delegatedRequest(t, delegated, 1, delegatedSession()))
	require.True(t, ok, "%q", body)
	r, g := rt.Counts()
	require.Equal(t, 1, r)
	require.Zero(t, g)
	call, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, rt.Drain(call))
	_, _, err := delegated.SendRequest("probe", true, nil)
	require.Error(t, err)
	_, _, err = local.SendRequest("probe", true, nil)
	require.NoError(t, err)
	r, g = rt.Counts()
	require.Zero(t, r)
	require.Zero(t, g)
}

// A registration the authority is still deciding when a drain comes is
// counted, its transport is closed, and it can't publish once the drain is
// resumed: the epoch it began in is gone.
func TestPendingRegistrationCannotPublishAfterResume(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	authority := &fakeAuthority{register: func(DelegatedRegistration) (RegistrationResult, error) {
		close(entered)
		<-release
		return RegistrationResult{AccountID: fixtureAccountID, Disposition: DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, nil
	}}
	s := newDelegatedTestServer(t, authority)
	rt := s.runtime()
	client := dialHost(t, s.addr, s.signer, nil)
	host := newProven(t)
	done := createAsync(t, client, host.delegatedRequest(t, client, 1, delegatedSession()))
	<-entered
	r, _ := rt.Counts()
	require.Equal(t, 1, r, "a registration the authority is deciding was not counted")
	call, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	require.ErrorIs(t, rt.Drain(call), context.DeadlineExceeded)
	cancel()
	rt.Resume()
	close(release)
	result := awaitSignal(t, done, "the registration's end")
	require.Error(t, result.err, "the raw host transport survived the drain")
	require.Eventually(t, func() bool { r, g := rt.Counts(); return r == 0 && g == 0 }, 5*time.Second, time.Millisecond)
	_, err := s.SessionManager.GetSession(host.id())
	require.Error(t, err, "a late registration appeared after the drain was resumed")
}

// Each fence is independent of the others and of the drain latch, and work
// that began before any of them changed can't publish, however they end.
func TestIndependentFencesAndLatePublication(t *testing.T) {
	rt := newDelegatedHosts("", "", "")
	old := rt.begin(func() {})
	require.NotNil(t, old)
	defer old.end()
	first, second := rt.Fence("first"), rt.Fence("second")
	require.Same(t, first, rt.Fence("first"), "the same name gave another fence")
	first.Set()
	second.Set()
	first.Clear()
	rt.Resume()
	require.Nil(t, rt.begin(func() {}), "a resume cleared a fence")
	first.Set()
	second.Clear()
	require.Nil(t, rt.begin(func() {}))
	first.Clear()
	require.False(t, old.publish(func() { t.Fatal("a late reply published after the fences cleared") }))
	next := rt.begin(func() {})
	require.NotNil(t, next)
	require.True(t, next.publish(func() {}))
	next.end()
}

// A fence refuses new registrations and closes nothing; a drain closes what
// there is, and a resume leaves the fence set.
func TestDrainWithControlFenceKeepsExistingTransport(t *testing.T) {
	s := newDelegatedTestServer(t, &fakeAuthority{})
	rt := s.runtime()
	delegated := dialHost(t, s.addr, s.signer, nil)
	host := newProven(t)
	ok, body := sendCreate(t, delegated, host.delegatedRequest(t, delegated, 1, delegatedSession()))
	require.True(t, ok, "%q", body)
	rt.Fence("control").Set()
	_, _, err := delegated.SendRequest("probe", true, nil)
	require.NoError(t, err, "a fence alone closed the transport")
	r, g := rt.Counts()
	require.Equal(t, 1, r)
	require.Zero(t, g)
	late := dialHost(t, s.addr, s.signer, nil)
	ok, body = sendCreate(t, late, newProven(t).delegatedRequest(t, late, 1, delegatedSession()))
	requireDelegatedError(t, ok, body, DelegatedErrorCode_DELEGATED_UNAVAILABLE)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, rt.Drain(ctx))
	_, _, err = delegated.SendRequest("probe", true, nil)
	require.Error(t, err, "the drain returned before the raw close")
	r, g = rt.Counts()
	require.Zero(t, r)
	require.Zero(t, g)
	rt.Resume()
	require.Nil(t, rt.begin(func() {}), "a resume cleared the fence")
}

// A delegated registration is adopted only if no fence was set, and none
// changed, from before the authority is asked until its route is published;
// a drain at any of those points closes its connection. Once published, a
// fence leaves it alone and a drain closes it.
func TestDelegatedAdoptionIsAtomicWithFences(t *testing.T) {
	type checkpoint string
	const (
		beforeRegister checkpoint = "before Register"
		registerHeld   checkpoint = "Register held"
		storeHeld      checkpoint = "after the pending add"
		beforePublish  checkpoint = "before publish"
		published      checkpoint = "after publication"
	)
	type action string
	const (
		set      action = "Set"
		setClear action = "Set then Clear"
		drain    action = "Drain"
	)
	type outcome struct {
		reply     bool               // a reply arrives
		ok        bool               // and accepts
		code      DelegatedErrorCode // or refuses with this
		registers bool               // the authority was asked
		route     bool               // the route is published at the end
	}
	// expect is each outcome by the rules: a fence or drain in force before
	// the obligation refuses it; an epoch change between the obligation and
	// the pending add, or between it and adoption, makes the store's add
	// stale; one before publication retires the host and closes its
	// connection; a drain closes the connection wherever the work is; after
	// publication only a drain ends the route.
	expect := func(c checkpoint, a action) outcome {
		switch c {
		case beforeRegister:
			if a == setClear {
				return outcome{reply: true, ok: true, registers: true, route: true}
			}
			return outcome{reply: true, code: DelegatedErrorCode_DELEGATED_UNAVAILABLE}
		case registerHeld, storeHeld:
			if a == drain {
				return outcome{registers: true}
			}
			return outcome{reply: true, code: DelegatedErrorCode_DELEGATED_STALE_GENERATION, registers: true}
		case beforePublish:
			return outcome{registers: true}
		default:
			if a == drain {
				return outcome{reply: true, ok: true, registers: true}
			}
			return outcome{reply: true, ok: true, registers: true, route: true}
		}
	}

	for _, c := range []checkpoint{beforeRegister, registerHeld, storeHeld, beforePublish, published} {
		for _, a := range []action{set, setClear, drain} {
			want := expect(c, a)
			t.Run(string(c)+"/"+string(a), func(t *testing.T) {
				authority := &fakeAuthority{}
				store := &publishStore{SessionStore: newMemorySessionStore(slog.New(slog.DiscardHandler)), arrived: make(chan struct{}), resume: make(chan struct{})}
				var resumeOnce sync.Once
				resumeStore := func() { resumeOnce.Do(func() { close(store.resume) }) }
				t.Cleanup(resumeStore)
				if c != storeHeld {
					resumeStore()
				}
				hookArrived, hookRelease := make(chan struct{}), make(chan struct{})
				var hookOnce sync.Once
				releaseHook := func() { hookOnce.Do(func() { close(hookRelease) }) }
				t.Cleanup(releaseHook)
				srv := delegatedSSHD(t, authority, func(s *sshd) {
					s.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
					if c == beforePublish {
						s.beforePublish = func(ctx context.Context) {
							close(hookArrived)
							select {
							case <-hookRelease:
							case <-ctx.Done():
							}
						}
					}
				})
				rt := srv.sshd.delegated
				fence := rt.Fence("f")
				drained := make(chan error, 1)
				act := func() {
					switch a {
					case set:
						fence.Set()
					case setClear:
						fence.Set()
						fence.Clear()
					case drain:
						go func() {
							ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
							defer cancel()
							drained <- rt.Drain(ctx)
						}()
					}
				}
				var arrived <-chan struct{}
				var releaseRegister func()
				if c == registerHeld {
					arrived, releaseRegister = authority.gate()
				}

				p := newProven(t)
				host := originHost(t, srv, "original", Ingress_INGRESS_SSH)
				if c == beforeRegister {
					act()
					if a == drain {
						require.NoError(t, <-drained, "a drain with no work waited")
					}
				}
				done := createAsync(t, host, originRequest(t, p, "original", 1))
				switch c {
				case registerHeld:
					awaitSignal(t, arrived, "Register")
					act()
					if a != drain {
						releaseRegister()
					}
				case storeHeld:
					awaitSignal(t, store.arrived, "the store's Register")
					act()
					if a == drain {
						// The connection is closed before the store answers.
						result := awaitSignal(t, done, "the reply")
						require.Error(t, result.err)
						done = nil
					}
					resumeStore()
				case beforePublish:
					awaitSignal(t, hookArrived, "the publication")
					act()
					// A drain releases the hook itself, by closing the host's
					// connection.
					if a != drain {
						releaseHook()
					}
				}
				var result createResult
				if done != nil {
					result = awaitSignal(t, done, "the reply")
				}
				if c == published {
					require.NoError(t, result.err)
					require.True(t, result.ok, "%q", result.body)
					act()
				}
				if a == drain && c != beforeRegister {
					require.NoError(t, awaitSignal(t, drained, "the drain"))
				}

				switch {
				case c == storeHeld && a == drain:
				case !want.reply:
					require.Error(t, result.err, "a reply arrived: ok=%v %q", result.ok, result.body)
				case want.ok:
					require.NoError(t, result.err)
					require.True(t, result.ok, "%q", result.body)
					var resp CreateSessionResponse
					require.NoError(t, proto.Unmarshal(result.body, &resp))
					require.Equal(t, p.id(), resp.SessionID)
				default:
					require.NoError(t, result.err)
					requireDelegatedError(t, result.ok, result.body, want.code)
				}
				registrations, _ := authority.seen()
				require.Equal(t, want.registers, len(registrations) == 1, "the authority was asked %d times", len(registrations))

				// The whole end state, read again on each look.
				require.Eventually(t, func() bool {
					_, routeErr := srv.sshd.SessionManager.GetSession(p.id())
					_, held := srv.sshd.Lookup(p.id())
					r, g := rt.Counts()
					if want.route {
						return routeErr == nil && held && r == 1 && g == 0
					}
					return routeErr != nil && !held && slotOf(srv, p.id()) == nil && r == 0 && g == 0
				}, 5*time.Second, time.Millisecond)
				if want.route {
					_, _, err := host.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil)
					require.NoError(t, err, "a fence closed a published registration's connection")
				}
			})
		}
	}
}

// A drain closes what the authority is deciding without waiting for it: an
// authority that never answers holds up nothing.
func TestRuntimeDrainNeverWaitsOnTheAuthority(t *testing.T) {
	authority := &fakeAuthority{}
	arrived, _ := authority.gate()
	authority.hangs()
	s := newDelegatedTestServer(t, authority)
	rt := s.runtime()
	client := dialHost(t, s.addr, s.signer, nil)
	host := newProven(t)
	done := createAsync(t, client, host.delegatedRequest(t, client, 1, delegatedSession()))
	awaitSignal(t, arrived, "Register")
	r, _ := rt.Counts()
	require.Equal(t, 1, r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, rt.Drain(ctx))
	r, g := rt.Counts()
	require.Zero(t, r)
	require.Zero(t, g)
	result := awaitSignal(t, done, "the registration's end")
	require.Error(t, result.err, "the host's transport outlived the drain")
	require.Equal(t, 1, authority.calls(), "the drain called the authority")
	_, err := s.SessionManager.GetSession(host.id())
	require.Error(t, err)
	require.NoError(t, ctx.Err(), "the drain used up its context")
}
