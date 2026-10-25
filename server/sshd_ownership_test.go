package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// The functional rows retain their finite witnesses. The daemon producer
// drain supplies the admission seal which individual Release returns cannot.
type ownershipGate struct {
	entered             chan struct{}
	open                chan struct{}
	enterOnce, openOnce sync.Once
}

func newOwnershipGate() *ownershipGate {
	return &ownershipGate{entered: make(chan struct{}), open: make(chan struct{})}
}
func (g *ownershipGate) release() { g.openOnce.Do(func() { close(g.open) }) }
func (g *ownershipGate) hold() {
	g.enterOnce.Do(func() { close(g.entered) })
	// Deliberately not canceled by the production call's deadline. The test
	// owns this hold and must rescue it even after an assertion fails.
	<-g.open
}

type releaseCallKey struct{}
type witnessedRelease struct {
	reg      *Registration
	ordinal  int // ordinal within this ID/generation/lease, including duplicates
	sequence int
	gate     *ownershipGate
	returned chan struct{} // the underlying method returned; not its parent
	err      error         // published by returned
}

type releaseWitnessStore struct {
	SessionStore
	mu                 sync.Mutex
	calls              []*witnessedRelease
	changed            chan struct{}
	holds              map[int]*ownershipGate // immutable, global call sequence -> hold
	transportHold      bool
	registerReturned   chan struct{}
	registerOnce       sync.Once
	reregisterReturned chan struct{}
	reregisterOnce     sync.Once
}

func newReleaseWitnessStore(holds ...int) *releaseWitnessStore {
	s := &releaseWitnessStore{changed: make(chan struct{}, 1), holds: make(map[int]*ownershipGate),
		registerReturned: make(chan struct{}), reregisterReturned: make(chan struct{})}
	for _, n := range holds {
		s.holds[n] = newOwnershipGate()
	}
	return s
}
func (s *releaseWitnessStore) Register(ctx context.Context, v *Session) (*Registration, error) {
	r, err := s.SessionStore.Register(ctx, v)
	s.registerOnce.Do(func() { close(s.registerReturned) })
	return r, err
}
func (s *releaseWitnessStore) Reregister(ctx context.Context, r *Registration) (*Registration, error) {
	next, err := s.SessionStore.Reregister(ctx, r)
	s.reregisterOnce.Do(func() { close(s.reregisterReturned) })
	return next, err
}
func (s *releaseWitnessStore) Release(ctx context.Context, reg *Registration) error {
	s.mu.Lock()
	ordinal := 1
	for _, c := range s.calls {
		if c.reg.ID() == reg.ID() && c.reg.Generation() == reg.Generation() && c.reg.lease == reg.lease {
			ordinal++
		}
	}
	call := &witnessedRelease{reg: reg, ordinal: ordinal, sequence: len(s.calls) + 1, returned: make(chan struct{})}
	call.gate = s.holds[call.sequence]
	s.calls = append(s.calls, call)
	s.mu.Unlock()
	select {
	case s.changed <- struct{}{}:
	default:
	}
	if call.gate != nil && !s.transportHold {
		call.gate.hold()
	}
	call.err = s.SessionStore.Release(context.WithValue(ctx, releaseCallKey{}, call), reg)
	close(call.returned)
	return call.err
}
func (s *releaseWitnessStore) snapshot() []*witnessedRelease {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*witnessedRelease(nil), s.calls...)
}
func (s *releaseWitnessStore) releaseHolds() {
	for _, g := range s.holds {
		g.release()
	}
}
func (s *releaseWitnessStore) call(t *testing.T, sequence int) *witnessedRelease {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		for _, c := range s.snapshot() {
			if c.sequence == sequence {
				return c
			}
		}
		select {
		case <-s.changed:
		case <-timer.C:
			t.Fatalf("Release call %d never entered", sequence)
		}
	}
}

type releaseReplyHold struct{ next http.RoundTripper }

func (h releaseReplyHold) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := h.next.RoundTrip(r)
	if err == nil && strings.HasPrefix(r.URL.Path, "/v1/session/destroy/") {
		if call, ok := r.Context().Value(releaseCallKey{}).(*witnessedRelease); ok && call.gate != nil {
			call.gate.hold()
		}
	}
	return response, err
}
func (h releaseReplyHold) CloseIdleConnections() { closeTestIdleConnections(h.next) }

// Cleanup records each missing witness without skipping the remaining rescue.
func ownershipJoin(t *testing.T, done <-chan struct{}, what string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return ownershipJoinUntil(t, ctx, done, what)
}

func ownershipJoinUntil(t *testing.T, ctx context.Context, done <-chan struct{}, what string) bool {
	t.Helper()
	// Retain a completion already published, including after the aggregate
	// deadline expired while a different witness was missing.
	select {
	case <-done:
		t.Logf("ownership joined: %s", what)
		return true
	default:
	}
	select {
	case <-done:
		t.Logf("ownership joined: %s", what)
		return true
	case <-ctx.Done():
		t.Errorf("ownership unjoined: %s", what)
		return false
	}
}
func ownershipDone(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

type ownershipRequest struct {
	done     chan struct{}
	reply    hostReply
	launched bool
}

type ownershipAdoption struct {
	t           *testing.T
	h           *adoptRace
	daemon      *sshd
	store       *releaseWitnessStore
	ends        map[uint64]chan struct{}
	endOnce     map[uint64]*sync.Once
	requests    []*ownershipRequest
	clients     []*ssh.Client
	clientWaits []chan struct{}
	endsToJoin  map[uint64]bool // actual confirmation, or finite successful path after rescue
	finishOnce  sync.Once
	cleanupOK   bool
	checkClose  func()
}

func newOwnershipAdoption(t *testing.T, cfg adoptRaceConfig, holds ...int) *ownershipAdoption {
	p := &ownershipAdoption{t: t, store: newReleaseWitnessStore(holds...),
		ends:    map[uint64]chan struct{}{1: make(chan struct{}), 2: make(chan struct{})},
		endOnce: map[uint64]*sync.Once{1: {}, 2: {}}, endsToJoin: make(map[uint64]bool)}
	// Earliest fallback: before fake/store/listener/client acquisition. The
	// actual close callback also releases these holds before any bounded join.
	t.Cleanup(p.store.releaseHolds)
	p.store.transportHold = true
	cfg.transport = func(next http.RoundTripper) http.RoundTripper { return releaseReplyHold{next} }
	cfg.beforeClose = func() {
		p.finish()
		if p.checkClose != nil {
			p.checkClose()
		}
		if p.cleanupOK {
			t.Log("ownership actual store.Close boundary after controller and producer drain")
		} else {
			t.Log("ownership actual store.Close boundary after incomplete cleanup; controller returned")
		}
	}
	cfg.configure = func(h *adoptRace, d *sshd) {
		p.h = h
		p.daemon = d
		p.store.SessionStore = h.store
		d.SessionManager = newSessionManagerWithStore(p.store, routing.NewEncodeDecoder(routing.ModeConsul))
		previous := d.onEnded
		d.onEnded = func(reg *Registration) {
			if previous != nil {
				previous(reg)
			}
			if once := p.endOnce[reg.Generation()]; once != nil {
				once.Do(func() { close(p.ends[reg.Generation()]) })
			}
		}
	}
	p.h = newAdoptRace(t, cfg)
	t.Cleanup(p.finish)
	return p
}
func (p *ownershipAdoption) dial(key string) *ssh.Client {
	client := p.h.s.dialAs(p.t, key)
	p.t.Cleanup(p.h.releaseAll)
	p.clients = append(p.clients, client)
	done := make(chan struct{})
	p.clientWaits = append(p.clientWaits, done)
	go func() { _ = client.Wait(); close(done) }()
	return client
}
func (p *ownershipAdoption) send(client *ssh.Client, key string, generation uint64) *ownershipRequest {
	r := &ownershipRequest{done: make(chan struct{})}
	p.requests = append(p.requests, r) // owner before either launch
	result := p.h.send(client, key, generation)
	r.launched = true
	go func() { r.reply = <-result; close(r.done) }()
	return r
}
func (p *ownershipAdoption) reply(r *ownershipRequest, generation uint64) {
	require.True(p.t, ownershipJoin(p.t, r.done, "client request result"))
	require.NoError(p.t, r.reply.err)
	require.True(p.t, r.reply.ok, string(r.reply.body))
	p.endsToJoin[generation] = true
}
func (p *ownershipAdoption) finish() {
	p.finishOnce.Do(func() {
		if p.daemon == nil {
			p.store.releaseHolds()
			return
		}
		// One aggregate deadline bounds the controller's witness joins. There
		// is no competing outer timeout: Close waits for its actual return.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p.daemon.mux.Lock()
		if p.daemon.work == nil {
			p.daemon.work = newSSHSessionWork()
		}
		owner := p.daemon.work
		p.daemon.mux.Unlock()
		controlled := make(chan struct{})
		go func() {
			defer close(controlled)
			<-owner.sealed
			p.cleanupOK = p.rescueAndJoin(ctx)
		}()
		stopErr := p.daemon.Shutdown()
		<-controlled
		if stopErr != nil {
			p.t.Errorf("sshd Shutdown: %v", stopErr)
			p.cleanupOK = false
		}
		if p.h == nil || p.h.s == nil {
			p.cleanupOK = false
			return
		}
		if !ownershipJoinUntil(p.t, ctx, p.h.s.served, "Serve") {
			p.cleanupOK = false
		}
	})
}

func (p *ownershipAdoption) rescueAndJoin(ctx context.Context) bool {
	complete := true
	join := func(done <-chan struct{}, what string) bool {
		ok := ownershipJoinUntil(p.t, ctx, done, what)
		complete = complete && ok
		return ok
	}
	p.store.releaseHolds()
	if p.h == nil {
		return false
	}
	p.h.releaseAll()
	for _, c := range p.clients {
		_ = c.Close()
	}
	launched := false
	for _, r := range p.requests {
		if !r.launched {
			p.t.Log("ownership request allocated but not launched")
			continue
		}
		launched = true
		if join(r.done, "client SendRequest result") && r.reply.err != nil {
			p.t.Log("client request ended with error; daemon drain separately covers handler and direct disconnected end")
		}
	}
	if launched {
		join(p.store.registerReturned, "underlying Register return")
	}
	for _, done := range p.clientWaits {
		join(done, "client Wait")
	}
	if launched {
		for generation := range p.endsToJoin {
			join(p.ends[generation], fmt.Sprintf("real onEnded generation %d", generation))
		}
	}
	for _, c := range p.h.registered {
		if ownershipDone(c.entered) {
			join(c.left, "entered onRegistered hook left")
		}
	}
	for _, c := range p.h.confirming {
		if ownershipDone(c.entered) {
			join(c.left, "entered beforeConfirm hook left")
		}
	}
	for _, d := range p.h.deliveries {
		join(d.done, "manual delivery")
	}
	if p.h.rebuild != nil && ownershipDone(p.h.rebuild.entered) {
		join(p.store.reregisterReturned, "underlying Reregister return")
	}
	for _, c := range p.store.snapshot() {
		if join(c.returned, fmt.Sprintf("Release id=%s generation=%d lease=%s ordinal=%d", c.reg.ID(), c.reg.Generation(), c.reg.lease, c.ordinal)) && c.err != nil {
			p.t.Errorf("Release delegate returned error: %v", c.err)
			complete = false
		}
	}

	return complete
}
func (p *ownershipAdoption) prematureClose(call *witnessedRelease, generation uint64) {
	p.t.Helper()
	// Read at the actual callback, never after a scheduling opportunity.
	returned, ended := ownershipDone(call.returned), ownershipDone(p.ends[generation])
	p.t.Logf("ownership close snapshot: sequence=%d ordinal=%d delegateReturned=%v onEnded=%v", call.sequence, call.ordinal, returned, ended)
	if !returned || !ended {
		p.t.Errorf("premature store.Close: held Release caller or real onEnded remains live")
	}
}

func TestSSHDOriginalAndSuccessorReleaseCompletion(t *testing.T) {
	for _, successor := range []bool{false, true} {
		name := "original only"
		if successor {
			name = "installed successor"
		}
		t.Run(name, func(t *testing.T) {
			cfg := adoptRaceConfig{hold: []uint64{1}, holdRebuild: successor}
			holds := []int{1}
			if successor {
				holds = []int{1, 2, 3}
			}
			p := newOwnershipAdoption(t, cfg, holds...)
			p.endsToJoin[1] = true
			h := p.h
			client := p.dial("conn-1")
			request := p.send(client, "conn-1", 1)
			receiveWithin(t, h.registered[1].entered, "Register never reached onRegistered")
			h.reg1 = h.registered[1].reg
			h.lease1 = h.reg1.lease
			h.registered[1].release()
			p.reply(request, 1)
			sequence := 1
			if successor {
				h.consul.reset()
				h.deliverWhole()
				receiveWithin(t, h.rebuild.entered, "keeper never entered real rebuild")
				h.rebuild.release()
				receiveWithin(t, h.delay.entered(2), "rebuild reply never held after commit")
				receiveWithin(t, h.rebuild.left, "rebuild transport never returned")
				committed := h.consul.entry()
				require.NotNil(t, committed)
				require.NotEqual(t, h.lease1, committed.Session)
				h.delay.release(2)
				retirement := p.store.call(t, 1)
				receiveWithin(t, retirement.gate.entered, "original retirement response never held")
				require.Equal(t, h.lease1, retirement.reg.lease)
				require.Equal(t, 1, retirement.ordinal)
				retirement.gate.release()
				receiveWithin(t, retirement.returned, "original retirement delegate never returned")
				require.NoError(t, retirement.err)
				current := h.served()
				require.NotNil(t, current)
				require.Equal(t, committed.Session, current.lease)
				t.Logf("ownership original retirement complete: lease=%s ordinal=%d", retirement.reg.lease, retirement.ordinal)
				sequence = 2
			}
			require.NoError(t, client.Close())
			receiveWithin(t, p.clientWaits[0], "client Wait never returned")
			call := p.store.call(t, sequence)
			receiveWithin(t, call.gate.entered, "end's actual destroy response never held")
			require.False(t, ownershipDone(call.returned))
			require.False(t, ownershipDone(p.ends[1]))
			if successor {
				require.NotEqual(t, h.lease1, call.reg.lease)
			}
			p.checkClose = func() { p.prematureClose(call, 1) }
			// Keep the delegate held until shutdown seals admission. The GREEN
			// controller then releases and joins it before the Close snapshot.
		})
	}
}

type heldHandshakeConn struct {
	net.Conn
	gate *ownershipGate
	once sync.Once
}

func (c *heldHandshakeConn) Write(b []byte) (int, error) {
	c.once.Do(c.gate.hold)
	return c.Conn.Write(b)
}

func TestSSHDFixtureCleanupWithPendingRegistration(t *testing.T) {
	t.Run("handshake pending", func(t *testing.T) {
		p := newOwnershipAdoption(t, adoptRaceConfig{})
		gate := newOwnershipGate()
		t.Cleanup(gate.release)
		raw := p.h.s.rawConn(t)
		config := p.h.s.proxyConfig(t, "handshake")
		done := make(chan struct{})
		var result ssh.Conn
		var resultErr error
		// Own the hold, raw transport and real handshake result before launch.
		t.Cleanup(func() {
			gate.release()
			_ = raw.Close()
			if ownershipJoin(t, done, "initiated handshake result") {
				if result != nil {
					_ = result.Close()
				}
				t.Logf("ownership handshake result: %v", resultErr)
			}
		})
		go func() {
			result, _, _, resultErr = ssh.NewClientConn(&heldHandshakeConn{Conn: raw, gate: gate}, p.h.s.addr, config)
			close(done)
		}()
		receiveWithin(t, gate.entered, "handshake never reached first Write")
		require.False(t, ownershipDone(done))
		t.Log("MISSING WITNESS: server preauth completion; client handshake result is owned before ssh.Client exists")
	})
	for _, stage := range []string{"Register reply pending", "onRegistered pending", "beforeConfirm pending", "add refused after disconnect", "confirm refused before disconnect", "disconnect after confirm", "rebuild reply held across disconnect"} {
		t.Run(stage, func(t *testing.T) {
			cfg := adoptRaceConfig{hold: []uint64{1}}
			cfg.delay = stage == "Register reply pending"
			cfg.confirm = []uint64{1}
			cfg.holdRebuild = stage == "rebuild reply held across disconnect"
			p := newOwnershipAdoption(t, cfg)
			// These finite paths will confirm after rescue, even if Fatal occurs
			// immediately at the early checkpoint. Register that later end owner
			// before launching the request, not after the checkpoint assertion.
			if stage != "add refused after disconnect" && stage != "confirm refused before disconnect" {
				p.endsToJoin[1] = true
			}
			h := p.h
			client := p.dial("conn-1")
			request := p.send(client, "conn-1", 1)
			if cfg.delay {
				receiveWithin(t, h.delay.entered(1), "Register commit reply never held")
				require.False(t, ownershipDone(p.store.registerReturned))
				// No keeper/onEnded exists yet. Rescue owns the raw/request
				// result and the reply hold before allowing later adoption.
				p.endsToJoin[1] = true // this finite row permits confirmation after rescue
				t.Log("stage: Register reply pending; keeper and confirmed end observer not installed")
				return
			}
			receiveWithin(t, h.registered[1].entered, "onRegistered never entered")
			h.reg1 = h.registered[1].reg
			h.lease1 = h.reg1.lease
			receiveWithin(t, p.store.registerReturned, "Register delegate did not return")
			if stage == "onRegistered pending" {
				p.endsToJoin[1] = true
				t.Log("stage: onRegistered pending; keeper and confirmed end observer not installed")
				return
			}
			if stage == "add refused after disconnect" {
				second := p.dial("conn-2")
				p.endsToJoin[2] = true
				p.reply(p.send(second, "conn-2", 2), 2)
				require.NoError(t, client.Close())
				receiveWithin(t, p.clientWaits[0], "disconnected client Wait did not return")
				h.registered[1].release()
				receiveWithin(t, h.registered[1].left, "onRegistered did not leave")
				receiveWithin(t, request.done, "disconnected request result did not return")
				require.Error(t, request.reply.err)
				call := p.store.call(t, 1)
				receiveWithin(t, call.returned, "refused registration Release did not return")
				require.Equal(t, uint64(1), call.reg.Generation())
				require.NoError(t, call.err)
				t.Log("MISSING WITNESS: disconnected add-refusal handler return; Release return and client EOF do not supply it; no keeper installed for refused handle")
				return
			}
			h.registered[1].release()
			receiveWithin(t, h.registered[1].left, "onRegistered did not leave")
			receiveWithin(t, h.confirming[1].entered, "beforeConfirm never entered")
			if stage == "beforeConfirm pending" {
				p.endsToJoin[1] = true
				t.Log("stage: beforeConfirm pending; slot/keeper installed, confirmed onEnded observer not installed; cancellation is not keeper completion")
				return
			}
			if stage == "confirm refused before disconnect" {
				// Cache a newer registration without adopting it locally.
				reg2, err := h.store.Register(context.Background(), &Session{ID: h.id, NodeAddr: "node-b:22", Generation: 2})
				require.NoError(t, err)
				t.Cleanup(func() {
					if err := h.store.Release(context.Background(), reg2); err != nil {
						t.Errorf("other registration cleanup: %v", err)
					}
				})
				h.confirming[1].release()
				receiveWithin(t, h.confirming[1].left, "beforeConfirm did not leave")
				receiveWithin(t, request.done, "refused request result did not return")
				require.False(t, request.reply.ok && request.reply.err == nil)
				call := p.store.call(t, 1)
				receiveWithin(t, call.returned, "confirm refusal's retire Release did not return")
				require.NoError(t, call.err)
				t.Log("MISSING WITNESS: confirm-refusal handler and canceled keeper completion; refusal may arrive as EOF; no confirmed onEnded installed")
				return
			}
			h.confirming[1].release()
			receiveWithin(t, h.confirming[1].left, "beforeConfirm did not leave")
			p.reply(request, 1)
			if cfg.holdRebuild {
				h.consul.reset()
				h.deliverWhole()
				receiveWithin(t, h.rebuild.entered, "rebuild never entered")
				h.rebuild.release()
				receiveWithin(t, h.delay.entered(2), "rebuild reply never held")
				require.NoError(t, client.Close())
				receiveWithin(t, p.clientWaits[0], "client Wait did not return across held rebuild")
				receiveWithin(t, p.ends[1], "disconnect end did not finish while rebuild reply held")
				require.False(t, ownershipDone(p.store.reregisterReturned))
				// Let the late success reach the collector, but do not call
				// operation return a collector completion witness.
				h.delay.release(2)
				receiveWithin(t, p.store.reregisterReturned, "late rebuild delegate did not return")
				late := p.store.call(t, 2)
				receiveWithin(t, late.returned, "late rebuilt handle Release did not return")
				require.NotEqual(t, h.lease1, late.reg.lease)
				t.Log("MISSING WITNESS: canceled TCP keeper/late-result collector completion; late operation and actual Release returned separately")
			} else {
				require.NoError(t, client.Close())
				receiveWithin(t, p.clientWaits[0], "client Wait did not return")
				receiveWithin(t, p.ends[1], "real confirmed onEnded did not return")
				t.Log("confirmed disconnect: client Wait and real onEnded separately observed")
			}
		})
	}
}

// Direct rows admit no sockets, forward run groups or TTL keepers. Their
// callers are joined individually; a detached Release's return is still not
// labeled as the exit of the goroutine containing it.
type ownershipDirect struct {
	work       *sshWorkRef
	t          *testing.T
	store      *releaseWitnessStore
	sm         *SessionManager
	sessions   *localSessions
	handler    *streamlocalForwardHandler
	network    *MemoryProvider
	joins      []<-chan struct{}
	checkClose func()
}

func newOwnershipDirect(t *testing.T) *ownershipDirect {
	logger := slog.Default()
	d := &ownershipDirect{t: t, store: newReleaseWitnessStore(1), network: &MemoryProvider{}}
	d.store.SessionStore = newMemorySessionStore(logger)
	d.sm = newSessionManagerWithStore(d.store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	mp, _ := newTestMetrics(t)
	owner := newSSHSessionWork()
	d.work, _ = owner.enter()
	d.sessions = newLocalSessions(owner, mp, d.sm, logger)
	// The fallback owns all currently initiated work before assertions below.
	t.Cleanup(func() {
		if d.checkClose != nil {
			d.checkClose()
		}
		d.store.releaseHolds()
		for _, done := range d.joins {
			ownershipJoin(t, done, "direct caller/end")
		}
		for _, call := range d.store.snapshot() {
			if ownershipJoin(t, call.returned, fmt.Sprintf("direct Release sequence=%d ordinal=%d", call.sequence, call.ordinal)) && call.err != nil {
				t.Errorf("direct Release: %v", call.err)
			}
		}
		// No producer can add a new slot in these direct rows after their
		// owned calls return. End any test-installed remaining current slot.
		d.sessions.mu.Lock()
		var remaining []*Registration
		for _, slot := range d.sessions.regs {
			remaining = append(remaining, slot.reg)
		}
		d.sessions.mu.Unlock()
		for _, reg := range remaining {
			d.sessions.end(reg)
		}
		d.work.done()
		owner.seal()
		ctx, cancel := context.WithTimeout(context.Background(), serverShutDownDeadline)
		defer cancel()
		if err := owner.wait(ctx); err != nil {
			t.Errorf("direct producer drain: %v", err)
		}
		if err := d.store.Close(); err != nil {
			t.Errorf("direct store.Close: %v", err)
		}
		t.Log("ownership direct store.Close after rescued calls and producer drain")
	})
	require.NoError(t, d.network.SetOpts(nil))
	d.handler = newStreamlocalForwardHandler(d.work.owner, d.sm, d.network.Session(), d.sessions, logger)
	return d
}
func (d *ownershipDirect) register(generation uint64) *Registration {
	reg, _, err := d.sm.Register(context.Background(), &Session{ID: "ownership", NodeAddr: "node", Generation: generation})
	require.NoError(d.t, err)
	return reg
}
func (d *ownershipDirect) held() *witnessedRelease {
	call := d.store.call(d.t, 1)
	receiveWithin(d.t, call.gate.entered, "direct Release never reached wrapper-entry hold")
	require.False(d.t, ownershipDone(call.returned))
	d.checkClose = func() {
		d.t.Logf("ownership direct callback: delegateReturned=%v (wrapper-entry hold, not HTTP response)", ownershipDone(call.returned))
	}
	return call
}

type ownershipListener struct {
	net.Listener
	closed chan struct{}
	once   sync.Once
}

func (l *ownershipListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}
func (d *ownershipDirect) listener(reg *Registration) *ownershipListener {
	ln, err := d.network.Session().Listen(reg.ID())
	require.NoError(d.t, err)
	owned := &ownershipListener{Listener: ln, closed: make(chan struct{})}
	d.t.Cleanup(func() { _ = owned.Close() })
	d.handler.trackListener(reg, owned)
	return owned
}

func TestSSHDFixtureCleanupWithPendingRelease(t *testing.T) {
	t.Run("retire", func(t *testing.T) {
		d := newOwnershipDirect(t)
		reg := d.register(1)
		peer := newCloser()
		d.sessions.retire(d.work, peer, reg)
		require.True(t, peer.isClosed(), "retire waited for Release before closing peer")
		d.held()
		t.Log("retire parent returned and peer closed while Release is held; detached tail has no completion channel")
	})
	t.Run("releaseReplaced without forward", func(t *testing.T) {
		d := newOwnershipDirect(t)
		original := d.register(1)
		original.lease = "old-lease" // explicit leased-handle branch with TTL zero
		peer := newCloser()
		_, err := d.sessions.add(d.work, original, peer)
		require.NoError(t, err)
		successor := d.register(2)
		successor.lease = "new-lease"
		conn, cancel := newTestConnContext(t)
		ended := make(chan struct{})
		d.joins = append(d.joins, ended)
		daemon := &sshd{SessionManager: d.sm, sessions: d.sessions, forwardHandler: d.handler,
			Logger: slog.Default(), onEnded: func(*Registration) { close(ended) }}
		ok, body := daemon.adopt(d.work, conn, successor, nil)
		require.True(t, ok, string(body))
		require.True(t, peer.isClosed(), "takeover reply did not close old peer")
		call := d.held()
		require.Equal(t, "old-lease", call.reg.lease)
		require.True(t, d.sessions.active(successor))
		require.False(t, ownershipDone(call.returned), "takeover waited on old Release")
		cancel()
		t.Log("actual direct takeover reply and old-peer close precede old Release; new disconnect end owned separately")
	})
	t.Run("forward eviction", func(t *testing.T) {
		d := newOwnershipDirect(t)
		original := d.register(1)
		_, err := d.sessions.add(d.work, original, newCloser())
		require.NoError(t, err)
		ln := d.listener(original)
		successor := d.register(2)
		_, err = d.sessions.add(d.work, successor, newCloser())
		require.NoError(t, err)
		d.handler.evict(d.work, original)
		receiveWithin(t, ln.closed, "eviction did not close old listener")
		call := d.held()
		require.Equal(t, uint64(1), call.reg.Generation())
		require.True(t, d.sessions.active(successor))
		t.Log("forward eviction parent returned while old end's Release remains held; no accepted peers or listen run group admitted")
	})
	t.Run("forward cancel winner", func(t *testing.T) {
		d := newOwnershipDirect(t)
		reg := d.register(1)
		_, err := d.sessions.add(d.work, reg, newCloser())
		require.NoError(t, err)
		ln := d.listener(reg)
		winner := make(chan struct{})
		d.joins = append(d.joins, winner) // actual caller owner before launch
		go func() { d.handler.closeListener(reg); close(winner) }()
		d.held() // identifies the winner before launching the loser
		receiveWithin(t, ln.closed, "winner did not close listener")
		d.handler.closeListener(reg)
		require.False(t, ownershipDone(winner), "losing cancel was mistaken for winning end completion")
		t.Log("second cancel returned while first untrack winner remains held at Release")
	})
	t.Run("capable keeper late result", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			logger := slog.Default()
			operation := newOwnershipGate()
			base := &leaseStore{t: t, ttl: keeperTTL, memorySessionStore: newMemorySessionStore(logger)}
			base.reregister = func(_ context.Context, reg *Registration) (*Registration, error) {
				operation.hold() // explicitly noncooperative after cancellation
				return base.memorySessionStore.Reregister(context.Background(), reg)
			}
			store := newReleaseWitnessStore(1)
			store.SessionStore = base
			sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
			reg, _, err := sm.Register(context.Background(), &Session{ID: "late", NodeAddr: "node", Generation: 1})
			require.NoError(t, err)
			owner := newSSHSessionWork()
			work, _ := owner.enter()
			ctx, cancel := context.WithCancel(owner.keeperContext)
			runDone := make(chan struct{})
			lost := make(chan struct{}, 1)
			keeper := &leaseKeeper{sm: sm, ttl: keeperTTL, timing: defaultLeaseTiming, lost: lost,
				logger: logger, closeConn: func() {}, replace: func(*Registration) bool { return false }}
			// Gates and run-result owner exist before the keeper or its
			// capable children can launch. Bubble cleanup releases all holds.
			t.Cleanup(func() {
				cancel()
				operation.release()
				store.releaseHolds()
				ownershipJoin(t, runDone, "canceled keeper run")
				ownershipJoin(t, store.reregisterReturned, "noncooperative operation return")
				synctest.Wait()
				for _, call := range store.snapshot() {
					ownershipJoin(t, call.returned, "late-result Release delegate")
				}
				owner.seal()
				if err := owner.wait(context.Background()); err != nil {
					t.Errorf("late keeper drain: %v", err)
				}
				if err := store.Close(); err != nil {
					t.Errorf("bubble store.Close: %v", err)
				}
			})
			lost <- struct{}{}
			go func() { keeper.run(work, ctx, reg); work.done(); close(runDone) }()
			receiveWithin(t, operation.entered, "keeper rebuild did not enter noncooperative call")
			cancel()
			receiveWithin(t, runDone, "keeper run did not cancel independently of operation")
			require.False(t, ownershipDone(store.reregisterReturned))
			operation.release()
			receiveWithin(t, store.reregisterReturned, "late Reregister never returned")
			call := store.call(t, 1)
			receiveWithin(t, call.gate.entered, "late-result collector did not launch Release")
			require.False(t, ownershipDone(call.returned))
			require.True(t, ownershipDone(runDone))
			t.Log("canceled keeper run is complete while its late-result Release is live; operation, collector and release are separate scopes")
			call.gate.release()
			receiveWithin(t, call.returned, "late-result Release did not return")
			synctest.Wait()
			_, err = base.Get(reg.ID())
			require.Error(t, err, "late successful registration was not conditionally released")
		})
	})
}

// drainStore holds the real finalization entry separately from the worker
// being tested. An omitted-owner mutant can reach Close and settle here;
// neither this callback nor the worker rescues the other before the assertion.
type drainStore struct {
	*releaseWitnessStore
	closeGate     *ownershipGate
	registerGate  *ownershipGate
	registerCalls atomic.Int32
	closes        atomic.Int32
}

func newDrainStore(base SessionStore, holds ...int) *drainStore {
	witness := newReleaseWitnessStore(holds...)
	witness.SessionStore = base
	return &drainStore{releaseWitnessStore: witness, closeGate: newOwnershipGate()}
}
func (s *drainStore) Register(ctx context.Context, session *Session) (*Registration, error) {
	s.registerCalls.Add(1)
	if s.registerGate != nil {
		s.registerGate.hold()
	}
	return s.releaseWitnessStore.Register(ctx, session)
}
func (s *drainStore) Close() error {
	s.closes.Add(1)
	s.closeGate.hold()
	return s.SessionStore.Close()
}

type producerDrainFixture struct {
	t       *testing.T
	ssh     *testSSHD
	store   *drainStore
	gates   []*ownershipGate
	done    chan struct{}
	stopErr error
}

func newProducerDrainFixture(t *testing.T, store *drainStore, options ...func(*sshd)) *producerDrainFixture {
	t.Helper()
	f := &producerDrainFixture{t: t, store: store}
	options = append([]func(*sshd){func(d *sshd) {
		d.SessionManager = newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
	}}, options...)
	f.ssh = newBubbleSSHD(t, options...)
	t.Cleanup(f.finish)
	return f
}
func (f *producerDrainFixture) hold(gate *ownershipGate) { f.gates = append(f.gates, gate) }
func (f *producerDrainFixture) startStop() {
	if f.done != nil {
		return
	}
	f.done = make(chan struct{})
	go func() {
		defer close(f.done)
		f.stopErr = f.ssh.sshd.Shutdown()
		<-f.ssh.served
		f.stopErr = errors.Join(f.stopErr, f.ssh.sshd.SessionManager.Shutdown(context.Background(), f.ssh.addr))
	}()
}
func (f *producerDrainFixture) pending(class string) {
	f.t.Helper()
	<-f.ssh.sshd.work.sealed
	synctest.Wait() // Shutdown and every runnable producer have reached their held boundary.
	if ownershipDone(f.store.closeGate.entered) {
		f.t.Errorf("premature store.Close: %s is still live", class)
	}
	if ownershipDone(f.done) {
		f.t.Errorf("shutdown returned while %s is still live", class)
	}
}
func (f *producerDrainFixture) finish() {
	// Rescue all gates before any join, including Close's independent gate.
	for _, gate := range f.gates {
		gate.release()
	}
	f.store.releaseHolds()
	f.store.closeGate.release()
	f.startStop()
	<-f.done
	synctest.Wait() // Released request and worker tails have returned before completion assertions.
	if f.stopErr != nil {
		f.t.Errorf("producer fixture shutdown: %v", f.stopErr)
	}
	if f.store.closes.Load() != 1 {
		f.t.Errorf("store Close count = %d, want 1", f.store.closes.Load())
	}
}
func (f *producerDrainFixture) registration(generation uint64) *Registration {
	f.t.Helper()
	reg, _, err := f.ssh.sshd.SessionManager.Register(context.Background(), &Session{
		ID: "owned", NodeAddr: f.ssh.addr, Generation: generation})
	require.NoError(f.t, err)
	return reg
}
func (f *producerDrainFixture) enter() *sshWorkRef {
	f.t.Helper()
	ref, ok := f.ssh.sshd.work.enter()
	require.True(f.t, ok)
	return ref
}
func (f *producerDrainFixture) heldRelease(sequence int) *witnessedRelease {
	f.t.Helper()
	call := f.store.call(f.t, sequence)
	<-call.gate.entered
	require.False(f.t, ownershipDone(call.returned))
	return call
}

func TestSSHDStoreProducerDrain(t *testing.T) {
	t.Run("confirmed original end", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			store := newDrainStore(newMemorySessionStore(slog.Default()), 1)
			ended := make(chan struct{})
			f := newProducerDrainFixture(t, store, func(d *sshd) { d.onEnded = func(*Registration) { close(ended) } })
			reg := f.registration(0)
			ctx, cancel := newTestConnContext(t)
			work := f.enter()
			ok, body := f.ssh.sshd.adopt(work, ctx, reg, nil)
			work.done()
			require.True(t, ok, string(body))
			cancel()
			call := f.heldRelease(1)
			f.startStop()
			f.pending("confirmed original end")
			require.False(t, ownershipDone(ended), "onEnded preceded the held Release")
			f.finish()
			require.True(t, ownershipDone(call.returned))
			require.True(t, ownershipDone(ended))
		})
	})
	t.Run("forward untrack winner", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			store := newDrainStore(newMemorySessionStore(slog.Default()), 1)
			f := newProducerDrainFixture(t, store)
			reg := f.registration(0)
			ctx, cancel := newTestConnContext(t)
			work := f.enter()
			_, err := f.ssh.sshd.sessions.add(work, reg, newCloser())
			work.done()
			require.NoError(t, err)
			ownSession(ctx, reg)
			request := &ssh.Request{Type: streamlocalForwardChannelType,
				Payload: ssh.Marshal(&streamlocalChannelForwardMsg{SocketPath: reg.ID()})}
			ok, body := f.ssh.sshd.forwardHandler.Handler(ctx, f.ssh.sshd.server, request)
			require.True(t, ok, string(body))
			cancel() // The actual forward group wins untrack and enters its synchronous end.
			call := f.heldRelease(1)
			request.Type = cancelStreamlocalForwardChannelType
			ok, body = f.ssh.sshd.forwardHandler.Handler(ctx, f.ssh.sshd.server, request)
			require.True(t, ok, string(body))
			require.False(t, ownershipDone(call.returned), "losing cancel joined the winner")
			f.startStop()
			f.pending("forward untrack winner")
			f.finish()
			require.True(t, ownershipDone(call.returned))
		})
	})
	t.Run("late keeper successor", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			operation := newOwnershipGate()
			base := &leaseStore{t: t, ttl: keeperTTL, memorySessionStore: newMemorySessionStore(slog.Default())}
			base.reregister = func(_ context.Context, reg *Registration) (*Registration, error) {
				operation.hold()
				next, err := base.memorySessionStore.Reregister(context.Background(), reg)
				if next != nil {
					next.lease = "late-successor"
				}
				return next, err
			}
			store := newDrainStore(base, 1)
			f := newProducerDrainFixture(t, store)
			f.hold(operation)
			reg := f.registration(1)
			lost := make(chan struct{}, 1)
			lost <- struct{}{}
			keeper := &leaseKeeper{sm: f.ssh.sshd.SessionManager, ttl: keeperTTL, timing: defaultLeaseTiming,
				lost: lost, logger: slog.Default(), closeConn: func() {}, replace: func(*Registration) bool { return false }}
			runWork := f.enter()
			runDone := make(chan struct{})
			go func() {
				defer close(runDone)
				defer runWork.done()
				keeper.run(runWork, f.ssh.sshd.work.keeperContext, reg)
			}()
			<-operation.entered
			f.startStop()
			f.pending("late keeper operation")
			require.True(t, ownershipDone(runDone), "keeper run failed to cancel independently of its operation")
			require.False(t, ownershipDone(store.reregisterReturned))
			operation.release()
			<-store.reregisterReturned
			call := f.heldRelease(1)
			require.Equal(t, "late-successor", call.reg.lease)
			f.pending("late keeper successor") // Operation and run are now finished; only the late cleanup holds the drain.
			require.True(t, ownershipDone(runDone))
			require.True(t, ownershipDone(store.reregisterReturned))
			require.False(t, ownershipDone(call.returned))
			f.finish()
			require.True(t, ownershipDone(call.returned))
		})
	})
	t.Run("admitted request handoff", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			held := newOwnershipGate()
			base := &leaseStore{t: t, ttl: keeperTTL, memorySessionStore: newMemorySessionStore(slog.Default())}
			store := newDrainStore(base)
			ended := make(chan struct{})
			f := newProducerDrainFixture(t, store, func(d *sshd) {
				d.onRegistered = func(context.Context, *Registration) { held.hold() }
				d.onEnded = func(*Registration) { close(ended) }
			})
			f.hold(held)
			ctx, cancel := newTestConnContext(t)
			payload, err := proto.Marshal(&CreateSessionRequest{HostUser: "owner"})
			require.NoError(t, err)
			request := &ssh.Request{Type: upterm.ServerCreateSessionRequestType, Payload: payload}
			requestDone := make(chan struct{})
			go func() { defer close(requestDone); f.ssh.sshd.createSessionHandler(ctx, f.ssh.sshd.server, request) }()
			<-held.entered
			cancel()
			f.startStop()
			f.pending("admitted request handoff")
			before := store.registerCalls.Load()
			ok, _ := f.ssh.sshd.createSessionHandler(ctx, f.ssh.sshd.server, request)
			require.False(t, ok, "request admitted after seal")
			require.Equal(t, before, store.registerCalls.Load(), "post-seal callback reached Register")
			f.finish() // The admitted handler may create its keeper and confirmed-end child after seal.
			require.True(t, ownershipDone(requestDone))
			require.True(t, ownershipDone(ended))
		})
	})
	t.Run("entered observer retire", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			store := newDrainStore(newMemorySessionStore(slog.Default()), 1)
			f := newProducerDrainFixture(t, store)
			reg := f.registration(1)
			peer := newCloser()
			work := f.enter()
			_, err := f.ssh.sshd.sessions.add(work, reg, peer)
			work.done()
			require.NoError(t, err)
			newer := map[string]StoreEntry{reg.ID(): {Session: &Session{ID: reg.ID(), NodeAddr: "elsewhere", Generation: 2}}}
			f.ssh.sshd.sessions.observe(0, 0, newer)
			require.True(t, peer.isClosed(), "observer did not close the superseded peer")
			call := f.heldRelease(1)
			// Leave another slot which only the deliberately post-seal delivery could retire.
			next := &Registration{Session: &Session{ID: "later", NodeAddr: f.ssh.addr, Generation: 1}}
			nextPeer := newCloser()
			work = f.enter()
			_, err = f.ssh.sshd.sessions.add(work, next, nextPeer)
			work.done()
			require.NoError(t, err)
			f.startStop()
			f.pending("entered observer retire")
			f.ssh.sshd.sessions.observe(0, 0, map[string]StoreEntry{"later": {Session: &Session{ID: "later", Generation: 2}}})
			require.False(t, nextPeer.isClosed(), "post-seal observer retired a new slot")
			require.Len(t, store.snapshot(), 1, "post-seal observer started another Release")
			f.finish()
			require.True(t, ownershipDone(call.returned))
		})
	})
	t.Run("preauth completion", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			store := newDrainStore(newMemorySessionStore(slog.Default()))
			f := newProducerDrainFixture(t, store)
			tail := newOwnershipGate()
			f.hold(tail)
			// No peer exists yet. The callback is inside HandleConn's deferred tail,
			// after raw Close has unblocked the handshake, rather than blocking Close.
			f.ssh.sshd.server.ConnectionCloseCallback = func(net.Conn) { tail.hold() }
			_ = f.ssh.rawConn(t)
			synctest.Wait() // The accepted raw peer is parked in its incomplete handshake.
			f.ssh.sshd.work.mu.Lock()
			accepted := len(f.ssh.sshd.work.peers)
			f.ssh.sshd.work.mu.Unlock()
			require.Equal(t, 1, accepted)
			f.startStop()
			<-tail.entered
			f.pending("preauth completion")
			f.finish()
			f.ssh.sshd.work.mu.Lock()
			remaining := len(f.ssh.sshd.work.peers)
			f.ssh.sshd.work.mu.Unlock()
			require.Zero(t, remaining, "HandleConn wrapper has not returned")
			require.True(t, ownershipDone(f.ssh.sshd.work.drained))
		})
	})
	t.Run("bounded incomplete finalization", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			held := newOwnershipGate()
			store := newDrainStore(newMemorySessionStore(slog.Default()))
			store.registerGate = held
			store.closeGate.release() // This row tests real bounded error return, not an omitted-owner Close hold.
			sm := newSessionManagerWithStore(store, routing.NewEncodeDecoder(routing.ModeEmbedded))
			network := &MemoryProvider{}
			require.NoError(t, network.SetOpts(nil))
			signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
			require.NoError(t, err)
			server := &Server{NodeAddr: "bubble", SessionManager: sm, NetworkProvider: network,
				HostSigners: []ssh.Signer{signer}, Signers: []ssh.Signer{signer},
				MetricsProvider: provider.NewDiscardProvider(), Logger: slog.Default()}
			served, stopped := make(chan struct{}), make(chan struct{})
			var serveErr, stopErr error
			ctx, cancel := context.WithCancel(context.Background())
			stopStarted := false
			var client *ssh.Client
			// Own every rescue before starting Serve, handshake, request or Shutdown.
			t.Cleanup(func() {
				held.release()
				cancel()
				if client != nil {
					_ = client.Close()
				}
				if !stopStarted {
					stopStarted = true
					go func() { stopErr = server.Shutdown(); close(stopped) }()
				}
				<-stopped
				<-served
			})
			go func() { serveErr = server.ServeWithContext(ctx, nil, nil); close(served) }()
			synctest.Wait() // Internal sshd is listening on the bubble's memory provider.
			raw, err := network.SSHD().DialContext(context.Background())
			require.NoError(t, err)
			t.Cleanup(func() { _ = raw.Close() })
			auth := &testSSHD{signer: signer}
			conn, chans, reqs, err := ssh.NewClientConn(raw, "bubble", auth.proxyConfig(t, "bounded"))
			require.NoError(t, err)
			client = ssh.NewClient(conn, chans, reqs)
			payload, err := proto.Marshal(&CreateSessionRequest{HostUser: "owner"})
			require.NoError(t, err)
			requestDone := make(chan struct{})
			go func() {
				defer close(requestDone)
				_, _, _ = client.SendRequest(upterm.ServerCreateSessionRequestType, true, payload)
			}()
			<-held.entered
			stopStarted = true
			go func() { stopErr = server.Shutdown(); close(stopped) }()
			synctest.Wait() // The handler is still held; shutdown has sealed and closed its peer.
			require.False(t, ownershipDone(stopped), "premature finalization: bounded incomplete request is still live before drain deadline")
			require.Zero(t, store.closes.Load())
			time.Sleep(serverShutDownDeadline - time.Nanosecond)
			synctest.Wait() // The existing sshd deadline has not expired yet.
			require.False(t, ownershipDone(stopped), "shutdown returned before its bound")
			time.Sleep(time.Nanosecond)
			synctest.Wait() // The one-second incomplete drain and outer finalization have finished.
			require.True(t, ownershipDone(served), "Serve did not finish at the bounded drain")
			require.True(t, ownershipDone(stopped), "Shutdown did not retain bounded finalization")
			assert.ErrorIs(t, serveErr, context.DeadlineExceeded, "missing incomplete error from Serve")
			assert.ErrorIs(t, stopErr, context.DeadlineExceeded, "missing incomplete error from Shutdown")
			assert.ErrorIs(t, stopErr, errShutdownIncomplete, "missing incomplete category from Shutdown")
			require.Equal(t, int32(1), store.closes.Load(), "bounded error must still finalize once")
			held.release()
			<-store.registerReturned
			<-requestDone
			synctest.Wait() // The rescued handler's direct and confirmed end callers have returned.
			for _, call := range store.snapshot() {
				require.True(t, ownershipDone(call.returned))
			}
			require.Len(t, store.snapshot(), 2, "rescued disconnected handler did not finish both end calls")
		})
	})
}
