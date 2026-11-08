// Package testauthority is a scripted server.Authority for tests: it answers
// Register with the results it is given, in order, answers Control as it is
// told to, can hold a call until a test releases it or hang every call, and
// records every call it is asked.
//
// It is a package of its own because it imports server, and server's tests
// import internal/testhelpers.
package testauthority

import (
	"context"
	"sync"
	"time"

	"github.com/owenthereal/upterm/server"
)

// AccountID is the account of a current registration the authority wasn't
// scripted to answer otherwise.
const AccountID = "77777777-7777-4777-8777-777777777777"

// Call is one call the authority was asked, recorded as it arrived.
type Call struct {
	// Method is "Register" or "Control".
	Method string
	// Registration is Register's argument, or the registration Control's
	// report is about.
	Registration server.DelegatedRegistration
	// Request is Control's report; nil for Register.
	Request *server.DelegatedControlRequest
	At      time.Time
}

// Authority is a scripted server.Authority. The zero value isn't usable; use
// New.
type Authority struct {
	mu      sync.Mutex
	results []server.RegistrationResult
	err     error
	reply   func(server.Report) (*server.DelegatedControlReply, error)
	gates   []*gate
	hang    bool
	calls   []Call
}

// gate holds one call until it is released.
type gate struct {
	arrived, released chan struct{}
	arrive, release   sync.Once
}

// New is an authority that answers every Register with a current decision at
// revision 1 for AccountID, and every Control with the same, acknowledging
// the report.
func New() *Authority { return &Authority{} }

var _ server.Authority = (*Authority)(nil)

// Script queues Register's answers, in order. Once they are used up, Register
// answers as New's does.
func (a *Authority) Script(results ...server.RegistrationResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.results = append(a.results, results...)
}

// ScriptErr has every later Register fail with err, until ScriptErr(nil).
func (a *Authority) ScriptErr(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.err = err
}

// Reply has Control answer with f.
func (a *Authority) Reply(f func(server.Report) (*server.DelegatedControlReply, error)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reply = f
}

// Gate holds the next call, of either method, until release is called or the
// call's context ends, when the call returns its context's error. arrived is
// closed once that call has arrived and is held. release may be called more
// than once, and before the call arrives.
func (a *Authority) Gate() (arrived <-chan struct{}, release func()) {
	g := &gate{arrived: make(chan struct{}), released: make(chan struct{})}
	a.mu.Lock()
	a.gates = append(a.gates, g)
	a.mu.Unlock()
	return g.arrived, func() { g.release.Do(func() { close(g.released) }) }
}

// Hang has every later call block until its context ends, and then return the
// context's error.
func (a *Authority) Hang() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hang = true
}

// Calls is every call the authority was asked, in the order they arrived.
func (a *Authority) Calls() []Call {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Call(nil), a.calls...)
}

// arrive records call and waits as the authority was told to: on the next
// gate, or forever if it hangs. It reports the context's error if that ended
// the wait.
func (a *Authority) arrive(ctx context.Context, call Call) error {
	a.mu.Lock()
	a.calls = append(a.calls, call)
	hang := a.hang
	var g *gate
	if len(a.gates) > 0 {
		g, a.gates = a.gates[0], a.gates[1:]
	}
	a.mu.Unlock()
	if hang {
		if g != nil {
			g.arrive.Do(func() { close(g.arrived) })
		}
		<-ctx.Done()
		return ctx.Err()
	}
	if g != nil {
		g.arrive.Do(func() { close(g.arrived) })
		select {
		case <-g.released:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (a *Authority) Register(ctx context.Context, r server.DelegatedRegistration) (server.RegistrationResult, error) {
	if err := a.arrive(ctx, Call{Method: "Register", Registration: r, At: time.Now()}); err != nil {
		return server.RegistrationResult{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return server.RegistrationResult{}, a.err
	}
	if len(a.results) > 0 {
		result := a.results[0]
		a.results = a.results[1:]
		return result, nil
	}
	return server.RegistrationResult{AccountID: AccountID, Disposition: server.DelegatedDisposition_DELEGATED_CURRENT, DecisionRevision: 1}, nil
}

func (a *Authority) Control(ctx context.Context, r server.Report) (*server.DelegatedControlReply, error) {
	if err := a.arrive(ctx, Call{Method: "Control", Registration: r.Registration, Request: r.Request, At: time.Now()}); err != nil {
		return nil, err
	}
	a.mu.Lock()
	reply := a.reply
	a.mu.Unlock()
	if reply != nil {
		return reply(r)
	}
	return &server.DelegatedControlReply{
		ExternalSessionId:    r.Request.ExternalSessionId,
		Generation:           r.Request.Generation,
		AcknowledgedSequence: r.Request.Sequence,
		Disposition:          server.DelegatedDisposition_DELEGATED_CURRENT,
		DecisionRevision:     1,
	}, nil
}
