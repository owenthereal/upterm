// Package testbroker is a scripted host.Broker for tests: it places every run
// with the placement it was given, under the run's own routing ID when that
// placement names none, can fail the next placement, and records every run it
// was asked to place.
//
// It is a package of its own because it imports host, and host's tests
// import internal/testhelpers.
package testbroker

import (
	"context"
	"sync"

	"github.com/owenthereal/upterm/host"
)

// Broker is a scripted host.Broker. The zero value isn't usable; use New.
type Broker struct {
	mu   sync.Mutex
	p    host.Placement
	fail error
	runs []host.Run
}

var _ host.Broker = (*Broker)(nil)

// New is a broker that places every run with p.
func New(p host.Placement) *Broker { return &Broker{p: p} }

// Fail has the next Place return err, and only the next.
func (b *Broker) Fail(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fail = err
}

// Runs is every run the broker was asked to place, in order.
func (b *Broker) Runs() []host.Run {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]host.Run(nil), b.runs...)
}

// Place records run and answers with the broker's placement, or with the
// error Fail set.
func (b *Broker) Place(_ context.Context, run host.Run) (host.Placement, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.runs = append(b.runs, run)
	if err := b.fail; err != nil {
		b.fail = nil
		return host.Placement{}, err
	}
	p := b.p
	if p.RoutingID == "" {
		p.RoutingID = run.RoutingID
	}
	return p, nil
}
