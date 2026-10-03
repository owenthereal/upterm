// Package liveness judges a connection by the bytes that arrive on it.
//
// A keepalive that waits for one reply within a bound is wrong on a slow
// uplink: x/crypto serialises want-reply requests, so a reply can sit behind
// megabytes of queued output for longer than any bound that is also short
// enough to notice a dead peer. The output is arriving the whole time, though,
// and that is proof of life. So here a connection is alive for as long as any
// bytes arrive on it, a probe is a nudge for a peer that has gone quiet, and
// only silence is evidence against it.
//
// It lives at the module root's internal/ rather than under host/internal
// because both ends of an SSH tunnel use it: the relay's pings and the host's
// keepalive.
package liveness

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// base is what every recorded read is measured from. time.Now carries a
// monotonic reading, and Add and Since keep it, so a silence computed from it
// is immune to the wall clock being stepped by NTP, a suspended laptop or an
// operator: a step forward must not read as a peer that went quiet for an
// hour, nor a step back as one that never will.
var base = time.Now()

// Conn is a net.Conn that records when bytes last arrived on it.
//
// It wraps the connection beneath the SSH transport, so that anything the peer
// sends -- a probe's reply, a session's output, a window adjust -- counts, not
// just the one reply a probe was waiting for.
type Conn struct {
	net.Conn

	// last is how long after base the last bytes arrived. An atomic integer
	// rather than a time.Time under a mutex because the SSH transport's reader
	// writes it and a Watch reads it, on every byte and every wake.
	last atomic.Int64
}

// NewConn starts the silence now: a connection that has not yet been read is
// not one that has been quiet since the beginning of time.
func NewConn(c net.Conn) *Conn {
	lc := &Conn{Conn: c}
	lc.touch()
	return lc
}

// Read records the arrival only when it returned bytes. A read that failed with
// none, a timeout or an EOF, is a connection going quiet, which is the opposite
// of what this exists to record.
func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *Conn) touch() { c.last.Store(int64(time.Since(base))) }

// LastRead is when bytes last arrived. The time carries a monotonic reading,
// so a silence taken from it with time.Since is unaffected by the wall clock.
func (c *Conn) LastRead() time.Time { return base.Add(time.Duration(c.last.Load())) }

// Timing is how long a connection may be quiet. The two together are the whole
// budget: a peer is probed after Interval of silence and given up on after
// Interval+Bound, so Bound is how long a probe has to prompt any bytes at all.
type Timing struct {
	Interval, Bound time.Duration
}

// DefaultTiming gives up on a peer that has said nothing for 30 s, having
// probed it after 15 s.
var DefaultTiming = Timing{Interval: 15 * time.Second, Bound: 15 * time.Second}

// OrDefault fills in whichever field was left zero or negative, so that a
// caller can override one and inherit the other. A negative duration is as
// much "not set" as zero: neither is a silence anyone can wait for.
func (t Timing) OrDefault() Timing {
	if t.Interval <= 0 {
		t.Interval = DefaultTiming.Interval
	}
	if t.Bound <= 0 {
		t.Bound = DefaultTiming.Bound
	}
	return t
}

// ErrSilent is what a connection that went quiet is reported as, so that a
// caller can tell it from a probe that failed outright.
var ErrSilent = errors.New("no bytes from the peer")

// Watch probes a connection once it has been silent for t.Interval, and gives
// up on it once it has been silent for t.Interval+t.Bound. It returns when ctx
// ends or after calling onDead, which it calls at most once.
//
// Silence is measured from lastRead, and the next wake is worked out from it
// each time rather than taken from a ticker: bytes that arrive while Watch
// sleeps push the deadline out, and a ticker would wake for nothing on a
// connection that never needs a probe.
//
// At most one probe is in flight. x/crypto would serialise a second behind the
// first anyway, so a probe that is slow to be answered is not piled on, and it
// does not matter how slow: the reply moves lastRead like any other bytes, and
// a probe that stays unanswered is no reason to give up while other bytes keep
// arriving.
//
// A probe also never starts within Interval of the previous one. A reply moves
// lastRead, so that is normally already true; it is what stops a probe that
// returns nil without any bytes having arrived, which is a caller whose
// lastRead is not fed by the connection the probe goes over, from being run
// again on every pass for as long as the silence lasts.
//
// A probe that returns an error is a connection that has gone. One that
// returns nil needs nothing more here.
//
// onDead is called only for a connection that actually failed. A ctx that ends
// is the caller's own teardown and says nothing about the peer, even if that
// teardown is what made a probe in flight fail.
func Watch(ctx context.Context, t Timing, lastRead func() time.Time, probe func() error, onDead func(error)) {
	// A zero or negative Interval would wake at once, every time, for as long
	// as it lasted.
	t = t.OrDefault()

	// inFlight is nil while no probe is running, and a receive from a nil
	// channel blocks, which is what keeps that case out of the select below.
	var inFlight chan error
	// probed is when the last probe started, zero before the first.
	var probed time.Time
	for {
		if ctx.Err() != nil {
			return
		}

		silence := time.Since(lastRead())
		if silence >= t.Interval+t.Bound {
			onDead(fmt.Errorf("%w for %s", ErrSilent, silence.Round(time.Millisecond)))
			return
		}

		wake := t.Interval + t.Bound - silence
		if inFlight == nil {
			wait := t.Interval - silence
			if !probed.IsZero() {
				wait = max(wait, t.Interval-time.Since(probed))
			}
			if wait <= 0 {
				inFlight = startProbe(probe)
				probed = time.Now()
			} else {
				wake = min(wake, wait)
			}
		}

		timer := time.NewTimer(wake)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case err := <-inFlight:
			timer.Stop()
			inFlight = nil
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				onDead(err)
				return
			}
		case <-timer.C:
		}
	}
}

// startProbe runs one probe and returns the channel its result arrives on.
//
// If Watch returns first, the goroutine is abandoned rather than waited for: it
// is parked in exactly the place a dead peer leaves it, and it ends when the
// caller closes the connection, which is what onDead does. The channel is
// buffered so that its send cannot be what keeps it alive.
func startProbe(probe func() error) chan error {
	result := make(chan error, 1)
	go func() { result <- probe() }()
	return result
}
