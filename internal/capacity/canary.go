package capacity

import (
	"time"
)

// Idle host-only phases keep zero steady guests. One transient guest at
// readiness and every thirty seconds proves a sampled host still serves a
// shell, without a separate generator or unbounded extra connections.
func (r *runState) hostCanary(sample int) error {
	et, _ := r.cfg.target(r.cfg.EntryTarget)
	if r.canary == nil {
		identity, err := makeSigner()
		if err != nil {
			return err
		}
		q := &guest{id: 0, target: et, identity: identity, canary: true, expected: true}
		r.clientsMu.Lock()
		r.guests = append(r.guests, q)
		r.clientsMu.Unlock()
		r.canary = q
	}
	q := r.canary
	q.host = r.hosts[sample%len(r.hosts)]
	u, err := transport(et, r.cfg.GuestWSPercent, (sample*37)%100, 100, r.cfg.EntryPublic)
	if err != nil {
		return err
	}
	q.endpoint = u
	proxy, err := newTunnelProxy(r.ctx, r.guard, et)
	if err != nil {
		return err
	}
	defer proxy.close()
	q.proxy = proxy
	q.mu.Lock()
	q.generation++
	q.mu.Unlock()
	r.rec.mu.Lock()
	r.rec.summary.CanaryOffered++
	r.rec.mu.Unlock()
	began := time.Now()
	err = q.connect(r.ctx, r)
	readyElapsed := time.Since(began) - q.queueElapsed
	q.setExpected(true)
	q.close()
	if err != nil {
		return err
	}
	ms := float64(readyElapsed) / float64(time.Millisecond)
	r.rec.mu.Lock()
	r.rec.summary.CanaryEstablished++
	if ms > r.rec.summary.CanaryReadyMillis {
		r.rec.summary.CanaryReadyMillis = ms
	}
	r.rec.mu.Unlock()
	r.rec.event("host_only_canary", map[string]any{"sample": sample, "host": q.host.id, "transport": u.Scheme, "ready_ms": ms, "queue_ms": float64(q.queueElapsed) / float64(time.Millisecond), "transient_guest": true, "channels": 1})
	return nil
}
func (r *runState) canaries() {
	r.workers.Add(1)
	go func() {
		defer r.workers.Done()
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		sample := 1
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-tick.C:
				if err := r.hostCanary(sample); err != nil {
					if r.ctx.Err() == nil {
						r.fail(err)
					}
					return
				}
				sample++
			}
		}
	}()
}
