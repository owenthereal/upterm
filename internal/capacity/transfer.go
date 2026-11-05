package capacity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/sftp"
)

type deterministicReader struct{ offset int64 }

func (d *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte((d.offset + int64(i)) % 251)
	}
	d.offset += int64(len(p))
	return len(p), nil
}
func deterministicHash() string {
	h := sha256.New()
	_, _ = io.CopyN(h, &deterministicReader{}, TransferSize)
	return hex.EncodeToString(h.Sum(nil))
}
func (r *runState) transfers() error {
	expected := deterministicHash()
	var wg sync.WaitGroup
	results := make(chan error, r.cfg.TransferConcurrency)
	for i := 0; i < r.cfg.TransferConcurrency; i++ {
		wg.Add(1)
		go func(index int) { defer wg.Done(); results <- r.transfer(index, expected) }(i)
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			return err
		}
	}
	return nil
}
func (r *runState) transfer(index int, expected string) (err error) {
	q := r.guests[index%len(r.guests)]
	q.ops.Lock()
	client := q.client
	q.ops.Unlock()
	c, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer c.Close()
	path := filepath.ToSlash(filepath.Join(filepath.Dir(q.host.socket), fmt.Sprintf("transfer-%d.bin", index)))
	defer func() { _ = c.Remove(path) }()
	began := time.Now()
	var uploaded, downloaded int64
	defer func() {
		fields := map[string]any{"transfer": index, "guest": q.id, "upload_bytes": uploaded, "download_bytes": downloaded, "sha256": expected, "verified": err == nil, "duration_seconds": time.Since(began).Seconds()}
		if err != nil {
			fields["error"] = err.Error()
		}
		r.rec.event("transfer", fields)
	}()
	if err = r.reserve(2 * TransferSize); err != nil {
		return err
	}
	f, err := c.Create(path)
	if err != nil {
		return err
	}
	uploaded, err = io.CopyN(f, &deterministicReader{}, TransferSize)
	closeErr := f.Close()
	r.actual(uploaded)
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if uploaded != TransferSize {
		return errors.New("upload length mismatch")
	}
	f, err = c.Open(path)
	if err != nil {
		return err
	}
	h := sha256.New()
	downloaded, err = io.Copy(h, io.LimitReader(f, TransferSize+1))
	closeErr = f.Close()
	r.actual(downloaded)
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	got := hex.EncodeToString(h.Sum(nil))
	if downloaded != TransferSize || got != expected {
		return errors.New("download hash/length mismatch")
	}
	r.rec.mu.Lock()
	r.rec.summary.Transfers++
	r.rec.summary.TransferBytes += uploaded + downloaded
	r.rec.mu.Unlock()
	return nil
}

// Churn cuts existing sockets. The same Host.Run (and session ID), guest key,
// role and transport survive; fresh guest TCP/SSH transports are reported as
// reconnects, separately from first admission.
func (r *runState) churn() error {
	actions := churnSchedule(r.cfg.Hosts, r.cfg.GuestsPerHost, r.cfg.ChurnPercent)
	if len(actions) == 0 {
		return errors.New("churn percentage selects no transports")
	}
	affectedHosts := map[int]bool{}
	affectedGuests := map[int]bool{}
	for _, a := range actions {
		if a.host {
			affectedHosts[a.index] = true
		} else {
			affectedGuests[a.index] = true
		}
	}
	var canary *guest
	for _, q := range r.guests {
		if !affectedHosts[q.host.id] && !affectedGuests[q.id] {
			canary = q
			break
		}
	}
	if canary == nil {
		return errors.New("churn has no survivor canary")
	}
	canary.mu.Lock()
	before := canary.acks
	canary.mu.Unlock()
	start := time.Now().Add(time.Second)
	var wg sync.WaitGroup
	results := make(chan error, len(actions))
	for _, a := range actions {
		if err := pause(r.ctx, time.Until(start.Add(a.offset))); err != nil {
			wg.Wait()
			return err
		}
		wg.Add(1)
		go func(action churnAction) {
			defer wg.Done()
			var err error
			if action.host {
				err = r.cutHost(r.hosts[action.index])
			} else {
				err = r.cutGuest(r.guests[action.index])
			}
			if err != nil {
				r.fail(err)
			}
			results <- err
		}(a)
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			return err
		}
	}
	if !r.cfg.Active {
		if err := canary.active(r); err != nil {
			return err
		}
		if err := pause(r.ctx, time.Second); err != nil {
			return err
		}
	}
	canary.mu.Lock()
	after := canary.acks
	canary.mu.Unlock()
	if after <= before {
		return errors.New("survivor canary stopped responding")
	}
	r.rec.mu.Lock()
	r.rec.summary.ChurnCompleted = true
	r.rec.mu.Unlock()
	r.rec.event("survivor_canary", map[string]any{"guest": canary.id, "host": canary.host.id, "responses_before": before, "responses_after": after, "transport_replaced": false})
	return nil
}
func (r *runState) restoreGuest(q *guest, began time.Time) error {
	q.close()
	q.mu.Lock()
	q.pending = map[string]time.Time{}
	q.generation++
	q.mu.Unlock()
	var last error
	for tries := 0; tries < 3; tries++ {
		last = q.connect(r.ctx, r)
		if last == nil {
			q.setExpected(false)
			r.rec.mu.Lock()
			r.rec.summary.Reconnects++
			r.rec.mu.Unlock()
			r.rec.event("guest_restored", map[string]any{"guest": q.id, "host": q.host.id, "generation": q.generation, "restoration_ms": float64(time.Since(began)) / float64(time.Millisecond), "same_identity": true})
			return nil
		}
		q.close()
		if err := pause(r.ctx, time.Second); err != nil {
			return err
		}
	}
	return fmt.Errorf("guest restoration failed: %w", last)
}
func (r *runState) cutGuest(q *guest) error {
	q.host.repair.Lock()
	defer q.host.repair.Unlock()
	q.setExpected(true)
	began := time.Now()
	r.rec.event("transport_cut", map[string]any{"role": "guest", "guest": q.id, "host": q.host.id})
	q.ops.Lock()
	if q.raw != nil {
		_ = q.raw.Close()
	}
	q.ops.Unlock()
	return r.restoreGuest(q, began)
}
func (r *runState) cutHost(h *hostRun) error {
	h.repair.Lock()
	defer h.repair.Unlock()
	var guests []*guest
	for _, q := range r.guests {
		if q.host == h {
			q.setExpected(true)
			guests = append(guests, q)
		}
	}
	began := time.Now()
	r.rec.event("transport_cut", map[string]any{"role": "host", "host": h.id})
	h.proxy.cut()
	ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
	defer cancel()
	down := false
	for {
		select {
		case e := <-h.tunnel:
			if !e.Up {
				down = true
				if !e.CanReconnect {
					return errors.New("relay cannot restore host")
				}
			}
			if e.Up && down {
				s, err := h.session(ctx)
				if err != nil {
					return err
				}
				if err = r.guard.session(ctx, s); err != nil {
					return err
				}
				r.rec.mu.Lock()
				r.rec.summary.Reconnects++
				r.rec.mu.Unlock()
				r.rec.event("host_restored", map[string]any{"host": h.id, "session_id": s.SessionId, "restoration_ms": float64(time.Since(began)) / float64(time.Millisecond), "same_host_run": true})
				for _, q := range guests {
					if err = r.restoreGuest(q, began); err != nil {
						return err
					}
				}
				return nil
			}
		case <-ctx.Done():
			return fmt.Errorf("host restoration: %w", ctx.Err())
		}
	}
}

func pause(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type churnAction struct {
	host   bool
	index  int
	offset time.Duration
}

func churnSchedule(hosts, guests, percent int) []churnAction {
	hn := hosts * percent / 100
	gn := hosts * guests * percent / 100
	var actions []churnAction
	for i := 0; i < hn; i++ {
		actions = append(actions, churnAction{host: true, index: i * hosts / hn})
	}
	for i := 0; i < gn; i++ {
		actions = append(actions, churnAction{index: i * hosts * guests / gn})
	}
	for i := range actions {
		if len(actions) > 1 {
			actions[i].offset = time.Duration(i) * 10 * time.Second / time.Duration(len(actions)-1)
		}
	}
	return actions
}
