package capacity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

type frameBarrier struct {
	sent  time.Time
	done  chan struct{}
	once  sync.Once
	final bool
}

// B reports the helper's emitted H count after processing all earlier input.
// A baseline Q excludes replay; a final F quiesces periodic helper output.
func (q *guest) barrier(ctx context.Context, r *runState, w io.Writer, stream int, kind string) error {
	b := &frameBarrier{sent: time.Now(), done: make(chan struct{}), final: kind == "F"}
	q.mu.Lock()
	if q.barriers == nil {
		q.barriers = map[int]*frameBarrier{}
	}
	q.barriers[stream] = b
	q.mu.Unlock()
	if err := r.sendBarrier(q, w, stream, kind, b.sent); err != nil {
		return err
	}
	select {
	case <-b.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("terminal delivery barrier: %w", ctx.Err())
	}
}
func (r *runState) sendBarrier(q *guest, w io.Writer, stream int, kind string, at time.Time) error {
	fanout := r.cfg.GuestsPerHost * r.cfg.ChannelsPerGuest
	if q.canary {
		fanout = 1
	}
	if err := r.reserve(128 * int64(1+fanout)); err != nil {
		return err
	}
	n, err := w.Write(frame(kind, stream, 0, at, 128))
	r.actual(int64(n))
	if n != 128 && err == nil {
		err = io.ErrShortWrite
	}
	if n == 128 {
		r.rec.mu.Lock()
		r.rec.summary.HandshakeFrames++
		r.rec.mu.Unlock()
	}
	return err
}
func (r *runState) completeDelivery() error {
	// Own acknowledgments prove every offered input reached the helper before
	// final barriers are queued. Each receiver then verifies every active
	// source's final sequence, covering a lost fan-out suffix as well.
	for {
		pending := 0
		for _, q := range r.guests {
			q.mu.Lock()
			pending += len(q.pending)
			q.mu.Unlock()
		}
		if pending == 0 {
			break
		}
		if err := pause(r.ctx, 10*time.Millisecond); err != nil {
			return err
		}
	}
	var wg sync.WaitGroup
	failures := make(chan error, len(r.guests))
	for _, q := range r.guests {
		if q.canary {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			q.mu.Lock()
			expected := q.expected
			q.mu.Unlock()
			if expected {
				failures <- errors.New("terminal_restoration_incomplete")
				return
			}
			q.ops.Lock()
			defer q.ops.Unlock()
			for ch, w := range q.writers {
				if err := q.barrier(r.ctx, r, w, q.id*4+ch, "F"); err != nil {
					failures <- err
					return
				}
			}
			q.mu.Lock()
			pending := len(q.pending)
			q.mu.Unlock()
			if pending != 0 {
				failures <- fmt.Errorf("terminal delivery missing %d replies", pending)
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			return err
		}
	}
	return nil
}

// Each guest owns its own absolute one-second schedule. A slow writer or an
// expected restoration cannot hold up any other guest's offered cadence.
func (r *runState) activeWorkload(start time.Time, wg *sync.WaitGroup) {
	if !r.cfg.Active {
		return
	}
	for _, q := range r.guests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < r.cfg.DurationSeconds; i++ {
				if err := pause(r.ctx, time.Until(start.Add(time.Duration(i)*time.Second))); err != nil {
					return
				}
				if now := time.Now(); !now.Before(start.Add(time.Duration(r.cfg.DurationSeconds)*time.Second)) || now.Sub(start.Add(time.Duration(i)*time.Second)) >= time.Second {
					r.fail(errors.New("generator_cadence_late"))
					return
				}
				if err := q.active(r); err != nil {
					r.fail(err)
					return
				}
			}
		}()
	}
}

func (r *runState) verifyFinalInputs(tracker sequenceTracker, hostID int, baseline time.Time) error {
	r.clientsMu.RLock()
	defer r.clientsMu.RUnlock()
	for _, source := range r.guests {
		if source.host.id != hostID {
			continue
		}
		source.mu.Lock()
		expected := source.lastActiveSeq
		required := source.activeOffered && source.activeGeneration == source.generation && !source.lastActiveAt.Before(baseline)
		id := source.id
		source.mu.Unlock()
		if required {
			got, ok := tracker[fmt.Sprintf("I:%d", id*4)]
			if !ok || got != expected {
				return fmt.Errorf("input suffix missing: guest=%d received_through=%d expected=%d", id, got, expected)
			}
		}
	}
	return nil
}
