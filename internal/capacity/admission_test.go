package capacity

import (
	"context"
	"testing"
	"time"
)

func TestAdmissionWorkersOverlapReadinessWithinBound(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(context.Canceled)
	r := &runState{ctx: ctx, cancel: cancel}
	started := make(chan struct{}, 40)
	release := make(chan struct{})
	finished := make(chan error, 1)
	go func() { finished <- r.admissions(40, func(int) error { started <- struct{}{}; <-release; return nil }) }()
	defer func() { close(release); <-finished }()
	for i := 0; i < 20; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d readiness checks overlapped", i)
		}
	}
	select {
	case <-started:
		t.Fatal("more than twenty admission workers started")
	case <-time.After(20 * time.Millisecond):
	}
}
