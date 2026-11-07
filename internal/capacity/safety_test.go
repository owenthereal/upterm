package capacity

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTelemetryLossUsesThirtySecondBound(t *testing.T) {
	now := time.Unix(100, 0)
	if telemetryLost(now, now.Add(30*time.Second)) {
		t.Fatal("telemetry stopped before grace expired")
	}
	if !telemetryLost(now, now.Add(30*time.Second+time.Nanosecond)) {
		t.Fatal("telemetry loss did not stop after 30 seconds")
	}
}
func TestWatchdogStopAndStaleHeartbeat(t *testing.T) {
	c := validConfig(t)
	dir := t.TempDir()
	c.WatchdogFile = filepath.Join(dir, "stop")
	c.WatchdogHeartbeatFile = filepath.Join(dir, "heartbeat")
	now := time.Now()
	if err := os.WriteFile(c.WatchdogHeartbeatFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := watchFiles(c, now); err != nil {
		t.Fatal(err)
	}
	if err := watchFiles(c, now.Add(31*time.Second)); err == nil {
		t.Fatal("stale watchdog heartbeat accepted")
	}
	if err := os.WriteFile(c.WatchdogFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(t.Context(), c, io.Discard); err == nil {
		t.Fatal("watchdog stop admitted workload")
	}
}
func TestAdmissionRateIncludesRetriesAndCancellation(t *testing.T) {
	c := validConfig(t)
	g := newGuard(c)
	var starts []time.Time
	g.dial = func(context.Context, string, string) (net.Conn, error) {
		starts = append(starts, time.Now())
		return nil, errors.New("failed dial")
	}
	for i := 0; i < 3; i++ {
		_, _ = g.connect(t.Context(), c.Manifest.Targets[0], "127.0.0.1:2222")
	}
	if len(starts) != 3 || starts[2].Sub(starts[0]) < 95*time.Millisecond {
		t.Fatalf("retry handshakes escaped limiter: %v", starts)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _ = g.connect(ctx, c.Manifest.Targets[0], "127.0.0.1:2222")
	if len(starts) != 3 {
		t.Fatal("cancelled admission dialed")
	}
}
func TestPayloadStopReservesBeforeWriting(t *testing.T) {
	c := validConfig(t)
	c.PayloadBudgetBytes = 255
	r := &runState{cfg: c, rec: newRecorder(io.Discard, c)}
	q := &guest{}
	sink := &countWriter{}
	if err := r.send(q, sink, 0, 0); err == nil {
		t.Fatal("over-budget input was sent")
	}
	if sink.n != 0 {
		t.Fatalf("over-budget input emitted %d bytes", sink.n)
	}
}

type countWriter struct{ n int }

func (w *countWriter) Write(p []byte) (int, error) { w.n += len(p); return len(p), nil }
func TestTelemetryLossCancelsRunningPhase(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(context.Canceled)
	c := validConfig(t)
	r := &runState{cfg: c, ctx: ctx, cancel: cancel, rec: newRecorder(io.Discard, c), lastTelemetry: map[string]time.Time{"test-machine": time.Now().Add(-31 * time.Second)}}
	r.watch()
	defer func() { cancel(context.Canceled); r.workers.Wait() }()
	select {
	case <-ctx.Done():
		if context.Cause(ctx).Error() != "telemetry_lost" {
			t.Fatalf("wrong stop cause %v", context.Cause(ctx))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("telemetry loss did not cancel the phase")
	}
}
