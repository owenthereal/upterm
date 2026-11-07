package capacity

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The first source finishes its probe before the second terminal subscribes.
// Losing only the first steady fan-out frame must not turn the rest of that
// source's sequence into a new, apparently complete range.
func TestFirstSteadyPeerFrameMustReachEveryReceiver(t *testing.T) {
	for _, damage := range []string{"lost", "corrupt"} {
		t.Run(damage, func(t *testing.T) {
			c := localRelay(t)
			c.GuestsPerHost = 2
			c.DurationSeconds = 2
			firstReady := make(chan struct{})
			var readyOnce sync.Once
			c.terminalIO = func(guest, channel, generation int, in io.WriteCloser, out io.Reader) (io.WriteCloser, io.Reader) {
				if guest == 1 {
					select {
					case <-firstReady:
					case <-t.Context().Done():
					case <-time.After(10 * time.Second):
						t.Error("first source never completed its probe")
					}
				}
				return in, &frameTransformReader{reader: bufio.NewReader(out), transform: func(line []byte) []byte {
					o, ok := parseFrame(string(line))
					if ok && o.kind == "I" && o.id == 0 {
						if guest == 0 && o.seq == 0 {
							readyOnce.Do(func() { close(firstReady) })
						}
						if guest == 1 && o.seq == 1 {
							if damage == "lost" {
								return nil
							}
							line[len(line)-3] = 'y'
						}
					}
					return line
				}}
			}
			var out bytes.Buffer
			s, err := Run(t.Context(), c, &out)
			if s.EstablishedGuests != 2 {
				t.Fatalf("fixture did not admit both receivers: %v\n%s", err, out.String())
			}
			if err == nil || s.DeliveryComplete {
				t.Fatalf("%s first peer frame was accepted as complete delivery: %+v", damage, s)
			}
			if !strings.Contains(err.Error(), "sequence gap/reordering") {
				t.Fatalf("missing first peer frame was not detected at the next sequence: %v\n%s", err, out.String())
			}
			if !s.CleanupComplete {
				t.Fatal("failed delivery did not clean up")
			}
		})
	}
}

type frameTransformReader struct {
	reader    *bufio.Reader
	transform func([]byte) []byte
	pending   []byte
	err       error
}

func (r *frameTransformReader) Read(p []byte) (int, error) {
	for len(r.pending) == 0 && r.err == nil {
		line, err := r.reader.ReadBytes('\n')
		r.pending, r.err = r.transform(line), err
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	if n != 0 {
		return n, nil
	}
	return 0, r.err
}

func TestLaterHostCutOwnsGuestRestorationCommit(t *testing.T) {
	c := localRelay(t)
	c.Hosts = 2
	ctx, cancel := context.WithCancelCause(t.Context())
	dir, err := os.MkdirTemp("", "cap-commit-")
	if err != nil {
		t.Fatal(err)
	}
	r := &runState{ctx: ctx, cancel: cancel, cfg: c, guard: newGuard(c), rec: newRecorder(io.Discard, c), helper: c.HelperExecutable, dir: dir}
	t.Cleanup(func() {
		if err := r.cleanup(); err != nil {
			t.Error(err)
		}
	})
	if err := r.admit(nil); err != nil {
		t.Fatal(err)
	}
	var repairHost func() error
	r.cfg.beforeRestoreCommit = func() {
		// q.connect has completed, but the older repair has not committed its
		// successful transition. This cut must keep ownership of the outage.
		repairHost, err = r.cutAction(churnAction{host: true, index: 0}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := r.cutGuest(r.guests[0]); err != nil {
		t.Fatal(err)
	}
	r.cfg.beforeRestoreCommit = nil
	q := r.guests[0]
	q.mu.Lock()
	expected, disruption := q.expected, q.disruption
	q.mu.Unlock()
	if !expected || disruption != 2 || r.rec.summary.Reconnects != 0 {
		t.Fatalf("stale repair cleared or counted the later host outage: expected=%v disruption=%d reconnects=%d", expected, disruption, r.rec.summary.Reconnects)
	}
	if err := q.active(r); err != nil {
		t.Fatalf("new outage did not keep input paused: %v", err)
	}
	if err := r.guests[1].active(r); err != nil {
		t.Fatalf("unaffected survivor lost its terminal: %v", err)
	}
	if r.rec.summary.PausedActiveFrames != 1 || r.rec.summary.ActiveFrames != 1 {
		t.Fatal("overlap changed survivor or interrupted input accounting")
	}
	if repairHost == nil {
		t.Fatal("fixture did not perform the later host cut")
	}
	if err := repairHost(); err != nil {
		t.Fatal(err)
	}
	q.mu.Lock()
	expected, live := q.expected, q.transportLive
	q.mu.Unlock()
	if expected || !live || r.rec.summary.Reconnects != 2 || r.rec.summary.EstablishedGuests != 2 || r.rec.summary.ActualGuestCuts != 1 || r.rec.summary.ActualHostCuts != 1 {
		t.Fatalf("later owner did not restore the same guest exactly once: expected=%v live=%v summary=%+v", expected, live, r.rec.summary)
	}
}

func TestInputRangeExcludesOnlyPreBoundaryFrames(t *testing.T) {
	for _, ch := range []int{0, 3} {
		for _, missing := range []bool{false, true} {
			h := &hostRun{id: 0}
			q := &guest{host: h, seq: 4, probeSeq: [4]int{0, 0, 0, 4}}
			r := &runState{cfg: Config{ChannelsPerGuest: 4}, guests: []*guest{q}}
			tracker, epochs := sequenceTracker{}, map[string]inputEpoch{}
			r.baselineInputs(tracker, epochs, 0)
			// Replayed and in-flight earlier input may arrive after the B frame.
			for _, seq := range []int{0, 3, 2} {
				if err := r.observe(tracker, epochs, observation{kind: "I", id: ch, seq: seq}); err != nil {
					t.Fatalf("pre-boundary input became a live gap: %v", err)
				}
			}
			if !missing {
				if err := r.observe(tracker, epochs, observation{kind: "I", id: ch, seq: 4}); err != nil {
					t.Fatal(err)
				}
			}
			err := r.observe(tracker, epochs, observation{kind: "I", id: ch, seq: 5})
			if (err != nil) != missing {
				t.Fatalf("channel %d complete allocated range: missing=%v err=%v", ch, missing, err)
			}
		}
	}
}

func TestFirstPeerFrameAfterSourceReconnectIsRequired(t *testing.T) {
	q := &guest{generation: 1, inputStart: [4]int{7}, seq: 9}
	r := &runState{guests: []*guest{q}}
	tracker := sequenceTracker{"I:0": 3}
	epochs := map[string]inputEpoch{"I:0": {generation: 0, floor: 0}}
	// The reconnect probe and interrupted old epoch are excluded. A delayed
	// receiver still requires sequence 7, even when 8 has already been offered.
	if err := r.observe(tracker, epochs, observation{kind: "I", id: 0, seq: 6}); err != nil {
		t.Fatal(err)
	}
	if err := r.observe(tracker, epochs, observation{kind: "I", id: 0, seq: 8}); err == nil {
		t.Fatal("lost first input after peer restoration became a new baseline")
	}
	if err := r.observe(tracker, epochs, observation{kind: "I", id: 0, seq: 7}); err != nil {
		t.Fatal(err)
	}
	if err := r.observe(tracker, epochs, observation{kind: "I", id: 0, seq: 8}); err != nil {
		t.Fatal(err)
	}
}

func TestRecorderBoundsCumulativeEncodedOutput(t *testing.T) {
	// JSON escapes every NUL to six bytes. Retain only byte counts, so the
	// regression exercises the real cap without allocating a huge log.
	out := &countOutput{}
	r := newRecorder(out, Config{})
	body := strings.Repeat("\x00", 1<<20)
	for i := 0; i < 100 && r.err == nil; i++ {
		r.event("relay_metrics", map[string]any{"prometheus": body})
	}
	if r.err == nil || r.err.Error() != "output_budget" {
		t.Fatalf("unbounded encoded metrics were retained: bytes=%d err=%v", out.bytes, r.err)
	}
	if out.bytes > 512<<20 {
		t.Fatalf("encoded output exceeded the cap before rejection: %d", out.bytes)
	}
	before := out.bytes
	r.event("summary", nil)
	if out.bytes != before {
		t.Fatal("failed recorder kept writing after exhausting its output budget")
	}
}

type countOutput struct{ bytes int64 }

func (w *countOutput) Write(p []byte) (int, error) {
	w.bytes += int64(len(p))
	return len(p), nil
}

func TestEncodedOutputBudgetChecksExactLimitBeforeWrite(t *testing.T) {
	for _, limit := range []int64{8, 9, 10} {
		var out bytes.Buffer
		w := &outputBudgetWriter{out: &out, remaining: limit}
		encoder := json.NewEncoder(w)
		err := encoder.Encode("\x00") // "\u0000" plus LF is exactly nine bytes.
		if limit == 8 {
			if !errors.Is(err, errOutputBudget) || out.Len() != 0 || w.remaining != 8 {
				t.Fatalf("oversized encoded event wrote a prefix: limit=%d err=%v output=%q remaining=%d", limit, err, out.String(), w.remaining)
			}
			continue
		}
		if err != nil || out.String() != "\"\\u0000\"\n" || w.remaining != limit-9 {
			t.Fatalf("complete event at the limit was rejected/miscounted: limit=%d err=%v output=%q remaining=%d", limit, err, out.String(), w.remaining)
		}
		if err := encoder.Encode("x"); !errors.Is(err, errOutputBudget) || out.Len() != 9 || w.remaining != limit-9 {
			t.Fatalf("cumulative overflow wrote a partial second event: limit=%d err=%v output=%q remaining=%d", limit, err, out.String(), w.remaining)
		}
	}
}

func TestOutputBudgetStopsLiveWorkAndCleansUp(t *testing.T) {
	c := localRelay(t)
	c.DurationSeconds = 20
	c.outputLimit = 64 << 10
	var samples atomic.Int32
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if samples.Add(1) == 1 {
			_, _ = io.WriteString(w, "test_metric 1\n")
			return
		}
		_, _ = io.WriteString(w, strings.Repeat("\x00", 32<<10))
	}))
	t.Cleanup(metrics.Close)
	c.Manifest.Targets[0].TelemetryURL = metrics.URL + "/metrics"
	var out bytes.Buffer
	s, err := Run(t.Context(), c, &out)
	if !errors.Is(err, errOutputBudget) || s.StopReason != "output_budget" || s.DeliveryComplete || !s.CleanupComplete {
		t.Fatalf("output exhaustion did not stop and invalidate the phase: err=%v summary=%+v", err, s)
	}
	if s.EstablishedGuests != 1 || s.ActiveFrames == 0 || s.DurationSeconds >= 10 {
		t.Fatalf("fixture did not cancel a live workload promptly: %+v", s)
	}
	if int64(out.Len()) > c.outputLimit {
		t.Fatalf("output exceeded its budget: %d", out.Len())
	}
	decoder := json.NewDecoder(&out)
	for decoder.More() {
		var event map[string]any
		if err := decoder.Decode(&event); err != nil {
			t.Fatalf("quota retained a partial JSON event: %v", err)
		}
	}
}

func TestOutputBudgetDuringStartupStillCleansUp(t *testing.T) {
	c := localRelay(t)
	c.outputLimit = 1
	var out bytes.Buffer
	s, err := Run(t.Context(), c, &out)
	if !errors.Is(err, errOutputBudget) || s.StopReason != "output_budget" || s.DeliveryComplete || !s.CleanupComplete || out.Len() != 0 {
		t.Fatalf("startup budget failure lost its cause or cleanup: err=%v summary=%+v output=%d", err, s, out.Len())
	}
}

func TestFinalOutputFailureInvalidatesDelivery(t *testing.T) {
	c := localRelay(t)
	c.DurationSeconds = 1
	s, err := Run(t.Context(), c, rejectSummaryOutput{})
	if !errors.Is(err, errOutputBudget) || s.StopReason != "output_budget" || s.DeliveryComplete || !s.CleanupComplete || s.EstablishedGuests != 1 {
		t.Fatalf("final output failure reported successful delivery: err=%v summary=%+v", err, s)
	}
}

type rejectSummaryOutput struct{}

func (rejectSummaryOutput) Write(p []byte) (int, error) {
	var event struct{ Event string }
	if err := json.Unmarshal(p, &event); err != nil {
		return 0, err
	}
	if event.Event == "summary" {
		return 0, errOutputBudget
	}
	return len(p), nil
}
