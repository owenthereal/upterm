package capacity

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const silentAfterReadinessScript = `inputs=0
while IFS= read -r line; do
case "$line" in
'CAP R '*) printf 'CAP A %s\n' "${line#CAP R }";;
'CAP Q '*) printf 'CAP B %s\n' "${line#CAP Q }";;
'CAP I '*)
  if [ "$inputs" -eq 0 ]; then printf '%s\n' "$line"; fi
  inputs=$((inputs + 1));;
esac
done
`
const lateFinalReplyScript = `inputs=0
while IFS= read -r line; do
case "$line" in
'CAP R '*) printf 'CAP A %s\n' "${line#CAP R }";;
'CAP Q '*) printf 'CAP B %s\n' "${line#CAP Q }";;
'CAP I '*)
  if [ "$inputs" -eq 1 ]; then sleep 1.2; fi
  if [ "$inputs" -le 1 ]; then printf '%s\n' "$line"; fi
  inputs=$((inputs + 1));;
'CAP F '*) printf 'CAP B %s\n' "${line#CAP F }";;
esac
done
`
const retryReadinessScript = `challenges=0
while IFS= read -r line; do
case "$line" in
'CAP R '*)
  if [ "$challenges" -gt 0 ]; then printf 'CAP A %s\n' "${line#CAP R }"; fi
  challenges=$((challenges + 1));;
'CAP Q '*) printf 'CAP B %s\n' "${line#CAP Q }";;
'CAP F '*) printf 'CAP B %s\n' "${line#CAP F }";;
'CAP I '*) printf '%s\n' "$line";;
esac
done
`

func TestSilentAfterReadinessFailsDelivery(t *testing.T) {
	c := localRelay(t)
	helper := filepath.Join(t.TempDir(), "silent-helper")
	script := "#!/bin/sh\nstty raw -echo\n" + silentAfterReadinessScript
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	c.HelperExecutable = helper
	c.DurationSeconds = 3
	s, err := Run(t.Context(), c, io.Discard)
	t.Logf("delivery result: err=%v active=%d rtt=%d stop=%s", err, s.ActiveFrames, s.RTTCount, s.StopReason)
	if s.EstablishedGuests != 1 || s.ActiveFrames != 3 {
		t.Fatalf("fixture did not reach steady workload: %+v", s)
	}
	if err == nil {
		t.Fatalf("silent post-readiness workload succeeded: active=%d rtt=%d stop=%s", s.ActiveFrames, s.RTTCount, s.StopReason)
	}
	if !s.CleanupComplete {
		t.Fatal("failed delivery did not clean up")
	}
}

func TestExpectedRestoreDoesNotBlockHealthyCadence(t *testing.T) {
	c := validConfig(t)
	r := &runState{cfg: c, rec: newRecorder(io.Discard, c)}
	disrupted := &guest{expected: true}
	healthy := &guest{writers: []io.WriteCloser{discardWriteCloser{}}}
	disrupted.ops.Lock() // connect holds this throughout a slow restoration.
	defer disrupted.ops.Unlock()
	finished := make(chan error, 1)
	go func() {
		for i := 0; i < 3; i++ {
			if err := disrupted.active(r); err != nil {
				finished <- err
				return
			}
			if err := healthy.active(r); err != nil {
				finished <- err
				return
			}
		}
		finished <- nil
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("restoring guest blocked healthy offered cadence")
	}
	if r.rec.summary.ActiveFrames != 3 || r.rec.summary.PausedActiveFrames != 3 {
		t.Fatalf("wrong independent cadence accounting: %+v", r.rec.summary)
	}
}

type discardWriteCloser struct{}

func (discardWriteCloser) Write(b []byte) (int, error) { return len(b), nil }
func (discardWriteCloser) Close() error                { return nil }

func TestGuestTransportCutDoesNotWaitForHostRepair(t *testing.T) {
	c := validConfig(t)
	ctx, cancel := context.WithCancelCause(t.Context())
	r := &runState{ctx: ctx, cancel: cancel, cfg: c, rec: newRecorder(io.Discard, c)}
	raw, peer := net.Pipe()
	defer peer.Close()
	h := &hostRun{}
	q := &guest{host: h, raw: raw, transportLive: true}
	r.guests = []*guest{q}
	h.repair.Lock()
	finished := make(chan error, 1)
	go func() { finished <- r.cutGuest(q) }()
	defer func() { cancel(context.Canceled); h.repair.Unlock(); <-finished }()
	_ = peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("transport was not cut")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("actual transport cut waited behind slow host repair")
	}
}

func TestAdmissionQueueIsOutsideServiceReadinessDeadline(t *testing.T) {
	for _, mix := range []struct {
		name string
		ws   int
	}{{"ssh", 0}, {"ws", 100}} {
		t.Run(mix.name, func(t *testing.T) { pacedAdmissionFixture(t, mix.ws) })
	}
}
func pacedAdmissionFixture(t *testing.T, ws int) {
	c := localRelay(t)
	c.HostWSPercent = ws
	ctx, cancel := context.WithCancelCause(t.Context())
	dir, err := os.MkdirTemp("", "cap-admit-")
	if err != nil {
		t.Fatal(err)
	}
	var events bytes.Buffer
	r := &runState{ctx: ctx, cancel: cancel, cfg: c, rec: newRecorder(&events, c), guard: newGuard(c), dir: dir, helper: c.HelperExecutable, hostReadyTimeout: 200 * time.Millisecond, guestReadyTimeout: 200 * time.Millisecond}
	defer func() {
		if err := r.cleanup(); err != nil {
			t.Error(err)
		}
	}()
	r.hosts = make([]*hostRun, 1)
	r.guestIdentity = signer(t)
	r.guard.next = time.Now().Add(450 * time.Millisecond)
	target := c.Manifest.Targets[0]
	if err := r.startHost(0, target, nil); err != nil {
		t.Fatalf("generator queue consumed host service deadline: %v", err)
	}
	u, err := transport(target, ws, 0, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := newTunnelProxy(ctx, r.guard, target)
	if err != nil {
		t.Fatal(err)
	}
	r.proxies = append(r.proxies, proxy)
	q := &guest{host: r.hosts[0], target: target, endpoint: u, identity: r.guestIdentity, proxy: proxy}
	r.guests = append(r.guests, q)
	r.guard.mu.Lock()
	r.guard.next = time.Now().Add(450 * time.Millisecond)
	r.guard.mu.Unlock()
	if err = q.connect(ctx, r); err != nil {
		t.Fatalf("generator queue consumed guest service deadline: %v", err)
	}
	decoder := json.NewDecoder(&events)
	ready := 0
	for decoder.More() {
		var event map[string]any
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event["event"] == "host_ready" || event["event"] == "guest_ready" {
			ready++
			if event["queue_ms"].(float64) < 400 || event["ready_ms"].(float64) >= 200 {
				t.Fatalf("pacing polluted service latency: %+v", event)
			}
		}
	}
	if ready != 2 {
		t.Fatalf("missing service readiness timing events: %d", ready)
	}

}

func scriptedHelper(t *testing.T, body string) Config {
	t.Helper()
	c := localRelay(t)
	path := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nstty raw -echo\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	c.HelperExecutable = path
	return c
}

func TestLateFinalReplyIsDrainedAndMeasured(t *testing.T) {
	c := scriptedHelper(t, lateFinalReplyScript)
	c.DurationSeconds = 1
	s, err := Run(t.Context(), c, io.Discard)
	if err != nil {
		t.Fatalf("late final reply failed: %v %+v", err, s)
	}
	late := false
	for _, ms := range s.RTTMillis {
		late = late || ms >= 1000
	}
	if !s.DeliveryComplete || s.RTTCount != 2 || !late || s.DrainSeconds < .1 || s.SteadySeconds < 1 || s.SteadySeconds > 1.1 {
		t.Fatalf("late reply was not measured separately from offered interval: %+v", s)
	}
}

func TestMissingHostOutputSuffixFailsDelivery(t *testing.T) {
	// The barrier advertises one emitted H frame, but that entire suffix is
	// dropped. Every I frame is echoed, so own-response and gap-only checks pass.
	c := scriptedHelper(t, "while IFS= read -r line; do\ncase \"$line\" in\n'CAP R '*) printf '%s\\n' \"$line\" | tr R A;;\n'CAP Q '*) printf '%s\\n' \"$line\" | tr Q B;;\n'CAP F '*) printf '%s\\n' \"$line\" | awk '{$2=\"B\";$4=\"00000001\";print}';;\n*) printf '%s\\n' \"$line\";;\nesac\ndone\n")
	c.DurationSeconds = 1
	s, err := Run(t.Context(), c, io.Discard)
	if err == nil {
		t.Fatalf("missing H suffix succeeded: %+v", s)
	}
	if !strings.Contains(err.Error(), "host output suffix missing") {
		t.Fatalf("fixture did not detect missing H suffix: %v", err)
	}
}

func TestFinalFanoutSuffixMustReachEveryReceiver(t *testing.T) {
	h := &hostRun{id: 0}
	r := &runState{guests: []*guest{{id: 0, host: h, activeOffered: true, lastActiveSeq: 4}, {id: 1, host: h, activeOffered: true, lastActiveSeq: 7}}}
	if err := r.verifyFinalInputs(sequenceTracker{"I:0": 4, "I:4": 6}, 0, time.Time{}); err == nil {
		t.Fatal("missing final peer input was accepted")
	}
	if err := r.verifyFinalInputs(sequenceTracker{"I:0": 4, "I:4": 7}, 0, time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestActualCutsKeepScheduleDuringSlowOverlappingRepairs(t *testing.T) {
	c := validConfig(t)
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(context.Canceled)
	r := &runState{cfg: c, ctx: ctx, cancel: cancel, rec: newRecorder(io.Discard, c)}
	h := &hostRun{id: 0, proxy: &tunnelProxy{conns: map[net.Conn]bool{}}}
	hostRaw, hostPeer := net.Pipe()
	defer hostPeer.Close()
	h.proxy.conns[hostRaw] = true
	r.hosts = []*hostRun{h}
	var peers []net.Conn
	for i := 0; i < 2; i++ {
		raw, peer := net.Pipe()
		peers = append(peers, peer)
		defer peer.Close()
		r.guests = append(r.guests, &guest{id: i, host: h, raw: raw, transportLive: true})
	}
	actions := []churnAction{{index: 0}, {index: 1, offset: 25 * time.Millisecond}, {host: true, index: 0, offset: 50 * time.Millisecond}}
	release := make(chan struct{})
	actual := make(chan time.Time, len(actions))
	finished := make(chan error, 1)
	start := time.Now().Add(10 * time.Millisecond)
	go func() {
		finished <- executeCuts(ctx, actions, start, func(a churnAction, planned time.Time) (func() error, error) {
			_, err := r.cutAction(a, planned)
			actual <- time.Now()
			return func() error { <-release; return nil }, err
		})
	}()
	for i, a := range actions {
		select {
		case at := <-actual:
			if delay := at.Sub(start.Add(a.offset)); delay < 0 || delay > 40*time.Millisecond {
				t.Errorf("actual cut %d missed planned time by %s", i, delay)
			}
		case <-time.After(150 * time.Millisecond):
			t.Error("actual cut waited for repair")
		}
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if r.rec.summary.ActualHostCuts != 1 || r.rec.summary.ActualGuestCuts != 2 {
		t.Fatalf("cuts were silently reduced: %+v", r.rec.summary)
	}
	for _, peer := range append(peers, hostPeer) {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("scheduled transport did not actually close: %v", err)
		}
	}
	if _, err := r.cutAction(actions[0], time.Now()); err == nil {
		t.Fatal("already-disrupted transport was counted as another cut")
	}
}

func TestIndependentGuestCadenceDuringSlowRestore(t *testing.T) {
	c := validConfig(t)
	c.DurationSeconds = 3
	c.Active = true
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(context.Canceled)
	r := &runState{cfg: c, ctx: ctx, cancel: cancel, rec: newRecorder(io.Discard, c)}
	disrupted := &guest{expected: true}
	healthy := &guest{id: 1, writers: []io.WriteCloser{timedWriter{calls: make(chan time.Time, 3)}}}
	calls := healthy.writers[0].(timedWriter).calls
	r.guests = []*guest{disrupted, healthy}
	disrupted.ops.Lock()
	defer disrupted.ops.Unlock()
	began := time.Now()
	r.activeWorkload(began, &r.activeWorkers)
	for i := 0; i < 3; i++ {
		select {
		case at := <-calls:
			if delay := at.Sub(began.Add(time.Duration(i) * time.Second)); delay < 0 || delay > 150*time.Millisecond {
				t.Errorf("healthy guest cadence %d delayed %s", i, delay)
			}
		case <-time.After(1200 * time.Millisecond):
			t.Errorf("healthy cadence %d blocked by restoration", i)
		}
	}
	r.activeWorkers.Wait()
	if r.rec.summary.ActiveFrames != 3 || r.rec.summary.PausedActiveFrames != 3 {
		t.Fatalf("healthy work was paused: %+v", r.rec.summary)
	}
}

type timedWriter struct{ calls chan time.Time }

func (w timedWriter) Write(b []byte) (int, error) { w.calls <- time.Now(); return len(b), nil }
func (w timedWriter) Close() error                { return nil }

func TestActualDialsRemainPacedAcrossReservationsAndRetries(t *testing.T) {
	c := validConfig(t)
	c.AdmissionsPerSecond = 20
	g := newGuard(c)
	var mu sync.Mutex
	var starts []time.Time
	g.dial = func(context.Context, string, string) (net.Conn, error) {
		mu.Lock()
		starts = append(starts, time.Now())
		mu.Unlock()
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := g.connect(t.Context(), c.Manifest.Targets[0], "127.0.0.1:2222")
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
		}()
	}
	wg.Wait()
	for i := 1; i < len(starts); i++ {
		if starts[i].Sub(starts[i-1]) < 49*time.Millisecond {
			t.Fatalf("external dials bunched: %v", starts)
		}
	}
	if len(starts) != 5 {
		t.Fatalf("missing real dial attempts: %d", len(starts))
	}
}

func TestRetryBacklogIsGeneratorLimitedBeforeServiceStarts(t *testing.T) {
	c := validConfig(t)
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(context.Canceled)
	g := newGuard(c)
	proxy, err := newTunnelProxy(ctx, g, c.Manifest.Targets[0])
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	proxy.queueLimit = 30 * time.Millisecond
	proxy.failure = cancel
	g.next = time.Now().Add(time.Second)
	req := httptest.NewRequest(http.MethodConnect, "http://127.0.0.1:2222", nil)
	req.Host = "127.0.0.1:2222"
	proxy.ServeHTTP(httptest.NewRecorder(), req)
	if cause := context.Cause(ctx); cause == nil || cause.Error() != "generator_admission_backlog" {
		t.Fatalf("retry backlog looked like a relay service failure: %v", cause)
	}
	if g.peak != 0 {
		t.Fatal("timed-out generator queue started an external dial")
	}
}

func TestRealDeliveryEvidence(t *testing.T) {
	c := localRelay(t)
	c.DurationSeconds = 1
	c.GuestWSPercent = 100
	c.GuestsPerHost = 2
	c.ChannelsPerGuest = 4
	var out bytes.Buffer
	s, err := Run(t.Context(), c, &out)
	if err != nil {
		t.Fatalf("real crossed delivery: %v\n%s", err, out.String())
	}
	if !s.DeliveryComplete || s.RTTCount != 10 || s.InputFrames != 10 || s.InputFrames != int64(s.RTTCount+s.CanaryRTTCount+s.InterruptedReplies) || !s.CleanupComplete {
		t.Fatalf("delivery evidence incomplete: %+v", s)
	}
	if dir := os.Getenv("CAPACITY_EVIDENCE_DIR"); dir != "" {
		manifest, e := json.MarshalIndent(c.Manifest, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		phase, e := json.MarshalIndent(c, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		for name, data := range map[string][]byte{"manifest.json": manifest, "phase.json": phase, "events.jsonl": out.Bytes()} {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("retained successful local fixture evidence in %s (Darwin has no /proc telemetry)", dir)
	}
}

func TestHelperFinalBarrierFlushesAndQuiescesHostOutput(t *testing.T) {
	in, input := io.Pipe()
	output, out := io.Pipe()
	defer input.Close()
	defer output.Close()
	finished := make(chan error, 1)
	go func() {
		err := helper(t.Context(), in, out, 0, true, 20*time.Millisecond)
		_ = out.Close()
		finished <- err
	}()
	observations := make(chan observation, 16)
	scanned := make(chan error, 1)
	go func() {
		scanned <- scanFrames(output, func(o observation) error { observations <- o; return nil }, func(observation) {})
	}()
	seen := 0
	for seen < 2 {
		select {
		case o := <-observations:
			if o.kind != "H" || o.seq != seen {
				t.Fatalf("host cadence/sequence missing: %+v", o)
			}
			seen++
		case <-time.After(100 * time.Millisecond):
			t.Fatal("helper skipped a due host-output interval")
		}
	}
	if _, err := input.Write(frame("F", 0, 0, time.Now(), 128)); err != nil {
		t.Fatal(err)
	}
	select {
	case o := <-observations:
		if o.kind != "B" || o.seq != 2 {
			t.Fatalf("final host-output count missing: %+v", o)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("helper final barrier blocked")
	}
	select {
	case o := <-observations:
		t.Fatalf("helper emitted output after final barrier: %+v", o)
	case <-time.After(60 * time.Millisecond):
	}
	_ = input.Close()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := <-scanned; err != io.EOF {
		t.Fatal(err)
	}
}

func TestReplayCannotAcknowledgeOrRemeasureCurrentRequest(t *testing.T) {
	now := time.Now()
	q := &guest{pending: map[string]time.Time{"0:4": now}}
	old := observation{kind: "I", id: 0, seq: 4, sent: now.Add(-time.Minute)}
	if _, ok := q.acknowledge(old); ok {
		t.Fatal("replayed timestamp acknowledged current input")
	}
	if len(q.pending) != 1 {
		t.Fatal("replay removed outstanding input")
	}
	old.sent = now
	if sent, ok := q.acknowledge(old); !ok || !sent.Equal(now) {
		t.Fatal("matching reply was not acknowledged")
	}
	if _, ok := q.acknowledge(old); ok || q.acks != 1 {
		t.Fatal("duplicate reply inflated RTT/count")
	}
}

func TestFreshChallengeSurvivesUnterminatedTerminalReplay(t *testing.T) {
	// Terminal reconstruction may finish with a partial screen row rather than
	// LF. Its old text and the first fresh helper frame then share a scan line.
	replay := strings.TrimSuffix(string(frame("I", 4, 3, time.Unix(1, 0), 128)), "\n") + "\x1b[0m"
	fresh := frame("A", 4, 11, time.Unix(2, 0), 128)
	o, ok := parseFrame(replay + string(fresh))
	if !ok || o.kind != "A" || o.seq != 11 || !o.sent.Equal(time.Unix(2, 0)) {
		t.Fatalf("fresh challenge swallowed by terminal replay suffix: %+v valid=%v", o, ok)
	}
}

func TestReconnectCannotReuseReplayedBaseline(t *testing.T) {
	old := time.Unix(1, 0)
	// The old transport's baseline can be replayed with an incomplete screen
	// history. None of it belongs to this connection's delivery interval.
	replay := string(frame("B", 0, 0, old, 128)) + string(frame("H", 0, 0, old, 1024)) + string(frame("H", 0, 2, old, 1024))
	c := scriptedHelper(t, "printf '%s' '"+replay+"'\nwhile IFS= read -r line; do\ncase \"$line\" in\n'CAP R '*) printf '%s\\n' \"$line\" | tr R A;;\n'CAP Q '*) printf '%s\\n' \"$line\" | tr Q B;;\n*) printf '%s\\n' \"$line\";;\nesac\ndone\n")
	ctx, cancel := context.WithCancelCause(t.Context())
	dir, err := os.MkdirTemp("", "cap-replay-")
	if err != nil {
		t.Fatal(err)
	}
	r := &runState{ctx: ctx, cancel: cancel, cfg: c, rec: newRecorder(io.Discard, c), guard: newGuard(c), dir: dir, helper: c.HelperExecutable, guestReadyTimeout: 2 * time.Second, hosts: make([]*hostRun, 1)}
	defer func() {
		if err := r.cleanup(); err != nil {
			t.Error(err)
		}
	}()
	target := c.Manifest.Targets[0]
	r.guestIdentity = signer(t)
	if err := r.startHost(0, target, nil); err != nil {
		t.Fatal(err)
	}
	u, err := transport(target, 0, 0, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := newTunnelProxy(ctx, r.guard, target)
	if err != nil {
		t.Fatal(err)
	}
	r.proxies = append(r.proxies, proxy)
	q := &guest{host: r.hosts[0], target: target, endpoint: u, identity: r.guestIdentity, proxy: proxy, expected: true, generation: 1, barriers: map[int]*frameBarrier{0: {sent: old, done: make(chan struct{})}}}
	r.guests = append(r.guests, q)
	if err := q.connect(ctx, r); err != nil {
		t.Fatalf("replayed old baseline prevented fresh readiness: %v", err)
	}
	q.mu.Lock()
	acks, barrier := q.acks, q.barriers[0]
	q.mu.Unlock()
	if acks != 1 || barrier == nil || !barrier.sent.After(old) {
		t.Fatalf("fresh connection did not establish its own live boundary: acks=%d barrier=%+v", acks, barrier)
	}
}

func TestShortWriteCannotBecomeOfferedOrOutstandingFrame(t *testing.T) {
	c := validConfig(t)
	r := &runState{cfg: c, rec: newRecorder(io.Discard, c)}
	q := &guest{writers: []io.WriteCloser{shortFrameWriter{}}}
	if err := q.active(r); err != io.ErrShortWrite {
		t.Fatalf("short write became a successful active frame: err=%v active=%d", err, r.rec.summary.ActiveFrames)
	}
	if len(q.pending) != 0 || r.rec.summary.InputFrames != 0 || r.rec.summary.ActiveFrames != 0 {
		t.Fatal("partial input inflated completion accounting")
	}
}

type shortFrameWriter struct{}

func (shortFrameWriter) Write(b []byte) (int, error) { return len(b) / 2, nil }
func (shortFrameWriter) Close() error                { return nil }

func TestHelperResynchronizesAfterCutTruncatesInput(t *testing.T) {
	// A transport cut may leave a partial old input before the next guest's
	// complete challenge on the shared PTY. Fixed-size reads stay misaligned.
	broken := frame("I", 0, 5, time.Unix(1, 0), 128)[:63]
	challenge := frame("R", 4, 11, time.Unix(2, 0), 128)
	var out bytes.Buffer
	err := Helper(t.Context(), bytes.NewReader(append(broken, challenge...)), &out, 0, false)
	if err != nil || !bytes.Contains(out.Bytes(), frame("A", 4, 11, time.Unix(2, 0), 128)) {
		t.Fatalf("partial disrupted input prevented a fresh challenge: err=%v output=%q", err, out.Bytes())
	}
}

func TestReadinessChallengeCanRetryWithinSameServiceBudget(t *testing.T) {
	// A reconstruction can consume/transform the first challenge response.
	// A repeated authenticated challenge must prove the same live channel.
	c := scriptedHelper(t, retryReadinessScript)
	c.DurationSeconds = 1
	s, err := Run(t.Context(), c, io.Discard)
	if err != nil || !s.DeliveryComplete || s.EstablishedGuests != 1 || s.InputFrames != 2 || s.RTTCount != 2 || s.HandshakeFrames < 4 {
		t.Fatalf("bounded repeated challenge did not prove live delivery: err=%v summary=%+v", err, s)
	}
}

func TestActiveWorkloadNeverOffersAfterSteadyEnd(t *testing.T) {
	c := validConfig(t)
	c.Active = true
	c.DurationSeconds = 2
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(context.Canceled)
	r := &runState{cfg: c, ctx: ctx, cancel: cancel, rec: newRecorder(io.Discard, c), guests: []*guest{{writers: []io.WriteCloser{discardWriteCloser{}}}}}
	r.activeWorkload(time.Now().Add(-2*time.Second), &r.activeWorkers)
	r.activeWorkers.Wait()
	if r.rec.summary.ActiveFrames != 0 || context.Cause(ctx) == nil {
		t.Fatalf("missed offered intervals were sent in final drain: active=%d cause=%v", r.rec.summary.ActiveFrames, context.Cause(ctx))
	}
}
