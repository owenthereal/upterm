package capacity

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestFixedFramesAndSequenceGaps(t *testing.T) {
	b := frame("I", 7, 1, time.Unix(1, 2), 128)
	if len(b) != 128 || !strings.HasPrefix(string(b), "CAP I 00000007 00000001 0000000001000000002 ") {
		t.Fatalf("incorrect offered frame %q", b)
	}
	o, ok := parseFrame(string(b))
	if !ok || o.id != 7 || o.seq != 1 {
		t.Fatal("frame lost its tag")
	}
	tracker := sequenceTracker{}
	if err := tracker.observe(o); err != nil {
		t.Fatal(err)
	}
	o.seq = 3
	if tracker.observe(o) == nil {
		t.Fatal("missing frame went undetected")
	}
}
func TestIntentionalReconnectResetsOnlyAffectedSource(t *testing.T) {
	peer := &guest{generation: 1, inputStart: [4]int{4}}
	r := &runState{guests: []*guest{peer}}
	tracker := sequenceTracker{"I:0": 1}
	epochs := map[string]inputEpoch{"I:0": {generation: 0, floor: 0}}
	if err := r.observe(tracker, epochs, observation{kind: "I", id: 0, seq: 4}); err != nil {
		t.Fatalf("intentional reconnect gap was treated as survivor loss: %v", err)
	}
	if err := r.observe(tracker, epochs, observation{kind: "I", id: 0, seq: 6}); err == nil {
		t.Fatal("unplanned gap within a generation went undetected")
	}
}
func TestHelperReadinessChallengeCannotBeKernelEcho(t *testing.T) {
	request := frame("R", 2, 0, time.Unix(1, 0), 128)
	var out bytes.Buffer
	if err := Helper(context.Background(), bytes.NewReader(request), &out, 0, false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte("CAP A 00000002")) {
		t.Fatalf("helper did not return distinct readiness proof: %q", out.String())
	}
}
