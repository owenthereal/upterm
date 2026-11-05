package capacity

import (
	"bytes"
	"testing"
	"time"
)

func TestChurnSchedulesCutsAcrossTenSeconds(t *testing.T) {
	actions := churnSchedule(20, 4, 10)
	if len(actions) != 10 {
		t.Fatalf("want two host and eight guest cuts, got %d", len(actions))
	}
	if actions[0].offset != 0 || actions[len(actions)-1].offset != 10*time.Second {
		t.Fatalf("cuts do not span ten seconds: %+v", actions)
	}
	for i := 1; i < len(actions); i++ {
		if actions[i].offset <= actions[i-1].offset {
			t.Fatal("cuts not staggered")
		}
	}
}
func TestRealTransportChurnRestoresOriginalSessions(t *testing.T) {
	c := localRelay(t)
	c.Hosts = 2
	c.GuestsPerHost = 2
	c.DurationSeconds = 25
	c.ChurnPercent = 50
	c.PayloadBudgetBytes = 4 << 20
	c.HostWSPercent = 50
	c.GuestWSPercent = 50
	var out bytes.Buffer
	s, err := Run(t.Context(), c, &out)
	if err != nil {
		t.Fatalf("churn: %v\n%s", err, out.String())
	}
	if s.Reconnects < 3 {
		t.Fatalf("real host/guest restoration absent: %+v", s)
	}
	for _, event := range []string{`"event":"transport_cut"`, `"event":"host_restored"`, `"event":"guest_restored"`, `"event":"survivor_canary"`} {
		if !bytes.Contains(out.Bytes(), []byte(event)) {
			t.Fatalf("missing %s", event)
		}
	}
	if s.EstablishedHosts != 2 || s.EstablishedGuests != 4 {
		t.Fatalf("reconnect was counted as new admission: %+v", s)
	}
}
