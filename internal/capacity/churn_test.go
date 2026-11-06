package capacity

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
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
	if !s.DeliveryComplete || s.ActualHostCuts != 1 || s.ActualGuestCuts != 2 {
		t.Fatalf("actual churn delivery/cuts incomplete: %+v", s)
	}
	if s.InputFrames != int64(s.RTTCount+s.CanaryRTTCount+s.InterruptedReplies) {
		t.Fatalf("churn completion accounting lost or duplicated replies: %+v", s)
	}
	if dir := os.Getenv("CAPACITY_EVIDENCE_DIR"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "churn-events.jsonl"), out.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// A 1:1 selection cuts matching pairs and leaves all other pairs untouched.
func TestBalancedChurnSchedulesPreserveSurvivors(t *testing.T) {
	for _, tc := range []struct {
		name           string
		hosts, percent int
		want           []churnAction
		survivors      []int
	}{
		{"ten-percent", 10, 10, []churnAction{{index: 0}, {host: true, index: 0, offset: 10 * time.Second}}, []int{1, 2, 3, 4, 5, 6, 7, 8, 9}},
		{"fifty-percent", 2, 50, []churnAction{{index: 0}, {host: true, index: 0, offset: 10 * time.Second}}, []int{1}},
		{"rounded", 5, 50, []churnAction{{index: 0}, {index: 2, offset: 10 * time.Second / 3}, {host: true, index: 0, offset: 20 * time.Second / 3}, {host: true, index: 2, offset: 10 * time.Second}}, []int{1, 3, 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actions := churnSchedule(tc.hosts, 1, tc.percent)
			if !reflect.DeepEqual(actions, tc.want) {
				t.Fatalf("cut schedule = %+v; want %+v", actions, tc.want)
			}
			hosts, guests := map[int]bool{}, map[int]bool{}
			for _, a := range actions {
				if a.host {
					hosts[a.index] = true
				} else {
					guests[a.index] = true
				}
			}
			if !reflect.DeepEqual(hosts, guests) {
				t.Fatalf("balanced affected sets differ: hosts=%v guests=%v", hosts, guests)
			}
			var survivors []int
			for i := 0; i < tc.hosts; i++ {
				if !hosts[i] && !guests[i] {
					survivors = append(survivors, i)
				}
			}
			if !reflect.DeepEqual(survivors, tc.survivors) {
				t.Fatalf("untouched pairs = %v; want %v", survivors, tc.survivors)
			}
		})
	}
}

func TestRealBalancedMixedChurnRestoresOriginalSessions(t *testing.T) {
	c := localRelay(t)
	c.Hosts, c.GuestsPerHost, c.ChurnPercent, c.DurationSeconds = 2, 1, 50, 25
	c.HostWSPercent, c.GuestWSPercent = 50, 50
	c.PayloadBudgetBytes = 4 << 20
	var out bytes.Buffer
	s, err := Run(t.Context(), c, &out)
	// Preserve the actual run even if an assertion fails; no extra evidence run.
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
			if e := os.WriteFile(filepath.Join(dir, "balanced-churn-"+name), data, 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
	if err != nil {
		t.Fatalf("balanced churn: %v\n%s", err, out.String())
	}
	if s.EstablishedHosts != 2 || s.EstablishedGuests != 2 || s.EstablishedChannels != 2 || s.AdmissionFailures != 0 {
		t.Fatalf("balanced original admissions changed: %+v", s)
	}
	if s.ActualHostCuts != 1 || s.ActualGuestCuts != 1 || s.Reconnects < 2 || !s.ChurnCompleted {
		t.Fatalf("balanced real cuts/restoration missing: %+v", s)
	}
	if !s.DeliveryComplete || !s.CleanupComplete || s.StopReason != "duration" || s.SteadySeconds < 25 {
		t.Fatalf("balanced hold/delivery/cleanup incomplete: %+v", s)
	}
	if s.ActiveFrames == 0 || s.ActiveFrames+s.PausedActiveFrames != 50 || s.InputFrames != int64(s.RTTCount+s.CanaryRTTCount+s.InterruptedReplies) || s.ReceivedFrames <= int64(s.RTTCount) {
		t.Fatalf("balanced input/reply/host-output accounting incomplete: %+v", s)
	}
	type event struct {
		Event        string    `json:"event"`
		Role         string    `json:"role"`
		Host         int       `json:"host"`
		Guest        int       `json:"guest"`
		Session      string    `json:"session_id"`
		Transport    string    `json:"transport"`
		Generation   int       `json:"generation"`
		SameIdentity bool      `json:"same_identity"`
		SameHostRun  bool      `json:"same_host_run"`
		Replaced     bool      `json:"transport_replaced"`
		Before       int       `json:"responses_before"`
		After        int       `json:"responses_after"`
		Actual       int       `json:"actual_transports"`
		Planned      time.Time `json:"planned_at"`
	}
	sessions, transports := map[int]string{}, map[int]string{}
	ready := map[int]int{}
	hostRestores, guestRestores, canaries := 0, 0, 0
	var cuts []event
	decoder := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for {
		var e event
		if err := decoder.Decode(&e); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		switch e.Event {
		case "host_ready":
			if e.Host < 0 || e.Host > 1 || sessions[e.Host] != "" || e.Session == "" {
				t.Fatalf("invalid original host: %+v", e)
			}
			sessions[e.Host], transports[e.Host] = e.Session, e.Transport
		case "guest_ready":
			if e.Guest < 0 || e.Guest > 1 || e.Host != e.Guest || e.Session != sessions[e.Host] {
				t.Fatalf("guest moved sessions: %+v", e)
			}
			want := []string{"ssh", "ws"}[e.Guest]
			if e.Transport != want || (e.Guest == 1 && (e.Generation != 0 || ready[1] != 0)) {
				t.Fatalf("guest transport/identity changed: %+v", e)
			}
			ready[e.Guest]++
		case "transport_cut":
			if e.Host != 0 || e.Actual != 1 || (e.Role == "guest" && e.Guest != 0) {
				t.Fatalf("survivor or absent transport cut: %+v", e)
			}
			cuts = append(cuts, e)
		case "host_restored":
			if e.Host != 0 || !e.SameHostRun || e.Session != sessions[0] {
				t.Fatalf("host/session replaced: %+v", e)
			}
			hostRestores++
		case "guest_restored":
			if e.Guest != 0 || e.Host != 0 || !e.SameIdentity || e.Generation < 1 {
				t.Fatalf("guest identity replaced: %+v", e)
			}
			guestRestores++
		case "survivor_canary":
			if e.Host != 1 || e.Guest != 1 || e.Replaced || e.After <= e.Before {
				t.Fatalf("original survivor stopped responding: %+v", e)
			}
			canaries++
		}
	}
	if transports[0] != "ws" || transports[1] != "ssh" || len(sessions) != 2 || ready[0] < 2 || ready[1] != 1 || hostRestores != 1 || guestRestores < 1 || canaries != 1 {
		t.Fatalf("missing crossed transports, same sessions or untouched survivor: hosts=%v ready=%v restores=%d/%d canaries=%d", transports, ready, hostRestores, guestRestores, canaries)
	}
	if len(cuts) != 2 || cuts[0].Role != "guest" || cuts[1].Role != "host" || cuts[1].Planned.Sub(cuts[0].Planned) != 10*time.Second {
		t.Fatalf("actual balanced cut schedule changed: %+v", cuts)
	}
	t.Logf("balanced 2 hosts/2 guests: one host and one guest cut, original identities/sessions, unchanged generation-0 survivor, 50 offered active slots, complete delivery/cleanup; summary=%+v", s)
}
