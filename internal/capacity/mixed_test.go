package capacity

import (
	"bytes"
	"encoding/json"
	"io"
	"maps"
	"os"
	"path/filepath"
	"testing"
)

// Ascending transport selection for both grouped roles loses crossed pairs.
func TestRealMixedTransportPairing(t *testing.T) {
	for _, tc := range []struct {
		name                string
		hosts, guests       int
		wantHost, wantGuest map[string]int
		wantPairs           map[string]int
	}{
		{"even", 4, 1, map[string]int{"ssh": 2, "ws": 2}, map[string]int{"ssh": 2, "ws": 2}, map[string]int{"ssh->ws": 2, "ws->ssh": 2}},
		{"rounded-host-count", 3, 2, map[string]int{"ssh": 2, "ws": 1}, map[string]int{"ssh": 3, "ws": 3}, map[string]int{"ssh->ws": 3, "ws->ssh": 2, "ssh->ssh": 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := localRelay(t)
			c.Hosts, c.GuestsPerHost = tc.hosts, tc.guests
			c.HostWSPercent, c.GuestWSPercent = 50, 50
			c.DurationSeconds = 1
			captureChurnTerminals(t, &c)
			var out bytes.Buffer
			s, err := Run(t.Context(), c, &out)
			if err != nil {
				t.Fatalf("mixed workload: %v\n%s", err, out.String())
			}
			if s.EstablishedHosts != tc.hosts || s.EstablishedGuests != tc.hosts*tc.guests || s.EstablishedChannels != tc.hosts*tc.guests {
				t.Fatalf("admission totals: %+v", s)
			}
			if !s.DeliveryComplete || !s.CleanupComplete || s.StopReason != "duration" || s.ActiveFrames == 0 || s.ReceivedFrames == 0 || s.InputFrames != int64(s.RTTCount) {
				t.Fatalf("mixed delivery or cleanup incomplete: %+v", s)
			}
			hosts := map[int]string{}
			hostCounts, guestCounts, pairs := map[string]int{}, map[string]int{}, map[string]int{}
			guests := map[int]bool{}
			decoder := json.NewDecoder(bytes.NewReader(out.Bytes()))
			for {
				var event struct {
					Event     string `json:"event"`
					Host      int    `json:"host"`
					Guest     int    `json:"guest"`
					Transport string `json:"transport"`
				}
				if err := decoder.Decode(&event); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				switch event.Event {
				case "host_ready":
					if _, exists := hosts[event.Host]; exists || event.Host < 0 || event.Host >= tc.hosts {
						t.Fatalf("duplicate or invalid host identity: %+v", event)
					}
					hosts[event.Host] = event.Transport
					hostCounts[event.Transport]++
				case "guest_ready":
					if guests[event.Guest] || event.Guest < 0 || event.Guest >= tc.hosts*tc.guests || event.Host != event.Guest/tc.guests || hosts[event.Host] == "" {
						t.Fatalf("duplicate, invalid or reassigned guest identity: %+v", event)
					}
					guests[event.Guest] = true
					guestCounts[event.Transport]++
					pairs[hosts[event.Host]+"->"+event.Transport]++
				}
			}
			if !maps.Equal(hostCounts, tc.wantHost) || !maps.Equal(guestCounts, tc.wantGuest) {
				t.Errorf("role transport counts: hosts=%v guests=%v; want hosts=%v guests=%v", hostCounts, guestCounts, tc.wantHost, tc.wantGuest)
			}
			if !maps.Equal(pairs, tc.wantPairs) {
				t.Fatalf("mixed host->guest transport pairs = %v; want %v", pairs, tc.wantPairs)
			}
			t.Logf("actual admissions: hosts=%v guests=%v host->guest=%v; delivery and cleanup complete", hostCounts, guestCounts, pairs)
			if dir := os.Getenv("CAPACITY_EVIDENCE_DIR"); dir != "" {
				manifest, err := json.MarshalIndent(c.Manifest, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				phase, err := json.MarshalIndent(c, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				for name, data := range map[string][]byte{"manifest.json": manifest, "phase.json": phase, "events.jsonl": out.Bytes()} {
					if err := os.WriteFile(filepath.Join(dir, "mixed-"+tc.name+"-"+name), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}
