package capacity

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type Summary struct {
	PeakExternalConnections int       `json:"peak_external_connections"`
	HandshakeFrames         int64     `json:"handshake_frames"`
	CanaryRTTCount          int       `json:"canary_rtt_count"`
	CanaryRTTMillis         []float64 `json:"canary_rtt_millis"`
	CanaryOffered           int       `json:"canary_offered"`
	CanaryEstablished       int       `json:"canary_established"`
	CanaryReadyMillis       float64   `json:"canary_ready_millis"`
	CleanupComplete         bool      `json:"cleanup_complete"`
	PausedActiveFrames      int64     `json:"paused_active_frames"`
	InputFrames             int64     `json:"input_frames"`
	ActiveFrames            int64     `json:"active_frames"`
	ChurnCompleted          bool      `json:"churn_completed"`
	RTTSampling             string    `json:"rtt_sampling"`
	ReservedPayloadBytes    int64     `json:"reserved_payload_bytes"`
	SetupSeconds            float64   `json:"setup_seconds"`
	SteadySeconds           float64   `json:"steady_seconds"`
	RunID                   string    `json:"run_id"`
	OfferedHosts            int       `json:"offered_hosts"`
	OfferedGuests           int       `json:"offered_guests"`
	OfferedChannels         int       `json:"offered_channels"`
	EstablishedHosts        int       `json:"established_hosts"`
	EstablishedGuests       int       `json:"established_guests"`
	EstablishedChannels     int       `json:"established_channels"`
	AdmissionFailures       int       `json:"admission_failures"`
	PayloadBytes            int64     `json:"payload_bytes"`
	PayloadBudgetBytes      int64     `json:"payload_budget_bytes"`
	ReceivedFrames          int64     `json:"received_frames"`
	RTTCount                int       `json:"rtt_count"`
	RTTMillis               []float64 `json:"rtt_millis"`
	RTTP50Millis            float64   `json:"rtt_p50_millis"`
	RTTP95Millis            float64   `json:"rtt_p95_millis"`
	RTTP99Millis            float64   `json:"rtt_p99_millis"`
	Reconnects              int       `json:"reconnects"`
	Transfers               int       `json:"transfers"`
	TransferBytes           int64     `json:"transfer_bytes"`
	DurationSeconds         float64   `json:"duration_seconds"`
	StopReason              string    `json:"stop_reason"`
}

type recorder struct {
	mu      sync.Mutex
	encoder *json.Encoder
	err     error
	summary Summary
}

func (r *recorder) event(kind string, fields map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fields == nil {
		fields = map[string]any{}
	}
	fields["event"] = kind
	fields["at"] = time.Now().UTC()
	fields["run_id"] = r.summary.RunID
	if r.err == nil {
		r.err = r.encoder.Encode(fields)
	}
}
func newRecorder(out io.Writer, c Config) *recorder {
	return &recorder{encoder: json.NewEncoder(out), summary: Summary{RunID: c.Manifest.RunID, RTTSampling: "uniform_reservoir_100000", OfferedHosts: c.Hosts, OfferedGuests: c.Hosts * c.GuestsPerHost, OfferedChannels: c.Hosts * c.GuestsPerHost * c.ChannelsPerGuest, PayloadBudgetBytes: c.PayloadBudgetBytes}}
}
