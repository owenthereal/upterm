package capacity

import (
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

type Summary struct {
	ReadinessChallengeRetries int       `json:"readiness_challenge_retries"`
	DrainSeconds              float64   `json:"drain_seconds"`
	DeliveryComplete          bool      `json:"delivery_complete"`
	ActualHostCuts            int       `json:"actual_host_cuts"`
	ActualGuestCuts           int       `json:"actual_guest_cuts"`
	InterruptedReplies        int       `json:"interrupted_replies"`
	PeakExternalConnections   int       `json:"peak_external_connections"`
	HandshakeFrames           int64     `json:"handshake_frames"`
	CanaryRTTCount            int       `json:"canary_rtt_count"`
	CanaryRTTMillis           []float64 `json:"canary_rtt_millis"`
	CanaryOffered             int       `json:"canary_offered"`
	CanaryEstablished         int       `json:"canary_established"`
	CanaryReadyMillis         float64   `json:"canary_ready_millis"`
	CleanupComplete           bool      `json:"cleanup_complete"`
	PausedActiveFrames        int64     `json:"paused_active_frames"`
	InputFrames               int64     `json:"input_frames"`
	ActiveFrames              int64     `json:"active_frames"`
	ChurnCompleted            bool      `json:"churn_completed"`
	RTTSampling               string    `json:"rtt_sampling"`
	ReservedPayloadBytes      int64     `json:"reserved_payload_bytes"`
	SetupSeconds              float64   `json:"setup_seconds"`
	SteadySeconds             float64   `json:"steady_seconds"`
	RunID                     string    `json:"run_id"`
	OfferedHosts              int       `json:"offered_hosts"`
	OfferedGuests             int       `json:"offered_guests"`
	OfferedChannels           int       `json:"offered_channels"`
	EstablishedHosts          int       `json:"established_hosts"`
	EstablishedGuests         int       `json:"established_guests"`
	EstablishedChannels       int       `json:"established_channels"`
	AdmissionFailures         int       `json:"admission_failures"`
	PayloadBytes              int64     `json:"payload_bytes"`
	PayloadBudgetBytes        int64     `json:"payload_budget_bytes"`
	ReceivedFrames            int64     `json:"received_frames"`
	RTTCount                  int       `json:"rtt_count"`
	RTTMillis                 []float64 `json:"rtt_millis"`
	RTTP50Millis              float64   `json:"rtt_p50_millis"`
	RTTP95Millis              float64   `json:"rtt_p95_millis"`
	RTTP99Millis              float64   `json:"rtt_p99_millis"`
	Reconnects                int       `json:"reconnects"`
	Transfers                 int       `json:"transfers"`
	TransferBytes             int64     `json:"transfer_bytes"`
	DurationSeconds           float64   `json:"duration_seconds"`
	StopReason                string    `json:"stop_reason"`
}

type recorder struct {
	mu      sync.Mutex
	encoder *json.Encoder
	err     error
	fail    func(error)
	summary Summary
}

const maxOutputBytes = int64(512 << 20)

var errOutputBudget = errors.New("output_budget")

// json.Encoder writes one complete encoded event at a time. Check its actual
// encoded size, including escaping and LF, before forwarding any of it.
type outputBudgetWriter struct {
	out       io.Writer
	remaining int64
}

func (w *outputBudgetWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errOutputBudget
	}
	n, err := w.out.Write(p)
	w.remaining -= int64(n)
	if n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
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
		if r.err != nil && r.fail != nil {
			r.fail(r.err)
		}
	}
}
func newRecorder(out io.Writer, c Config) *recorder {
	limit := maxOutputBytes
	if c.outputLimit > 0 && c.outputLimit < limit {
		limit = c.outputLimit
	}
	return &recorder{encoder: json.NewEncoder(&outputBudgetWriter{out: out, remaining: limit}), summary: Summary{RunID: c.Manifest.RunID, RTTSampling: "uniform_reservoir_100000", OfferedHosts: c.Hosts, OfferedGuests: c.Hosts * c.GuestsPerHost, OfferedChannels: c.Hosts * c.GuestsPerHost * c.ChannelsPerGuest, PayloadBudgetBytes: c.PayloadBudgetBytes}}
}
