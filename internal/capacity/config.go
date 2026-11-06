// Package capacity is the opt-in, bounded relay experiment runner.
package capacity

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Manifest struct {
	RunID     string    `json:"run_id"`
	ExpiresAt time.Time `json:"expires_at"`
	LocalOnly bool      `json:"local_only"`
	Targets   []Target  `json:"targets"`
}

type Target struct {
	PublicSSHURL  string   `json:"public_ssh_url,omitempty"`
	PublicWSURL   string   `json:"public_ws_url,omitempty"`
	AppID         string   `json:"app_id"`
	MachineID     string   `json:"machine_id"`
	SSHURL        string   `json:"ssh_url"`
	WSURL         string   `json:"ws_url"`
	NodeAddresses []string `json:"node_addresses"`
	AllowedIPs    []string `json:"allowed_ips"`
	HostKeys      []string `json:"host_keys"`
	TelemetryURL  string   `json:"telemetry_url"`
}

type Config struct {
	HostPublic            bool   `json:"host_public"`
	EntryPublic           bool   `json:"entry_public"`
	HostIdentityFile      string `json:"host_identity_file"`
	WatchdogHeartbeatFile string `json:"watchdog_heartbeat_file"`
	// HelperExecutable must be this runner binary (defaults to os.Executable).
	HelperExecutable    string   `json:"-"`
	Manifest            Manifest `json:"-"`
	Hosts               int      `json:"hosts"`
	GuestsPerHost       int      `json:"guests_per_host"`
	HostTarget          string   `json:"host_target"`
	EntryTarget         string   `json:"entry_target"`
	HostWSPercent       int      `json:"host_ws_percent"`
	GuestWSPercent      int      `json:"guest_ws_percent"`
	ChannelsPerGuest    int      `json:"channels_per_guest"`
	DurationSeconds     int      `json:"duration_seconds"`
	AdmissionsPerSecond int      `json:"admissions_per_second"`
	PayloadBudgetBytes  int64    `json:"payload_budget_bytes"`
	Active              bool     `json:"active"`
	TransferConcurrency int      `json:"transfer_concurrency"`
	ChurnPercent        int      `json:"churn_percent"`
	WatchdogFile        string   `json:"watchdog_file"`
}

const MaxPayload = int64(50 << 30)
const TransferSize = int64(16 << 20)

func decodeOne(r io.Reader, v any) error {
	if r == nil {
		return errors.New("explicit manifest and phase inputs required")
	}
	d := json.NewDecoder(io.LimitReader(r, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("configuration must contain one JSON object")
	}
	return nil
}

func Decode(manifest, phase io.Reader) (Config, error) {
	var c Config
	if err := decodeOne(manifest, &c.Manifest); err != nil {
		return c, fmt.Errorf("manifest: %w", err)
	}
	if err := decodeOne(phase, &c); err != nil {
		return c, fmt.Errorf("phase: %w", err)
	}
	return c, c.Validate(time.Now())
}

func production(s string) bool {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	return s == "upterm" || s == "uptermd" || s == "upterm.fly.dev" || s == "upterm.internal" || strings.HasSuffix(s, ".upterm.internal") || s == "upterm.dev" || strings.HasSuffix(s, ".upterm.dev") || s == "upterm.io" || strings.HasSuffix(s, ".upterm.io")
}

func endpoint(raw string, schemes ...string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid endpoint URL")
	}
	ok := false
	for _, s := range schemes {
		ok = ok || u.Scheme == s
	}
	if !ok || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || production(u.Hostname()) {
		return nil, errors.New("unauthorized endpoint")
	}
	if u.Path != "" && u.Path != "/" && !(u.Scheme == "http" && u.Path == "/metrics") {
		return nil, errors.New("unexpected endpoint path")
	}
	if u.Port() == "" {
		ports := map[string]string{"ssh": "22", "ws": "80", "wss": "443", "http": "80"}
		u.Host = net.JoinHostPort(u.Hostname(), ports[u.Scheme])
	}
	if _, err := net.LookupPort("tcp", u.Port()); err != nil {
		return nil, errors.New("invalid endpoint port")
	}
	return u, nil
}

func (c Config) target(id string) (Target, bool) {
	for _, t := range c.Manifest.Targets {
		if t.MachineID == id {
			return t, true
		}
	}
	return Target{}, false
}

func (c Config) Validate(now time.Time) error {
	m := c.Manifest
	if m.RunID == "" || !m.ExpiresAt.After(now) || m.ExpiresAt.Sub(now) > 24*time.Hour || len(m.Targets) < 1 || len(m.Targets) > 2 {
		return errors.New("manifest missing, expired, or beyond 24-hour/two-target limit")
	}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if os.Getenv(k) != "" {
			return fmt.Errorf("implicit proxy environment %s refused", k)
		}
	}
	if c.Hosts < 1 || c.Hosts > 998 || c.GuestsPerHost < 0 || c.GuestsPerHost > 998 || c.Hosts*(1+c.GuestsPerHost)+len(m.Targets)+c.canaryConnection() > 1000 {
		return errors.New("host/guest external connection limit exceeded")
	}
	if c.AdmissionsPerSecond < 1 || c.AdmissionsPerSecond > 20 || c.DurationSeconds < 1 || c.DurationSeconds > 86400 || time.Duration(c.DurationSeconds)*time.Second > m.ExpiresAt.Sub(now) {
		return errors.New("rate/duration outside approved bounds")
	}
	if c.PayloadBudgetBytes < 1 || c.PayloadBudgetBytes > MaxPayload || (c.ChannelsPerGuest != 1 && c.ChannelsPerGuest != 4) {
		return errors.New("byte/channel limit outside approved bounds")
	}
	if c.HostWSPercent < 0 || c.HostWSPercent > 100 || c.GuestWSPercent < 0 || c.GuestWSPercent > 100 {
		return errors.New("transport percentage outside 0..100")
	}
	if c.TransferConcurrency != 0 && c.TransferConcurrency != 4 && c.TransferConcurrency != 8 {
		return errors.New("transfer concurrency must be zero, four or eight")
	}
	if c.TransferConcurrency > 0 && (c.GuestsPerHost == 0 || int64(c.TransferConcurrency)*2*TransferSize > c.PayloadBudgetBytes) {
		return errors.New("transfer requires guests and sufficient byte budget")
	}
	if c.ChurnPercent != 0 && c.ChurnPercent != 10 && c.ChurnPercent != 50 {
		return errors.New("churn must be zero, ten or fifty percent")
	}
	if c.ChurnPercent > 0 && (c.Hosts < 2 || c.GuestsPerHost < 1 || c.DurationSeconds < 25 || c.Hosts*c.ChurnPercent/100 < 1) {
		return errors.New("churn needs survivor hosts/guests and at least 25 seconds")
	}
	fanout := int64(1 + c.GuestsPerHost*c.ChannelsPerGuest)
	probes := int64(c.Hosts*c.GuestsPerHost*c.ChannelsPerGuest) * 512 * fanout
	if c.idleHostOnly() {
		probes += int64(1+(c.DurationSeconds-1)/30) * 768
	}
	active := int64(0)
	if c.Active {
		active = int64(c.Hosts*c.GuestsPerHost*c.DurationSeconds) * 128 * fanout
	}
	if c.hostOutputReservation()+probes+active+int64(c.TransferConcurrency)*2*TransferSize > c.PayloadBudgetBytes {
		return errors.New("payload budget cannot cover offered workload")
	}
	seen := map[string]bool{}
	for _, t := range m.Targets {
		if t.AppID == "" || t.MachineID == "" || seen[t.MachineID] || production(t.AppID) || len(t.AllowedIPs) == 0 || len(t.HostKeys) == 0 || len(t.NodeAddresses) == 0 {
			return errors.New("manifest requires isolated, unique machine IDs, IPs, nodes and keys")
		}
		seen[t.MachineID] = true
		for _, ip := range t.AllowedIPs {
			a, err := netip.ParseAddr(ip)
			if err != nil || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() != m.LocalOnly {
				return errors.New("manifest IP violates explicit local-only isolation")
			}
		}
		for _, k := range t.HostKeys {
			key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(k))
			if err != nil || len(rest) != 0 || ssh.FingerprintSHA256(key) == "SHA256:9ajV8JqMe6jJE/s3TYjb/9xw7T0pfJ2+gADiBIJWDPE" {
				return errors.New("invalid or production host key")
			}
		}
		endpoints := map[string][]string{t.SSHURL: {"ssh"}, t.WSURL: {"ws", "wss"}, t.TelemetryURL: {"http"}}
		if t.PublicSSHURL != "" {
			endpoints[t.PublicSSHURL] = []string{"ssh"}
		}
		if t.PublicWSURL != "" {
			endpoints[t.PublicWSURL] = []string{"ws", "wss"}
		}
		for raw, schemes := range endpoints {
			u, err := endpoint(raw, schemes...)
			if err != nil {
				return err
			}
			if a, err := netip.ParseAddr(u.Hostname()); err == nil && !contains(t.AllowedIPs, a.String()) {
				return errors.New("endpoint IP absent from manifest")
			}
			if m.LocalOnly && net.ParseIP(u.Hostname()) == nil {
				return errors.New("local-only endpoints must use literal loopback IPs")
			}
		}
		for _, node := range t.NodeAddresses {
			h, p, err := net.SplitHostPort(node)
			if err != nil || h == "" || p == "" || production(h) {
				return errors.New("invalid/production session node")
			}
			if a, err := netip.ParseAddr(h); err == nil && !contains(t.AllowedIPs, a.String()) {
				return errors.New("session node IP absent from manifest")
			}
		}
	}
	if _, ok := c.target(c.HostTarget); !ok {
		return errors.New("unknown host target")
	}
	if _, ok := c.target(c.EntryTarget); !ok {
		return errors.New("unknown entry target")
	}
	for _, selection := range []struct {
		id     string
		public bool
	}{{c.HostTarget, c.HostPublic}, {c.EntryTarget, c.EntryPublic}} {
		if selection.public {
			t, _ := c.target(selection.id)
			if t.PublicSSHURL == "" || t.PublicWSURL == "" {
				return errors.New("public phase requires explicit public endpoints")
			}
		}
	}
	return nil
}

func (c Config) hostOutputReservation() int64 {
	fanout := int64(1 + c.GuestsPerHost*c.ChannelsPerGuest)
	// Startup has an independent, enforced ramp+30s deadline. Teardown can
	// produce one final tick, reserved here before any helper is started.
	seconds := int64(c.DurationSeconds + 52 + c.Hosts*(1+c.GuestsPerHost)/c.AdmissionsPerSecond)
	output := int64(10) // helper-ready marker
	if c.Active {
		output += (seconds/10 + 1) * 1024
	}
	return int64(c.Hosts) * output * fanout
}
func contains(ss []string, s string) bool {
	for _, v := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func (c Config) idleHostOnly() bool { return c.GuestsPerHost == 0 && !c.Active }
func (c Config) canaryConnection() int {
	if c.idleHostOnly() {
		return 1
	}
	return 0
}
