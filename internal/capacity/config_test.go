package capacity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validConfig(t *testing.T) Config {
	t.Helper()
	return Config{Manifest: Manifest{RunID: "test-run", ExpiresAt: time.Now().Add(time.Hour), LocalOnly: true,
		Targets: []Target{{AppID: "test-app", MachineID: "test-machine", SSHURL: "ssh://127.0.0.1:2222", WSURL: "ws://127.0.0.1:8080", NodeAddresses: []string{"127.0.0.1:2222"}, AllowedIPs: []string{"127.0.0.1"}, HostKeys: []string{string(ssh.MarshalAuthorizedKey(signer(t).PublicKey()))}, TelemetryURL: "http://127.0.0.1:9091/metrics"}}},
		Hosts: 1, GuestsPerHost: 1, HostTarget: "test-machine", EntryTarget: "test-machine", ChannelsPerGuest: 1, DurationSeconds: 2, AdmissionsPerSecond: 20, PayloadBudgetBytes: 1 << 20}
}

func clearProxies(t *testing.T) {
	t.Helper()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(k, "")
	}
}

// Removing any bound or manifest check must allow one of these forbidden runs.
func TestInvalidConfigurationRefusesRun(t *testing.T) {
	clearProxies(t)
	tests := []struct {
		name   string
		change func(*Config)
	}{
		{"absent manifest", func(c *Config) { c.Manifest = Manifest{} }},
		{"expired", func(c *Config) { c.Manifest.ExpiresAt = time.Now().Add(-time.Second) }},
		{"production", func(c *Config) { c.Manifest.Targets[0].SSHURL = "ssh://uptermd.upterm.dev:22" }},
		{"production app", func(c *Config) { c.Manifest.Targets[0].AppID = "upterm" }},
		{"local escape", func(c *Config) { c.Manifest.Targets[0].AllowedIPs = []string{"8.8.8.8"} }},
		{"zero hosts", func(c *Config) { c.Hosts = 0 }},
		{"negative guests", func(c *Config) { c.GuestsPerHost = -1 }},
		{"overflow counts", func(c *Config) { c.Hosts = int(^uint(0) >> 1); c.GuestsPerHost = 100 }},
		{"connections", func(c *Config) { c.Hosts = 500; c.GuestsPerHost = 1 }},
		{"rate", func(c *Config) { c.AdmissionsPerSecond = 21 }},
		{"zero rate", func(c *Config) { c.AdmissionsPerSecond = 0 }},
		{"duration", func(c *Config) { c.DurationSeconds = 86401 }},
		{"bytes", func(c *Config) { c.PayloadBudgetBytes = 50*(1<<30) + 1 }},
		{"channels", func(c *Config) { c.ChannelsPerGuest = 5 }},
		{"transport", func(c *Config) { c.GuestWSPercent = 101 }},
		{"unknown target", func(c *Config) { c.EntryTarget = "other" }},
		{"transfer", func(c *Config) { c.TransferConcurrency = 5 }},
		{"churn", func(c *Config) { c.ChurnPercent = 99 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig(t)
			tt.change(&cfg)
			if _, err := Run(context.Background(), cfg, io.Discard); err == nil {
				t.Fatal("unsafe configuration started successfully")
			}
		})
	}
}

func TestProxyEnvironmentRefused(t *testing.T) {
	clearProxies(t)
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, "socks5://127.0.0.1:9")
			if err := validConfig(t).Validate(time.Now()); err == nil {
				t.Fatal("implicit proxy accepted")
			}
		})
	}
}

func TestDecodeRequiresBothExplicitInputs(t *testing.T) {
	for _, input := range []struct{ m, p io.Reader }{{nil, strings.NewReader("{}")}, {strings.NewReader("{}"), nil}, {strings.NewReader("{}"), strings.NewReader(`{"unrecognized":true}`)}} {
		if _, err := Decode(input.m, input.p); err == nil {
			t.Fatal("missing or unknown configuration accepted")
		}
	}
}
