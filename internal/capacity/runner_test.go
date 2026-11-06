package capacity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"golang.org/x/crypto/ssh"
)

var helperDir string

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "helper" {
		os.Exit(runFaultHelperProcess())
	}
	var err error
	helperDir, err = os.MkdirTemp("", "capacity-test-")
	if err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(helperDir)
	os.Exit(code)
}

var helperOnce sync.Once
var helperBinary string
var helperError error

func buildHelper(t *testing.T) string {
	t.Helper()
	helperOnce.Do(func() {
		name := "capacity"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		helperBinary = filepath.Join(helperDir, name)
		cmd := exec.Command("go", "build", "-o", helperBinary, "./cmd")
		if out, err := cmd.CombinedOutput(); err != nil {
			helperError = fmt.Errorf("helper build: %w: %s", err, out)
		}
	})
	if helperError != nil {
		t.Fatal(helperError)
	}
	return helperBinary
}
func localRelay(t *testing.T, options ...func(*server.Server)) Config {
	t.Helper()
	clearProxies(t)
	sshln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wsln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	key := signer(t)
	cert, err := (&server.HostCertSigner{Hostnames: []string{"127.0.0.1"}}).SignCert(key)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	network := &server.MemoryProvider{}
	if err = network.SetOpts(nil); err != nil {
		t.Fatal(err)
	}
	sm, err := server.NewSessionManager(routing.ModeEmbedded, server.WithSessionManagerLogger(logger))
	if err != nil {
		t.Fatal(err)
	}
	relay := &server.Server{NodeAddr: sshln.Addr().String(), HostSigners: []ssh.Signer{cert}, Signers: []ssh.Signer{key}, NetworkProvider: network, SessionManager: sm, MetricsProvider: provider.NewDiscardProvider(), Logger: logger}
	for _, option := range options {
		option(relay)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- relay.ServeListeners(ctx, server.Listeners{SSH: sshln, WS: wsln}) }()
	t.Cleanup(func() {
		cancel()
		_ = relay.Shutdown()
		select {
		case err := <-done:
			_ = err // Shutdown owns the expected serving error.
		case <-time.After(10 * time.Second):
			t.Error("relay leaked")
		}
	})
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "test_metric 1\n") }))
	t.Cleanup(metrics.Close)
	c := validConfig(t)
	c.HelperExecutable = buildHelper(t)
	c.Manifest.Targets[0].SSHURL = "ssh://" + sshln.Addr().String()
	c.Manifest.Targets[0].WSURL = "ws://" + wsln.Addr().String()
	c.Manifest.Targets[0].NodeAddresses = []string{sshln.Addr().String()}
	c.Manifest.Targets[0].HostKeys = []string{string(ssh.MarshalAuthorizedKey(key.PublicKey()))}
	c.Manifest.Targets[0].TelemetryURL = metrics.URL + "/metrics"
	c.Active = true
	return c
}
func TestRealSessionsAcrossTransports(t *testing.T) {
	for _, mix := range []struct {
		name string
		h, g int
	}{{"ssh", 0, 0}, {"ws", 100, 100}, {"ssh-to-ws", 0, 100}, {"ws-to-ssh", 100, 0}} {
		t.Run(mix.name, func(t *testing.T) {
			c := localRelay(t)
			c.HostWSPercent = mix.h
			c.GuestWSPercent = mix.g
			c.ChannelsPerGuest = 4
			c.DurationSeconds = 3
			var out bytes.Buffer
			s, err := Run(t.Context(), c, &out)
			if err != nil {
				t.Fatalf("Run: %v\n%s", err, out.String())
			}
			if s.EstablishedHosts != 1 || s.EstablishedGuests != 1 || s.EstablishedChannels != 4 {
				t.Fatalf("real readiness not counted: %+v", s)
			}
			if s.RTTCount < 4 || s.ReceivedFrames < 4 || s.PayloadBytes == 0 {
				t.Fatalf("usable terminal traffic missing: %+v", s)
			}
			if s.SteadySeconds < 3 || s.InputFrames != 7 {
				t.Fatalf("offered workload or hold was shortened: %+v", s)
			}
			if s.StopReason != "duration" {
				t.Fatalf("unexpected stop: %+v", s)
			}
		})
	}
}
func TestFailedReadinessNeverCountsEstablished(t *testing.T) {
	c := localRelay(t)
	c.HelperExecutable = "/does/not/exist"
	s, err := Run(t.Context(), c, io.Discard)
	if err == nil {
		t.Fatal("failed helper readiness reported success")
	}
	if s.EstablishedHosts != 0 || s.EstablishedGuests != 0 {
		t.Fatalf("failed readiness counted: %+v", s)
	}
}

func TestRealSFTPTransfersHaveVerifiedBytes(t *testing.T) {
	c := localRelay(t)
	c.Active = false
	c.DurationSeconds = 6
	c.TransferConcurrency = 4
	c.PayloadBudgetBytes = 256 << 20
	var out bytes.Buffer
	s, err := Run(t.Context(), c, &out)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, out.String())
	}
	if s.Transfers != 4 || s.TransferBytes != 134217728 {
		t.Fatalf("four verified upload/download pairs missing: %+v", s)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"sha256"`)) {
		t.Fatal("transfer hashes absent from evidence")
	}
}
func TestRunCancellationJoinsOwnedWork(t *testing.T) {
	c := localRelay(t)
	c.DurationSeconds = 120
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(500*time.Millisecond, cancel)
	start := time.Now()
	s, err := Run(ctx, c, io.Discard)
	if err == nil || s.StopReason == "duration" {
		t.Fatalf("cancel was reported successful: %+v %v", s, err)
	}
	if !s.CleanupComplete {
		t.Fatal("cancellation did not verify temporary directory cleanup")
	}
	if time.Since(start) > 8*time.Second {
		t.Fatal("owned work did not join promptly")
	}
}
func TestInvalidLimitsNeverStartHostTransport(t *testing.T) {
	clearProxies(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	calls := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			select {
			case calls <- struct{}{}:
			default:
			}
			_ = c.Close()
		}
	}()
	c := validConfig(t)
	c.Manifest.Targets[0].SSHURL = "ssh://" + ln.Addr().String()
	c.AdmissionsPerSecond = 21
	if _, err := Run(t.Context(), c, io.Discard); err == nil {
		t.Fatal("invalid rate admitted host")
	}
	_ = ln.Close()
	<-done
	select {
	case <-calls:
		t.Fatal("invalid limits started a host transport")
	default:
	}
}

func TestSuppliedHostIdentityAuthenticatesRestrictedRelay(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "capacity-test")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "identity")
	authorized := filepath.Join(dir, "authorized_keys")
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(authorized, ssh.MarshalAuthorizedKey(identity.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	c := localRelay(t, func(s *server.Server) { s.AuthorizedKeysFiles = []string{authorized} })
	c.HostIdentityFile = keyFile
	c.DurationSeconds = 1
	var out bytes.Buffer
	s, err := Run(t.Context(), c, &out)
	if err != nil {
		t.Fatalf("restricted relay: %v", err)
	}
	if s.EstablishedHosts != 1 || !s.CleanupComplete {
		t.Fatalf("identity/cleanup missing: %+v", s)
	}
	if bytes.Contains(out.Bytes(), []byte(keyFile)) || bytes.Contains(out.Bytes(), []byte("BEGIN OPENSSH PRIVATE KEY")) {
		t.Fatal("private identity leaked into events")
	}
}
func TestIdleHostOnlyPhaseProvesSparseGuestCanary(t *testing.T) {
	c := localRelay(t)
	c.Hosts = 2
	c.GuestsPerHost = 0
	c.Active = false
	c.DurationSeconds = 1
	var out bytes.Buffer
	s, err := Run(t.Context(), c, &out)
	if err != nil {
		t.Fatalf("host-only: %v\n%s", err, out.String())
	}
	if s.OfferedGuests != 0 || s.EstablishedGuests != 0 {
		t.Fatalf("transient canary changed nominal guests: %+v", s)
	}
	if s.CanaryOffered != 1 || s.CanaryEstablished != 1 || s.CanaryReadyMillis <= 0 {
		t.Fatalf("host-only usability was not proved: %+v", s)
	}
	if !s.CleanupComplete {
		t.Fatal("canary transport cleanup failed")
	}
}
func TestIdleCanariesReuseOneSlotAndRotateHosts(t *testing.T) {
	c := localRelay(t)
	c.Hosts = 2
	c.GuestsPerHost = 0
	c.Active = false
	ctx, cancel := context.WithCancelCause(t.Context())
	dir, err := os.MkdirTemp("", "capacity-canary-")
	if err != nil {
		t.Fatal(err)
	}
	r := &runState{cfg: c, ctx: ctx, cancel: cancel, guard: newGuard(c), rec: newRecorder(io.Discard, c), helper: c.HelperExecutable, dir: dir}
	defer func() {
		if err := r.cleanup(); err != nil {
			t.Error(err)
		}
	}()
	if err = r.admit(nil); err != nil {
		t.Fatal(err)
	}
	if err = r.hostCanary(1); err != nil {
		t.Fatal(err)
	}
	if len(r.guests) != 1 || r.canary.host.id != 1 || r.rec.summary.CanaryEstablished != 2 || r.rec.summary.CanaryRTTCount != 2 {
		t.Fatalf("canaries did not rotate within one slot: guests=%d summary=%+v", len(r.guests), r.rec.summary)
	}
	r.guard.mu.Lock()
	active := r.guard.active
	r.guard.mu.Unlock()
	if active != 2 {
		t.Fatalf("transient canary transport leaked: active=%d want two hosts", active)
	}
}
