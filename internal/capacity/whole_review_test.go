package capacity

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestHostTunnelLossClassification(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		established, expected bool
		events                []host.TunnelEvent
		wantFailure           bool
	}{
		{"startup", false, false, []host.TunnelEvent{{CanReconnect: true}, {Up: true}}, false},
		{"unexpected", true, false, []host.TunnelEvent{{CanReconnect: true}, {Up: true}}, true},
		{"permanent loss", true, false, []host.TunnelEvent{{}}, true},
		{"planned recovery", true, true, []host.TunnelEvent{{CanReconnect: true}, {Up: true}}, false},
		{"loss after planned recovery", true, true, []host.TunnelEvent{{CanReconnect: true}, {Up: true}, {CanReconnect: true}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(context.Canceled)
			r := &runState{ctx: ctx, cancel: cancel, rec: newRecorder(io.Discard, Config{})}
			h := &hostRun{established: tc.established, expectedCut: tc.expected, proxy: &tunnelProxy{}, tunnel: make(chan tunnelObservation, 8)}
			for _, e := range tc.events {
				r.hostTunnel(h, e)
			}
			if failed := context.Cause(ctx) != nil; failed != tc.wantFailure {
				t.Fatalf("host loss classification: failed=%v want=%v cause=%v", failed, tc.wantFailure, context.Cause(ctx))
			}
		})
	}
	t.Run("normal teardown", func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(t.Context())
		cancel(context.Canceled)
		r := &runState{ctx: ctx, cancel: func(err error) { t.Errorf("teardown caused run failure: %v", err) }, rec: newRecorder(io.Discard, Config{})}
		h := &hostRun{established: true, tunnel: make(chan tunnelObservation, 1)}
		r.hostTunnel(h, host.TunnelEvent{})
		if !errors.Is(context.Cause(ctx), context.Canceled) {
			t.Fatal("teardown changed cancellation cause")
		}
	})
}

func TestUnexpectedHostDownFailsDespiteImmediateRecovery(t *testing.T) {
	c := localRelay(t)
	c.Active = false
	c.GuestsPerHost = 0
	r := admittedRun(t, c)
	h := r.hosts[0]
	h.h.TunnelCallback(host.TunnelEvent{CanReconnect: true})
	h.h.TunnelCallback(host.TunnelEvent{Up: true})
	if cause := context.Cause(r.ctx); cause == nil || !strings.Contains(cause.Error(), "unexpected host transport loss") {
		t.Fatalf("established idle host loss escaped failure after recovery: %v", cause)
	}
}

func TestRealIdleHostTransportLossFailsBeforeNextCanary(t *testing.T) {
	c := localRelay(t)
	c.Active = false
	c.GuestsPerHost = 0
	r := admittedRun(t, c)
	r.canaries()
	if n, _ := r.hosts[0].proxy.cut(); n != 1 {
		t.Fatalf("test did not sever a real host transport: %d", n)
	}
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	recovered := false
	for {
		select {
		case event := <-r.hosts[0].tunnel:
			recovered = recovered || event.event.Up
		case <-r.ctx.Done():
			if cause := context.Cause(r.ctx); !strings.Contains(cause.Error(), "unexpected host transport loss") {
				t.Fatalf("host loss failed for the wrong reason: %v", cause)
			}
			r.workers.Wait()
			if r.rec.summary.CanaryEstablished != 1 {
				t.Fatal("unexpected loss was only detected by another canary")
			}
			return
		case <-timer.C:
			t.Fatalf("real idle host loss did not fail before the next canary (recovered=%v)", recovered)
		}
	}
}

func TestFaultHelpersDispatchCompleteRepeatedReadinessFrames(t *testing.T) {
	for _, tc := range []struct{ name, input, output string }{
		{"silent", "RRQII", "AABI-"},
		{"late", "RRQIIF", "AABIIB"},
		{"retry", "RRRQIIF", "-AABIIB"},
	} {
		for _, fragmented := range []bool{false, true} {
			name := tc.name + "/whole"
			if fragmented {
				name = tc.name + "/fragmented"
			}
			t.Run(name, func(t *testing.T) {
				var input, want []byte
				for i, kind := range tc.input {
					at := time.Unix(1700000000, int64(i))
					input = append(input, frame(string(kind), 0, i, at, 128)...)
					if tc.output[i] != '-' {
						want = append(want, frame(string(tc.output[i]), 0, i, at, 128)...)
					}
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, faultHelperExecutable(t, tc.name, ""), "helper", "0", "false")
				var output bytes.Buffer
				cmd.Stdout = &output
				cmd.Stderr = &output
				stdin, err := cmd.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err = cmd.Start(); err != nil {
					t.Fatal(err)
				}
				for len(input) > 0 {
					n := len(input)
					if fragmented {
						n = min(n, 11)
					}
					if _, err = stdin.Write(input[:n]); err != nil {
						t.Error(err)
						break
					}
					input = input[n:]
					if fragmented {
						time.Sleep(time.Millisecond)
					}
				}
				_ = stdin.Close()
				if err = cmd.Wait(); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(output.Bytes(), want) {
					t.Fatalf("complete repeated-R admission/fault responses mismatch: got %q, want %q", output.Bytes(), want)
				}
			})
		}
	}
}

func admittedRun(t *testing.T, c Config) *runState {
	t.Helper()
	ctx, cancel := context.WithCancelCause(t.Context())
	dir, err := os.MkdirTemp("", "capacity-review-")
	if err != nil {
		t.Fatal(err)
	}
	r := &runState{cfg: c, ctx: ctx, cancel: cancel, guard: newGuard(c), rec: newRecorder(io.Discard, c), helper: c.HelperExecutable, dir: dir}
	t.Cleanup(func() {
		if err := r.cleanup(); err != nil {
			t.Error(err)
		}
	})
	if err := r.admit(nil); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRunGuestAuthorizationAcrossTransports(t *testing.T) {
	var previousRunKey []byte
	for _, ws := range []int{0, 100} {
		name := "ssh"
		if ws == 100 {
			name = "ws"
		}
		t.Run(name, func(t *testing.T) {
			c := localRelay(t)
			c.Active = false
			c.Hosts = 2
			c.TransferConcurrency = 4
			c.PayloadBudgetBytes = 256 << 20
			c.GuestWSPercent = ws
			r := admittedRun(t, c)
			runKey := r.guests[0].identity.PublicKey().Marshal()
			if bytes.Equal(runKey, previousRunKey) {
				t.Fatal("separate runs reused a guest authorization key")
			}
			previousRunKey = runKey
			// Admission has proved a usable authenticated shell on each host.
			for _, q := range r.guests {
				client, err := sftp.NewClient(q.client)
				if err != nil {
					t.Fatalf("authorized guest SFTP: %v", err)
				}
				path := filepath.Join(q.host.h.CommandDir, "authorized-transfer")
				f, err := client.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				payload := []byte("run-owned transfer\n")
				if _, err = f.Write(payload); err != nil {
					t.Fatal(err)
				}
				if err = f.Close(); err != nil {
					t.Fatal(err)
				}
				f, err = client.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(f)
				_ = f.Close()
				_ = client.Close()
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("authorized transfer mismatch: %q, %v", got, err)
				}
			}
			q := r.guests[0]
			s, err := q.host.session(r.ctx)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(r.ctx, 3*time.Second)
			defer cancel()
			foreign, raw, err := openGuest(ctx, r.guard, q.target, q.endpoint, s, signer(t), q.proxy)
			if raw != nil {
				defer func() { _ = raw.Close() }()
			}
			if err == nil {
				defer func() { _ = foreign.Close() }()
				files, sftpErr := sftp.NewClient(foreign)
				if sftpErr == nil {
					_ = files.Close()
					t.Error("fresh foreign key opened SFTP on a benchmark host")
				}
				t.Fatal("fresh foreign key joined a benchmark session")
			}
			if ctx.Err() != nil {
				t.Fatalf("foreign key was not rejected within the handshake budget: %v", err)
			}
			for _, q := range r.guests {
				if !bytes.Equal(q.identity.PublicKey().Marshal(), r.guests[0].identity.PublicKey().Marshal()) {
					t.Fatal("synthetic guests do not share the run-owned authorization key")
				}
				for _, other := range []ssh.Signer{q.host.h.Signers[0], q.host.h.HostKey} {
					if bytes.Equal(q.identity.PublicKey().Marshal(), other.PublicKey().Marshal()) {
						t.Fatal("guest identity reused a host registration or session key")
					}
				}
				key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(q.target.HostKeys[0]))
				if err != nil || bytes.Equal(q.identity.PublicKey().Marshal(), key.Marshal()) {
					t.Fatal("guest identity reused the relay key")
				}
			}
		})
	}
}
