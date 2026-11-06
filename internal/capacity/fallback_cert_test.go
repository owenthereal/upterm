package capacity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"golang.org/x/crypto/ssh"
)

// Falling back to all manifest pins/principals, or permitting raw entry keys,
// would admit one of the rejected cases below. Each authority stays paired
// with its own principal even when the origin and entry share an authority.
func TestGuestKeyConsulWebSocketFallback(t *testing.T) {
	for _, shared := range []bool{false, true} {
		name := "distinct authorities"
		if shared {
			name = "shared authority"
		}
		t.Run(name, func(t *testing.T) {
			c := validConfig(t)
			originKey, entryKey, thirdKey := signer(t), signer(t), signer(t)
			if shared {
				entryKey = originKey
			}
			origin := c.Manifest.Targets[0]
			origin.HostKeys = []string{string(ssh.MarshalAuthorizedKey(originKey.PublicKey()))}
			entry := origin
			entry.MachineID = "entry"
			entry.SSHURL, entry.WSURL = "ssh://[::1]:2222", "ws://[::1]:8080"
			entry.PublicWSURL = "wss://entry.example:443"
			entry.NodeAddresses, entry.AllowedIPs = []string{"[::1]:2222"}, []string{"::1"}
			entry.HostKeys = []string{string(ssh.MarshalAuthorizedKey(entryKey.PublicKey()))}
			third := origin
			third.MachineID = "third"
			third.NodeAddresses, third.AllowedIPs = []string{"127.0.0.2:2222"}, []string{"127.0.0.2"}
			third.HostKeys = []string{string(ssh.MarshalAuthorizedKey(thirdKey.PublicKey()))}
			c.Manifest.Targets = []Target{origin, entry, third}
			g := newGuard(c)
			s := &api.GetSessionResponse{SessionId: "session", SshUser: "session", NodeAddr: "127.0.0.1:2222"}
			cert := func(authority ssh.Signer, principal string, change func(*ssh.Certificate)) *ssh.Certificate {
				c := &ssh.Certificate{Key: authority.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: []string{principal}, ValidBefore: ssh.CertTimeInfinity}
				if change != nil {
					change(c)
				}
				if err := c.SignCert(rand.Reader, authority); err != nil {
					t.Fatal(err)
				}
				return c
			}
			for _, endpoint := range []struct{ transport, addr, principal string }{
				{"ws", "[::1]:8080", "::1"},
				{"wss", "entry.example:443", "entry.example"},
			} {
				t.Run(endpoint.transport, func(t *testing.T) {
					check, err := g.guestKey(t.Context(), entry, endpoint.transport, s)
					if err != nil {
						t.Fatal(err)
					}
					for name, key := range map[string]ssh.PublicKey{
						"origin certificate": cert(originKey, "127.0.0.1", nil),
						"origin raw pin":     originKey.PublicKey(),
						"entry certificate":  cert(entryKey, endpoint.principal, nil),
					} {
						t.Run(name, func(t *testing.T) {
							if err := check(endpoint.addr, nil, key); err != nil {
								t.Fatalf("authenticated exact route refused: %v", err)
							}
						})
					}
					corrupt := cert(entryKey, endpoint.principal, nil)
					corrupt.Signature.Blob[0] ^= 1
					bad := map[string]ssh.PublicKey{
						"missing entry principal":          cert(entryKey, endpoint.principal, func(c *ssh.Certificate) { c.ValidPrincipals = nil }),
						"missing origin principal":         cert(originKey, "127.0.0.1", func(c *ssh.Certificate) { c.ValidPrincipals = nil }),
						"empty entry principal list":       cert(entryKey, endpoint.principal, func(c *ssh.Certificate) { c.ValidPrincipals = []string{} }),
						"empty origin principal list":      cert(originKey, "127.0.0.1", func(c *ssh.Certificate) { c.ValidPrincipals = []string{} }),
						"entry authority third principal":  cert(entryKey, "127.0.0.2", nil),
						"origin authority third principal": cert(originKey, "127.0.0.2", nil),
						"third authority entry principal":  cert(thirdKey, endpoint.principal, nil),
						"third authority origin principal": cert(thirdKey, "127.0.0.1", nil),
						"third certificate":                cert(thirdKey, "127.0.0.2", nil),
						"third raw key":                    thirdKey.PublicKey(),
						"foreign authority":                cert(signer(t), endpoint.principal, nil),
						"user certificate":                 cert(entryKey, endpoint.principal, func(c *ssh.Certificate) { c.CertType = ssh.UserCert }),
						"expired":                          cert(entryKey, endpoint.principal, func(c *ssh.Certificate) { c.ValidBefore = uint64(time.Now().Add(-time.Hour).Unix()) }),
						"future":                           cert(entryKey, endpoint.principal, func(c *ssh.Certificate) { c.ValidAfter = uint64(time.Now().Add(time.Hour).Unix()) }),
						"invalid signature":                corrupt,
					}
					if !shared {
						bad["entry authority origin principal"] = cert(entryKey, "127.0.0.1", nil)
						bad["origin authority entry principal"] = cert(originKey, endpoint.principal, nil)
						bad["entry raw key"] = entryKey.PublicKey()
					}
					for name, key := range bad {
						t.Run(name, func(t *testing.T) {
							if err := check(endpoint.addr, nil, key); err == nil {
								t.Fatal("invalid fallback certificate/key accepted")
							}
						})
					}
				})
			}
		})
	}
}

// An initially unavailable advertised node forces the real Consul WebSocket
// handler to hand off to the entry's SSH proxy. Restore that TCP path when the
// handler reports the refused dial, before the entry authenticates the guest.
// Removing entry certificate fallback fails the handshake before any shell.
func TestRealConsulWebSocketFallbackCertificate(t *testing.T) {
	clearProxies(t)
	registry := forwardedSessionRegistry(t)
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	node := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	originKey, entryKey := signer(t), signer(t)
	origin := forwardedRelay(t, "origin", "127.0.0.1", originKey, routing.ModeConsul, registry, func(s *server.Server) {
		s.NodeAddr = node
		s.HopTrusted = []ssh.PublicKey{entryKey.PublicKey()}
	})
	var fallback atomic.Int32
	var once sync.Once
	entry := forwardedRelay(t, "entry", "::1", entryKey, routing.ModeConsul, registry, func(s *server.Server) {
		s.NodeTrusted = []ssh.PublicKey{originKey.PublicKey()}
		s.Logger = slog.New(&fallbackLogHandler{Handler: slog.NewTextHandler(io.Discard, nil), record: func(r slog.Record) {
			if r.Message == "error dialing the session's node" {
				fallback.Add(1)
				once.Do(func() { restoreFallbackNode(t, node, strings.TrimPrefix(origin.SSHURL, "ssh://")) })
			}
		}})
	})
	c := validConfig(t)
	c.Manifest.Targets = []Target{origin, entry}
	c.HostTarget, c.EntryTarget = "origin", "entry"
	c.HelperExecutable = buildHelper(t)
	c.GuestWSPercent = 100
	c.Active, c.DurationSeconds, c.ChannelsPerGuest = true, 1, 4
	var out bytes.Buffer
	s, err := Run(t.Context(), c, &out)
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
			if e := os.WriteFile(filepath.Join(dir, "fallback-"+name), data, 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
	if fallback.Load() != 1 {
		t.Fatalf("expected exactly one real TCP dial failure and handoff, got %d", fallback.Load())
	}
	if err != nil {
		t.Fatalf("fallback shell workload: %v\n%s", err, out.String())
	}
	if s.EstablishedHosts != 1 || s.EstablishedGuests != 1 || s.EstablishedChannels != 4 || s.AdmissionFailures != 0 {
		t.Fatalf("fallback admissions incomplete: %+v", s)
	}
	if !s.DeliveryComplete || !s.CleanupComplete || s.StopReason != "duration" || s.SteadySeconds < 1 || s.ActiveFrames != 1 || s.InputFrames != 5 || s.RTTCount != 5 || s.PayloadBytes == 0 {
		t.Fatalf("fallback framed delivery/cleanup incomplete: %+v", s)
	}
}

type fallbackLogHandler struct {
	slog.Handler
	record func(slog.Record)
}

func (h *fallbackLogHandler) Handle(ctx context.Context, r slog.Record) error {
	h.record(r)
	return h.Handler.Handle(ctx, r)
}
func (h *fallbackLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &fallbackLogHandler{Handler: h.Handler.WithAttrs(attrs), record: h.record}
}
func (h *fallbackLogHandler) WithGroup(name string) slog.Handler {
	return &fallbackLogHandler{Handler: h.Handler.WithGroup(name), record: h.record}
}

func restoreFallbackNode(t *testing.T, node, upstream string) {
	t.Helper()
	ln, err := net.Listen("tcp", node)
	if err != nil {
		t.Errorf("restore origin TCP listener: %v", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			down, err := ln.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer down.Close()
				stopDown := context.AfterFunc(ctx, func() { _ = down.Close() })
				defer stopDown()
				up, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", upstream)
				if err != nil {
					t.Errorf("restored origin dial: %v", err)
					return
				}
				defer up.Close()
				stopUp := context.AfterFunc(ctx, func() { _ = up.Close() })
				defer stopUp()
				done := make(chan struct{})
				go func() {
					defer close(done)
					_, _ = io.Copy(up, down)
					_ = up.Close()
				}()
				_, _ = io.Copy(down, up)
				_ = down.Close()
				<-done
			})
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		workers.Wait()
	})
}
