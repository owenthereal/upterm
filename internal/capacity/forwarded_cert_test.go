package capacity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	consul "github.com/hashicorp/consul/api"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"golang.org/x/crypto/ssh"
)

// Trusting the entry/all manifest keys for a forwarded certificate, or using
// the origin principal for an SSH/embedded/direct guest, breaks these checks.
func TestGuestKeyBindsExactRouteAndPreservesEntryChecks(t *testing.T) {
	c := validConfig(t)
	originKey, entryKey := signer(t), signer(t)
	origin := c.Manifest.Targets[0]
	origin.HostKeys = []string{string(ssh.MarshalAuthorizedKey(originKey.PublicKey()))}
	entry := origin
	entry.MachineID = "entry"
	entry.NodeAddresses, entry.AllowedIPs = []string{"[::1]:2222"}, []string{"::1"}
	entry.HostKeys = []string{string(ssh.MarshalAuthorizedKey(entryKey.PublicKey()))}
	c.Manifest.Targets = []Target{origin, entry}
	g := newGuard(c)
	s := &api.GetSessionResponse{SessionId: "session", SshUser: "session", NodeAddr: "127.0.0.1:2222"}
	newCert := func(key ssh.Signer, principal string, change func(*ssh.Certificate)) *ssh.Certificate {
		cert := &ssh.Certificate{Key: key.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: []string{principal}, ValidBefore: ssh.CertTimeInfinity}
		if change != nil {
			change(cert)
		}
		if err := cert.SignCert(rand.Reader, key); err != nil {
			t.Fatal(err)
		}
		return cert
	}
	check, err := g.guestKey(t.Context(), entry, "ws", s)
	if err != nil {
		t.Fatal(err)
	}
	valid := newCert(originKey, "127.0.0.1", nil)
	if err := check("[::1]:8080", nil, valid); err != nil {
		t.Fatalf("exact origin certificate refused: %v", err)
	}
	if err := check("[::1]:8080", nil, originKey.PublicKey()); err != nil {
		t.Fatalf("exact origin raw pin refused: %v", err)
	}
	corrupt := newCert(originKey, "127.0.0.1", nil)
	corrupt.Signature.Blob[0] ^= 1
	for name, key := range map[string]ssh.PublicKey{
		"wrong origin principal":     newCert(originKey, "::1", nil),
		"another manifest authority": newCert(entryKey, "127.0.0.1", nil),
		"foreign authority":          newCert(signer(t), "127.0.0.1", nil),
		"another manifest raw key":   entryKey.PublicKey(),
		"user certificate":           newCert(originKey, "127.0.0.1", func(c *ssh.Certificate) { c.CertType = ssh.UserCert }),
		"expired":                    newCert(originKey, "127.0.0.1", func(c *ssh.Certificate) { c.ValidBefore = uint64(time.Now().Add(-time.Hour).Unix()) }),
		"future":                     newCert(originKey, "127.0.0.1", func(c *ssh.Certificate) { c.ValidAfter = uint64(time.Now().Add(time.Hour).Unix()) }),
		"invalid signature":          corrupt,
	} {
		t.Run(name, func(t *testing.T) {
			if err := check("[::1]:8080", nil, key); err == nil {
				t.Fatal("invalid forwarded certificate/key accepted")
			}
		})
	}
	for _, tc := range []struct {
		name, transport, addr, principal string
		entry                            Target
		route                            string
		key                              ssh.Signer
	}{
		{"ssh entry", "ssh", "[::1]:2222", "::1", entry, "session", entryKey},
		{"embedded ws entry", "ws", "[::1]:8080", "::1", entry, (&routing.EmbeddedEncodeDecoder{}).Encode("session", s.NodeAddr), entryKey},
		{"direct private", "ws", "127.0.0.1:8080", "127.0.0.1", origin, "session", originKey},
		{"direct public", "wss", "isolated.example:443", "isolated.example", origin, "session", originKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := &api.GetSessionResponse{SessionId: "session", SshUser: tc.route, NodeAddr: "127.0.0.1:2222"}
			check, err := g.guestKey(t.Context(), tc.entry, tc.transport, session)
			if err != nil {
				t.Fatal(err)
			}
			if err := check(tc.addr, nil, newCert(tc.key, tc.principal, nil)); err != nil {
				t.Fatalf("entry endpoint certificate refused: %v", err)
			}
			if err := check(tc.addr, nil, newCert(tc.key, "wrong.example", nil)); err == nil {
				t.Fatal("entry endpoint principal check bypassed")
			}
		})
	}
}

func TestGuestInvalidRouteFailsBeforeAdmission(t *testing.T) {
	c := validConfig(t)
	g := newGuard(c)
	calls := 0
	g.dial = func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("unexpected dial")
	}
	u, err := url.Parse(c.Manifest.Targets[0].SSHURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range []*api.GetSessionResponse{
		nil,
		{SessionId: "session", SshUser: "session", NodeAddr: "[::1]:2222"},
		{SessionId: "session", SshUser: "different", NodeAddr: "127.0.0.1:2222"},
		{SessionId: "session", SshUser: (&routing.EmbeddedEncodeDecoder{}).Encode("session", "[::1]:2222"), NodeAddr: "127.0.0.1:2222"},
	} {
		if _, _, err := openGuest(t.Context(), g, c.Manifest.Targets[0], u, session, signer(t), &tunnelProxy{}); err == nil {
			t.Fatal("unvalidated guest route accepted")
		}
	}
	if calls != 0 || g.peak != 0 || !g.next.IsZero() {
		t.Fatalf("invalid route entered admission: dials=%d peak=%d next=%v", calls, g.peak, g.next)
	}
}

// Distinct loopback principals reproduce a real forwarded certificate: the
// guest dials B, while routing presents A's certificate to the guest.
func TestRealForwardedGuestCertificate(t *testing.T) {
	for _, mode := range []routing.Mode{routing.ModeEmbedded, routing.ModeConsul} {
		t.Run(string(mode), func(t *testing.T) {
			var registry *url.URL
			if mode == routing.ModeConsul {
				registry = forwardedSessionRegistry(t)
			}
			for _, tc := range []struct {
				name string
				h, g int
			}{{"ssh", 0, 0}, {"ws", 100, 100}, {"ssh-to-ws", 0, 100}, {"ws-to-ssh", 100, 0}} {
				t.Run(tc.name, func(t *testing.T) {
					clearProxies(t)
					key := signer(t)
					origin := forwardedRelay(t, "origin", "127.0.0.1", key, mode, registry)
					entry := forwardedRelay(t, "entry", "::1", key, mode, registry)
					c := validConfig(t)
					c.Manifest.Targets = []Target{origin, entry}
					c.HostTarget, c.EntryTarget = "origin", "entry"
					c.HelperExecutable = buildHelper(t)
					c.HostWSPercent, c.GuestWSPercent = tc.h, tc.g
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
							if e := os.WriteFile(filepath.Join(dir, "forwarded-"+string(mode)+"-"+tc.name+"-"+name), data, 0600); e != nil {
								t.Fatal(e)
							}
						}
					}
					if err != nil {
						t.Fatalf("forwarded shell workload: %v\n%s", err, out.String())
					}
					if s.EstablishedHosts != 1 || s.EstablishedGuests != 1 || s.EstablishedChannels != 4 || s.AdmissionFailures != 0 {
						t.Fatalf("forwarded admissions incomplete: %+v", s)
					}
					if !s.DeliveryComplete || !s.CleanupComplete || s.StopReason != "duration" || s.SteadySeconds < 1 || s.ActiveFrames != 1 || s.InputFrames != 5 || s.RTTCount != 5 || s.PayloadBytes == 0 {
						t.Fatalf("forwarded framed delivery/cleanup incomplete: %+v", s)
					}
					nodes := map[string]int{}
					dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
					for {
						var event struct {
							Event string `json:"event"`
							Node  string `json:"node"`
						}
						if err := dec.Decode(&event); err == io.EOF {
							break
						} else if err != nil {
							t.Fatal(err)
						}
						if event.Event == "guest_ready" {
							nodes[event.Node]++
						}
					}
					if !maps.Equal(nodes, map[string]int{origin.NodeAddresses[0]: 1}) {
						t.Fatalf("guest readiness named wrong origin: %v", nodes)
					}
				})
			}
		})
	}
}

func forwardedRelay(t *testing.T, id, ip string, key ssh.Signer, mode routing.Mode, registry *url.URL, options ...func(*server.Server)) Target {
	t.Helper()
	sshln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatalf("required distinct-principal loopback %s unavailable: %v", ip, err)
	}
	t.Cleanup(func() { _ = sshln.Close() })
	wsln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wsln.Close() })
	cert, err := (&server.HostCertSigner{Hostnames: []string{ip}}).SignCert(key)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	network := &server.MemoryProvider{}
	if err := network.SetOpts(nil); err != nil {
		t.Fatal(err)
	}
	sm, err := server.NewSessionManager(mode, server.WithSessionManagerLogger(logger), server.WithSessionManagerConsulURL(registry))
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
			t.Error("forwarded relay leaked")
		}
	})
	metrics := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "test_metric 1\n") }))
	_ = metrics.Listener.Close()
	metrics.Listener, err = net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	metrics.Start()
	t.Cleanup(metrics.Close)
	return Target{AppID: "test-app", MachineID: id, SSHURL: "ssh://" + sshln.Addr().String(), WSURL: "ws://" + wsln.Addr().String(), NodeAddresses: []string{relay.NodeAddr}, AllowedIPs: []string{ip}, HostKeys: []string{string(ssh.MarshalAuthorizedKey(key.PublicKey()))}, TelemetryURL: metrics.URL + "/metrics"}
}

// The registry supplies only the local storage protocol needed for a single
// non-churning session. Certificate exchange, route lookup, shell framing and
// cleanup all run through the real relay and host implementations.
func forwardedSessionRegistry(t *testing.T) *url.URL {
	t.Helper()
	var mu sync.Mutex
	index, leases := uint64(1), 0
	pairs := map[string]*consul.KVPair{}
	changed := make(chan struct{})
	poke := func() { index++; close(changed); changed = make(chan struct{}) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/catalog/register":
			_, _ = io.WriteString(w, "true")
		case r.URL.Path == "/v1/session/create":
			leases++
			_ = json.NewEncoder(w).Encode(map[string]string{"ID": fmt.Sprintf("lease-%d", leases)})
		case strings.HasPrefix(r.URL.Path, "/v1/session/destroy/"):
			lease := strings.TrimPrefix(r.URL.Path, "/v1/session/destroy/")
			for key, pair := range pairs {
				if pair.Session == lease {
					delete(pairs, key)
					poke()
				}
			}
			_, _ = io.WriteString(w, "true")
		case r.URL.Path == "/v1/txn":
			var ops consul.TxnOps
			if err := json.NewDecoder(r.Body).Decode(&ops); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var results consul.TxnResults
			for _, op := range ops {
				kv := op.KV
				switch kv.Verb {
				case consul.KVCheckNotExists, consul.KVCheckIndex, consul.KVCheckSession:
				case consul.KVLock:
					poke()
					pair := &consul.KVPair{Key: kv.Key, Value: kv.Value, Session: kv.Session, ModifyIndex: index}
					pairs[kv.Key] = pair
					results = append(results, &consul.TxnResult{KV: pair})
				case consul.KVDelete:
					delete(pairs, kv.Key)
					poke()
				default:
					t.Errorf("unexpected registry transaction: %s", kv.Verb)
				}
			}
			_ = json.NewEncoder(w).Encode(consul.TxnResponse{Results: results})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/kv/"):
			if wait, _ := strconv.ParseUint(r.URL.Query().Get("index"), 10, 64); wait == index {
				wake := changed
				mu.Unlock()
				select {
				case <-wake:
				case <-r.Context().Done():
				}
				mu.Lock()
			}
			w.Header().Set("X-Consul-Index", strconv.FormatUint(index, 10))
			key := strings.TrimPrefix(r.URL.Path, "/v1/kv/")
			var found consul.KVPairs
			for k, pair := range pairs {
				if k == key || (r.URL.Query().Has("recurse") && strings.HasPrefix(k, key)) {
					found = append(found, pair)
				}
			}
			if len(found) == 0 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(found)
		default:
			t.Errorf("unexpected registry request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
