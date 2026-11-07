package capacity

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"testing"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/server"
	"golang.org/x/crypto/ssh"
)

func TestGuardInvalidDestinationNeverDials(t *testing.T) {
	c := validConfig(t)
	g := newGuard(c)
	calls := 0
	g.dial = func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("dial attempted")
	}
	if _, err := g.connect(t.Context(), c.Manifest.Targets[0], "uptermd.upterm.dev:22"); err == nil {
		t.Fatal("escaped endpoint accepted")
	}
	if calls != 0 {
		t.Fatalf("invalid endpoint caused %d dials", calls)
	}
}

func TestGuardDNSRebindingNeverDials(t *testing.T) {
	c := validConfig(t)
	c.Manifest.LocalOnly = false
	c.Manifest.Targets[0].SSHURL = "ssh://isolated.internal:2222"
	c.Manifest.Targets[0].AllowedIPs = []string{"fdaa::1"}
	g := newGuard(c)
	calls := 0
	g.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("fdaa::1")}, {IP: net.ParseIP("8.8.8.8")}}, nil
	}
	g.dial = func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("dial attempted")
	}
	if _, err := g.connect(t.Context(), c.Manifest.Targets[0], "isolated.internal:2222"); err == nil {
		t.Fatal("unapproved DNS response accepted")
	}
	if calls != 0 {
		t.Fatalf("DNS escape caused %d dials", calls)
	}
}

func TestGuardSessionNodeEscape(t *testing.T) {
	g := newGuard(validConfig(t))
	for _, s := range []*api.GetSessionResponse{
		{SessionId: "session", SshUser: "session", NodeAddr: "uptermd.upterm.dev:22"},
		{SessionId: "session", SshUser: "session:" + base64.URLEncoding.EncodeToString([]byte("8.8.8.8:22")), NodeAddr: "127.0.0.1:2222"},
		{SessionId: "session", SshUser: "different", NodeAddr: "127.0.0.1:2222"},
	} {
		if err := g.session(t.Context(), s); err == nil {
			t.Fatal("session route escape accepted")
		}
	}
}
func TestPinnedKeysRejectForeignCertificatesAndPrincipals(t *testing.T) {
	c := validConfig(t)
	key := signer(t)
	c.Manifest.Targets[0].HostKeys = []string{string(ssh.MarshalAuthorizedKey(key.PublicKey()))}
	check := pinnedKey(c.Manifest.Targets[0])
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
	if err := check("127.0.0.1:22", addr, key.PublicKey()); err != nil {
		t.Fatal(err)
	}
	foreign := signer(t)
	if err := check("127.0.0.1:22", addr, foreign.PublicKey()); err == nil {
		t.Fatal("foreign relay key accepted")
	}
	for _, principal := range []string{"127.0.0.1", "another.internal"} {
		cert, err := (&server.HostCertSigner{Hostnames: []string{principal}}).SignCert(key)
		if err != nil {
			t.Fatal(err)
		}
		err = check("127.0.0.1:22", addr, cert.PublicKey())
		if (err == nil) != (principal == "127.0.0.1") {
			t.Fatalf("certificate principal %s: %v", principal, err)
		}
	}
}
func TestExternalPeakIncludesTransientConnections(t *testing.T) {
	c := validConfig(t)
	g := newGuard(c)
	g.dial = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		return client, nil
	}
	first, err := g.connect(t.Context(), c.Manifest.Targets[0], "127.0.0.1:2222")
	if err != nil {
		t.Fatal(err)
	}
	second, err := g.connect(t.Context(), c.Manifest.Targets[0], "127.0.0.1:2222")
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	_ = second.Close()
	if g.active != 0 || g.peak != 2 {
		t.Fatalf("transient external connections missing from peak: active=%d peak=%d", g.active, g.peak)
	}
}
