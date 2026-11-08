package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// pendingHostHop is one gate hop of a hopGateFixture's home, served by
// serveHopGate over loopback TCP, whose connection to the host is held at its
// dial until release. The hop's global requests reach the gate through an
// unbuffered channel, handed, and taken names each one once the gate has
// received it, so a test knows what the gate holds without waiting on time.
// A test can also send handed requests of its own, and end the hop's context
// with cancel.
type pendingHostHop struct {
	ingress *upstreamConn
	taken   <-chan string
	dialing <-chan struct{}
	release func()
	cancel  context.CancelFunc
	done    <-chan error
	handed  chan<- *ssh.Request
}

// pendingHostStage is the hop's upstream stage: long enough that no timeout
// ends a hop while a test holds its host's dial.
const pendingHostStage = 30 * time.Second

func servePendingHostHop(t *testing.T, f *hopGateFixture, host string) *pendingHostHop {
	t.Helper()
	dialing, released := make(chan struct{}), make(chan struct{})
	f.proxy.mux.Lock()
	auth := *f.proxy.routing.Auth
	f.proxy.mux.Unlock()
	auth.ConnDialer = &routeDialer{routes: map[string]func(context.Context) (net.Conn, error){"home:2222": func(ctx context.Context) (net.Conn, error) {
		close(dialing)
		select {
		case <-released:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", host)
	}}}
	routing := &SSHRouting{HostSigners: []ssh.Signer{f.signer}, Auth: &auth, Logger: f.proxy.Logger, MetricsProvider: provider.NewDiscardProvider()}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return &ssh.Permissions{}, nil }}
	cfg.AddHostKey(f.signer)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	taken := make(chan string, 4*maxSSHQueuedRequests)
	done := make(chan error, 1)
	// handed is closed, ending the gate's source, once the mux's requests have
	// all been relayed and the test sends no more: when the test ends.
	handed, relayed, stop := make(chan *ssh.Request), make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		close(stop)
		select {
		case <-relayed:
			close(handed)
		case <-time.After(5 * time.Second):
			t.Error("the mux's requests never ended")
		}
	})
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = raw.Close() }()
		conn, channels, requests, err := ssh.NewServerConn(raw, cfg)
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		go func() {
			defer close(relayed)
			for r := range requests {
				select {
				case handed <- r:
					taken <- r.Type
				case <-stop:
					// Drain until the mux closes, so that it is never left
					// blocked delivering a request.
					for range requests {
					}
					return
				}
			}
		}()
		err = routing.serveHopGate(ctx, sshPeer{conn, channels, handed}, f.auth, f.guest.PublicKey(), pendingHostStage, newSSHRoutingInstruments(provider.NewDiscardProvider()))
		cancel()
		done <- err
	}()

	cert, err := (&UserCertSigner{SessionID: "ingress-cert-id", User: "route", AuthRequest: f.auth}).SignCert(f.authority)
	require.NoError(t, err)
	raw, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	require.NoError(t, err)
	conn, channels, requests, err := ssh.NewClientConn(raw, ln.Addr().String(), &ssh.ClientConfig{User: "route", Auth: []ssh.AuthMethod{ssh.PublicKeys(cert)}, HostKeyCallback: ssh.FixedHostKey(f.signer.PublicKey())})
	require.NoError(t, err)
	u := &upstreamConn{sshPeer: sshPeer{conn, channels, requests}, raw: raw, homeNode: "home:2222"}
	t.Cleanup(u.Close)
	home, err := negotiateHome(t.Context(), u, freshModeRequest("route"))
	require.NoError(t, err)
	require.Equal(t, AuthorityLocal, home.Ref().Authority)
	select {
	case name := <-taken:
		require.Equal(t, "gate-mode@upterm.dev", name)
	case <-time.After(5 * time.Second):
		t.Fatal("the gate never took the mode request")
	}
	select {
	case <-dialing:
	case <-time.After(5 * time.Second):
		t.Fatal("the home never dialed its host")
	}
	var once sync.Once
	return &pendingHostHop{ingress: u, taken: taken, dialing: dialing, cancel: cancel, done: done, handed: handed, release: func() { once.Do(func() { close(released) }) }}
}

// requireTaken requires the gate to take n more requests.
func (h *pendingHostHop) requireTaken(t *testing.T, n int) {
	t.Helper()
	for i := range n {
		select {
		case <-h.taken:
		case <-time.After(5 * time.Second):
			t.Fatalf("the gate took only %d of %d requests", i, n)
		}
	}
}

// requireReceived requires the gate to receive n more requests of the test's
// own, each within a bound, as it must for as long as their source is open.
func (h *pendingHostHop) requireReceived(t *testing.T, n int) {
	t.Helper()
	for i := range n {
		select {
		case h.handed <- &ssh.Request{Type: fmt.Sprintf("after-close-%d@upterm.test", i)}:
		case <-time.After(5 * time.Second):
			t.Fatalf("the gate stopped receiving its source's requests after %d of %d", i, n)
		}
	}
}

// requireClosed requires the hop to close.
func (h *pendingHostHop) requireClosed(t *testing.T, why string) {
	t.Helper()
	closed := make(chan struct{})
	go func() { _ = h.ingress.conn.Wait(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal(why)
	}
	select {
	case err := <-h.done:
		require.Error(t, err, "the gate ended a closed hop without an error")
	case <-time.After(5 * time.Second):
		t.Fatal("the gate never returned")
	}
}

// recordingGateHost is gateEchoHost that also names, in order, each global
// request a relay sends it.
func recordingGateHost(t *testing.T, signer ssh.Signer) (string, <-chan string) {
	t.Helper()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if _, _, err := (&UserCertChecker{IsUserAuthority: func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), signer.PublicKey().Marshal()) }}).Authenticate(meta.User(), key); err != nil {
			return nil, err
		}
		return &ssh.Permissions{}, nil
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan string, 4*maxSSHQueuedRequests)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = raw.Close() }()
				conn, channels, requests, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				go func() {
					for r := range requests {
						got <- r.Type
						_ = r.Reply(true, r.Payload)
					}
				}()
				for incoming := range channels {
					channel, requests, err := incoming.Accept()
					if err != nil {
						continue
					}
					go ssh.DiscardRequests(requests)
					go func() { defer func() { _ = channel.Close() }(); _, _ = io.Copy(channel, channel) }()
				}
			}()
		}
	}()
	return ln.Addr().String(), got
}

// A guest's ordinary global requests that arrive at a gate hop while its
// home is still connecting to the host are held, as they are on any other
// hop, and reach the host in order once it is connected.
func TestGateHopQueuesRequestsWhileTheHostConnects(t *testing.T) {
	for _, n := range []int{3, maxSSHQueuedRequests} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			f := newHopGateFixture(t)
			host, got := recordingGateHost(t, f.signer)
			h := servePendingHostHop(t, f, host)
			for i := range n - 1 {
				_, _, err := h.ingress.conn.SendRequest(fmt.Sprintf("ordinary-%d@upterm.test", i), false, nil)
				require.NoError(t, err)
			}
			last := fmt.Sprintf("ordinary-%d@upterm.test", n-1)
			type reply struct {
				ok      bool
				payload []byte
				err     error
			}
			replied := make(chan reply, 1)
			go func() {
				ok, payload, err := h.ingress.conn.SendRequest(last, true, []byte("answered"))
				replied <- reply{ok, payload, err}
			}()
			// The gate holds every request before the host is connected.
			h.requireTaken(t, n)
			h.release()
			select {
			case r := <-replied:
				require.NoError(t, r.err, "the hop closed on the guest's requests")
				require.True(t, r.ok)
				require.Equal(t, "answered", string(r.payload))
			case <-time.After(5 * time.Second):
				t.Fatal("the host never answered")
			}
			// The host answered the last request, so it got every one before it.
			for i := range n {
				select {
				case name := <-got:
					require.Equal(t, fmt.Sprintf("ordinary-%d@upterm.test", i), name)
				case <-time.After(5 * time.Second):
					t.Fatalf("the host got %d of %d requests", i, n)
				}
			}
			requireEcho(t, h.ingress.conn, "still joined")
		})
	}
}

// A flood of global requests beyond what any hop holds closes a gate hop, as
// it closes any other, whether by count or by bytes.
func TestGateHopRefusesARequestFlood(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 200*1024)
	for _, tc := range []struct {
		name    string
		n       int
		payload []byte
	}{
		{name: "count", n: maxSSHQueuedRequests + 1},
		// Six of them pass maxSSHQueuedRequestBytes; five don't.
		{name: "bytes", n: maxSSHQueuedRequestBytes/len(payload) + 1, payload: payload},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newHopGateFixture(t)
			host, got := recordingGateHost(t, f.signer)
			h := servePendingHostHop(t, f, host)
			defer h.release()
			for i := range tc.n {
				_, _, err := h.ingress.conn.SendRequest(fmt.Sprintf("flood-%d@upterm.test", i), false, tc.payload)
				require.NoError(t, err)
			}
			// The gate takes every request up to the bound, and the one past it.
			h.requireTaken(t, tc.n)
			h.requireClosed(t, "the hop held a flood beyond the bound")
			select {
			case name := <-got:
				t.Fatalf("the host got %s", name)
			default:
			}
		})
	}
}

// A gate hop that closes keeps receiving the guest's requests, discarding
// them, until its connection ends, as any hop's forwarder does once
// cancelled: a mux left blocked delivering one never sees its transport
// close. That holds however the hop closes: on a flood, on a gate request it
// refuses, or when its context ends.
func TestClosedGateHopKeepsReceivingRequests(t *testing.T) {
	// More than the mux buffers, so that a gate that stopped receiving would
	// leave the mux blocked.
	const after = 2 * 16
	for _, tc := range []struct {
		name  string
		close func(t *testing.T, h *pendingHostHop)
	}{
		{name: "flood", close: func(t *testing.T, h *pendingHostHop) {
			for i := range maxSSHQueuedRequests + 1 {
				_, _, err := h.ingress.conn.SendRequest(fmt.Sprintf("flood-%d@upterm.test", i), false, nil)
				require.NoError(t, err)
			}
			h.requireTaken(t, maxSSHQueuedRequests+1)
		}},
		{name: "refused_gate_request", close: func(t *testing.T, h *pendingHostHop) {
			// A second mode request: the gate refuses it and closes the hop.
			go func() { _, _, _ = h.ingress.conn.SendRequest(upterm.GateModeRequestType, true, nil) }()
			h.requireTaken(t, 1)
		}},
		{name: "context_ends", close: func(t *testing.T, h *pendingHostHop) { h.cancel() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newHopGateFixture(t)
			host, _ := recordingGateHost(t, f.signer)
			h := servePendingHostHop(t, f, host)
			defer h.release()
			tc.close(t, h)
			h.requireClosed(t, "the hop didn't close")
			h.requireReceived(t, after)
		})
	}
}
