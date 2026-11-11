package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/host/api"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Hold only the final downstream request, after the host has already sent it.
// This exposes the stock forwarder's buffered-tail drain without relying on
// scheduling or changing production timers. Transport closure releases it too.
type heldExitChannel struct {
	ssh.Channel
	entered               chan struct{}
	release, disconnected <-chan struct{}
}

type retirementDialer struct {
	addr             string
	entered, release chan struct{}
}

func (d *retirementDialer) Dial(id *api.Identifier) (net.Conn, error) {
	return d.DialContext(context.Background(), id)
}

func (d *retirementDialer) DialContext(ctx context.Context, _ *api.Identifier) (net.Conn, error) {
	close(d.entered)
	select {
	case <-d.release:
		return (&net.Dialer{}).DialContext(ctx, "tcp", d.addr)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestHopGateLocalRetirementDuringDial(t *testing.T) {
	for _, release := range []bool{true, false} {
		name := "bounded_stalled_dial"
		if release {
			name = "completed_dial_still_refuses"
		}
		t.Run(name, func(t *testing.T) {
			dialer := &retirementDialer{entered: make(chan struct{}), release: make(chan struct{})}
			f := newHopGateFixture(t, func(p *sshProxy) { p.ConnDialer = dialer })
			dialer.addr = f.dialer.addr
			u, err := f.connect(t, f.auth, f.authority)
			require.NoError(t, err)
			_, err = negotiateHome(t.Context(), u, freshModeRequest("route"))
			require.NoError(t, err)
			select {
			case <-dialer.entered:
			case <-time.After(time.Second):
				t.Fatal("host dial was not reached")
			}
			f.home.retire()
			if release {
				close(dialer.release)
			}
			result := make(chan bool, 1)
			go func() { ok, _, _ := u.conn.SendRequest("application-probe", true, nil); result <- ok }()
			select {
			case ok := <-result:
				require.False(t, ok, "retired home forwarded guest application work")
			case <-time.After(3 * time.Second):
				t.Fatal("retired local host dial exceeded original stage")
			}
			if release {
				// The completed dial finds the home retired and closes the hop.
				requireHopClosed(t, u, "retired home kept the hop open")
				return
			}
			_, _, err = u.conn.OpenChannel("session", nil)
			require.Error(t, err, "retired home admitted a guest channel")
		})
	}
}

func (c heldExitChannel) SendRequest(name string, reply bool, body []byte) (bool, error) {
	if name == "exit-status" {
		close(c.entered)
		select {
		case <-c.release:
		case <-c.disconnected:
			return false, io.EOF
		}
	}
	return c.Channel.SendRequest(name, reply, body)
}

type heldExitOpen struct {
	ssh.NewChannel
	entered               chan struct{}
	release, disconnected <-chan struct{}
}

func (c heldExitOpen) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	ch, requests, err := c.NewChannel.Accept()
	return heldExitChannel{ch, c.entered, c.release, c.disconnected}, requests, err
}

func TestHopGateRetirementPreservesLocalExitTail(t *testing.T) {
	for _, tc := range []struct {
		authority SessionAuthority
		stalled   bool
	}{{AuthorityLocal, false}, {AuthorityDelegated, false}, {AuthorityLocal, true}} {
		stalled := tc.stalled
		name := string(tc.authority)
		if stalled {
			name += "_stalled"
		}
		t.Run(name, func(t *testing.T) {
			f := newHopGateFixture(t)
			if tc.authority == AuthorityDelegated {
				f.delegatedHome(t)
			}
			hostListener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer func() { _ = hostListener.Close() }()
			f.dialer.addr = hostListener.Addr().String()
			hostSent := make(chan struct{})
			hostDone := make(chan struct{})
			go func() {
				defer close(hostDone)
				raw, err := hostListener.Accept()
				if err != nil {
					return
				}
				defer func() { _ = raw.Close() }()
				cfg := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					_, _, err := (&UserCertChecker{IsUserAuthority: func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), f.signer.PublicKey().Marshal()) }}).Authenticate(meta.User(), key)
					return nil, err
				}}
				cfg.AddHostKey(f.signer)
				conn, channels, requests, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				go ssh.DiscardRequests(requests)
				incoming := <-channels
				if incoming == nil {
					return
				}
				ch, requests, err := incoming.Accept()
				if err != nil {
					return
				}
				go ssh.DiscardRequests(requests)
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{7}))
				_ = ch.Close()
				close(hostSent)
				// The host stays connected: retirement must be what ends the
				// upstream. A host that disconnects on its own can end it before
				// the gate has accepted the guest's channel, which the gate then
				// refuses.
				_ = conn.Wait()
			}()

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer func() { _ = ln.Close() }()
			f.addr = ln.Addr().String()
			entered, release, disconnected := make(chan struct{}), make(chan struct{}), make(chan struct{})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			gateDone := make(chan error, 1)
			go func() {
				raw, err := ln.Accept()
				if err != nil {
					gateDone <- err
					return
				}
				defer func() { _ = raw.Close() }()
				cfg := &ssh.ServerConfig{ServerVersion: "SSH-2.0-test gate-v1", PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					_, _, _, err := f.proxy.routing.Auth.authenticate(meta, key)
					return nil, err
				}}
				cfg.AddHostKey(f.signer)
				conn, channels, requests, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					gateDone <- err
					return
				}
				defer func() { _ = conn.Close() }()
				go func() { _ = conn.Wait(); close(disconnected) }()
				wrapped := make(chan ssh.NewChannel)
				go func() {
					defer close(wrapped)
					for ch := range channels {
						select {
						case wrapped <- heldExitOpen{ch, entered, release, disconnected}:
						case <-ctx.Done():
							return
						case <-disconnected:
							return
						}
					}
				}()
				gateDone <- f.proxy.routing.serveHopGate(ctx, sshPeer{conn, wrapped, requests}, f.auth, f.guest.PublicKey(), 2*time.Second, newSSHRoutingInstruments(provider.NewDiscardProvider()))
			}()
			u, err := f.connect(t, f.auth, f.authority)
			require.NoError(t, err)
			home, err := negotiateHome(t.Context(), u, freshModeRequest("route"))
			require.NoError(t, err)
			if tc.authority == AuthorityDelegated {
				require.NoError(t, assertHomeAdmission(t.Context(), home, f.admissionOf(home)))
			}
			channel, requests, err := u.conn.OpenChannel("session", nil)
			require.NoError(t, err)
			defer func() { _ = channel.Close() }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("exit status did not reach delivery barrier")
			}
			<-hostSent
			f.home.retire()
			if tc.authority == AuthorityDelegated {
				// A delegated registration's retirement interrupts even what
				// the host already sent.
				select {
				case <-disconnected:
				case <-time.After(time.Second):
					t.Fatal("delegated retirement waited for buffered status")
				}
			} else if stalled {
				select {
				case <-disconnected:
				case <-time.After(sshForwardDrainTimeout + time.Second):
					t.Fatal("unread local exit tail exceeded the stock drain bound")
				}
			} else {
				// Existing stock drain remains bounded, but retirement alone may
				// not discard an already received local exit request.
				select {
				case <-disconnected:
					t.Fatal("local retirement discarded buffered exit status")
				case <-time.After(25 * time.Millisecond):
				}
				close(release)
				select {
				case r := <-requests:
					require.NotNil(t, r)
					require.Equal(t, "exit-status", r.Type)
					var status struct{ Status uint32 }
					require.NoError(t, ssh.Unmarshal(r.Payload, &status))
					require.EqualValues(t, 7, status.Status)
				case <-time.After(time.Second):
					t.Fatal("local exit status did not drain")
				}
			}
			_ = u.conn.Close()
			select {
			case err := <-gateDone:
				t.Logf("gate completed bounded cleanup: %v", err)
			case <-time.After(2 * time.Second):
				t.Fatal("gate did not finish bounded cleanup")
			}
			<-hostDone
		})
	}
}
