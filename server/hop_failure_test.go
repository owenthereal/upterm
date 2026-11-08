package server

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

func TestHopGateNegativeReasons(t *testing.T) {
	t.Run("absent_adopted_home", func(t *testing.T) {
		f := newHopGateFixture(t)
		f.registry.current.Store(nil)
		u, err := f.connect(t, f.auth, f.authority)
		require.NoError(t, err)
		h, err := negotiateHome(t.Context(), u, freshModeRequest("route"))
		require.Nil(t, h)
		require.ErrorIs(t, err, errUpstreamNoHost)
		require.Equal(t, errUpstreamNoHost, upstreamFailureReason(err))
		_, _, err = u.conn.OpenChannel("session", nil)
		require.Error(t, err, "negative mode reply must close the attempt")
		require.Zero(t, f.dialer.calls.Load())
	})
	t.Run("refused_original_key", func(t *testing.T) {
		f := newHopGateFixture(t)
		auth := proto.Clone(f.auth).(*AuthRequest)
		auth.AuthorizedKey = ssh.MarshalAuthorizedKey(certTestSigner(t).PublicKey())
		u, err := f.connect(t, auth, f.authority)
		require.NoError(t, err)
		h, err := negotiateHome(t.Context(), u, freshModeRequest("route"))
		require.NoError(t, err)
		require.Equal(t, AuthorityLocal, h.Ref().Authority)
		_, _, err = u.conn.OpenChannel("session", nil)
		var rejected *ssh.OpenChannelError
		require.ErrorAs(t, err, &rejected)
		require.Equal(t, upterm.UpstreamKeyRefused, rejected.Message)
		require.Zero(t, f.dialer.calls.Load())
	})
}

// A gate hop whose home can't reach its host, after the mode exchange
// admitted it, has its channels rejected with the classified reason, as any
// other hop does, rather than closed without one.
func TestHopGateReportsTheHostsFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		host func(t *testing.T) string
		want string
	}{
		{name: "host_key_mismatch", want: upterm.UpstreamHostKeyMismatch, host: func(t *testing.T) string {
			// A host presenting a key other than the registration's run key.
			addr, _ := stockTestUpstream(t, false, HostPrivateKeyContent)
			return addr
		}},
		{name: "unreachable", want: upterm.UpstreamUnavailable, host: func(t *testing.T) string {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			addr := ln.Addr().String()
			require.NoError(t, ln.Close())
			return addr
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newHopGateFixture(t)
			f.dialer.addr = tc.host(t)
			u, err := f.connect(t, f.auth, f.authority)
			require.NoError(t, err)
			h, err := negotiateHome(t.Context(), u, freshModeRequest("route"))
			require.NoError(t, err)
			require.Equal(t, AuthorityLocal, h.Ref().Authority)
			_, _, err = u.conn.OpenChannel("session", nil)
			var rejected *ssh.OpenChannelError
			require.ErrorAs(t, err, &rejected, "the hop closed without telling the ingress why")
			require.Equal(t, tc.want, rejected.Message)
			require.Equal(t, int32(1), f.dialer.calls.Load())
		})
	}
}

func TestHopGateNegativeReplyControls(t *testing.T) {
	for _, tc := range []struct {
		name, request, payload string
		late, canceled, named  bool
	}{
		{name: "exact_mode_reason", request: upterm.GateModeRequestType, payload: upterm.UpstreamNoHost, named: true},
		{name: "unknown", request: upterm.GateModeRequestType, payload: "internal address 10.1.2.3"},
		{name: "substring", request: upterm.GateModeRequestType, payload: upterm.UpstreamNoHost + " extra"},
		// Another gate operation: only the mode request has a no-home verdict.
		{name: "wrong_operation", request: "gate-admit@upterm.dev", payload: upterm.UpstreamNoHost},
		{name: "late", request: upterm.GateModeRequestType, payload: upterm.UpstreamNoHost, late: true},
		{name: "canceled", request: upterm.GateModeRequestType, payload: upterm.UpstreamNoHost, canceled: true},
		{name: "oversized", request: upterm.GateModeRequestType, payload: strings.Repeat("x", maxGatePayload+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var elapsed atomic.Int64
			u := gateContractPeer(t, certTestSigner(t), func(r *ssh.Request) {
				if tc.late {
					elapsed.Store(int64(gateTimeout + time.Nanosecond))
				}
				if tc.canceled {
					cancel()
				}
				_ = r.Reply(false, []byte(tc.payload))
			})
			start := time.Now()
			u.now = func() time.Time { return start.Add(time.Duration(elapsed.Load())) }
			body, err := sendGate(ctx, u, tc.request, freshModeRequest("route"))
			require.Nil(t, body)
			if tc.named {
				require.ErrorIs(t, err, errUpstreamNoHost)
			} else {
				require.ErrorIs(t, err, errGateRefused)
			}
			_, _, err = u.conn.OpenChannel("session", nil)
			require.Error(t, err)
		})
	}
}

func TestHopGateAbsentHomeRequiresValidTarget(t *testing.T) {
	f := newHopGateFixture(t)
	f.registry.current.Store(nil)
	for _, target := range []string{"route", "other"} {
		request := freshModeRequest(target)
		body, err := proto.Marshal(request)
		require.NoError(t, err)
		g := &hopGate{auth: f.auth, lookup: f.registry, now: time.Now}
		ok, reply, err := g.request(&ssh.Request{Type: upterm.GateModeRequestType, WantReply: true, Payload: body})
		require.False(t, ok)
		require.Error(t, err)
		if target == "route" {
			require.Equal(t, upterm.UpstreamNoHost, string(reply))
		} else {
			require.Empty(t, reply)
		}
		require.False(t, g.mode)
		require.False(t, g.admitted)
	}
}
