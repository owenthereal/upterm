package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"

	gssh "charm.land/ssh"
	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type forwardingTestContext struct {
	gssh.Context
	values map[any]any
}

func (c forwardingTestContext) Value(key any) any { return c.values[key] }

type rejectingForwardingChannel struct {
	ssh.NewChannel
	extraDataCalls int
	acceptCalls    int
	rejectReason   ssh.RejectionReason
	rejectMessage  string
}

func (c *rejectingForwardingChannel) ExtraData() []byte {
	c.extraDataCalls++
	return ssh.Marshal(&struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}{"127.0.0.1", 22, "127.0.0.1", 1})
}

func (c *rejectingForwardingChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	c.acceptCalls++
	return nil, nil, errors.New("unexpected Accept")
}

func (c *rejectingForwardingChannel) Reject(reason ssh.RejectionReason, message string) error {
	c.rejectReason = reason
	c.rejectMessage = message
	return nil
}

func TestForwardingRejectsMissingConnectionMetadata(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	validGuest := authenticatedGuest{auth: &server.AuthRequest{}, key: key}

	tests := []struct {
		name    string
		corrupt func(map[any]any)
	}{
		{"missing presence state", func(values map[any]any) { delete(values, forwardingPresenceKey{}) }},
		{"wrong presence state", func(values map[any]any) { values[forwardingPresenceKey{}] = "wrong" }},
		{"typed nil presence state", func(values map[any]any) { values[forwardingPresenceKey{}] = (*sync.Once)(nil) }},
		{"missing guest", func(values map[any]any) { delete(values, authenticatedGuestKey{}) }},
		{"wrong guest", func(values map[any]any) { values[authenticatedGuestKey{}] = "wrong" }},
		{"guest without auth", func(values map[any]any) { values[authenticatedGuestKey{}] = authenticatedGuest{key: key} }},
		{"guest without key", func(values map[any]any) {
			values[authenticatedGuestKey{}] = authenticatedGuest{auth: &server.AuthRequest{}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			once := new(sync.Once)
			values := map[any]any{forwardingPresenceKey{}: once, authenticatedGuestKey{}: validGuest}
			tt.corrupt(values)
			ctx := forwardingTestContext{values: values}
			channel := &rejectingForwardingChannel{}
			events := emitter.New(1)
			joined := events.On(upterm.EventForwardingClientJoined)
			permissionCalls := 0
			srv := &gssh.Server{LocalPortForwardingCallback: func(gssh.Context, string, uint32) bool {
				permissionCalls++
				return false // A mistaken delegation still cannot dial a target.
			}}

			forwardingHandler(events)(srv, nil, channel, ctx)

			require.Equal(t, ssh.ConnectionFailed, channel.rejectReason)
			require.Contains(t, channel.rejectMessage, "metadata")
			require.Zero(t, channel.extraDataCalls, "library handler must not run")
			require.Zero(t, permissionCalls, "forwarding permission must not be checked")
			require.Zero(t, channel.acceptCalls)
			select {
			case <-joined:
				t.Fatal("invalid forwarding metadata announced guest presence")
			default:
			}
			consumed := false
			once.Do(func() { consumed = true })
			require.True(t, consumed, "invalid metadata must not consume presence latch")
		})
	}
}

// Forcing the peer to close during Accept over real SSH is nondeterministic.
// Substitute only the channel acceptance boundary; successful acceptance and
// traffic are covered through Host.Run with the real library handler.
type failedForwardingChannel struct{ ssh.NewChannel }

func (failedForwardingChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, errors.New("peer closed before acceptance")
}

func TestForwardingFailedAcceptDoesNotAnnounce(t *testing.T) {
	announced := false
	channel := &forwardingChannel{NewChannel: failedForwardingChannel{}, accepted: func() { announced = true }}
	conn, requests, err := channel.Accept()
	require.ErrorContains(t, err, "peer closed before acceptance")
	require.Nil(t, conn)
	require.Nil(t, requests)
	require.False(t, announced, "failed acceptance must not publish presence")
}
