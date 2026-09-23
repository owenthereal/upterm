package internal

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

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
