package ftests

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// missingSession is a session on the node at hostNodeAddr that isn't there.
// The user is in the embedded encoding, which the Consul decoder also accepts.
func missingSession(hostNodeAddr string) *api.GetSessionResponse {
	return &api.GetSessionResponse{SessionId: "nosuchsession", NodeAddr: hostNodeAddr,
		SshUser: "nosuchsession:" + base64.URLEncoding.EncodeToString([]byte(hostNodeAddr))}
}

func testClientBannerForMissingSession(t *testing.T, hostNodeAddr, clientJoinURL string) {
	var banners []string
	c := &Client{PrivateKeys: []string{ClientPrivateKey}, BannerCallback: func(m string) error { banners = append(banners, m); return nil }}
	require.Error(t, c.Join(missingSession(hostNodeAddr), clientJoinURL))
	require.Equal(t, []string{fmt.Sprintf(upterm.BannerNoHostFormat, "nosuchsession")}, banners)
}

// A guest whose handshake another node completes hears that the session isn't
// there when it opens its session: in that node's rejection of the channel,
// not in a banner. A person using ssh reads it in a sentence; upterm join reads
// the wire text it matches.
func testClientToldOfMissingSessionThroughAnotherNode(t *testing.T, hostNodeAddr, clientJoinURL string) {
	for clientVersion, want := range map[string]string{
		"":                          "upterm: no host is connected for session nosuchsession right now; it may have ended, or the ID may be wrong.",
		upterm.JoinSSHClientVersion: upterm.UpstreamNoHost,
	} {
		c := &Client{PrivateKeys: []string{ClientPrivateKey}, ClientVersion: clientVersion}
		var rejection *ssh.OpenChannelError
		require.ErrorAs(t, c.Join(missingSession(hostNodeAddr), clientJoinURL), &rejection, "%q", clientVersion)
		require.Equal(t, want, rejection.Message, "%q", clientVersion)
	}
}
