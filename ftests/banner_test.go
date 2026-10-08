package ftests

import (
	"encoding/base64"
	"testing"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
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
	require.Len(t, banners, 1)
	require.Contains(t, banners[0], "no host is connected for session nosuchsession")
}

// A guest whose handshake another node completes hears that the session isn't
// there when it opens its session: in that node's rejection of the channel,
// not in a banner.
func testClientToldOfMissingSessionThroughAnotherNode(t *testing.T, hostNodeAddr, clientJoinURL string) {
	c := &Client{PrivateKeys: []string{ClientPrivateKey}}
	require.ErrorContains(t, c.Join(missingSession(hostNodeAddr), clientJoinURL), upterm.UpstreamNoHost)
}
