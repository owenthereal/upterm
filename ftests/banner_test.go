package ftests

import (
	"encoding/base64"
	"testing"

	"github.com/owenthereal/upterm/host/api"
	"github.com/stretchr/testify/require"
)

// The user is in the embedded encoding, which the Consul decoder also accepts.
func testClientBannerForMissingSession(t *testing.T, hostNodeAddr, clientJoinURL string) {
	var banners []string
	c := &Client{PrivateKeys: []string{ClientPrivateKey}, BannerCallback: func(m string) error { banners = append(banners, m); return nil }}
	missing := &api.GetSessionResponse{SessionId: "nosuchsession", NodeAddr: hostNodeAddr,
		SshUser: "nosuchsession:" + base64.URLEncoding.EncodeToString([]byte(hostNodeAddr))}
	require.Error(t, c.Join(missing, clientJoinURL))
	require.Len(t, banners, 1)
	require.Contains(t, banners[0], "no host is connected for session nosuchsession")
}
