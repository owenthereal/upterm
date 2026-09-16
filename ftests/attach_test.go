package ftests

import (
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/stretchr/testify/require"
)

// The fixture's own client comes in by the host door and a guest by the
// guest door; the admin API says which is which.
func testHostKindAndGuestKindInConnectedClients(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	adminSocketFile := setupAdminSocket(t)
	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	require.NoError(t, h.Share(hostShareURL))
	defer h.Close()

	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)
	c := &Client{PrivateKeys: []string{ClientPrivateKey}}
	require.NoError(t, c.Join(session, clientJoinURL))
	defer c.Close()
	_, out := c.InputOutput()
	go func() {
		for range out { //nolint:revive // drained, not inspected
		}
	}()

	require.Eventually(t, func() bool {
		sess, err := adminClientSession(adminSocketFile)
		if err != nil {
			return false
		}
		kinds := map[api.Client_Kind]int{}
		for _, cl := range sess.ConnectedClients {
			kinds[cl.Kind]++
		}
		return kinds[api.Client_HOST] == 1 && kinds[api.Client_GUEST] == 1
	}, callbackTimeout, 50*time.Millisecond, "expected one host-kind and one guest-kind client")
}
