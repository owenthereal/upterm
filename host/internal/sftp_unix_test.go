//go:build !windows

package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"sync"
	"testing"

	hostsftp "github.com/owenthereal/upterm/host/sftp"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// denyingChecker refuses every SFTP operation and remembers the client the
// last prompt would have named.
type denyingChecker struct {
	mu      sync.Mutex
	asked   bool
	lastFor hostsftp.ClientInfo
}

func (c *denyingChecker) CheckPermission(op hostsftp.Operation, client hostsftp.ClientInfo, paths ...string) (hostsftp.PermissionResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.asked, c.lastFor = true, client
	return hostsftp.PermissionDenied, nil
}

func (c *denyingChecker) ClearSession(string) {}

// The prompt names the key the guest authenticated with: the fingerprint the
// host's client list shows. The relay reaches the host with a certificate it
// signs with its own key and carries the guest's key inside it, so the key
// the host's SSH server sees fingerprints as neither.
func TestSFTPPromptNamesTheGuestKey(t *testing.T) {
	checker := &denyingChecker{}
	h := startHost(t, &Server{Command: readsALine("READY", 0), SFTPPermissionChecker: checker})

	guestPublic, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	guestKey, err := ssh.NewPublicKey(guestPublic)
	require.NoError(t, err)
	cert := &server.UserCertSigner{
		User: "guest", SessionID: t.Name(),
		AuthRequest: &server.AuthRequest{AuthorizedKey: ssh.MarshalAuthorizedKey(guestKey)},
	}
	// Signed by the harness's relay, the authority this host trusts: a
	// certificate from anyone else is refused at the guest door, so the prompt
	// would never be reached.
	h.guestSigner, err = cert.SignCert(h.relaySigner)
	require.NoError(t, err)

	sftpClient, err := sftp.NewClient(h.guestClient(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sftpClient.Close() })

	// The host answers the open only once the checker has decided, so the
	// prompt has been recorded by the time Open returns.
	_, err = sftpClient.Open(filepath.Join(t.TempDir(), "notes.txt"))
	require.Error(t, err)

	checker.mu.Lock()
	defer checker.mu.Unlock()
	require.True(t, checker.asked, "the download was not put to the checker")
	require.Equal(t, utils.FingerprintSHA256(guestKey), checker.lastFor.Fingerprint)
}
