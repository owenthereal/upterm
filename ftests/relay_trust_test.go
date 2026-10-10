package ftests

import (
	"crypto/rand"
	"testing"

	"github.com/owenthereal/upterm/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// testClientCertFromUnknownAuthorityRejected checks the guest path end to end: a
// guest whose key is not authorized offers a certificate signed by no authority
// the relay or the host recognizes, whose AuthRequest names the authorized key.
// That name must not be believed.
func testClientCertFromUnknownAuthorityRejected(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)
	assert := assert.New(t)

	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	require.NoError(h.Share(hostShareURL))
	defer h.Close()

	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	// The attacker holds a key the host does not permit.
	attacker, err := ssh.ParsePrivateKey([]byte(HostPrivateKeyContent))
	require.NoError(err)

	// Control: without a certificate, that key is refused. If this ever stops
	// failing, the test below proves nothing.
	control := &Client{PrivateKeys: []string{HostPrivateKey}}
	require.Error(control.Join(session, clientJoinURL))

	permitted, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPublicKeyContent))
	require.NoError(err)

	ucs := server.UserCertSigner{
		SessionID:   "forged",
		User:        session.SshUser,
		AuthRequest: &server.AuthRequest{AuthorizedKey: ssh.MarshalAuthorizedKey(permitted)},
	}
	forged, err := ucs.SignCert(attacker)
	require.NoError(err)

	c := &Client{Signers: []ssh.Signer{forged}}
	err = c.Join(session, clientJoinURL)
	require.Error(err, "a certificate from an unrecognized authority must not join")
	assert.ErrorContains(err, keyRefusal(hostShareURL, clientJoinURL))
}

// testClientAgentCertAuthorizedAsItsOwnKey covers the other half of the
// contract: a certificate upterm did not mint is treated as the key it
// certifies, not as its signer and not as a refusal, so an ssh-agent holding a
// CA-issued certificate for an authorized key still joins.
func testClientAgentCertAuthorizedAsItsOwnKey(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	require := require.New(t)

	adminSocketFile := setupAdminSocket(t)

	h := &Host{
		Command:                  getTestShell(),
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
	}
	require.NoError(h.Share(hostShareURL))
	defer h.Close()

	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	// The permitted key, wrapped in a certificate from an unrelated CA whose
	// principals name some other realm entirely.
	guest, err := ssh.ParsePrivateKey([]byte(ClientPrivateKeyContent))
	require.NoError(err)
	ca, err := ssh.ParsePrivateKey([]byte(HostPrivateKeyContent))
	require.NoError(err)

	cert := &ssh.Certificate{
		Key:             guest.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "agent",
		ValidPrincipals: []string{"someone-elses-realm"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	require.NoError(cert.SignCert(rand.Reader, ca))
	agentSigner, err := ssh.NewCertSigner(cert, guest)
	require.NoError(err)

	c := &Client{Signers: []ssh.Signer{agentSigner}}
	require.NoError(c.Join(session, clientJoinURL))
	defer c.Close()

	in, out := c.InputOutput()
	sc := scanner(out)
	in <- `echo "joined-$((40+2))"`
	expectLine(t, sc, "joined-42")
}
