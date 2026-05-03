package server

import (
	"context"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics/provider"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	HostPublicKeyContent  = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOA+rMcwWFPJVE2g6EwRPkYmNJfaS/+gkyZ99aR/65uz`
	HostPrivateKeyContent = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDgPqzHMFhTyVRNoOhMET5GJjSX2kv/oJMmffWkf+ubswAAAIiu5GOBruRj
gQAAAAtzc2gtZWQyNTUxOQAAACDgPqzHMFhTyVRNoOhMET5GJjSX2kv/oJMmffWkf+ubsw
AAAEDBHlsR95C/pGVHtQGpgrUi+Qwgkfnp9QlRKdEhhx4rxOA+rMcwWFPJVE2g6EwRPkYm
NJfaS/+gkyZ99aR/65uzAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----`
)

func Test_sshProxy_dialUpstream(t *testing.T) {
	logger := logging.Must(logging.Console(), logging.Debug()).Logger

	signer, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	if err != nil {
		t.Fatal(err)
	}

	cs := HostCertSigner{
		Hostnames: []string{"127.0.0.1"},
	}
	hostSigner, err := cs.SignCert(signer)
	if err != nil {
		t.Fatal(err)
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = proxyLn.Close()
	}()

	proxyAddr := proxyLn.Addr().String()
	cd := sidewayConnDialer{
		NodeAddr:        proxyAddr,
		NeighbourDialer: tcpConnDialer{},
		Logger:          logger,
	}
	proxy := &sshProxy{
		HostSigners:     []ssh.Signer{hostSigner},
		Signers:         []ssh.Signer{signer},
		SessionManager:  newEmbeddedSessionManager(logger),
		NodeAddr:        proxyAddr,
		ConnDialer:      cd,
		Logger:          logger,
		MetricsProvider: provider.NewDiscardProvider(),
	}

	go func() {
		_ = proxy.Serve(proxyLn)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := utils.WaitForServer(ctx, proxyAddr); err != nil {
		t.Fatal(err)
	}

	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = sshLn.Close()
	}()

	sshdAddr := sshLn.Addr().String()
	sshd := &sshd{
		SessionManager: newEmbeddedSessionManager(logger),
		HostSigners:    []ssh.Signer{signer},
		NodeAddr:       sshdAddr,
		Logger:         logger,
	}

	go func() {
		_ = sshd.Serve(sshLn)
	}()

	if err := utils.WaitForServer(ctx, sshdAddr); err != nil {
		t.Fatal(err)
	}

	encoder := routing.NewEncodeDecoder(routing.ModeEmbedded)
	user := encoder.Encode(xid.New().String(), sshdAddr)
	ucs, err := testCertSigner(user, signer)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		Name   string
		Signer ssh.Signer
	}{
		{
			Name:   "public-key auth",
			Signer: signer,
		},
		{
			Name:   "public-key user cert auth",
			Signer: ucs,
		},
	}

	for _, c := range cases {
		cc := c

		t.Run(c.Name, func(t *testing.T) {
			config := &ssh.ClientConfig{
				User:            user,
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(cc.Signer)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}
			client, err := ssh.Dial("tcp", proxyAddr, config) // proxy to sshd
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.NewSession()
			if err == nil || !strings.Contains(err.Error(), "unsupported channel type") {
				t.Fatalf("expect unsupported channel type error but got %v", err)
			}
		})
	}
}

func testCertSigner(user string, signer ssh.Signer) (ssh.Signer, error) {
	cert := &ssh.Certificate{
		Key:             signer.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "1234",
		ValidPrincipals: []string{user},
		ValidBefore:     ssh.CertTimeInfinity,
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}

	return ssh.NewCertSigner(cert, signer)
}

// fakeConnMetadata is a minimal ssh.ConnMetadata stub for unit-testing
// authPiper.checkAuthorizedKeys, which only consults ClientVersion.
type fakeConnMetadata struct {
	clientVersion string
}

func (f *fakeConnMetadata) User() string          { return "" }
func (f *fakeConnMetadata) SessionID() []byte     { return nil }
func (f *fakeConnMetadata) ClientVersion() []byte { return []byte(f.clientVersion) }
func (f *fakeConnMetadata) ServerVersion() []byte { return nil }
func (f *fakeConnMetadata) RemoteAddr() net.Addr  { return nil }
func (f *fakeConnMetadata) LocalAddr() net.Addr   { return nil }

func writeKeyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authorized_keys")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

func Test_loadAuthorizedKeys(t *testing.T) {
	hostSigner, err := ssh.ParsePrivateKey([]byte(HostPrivateKeyContent))
	require.NoError(t, err)
	hostFp := utils.FingerprintSHA256(hostSigner.PublicKey())

	otherSigner, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	otherPubKeyLine := string(ssh.MarshalAuthorizedKey(otherSigner.PublicKey()))
	otherFp := utils.FingerprintSHA256(otherSigner.PublicKey())

	t.Run("nil paths returns nil set (gate disabled)", func(t *testing.T) {
		got, err := loadAuthorizedKeys(nil)
		require.NoError(t, err)
		require.Nil(t, got)
	})

	t.Run("single file is parsed into fingerprint set", func(t *testing.T) {
		got, err := loadAuthorizedKeys([]string{writeKeyFile(t, HostPublicKeyContent+"\n")})
		require.NoError(t, err)
		require.Contains(t, got, hostFp)
		require.Len(t, got, 1)
	})

	t.Run("multiple files are unioned", func(t *testing.T) {
		got, err := loadAuthorizedKeys([]string{
			writeKeyFile(t, HostPublicKeyContent+"\n"),
			writeKeyFile(t, otherPubKeyLine),
		})
		require.NoError(t, err)
		require.Contains(t, got, hostFp)
		require.Contains(t, got, otherFp)
	})

	t.Run("comment-only file yields empty set, not an error", func(t *testing.T) {
		got, err := loadAuthorizedKeys([]string{writeKeyFile(t, "# header\n# nothing else\n")})
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("missing file fails fast", func(t *testing.T) {
		_, err := loadAuthorizedKeys([]string{filepath.Join(t.TempDir(), "does-not-exist")})
		require.Error(t, err)
	})
}

func Test_authPiper_checkAuthorizedKeys(t *testing.T) {
	logger := logging.Must(logging.Console(), logging.Debug()).Logger

	hostSigner, err := ssh.ParsePrivateKey([]byte(HostPrivateKeyContent))
	require.NoError(t, err)
	hostPubKey := hostSigner.PublicKey()
	hostFp := utils.FingerprintSHA256(hostPubKey)

	// Wrap the host's key in a certificate to mimic an agent-provided CertSigner:
	// the SSH library passes the certificate (not the raw key) to PublicKeyCallback.
	hostCertSigner, err := testCertSigner("host", hostSigner)
	require.NoError(t, err)
	hostCertAsPubKey := hostCertSigner.PublicKey()

	otherSigner, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyContent))
	require.NoError(t, err)
	otherFp := utils.FingerprintSHA256(otherSigner.PublicKey())

	hostMeta := &fakeConnMetadata{clientVersion: upterm.HostSSHClientVersion}
	clientMeta := &fakeConnMetadata{clientVersion: "SSH-2.0-OpenSSH_9.0"}

	cases := []struct {
		name      string
		keys      map[string]struct{}
		meta      ssh.ConnMetadata
		offered   ssh.PublicKey
		wantGrant bool
	}{
		{
			name:      "nil set bypasses gate",
			keys:      nil,
			meta:      hostMeta,
			offered:   hostPubKey,
			wantGrant: true,
		},
		{
			name:      "non-host client version bypasses gate",
			keys:      map[string]struct{}{otherFp: {}}, // host key NOT in set
			meta:      clientMeta,
			offered:   hostPubKey,
			wantGrant: true,
		},
		{
			name:      "host key present in set is granted",
			keys:      map[string]struct{}{hostFp: {}},
			meta:      hostMeta,
			offered:   hostPubKey,
			wantGrant: true,
		},
		{
			name:      "host key absent from non-empty set is denied",
			keys:      map[string]struct{}{otherFp: {}},
			meta:      hostMeta,
			offered:   hostPubKey,
			wantGrant: false,
		},
		{
			name:      "empty (non-nil) set denies all hosts",
			keys:      map[string]struct{}{},
			meta:      hostMeta,
			offered:   hostPubKey,
			wantGrant: false,
		},
		{
			name:      "cert is matched against its underlying key (in set)",
			keys:      map[string]struct{}{hostFp: {}},
			meta:      hostMeta,
			offered:   hostCertAsPubKey,
			wantGrant: true,
		},
		{
			name:      "cert is matched against its underlying key (absent)",
			keys:      map[string]struct{}{otherFp: {}},
			meta:      hostMeta,
			offered:   hostCertAsPubKey,
			wantGrant: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := authPiper{
				authorizedKeys: tc.keys,
				Logger:         logger,
			}
			err := a.checkAuthorizedKeys(tc.meta, tc.offered)
			if tc.wantGrant {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
