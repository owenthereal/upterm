package command

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/join"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestJoinRejectsHostCertificatesWithoutPrincipals(t *testing.T) {
	data, err := os.ReadFile("../../../host/internal/testdata/legacy-host-no-principals.pub")
	require.NoError(t, err)
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	require.NoError(t, err)
	cert, ok := key.(*ssh.Certificate)
	require.True(t, ok)
	require.Equal(t, uint32(ssh.HostCert), cert.CertType)
	require.Empty(t, cert.ValidPrincipals)

	for _, tc := range []struct {
		name    string
		content string
		missing bool
	}{
		{name: "known authority", content: "@cert-authority " + knownhosts.Line([]string{"relay.test"}, cert.SignatureKey) + "\n"},
		{name: "pinned raw key", content: knownhosts.Line([]string{"relay.test"}, cert.Key) + "\n"},
		{name: "empty file"},
		{name: "missing file", missing: true},
	} {
		for _, mode := range []struct {
			name string
			skip bool
		}{{"prompting", false}, {"auto-accepting", true}} {
			t.Run(tc.name+"/"+mode.name, func(t *testing.T) {
				file := filepath.Join(t.TempDir(), "known_hosts")
				if !tc.missing {
					require.NoError(t, os.WriteFile(file, []byte(tc.content), 0o600))
				}
				in := strings.NewReader("yes\n")
				var out bytes.Buffer
				keys := newRelayKeys(host.KnownHosts{File: file, Stdout: &out}, mode.skip, in, func() error { return nil })
				err := keys.check("relay.test:22", relayAddr, cert)
				require.ErrorContains(t, err, "valid principals")
				require.NotErrorIs(t, err, join.ErrHostKeyUnknown, "a refusal must not reach join's confirmation path")
				require.NotErrorIs(t, err, join.ErrHostKeyChanged)
				require.Empty(t, out.String(), "no prompt or acceptance warning")
				require.Equal(t, len("yes\n"), in.Len(), "no input consumed")
				if tc.missing {
					require.NoFileExists(t, file)
				} else {
					content, err := os.ReadFile(file)
					require.NoError(t, err)
					require.Equal(t, tc.content, string(content), "nothing recorded")
				}
			})
		}
	}
}

func TestJoinAcceptsRawKeysAndNamedHostCertificates(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	cert := &ssh.Certificate{
		Key: signer.PublicKey(), CertType: ssh.HostCert,
		ValidPrincipals: []string{"relay.test"}, ValidBefore: ssh.CertTimeInfinity,
	}
	require.NoError(t, cert.SignCert(rand.Reader, signer))
	plain := knownhosts.Line([]string{"relay.test"}, signer.PublicKey()) + "\n"
	authority := "@cert-authority " + plain

	for _, presented := range []struct {
		name     string
		key      ssh.PublicKey
		recorded string
	}{
		{"raw key", signer.PublicKey(), plain},
		{"named certificate", cert, authority},
	} {
		for _, tc := range []struct {
			name    string
			content string
			missing bool
		}{
			{name: "pinned raw key", content: plain},
			{name: "known authority", content: authority},
			{name: "empty file"},
			{name: "missing file", missing: true},
		} {
			for _, mode := range []struct {
				name string
				skip bool
			}{{"prompting", false}, {"auto-accepting", true}} {
				t.Run(presented.name+"/"+tc.name+"/"+mode.name, func(t *testing.T) {
					file := filepath.Join(t.TempDir(), "known_hosts")
					if !tc.missing {
						require.NoError(t, os.WriteFile(file, []byte(tc.content), 0o600))
					}
					in := strings.NewReader("yes\n")
					var out bytes.Buffer
					kh := host.KnownHosts{File: file, Stdout: &out}
					keys := newRelayKeys(kh, mode.skip, in, func() error { return nil })
					err := keys.check("relay.test:22", relayAddr, presented.key)
					if errors.Is(err, join.ErrHostKeyUnknown) {
						confirm := keys.confirmFor("relay.test:22")
						require.NotNil(t, confirm)
						accepted, err := confirm(context.Background(), "relay.test:22", presented.key)
						require.NoError(t, err)
						require.True(t, accepted)
					} else {
						require.NoError(t, err)
					}
					require.NoError(t, keys.check("relay.test:22", relayAddr, presented.key))
					content, err := os.ReadFile(file)
					require.NoError(t, err)
					want := tc.content
					if want == "" {
						want = presented.recorded
					} else {
						require.Empty(t, out.String(), "known keys need no prompt or warning")
						require.Equal(t, len("yes\n"), in.Len())
					}
					require.Equal(t, want, string(content))
				})
			}
		}
	}
}
