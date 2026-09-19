package host

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestSignersFallback(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	invalid := filepath.Join(dir, "invalid")
	require.NoError(t, os.WriteFile(invalid, []byte("not a private key"), 0600))

	for _, tc := range []struct {
		name string
		keys []string
	}{
		{name: "no keys"},
		{name: "missing key", keys: []string{filepath.Join(dir, "missing")}},
		{name: "invalid key", keys: []string{invalid}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signers, cleanup, err := Signers(tc.keys, false)
			if cleanup != nil {
				t.Cleanup(cleanup)
			}
			require.NoError(t, err)
			require.Len(t, signers, 1, "generate a temporary key when no keys can be loaded")
			message := []byte("authenticate with a generated key")
			signature, err := signers[0].Sign(rand.Reader, message)
			require.NoError(t, err)
			require.NoError(t, signers[0].PublicKey().Verify(message, signature))
		})
	}
}

func TestSignersPreservesFileKey(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	require.NoError(t, err)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(block), 0600))

	signers, cleanup, err := Signers([]string{filepath.Join(dir, "missing"), keyFile}, false)
	if cleanup != nil {
		t.Cleanup(cleanup)
	}
	require.NoError(t, err)
	require.Len(t, signers, 1)
	want, err := ssh.NewPublicKey(publicKey)
	require.NoError(t, err)
	require.Equal(t, want.Marshal(), signers[0].PublicKey().Marshal())
}

const (
	// Passphrase is "1234"
	rsaPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
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
a9rQ==
-----END OPENSSH PRIVATE KEY-----
`
	// nolint
	rsaPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCt//y3H4heRi1+3bO+FsqKyGTw5YQnu6MChEaDJY2SJqFCHGEwBAWGsuaDZPb6P+V16I5u2H+MtKBWDbkVK9760DkAFimuQ4XTtIzPhyb+Jc95wvNW6pAYXoetVlZIbzNzMEykE41kOMq19SNS3snvE5mYzfd2B6AGw3T2SubfF6G0staxtEYwlsWP/N+YIR4yLz11bxwuuTee/eMldvKZfzQQXIuopANU2mnAmoOqsG0G+DKNuXw7F7zd7lxus8zBF3fszur7Sc9APbWab5phJXWzE81ME2Z0Rro3/l/5mD3YqmS6+jyIqlvqR150Uf/2rKawVgzxZWvQhe1+gGIktavL85dO9VnxA/BASYM0caqFY/KwVpAs/mZ18SpjgPaEzm3H5eeTJRFMrwRusyunPTDv8lmAAXsr/ZMhd1gBkDiGE/YuTfekv8rMbkZNeB2HuXavcRTuCqY8y44ehe+sRug9nwykPnfRqjIeAm9zh+zknfJGl5TONHKnEj5tudpUvTd38ZnOM+CTzMHbSDOwkSLAp9mCzrbWc6OIeVqsqibPmia4SxyP7wxnszfH1MOkuCmphiCzk4nicYDhMW6jjXhRKok4yNIU9wqj0MMEKS3RKblAzCu7VFVTDrLSJIzs7Ch0RIuGnVTQ5S4O156Kr9hL535k6c6/NUXbylXtuw==`

	// Passphrase is "1234"
	ed25519PriavteKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCGNomvLJ
kXLr+TqkGZ2fuiAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIA9dIfLyILssYzKI
VY7UQenn2Il6cUeeYppVwDSAiqPzAAAAsAied6o/EzONSz0GmRvzUIUmK899O+N/ARFc9c
sSq5R8Qu+iqFOtgNFnPI1/wu22agUYxs3h6Su4Jv6WbySJpJhHhIN/6pZ4DZgj4zWGGSJl
5Kt2/q0hzzuxmO6hTGUGLArVXbJEXxTPV/jo/1w8qBYyB1rdKal1dN0OzUlCP1568WR8wq
CUI+b0Gxfqa/HSKlS23Iu7ZeWoMakwvcg5A5M8E/ihBLSDNsCJU8pgZ9FD
-----END OPENSSH PRIVATE KEY-----
`
	// nolint
	ed25519PublicKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA9dIfLyILssYzKIVY7UQenn2Il6cUeeYppVwDSAiqPz jou@oou-ltm.internal.salesforce.com`
)

func Test_signerFromFile(t *testing.T) {
	cases := []struct {
		name       string
		privateKey string
		passphrase string
		errMsg     string
	}{
		{
			name:       "rsa private key wrong passphrase",
			privateKey: rsaPrivateKey,
			passphrase: "wrong passphrase",
			errMsg:     "error decrypting private key",
		},
		{
			name:       "rsa private key correct passphrase",
			privateKey: rsaPrivateKey,
			passphrase: "1234",
		},
		{
			name:       "ed25519 private key wrong passphrase",
			privateKey: ed25519PriavteKey,
			passphrase: "wrong passphrase",
			errMsg:     "error decrypting private key",
		},
		{
			name:       "ed25519 private key correct passphrase",
			privateKey: ed25519PriavteKey,
			passphrase: "1234",
		},
	}

	for _, cc := range cases {
		c := cc
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			tmpfn := filepath.Join(dir, "private_key")
			if err := os.WriteFile(tmpfn, []byte(c.privateKey), 0600); err != nil {
				t.Fatal(err)
			}

			_, err := signerFromFile(tmpfn, func(file string) ([]byte, error) {
				if want, got := tmpfn, file; want != got {
					t.Fatalf("file mismatched, want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
				}

				return []byte(c.passphrase), nil
			})

			if err == nil && c.errMsg != "" {
				t.Fatal("error shouldn't be nil")
			}

			if err != nil && c.errMsg == "" {
				t.Fatalf("error should be nil but it's %s", err.Error())
			}

			if err != nil && !strings.Contains(err.Error(), c.errMsg) {
				t.Fatalf("unexpected error message, want=%q, got=%q", c.errMsg, err.Error())
			}
		})
	}
}

// failingPrompt is a passphrase prompt that must never be reached.
func failingPrompt(t *testing.T) func(string) ([]byte, error) {
	return func(file string) ([]byte, error) {
		t.Fatalf("the passphrase prompt was called for %s", file)
		return nil, nil
	}
}

func TestIdentitySigners_EmptyListIsAnError(t *testing.T) {
	_, cleanup, err := identitySigners(nil, "", failingPrompt(t))
	require.Nil(t, cleanup)
	require.EqualError(t, err, "private-key was supplied but names no files")
}

func TestIdentitySigners_MissingFileIsAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	_, _, err := identitySigners([]string{missing}, "", failingPrompt(t))
	require.ErrorContains(t, err, "cannot read private key "+missing)
}

func TestIdentitySigners_UnparseableFileIsAnError(t *testing.T) {
	junk := filepath.Join(t.TempDir(), "junk")
	require.NoError(t, os.WriteFile(junk, []byte("not a key of any kind"), 0600))
	_, _, err := identitySigners([]string{junk}, "", failingPrompt(t))
	require.ErrorContains(t, err, "cannot parse private key "+junk)
}

// skPrivateKeyAuthMagic and the wire structs below mirror x/crypto's
// openssh-key-v1 container (golang.org/x/crypto/ssh/keys.go, v0.57.0) well
// enough to build a private-key file whose inner key type is
// sk-ssh-ed25519@openssh.com: a FIDO/security-key handle, not a signable
// private key. `ssh-keygen -t ed25519-sk` writes exactly this container
// shape. x/crypto's parseOpenSSHPrivateKey type-switches on RSA, Ed25519 and
// ECDSA only, so this key type falls to its default case and returns "ssh:
// unhandled key type" — the failure this fix is about.
const skPrivateKeyAuthMagic = "openssh-key-v1\x00"

type skOpenSSHContainer struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
}

type skOpenSSHPrivateBlock struct {
	Check1  uint32
	Check2  uint32
	Keytype string
	Rest    []byte `ssh:"rest"`
}

type skEd25519PublicKeyWire struct {
	Name        string
	KeyBytes    []byte
	Application string
}

// skEd25519PublicKeyBlob returns the wire-format public key blob for a
// FIDO/security-key ed25519 identity: the shape ssh-keygen -t ed25519-sk
// writes to <file>.pub, and what x/crypto's own parseSKEd25519 expects.
func skEd25519PublicKeyBlob(pub ed25519.PublicKey) []byte {
	return ssh.Marshal(skEd25519PublicKeyWire{
		Name:        "sk-ssh-ed25519@openssh.com",
		KeyBytes:    []byte(pub),
		Application: "ssh:",
	})
}

// skEd25519PrivateStub builds a genuine openssh-key-v1 private-key file
// whose inner key type is sk-ssh-ed25519@openssh.com — a FIDO/security-key
// stub. pub only needs to be 32 bytes; nothing reads it as a real key,
// because x/crypto rejects the key type before it would get that far.
func skEd25519PrivateStub(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()

	privBlock := ssh.Marshal(skOpenSSHPrivateBlock{
		Check1:  0x2a2a2a2a,
		Check2:  0x2a2a2a2a,
		Keytype: "sk-ssh-ed25519@openssh.com",
	})
	container := ssh.Marshal(skOpenSSHContainer{
		CipherName:   "none",
		KdfName:      "none",
		KdfOpts:      "",
		NumKeys:      1,
		PubKey:       skEd25519PublicKeyBlob(pub),
		PrivKeyBlock: privBlock,
	})
	full := append([]byte(skPrivateKeyAuthMagic), container...)
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: full})
}

// TestSkEd25519PrivateStub_IsUnhandledKeyType pins the premise the sk-stub
// tests in this package depend on: the synthetic private key really does
// reach x/crypto's "ssh: unhandled key type" branch, the same one a real
// `ssh-keygen -t ed25519-sk` private file hits.
func TestSkEd25519PrivateStub_IsUnhandledKeyType(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = ssh.ParseRawPrivateKey(skEd25519PrivateStub(t, pub))
	require.EqualError(t, err, "ssh: unhandled key type")
}

// The "no .pub sibling" sk-stub case used to stop here with the file
// unresolvable, same as ordinary junk. It no longer does: the public key
// embedded in the openssh-key-v1 container itself is now recovered and
// tried against the agent, so the case needs an agent and lives with the
// other agent-backed tests in signer_unix_test.go, as
// TestIdentitySigners_SecurityKeyStubWithNoPubSiblingResolvesThroughAgent
// and TestIdentitySigners_SecurityKeyStubWithNoPubSiblingNotHeldByAgentIsAnError.

func TestIdentitySigners_UnencryptedFileNeedsNoAgent(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	require.NoError(t, err)
	keyFile := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(block), 0600))

	// No agent socket at all: an unencrypted file must not want one.
	signers, cleanup, err := identitySigners([]string{keyFile}, "", failingPrompt(t))
	require.NoError(t, err)
	t.Cleanup(cleanup)
	require.Len(t, signers, 1)
	want, err := ssh.NewPublicKey(publicKey)
	require.NoError(t, err)
	require.Equal(t, want.Marshal(), signers[0].PublicKey().Marshal())
}

func TestIdentitySigners_EncryptedFileWithNoAgentPrompts(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(keyFile, []byte(ed25519PriavteKey), 0600))

	t.Run("right passphrase", func(t *testing.T) {
		prompts := 0
		signers, cleanup, err := identitySigners([]string{keyFile}, "", func(string) ([]byte, error) {
			prompts++
			return []byte("1234"), nil
		})
		require.NoError(t, err)
		t.Cleanup(cleanup)
		require.Len(t, signers, 1)
		require.Equal(t, 1, prompts)
		want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ed25519PublicKey))
		require.NoError(t, err)
		require.Equal(t, want.Marshal(), signers[0].PublicKey().Marshal())
	})

	t.Run("wrong passphrase three times is an error, not a generated key", func(t *testing.T) {
		prompts := 0
		_, _, err := identitySigners([]string{keyFile}, "", func(string) ([]byte, error) {
			prompts++
			return []byte("wrong"), nil
		})
		require.ErrorContains(t, err, "error decrypting private key "+keyFile)
		require.Equal(t, 3, prompts)
	})
}

func TestIdentitySigners_PubSelectorWithNoAgentIsAnError(t *testing.T) {
	pubFile := filepath.Join(t.TempDir(), "id.pub")
	require.NoError(t, os.WriteFile(pubFile, []byte(ed25519PublicKey), 0600))
	_, _, err := identitySigners([]string{pubFile}, "", failingPrompt(t))
	require.ErrorContains(t, err, pubFile+": no SSH agent to look up")
	require.ErrorContains(t, err, "SSH agent is not running")
}

func TestSigners_IdentitiesOnlyDoesNotFallBackToAGeneratedKey(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	missing := filepath.Join(t.TempDir(), "missing")
	_, _, err := Signers([]string{missing}, true)
	require.ErrorContains(t, err, "cannot read private key "+missing)
}
