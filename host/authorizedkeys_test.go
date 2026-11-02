package host

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func Test_AuthorizedKeysFromFile(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "valid")
	require.NoError(t, os.WriteFile(valid, []byte(testPublicKey+"\n"), 0600))

	empty := filepath.Join(dir, "empty")
	require.NoError(t, os.WriteFile(empty, nil, 0600))

	blank := filepath.Join(dir, "blank")
	require.NoError(t, os.WriteFile(blank, []byte("\n\n  \n"), 0600))

	cases := []struct {
		name          string
		file          string
		wantErrSubstr string
		wantKeys      int
	}{
		{name: "valid file", file: valid, wantKeys: 1},
		{
			name:          "missing file returns an error rather than nil, nil",
			file:          filepath.Join(dir, "nope"),
			wantErrSubstr: "nope",
		},
		{
			name:          "empty file is refused",
			file:          empty,
			wantErrSubstr: "no public keys found",
		},
		{
			name:          "whitespace-only file is refused",
			file:          blank,
			wantErrSubstr: "ssh: no key found",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ak, err := AuthorizedKeysFromFile(c.file)
			if c.wantErrSubstr != "" {
				assert.Nil(t, ak)
				assert.ErrorContains(t, err, c.wantErrSubstr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, ak)
			assert.Len(t, ak.PublicKeys, c.wantKeys)
		})
	}
}

func Test_parseAuthorizedKeys_emptyInputIsAnError(t *testing.T) {
	ak, err := parseAuthorizedKeys(nil, "github:alice@github.com")
	assert.Nil(t, ak)
	assert.ErrorContains(t, err, "no public keys found in github:alice@github.com")
}

// The approval review names a guest by the allowlist entry its key is on, as
// the host wrote it: an --authorized-user's user and reference, or, for an
// entry that names no one and may hold several guests' keys, the key and
// where it came from. A key on two entries is named by one that names someone.
func Test_guestLabels(t *testing.T) {
	pinGitHubHost(t, "github.com")
	newKey := func() ssh.PublicKey {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		key, err := ssh.NewPublicKey(pub)
		require.NoError(t, err)
		return key
	}
	named := func(s string) string {
		ref, err := ParseUserRef(s)
		require.NoError(t, err)
		return ref.guest()
	}
	dave, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testPublicKey))
	require.NoError(t, err)
	alice, bob, carol, erin := newKey(), newKey(), newKey(), newKey()
	aks := []*AuthorizedKey{
		{PublicKeys: []ssh.PublicKey{alice, dave}, Comment: "/home/owen/.ssh/authorized_keys"},
		{PublicKeys: []ssh.PublicKey{alice}, Comment: "github:alice@github.com", guest: named("github:alice")},
		{PublicKeys: []ssh.PublicKey{bob}, Comment: "gitea:bob@git.example.com", guest: named("gitea:bob@git.example.com")},
		{PublicKeys: []ssh.PublicKey{carol}, Comment: "https://keys.example.com/carol.keys"},
		{PublicKeys: []ssh.PublicKey{erin}},
	}
	assert.Equal(t, map[string]string{
		utils.FingerprintSHA256(alice): "alice (github:alice)",
		utils.FingerprintSHA256(dave):  "a guest with key SHA256:NjkIYAtFt4JkGVLZL0P8B0AXyCnb5oKDHh5H9yOF6/o from /home/owen/.ssh/authorized_keys",
		utils.FingerprintSHA256(bob):   "bob (gitea:bob@git.example.com)",
		utils.FingerprintSHA256(carol): "a guest with key " + utils.FingerprintSHA256(carol) + " from https://keys.example.com/carol.keys",
		utils.FingerprintSHA256(erin):  "a guest with key " + utils.FingerprintSHA256(erin),
	}, guestLabels(aks))
	assert.Empty(t, guestLabels(nil))
}
