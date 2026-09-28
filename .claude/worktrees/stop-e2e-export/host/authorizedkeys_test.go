package host

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
