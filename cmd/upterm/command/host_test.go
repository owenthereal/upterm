package command

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/owenthereal/upterm/host"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func Test_validateShareRequiredFlags_readOnlyAndLocalTCPForwarding(t *testing.T) {
	origServer := flagServer
	origReadOnly := flagReadOnly
	origAllowLocalTCPForwarding := flagAllowLocalTCPForwarding
	t.Cleanup(func() {
		flagServer = origServer
		flagReadOnly = origReadOnly
		flagAllowLocalTCPForwarding = origAllowLocalTCPForwarding
	})

	flagServer = "ssh://uptermd.upterm.dev:22"

	cases := []struct {
		name                    string
		readOnly                bool
		allowLocalTCPForwarding bool
		wantErrSubstr           string
	}{
		{name: "neither", readOnly: false, allowLocalTCPForwarding: false},
		{name: "read-only only", readOnly: true, allowLocalTCPForwarding: false},
		{name: "forwarding only", readOnly: false, allowLocalTCPForwarding: true},
		{
			name:                    "both rejected",
			readOnly:                true,
			allowLocalTCPForwarding: true,
			wantErrSubstr:           "--read-only and --allow-local-tcp-forwarding cannot be used together",
		},
	}

	for _, c := range cases {
		cc := c
		t.Run(cc.name, func(t *testing.T) {
			flagReadOnly = cc.readOnly
			flagAllowLocalTCPForwarding = cc.allowLocalTCPForwarding

			err := validateShareRequiredFlags(nil, nil)
			if cc.wantErrSubstr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, cc.wantErrSubstr)
		})
	}
}

func Test_parseURL(t *testing.T) {
	cases := []struct {
		name       string
		url        string
		wantScheme string
		wantHost   string
		wantPort   string
	}{
		{
			name:       "port 443",
			url:        "wss://foo.com:443",
			wantScheme: "wss",
			wantHost:   "foo.com",
			wantPort:   "443",
		},
		{
			name:       "port 80",
			url:        "http://foo.com:80",
			wantScheme: "http",
			wantHost:   "foo.com",
			wantPort:   "80",
		},
		{
			name:       "port 22",
			url:        "ssh://foo.com:22",
			wantScheme: "ssh",
			wantHost:   "foo.com",
			wantPort:   "22",
		},
		{
			name:       "no port",
			url:        "wss://foo.com",
			wantScheme: "wss",
			wantHost:   "foo.com",
			wantPort:   "443",
		},
	}

	for _, c := range cases {
		cc := c
		t.Run(cc.name, func(t *testing.T) {
			t.Parallel()

			_, scheme, host, port, err := parseURL(cc.url)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(cc.wantScheme, scheme); diff != "" {
				t.Fatal(diff)
			}

			if diff := cmp.Diff(cc.wantHost, host); diff != "" {
				t.Fatal(diff)
			}

			if diff := cmp.Diff(cc.wantPort, port); diff != "" {
				t.Fatal(diff)
			}
		})
	}

}

func Test_collectUserRefs(t *testing.T) {
	origAuthorized := flagAuthorizedUsers
	origGitHub := flagGitHubUsers
	origSourceHut := flagSourceHutUsers
	t.Cleanup(func() {
		flagAuthorizedUsers = origAuthorized
		flagGitHubUsers = origGitHub
		flagSourceHutUsers = origSourceHut
	})

	t.Setenv("GH_HOST", "github.com")

	flagAuthorizedUsers = []string{"github:alice", "gitea:carol@git.corp.com"}
	flagGitHubUsers = []string{"bob"}
	flagSourceHutUsers = []string{"dave"}

	refs, err := collectUserRefs()
	require.NoError(t, err)

	got := make([]string, 0, len(refs))
	for _, r := range refs {
		got = append(got, r.Display())
	}

	// Legacy per-provider flags translate into the same grammar and append
	// after the new flag's values.
	assert.Equal(t, []string{
		"github:alice@github.com",
		"gitea:carol@git.corp.com",
		"github:bob@github.com",
		"srht:dave@meta.sr.ht",
	}, got)
}

func Test_collectUserRefs_reportsEveryBadReference(t *testing.T) {
	origAuthorized := flagAuthorizedUsers
	t.Cleanup(func() { flagAuthorizedUsers = origAuthorized })

	flagAuthorizedUsers = []string{"nope", "gitea:alice", "http://git.corp.com/bob"}

	_, err := collectUserRefs()
	require.Error(t, err)
	assert.ErrorContains(t, err, "missing provider")
	assert.ErrorContains(t, err, "requires a host")
	assert.ErrorContains(t, err, "refusing to fetch keys over http://")
}

func Test_authorizationRequested(t *testing.T) {
	orig := suppliedFlags
	t.Cleanup(func() { suppliedFlags = orig })

	suppliedFlags = map[string]bool{}
	assert.False(t, authorizationRequested())

	// A flag set on the command line is recorded via the flag.Changed seed,
	// which is the only origin that sees it.
	suppliedFlags = map[string]bool{"authorized-keys": true}
	assert.True(t, authorizationRequested())

	suppliedFlags = map[string]bool{"github-user": true}
	assert.True(t, authorizationRequested())

	suppliedFlags = map[string]bool{"read-only": true}
	assert.False(t, authorizationRequested())
}

func Test_countKeys_ignoresNilEntries(t *testing.T) {
	assert.Zero(t, countKeys(nil))
	assert.Zero(t, countKeys([]*host.AuthorizedKey{nil}))
	assert.Equal(t, 1, countKeys([]*host.AuthorizedKey{{PublicKeys: []ssh.PublicKey{nil}}}))
}

// Test_hostCmd_refusesEmptyAuthorization exercises the real path from
// command-line parsing through ingestion to refusal, rather than populating
// suppliedFlags by hand. --accept keeps it non-interactive, and every case
// fails before any network call.
func Test_hostCmd_refusesEmptyAuthorization(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	emptyKeys := filepath.Join(dir, "empty.keys")
	require.NoError(t, os.WriteFile(emptyKeys, nil, 0600))

	cases := []struct {
		name          string
		args          []string
		wantErrSubstr string
	}{
		{
			name:          "empty authorized_keys file",
			args:          []string{"host", "--accept", "--authorized-keys", emptyKeys, "--", "true"},
			wantErrSubstr: "no public keys found",
		},
		{
			name:          "missing authorized_keys file",
			args:          []string{"host", "--accept", "--authorized-keys", filepath.Join(dir, "nope"), "--", "true"},
			wantErrSubstr: "error reading authorized keys",
		},
		{
			name:          "unparseable reference",
			args:          []string{"host", "--accept", "--authorized-user", "nonsense", "--", "true"},
			wantErrSubstr: "missing provider",
		},
		{
			name:          "plaintext reference",
			args:          []string{"host", "--accept", "--authorized-user", "http://git.corp.com/bob", "--", "true"},
			wantErrSubstr: "refusing to fetch keys over http://",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := Root()
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			root.SetArgs(c.args)

			err := root.Execute()
			assert.ErrorContains(t, err, c.wantErrSubstr)
		})
	}
}

// Test_hostCmd_guardRefusesWhenRequestedButEmpty reaches the guard itself.
//
// An empty flag value supplies the flag — pflag records Changed and stores an
// empty slice — while producing no references at all, so no parser runs and
// nothing errors earlier. Deleting the guard branch makes these cases start a
// session that accepts any client, so they must go through Root().Execute()
// rather than asserting on helpers.
func Test_hostCmd_guardRefusesWhenRequestedButEmpty(t *testing.T) {
	const wantErr = "authorization was requested but no public keys were resolved"

	t.Run("empty flag value", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())

		root := Root()
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs([]string{"host", "--accept", "--authorized-user", "", "--", "true"})

		assert.ErrorContains(t, root.Execute(), wantErr)
	})

	t.Run("empty config list", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", dir)

		confDir := filepath.Join(dir, "upterm")
		require.NoError(t, os.MkdirAll(confDir, 0o755))
		require.NoError(t, os.WriteFile(
			filepath.Join(confDir, "config.yaml"), []byte("authorized-user: []\n"), 0o600))

		root := Root()
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs([]string{"host", "--accept", "--", "true"})

		assert.ErrorContains(t, root.Execute(), wantErr)
	})

	t.Run("empty environment variable", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		t.Setenv("UPTERM_AUTHORIZED_USER", "")

		root := Root()
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs([]string{"host", "--accept", "--", "true"})

		assert.ErrorContains(t, root.Execute(), wantErr)
	})
}
