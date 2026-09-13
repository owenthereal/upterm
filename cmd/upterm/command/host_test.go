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

func Test_ResolveSessionName(t *testing.T) {
	require.Equal(t, "mine", resolveSessionName("mine", []string{"bash"}))
	require.Regexp(t, `^bash-[0-9a-f]{4}$`, resolveSessionName("", []string{"/bin/bash", "-l"}))
}

func Test_ResolveSessionName_RejectsUnsafeExplicitName(t *testing.T) {
	// The CLI must refuse early with a readable message rather than letting
	// Claim reject it after the process is already underway.
	require.Error(t, validateSessionNameFlag(".."))
	require.Error(t, validateSessionNameFlag("a/b"))
	require.NoError(t, validateSessionNameFlag(""))
	require.NoError(t, validateSessionNameFlag("demo"))
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

// Test_collectUserRefs_legacyFlagsMatchTheNewForm pins the compatibility
// requirement that --codeberg-user alice and --authorized-user codeberg:alice
// are the same request. It covers all four legacy flags because the only way
// the translation can break is a swapped entry in the legacyUserFlags table,
// which a github-only test would not catch.
func Test_collectUserRefs_legacyFlagsMatchTheNewForm(t *testing.T) {
	origAuthorized := flagAuthorizedUsers
	origCodeberg := flagCodebergUsers
	origGitHub := flagGitHubUsers
	origGitLab := flagGitLabUsers
	origSourceHut := flagSourceHutUsers
	t.Cleanup(func() {
		flagAuthorizedUsers = origAuthorized
		flagCodebergUsers = origCodeberg
		flagGitHubUsers = origGitHub
		flagGitLabUsers = origGitLab
		flagSourceHutUsers = origSourceHut
	})

	t.Setenv("GH_HOST", "github.com")

	resetAllUserFlags := func() {
		flagAuthorizedUsers = nil
		flagCodebergUsers = nil
		flagGitHubUsers = nil
		flagGitLabUsers = nil
		flagSourceHutUsers = nil
	}

	cases := []struct {
		name     string
		provider string
		values   *[]string
	}{
		{"codeberg", "codeberg", &flagCodebergUsers},
		{"github", "github", &flagGitHubUsers},
		{"gitlab", "gitlab", &flagGitLabUsers},
		{"srht", "srht", &flagSourceHutUsers},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// legacy form
			resetAllUserFlags()
			*c.values = []string{"alice"}
			viaLegacy, err := collectUserRefs()
			require.NoError(t, err)
			require.Len(t, viaLegacy, 1)

			// new form
			resetAllUserFlags()
			flagAuthorizedUsers = []string{c.provider + ":alice"}
			viaNew, err := collectUserRefs()
			require.NoError(t, err)
			require.Len(t, viaNew, 1)

			// Compare the whole UserRef, not just Display(): a swapped provider
			// in legacyUserFlags would still produce a plausible-looking Display()
			// string for the wrong provider, so only a full comparison catches it.
			assert.Equal(t, viaNew[0], viaLegacy[0],
				"the legacy flag must translate to exactly the new-form reference")
		})
	}
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

// Test_hostCmd_authorizedKeysErrorNamesTheFileOnce pins that shareRunE does not
// re-wrap an error AuthorizedKeysFromFile has already described.
func Test_hostCmd_authorizedKeysErrorNamesTheFileOnce(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	missing := filepath.Join(dir, "nope")

	root := Root()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"host", "--accept", "--authorized-keys", missing, "--", "true"})

	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error reading authorized keys file "+missing)
	assert.NotContains(t, err.Error(), "error reading authorized keys: error reading authorized keys")
}

// Test_hostCmd_legacyFlagsAreRegisteredAndHidden pins the MarkHidden loop
// against legacyUserFlags: the loop's only failure mode is a name that is not a
// registered flag, which MarkHidden reports by returning an error nobody reads.
func Test_hostCmd_legacyFlagsAreRegisteredAndHidden(t *testing.T) {
	cmd := hostCmd()

	for _, lf := range legacyUserFlags {
		t.Run(lf.flag, func(t *testing.T) {
			flag := cmd.PersistentFlags().Lookup(lf.flag)
			require.NotNil(t, flag, "legacyUserFlags names a flag that is not registered")
			assert.True(t, flag.Hidden, "superseded flags stay working but hidden")
		})
	}
}

// Test_hostCmd_authorizedUserNewlineIsAnError pins the reported defect: pflag's
// own stringSliceValue.Set reads only the first CSV record, so a newline used
// to silently drop everything after it ("github:alice\ngithub:bob" became
// just "github:alice") and the command proceeded to dial with bob never
// authorized. --server points at a port nothing can accept on, so if the
// value were ever silently truncated instead of rejected, this test would
// fail by observing a dial/connection error instead of a parse error naming
// the flag.
func Test_hostCmd_authorizedUserNewlineIsAnError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	root := Root()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"host", "--accept", "--server", "ssh://127.0.0.1:1",
		"--authorized-user", "github:alice\ngithub:bob",
		"--", "true",
	})

	err := root.Execute()
	require.Error(t, err)
	assert.ErrorContains(t, err, "authorized-user")
	assert.ErrorContains(t, err, "unexpected newline")
}

// Test_hostCmd_githubUserNewlineIsAnError is the same regression as
// Test_hostCmd_authorizedUserNewlineIsAnError, but for a legacy per-provider
// flag, since all five authorization flags share the same value type.
func Test_hostCmd_githubUserNewlineIsAnError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	root := Root()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"host", "--accept", "--server", "ssh://127.0.0.1:1",
		"--github-user", "alice\nbob",
		"--", "true",
	})

	err := root.Execute()
	require.Error(t, err)
	assert.ErrorContains(t, err, "github-user")
	assert.ErrorContains(t, err, "unexpected newline")
}

// Test_hostCmd_authorizedUserFlag_repeatedAppends pins pflag's repeat-flag
// semantics: the first Set replaces the (empty) default and every subsequent
// Set appends, so `--authorized-user a --authorized-user b` must yield both
// rather than just the last one.
func Test_hostCmd_authorizedUserFlag_repeatedAppends(t *testing.T) {
	orig := flagAuthorizedUsers
	t.Cleanup(func() { flagAuthorizedUsers = orig })

	cmd := hostCmd()
	require.NoError(t, cmd.PersistentFlags().Set("authorized-user", "github:alice"))
	require.NoError(t, cmd.PersistentFlags().Set("authorized-user", "github:bob"))

	assert.Equal(t, []string{"github:alice", "github:bob"}, flagAuthorizedUsers)

	refs, err := collectUserRefs()
	require.NoError(t, err)
	assert.Len(t, refs, 2)
}

// Test_hostCmd_authorizedUserFlag_quotedCommaSurvives pins that switching to
// splitCSV did not regress pflag's own CSV-quoting behavior: a single element
// containing a comma, written with CSV quotes, must still come through as one
// element rather than being split on the embedded comma.
func Test_hostCmd_authorizedUserFlag_quotedCommaSurvives(t *testing.T) {
	orig := flagAuthorizedUsers
	t.Cleanup(func() { flagAuthorizedUsers = orig })

	cmd := hostCmd()
	require.NoError(t, cmd.PersistentFlags().Set("authorized-user", `"gitea:bob,carol@git.corp.com"`))

	assert.Equal(t, []string{"gitea:bob,carol@git.corp.com"}, flagAuthorizedUsers)
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

// Test_hostCmd_guardCoversEveryAuthorizationFlag drives every flag that asks
// for a restriction, because authorizationRequested() is a list of names and a
// name missing from it fails open: an empty value supplies the flag, resolves
// no keys, errors nowhere earlier, and the session then accepts any client
// holding the token. Only --github-user was covered before, so mutating the
// other three names left the whole suite green.
func Test_hostCmd_guardCoversEveryAuthorizationFlag(t *testing.T) {
	const wantErr = "authorization was requested but no public keys were resolved"

	// A port nothing can accept on: should the guard ever fail to fire, the
	// command proceeds to dial and the test fails loudly instead of hanging or
	// reaching a real server.
	const unreachable = "ssh://127.0.0.1:1"

	flags := []string{"authorized-keys", "authorized-user"}
	for _, lf := range legacyUserFlags {
		flags = append(flags, lf.flag)
	}
	require.Len(t, flags, 6, "every authorization flag must be exercised")

	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())

			root := Root()
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			// An empty value, including for --authorized-keys: pflag records
			// Changed, shareRunE reads no file and parses no reference, so the
			// guard is the only thing standing between this and a session that
			// accepts anyone. (An empty authorized_keys *file* fails earlier,
			// inside AuthorizedKeysFromFile — covered above.)
			root.SetArgs([]string{"host", "--accept", "--server", unreachable, "--" + name, "", "--", "true"})

			assert.ErrorContains(t, root.Execute(), wantErr)
		})
	}
}
