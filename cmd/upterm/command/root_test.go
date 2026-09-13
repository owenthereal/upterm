package command

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withConfig points the XDG config directory at a temp dir holding body.
func withConfig(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	confDir := filepath.Join(dir, "upterm")
	require.NoError(t, os.MkdirAll(confDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(confDir, "config.yaml"), []byte(body), 0600))
}

func newTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "host", RunE: func(*cobra.Command, []string) error { return nil }}
	cmd.Flags().StringSlice("authorized-user", nil, "")
	cmd.Flags().StringSlice("private-key", nil, "")
	cmd.Flags().String("server", "", "")
	cmd.Flags().String("force-command", "", "")
	cmd.Flags().Bool("debug", false, "")
	return cmd
}

func Test_toStringSlice(t *testing.T) {
	cases := []struct {
		name          string
		val           any
		want          []string
		wantErrSubstr string
	}{
		{
			name: "comma-separated string keeps every element",
			val:  "github:alice,github:bob",
			want: []string{"github:alice", "github:bob"},
		},
		{
			name: "spaces around elements are trimmed",
			val:  "github:alice, github:bob",
			want: []string{"github:alice", "github:bob"},
		},
		{
			name: "yaml sequence passes through unsplit",
			val:  []any{"github:alice", "https://git.corp.com/a,b"},
			want: []string{"github:alice", "https://git.corp.com/a,b"},
		},
		{name: "string slice passes through", val: []string{"a"}, want: []string{"a"}},
		{
			name:          "mapping where a list belongs is an error",
			val:           map[string]any{"github": "alice"},
			wantErrSubstr: "expected a list or comma-separated string",
		},
		{
			name:          "non-string element is an error",
			val:           []any{"github:alice", 42},
			wantErrSubstr: "expected a string, got int",
		},
		{
			name:          "empty element is an error",
			val:           "github:alice,,github:bob",
			wantErrSubstr: "empty element",
		},
		{
			// pflag parses string slices with encoding/csv, so a quoted field
			// containing a comma is valid input today and must stay valid.
			name: "quoted field keeps its comma",
			val:  `"/tmp/key,one",/tmp/key2`,
			want: []string{"/tmp/key,one", "/tmp/key2"},
		},
		{
			name:          "malformed quoting is an error",
			val:           `"/tmp/unterminated`,
			wantErrSubstr: "cannot parse",
		},
		{
			// csv.Reader.Read returns the first record only, so a newline-
			// separated UPTERM_AUTHORIZED_USER used to drop everything after
			// the first line and shorten the authorization list in silence.
			name:          "a second line is an error rather than a truncation",
			val:           "github:alice\ngithub:bob",
			wantErrSubstr: "unexpected newline",
		},
		{
			name: "a trailing newline is not a second line",
			val:  "github:alice,github:bob\n",
			want: []string{"github:alice", "github:bob"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := toStringSlice("authorized-user", c.val)
			if c.wantErrSubstr != "" {
				assert.ErrorContains(t, err, c.wantErrSubstr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

func Test_toScalarString(t *testing.T) {
	cases := []struct {
		name          string
		val           any
		want          string
		wantErrSubstr string
	}{
		{name: "bool true", val: true, want: "true"},
		{name: "bool false", val: false, want: "false"},
		{name: "string", val: "/bin/bash -l", want: "/bin/bash -l"},
		{name: "int", val: 8443, want: "8443"},
		{
			// The message has to name the fix, not only the problem: this was
			// the form exampleConfig() documented until strict ingestion
			// landed, so existing configs hit it.
			name:          "yaml sequence is an error naming the single-string form",
			val:           []any{"/bin/bash", "-l"},
			wantErrSubstr: `expected a single value, got []interface {}; write it as a single string, e.g. force-command: "/bin/bash -l"`,
		},
		{
			name:          "string slice is an error naming the single-string form",
			val:           []string{"/bin/bash", "-l"},
			wantErrSubstr: `expected a single value, got []string; write it as a single string, e.g. force-command: "/bin/bash -l"`,
		},
		{
			// An empty collection has nothing to suggest, so the advice stands
			// alone rather than suggesting `force-command: ""`.
			name:          "empty sequence is an error with no example",
			val:           []any{},
			wantErrSubstr: "expected a single value, got []interface {}; write it as a single string",
		},
		{
			name:          "mapping is an error",
			val:           map[string]any{"a": "b"},
			wantErrSubstr: "expected a single value, got map[string]interface {}; write it as a single string",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := toScalarString("force-command", c.val)
			if c.wantErrSubstr != "" {
				assert.ErrorContains(t, err, c.wantErrSubstr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

func Test_bindFlagsToEnv_scalarFlagRejectsYAMLList(t *testing.T) {
	withConfig(t, `force-command: ["/bin/bash", "-l"]`+"\n")

	_, err := bindFlagsToEnv(newTestCmd())
	assert.ErrorContains(t, err, "force-command")
	assert.ErrorContains(t, err, `expected a single value, got []interface {}; write it as a single string, e.g. force-command: "/bin/bash -l"`)
}

func Test_bindFlagsToEnv_badEnvValueNamesTheEnvVar(t *testing.T) {
	withConfig(t, "")
	t.Setenv("UPTERM_DEBUG", "yes")

	_, err := bindFlagsToEnv(newTestCmd())
	assert.ErrorContains(t, err, "UPTERM_DEBUG")
	assert.ErrorContains(t, err, "debug")
}

func Test_bindFlagsToEnv_badConfigValueNamesTheConfigFile(t *testing.T) {
	withConfig(t, "debug: yes\n")

	_, err := bindFlagsToEnv(newTestCmd())
	assert.ErrorContains(t, err, utils.UptermConfigFilePath())
	assert.ErrorContains(t, err, "debug")
}

func Test_bindFlagsToEnv_unknownConfigKeyIsFatal(t *testing.T) {
	withConfig(t, "authorized_user:\n  - github:alice\n")

	_, err := bindFlagsToEnv(newTestCmd())
	assert.ErrorContains(t, err, `unknown config key "authorized_user"`)
}

func Test_bindFlagsToEnv_unknownConfigKeyAcrossWholeCommandTree(t *testing.T) {
	// authorized-user lives on hostCmd's PersistentFlags, not root's. Running a
	// non-host command must still recognize it as a known key, or every config
	// containing it would be rejected by commands other than "host".
	withConfig(t, "authorized-user:\n  - github:alice\n")

	root := Root()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"version"})
	assert.NoError(t, root.Execute())
}

func Test_bindFlagsToEnv_unknownConfigKeySparesConfigPath(t *testing.T) {
	withConfig(t, "authorized_user:\n  - github:alice\n")

	root := Root()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"config", "path"})
	assert.NoError(t, root.Execute())
}

func Test_bindFlagsToEnv_yamlListIsNotFlattened(t *testing.T) {
	withConfig(t, "authorized-user:\n  - github:alice\n  - github:bob@ghe.corp.com\nprivate-key:\n  - /a/key1\n  - /a/key2\n")

	cmd := newTestCmd()
	supplied, err := bindFlagsToEnv(cmd)
	require.NoError(t, err)

	users, err := cmd.Flags().GetStringSlice("authorized-user")
	require.NoError(t, err)
	assert.Equal(t, []string{"github:alice", "github:bob@ghe.corp.com"}, users)

	// private-key is documented as a YAML list in the example config and was
	// flattened into one bracketed element by the previous CSV round trip.
	keys, err := cmd.Flags().GetStringSlice("private-key")
	require.NoError(t, err)
	assert.Equal(t, []string{"/a/key1", "/a/key2"}, keys)

	assert.True(t, supplied["authorized-user"])
}

func Test_bindFlagsToEnv_envListIsCommaSeparated(t *testing.T) {
	withConfig(t, "")
	t.Setenv("UPTERM_AUTHORIZED_USER", "github:alice,github:bob")

	cmd := newTestCmd()
	supplied, err := bindFlagsToEnv(cmd)
	require.NoError(t, err)

	users, err := cmd.Flags().GetStringSlice("authorized-user")
	require.NoError(t, err)
	assert.Equal(t, []string{"github:alice", "github:bob"}, users)
	assert.True(t, supplied["authorized-user"])
}

func Test_bindFlagsToEnv_malformedConfigIsFatal(t *testing.T) {
	withConfig(t, "authorized-user: [unclosed\n")

	_, err := bindFlagsToEnv(newTestCmd())
	assert.ErrorContains(t, err, "failed to read config file")
}

func Test_bindFlagsToEnv_unreadableConfigIsFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}

	withConfig(t, "authorized-user:\n  - github:alice\n")

	// Make the config directory unreadable. Both the read and a stat probe now
	// fail, so treating absence as "stat failed" would drop the restriction.
	confDir := filepath.Dir(utils.UptermConfigFilePath())
	require.NoError(t, os.Chmod(confDir, 0o000))
	t.Cleanup(func() { _ = os.Chmod(confDir, 0o755) })

	_, err := bindFlagsToEnv(newTestCmd())
	assert.ErrorContains(t, err, "failed to read config file")
}

func Test_bindFlagsToEnv_missingConfigIsFine(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	supplied, err := bindFlagsToEnv(newTestCmd())
	require.NoError(t, err)
	assert.Empty(t, supplied)
}

func Test_bindFlagsToEnv_nullConfigValueIsRejected(t *testing.T) {
	// viper reports IsSet=false AND InConfig=false for a null value; only
	// AllKeys sees the key. Skipping it would drop the restriction silently.
	withConfig(t, "authorized-user:\n")

	supplied, err := bindFlagsToEnv(newTestCmd())
	assert.ErrorContains(t, err, "config key has no value")
	assert.True(t, supplied["authorized-user"],
		"presence must be recorded even when the value is unusable")
}

func Test_bindFlagsToEnv_emptyEnvVarIsStillSupplied(t *testing.T) {
	withConfig(t, "")
	t.Setenv("UPTERM_AUTHORIZED_USER", "")

	cmd := newTestCmd()
	supplied, err := bindFlagsToEnv(cmd)
	require.NoError(t, err)

	// viper treats an empty env var as unset, so without the direct LookupEnv
	// this source would vanish and the guard would never fire.
	assert.True(t, supplied["authorized-user"])

	// Inspect the same command that was bound, not a fresh one.
	users, err := cmd.Flags().GetStringSlice("authorized-user")
	require.NoError(t, err)
	assert.Empty(t, users)
}

func Test_bindFlagsToEnv_recordsExplicitCLIFlags(t *testing.T) {
	withConfig(t, "")

	cmd := newTestCmd()
	require.NoError(t, cmd.Flags().Set("authorized-user", "github:alice"))

	supplied, err := bindFlagsToEnv(cmd)
	require.NoError(t, err)

	// The sync loop skips flags that are already Changed, so without an
	// explicit seed a command-line flag would never be recorded.
	assert.True(t, supplied["authorized-user"])
}

func Test_isConfigCommand(t *testing.T) {
	root := &cobra.Command{Use: "upterm"}
	cfg := &cobra.Command{Use: "config"}
	edit := &cobra.Command{Use: "edit"}
	hostCmd := &cobra.Command{Use: "host"}

	cfg.AddCommand(edit)
	root.AddCommand(cfg, hostCmd)

	assert.True(t, isConfigCommand(cfg))
	assert.True(t, isConfigCommand(edit))
	assert.False(t, isConfigCommand(hostCmd))
}

func Test_persistentPreRun_malformedConfigSpares_configCommands(t *testing.T) {
	withConfig(t, "authorized-user: [unclosed\n")

	// `config edit` launches $VISUAL. `true` exits 0 without touching the file,
	// which keeps the test from opening an editor while still exercising the
	// whole handler, including its post-edit validation warning.
	t.Setenv("VISUAL", "true")

	// All three must stay reachable: they are the commands you need in order to
	// repair a broken config file. view and edit are the ones that read or
	// rewrite its contents, so losing either leaves a user with a bricked file
	// and no way to see or fix it from upterm.
	for _, args := range [][]string{
		{"config", "path"},
		{"config", "view"},
		{"config", "edit"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			root := Root()
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			root.SetArgs(args)
			assert.NoError(t, root.Execute())
		})
	}

	// Every other command must refuse, rather than silently dropping a
	// requested authorization restriction. Use `version` rather than
	// `host --help`: cobra short-circuits --help without running
	// PersistentPreRunE, so a help invocation would never reach ingestion.
	root2 := Root()
	root2.SetOut(io.Discard)
	root2.SetErr(io.Discard)
	root2.SetArgs([]string{"version"})
	err := root2.Execute()
	assert.ErrorContains(t, err, "failed to read config file")
}
