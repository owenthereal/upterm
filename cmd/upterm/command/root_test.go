package command

import (
	"io"
	"os"
	"path/filepath"
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

	root := Root()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)

	// `upterm config path` must still reach its handler: it is one of the
	// commands you need in order to repair a broken config file.
	root.SetArgs([]string{"config", "path"})
	assert.NoError(t, root.Execute())

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
