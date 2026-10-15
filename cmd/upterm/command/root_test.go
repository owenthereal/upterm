package command

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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

	_, _, err := bindFlagsToEnv(newTestCmd())
	assert.ErrorContains(t, err, "force-command")
	assert.ErrorContains(t, err, `expected a single value, got []interface {}; write it as a single string, e.g. force-command: "/bin/bash -l"`)
}

func Test_bindFlagsToEnv_badEnvValueNamesTheEnvVar(t *testing.T) {
	withConfig(t, "")
	t.Setenv("UPTERM_DEBUG", "yes")

	_, _, err := bindFlagsToEnv(newTestCmd())
	assert.ErrorContains(t, err, "UPTERM_DEBUG")
	assert.ErrorContains(t, err, "debug")
}

func Test_bindFlagsToEnv_badConfigValueNamesTheConfigFile(t *testing.T) {
	withConfig(t, "debug: yes\n")

	_, _, err := bindFlagsToEnv(newTestCmd())
	assert.ErrorContains(t, err, utils.UptermConfigFilePath())
	assert.ErrorContains(t, err, "debug")
}

func Test_bindFlagsToEnv_unknownConfigKeyIsFatal(t *testing.T) {
	withConfig(t, "authorized_user:\n  - github:alice\n")

	_, _, err := bindFlagsToEnv(newTestCmd())
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
	supplied, _, err := bindFlagsToEnv(cmd)
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
	supplied, _, err := bindFlagsToEnv(cmd)
	require.NoError(t, err)

	users, err := cmd.Flags().GetStringSlice("authorized-user")
	require.NoError(t, err)
	assert.Equal(t, []string{"github:alice", "github:bob"}, users)
	assert.True(t, supplied["authorized-user"])
}

func Test_bindFlagsToEnv_malformedConfigIsFatal(t *testing.T) {
	withConfig(t, "authorized-user: [unclosed\n")

	_, _, err := bindFlagsToEnv(newTestCmd())
	assert.ErrorContains(t, err, "failed to read config file")
}

func Test_bindFlagsToEnv_unreadableConfigIsFatal(t *testing.T) {
	// Windows has no POSIX permission bits: os.Chmod only toggles the
	// read-only attribute and cannot make a directory unreadable, so the config
	// stays readable and there is nothing to assert. The root check below does
	// not cover it either, because os.Geteuid returns -1 there.
	// Test_bindFlagsToEnv_configThatIsNotAFileIsFatal covers the same
	// read-error-is-fatal rule on every platform.
	if runtime.GOOS == "windows" {
		t.Skip("chmod cannot make a directory unreadable on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}

	withConfig(t, "authorized-user:\n  - github:alice\n")

	// Make the config directory unreadable. Both the read and a stat probe now
	// fail, so treating absence as "stat failed" would drop the restriction.
	confDir := filepath.Dir(utils.UptermConfigFilePath())
	require.NoError(t, os.Chmod(confDir, 0o000))
	t.Cleanup(func() { _ = os.Chmod(confDir, 0o755) })

	_, _, err := bindFlagsToEnv(newTestCmd())
	assert.ErrorContains(t, err, "failed to read config file")
}

// Test_bindFlagsToEnv_configThatIsNotAFileIsFatal pins the same rule as the
// test above — a read failure that is not "does not exist" aborts rather than
// silently continuing — without depending on POSIX permissions, so it also
// runs on Windows.
func Test_bindFlagsToEnv_configThatIsNotAFileIsFatal(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	// A directory standing where the config file belongs. Opening it succeeds
	// and reading it fails with something that is not fs.ErrNotExist on every
	// platform, which is exactly the case errors.Is must not mistake for absence.
	require.NoError(t, os.MkdirAll(utils.UptermConfigFilePath(), 0o755))

	_, _, err := bindFlagsToEnv(newTestCmd())
	assert.ErrorContains(t, err, "failed to read config file")
}

func Test_bindFlagsToEnv_missingConfigIsFine(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	supplied, _, err := bindFlagsToEnv(newTestCmd())
	require.NoError(t, err)
	assert.Empty(t, supplied)
}

func Test_bindFlagsToEnv_nullConfigValueIsRejected(t *testing.T) {
	// viper reports IsSet=false AND InConfig=false for a null value; only
	// AllKeys sees the key. Skipping it would drop the restriction silently.
	withConfig(t, "authorized-user:\n")

	supplied, _, err := bindFlagsToEnv(newTestCmd())
	assert.ErrorContains(t, err, "config key has no value")
	assert.True(t, supplied["authorized-user"],
		"presence must be recorded even when the value is unusable")
}

func Test_bindFlagsToEnv_emptyEnvVarIsStillSupplied(t *testing.T) {
	withConfig(t, "")
	t.Setenv("UPTERM_AUTHORIZED_USER", "")

	cmd := newTestCmd()
	supplied, _, err := bindFlagsToEnv(cmd)
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

	supplied, _, err := bindFlagsToEnv(cmd)
	require.NoError(t, err)

	// The sync loop skips flags that are already Changed, so without an
	// explicit seed a command-line flag would never be recorded.
	assert.True(t, supplied["authorized-user"])
}

// newSliceDefaultCmd is newTestCmd with non-empty defaults on private-key and
// server, which is what the real host command has: the ~/.ssh/id_* files that
// exist, and the public relay.
func newSliceDefaultCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "host", RunE: func(*cobra.Command, []string) error { return nil }}
	cmd.Flags().StringSlice("authorized-user", nil, "")
	cmd.Flags().StringSlice("private-key", []string{"/default/id_ed25519"}, "")
	cmd.Flags().String("server", "ssh://default", "")
	cmd.Flags().String("force-command", "", "")
	cmd.Flags().Bool("debug", false, "")
	return cmd
}

func Test_bindFlagsToEnv_emptyEnvVarAloneEmptiesASliceFlag(t *testing.T) {
	withConfig(t, "")
	t.Setenv("UPTERM_PRIVATE_KEY", "")

	cmd := newSliceDefaultCmd()
	supplied, _, err := bindFlagsToEnv(cmd)
	require.NoError(t, err)
	assert.True(t, supplied["private-key"])

	// The variable named an empty list; the default is not what it said.
	keys, err := cmd.Flags().GetStringSlice("private-key")
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func Test_bindFlagsToEnv_emptyEnvVarKeepsAConfigValue(t *testing.T) {
	withConfig(t, "private-key: [/from/config]\nauthorized-user: [github:alice]\n")
	t.Setenv("UPTERM_PRIVATE_KEY", "")
	t.Setenv("UPTERM_AUTHORIZED_USER", "")

	cmd := newSliceDefaultCmd()
	supplied, _, err := bindFlagsToEnv(cmd)
	require.NoError(t, err)
	assert.True(t, supplied["private-key"])
	assert.True(t, supplied["authorized-user"])

	keys, err := cmd.Flags().GetStringSlice("private-key")
	require.NoError(t, err)
	assert.Equal(t, []string{"/from/config"}, keys, "config outranks an empty variable, as it does today")
	users, err := cmd.Flags().GetStringSlice("authorized-user")
	require.NoError(t, err)
	assert.Equal(t, []string{"github:alice"}, users)
}

func Test_bindFlagsToEnv_emptyEnvVarKeepsACLIValue(t *testing.T) {
	withConfig(t, "")
	t.Setenv("UPTERM_PRIVATE_KEY", "")
	t.Setenv("UPTERM_AUTHORIZED_USER", "")

	cmd := newSliceDefaultCmd()
	require.NoError(t, cmd.Flags().Set("private-key", "/from/cli"))
	require.NoError(t, cmd.Flags().Set("authorized-user", "github:bob"))
	supplied, _, err := bindFlagsToEnv(cmd)
	require.NoError(t, err)
	assert.True(t, supplied["private-key"])

	keys, err := cmd.Flags().GetStringSlice("private-key")
	require.NoError(t, err)
	assert.Equal(t, []string{"/from/cli"}, keys)
	users, err := cmd.Flags().GetStringSlice("authorized-user")
	require.NoError(t, err)
	assert.Equal(t, []string{"github:bob"}, users)
}

func Test_bindFlagsToEnv_emptyEnvVarLeavesScalarsAlone(t *testing.T) {
	withConfig(t, "")
	t.Setenv("UPTERM_SERVER", "")

	cmd := newSliceDefaultCmd()
	supplied, _, err := bindFlagsToEnv(cmd)
	require.NoError(t, err)
	assert.True(t, supplied["server"])

	server, err := cmd.Flags().GetString("server")
	require.NoError(t, err)
	assert.Equal(t, "ssh://default", server, "there is no empty value a scalar sensibly takes here")
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
	// whole handler, including its check of the file afterwards.
	t.Setenv("VISUAL", "true")

	// All three must stay reachable: they are the commands you need in order to
	// repair a broken config file. view and edit are the ones that read or
	// rewrite its contents, so losing either leaves a user with a bricked file
	// and no way to see or fix it from upterm.
	for _, args := range [][]string{
		{"config", "path"},
		{"config", "view"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			root := Root()
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			root.SetArgs(args)
			assert.NoError(t, root.Execute())
		})
	}

	// edit opens the editor on the broken file, and then says what is wrong
	// with it: its own report, not the refusal other commands give.
	t.Run("config edit", func(t *testing.T) {
		root := Root()
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs([]string{"config", "edit"})
		err := root.Execute()
		assert.ErrorContains(t, err, "; run upterm config edit to fix it")
		assert.NotContains(t, err.Error(), "failed to read config file")
	})

	// version reads no config, so it doesn't fail on one either.
	root2 := Root()
	root2.SetOut(io.Discard)
	root2.SetErr(io.Discard)
	root2.SetArgs([]string{"version"})
	assert.NoError(t, root2.Execute())

	// A command that reads it must refuse, rather than silently dropping a
	// requested authorization restriction. Not `host --help`: cobra
	// short-circuits --help without running PersistentPreRunE, so a help
	// invocation would never reach ingestion.
	root3 := Root()
	root3.SetOut(io.Discard)
	root3.SetErr(io.Discard)
	root3.SetArgs([]string{"session", "list"})
	assert.ErrorContains(t, root3.Execute(), "failed to read config file")
}

// Exactly these flags are per-run; every other flag stays bound, host's
// --join-timeout included (CI sets it).
func TestPerRunFlagsAreExactlyTheRunsOwnChoices(t *testing.T) {
	var got []string
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if _, ok := f.Annotations[annotationPerRun]; ok {
				got = append(got, c.CommandPath()+" --"+f.Name)
			}
		})
		for _, child := range c.Commands() {
			walk(child)
		}
	}
	walk(Root())
	require.ElementsMatch(t, []string{
		"upterm host --detach", "upterm host --name", "upterm host --output",
		"upterm join --wait",
		"upterm session current --output", "upterm session info --output",
		"upterm session set --join-timeout",
	}, got)
}

func TestPerRunEnvStillAppliesWithAWarning(t *testing.T) {
	t.Setenv("UPTERM_JOIN_TIMEOUT", "10m")
	setupSessionRoots(t)
	withConfig(t, "")
	_, stderr, code := runCLI(t, "session", "set", "nosuch")
	require.Equal(t, 4, code) // the value still applies: set looks the name up
	require.Contains(t, stderr, "upterm: UPTERM_JOIN_TIMEOUT is deprecated for upterm session set; pass --join-timeout. It will be ignored there starting in "+perRunIgnoredFrom+".\n")
}

func TestPerRunConfigNamesTheFile(t *testing.T) {
	prevOutput := flagOutput
	t.Cleanup(func() { flagOutput = prevOutput })
	setupSessionRoots(t)
	withConfig(t, "output: json\n")
	_, stderr, code := runCLI(t, "session", "info", "nosuch")
	require.Equal(t, 4, code) // the lookup fails, with the value or without it
	require.Contains(t, stderr, "upterm: the output key in "+utils.UptermConfigFilePath()+" is deprecated; pass --output. It will be ignored starting in "+perRunIgnoredFrom+".\n")

	// A config value alone still applies: without it, set would have nothing
	// to set (exit 1), not a name to look up.
	t.Setenv("UPTERM_JOIN_TIMEOUT", "")
	require.NoError(t, os.Unsetenv("UPTERM_JOIN_TIMEOUT"))
	withConfig(t, "join-timeout: 5m\n")
	_, stderr, code = runCLI(t, "session", "set", "nosuch")
	require.Equal(t, 4, code, stderr)
	require.Contains(t, stderr, "upterm: the join-timeout key in "+utils.UptermConfigFilePath()+" is deprecated for upterm session set; pass --join-timeout. It will be ignored there starting in "+perRunIgnoredFrom+".\n")
}

// Each value env and config hold is one line, the one that applies and the
// one it overrides alike: both stop being read in the same release. A value
// on the command line outranks them both, and nothing is said.
func TestPerRunWarnsOncePerValue(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "join-timeout: 5m\n")
	t.Setenv("UPTERM_JOIN_TIMEOUT", "10m")
	_, stderr, code := runCLI(t, "session", "set", "nosuch")
	require.Equal(t, 4, code)
	require.Equal(t, "upterm: UPTERM_JOIN_TIMEOUT is deprecated for upterm session set; pass --join-timeout. It will be ignored there starting in "+perRunIgnoredFrom+".\n"+
		"upterm: the join-timeout key in "+utils.UptermConfigFilePath()+" is deprecated for upterm session set; pass --join-timeout. It will be ignored there starting in "+perRunIgnoredFrom+".\n"+
		"upterm: no session named \"nosuch\"\n", stderr)

	_, stderr, code = runCLI(t, "session", "set", "nosuch", "--join-timeout", "1m")
	require.Equal(t, 4, code)
	require.Equal(t, "upterm: no session named \"nosuch\"\n", stderr)
}

// The daemon re-parses the same argv, env and config, and applies the same
// values; only the parent warns, since the daemon's stderr is the log.
func TestPerRunWarningsAreTheParentsOnly(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	t.Setenv("UPTERM_JOIN_TIMEOUT", "10m")
	_, stderr, code := runCLI(t, "session", "set", "nosuch")
	require.Equal(t, 4, code)
	require.Equal(t, 1, strings.Count(stderr, "UPTERM_JOIN_TIMEOUT is deprecated"), stderr)

	t.Setenv(daemonHandoffEnv, "3")
	_, stderr, code = runCLI(t, "session", "set", "nosuch")
	require.Equal(t, 4, code) // applied all the same
	require.Equal(t, "upterm: no session named \"nosuch\"\n", stderr)
}

// A CLI-only flag is never bound to env or config: an `output:` key or
// UPTERM_OUTPUT meant for another command would otherwise change or break a
// command that never asked for it. The name stays a known config key, which
// another command may own, so `output:` in a config neither sets the flag nor
// fails the run.
func TestCLIOnlyFlagsIgnoreEnvAndConfig(t *testing.T) {
	withConfig(t, "output: json\n")
	cmd := &cobra.Command{Use: "probe", RunE: func(*cobra.Command, []string) error { return nil }}
	var out string
	cmd.Flags().StringVarP(&out, "output", "o", "", "")
	require.NoError(t, cmd.Flags().SetAnnotation("output", annotationCLIOnly, []string{"true"}))
	t.Setenv("UPTERM_OUTPUT", "json")
	supplied, deps, err := bindFlagsToEnv(cmd)
	require.NoError(t, err)
	require.Empty(t, out)
	require.False(t, supplied["output"])
	require.Empty(t, deps)
}
