package command

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

// restoreFlags leaves every flag variable as a freshly built command tree
// has it when the test ends. Checking a config file applies its values to the
// flags' variables, and building the tree sets each back to its default, which
// is what tests that read them without building a command expect.
// TestBuildingTheRootResetsEveryFlagAConfigSets shows that it covers them all.
// Call it before the test sets any environment, so the tree is built under the
// environment the test started in.
func restoreFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { _ = Root() })
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// flagValues is the value of every flag in the tree, by command and name.
func flagValues(root *cobra.Command) map[string]string {
	values := make(map[string]string)
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, fs := range []*pflag.FlagSet{c.Flags(), c.PersistentFlags()} {
			fs.VisitAll(func(f *pflag.Flag) { values[c.CommandPath()+" --"+f.Name] = f.Value.String() })
		}
		for _, child := range c.Commands() {
			walk(child)
		}
	}
	walk(root)
	return values
}

// A file can set any flag that env and config bind, so building the tree must
// reset all of them, or a test that checks a file leaves them set for the next.
func TestBuildingTheRootResetsEveryFlagAConfigSets(t *testing.T) {
	restoreFlags(t)
	root := Root()
	before := flagValues(root)

	var body strings.Builder
	seen := make(map[string]bool)
	visitTreeFlags(root, func(f *pflag.Flag) {
		if f.Name == "help" || hasAnnotation(f, annotationCLIOnly) || seen[f.Name] {
			return
		}
		seen[f.Name] = true
		value := "x"
		switch f.Value.Type() {
		case "bool":
			value = "true"
		case "duration":
			value = "1s"
		case "stringSlice":
			value = "[x]"
		}
		fmt.Fprintf(&body, "%s: %s\n", f.Name, value)
	})
	validateConfigFile(root, writeConfig(t, body.String()))

	dirty := 0
	for name, value := range flagValues(root) {
		if value != before[name] {
			dirty++
		}
	}
	require.Greater(t, dirty, 10, "the file set the flags")

	require.Equal(t, before, flagValues(Root()))
}

func TestEveryProblemIsNamed(t *testing.T) {
	restoreFlags(t)
	path := writeConfig(t, "bogus-key: 1\nread-only: maybe\nzzz: 2\n")
	errs := validateConfigFile(Root(), path)
	require.Len(t, errs, 3)
	require.Contains(t, errs[0].Error(), `unknown key "bogus-key"`)
	require.Contains(t, errs[1].Error(), "read-only")
	require.Contains(t, errs[2].Error(), `unknown key "zzz"`)
	require.Equal(t, path+`: unknown key "bogus-key"; run upterm config edit to fix it`, errs[0].Error())
}

func TestValuesHostingWouldRejectAreProblems(t *testing.T) {
	restoreFlags(t)
	path := writeConfig(t, "join-timeout: -1s\nserver: ftp://example.com:22\n")
	errs := validateConfigFile(Root(), path)
	require.Len(t, errs, 2)
	require.Contains(t, errs[0].Error(), "join-timeout")
	require.Contains(t, errs[1].Error(), "server")
	require.Contains(t, errs[1].Error(), "unsupported server protocol ftp")
}

// What hosting refuses when it starts, from the values the file sets: each
// problem is named after its key, and a good value for the same key passes.
func TestValuesHostingRefusesAtStartupAreProblems(t *testing.T) {
	for _, tc := range []struct {
		key, bad, want string
		good           []string
	}{
		{"authorized-user", "nope", "nope: missing provider", []string{"github:alice", "[github:alice, gitea:carol@git.example.com]"}},
		{"authorized-user", "ftp:alice", `unknown provider "ftp"`, nil},
		{"github-user", "a/b", "invalid username", []string{"alice"}},
		{"proxy", "proxy.example.com:3128", "only http:// proxies are supported", []string{"http://proxy.example.com:3128", "http://user:pw@10.0.0.1:3128"}},
		{"escape-char", "ab", "must be a single ASCII character or 'none'", []string{"none", `"~"`, "^"}},
		{"pty-size", "big", `invalid size "big"`, []string{"132x43"}},
		{"force-command", "\"'unclosed\"", "error parsing command", []string{"tmux attach -t pair-programming"}},
		{"server", "ssh://:2222", "missing host in address", []string{"ssh://uptermd.example.com:2222", "ssh://[::1]:2222"}},
	} {
		t.Run(tc.key+"="+tc.bad, func(t *testing.T) {
			restoreFlags(t)
			setupSessionRoots(t)
			path := writeConfig(t, tc.key+": "+tc.bad+"\n")
			errs := validateConfigFile(Root(), path)
			require.Len(t, errs, 1)
			require.Contains(t, errs[0].Error(), path+": "+tc.key+": ")
			require.Contains(t, errs[0].Error(), tc.want)
			require.Contains(t, errs[0].Error(), "; run upterm config edit to fix it")

			for _, good := range tc.good {
				require.Empty(t, validateConfigFile(Root(), writeConfig(t, tc.key+": "+good+"\n")), tc.key+": "+good)
			}
		})
	}
}

// A proxy's credentials are not in the line that says the proxy is wrong.
func TestAProxyProblemDoesNotShowTheProxy(t *testing.T) {
	restoreFlags(t)
	errs := validateConfigFile(Root(), writeConfig(t, "proxy: user:secretpw@10.0.0.1:3128\n"))
	require.Len(t, errs, 1)
	require.NotContains(t, errs[0].Error(), "secretpw")
}

// Each bad entry of a list is a problem of its own, named after the key that
// holds it, a legacy per-service key included.
func TestEachBadUserIsAProblem(t *testing.T) {
	restoreFlags(t)
	path := writeConfig(t, "authorized-user: [nope, github:alice, ftp:bob]\ngithub-user: a/b\n")
	errs := validateConfigFile(Root(), path)
	require.Len(t, errs, 3)
	require.Contains(t, errs[0].Error(), path+": authorized-user: nope: missing provider")
	require.Contains(t, errs[1].Error(), path+": authorized-user: ftp:bob: unknown provider")
	require.Contains(t, errs[2].Error(), path+": github-user: github:a/b: invalid username")
}

// An ignored output value does not require detach.
func TestOutputWithoutDetachIsNotAProblem(t *testing.T) {
	restoreFlags(t)
	require.Empty(t, validateConfigFile(Root(), writeConfig(t, "output: json\n")))
}

func TestIgnoredConfigKeysAreNotValidatedOrApplied(t *testing.T) {
	restoreFlags(t)
	for _, value := range []string{"", "[invalid]", "true"} {
		root := Root()
		before := flagValues(root)
		require.Empty(t, validateConfigFile(root, writeConfig(t, "detach: "+value+"\nname: "+value+"\noutput: "+value+"\nwait: "+value+"\n")))
		after := flagValues(root)
		for name, value := range before {
			require.Equal(t, value, after[name], name)
		}
	}
}

func TestConfigEditReportsIgnoredValues(t *testing.T) {
	restoreFlags(t)
	setupSessionRoots(t)
	withConfig(t, "detach: [invalid]\nname:\noutput: yaml\nwait: invalid\njoin-timeout: 5m\n")
	t.Setenv("VISUAL", "true")
	_, stderr, code := runCLI(t, "config", "edit")
	require.Equal(t, 0, code, stderr)
	require.Equal(t, "upterm: ignoring the detach key in "+utils.UptermConfigFilePath()+"; pass --detach\n"+
		"upterm: ignoring the join-timeout key in "+utils.UptermConfigFilePath()+" for upterm session set; pass --join-timeout\n"+
		"upterm: ignoring the name key in "+utils.UptermConfigFilePath()+"; pass --name\n"+
		"upterm: ignoring the output key in "+utils.UptermConfigFilePath()+"; pass --output\n"+
		"upterm: ignoring the wait key in "+utils.UptermConfigFilePath()+"; pass --wait\n", stderr)
}

// Problems come out in key order whichever check finds them.
func TestProblemsAreSortedByKeyWhateverFoundThem(t *testing.T) {
	restoreFlags(t)
	path := writeConfig(t, "zzz: 1\nserver: ftp://example.com:22\naaa: 1\nread-only: true\nallow-local-tcp-forwarding: true\n")
	errs := validateConfigFile(Root(), path)
	require.Len(t, errs, 4)
	require.Contains(t, errs[0].Error(), `unknown key "aaa"`)
	require.Contains(t, errs[1].Error(), "--read-only and --allow-local-tcp-forwarding cannot be used together")
	require.Contains(t, errs[2].Error(), "unsupported server protocol ftp")
	require.Contains(t, errs[3].Error(), `unknown key "zzz"`)
}

// A file hosting accepts has no problems, however it spells its values.
func TestAFileCommandsAcceptHasNoProblems(t *testing.T) {
	restoreFlags(t)
	for name, body := range map[string]string{
		"empty":    "",
		"example":  exampleConfig(),
		"values":   "server: wss://uptermd.example.com\njoin-timeout: 10m\nread-only: true\nprivate-key:\n  - /a\n  - /b\nauthorized-user: github:alice,github:bob\ndebug: true\n",
		"ssh":      "server: ssh://uptermd.example.com:2222\nallow-local-tcp-forwarding: true\n",
		"no ports": "server: ws://uptermd.example.com\n",
		"bare ssh": "server: ssh://uptermd.example.com\n",
	} {
		t.Run(name, func(t *testing.T) {
			require.Empty(t, validateConfigFile(Root(), writeConfig(t, body)))
		})
	}
	// The editor can delete the file; commands read that as no config.
	require.Empty(t, validateConfigFile(Root(), filepath.Join(t.TempDir(), "gone.yaml")))
}

func TestAFileThatIsNotYAMLIsOneProblem(t *testing.T) {
	restoreFlags(t)
	path := writeConfig(t, "authorized-user: [unclosed\n")
	errs := validateConfigFile(Root(), path)
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Error(), path+": ")
	require.Contains(t, errs[0].Error(), "; run upterm config edit to fix it")
}

func TestAKeyWithoutAValueIsAProblem(t *testing.T) {
	restoreFlags(t)
	errs := validateConfigFile(Root(), writeConfig(t, "debug:\n"))
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Error(), "debug: config key has no value")
}

// A value the flag takes whole, such as a list where a string belongs, is
// refused the way commands refuse it.
func TestAListWhereAStringBelongsIsAProblem(t *testing.T) {
	restoreFlags(t)
	errs := validateConfigFile(Root(), writeConfig(t, "force-command: [/bin/bash, -l]\n"))
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Error(), "force-command: expected a single value")
}

// A flag that carries the cli-only annotation is a known key, but no value of
// the file's is set on it or judged by it.
func TestAKeyOnlyTheCommandLineSetsIsNotChecked(t *testing.T) {
	var onlyHere int
	root := &cobra.Command{Use: "upterm"}
	sub := &cobra.Command{Use: "sub"}
	sub.Flags().IntVar(&onlyHere, "only-here", 7, "")
	require.NoError(t, sub.Flags().SetAnnotation("only-here", annotationCLIOnly, []string{"true"}))
	root.AddCommand(sub)

	require.Empty(t, validateConfigFile(root, writeConfig(t, "only-here: not-a-number\n")))
	require.Equal(t, 7, onlyHere)
}

// A check runs only for the keys the file holds: the values the variables had
// before it (a default, or another file) are nobody's to judge here.
func TestOnlyTheKeysTheFileHoldsAreChecked(t *testing.T) {
	restoreFlags(t)
	root := Root()
	flagJoinTimeout = -time.Second
	flagServer = "ftp://example.com:22"
	flagReadOnly, flagAllowLocalTCPForwarding = true, true
	flagProxy = "proxy.example.com:3128"
	flagHostEscapeChar = "ab"
	flagPtySize = "big"
	flagForceCommand = "'unclosed"
	flagAuthorizedUsers = []string{"nope"}
	flagName = "a/b"
	flagOutput = "yaml"
	flagDetach = true

	require.Empty(t, validateConfigFile(root, writeConfig(t, "debug: true\n")))
	// Nor is a pair judged when the file holds only one of the two.
	require.Empty(t, validateConfigFile(root, writeConfig(t, "read-only: true\n")))
}

func TestVisualWinsOverEditor(t *testing.T) {
	env := map[string]string{"VISUAL": "vis", "EDITOR": "ed"}
	cmd, err := editorCommand(func(k string) string { return env[k] }, "/c/config.yaml")
	require.NoError(t, err)
	require.Equal(t, []string{"vis", "/c/config.yaml"}, cmd.Args)

	env["VISUAL"] = ""
	cmd, err = editorCommand(func(k string) string { return env[k] }, "/c/config.yaml")
	require.NoError(t, err)
	require.Equal(t, []string{"ed", "/c/config.yaml"}, cmd.Args)
}

func TestWithNoEditorSetTheDefaultOpensTheFile(t *testing.T) {
	cmd, err := editorCommand(func(string) string { return "" }, "/c/config.yaml")
	require.NoError(t, err)
	require.Len(t, cmd.Args, 2)
	require.Equal(t, "/c/config.yaml", cmd.Args[1])
}

// A value that is blank counts as unset, so it neither shadows the next
// variable nor is run.
func TestABlankVariableCountsAsUnset(t *testing.T) {
	env := map[string]string{"VISUAL": "  ", "EDITOR": "ed"}
	cmd, err := editorCommand(func(k string) string { return env[k] }, "/c/config.yaml")
	require.NoError(t, err)
	require.Equal(t, []string{"ed", "/c/config.yaml"}, cmd.Args)

	env["EDITOR"] = "\t "
	cmd, err = editorCommand(func(k string) string { return env[k] }, "/c/config.yaml")
	require.NoError(t, err)
	require.Len(t, cmd.Args, 2, "the default editor")
	require.Equal(t, "/c/config.yaml", cmd.Args[1])
}

// writeFileWithSpace makes a file whose path has a space in it, in a temp dir.
func writeFileWithSpace(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "my editor")
	require.NoError(t, os.WriteFile(path, nil, 0o700))
	return path
}

// An unquoted path with spaces in it, as the environment-variables dialog on
// Windows and a shell's export of a path in an app bundle leave it, is the
// program whole: split at the spaces it would name a program that isn't there.
func TestAnUnquotedEditorPathWithSpacesRunsWhole(t *testing.T) {
	editor := writeFileWithSpace(t)
	cmd, err := editorCommand(func(k string) string {
		if k == "EDITOR" {
			return editor
		}
		return ""
	}, "/c/config.yaml")
	require.NoError(t, err)
	require.Equal(t, []string{editor, "/c/config.yaml"}, cmd.Args)
}

// With an argument after it, or in quotes, the value is not a file, and is
// split as it always was.
func TestAnEditorPathWithSpacesAndAnArgumentIsSplit(t *testing.T) {
	editor := writeFileWithSpace(t)
	cmd, err := editorCommand(func(k string) string {
		if k == "EDITOR" {
			return editor + " --wait"
		}
		return ""
	}, "/c/config.yaml")
	require.NoError(t, err)
	require.NotEqual(t, editor, cmd.Args[0])
	require.Equal(t, []string{"--wait", "/c/config.yaml"}, cmd.Args[len(cmd.Args)-2:])
}

// Whitespace around the value is no part of it: a leading space would make an
// empty program name on Windows, and would hide a file from the lookup.
func TestSpacesAroundAnEditorAreNotPartOfIt(t *testing.T) {
	editor := writeFileWithSpace(t)
	for value, want := range map[string][]string{
		" " + editor + "\t": {editor, "/c/config.yaml"},
		"  ed --wait \n":    {"ed", "--wait", "/c/config.yaml"},
	} {
		cmd, err := editorCommand(func(k string) string {
			if k == "EDITOR" {
				return value
			}
			return ""
		}, "/c/config.yaml")
		require.NoError(t, err)
		require.Equal(t, want, cmd.Args, "%q", value)
	}
}

// A directory is not an editor: the value is split as always.
func TestADirectoryIsNotAnEditorWhole(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "my dir")
	require.NoError(t, os.Mkdir(dir, 0o700))
	cmd, err := editorCommand(func(k string) string {
		if k == "EDITOR" {
			return dir
		}
		return ""
	}, "/c/config.yaml")
	require.NoError(t, err)
	require.NotEqual(t, dir, cmd.Args[0])
}

func TestConfigViewKeepsWhatHomebrewChecks(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	require.NoError(t, os.Remove(utils.UptermConfigFilePath()))
	stdout, _, code := runCLI(t, "config", "view")
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "# Upterm Configuration File")
	require.Contains(t, stdout, "server: ssh://uptermd.upterm.dev:22")
}

// The example config's hide-client-ip entry says what the setting does: an
// uncommented false shows guests' addresses in CI too, so the example must not
// offer false as the default.
func TestTheExampleConfigSaysWhatHideClientIPDoes(t *testing.T) {
	require.Contains(t, exampleConfig(), "# Hide guests' IP addresses from upterm's output (default: hidden in CI only; false shows them there too)\n# hide-client-ip: true\n")
	require.NotContains(t, exampleConfig(), "# hide-client-ip: false")
}

func TestConfigEditIgnoresMappingsForUnboundKeys(t *testing.T) {
	for _, mapping := range []string{"{nested: invalid}", "{}"} {
		t.Run(mapping, func(t *testing.T) {
			restoreFlags(t)
			setupSessionRoots(t)
			withConfig(t, "detach: "+mapping+"\nname: "+mapping+"\noutput: "+mapping+"\nwait: "+mapping+"\n")
			t.Setenv("VISUAL", "true")
			_, stderr, code := runCLI(t, "config", "edit")
			require.Equal(t, 0, code, stderr)
			path := utils.UptermConfigFilePath()
			require.Equal(t, "upterm: ignoring the detach key in "+path+"; pass --detach\n"+
				"upterm: ignoring the name key in "+path+"; pass --name\n"+
				"upterm: ignoring the output key in "+path+"; pass --output\n"+
				"upterm: ignoring the wait key in "+path+"; pass --wait\n", stderr)
		})
	}
}

func TestConfigEditMappingsDoNotBypassBoundKeyValidation(t *testing.T) {
	for _, key := range []string{"authorized-user", "join-timeout", "unknown"} {
		t.Run(key, func(t *testing.T) {
			restoreFlags(t)
			root := Root()
			path := writeConfig(t, "output: {format: json}\n"+key+": {nested: invalid}\n")
			errs, deps := checkConfigFile(root, path)
			require.Len(t, errs, 1)
			require.Contains(t, errs[0].Error(), `unknown key "`+key+`.nested"`)
			if key == "join-timeout" {
				require.Len(t, deps, 2)
				require.Equal(t, "upterm: ignoring the join-timeout key in "+path+" for upterm session set; pass --join-timeout", deps[0].ignoredLine())
			}
		})
	}
}
