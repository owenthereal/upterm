package command

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
)

// restoreHostFlags puts back the host flags that checking a config file sets:
// the check applies the file's values to the flags' variables, and tests that
// read those without building a command expect their defaults.
func restoreHostFlags(t *testing.T) {
	t.Helper()
	server, joinTimeout, readOnly, forwarding := flagServer, flagJoinTimeout, flagReadOnly, flagAllowLocalTCPForwarding
	t.Cleanup(func() {
		flagServer, flagJoinTimeout, flagReadOnly, flagAllowLocalTCPForwarding = server, joinTimeout, readOnly, forwarding
	})
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestEveryProblemIsNamed(t *testing.T) {
	restoreHostFlags(t)
	path := writeConfig(t, "bogus-key: 1\nread-only: maybe\nzzz: 2\n")
	errs := validateConfigFile(Root(), path)
	require.Len(t, errs, 3)
	require.Contains(t, errs[0].Error(), `unknown key "bogus-key"`)
	require.Contains(t, errs[1].Error(), "read-only")
	require.Contains(t, errs[2].Error(), `unknown key "zzz"`)
	require.Equal(t, path+`: unknown key "bogus-key"; run upterm config edit to fix it`, errs[0].Error())
}

func TestValuesHostingWouldRejectAreProblems(t *testing.T) {
	restoreHostFlags(t)
	path := writeConfig(t, "join-timeout: -1s\nserver: ftp://example.com:22\n")
	errs := validateConfigFile(Root(), path)
	require.Len(t, errs, 2)
	require.Contains(t, errs[0].Error(), "join-timeout")
	require.Contains(t, errs[1].Error(), "server")
	require.Contains(t, errs[1].Error(), "unsupported server protocol ftp")
}

// Problems come out in key order whichever check finds them.
func TestProblemsAreSortedByKeyWhateverFoundThem(t *testing.T) {
	restoreHostFlags(t)
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
	restoreHostFlags(t)
	for name, body := range map[string]string{
		"empty":    "",
		"example":  exampleConfig(),
		"values":   "server: wss://uptermd.example.com\njoin-timeout: 10m\nread-only: true\nprivate-key:\n  - /a\n  - /b\nauthorized-user: github:alice,github:bob\ndebug: true\n",
		"ssh":      "server: ssh://uptermd.example.com:2222\nallow-local-tcp-forwarding: true\n",
		"no ports": "server: ws://uptermd.example.com\n",
	} {
		t.Run(name, func(t *testing.T) {
			require.Empty(t, validateConfigFile(Root(), writeConfig(t, body)))
		})
	}
	// The editor can delete the file; commands read that as no config.
	require.Empty(t, validateConfigFile(Root(), filepath.Join(t.TempDir(), "gone.yaml")))
}

func TestAFileThatIsNotYAMLIsOneProblem(t *testing.T) {
	path := writeConfig(t, "authorized-user: [unclosed\n")
	errs := validateConfigFile(Root(), path)
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Error(), path+": ")
	require.Contains(t, errs[0].Error(), "; run upterm config edit to fix it")
}

func TestAKeyWithoutAValueIsAProblem(t *testing.T) {
	restoreHostFlags(t)
	errs := validateConfigFile(Root(), writeConfig(t, "debug:\n"))
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Error(), "debug: config key has no value")
}

// A value the flag takes whole, such as a list where a string belongs, is
// refused the way commands refuse it.
func TestAListWhereAStringBelongsIsAProblem(t *testing.T) {
	restoreHostFlags(t)
	errs := validateConfigFile(Root(), writeConfig(t, "force-command: [/bin/bash, -l]\n"))
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Error(), "force-command: expected a single value")
}

// A flag the command line alone sets is not a config key's value to check.
func TestAKeyOnlyTheCommandLineSetsIsNotChecked(t *testing.T) {
	restoreHostFlags(t)
	require.Empty(t, validateConfigFile(Root(), writeConfig(t, "output: yaml\n")))
}

func TestOnlyTheKeysTheFileHoldsAreChecked(t *testing.T) {
	restoreHostFlags(t)
	require.Empty(t, validateConfigFile(Root(), writeConfig(t, "join-timeout: 5m\n")))
	require.Equal(t, 5*time.Minute, flagJoinTimeout, "the file's value is what the check ran on")
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
