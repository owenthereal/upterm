//go:build !windows

package command

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
)

func TestEditorArgumentsAreKept(t *testing.T) {
	cmd, err := editorCommand(func(k string) string {
		if k == "EDITOR" {
			return `code --wait`
		}
		return ""
	}, "/c/config.yaml")
	require.NoError(t, err)
	require.Equal(t, []string{"code", "--wait", "/c/config.yaml"}, cmd.Args)
}

// POSIX shell quoting: a quoted path with spaces is one word.
func TestEditorQuotingFollowsTheShell(t *testing.T) {
	cmd, err := editorCommand(func(k string) string {
		if k == "VISUAL" {
			return `'/opt/my editor/ed' -c "set nu"`
		}
		return ""
	}, "/c/config.yaml")
	require.NoError(t, err)
	require.Equal(t, []string{"/opt/my editor/ed", "-c", "set nu", "/c/config.yaml"}, cmd.Args)
}

func TestAnEditorWithAnUnclosedQuoteIsRefused(t *testing.T) {
	_, err := editorCommand(func(k string) string {
		if k == "EDITOR" {
			return `code "--wait`
		}
		return ""
	}, "/c/config.yaml")
	require.ErrorContains(t, err, "$EDITOR")
}

// writeEditor writes an executable shell script and returns its path.
func writeEditor(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700))
	return path
}

// config edit opens the file in an editor that takes arguments, then reports
// what the editor left in it, one line each, and exits 1 until the file is
// fine.
func TestConfigEditNamesWhatTheEditorLeftBehind(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	restoreHostFlags(t)
	t.Setenv("VISUAL", "")
	record := filepath.Join(t.TempDir(), "args")
	t.Setenv("EDITOR_RECORD", record)
	configPath := utils.UptermConfigFilePath()

	appender := writeEditor(t, "append", "printf '%s\\n' \"$@\" > \"$EDITOR_RECORD\"\nfor f; do :; done\necho 'bogus-key: 1' >> \"$f\"\n")
	t.Setenv("EDITOR", appender+" --wait")
	_, stderr, code := runCLI(t, "config", "edit")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: "+configPath+": unknown key \"bogus-key\"; run upterm config edit to fix it\n", stderr)
	args, err := os.ReadFile(record)
	require.NoError(t, err)
	require.Equal(t, "--wait\n"+configPath+"\n", string(args))

	remover := writeEditor(t, "remove", "for f; do :; done\ngrep -v '^bogus-key:' \"$f\" > \"$f.new\"\nmv \"$f.new\" \"$f\"\n")
	t.Setenv("EDITOR", remover)
	_, stderr, code = runCLI(t, "config", "edit")
	require.Equal(t, 0, code)
	require.Empty(t, stderr)
}

func TestConfigEditNamesEveryProblemOnItsOwnLine(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	restoreHostFlags(t)
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", writeEditor(t, "append", "for f; do :; done\nprintf 'zzz: 1\\njoin-timeout: -1s\\nbogus-key: 1\\n' >> \"$f\"\n"))
	configPath := utils.UptermConfigFilePath()

	_, stderr, code := runCLI(t, "config", "edit")
	require.Equal(t, 1, code)
	require.Equal(t,
		"upterm: "+configPath+": unknown key \"bogus-key\"; run upterm config edit to fix it\n"+
			"upterm: "+configPath+": join-timeout: --join-timeout cannot be negative; use 0 to wait forever; run upterm config edit to fix it\n"+
			"upterm: "+configPath+": unknown key \"zzz\"; run upterm config edit to fix it\n",
		stderr)
}

// An editor that fails is reported as that, not as a problem with the file.
func TestConfigEditReportsAnEditorThatWillNotStart(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", filepath.Join(t.TempDir(), "no-such-editor")+" --wait")

	_, stderr, code := runCLI(t, "config", "edit")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "upterm: failed to open editor: ")
}
