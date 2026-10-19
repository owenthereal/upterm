package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The bash script is cobra's V2 one, which asks the binary for completions
// with their descriptions, as the zsh one does. The assertions are plain
// booleans: a failing Contains would print the whole script.
func TestBashCompletionAsksTheBinary(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	for _, dir := range []string{"docs", "etc/man/man1", "etc/completion"} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}

	main()

	script, err := os.ReadFile(filepath.Join("etc", "completion", "upterm.bash_completion.sh"))
	require.NoError(t, err)
	text := string(script)
	require.True(t, strings.Contains(text, "__upterm_get_completion_results()"), "not the V2 script")
	require.True(t, strings.Contains(text, `${words[0]} __complete ${args[*]}`), "does not ask for descriptions")
	require.False(t, strings.Contains(text, "__upterm_handle_reply"), "the V1 script")
}

// The root and the groups run only to report an unknown command, so their
// pages show no usage line of their own, as for a command that can't run; a
// command that runs keeps its line.
func TestOnlyPagesOfCommandsThatRunShowAUsageLine(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	for _, dir := range []string{"docs", "etc/man/man1", "etc/completion"} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}

	main()

	for page, usage := range map[string]string{
		"upterm.md":         "upterm [flags]",
		"upterm_session.md": "upterm session [flags]",
		"upterm_config.md":  "upterm config [flags]",
	} {
		text, err := os.ReadFile(filepath.Join("docs", page))
		require.NoError(t, err)
		require.NotContains(t, string(text), "```\n"+usage+"\n```", page)
	}
	text, err := os.ReadFile(filepath.Join("docs", "upterm_version.md"))
	require.NoError(t, err)
	require.Contains(t, string(text), "```\nupterm version [flags]\n```")
}

// The cask installs the man pages it lists and no others.
func TestCaskListsEveryManPage(t *testing.T) {
	config, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yml"))
	require.NoError(t, err)

	var listed []string
	inList := false
	for _, line := range strings.Split(string(config), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "manpages:":
			inList = true
		case inList && (trimmed == "" || strings.HasPrefix(trimmed, "#")):
		case inList && strings.HasPrefix(trimmed, "- "):
			listed = append(listed, strings.Trim(strings.TrimPrefix(trimmed, "- "), `"'`))
		case inList:
			inList = false
		}
	}

	pages, err := filepath.Glob(filepath.Join("..", "..", "etc", "man", "man1", "*.1"))
	require.NoError(t, err)
	var generated []string
	for _, p := range pages {
		generated = append(generated, "etc/man/man1/"+filepath.Base(p))
	}

	require.NotEmpty(t, generated)
	slices.Sort(listed)
	slices.Sort(generated)
	require.Equal(t, generated, listed)
}
