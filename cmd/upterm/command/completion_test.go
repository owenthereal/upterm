package command

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// noFileComp is cobra's ShellCompDirectiveNoFileComp as `__complete` prints
// it: the shell offers no file names.
const noFileComp = ":4"

// noFileCompNoSpace is the same, and the shell leaves the cursor against the
// word it completed.
const noFileCompNoSpace = ":6"

// runningSession claims a name for the rest of the test. A claim nothing
// refers to is collected, and its lock files are closed with it, which ends
// the session.
func runningSession(t *testing.T, name string) {
	t.Helper()
	releaseAtEnd(t, claimSession(t, name))
}

// complete asks the CLI for the completions of words, as the shell's script
// does, and returns the candidates and the directive line.
func complete(t *testing.T, words ...string) (candidates []string, directive string) {
	t.Helper()
	stdout, _, code := runCLI(t, append([]string{"__complete"}, words...)...)
	require.Equal(t, 0, code)
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	return lines[:len(lines)-1], lines[len(lines)-1]
}

// The names come from the records, so a config that fails to load stops
// nothing.
func TestSessionNamesCompleteDespiteABadConfig(t *testing.T) {
	setupSessionRoots(t)
	runningSession(t, "build")
	runningSession(t, "bash-28e5")
	withConfig(t, "bogus-key: 1\n")
	stdout, _, code := runCLI(t, "__complete", "session", "info", "b")
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "build\n")
	require.Contains(t, stdout, "bash-28e5\n")
	require.Contains(t, stdout, ":4\n") // ShellCompDirectiveNoFileComp
}

func TestOnlyTheFirstArgumentCompletes(t *testing.T) {
	setupSessionRoots(t)
	runningSession(t, "build")
	for _, cmd := range [][]string{{"attach"}, {"session", "info"}, {"session", "stop"}, {"session", "set"}, {"session", "wait"}} {
		stdout, _, _ := runCLI(t, append(append([]string{"__complete"}, cmd...), "build", "")...)
		require.NotContains(t, stdout, "build\n", cmd)
		require.Contains(t, stdout, noFileComp+"\n", cmd)
	}
}

func TestSessionNamesCompleteByPrefix(t *testing.T) {
	setupSessionRoots(t)
	runningSession(t, "build")
	runningSession(t, "bash-28e5")
	runningSession(t, "test")
	for _, cmd := range [][]string{{"attach"}, {"session", "info"}, {"session", "stop"}, {"session", "set"}, {"session", "wait"}} {
		got, directive := complete(t, append(append([]string{}, cmd...), "b")...)
		require.ElementsMatch(t, []string{"build", "bash-28e5"}, got, cmd)
		require.Equal(t, noFileComp, directive, cmd)

		got, _ = complete(t, append(append([]string{}, cmd...), "")...)
		require.ElementsMatch(t, []string{"build", "bash-28e5", "test"}, got, cmd)
	}
}

// A flag before the name does not count as an argument.
func TestSessionNamesCompleteAfterAFlag(t *testing.T) {
	setupSessionRoots(t)
	runningSession(t, "build")
	got, directive := complete(t, "session", "set", "--join-timeout", "10m", "b")
	require.Equal(t, []string{"build"}, got)
	require.Equal(t, noFileComp, directive)
}

func TestNoSessionsCompletesNoNames(t *testing.T) {
	setupSessionRoots(t)
	got, directive := complete(t, "attach", "")
	require.Empty(t, got)
	require.Equal(t, noFileComp, directive)
}

func TestOutputFormatsComplete(t *testing.T) {
	setupSessionRoots(t)
	runningSession(t, "build")
	for _, tc := range []struct {
		words     []string
		want      []string
		directive string
	}{
		{[]string{"host", "-o", ""}, []string{"json"}, noFileComp},
		{[]string{"host", "--output", "j"}, []string{"json"}, noFileComp},
		{[]string{"session", "info", "build", "-o", ""}, []string{"json"}, noFileComp},
		{[]string{"session", "current", "-o", "j"}, []string{"json"}, noFileComp},
		// go-template= is a prefix, the template follows it: no space after.
		{[]string{"session", "current", "-o", "g"}, []string{"go-template="}, noFileCompNoSpace},
		{[]string{"session", "current", "-o", ""}, []string{"json", "go-template="}, noFileCompNoSpace},
	} {
		got, directive := complete(t, tc.words...)
		require.ElementsMatch(t, tc.want, got, tc.words)
		require.Equal(t, tc.directive, directive, tc.words)
	}
}
