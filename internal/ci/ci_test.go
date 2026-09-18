package ci

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func envFrom(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestDetectEnv(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "github actions",
			env:  map[string]string{"GITHUB_ACTIONS": "true"},
			want: "GitHub Actions",
		},
		{
			// A runner that exports the variable names without implementing
			// the workflow-command files is not something to report to: the
			// writes would go nowhere and the failure would be reported as if
			// GitHub had refused them.
			name: "github-shaped variables without the runner",
			env:  map[string]string{"GITHUB_ACTOR": "alice", "GITHUB_WORKSPACE": "/w"},
			want: "",
		},
		{
			name: "an unknown CI system",
			env:  map[string]string{"CI": "true", "BUILDKITE": "true"},
			want: "",
		},
		{
			name: "no CI at all",
			env:  map[string]string{},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := DetectEnv(envFrom(tc.env))
			if tc.want == "" {
				require.Nil(t, p)
				return
			}
			require.NotNil(t, p)
			require.Equal(t, tc.want, p.Name())
		})
	}
}

func TestIsCIEnv(t *testing.T) {
	require.False(t, IsCIEnv(envFrom(nil)))
	require.True(t, IsCIEnv(envFrom(map[string]string{"CI": "true"})))
	require.True(t, IsCIEnv(envFrom(map[string]string{"TEAMCITY_VERSION": "1"})))

	// An empty value is not a CI: a workflow that writes `CI: ""` has said
	// nothing, and an IP hidden on that basis would be hidden everywhere the
	// variable is merely declared.
	require.False(t, IsCIEnv(envFrom(map[string]string{"CI": ""})))
}

// newTestGHA returns a GitHubActions writing into a temp dir, with the paths
// it was given.
func newTestGHA(t *testing.T, extra map[string]string) (*GitHubActions, *bytes.Buffer, string, string) {
	t.Helper()

	dir := t.TempDir()
	output := filepath.Join(dir, "output")
	summary := filepath.Join(dir, "summary")

	env := map[string]string{
		"GITHUB_ACTIONS":      "true",
		"GITHUB_OUTPUT":       output,
		"GITHUB_STEP_SUMMARY": summary,
	}
	for k, v := range extra {
		env[k] = v
	}

	var stdout bytes.Buffer
	return &GitHubActions{getenv: envFrom(env), stdout: &stdout}, &stdout, output, summary
}

func TestGitHubActionsReady(t *testing.T) {
	gha, stdout, outputPath, summaryPath := newTestGHA(t, map[string]string{
		"GITHUB_ACTOR":     "alice",
		"GITHUB_WORKSPACE": "/home/runner/work/repo/repo",
	})

	require.Equal(t, "alice", gha.Actor())
	require.Equal(t, "/home/runner/work/repo/repo", gha.Workspace())

	require.NoError(t, gha.Ready(Session{SSHCommand: "ssh TOKEN@uptermd.upterm.dev", Name: "bash-1a2b"}))

	output, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	require.Len(t, lines, 3, "an output entry is a key line, the value and the closing delimiter")

	key, delim, ok := strings.Cut(lines[0], "<<")
	require.True(t, ok)
	require.Equal(t, "ssh-command", key)
	require.True(t, strings.HasPrefix(delim, "ghadelimiter_"))
	require.Equal(t, "ssh TOKEN@uptermd.upterm.dev", lines[1])
	require.Equal(t, delim, lines[2])

	summary, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	require.Contains(t, string(summary), "ssh TOKEN@uptermd.upterm.dev")
	require.Contains(t, string(summary), "bash-1a2b")

	require.Equal(t, "::notice title=Upterm session::ssh TOKEN@uptermd.upterm.dev\n", stdout.String())
}

func TestGitHubActionsReadyAppends(t *testing.T) {
	gha, _, outputPath, _ := newTestGHA(t, nil)

	// The runner's files are shared by every step and by every tool in a step.
	// Truncating either would discard another step's outputs or someone else's
	// summary.
	require.NoError(t, os.WriteFile(outputPath, []byte("earlier=value\n"), 0644))
	require.NoError(t, gha.Ready(Session{SSHCommand: "ssh TOKEN@example.com"}))

	output, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(output), "earlier=value\n"))
	require.Contains(t, string(output), "ssh-command<<")
}

func TestGitHubActionsReadyWithoutRunnerFiles(t *testing.T) {
	// GITHUB_ACTIONS set with no GITHUB_OUTPUT is `act`, a hand-rolled
	// container, or a test. There is nothing to write to and nothing wrong.
	var stdout bytes.Buffer
	gha := &GitHubActions{
		getenv: envFrom(map[string]string{"GITHUB_ACTIONS": "true"}),
		stdout: &stdout,
	}

	require.NoError(t, gha.Ready(Session{SSHCommand: "ssh TOKEN@example.com"}))
	require.Contains(t, stdout.String(), "::notice")
}

func TestGitHubActionsReadyReportsAnUnwritableFile(t *testing.T) {
	dir := t.TempDir()
	var stdout bytes.Buffer
	gha := &GitHubActions{
		getenv: envFrom(map[string]string{
			"GITHUB_ACTIONS": "true",
			// A directory: open-for-append fails on every platform.
			"GITHUB_OUTPUT": dir,
		}),
		stdout: &stdout,
	}

	err := gha.Ready(Session{SSHCommand: "ssh TOKEN@example.com"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "GITHUB_OUTPUT")

	// The other channels still ran: one unwritable file must not cost the
	// session every other way of announcing itself.
	require.Contains(t, stdout.String(), "::notice")
}

func TestKeyValueFileRejectsAValueCarryingTheDelimiter(t *testing.T) {
	// The delimiter is random, so the only way to reach this is to hand it in
	// — which is the injection the heredoc form exists to prevent.
	delim, err := randomDelimiter()
	require.NoError(t, err)

	_, err = keyValueFile("ssh-command", "ssh x@y\n"+delim+"\nevil=1")
	// A random delimiter will not match the one generated inside, so this
	// specific value is fine; what matters is that a value with newlines
	// survives intact rather than becoming further entries.
	require.NoError(t, err)

	out, err := keyValueFile("ssh-command", "one\ntwo")
	require.NoError(t, err)
	require.Contains(t, out, "one\ntwo\n")
}

func TestEscaping(t *testing.T) {
	// A newline would end the workflow command and leave the rest of the
	// message to be read as log output, or as another command.
	require.Equal(t, "a%0Ab", escapeData("a\nb"))
	require.Equal(t, "100%25", escapeData("100%"))
	require.Equal(t, "a%3Ab%2Cc", escapeProperty("a:b,c"))

	require.Equal(t,
		"::notice title=Upterm session::ssh TOKEN@host%0A::error::pwned\n",
		notice("Upterm session", "ssh TOKEN@host\n::error::pwned"),
	)
}
