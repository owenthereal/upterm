package command

import (
	"io"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// withoutCI clears every variable isCI reads, so a case sets the CI it means
// to test: GitHub's runners set CI and GITHUB_ACTIONS themselves.
func withoutCI(t *testing.T) {
	t.Helper()
	for _, v := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "TRAVIS", "JENKINS_URL", "BUILDKITE", "TF_BUILD", "TEAMCITY_VERSION", "BITBUCKET_BUILD_NUMBER"} {
		t.Setenv(v, "")
	}
}

// asRunningCmd makes cmd the command shouldHideClientIP answers for, for the
// rest of t, as the root's pre-run does for the command it runs.
func asRunningCmd(t *testing.T, cmd *cobra.Command) {
	t.Helper()
	orig := runningCmd
	t.Cleanup(func() { runningCmd = orig })
	runningCmd = cmd
}

// withHideClientIPFlag makes the rest of t a run of a command that was given
// --hide-client-ip=value, or none of it when value is empty.
func withHideClientIPFlag(t *testing.T, value string) {
	t.Helper()
	orig := flagHideClientIP
	t.Cleanup(func() { flagHideClientIP = orig })
	cmd := &cobra.Command{Use: "x"}
	cmd.Flags().BoolVar(&flagHideClientIP, "hide-client-ip", false, "")
	if value != "" {
		require.NoError(t, cmd.Flags().Set("hide-client-ip", value))
	}
	asRunningCmd(t, cmd)
}

// hiddenInRun runs the command at path with flags through the root's own
// pre-run, as upterm does, and returns what shouldHideClientIP says inside it.
func hiddenInRun(t *testing.T, path []string, flags ...string) bool {
	t.Helper()
	origFlag := flagHideClientIP
	t.Cleanup(func() { flagHideClientIP = origFlag })
	// Only the pre-run below says which command is running.
	asRunningCmd(t, nil)

	root := Root()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	cmd, _, err := root.Find(path)
	require.NoError(t, err)
	var hidden bool
	cmd.PreRunE = nil
	cmd.Args = cobra.ArbitraryArgs
	cmd.RunE = func(*cobra.Command, []string) error {
		hidden = shouldHideClientIP()
		return nil
	}
	root.SetArgs(append(append([]string{}, path...), flags...))
	require.NoError(t, root.Execute())
	return hidden
}

// A --hide-client-ip that was given a value, true or false, by the command
// line, UPTERM_HIDE_CLIENT_IP or the config file, decides. Only a flag nobody
// gave a value falls back to CI, which hides addresses on its own: a run that
// wants them in a CI log has to be able to say so.
func TestAnExplicitHideClientIPDecidesAndCIIsTheFallback(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ci     bool
		flags  []string
		env    string
		config string
		hidden bool
	}{
		{name: "no CI and nothing given shows"},
		{name: "CI and nothing given hides", ci: true, hidden: true},
		{name: "false on the command line beats CI", ci: true, flags: []string{"--hide-client-ip=false"}},
		{name: "false in the environment beats CI", ci: true, env: "false"},
		{name: "false in the config beats CI", ci: true, config: "hide-client-ip: false\n"},
		{name: "true on the command line hides", flags: []string{"--hide-client-ip"}, hidden: true},
		{name: "true in the environment hides", env: "true", hidden: true},
		{name: "true in the config hides", config: "hide-client-ip: true\n", hidden: true},
		{name: "true under CI hides", ci: true, flags: []string{"--hide-client-ip=true"}, hidden: true},
		{name: "the command line beats the environment", ci: true, flags: []string{"--hide-client-ip=false"}, env: "true"},
		{name: "an empty variable is no value, so CI hides", ci: true, env: "", hidden: true},
	} {
		for _, path := range [][]string{{"host"}, {"session", "list"}} {
			t.Run(tc.name+"/"+path[0], func(t *testing.T) {
				withoutCI(t)
				if tc.ci {
					t.Setenv("CI", "true")
				}
				withConfig(t, tc.config)
				t.Setenv("UPTERM_HIDE_CLIENT_IP", tc.env)
				setupSessionRoots(t)

				require.Equal(t, tc.hidden, hiddenInRun(t, path, tc.flags...))
			})
		}
	}
}

func TestExplicitFalseTurnsCIHidingOff(t *testing.T) {
	withoutCI(t)
	t.Setenv("CI", "true")
	origFlag := flagHideClientIP
	t.Cleanup(func() { flagHideClientIP = origFlag })

	// Built first: the flag is persistent on host, and registering it writes
	// its default into the variable.
	cmd := hostCmd()
	require.True(t, shouldHideClientIPFor(cmd), "CI hides what nobody said otherwise")

	require.NoError(t, cmd.PersistentFlags().Set("hide-client-ip", "false"))
	require.False(t, shouldHideClientIPFor(cmd))

	require.NoError(t, cmd.PersistentFlags().Set("hide-client-ip", "true"))
	require.True(t, shouldHideClientIPFor(cmd))
}

// A command with no such flag has nothing explicit to say, and CI decides.
func TestACommandWithoutTheFlagFallsBackToCI(t *testing.T) {
	withoutCI(t)
	cmd := &cobra.Command{Use: "x"}
	require.False(t, shouldHideClientIPFor(cmd))
	require.False(t, shouldHideClientIPFor(nil))

	t.Setenv("CI", "true")
	require.True(t, shouldHideClientIPFor(cmd))
	require.True(t, shouldHideClientIPFor(nil))
}
