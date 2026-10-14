package command

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// runCLI runs upterm with args in-process, as Main does: the root Main runs,
// ExecuteC, then Exit. stdin, stdout and stderr are pipes, so stderr holds
// both what the command wrote itself and what Exit printed, and code is the
// status main would exit with.
//
// It leaves the environment as the caller set it: the config file, the state
// directory the log goes to, the sessions. A test that needs them isolated
// calls withConfig and setupSessionRoots first, and a test that needs them
// otherwise (a bad config, an unopenable log directory, claimed sessions)
// sets that up instead.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	stdout, stderr, code, _ = runCLICmd(t, args...)
	return stdout, stderr, code
}

// runCLICmd is runCLI, and the command that ran.
func runCLICmd(t *testing.T, args ...string) (stdout, stderr string, code int, cmd *cobra.Command) {
	t.Helper()

	stdinR, stdinW, err := os.Pipe()
	require.NoError(t, err)
	stdoutR, stdoutW, err := os.Pipe()
	require.NoError(t, err)
	stderrR, stderrW, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, f := range []*os.File{stdinR, stdinW, stdoutR, stdoutW, stderrR, stderrW} {
			_ = f.Close()
		}
	})
	origIn, origOut, origErr := os.Stdin, os.Stdout, os.Stderr
	os.Stdin, os.Stdout, os.Stderr = stdinR, stdoutW, stderrW
	defer func() { os.Stdin, os.Stdout, os.Stderr = origIn, origOut, origErr }()

	// Drained concurrently: what a command prints can be more than a pipe
	// buffer holds.
	collect := func(r io.Reader) <-chan string {
		ch := make(chan string, 1)
		go func() {
			b, _ := io.ReadAll(r)
			ch <- string(b)
		}()
		return ch
	}
	outC, errC := collect(stdoutR), collect(stderrR)

	// Built after the swap: cobra's completion command keeps the stdout it
	// was created with.
	root := cliRoot()
	// Never nil: cobra reads nil as "take os.Args", the test binary's.
	root.SetArgs(append([]string{}, args...))
	cmd, err = root.ExecuteC()
	code = Exit(cmd, err, os.Stderr)
	// A command that fails skips PersistentPostRunE, which closes the log
	// file, and Exit has just written to it; Windows won't remove the state
	// directory while it is open.
	if logger := uptermctx.Logger(cmd.Context()); logger != nil {
		_ = logger.Close()
	}
	require.NoError(t, stdoutW.Close())
	require.NoError(t, stderrW.Close())
	return <-outC, <-errC, code, cmd
}

// withArgs makes os.Args upterm's own, with args, for the test.
func withArgs(t *testing.T, args ...string) {
	t.Helper()
	orig := os.Args
	os.Args = append([]string{"upterm"}, args...)
	t.Cleanup(func() { os.Args = orig })
}

func TestAnErrorIsOneLineOnce(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	_, stderr, code := runCLI(t, "session", "info", "nosuch")
	require.Equal(t, 4, code)
	require.Equal(t, "upterm: no session named \"nosuch\"\n", stderr)
}

// The line on stderr is also in upterm.log: the log is where a failure is
// looked for later, and main's slog line never reached it.
func TestAnErrorIsRecordedInTheLog(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	_, _, code := runCLI(t, "session", "info", "nosuch")
	require.Equal(t, 4, code)

	raw, err := os.ReadFile(utils.UptermLogFilePath())
	require.NoError(t, err)
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec), line)
		if rec["level"] == "ERROR" && rec["error"] == `no session named "nosuch"` {
			found = true
		}
	}
	require.True(t, found, "the log has the error: %s", raw)
}

func TestSeveralValidationErrorsAreOneLineEach(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	origTimeout, origOutput := flagJoinTimeout, flagHostOutput
	t.Cleanup(func() { flagJoinTimeout, flagHostOutput = origTimeout, origOutput })

	// Three: the negative timeout, --output without --detach, and the format.
	_, stderr, code := runCLI(t, "host", "--join-timeout=-1s", "--output", "yaml")
	require.Equal(t, 1, code)
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	require.Len(t, lines, 3, stderr)
	for _, l := range lines {
		require.True(t, strings.HasPrefix(l, "upterm: "), l)
	}
	require.NotContains(t, stderr, "error occurred")
	require.NotContains(t, stderr, "Usage:")
}

func TestAStatusOnlyOutcomePrintsNothing(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	prevOutput, prevSocket := flagOutput, flagAdminSocket
	t.Cleanup(func() { flagOutput, flagAdminSocket = prevOutput, prevSocket })
	t.Setenv("UPTERM_ADMIN_SOCKET", "")
	t.Setenv("UPTERM_OUTPUT", "")

	_, stderr, code := runCLI(t, "session", "current", "-o", "json")
	require.Equal(t, 4, code)
	require.Empty(t, stderr)
}

// A diagnostic the command printed itself (D1 case 3) isn't printed again:
// its status is the ExitCodeError it wraps, or the command's failure code.
func TestAReportedDiagnosticPrintsNothingMore(t *testing.T) {
	var stderr bytes.Buffer
	cmd := &cobra.Command{Use: "x"}
	require.Equal(t, 1, Exit(cmd, Reported{Err: errors.New("said already")}, &stderr))
	require.Equal(t, 7, Exit(cmd, Reported{Err: ExitCodeError{Code: 7, Err: errors.New("said already")}}, &stderr))
	require.Equal(t, 1, Exit(cmd, SilentError{Err: errors.New("said already")}, &stderr))
	require.Empty(t, stderr.String())
}

// A command declares the status its own failures exit with (D2a); an error
// with no status of its own takes it.
func TestAnErrorTakesTheCommandsFailureCode(t *testing.T) {
	var stderr bytes.Buffer
	cmd := &cobra.Command{Use: "x", Annotations: map[string]string{"upterm/failure-code": "255"}}
	require.Equal(t, 255, Exit(cmd, errors.New("nope"), &stderr))
	require.Equal(t, 3, Exit(cmd, ExitCodeError{Code: 3, Err: errors.New("its own")}, &stderr))
	require.Equal(t, "upterm: nope\nupterm: its own\n", stderr.String())
	require.Equal(t, 1, failureCode(&cobra.Command{Use: "y"}))
}

// The one message with lines of its own, the changed-relay-key warning, is
// printed as it is: the prefix on its first line, nowhere else.
func TestAChangedRelayKeyKeepsItsLines(t *testing.T) {
	refusal, _ := changedKeyRefusal(t)
	require.Contains(t, refusal, "\n")
	// As the daemon's failure reaches the foreground host: a string.
	err := fmt.Errorf("session s could not start: ssh: handshake failed: %s", refusal)

	var stderr bytes.Buffer
	require.Equal(t, 1, Exit(&cobra.Command{Use: "host"}, err, &stderr))
	require.Equal(t, "upterm: "+err.Error()+"\n", stderr.String())
	require.Equal(t, 1, strings.Count(stderr.String(), "upterm: "))
}

func TestUnknownCommandsSuggestOnOneLine(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")

	_, stderr, code := runCLI(t, "sesion")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: unknown command \"sesion\"; did you mean session or version?\n", stderr)

	_, stderr, code = runCLI(t, "bogus")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: unknown command \"bogus\"\n", stderr)

	stdout, stderr, code := runCLI(t, "session", "lsit")
	require.Equal(t, 1, code)
	require.Empty(t, stdout)
	require.Equal(t, "upterm: unknown command \"lsit\" for upterm session; did you mean list, set or wait?\n", stderr)

	_, stderr, code = runCLI(t, "config", "edti")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: unknown command \"edti\" for upterm config; did you mean edit?\n", stderr)

	// cobra adds this group inside ExecuteC; Main's root has it already.
	_, stderr, code = runCLI(t, "completion", "bahs")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: unknown command \"bahs\" for upterm completion; did you mean bash?\n", stderr)

	for _, group := range [][]string{nil, {"session"}, {"config"}, {"completion"}} {
		stdout, stderr, code := runCLI(t, group...)
		require.Equal(t, 0, code, group) // help, as today
		require.Contains(t, stdout, "Available Commands:", group)
		require.Empty(t, stderr, group)
	}
}

// The root and the groups only print their help or name an unknown command,
// so a broken config file doesn't stop them, as it never stopped the help
// they printed when cobra couldn't run them.
func TestRootAndGroupsReadNoConfig(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "bogus-key: 1\n")
	for _, group := range [][]string{nil, {"session"}, {"config"}, {"completion"}} {
		stdout, stderr, code := runCLI(t, group...)
		require.Equal(t, 0, code, group)
		require.Contains(t, stdout, "Available Commands:", group)
		require.Empty(t, stderr, group)
	}
	_, stderr, code := runCLI(t, "session", "lsit")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: unknown command \"lsit\" for upterm session; did you mean list, set or wait?\n", stderr)

	// A command that does read it still refuses.
	_, stderr, code = runCLI(t, "session", "list")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, `upterm: unknown config key "bogus-key"`)
}

// A command that reads no config never fails on it (D11.1, P7): version,
// cobra's help and completion, and __complete, which tab completion runs.
// What decides it is declared, not whether the command has flags: completion
// bash has --no-descriptions.
func TestVersionHelpAndCompletionIgnoreABadConfig(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "authorized-user: [unclosed\n")
	for _, args := range [][]string{{"version"}, {"help", "host"}, {"completion", "bash"}, {"completion", "bash", "--no-descriptions"}, {"__complete", "session", "info", ""}} {
		_, stderr, code := runCLI(t, args...)
		require.Equal(t, 0, code, args)
		require.NotContains(t, stderr, "failed to read config file", args)
	}
	_, stderr, code := runCLI(t, "session", "info", "x")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "upterm: failed to read config file")
}

// A log file that can't be opened turns logging off with one warning, and
// fails nothing (D11.1).
func TestAnUnopenableLogFileWarnsAndGoesOn(t *testing.T) {
	withConfig(t, "")
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	require.NoError(t, os.WriteFile(filepath.Join(state, "upterm"), nil, 0o600)) // a file where the dir goes
	stdout, stderr, code := runCLI(t, "version")
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "Upterm version")
	require.Contains(t, stderr, "upterm: warning: can't open the log file")
	require.Equal(t, 1, strings.Count(stderr, "\n"))

	// The daemon says nothing: the parent has, and its stderr is the log.
	t.Setenv(daemonHandoffEnv, "3")
	_, stderr, code = runCLI(t, "version")
	require.Equal(t, 0, code)
	require.Empty(t, stderr)
}

// With no home directory, building the commands never exits; only a run
// that relies on a default from it fails, naming the flag to pass (D11.3).
func TestNoHomeFailsOnlyWhatNeedsIt(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	_, _, code := runCLI(t, "version")
	require.Equal(t, 0, code)
	_, _, code = runCLI(t, "--help")
	require.Equal(t, 0, code)

	// The defaults are empty, never a relative .ssh/ path; the help still
	// shows where they'd be.
	host, _, err := Root().Find([]string{"host"})
	require.NoError(t, err)
	require.Equal(t, "[]", host.PersistentFlags().Lookup("private-key").Value.String())
	require.Equal(t, "", host.PersistentFlags().Lookup("known-hosts").Value.String())
	require.Equal(t, "~/.ssh/known_hosts", host.PersistentFlags().Lookup("known-hosts").DefValue)

	// Only --known-hosts needs it. -i's default with no home is a home with
	// no keys: the agent's, then a generated one.
	_, homeErr := os.UserHomeDir()
	require.Error(t, homeErr)
	want := fmt.Sprintf("upterm: can't find your home directory for the default --known-hosts: %v; pass --known-hosts\n", homeErr)
	_, stderr, code := runCLI(t, "host", "--", "true")
	require.Equal(t, 1, code)
	require.Equal(t, want, stderr)
	_, stderr, code = runCLI(t, "join", "abc@relay.test")
	require.Equal(t, 255, code)
	require.Equal(t, want, stderr)

	// Supplied, from any origin, it isn't needed: each run goes on to the
	// terminal it doesn't have.
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	_, stderr, code = runCLI(t, "join", "--known-hosts", knownHosts, "abc@relay.test")
	require.Equal(t, 255, code)
	require.Equal(t, "upterm: upterm join needs a terminal.\n", stderr)
	t.Setenv("UPTERM_KNOWN_HOSTS", knownHosts)
	_, stderr, code = runCLI(t, "host", "--", "true")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: upterm host needs a terminal to ask before starting; pass --accept to start without asking\n", stderr)
}

// cmd/gendoc writes a man page for every command Root has, and completion
// isn't one of them: only the root Main runs adds it.
func TestRootHasNoCompletionCommand(t *testing.T) {
	for _, c := range Root().Commands() {
		require.NotEqual(t, "completion", c.Name())
	}
}

func TestMainInstallsTheSignalPolicyFirst(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	var calls []string
	origPolicy, origRoot := installSignalPolicy, mainRoot
	t.Cleanup(func() { installSignalPolicy, mainRoot = origPolicy, origRoot })
	installSignalPolicy = func() { calls = append(calls, "policy") }
	mainRoot = func() *cobra.Command {
		root := origRoot()
		version, _, err := root.Find([]string{"version"})
		require.NoError(t, err)
		run := version.RunE
		version.RunE = func(c *cobra.Command, args []string) error {
			calls = append(calls, "cmd")
			return run(c, args)
		}
		return root
	}
	withArgs(t, "version")
	_ = captureStdout(t, func() { require.Equal(t, 0, Main()) })
	require.Equal(t, []string{"policy", "cmd"}, calls)
}

func TestAnInvalidNameHasNoPackagePrefixOrRegex(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	_, stderr, _ := runCLI(t, "session", "info", "a:b")
	require.Equal(t, "upterm: \"a:b\" isn't a session name: use letters, digits, '.', '_' and '-', starting with a letter or digit, at most 64 bytes\n", stderr)
}

// Without --accept, upterm host asks before it starts, and can't ask in a
// pipe. It says so on one line and exits 1.
func TestHostWithoutATerminalOrAcceptIsOneLine(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	_, stderr, code := runCLI(t, "host", "--", "true")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: upterm host needs a terminal to ask before starting; pass --accept to start without asking\n", stderr)
}

// Every way upterm fails in a command takes that command's failure code
// (D2a): a usage error before RunE, a flag, and a config error before it too,
// not just what RunE returns.
func TestUsageAndConfigErrorsTakeTheCommandsFailureCode(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"attach", "a", "b"}, 255},
		{[]string{"attach", "--bogus"}, 255},
		{[]string{"join", "--bogus", "x@y"}, 255},
		{[]string{"session", "wait"}, 125},
		{[]string{"session", "wait", "--bogus", "x"}, 125},
		{[]string{"session", "info", "--bogus"}, 1},
	} {
		_, _, code := runCLI(t, tc.args...)
		require.Equal(t, tc.want, code, tc.args)
	}

	// A config error is found by PersistentPreRunE, before RunE.
	withConfig(t, "bogus-key: 1\n")
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"join", "x@y"}, 255},
		{[]string{"attach", "x"}, 255},
		{[]string{"session", "wait", "x"}, 125},
		{[]string{"session", "info", "x"}, 1},
	} {
		_, stderr, code := runCLI(t, tc.args...)
		require.Equal(t, tc.want, code, tc.args)
		require.Contains(t, stderr, "unknown config key", tc.args)
	}
}

// Arguments a command doesn't take are a usage error (D11.2), with its
// failure code (D2a), where they used to be ignored.
func TestExtraArgumentsAreUsageErrors(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	for _, args := range [][]string{{"version", "x"}, {"session", "list", "x"}, {"session", "current", "x"}, {"session", "info"}, {"session", "info", "a", "b"}, {"proxy", "wss://a@b", "x"}, {"upgrade", "1", "2"}} {
		_, stderr, code := runCLI(t, args...)
		require.Equal(t, 1, code, args)
		require.Contains(t, stderr, "upterm: accepts", args)
	}
}

// Ctrl-C at the accept prompt says nothing and exits 130 (D2a); the TUI's own
// last frame is the only word on it.
func TestInterruptedAtTheAcceptPromptIsSilent130(t *testing.T) {
	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	err := mapUserAction(cmd, UserInterruptedError{})
	require.Equal(t, 130, Exit(cmd, err, &stderr))
	require.Empty(t, stderr.String())

	// However the daemon's or the parent's error wraps it.
	err = mapUserAction(cmd, fmt.Errorf("session s: %w", UserInterruptedError{}))
	require.Equal(t, 130, Exit(cmd, err, &stderr))
	require.Empty(t, stderr.String())
}
