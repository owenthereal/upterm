package command

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// allCommands is every command in the tree under root, root included.
func allCommands(root *cobra.Command) []*cobra.Command {
	cmds := []*cobra.Command{root}
	for _, c := range root.Commands() {
		cmds = append(cmds, allCommands(c)...)
	}
	return cmds
}

// findCommand is the command at path ("upterm session info") in the tree
// Main runs.
func findCommand(t *testing.T, path string) *cobra.Command {
	t.Helper()
	c, rest, err := cliRoot().Find(strings.Fields(path)[1:])
	require.NoError(t, err, path)
	require.Empty(t, rest, path)
	return c
}

// isCompletion is true for cobra's completion command and its subcommands.
func isCompletion(c *cobra.Command) bool {
	for ; c.HasParent(); c = c.Parent() {
		if c.Name() == "completion" && !c.Parent().HasParent() {
			return true
		}
	}
	return false
}

// oneSpaced is s with each run of white space one space, so that a help
// text may wrap anywhere.
func oneSpaced(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// exampleSessionID is the session ID the examples show.
const exampleSessionID = "d3k5fia7m4us73ehblug"

// exitStatuses is what each command's help ends with: when it exits with
// what.
var exitStatuses = map[string]string{
	"upterm host":   "Exit status: the command's own status when it exits; 1 when upterm fails, or the session is stopped or ends by a signal (whatever the command returns while it is torn down); 254 when this terminal is disconnected; 130 for Ctrl-C at a prompt, 143 for a SIGTERM there; 0 after declining at the prompt or detaching (~.). A command's own 1 or 254 reads the same. With --detach: 0 once the session has started, 1 when it can't start; upterm session wait NAME reports the command's status.",
	"upterm attach": "Exit status: 0 after a detach; the session's status once it ends (0 when no guest joined within its join timeout; 1 when it was stopped or ended by a signal); 254 if this terminal was disconnected; 255 if it could not attach, including a usage or configuration error.",
	"upterm join":   "Exits with the session's status when one arrives, 0 when you leave (~.), 130 when stopped, and 255 when it can't join, including a usage or configuration error.",
	"upterm proxy":  "Exit status: 1 when it can't connect to the relay, including a usage or configuration error. Once connected, the first result reported decides: 0 for end-of-input from ssh, 1 when the relay closes the connection or a read or write fails.",

	"upterm session current": "Exits 4 when not in a session ($UPTERM_ADMIN_SOCKET is unset, or no session answers at it), and 1 for any other failure. With -o, not being in a session prints nothing.",
	"upterm session info":    "Exits 4 when no session has the name, and 1 for any other failure.",
	"upterm session list":    "Exit status: 0, or 1 when the records directory can't be read, or for a usage or configuration error. A session whose own record can't be read is left out of the list.",
	"upterm session set":     "Exits 0 when the session took the change, was already claimed, is ending, or has already ended, 4 when no session has the name, and 1 for any other failure -- including a change that could not be confirmed, which may still have taken effect: running set again restarts the window, and 'upterm session info NAME' shows what the session holds.",
	"upterm session stop":    "Exits 4 when no session has the name, and 1 for any other failure.",
	"upterm session wait":    "Exit status follows the session: its command's status when the command exited; 0 when it was stopped, or no guest joined within its join timeout; 128+N when the host or its command was killed by signal N; 125 when the outcome can't be known or read, when no session has the name, or for a usage or configuration error. A command can exit 125 too; 'upterm session info NAME -o json' has the reason. Ctrl-C stops waiting, with 130 on Unix, and leaves the session running.",

	"upterm upgrade":     "Exit status: 0 when upterm is up to date or was replaced; 1 when it couldn't be, a package manager owns it, or its arguments are wrong.",
	"upterm version":     "Exit status: 0, or 1 on failure.",
	"upterm config path": "Exit status: 0, or 1 on failure.",
	"upterm config view": "Exit status: 0, or 1 on failure.",
	"upterm config edit": "Exit status: 0, or 1 on failure.",
}

// Every command that runs ends its help with when it exits with what; the
// root and the groups run nothing of their own, so theirs say nothing of it.
// A new command fails here until it has its line.
func TestEveryLeafCommandEndsWithItsExitStatuses(t *testing.T) {
	seen := make(map[string]bool)
	for _, c := range allCommands(cliRoot()) {
		path := c.CommandPath()
		if c.HasSubCommands() {
			require.NotContains(t, c.Long, "Exit status", path)
			require.NotContains(t, c.Long, "Exits ", path)
			continue
		}
		if c.Hidden || c.Name() == "help" || isCompletion(c) {
			continue
		}
		want, ok := exitStatuses[path]
		require.True(t, ok, "%s has no exit statuses in this test's table", path)
		require.True(t, strings.HasSuffix(oneSpaced(c.Long), oneSpaced(want)),
			"%s's help doesn't end with its exit statuses:\n%s", path, c.Long)
		seen[path] = true
	}
	for path := range exitStatuses {
		require.True(t, seen[path], "%s isn't a command", path)
	}
}

// The usage line --help prints names each argument a command takes.
func TestUsageLinesNameTheirArguments(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	for path, want := range map[string]string{
		"upterm host":         "upterm host [flags] [-- COMMAND [ARGS...]]",
		"upterm proxy":        "upterm proxy [flags] URL",
		"upterm upgrade":      "upterm upgrade [VERSION] [flags]",
		"upterm session info": "upterm session info NAME|ID [flags]",
		"upterm session wait": "upterm session wait NAME|ID [flags]",
		"upterm session stop": "upterm session stop NAME|ID [flags]",
		"upterm session set":  "upterm session set NAME|ID [flags]",
		"upterm attach":       "upterm attach [NAME|ID] [flags]",
	} {
		stdout, _, code := runCLI(t, append(strings.Fields(path)[1:], "--help")...)
		require.Equal(t, 0, code, path)
		_, usage, ok := strings.Cut(stdout, "Usage:\n  ")
		require.True(t, ok, "%s: %s", path, stdout)
		line, _, _ := strings.Cut(usage, "\n")
		require.Equal(t, want, line, path)
	}
}

// The commands that take a session say it may be given by name or by ID,
// and show an ID in an example.
func TestSessionArgumentsAreANameOrAnID(t *testing.T) {
	for _, path := range []string{"upterm attach", "upterm session info", "upterm session wait", "upterm session stop", "upterm session set"} {
		c := findCommand(t, path)
		require.Contains(t, oneSpaced(c.Long), oneSpaced(nameOrIDHelp), path)
		require.Contains(t, c.Example, exampleSessionID, path)
	}
}

// A flag that behaves the same in host, join and attach has one help text.
// -i's explicit list behaves the same in host and join, and its default
// doesn't, so the explicit list's text is shared and the rest is each
// command's own.
func TestSharedFlagsShareTheirHelp(t *testing.T) {
	host, join, attach := findCommand(t, "upterm host"), findCommand(t, "upterm join"), findCommand(t, "upterm attach")
	for _, name := range []string{"known-hosts", "skip-host-key-check", "proxy", "escape-char"} {
		require.NotNil(t, host.Flag(name), name)
		require.NotNil(t, join.Flag(name), name)
		require.Equal(t, join.Flag(name).Usage, host.Flag(name).Usage, name)
	}
	require.Equal(t, join.Flag("escape-char").Usage, attach.Flag("escape-char").Usage)

	require.Contains(t, host.Flag("private-key").Usage, identitiesOnlyHelp)
	require.Contains(t, join.Flag("private-key").Usage, identitiesOnlyHelp)
	require.NotEqual(t, join.Flag("private-key").Usage, host.Flag("private-key").Usage)
}

// session current's help lists every variable its template can read, and
// only those: the list's own words, not any mention elsewhere in the help.
func TestSessionCurrentNamesEveryTemplateVariable(t *testing.T) {
	long := findCommand(t, "upterm session current").Long
	_, list, ok := strings.Cut(long, "Template variables:")
	require.True(t, ok, long)
	list, _, _ = strings.Cut(list, ".")
	list = regexp.MustCompile(`\([^)]*\)`).ReplaceAllString(list, "")
	var listed []string
	for _, word := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		if word != "and" {
			listed = append(listed, word)
		}
	}

	var fields []string
	info := reflect.TypeFor[currentInfo]()
	for i := range info.NumField() {
		if f := info.Field(i); f.IsExported() {
			fields = append(fields, f.Name)
		}
	}
	require.ElementsMatch(t, fields, listed)
}

// host's help says the same about approving file transfers wherever it
// says it: in its description and at --accept, --read-only and --no-sftp.
func TestFileTransferApprovalIsToldTheSameEverywhere(t *testing.T) {
	host := findCommand(t, "upterm host")
	for what, text := range map[string]string{
		"help":        host.Long,
		"--accept":    host.Flag("accept").Usage,
		"--read-only": host.Flag("read-only").Usage,
		"--no-sftp":   host.Flag("no-sftp").Usage,
	} {
		require.Contains(t, oneSpaced(text), transferApprovalHelp, what)
		require.Contains(t, oneSpaced(text), transferDeniedHelp, what)
	}
}

// The help shows where --admin-socket's default comes from, never the path
// in this shell's variable, so generated docs and a pasted help leak none.
func TestSessionCurrentHelpShowsTheVariableNotItsValue(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "")
	t.Setenv("UPTERM_ADMIN_SOCKET", "/secret/admin.sock")
	stdout, _, code := runCLI(t, "session", "current", "--help")
	require.Equal(t, 0, code)
	require.NotContains(t, stdout, "/secret/admin.sock")
	require.Contains(t, stdout, `(default "$UPTERM_ADMIN_SOCKET")`)
}
