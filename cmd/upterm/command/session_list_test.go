package command

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/stretchr/testify/require"
)

func TestEveryRowIsPrinted(t *testing.T) {
	rows := make([]sessionRow, 13)
	for i := range rows {
		rows[i] = sessionRow{Name: fmt.Sprintf("s-%02d", i), Status: "ready", SessionID: fmt.Sprintf("%020d", i)}
	}
	var b bytes.Buffer
	writeSessionTable(&b, rows, 0)
	require.Equal(t, 14, strings.Count(b.String(), "\n"))
	require.Contains(t, b.String(), "s-12")
}

func TestNamesAndIDsAreNeverCut(t *testing.T) {
	long := "a-very-long-session-name-for-a-build"
	var b bytes.Buffer
	writeSessionTable(&b, []sessionRow{{Name: long, Status: "ready", SessionID: "Abc123Def456Ghi789Jk", Command: "/bin/bash -lc 'make test'", Relay: "ssh://uptermd.upterm.dev:22"}}, 30)
	require.Contains(t, b.String(), long)
	require.Contains(t, b.String(), "Abc123Def456Ghi789Jk")
}

func TestTheTableIsAlignedAndMarksTheCurrentSession(t *testing.T) {
	var b bytes.Buffer
	writeSessionTable(&b, []sessionRow{
		{Current: true, Name: "alpha", Status: "ready", SessionID: "sid-a", Command: "bash", Relay: "ssh://relay.example:2222"},
		{Name: "b", Status: "reconnecting", SessionID: "sid-b", Command: "tmux attach", Relay: "ssh://relay.example:2222"},
	}, 0)
	require.Equal(t, ""+
		"  NAME   STATUS        SESSION ID  COMMAND      RELAY\n"+
		"* alpha  ready         sid-a       bash         ssh://relay.example:2222\n"+
		"  b      reconnecting  sid-b       tmux attach  ssh://relay.example:2222\n",
		b.String())
}

// A session that has not reached ready has no session ID, relay or answer to
// the daemon, and its row still lines up and ends where its last cell does.
func TestEmptyCellsLeaveNoTrailingSpaces(t *testing.T) {
	var b bytes.Buffer
	writeSessionTable(&b, []sessionRow{{Name: "starting", Status: "starting", Command: "bash"}}, 0)
	require.Equal(t, ""+
		"  NAME      STATUS    SESSION ID  COMMAND  RELAY\n"+
		"  starting  starting              bash\n",
		b.String())
}

func TestLongCommandsAndRelaysAreShortenedToTheTerminal(t *testing.T) {
	const id = "Abc123Def456Ghi789Jk"
	command := "/usr/local/bin/some-very-long-wrapper --with --many --flags --and-then-some-more /a/long/path"
	relay := "wss://a-relay-with-a-very-long-host-name.example.com:8443/some/path"

	for _, tc := range []struct {
		name        string
		command     string
		relay       string
		wantCommand string
		wantRelay   string
		shortened   int
	}{
		{name: "both are long", command: command, relay: relay, shortened: 2},
		{name: "a short relay is kept whole", command: command, relay: "ssh://r.example", wantRelay: "ssh://r.example", shortened: 1},
		{name: "a short command is kept whole", command: "bash", relay: relay, wantCommand: "bash", shortened: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeSessionTable(&b, []sessionRow{{Name: "build", Status: "ready", SessionID: id, Command: tc.command, Relay: tc.relay}}, 80)

			lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
			require.Len(t, lines, 2)
			for _, line := range lines {
				require.LessOrEqual(t, utf8.RuneCountInString(line), 80, line)
			}
			row := lines[1]
			require.Contains(t, row, "build")
			require.Contains(t, row, id)
			if tc.wantCommand != "" {
				require.Contains(t, row, tc.wantCommand)
			}
			if tc.wantRelay != "" {
				require.Contains(t, row, tc.wantRelay)
			}
			require.Equal(t, tc.shortened, strings.Count(row, "…"), row)
			require.NotContains(t, lines[0], "…", "the header names the columns and is never cut")
		})
	}
}

// What fits is printed as it is: shortening is for cells that would run past
// the terminal, not for every cell on a terminal.
func TestCellsThatFitAreNotShortened(t *testing.T) {
	var b bytes.Buffer
	row := sessionRow{Name: "build", Status: "ready", SessionID: "sid", Command: "/bin/bash -lc 'make test'", Relay: "ssh://uptermd.upterm.dev"}
	writeSessionTable(&b, []sessionRow{row}, 200)
	require.NotContains(t, b.String(), "…")
	require.Contains(t, b.String(), row.Command)
	require.Contains(t, b.String(), row.Relay)
}

// Without a terminal nothing is shortened, however long: a script reads the
// whole cell.
func TestWidthZeroShortensNothing(t *testing.T) {
	row := sessionRow{Name: "build", Status: "ready", SessionID: "sid", Command: strings.Repeat("c", 500), Relay: "ssh://" + strings.Repeat("r", 500)}
	var b bytes.Buffer
	writeSessionTable(&b, []sessionRow{row}, 0)
	require.NotContains(t, b.String(), "…")
	require.Contains(t, b.String(), row.Command)
	require.Contains(t, b.String(), row.Relay)
}

func TestNarrowTerminalsNeverPanic(t *testing.T) {
	row := sessionRow{Name: "a-very-long-session-name-for-a-build", Status: "reconnecting", SessionID: "Abc123Def456Ghi789Jk", Command: "/bin/bash -lc 'make test'", Relay: "ssh://uptermd.upterm.dev:22"}
	for _, width := range []int{1, 2, 3, 10, 30, 60, 75} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			var b bytes.Buffer
			require.NotPanics(t, func() { writeSessionTable(&b, []sessionRow{row, {Name: "n", Current: true}}, width) })

			out := b.String()
			require.Contains(t, out, row.Name)
			require.Contains(t, out, row.SessionID)
			require.Equal(t, 3, strings.Count(out, "\n"))
			// Past what NAME, STATUS and SESSION ID need, there is nothing
			// left for COMMAND and RELAY but the width of their headers, of
			// which only the start of each cell is kept.
			require.NotContains(t, out, "bash")
			require.NotContains(t, out, "uptermd")
			require.Equal(t, 2, strings.Count(out, "…"), out)
		})
	}
}

// A cell holding a newline or a tab would split its row in two or push the
// columns after it out of line: the table is one row per session.
func TestACellCannotBreakItsRow(t *testing.T) {
	var b bytes.Buffer
	writeSessionTable(&b, []sessionRow{
		{Name: "multi", Status: "ready", SessionID: "sid", Command: "sh -c 'echo one\n\techo two\x1b[31m'", Relay: "ssh://r.example"},
	}, 0)
	out := b.String()
	require.Equal(t, 2, strings.Count(out, "\n"), out)
	require.NotContains(t, out, "\t")
	require.NotContains(t, out, "\x1b")
	require.Contains(t, out, "echo one")
	require.Contains(t, out, "echo two")
	require.Contains(t, out, "ssh://r.example")
}

func TestNoSessionsIsQuietOnStdout(t *testing.T) {
	setupSessionRoots(t)
	stdout, stderr, code := runCLI(t, "session", "list")
	require.Equal(t, 0, code)
	require.Empty(t, stdout)
	require.Equal(t, "upterm: no sessions are running\n", stderr)
}

func TestListPrintsEverySessionOnce(t *testing.T) {
	setupSessionRoots(t)
	const sessions = 12
	for i := range sessions {
		heldReady(t, fmt.Sprintf("s-%02d", i))
	}

	stdout, stderr, code := runCLI(t, "session", "list")
	require.Equal(t, 0, code, stderr)
	require.Empty(t, stderr)

	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	require.Len(t, lines, sessions+1, "the header and a row for each session, however many")
	require.Equal(t, []string{"NAME", "STATUS", "SESSION", "ID", "COMMAND", "RELAY"}, strings.Fields(lines[0]))
	for i, line := range lines[1:] {
		require.Equal(t, fmt.Sprintf("s-%02d", i), strings.Fields(line)[0])
	}
}

func TestListMarksTheSessionItRunsInside(t *testing.T) {
	setupSessionRoots(t)
	for _, name := range []string{"alpha", "beta"} {
		d := heldReady(t, name)
		serveStubAdmin(t, d.AdminSocket(), &api.GetSessionResponse{
			SessionId: "sid",
			Host:      "ssh://127.0.0.1:2222",
			NodeAddr:  "127.0.0.1:2222",
			Command:   []string{"bash", "-l"},
		})
		if name == "beta" {
			t.Setenv("UPTERM_ADMIN_SOCKET", d.AdminSocket())
		}
	}

	stdout, stderr, code := runCLI(t, "session", "list")
	require.Equal(t, 0, code, stderr)
	require.Equal(t, ""+
		"  NAME   STATUS  SESSION ID  COMMAND  RELAY\n"+
		"  alpha  ready   sid         bash -l  ssh://127.0.0.1:2222\n"+
		"* beta   ready   sid         bash -l  ssh://127.0.0.1:2222\n",
		stdout)
}

func TestListJSONIgnoresOutputFromEnv(t *testing.T) {
	setupSessionRoots(t)
	t.Setenv("UPTERM_OUTPUT", "yaml")
	stdout, _, code := runCLI(t, "session", "list", "-o", "json")
	require.Equal(t, 0, code)
	require.Equal(t, "[]\n", stdout)
}

// The format is the command line's alone: an output key or UPTERM_OUTPUT is
// for the commands that take it from there, and must neither turn this
// listing into JSON nor make it fail.
func TestListFormatIsNotTakenFromEnvOrConfig(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T)
	}{
		{"UPTERM_OUTPUT", func(t *testing.T) { t.Setenv("UPTERM_OUTPUT", "json") }},
		{"an output key in the config", func(t *testing.T) { withConfig(t, "output: json\n") }},
		{"an output key the host would refuse", func(t *testing.T) { withConfig(t, "output: yaml\n") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			tc.setup(t)

			stdout, stderr, code := runCLI(t, "session", "list")
			require.Equal(t, 0, code, stderr)
			require.Equal(t, "upterm: no sessions are running\n", stderr)
			require.Empty(t, stdout)

			heldReady(t, "listed")
			stdout, stderr, code = runCLI(t, "session", "list")
			require.Equal(t, 0, code, stderr)
			require.Empty(t, stderr)
			require.Equal(t, []string{"NAME", "STATUS", "SESSION", "ID", "COMMAND", "RELAY"}, strings.Fields(strings.SplitN(stdout, "\n", 2)[0]), stdout)
		})
	}
}

func TestListJSONIsAnArrayOfSessionInfo(t *testing.T) {
	setupSessionRoots(t)
	buildReady(t, "answering")
	buildStarting(t, "starting")
	// Ready by its record, with nothing bound where the record says it
	// answers: the record is all there is to say about it.
	silent := claimSession(t, "silent")
	releaseAtEnd(t, silent)
	require.NoError(t, silent.Update(func(r *sessiondir.Record) {
		r.Status = sessiondir.StatusReady
		r.SessionID = "sid-silent"
	}))

	stdout, stderr, code := runCLI(t, "session", "list", "-o", "json")
	require.Equal(t, 0, code, stderr)
	require.Empty(t, stderr)

	var got []map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &got), stdout)
	require.Len(t, got, 3)
	byName := map[string]map[string]any{}
	for _, info := range got {
		byName[info["name"].(string)] = info
	}

	answering := byName["answering"]
	require.Equal(t, sessiondir.StatusReady, answering["status"])
	require.Equal(t, "sid-1", answering["sessionId"])
	require.NotEmpty(t, answering["sshCommand"], "the daemon answered, so the object has what only it knows")
	require.NotEmpty(t, answering["joinCommand"])

	silentInfo := byName["silent"]
	require.Equal(t, "sid-silent", silentInfo["sessionId"])
	require.NotContains(t, silentInfo, "sshCommand", "nothing answered, so no connect string is invented")
	require.Equal(t, "record", silentInfo["joinStateSource"])

	require.Equal(t, sessiondir.StatusStarting, byName["starting"]["status"])

	// Each element is what `session info -o json` says of that session: the
	// listing builds it the same way, not a thinner copy.
	for name, listed := range byName {
		require.Equal(t, lookupJSON(t, name), listed, name)
	}
}

func TestListJSONWithNoSessionsIsAnEmptyArrayAndNothingElse(t *testing.T) {
	setupSessionRoots(t)
	stdout, stderr, code := runCLI(t, "session", "list", "-o", "json")
	require.Equal(t, 0, code)
	require.Equal(t, "[]\n", stdout)
	require.Empty(t, stderr, "the array is the answer, as it is for a script")
}

func TestListRejectsAnOutputFormatItDoesNotKnow(t *testing.T) {
	setupSessionRoots(t)
	heldReady(t, "listed")

	stdout, stderr, code := runCLI(t, "session", "list", "-o", "yaml")
	require.Equal(t, 1, code)
	require.Empty(t, stdout)
	require.Equal(t, "upterm: invalid output format \"yaml\": must be 'json'\n", stderr)
}

// The listing's JSON names a session's clients as `session info` does, so the
// address of a guest is hidden by the same three means: the flag, the
// environment variable and the config's hide-client-ip. A key or variable that
// reached `session info` and not this would print the address the host chose
// to hide.
func TestListJSONHidesClientIPsAsConfigured(t *testing.T) {
	const addr = "203.0.113.7"
	for _, tc := range []struct {
		name   string
		args   []string
		env    string
		config string
		hidden bool
	}{
		{name: "by the flag", args: []string{"--hide-client-ip"}, hidden: true},
		{name: "by the environment", env: "true", hidden: true},
		{name: "by the config", config: "hide-client-ip: true\n", hidden: true},
		{name: "by none of them"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// CI hides addresses on its own, which would prove nothing here.
			withClientIPs(t, false)
			withConfig(t, tc.config)
			t.Setenv("UPTERM_HIDE_CLIENT_IP", tc.env)

			setupSessionRoots(t)
			d := claimSession(t, "build")
			releaseAtEnd(t, d)
			require.NoError(t, d.Update(func(r *sessiondir.Record) {
				r.Status = sessiondir.StatusReady
				r.SessionID = "sid-1"
			}))
			serveStubAdmin(t, d.AdminSocket(), newDaemonAnswer(d.LaunchID()))

			stdout, stderr, code := runCLI(t, append([]string{"session", "list", "-o", "json"}, tc.args...)...)
			require.Equal(t, 0, code, stderr)
			if tc.hidden {
				require.Contains(t, stdout, "guest [redacted] SSH-2.0-OpenSSH_9.6 SHA256:alice")
				require.NotContains(t, stdout, addr)
				return
			}
			require.Contains(t, stdout, "guest "+addr+":50000 SSH-2.0-OpenSSH_9.6 SHA256:alice")
		})
	}
}

// COMMAND and RELAY give up width only down to their headers, which are never
// cut: a cell cut to less leaves its column as wide as the header, so the rows
// still run past the edge and for nothing. The header line's own width is the
// narrowest the table gets. At any width from there up no line runs past it;
// below, the table stays that wide, and no cell is cut shorter than its header.
// Names, statuses and IDs are never cut.
func TestShortenedColumnsNeverGoBelowTheirHeaders(t *testing.T) {
	const id = "Abc123Def456Ghi789Jk"
	longCommand := "/usr/local/bin/some-very-long-wrapper --with --many --flags --and-then-some-more /a/long/path"
	longRelay := "wss://a-relay-with-a-very-long-host-name.example.com:8443/some/path"

	for _, tc := range []struct {
		name string
		rows []sessionRow
	}{
		{"short cells", []sessionRow{{Name: "build", Status: "ready", SessionID: id, Command: "sh", Relay: "ssh://r:22"}}},
		{"both long", []sessionRow{{Name: "build", Status: "ready", SessionID: id, Command: longCommand, Relay: longRelay}}},
		{"a long command and a short relay", []sessionRow{{Name: "build", Status: "ready", SessionID: id, Command: longCommand, Relay: "ssh://r:22"}}},
		{"a short command and a long relay", []sessionRow{{Name: "build", Status: "ready", SessionID: id, Command: "sh", Relay: longRelay}}},
		{"a command much longer than the relay", []sessionRow{{Name: "build", Status: "ready", SessionID: id, Command: strings.Repeat("c", 300), Relay: "ssh://r:22"}}},
		{"a relay much longer than the command", []sessionRow{{Name: "build", Status: "ready", SessionID: id, Command: "sh", Relay: "ssh://" + strings.Repeat("r", 300)}}},
		{"rows of every shape", []sessionRow{
			{Current: true, Name: "a-very-long-session-name-for-a-build", Status: "reconnecting", SessionID: id, Command: longCommand, Relay: longRelay},
			{Name: "build", Status: "ready", SessionID: id, Command: "sh", Relay: longRelay},
			{Name: "tmux", Status: "ready", SessionID: id, Command: longCommand, Relay: "ssh://r:22"},
			{Name: "starting", Status: "starting", Command: "bash"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The narrowest the table can be is the one with nothing in
			// COMMAND and RELAY but their headers.
			bare := make([]sessionRow, len(tc.rows))
			for i, r := range tc.rows {
				r.Command, r.Relay = "", ""
				bare[i] = r
			}
			var b bytes.Buffer
			writeSessionTable(&b, bare, 0)
			narrowest := utf8.RuneCountInString(strings.SplitN(b.String(), "\n", 2)[0])

			b.Reset()
			writeSessionTable(&b, tc.rows, 0)
			widest := 0
			for _, line := range strings.Split(b.String(), "\n") {
				widest = max(widest, utf8.RuneCountInString(line))
			}

			printed := func(width int) []string {
				var b bytes.Buffer
				writeSessionTable(&b, tc.rows, width)
				lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
				require.Len(t, lines, len(tc.rows)+1, "width %d", width)
				return lines
			}

			t.Run("no line runs past a terminal as wide as the header line", func(t *testing.T) {
				for width := narrowest; width <= widest+1; width++ {
					for _, line := range printed(width) {
						require.LessOrEqual(t, utf8.RuneCountInString(line), width, "width %d: %q", width, line)
					}
				}
			})

			t.Run("a narrower terminal gets a table as wide as the header line", func(t *testing.T) {
				for width := 1; width < narrowest; width++ {
					for _, line := range printed(width) {
						require.LessOrEqual(t, utf8.RuneCountInString(line), narrowest, "width %d: %q", width, line)
					}
				}
			})

			t.Run("no cell is cut below its header, and names, statuses and IDs are not cut", func(t *testing.T) {
				commandHeader := utf8.RuneCountInString(sessionTableHeader[columnCommand])
				relayHeader := utf8.RuneCountInString(sessionTableHeader[columnRelay])
				for width := 1; width <= widest+1; width++ {
					lines := printed(width)
					header := lines[0]
					require.GreaterOrEqual(t, utf8.RuneCountInString(header), narrowest, "width %d: the header is never cut", width)
					commandAt, relayAt := strings.Index(header, "COMMAND"), strings.Index(header, "RELAY")

					for i, line := range lines[1:] {
						row := tc.rows[i]
						require.Contains(t, line, row.Name, "width %d", width)
						require.Contains(t, line, row.Status, "width %d", width)
						require.Contains(t, line, row.SessionID, "width %d", width)

						cells := []rune(line)
						cell := func(from, to int) string {
							if from >= len(cells) {
								return ""
							}
							return strings.TrimRight(string(cells[from:min(to, len(cells))]), " ")
						}
						if command := cell(commandAt, relayAt); strings.HasSuffix(command, "…") {
							require.GreaterOrEqual(t, utf8.RuneCountInString(command), commandHeader, "width %d: %q", width, line)
						}
						if relay := cell(relayAt, len(cells)); strings.HasSuffix(relay, "…") {
							require.GreaterOrEqual(t, utf8.RuneCountInString(relay), relayHeader, "width %d: %q", width, line)
						}
					}
				}
			})
		})
	}
}
