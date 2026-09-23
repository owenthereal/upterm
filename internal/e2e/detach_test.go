package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/tmux"
	"github.com/stretchr/testify/require"
)

// The session runs in a process of its own, and the terminal that started
// it is a client: ~. leaves it running, another terminal can attach, and
// session stop ends it.
func TestHostDetachKeyLeavesTheSessionRunning(t *testing.T) {
	h := newTestHarness(t, 200)
	name := fmt.Sprintf("e2e-fg-%d", time.Now().UnixNano()%1_000_000)
	h.stopOnCleanup(name)

	hostCmd := fmt.Sprintf("upterm host --accept --skip-host-key-check --server %s --private-key %s --name %s -- bash --rcfile %s --noprofile; echo HOST_STATUS=$?",
		h.serverURL, h.keyFile, name, h.rcFile)
	require.NoError(t, h.host.SendLine(h.ctx, hostCmd))
	require.NoError(t, h.waitForText(h.host, uptermPrompt, 30*time.Second), "the host's own terminal is attached to the session")

	marker := fmt.Sprintf("BEFORE_%d", time.Now().UnixNano())
	require.NoError(t, h.host.SendLine(h.ctx, fmt.Sprintf(`echo "BEF""%s"`, strings.TrimPrefix(marker, "BEF"))))
	require.NoError(t, h.waitForText(h.host, marker, 10*time.Second))

	require.NoError(t, h.host.SendKeys(h.ctx, "Enter"))
	require.NoError(t, h.host.SendKeys(h.ctx, "~."))
	require.NoError(t, h.waitForText(h.host, "detached from session "+name, 10*time.Second))
	require.NoError(t, h.waitForText(h.host, "HOST_STATUS=0", 10*time.Second), "a detach exits 0")

	// Still running, and still answering. The marker is split across a shell
	// concatenation so that the line typed does not itself contain it:
	// waiting for a marker the terminal has already echoed back would match
	// before upterm had printed a byte, and capture an empty screen.
	require.NoError(t, h.host.SendLine(h.ctx, "upterm session info "+name+` -o json; echo "INFO""_DONE"`))
	require.NoError(t, h.waitForText(h.host, "INFO_DONE", 20*time.Second))
	out, err := h.host.Capture(h.ctx)
	require.NoError(t, err)
	require.Contains(t, out, `"status": "ready"`)

	// Another terminal picks it up, with the earlier output in the replay.
	term := h.splitPane(h.host)
	require.NoError(t, term.SendLine(h.ctx, "upterm attach "+name+"; echo ATTACH_STATUS=$?"))
	require.NoError(t, h.waitForText(term, marker, 30*time.Second), "the replay carries what was printed before the detach")
	require.NoError(t, term.SendKeys(h.ctx, "Enter"))
	require.NoError(t, term.SendKeys(h.ctx, "~."))
	require.NoError(t, h.waitForText(term, "ATTACH_STATUS=0", 10*time.Second))

	// And session stop ends it, with the record saying so.
	require.NoError(t, h.host.SendLine(h.ctx, "clear; upterm session stop "+name+"; echo STOP_STATUS=$?"))
	require.NoError(t, h.waitForText(h.host, "STOP_STATUS=0", 40*time.Second))
	require.NoError(t, h.host.SendLine(h.ctx, "clear; upterm session info "+name+` -o json; echo "INFO2""_DONE"`))
	require.NoError(t, h.waitForText(h.host, "INFO2_DONE", 20*time.Second))
	out, err = h.host.Capture(h.ctx)
	require.NoError(t, err)
	require.Contains(t, out, `"status": "ended"`)
	require.Contains(t, out, `"reason": "stopped"`)
}

// --detach starts a session with no terminal at all and prints how to reach
// it; a script parses the JSON, a person attaches by name.
func TestDetachedHostPrintsJSONAndCanBeAttachedAndStopped(t *testing.T) {
	h := newTestHarness(t, 200)
	name := fmt.Sprintf("e2e-bg-%d", time.Now().UnixNano()%1_000_000)
	h.stopOnCleanup(name)

	hostCmd := fmt.Sprintf("clear; upterm host --detach --accept --skip-host-key-check --server %s --private-key %s --name %s -o json -- bash --rcfile %s --noprofile; echo DETACH_STATUS=$?",
		h.serverURL, h.keyFile, name, h.rcFile)
	require.NoError(t, h.host.SendLine(h.ctx, hostCmd))
	require.NoError(t, h.waitForText(h.host, "DETACH_STATUS=0", 30*time.Second))

	out, err := h.host.Capture(h.ctx)
	require.NoError(t, err)
	// The JSON is indented one field per line, so it survives a 200-column
	// pane intact; take the lines between the braces.
	start, end := strings.Index(out, "{"), strings.LastIndex(out, "}")
	require.True(t, start >= 0 && end > start, "no JSON in:\n%s", out)
	var info struct {
		Name         string `json:"name"`
		Status       string `json:"status"`
		SessionID    string `json:"sessionId"`
		SSHCommand   string `json:"sshCommand"`
		AttachSocket string `json:"attachSocket"`
		LogPath      string `json:"logPath"`
		Pid          int    `json:"pid"`
	}
	require.NoError(t, json.Unmarshal([]byte(out[start:end+1]), &info), "not JSON: %s", out[start:end+1])
	require.Equal(t, name, info.Name)
	require.Equal(t, "ready", info.Status)
	require.NotEmpty(t, info.SessionID)
	require.Contains(t, info.SSHCommand, "ssh ")
	require.NotEmpty(t, info.AttachSocket)
	require.NotEmpty(t, info.LogPath)
	require.NotZero(t, info.Pid)

	// A guest can join with the connect string it printed…
	client := h.splitPane(h.host)
	h.connectClient(client, info.SSHCommand)

	// …and a terminal can attach by name, finding the shell's prompt in the
	// replay even though nobody was watching when it printed.
	term := h.splitPane(h.host)
	require.NoError(t, term.SendLine(h.ctx, "upterm attach "+name+"; echo ATTACH_STATUS=$?"))
	require.NoError(t, h.waitForText(term, uptermPrompt, 30*time.Second))
	marker := fmt.Sprintf("DETACHED_%d", time.Now().UnixNano())
	require.NoError(t, term.SendLine(h.ctx, fmt.Sprintf(`echo "DET""%s"`, strings.TrimPrefix(marker, "DET"))))
	require.NoError(t, h.waitForText(term, marker, 10*time.Second))
	require.NoError(t, h.waitForText(client, marker, 10*time.Second), "the guest sees what the attached terminal typed")
	require.NoError(t, term.SendKeys(h.ctx, "Enter"))
	require.NoError(t, term.SendKeys(h.ctx, "~."))
	require.NoError(t, h.waitForText(term, "ATTACH_STATUS=0", 10*time.Second))

	require.NoError(t, h.host.SendLine(h.ctx, "clear; upterm session stop "+name+"; echo STOP_STATUS=$?"))
	require.NoError(t, h.waitForText(h.host, "STOP_STATUS=0", 40*time.Second))
	require.NoError(t, h.waitForText(client, "Connection to", 20*time.Second), "the guest's ssh ends with the session")
}

// A stop reaches every terminal attached to the session, not only the one
// that started it. Both the host's own terminal and an `upterm attach` see
// the resulting exit status: the door gives a command that was signalled
// rather than exited sess.Exit(1)
// (host/internal/server.go's commandDone branch — a stop sends SIGHUP to
// the command's process group, so bash dies by signal, not by exiting), and
// the host prints commandExitedMessage while `upterm attach` reports the
// status without attributing a cause it cannot observe. Both restore the
// terminal modes they found on the way out: the host's own through
// localclient.go, `upterm attach` through withRawTerminal in
// cmd/upterm/command/terminal.go. Every other stop test in this file stops
// a session with nothing attached; this is the one with two terminals on
// it when the stop lands.
func TestSessionStopReleasesAttachedTerminals(t *testing.T) {
	h := newTestHarness(t, 200)
	name := fmt.Sprintf("e2e-stopat-%d", time.Now().UnixNano()%1_000_000)
	h.stopOnCleanup(name)

	// The comparison lives in a script, as in
	// TestAttachLeavesTheTerminalAsItFoundIt: a pane is narrower than the
	// line this would otherwise be, and a marker split across a wrap is one
	// no assertion can find. modes() is that test's function verbatim — it
	// compares the modes raw mode turns off, not `stty -g`, because that
	// blob carries PENDIN too, a kernel state bit meaning "input is
	// pending" that the very keystrokes starting this script set, so
	// comparing it whole would report a difference that has nothing to do
	// with whether the terminal was restored.
	//
	// The script takes a label and then the command to run, so one script
	// serves both terminals. Its markers — HOST_STATUS=, HOST_TTY=,
	// ATTACH_STATUS=, ATTACH_TTY= — never appear in the typed command line,
	// which carries only the bare label: a wait for one of them can only
	// match the script's own output, never the terminal's echo of the
	// keystrokes that started it.
	script := filepath.Join(h.tmpDir, "stop-modes.sh")
	require.NoError(t, os.WriteFile(script, []byte(
		"modes() { stty -a | tr ' ,' '\\n\\n' | grep -E '^-?(echo|icanon|isig|iexten|icrnl|opost)$' | sort | tr '\\n' ' '; }\n"+
			"label=$1; shift\n"+
			"before=$(modes)\n"+
			"\"$@\"\n"+
			"status=$?\n"+
			"after=$(modes)\n"+
			"echo \"${label}_STATUS=$status\"\n"+
			"if [ \"$before\" = \"$after\" ]; then echo \"${label}_TTY=same\"; else echo \"${label}_TTY=CHANGED [$before] [$after]\"; fi\n"),
		0755))

	hostCmd := fmt.Sprintf("sh %s HOST upterm host --accept --skip-host-key-check --server %s --private-key %s --name %s -- bash --rcfile %s --noprofile",
		script, h.serverURL, h.keyFile, name, h.rcFile)
	require.NoError(t, h.host.SendLine(h.ctx, hostCmd))
	require.NoError(t, h.waitForText(h.host, uptermPrompt, 30*time.Second), "the host's own terminal is attached to the session")

	// A second terminal attaches the same way.
	term := h.splitPane(h.host)
	require.NoError(t, term.SendLine(h.ctx, fmt.Sprintf("sh %s ATTACH upterm attach %s", script, name)))
	require.NoError(t, h.waitForText(term, uptermPrompt, 30*time.Second))

	// Liveness before the stop, so what follows means something: two
	// terminals, one running session.
	live := fmt.Sprintf("LIVE_%d", time.Now().UnixNano())
	require.NoError(t, h.host.SendLine(h.ctx, fmt.Sprintf(`echo "LIV""%s"`, strings.TrimPrefix(live, "LIV"))))
	require.NoError(t, h.waitForText(h.host, live, 10*time.Second))
	require.NoError(t, h.waitForText(term, live, 10*time.Second))

	// The stop, from a third terminal. Split off vertically (top/bottom)
	// rather than through h.splitPane's horizontal (side-by-side) split:
	// h.host has already given up half its width to term, and a second
	// side-by-side split would leave it too narrow to print the 66-column
	// sentence below without an in-pane line wrap that breaks the
	// wait's substring match — a tmux layout artifact, not anything the
	// session gets wrong. A vertical split costs h.host height instead of
	// width, which none of its assertions need.
	ctl, err := h.host.SplitWindow(h.ctx, &tmux.SplitWindowOptions{
		SplitDirection: tmux.PaneSplitDirectionVertical,
		ShellCommand:   "bash --norc --noprofile",
	})
	require.NoError(t, err)
	require.NoError(t, ctl.SendLine(h.ctx, "upterm session stop "+name+"; echo STOP_STATUS=$?"))
	require.NoError(t, h.waitForText(ctl, "STOP_STATUS=0", 40*time.Second))

	// Both attached terminals see the stop: the host reports its command
	// exit, and attach reports the status without guessing the cause. Both
	// receive the signalled-command status and their terminal back the way they
	// found it. A failed restore shows up in the wait's error as
	// "…_TTY=CHANGED [before] [after]", which is the diagnostic wanted.
	require.NoError(t, h.waitForText(h.host, "ended: command exited (status 1)", 20*time.Second))
	require.NoError(t, h.waitForText(h.host, "HOST_STATUS=1", 15*time.Second))
	require.NoError(t, h.waitForText(h.host, "HOST_TTY=same", 15*time.Second))
	require.NoError(t, h.waitForText(term, "session "+name+" ended (status 1)", 20*time.Second))
	require.NoError(t, h.waitForText(term, "ATTACH_STATUS=1", 15*time.Second))
	require.NoError(t, h.waitForText(term, "ATTACH_TTY=same", 15*time.Second))

	// And the record agrees. ctl is only a fraction of the window's height
	// after the vertical split above, and the indented JSON runs to more
	// lines than that: the two lines the assertion needs are filtered out
	// of it before they reach the pane, so the visible screen is enough.
	require.NoError(t, ctl.SendLine(h.ctx, "clear; upterm session info "+name+` -o json | grep -E '"(status|reason)"'; echo "INFO""_DONE"`))
	require.NoError(t, h.waitForText(ctl, "INFO_DONE", 20*time.Second))
	out, err := ctl.Capture(h.ctx)
	require.NoError(t, err)
	require.Contains(t, out, `"status": "ended"`)
	require.Contains(t, out, `"reason": "stopped"`)
}

// A detached session whose command exits at once is still a session that
// started, and --detach's contract is that it exits 0 once the command is
// running. The parent has to be told "started", never "the session daemon
// exited before reporting whether it started" — the answer the daemon's
// readiness report used to be able to lose its race to.
//
// The JSON says what the record said when readiness was published: ready,
// since the ending write happens after run.Group has waited for the
// readiness actor. A script that needs to know whether the session is still
// there asks `session info`; this is about what --detach itself reports.
//
// The status is asserted as non-empty rather than as "ready" because the
// value is the record's to choose — a tunnel lost in that instant would
// legitimately make it disconnected — and an empty one is the bug this
// pins: the parent refuses a report without a status.
func TestDetachedHostWithACommandThatExitsAtOnceStillReportsStarted(t *testing.T) {
	h := newTestHarness(t, 200)
	name := fmt.Sprintf("e2e-bgx-%d", time.Now().UnixNano()%1_000_000)
	h.stopOnCleanup(name)

	hostCmd := fmt.Sprintf("clear; upterm host --detach --accept --skip-host-key-check --server %s --private-key %s --name %s -o json -- sh -c 'exit 0'; echo DETACH_STATUS=$?",
		h.serverURL, h.keyFile, name)
	require.NoError(t, h.host.SendLine(h.ctx, hostCmd))
	require.NoError(t, h.waitForText(h.host, "DETACH_STATUS=0", 30*time.Second),
		"a session whose command ran is not a session that failed to start")

	out, err := h.host.Capture(h.ctx)
	require.NoError(t, err)
	require.NotContains(t, out, "exited before reporting whether it started")

	start, end := strings.Index(out, "{"), strings.LastIndex(out, "}")
	require.True(t, start >= 0 && end > start, "no JSON in:\n%s", out)
	var info struct {
		Name      string `json:"name"`
		Status    string `json:"status"`
		SessionID string `json:"sessionId"`
	}
	require.NoError(t, json.Unmarshal([]byte(out[start:end+1]), &info), "not JSON: %s", out[start:end+1])
	require.Equal(t, name, info.Name)
	require.NotEmpty(t, info.SessionID)
	require.NotEmpty(t, info.Status, "the status is the record's, and a report without one is refused")
}

// upterm host exits with its command's status, every time, and prints no
// usage block for it.
func TestHostExitsWithTheCommandsStatus(t *testing.T) {
	h := newTestHarness(t, 200)
	name := fmt.Sprintf("e2e-st-%d", time.Now().UnixNano()%1_000_000)

	for i := 0; i < 3; i++ {
		// Each run is a session of its own; the command exits at once, so
		// each ends by itself, but the name is registered all the same — a
		// run that never got as far as exiting would otherwise be the one
		// leak the suite does not clean up.
		runName := fmt.Sprintf("%s-%d", name, i)
		h.stopOnCleanup(runName)
		// The status marker carries the run number. `clear` erases the
		// previous run's line, but not before the shell has got to it: a
		// status that every run spells the same way is one the wait matches
		// off the screen a tenth of a second before this run has started,
		// and runs two and three would prove nothing.
		hostCmd := fmt.Sprintf("clear; upterm host --accept --skip-host-key-check --server %s --private-key %s --name %s -- sh -c 'exit 7'; echo HOST_STATUS_%d=$?",
			h.serverURL, h.keyFile, runName, i)
		require.NoError(t, h.host.SendLine(h.ctx, hostCmd))
		require.NoError(t, h.waitForText(h.host, fmt.Sprintf("HOST_STATUS_%d=7", i), 30*time.Second), "run %d", i)
		out, err := h.host.Capture(h.ctx)
		require.NoError(t, err)
		require.NotContains(t, out, "Usage:")
	}
}
