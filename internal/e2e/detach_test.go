package e2e

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

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
