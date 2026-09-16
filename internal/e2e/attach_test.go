package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A host started in the background gets a terminal from upterm attach, loses
// it on ~., and gets it back — with the screen replayed — on the next attach.
func TestAttachDetachReattach(t *testing.T) {
	h := newTestHarness(t, 200)
	name := fmt.Sprintf("e2e-%d", time.Now().UnixNano()%1_000_000)

	hostCmd := fmt.Sprintf("upterm host --accept --skip-host-key-check --server %s --private-key %s --name %s -- bash --rcfile %s --noprofile &",
		h.serverURL, h.keyFile, name, h.rcFile)
	require.NoError(t, h.host.SendLine(h.ctx, hostCmd))
	require.NoError(t, h.waitForText(h.host, "SSH:", 30*time.Second))

	term := h.splitPane(h.host)
	require.NoError(t, term.SendLine(h.ctx, "upterm attach "+name+"; echo DETACH_STATUS=$?"))
	require.NoError(t, h.waitForText(term, uptermPrompt, 30*time.Second), "attach did not reach the session's prompt")

	// Input from the attached terminal reaches the command, and the
	// backgrounded host — a pty viewer now — shows the result too.
	first := fmt.Sprintf("FIRST_%d", time.Now().UnixNano())
	require.NoError(t, term.SendLine(h.ctx, fmt.Sprintf(`echo "FIR""%s"`, strings.TrimPrefix(first, "FIR"))))
	require.NoError(t, h.waitForText(term, first, 10*time.Second))
	require.NoError(t, h.waitForText(h.host, first, 10*time.Second), "the backgrounded host's terminal did not show what the attached one typed")

	// ~. at the start of a line detaches; the shell in the pane comes back.
	require.NoError(t, term.SendKeys(h.ctx, "Enter"))
	require.NoError(t, term.SendKeys(h.ctx, "~."))
	require.NoError(t, h.waitForText(term, "detached from session "+name, 10*time.Second))
	require.NoError(t, h.waitForText(term, "DETACH_STATUS=0", 10*time.Second), "a detach must exit 0")

	// The session survived the detach: the attach terminal can come back and
	// finds the earlier output in the replay. The screen is cleared first —
	// and the clear is confirmed — so that the marker found after the second
	// attach can only have been painted by the replay.
	require.NoError(t, term.SendLine(h.ctx, "clear"))
	require.Eventually(t, func() bool {
		content, err := term.Capture(h.ctx)
		return err == nil && !strings.Contains(content, first)
	}, 2*time.Second, 50*time.Millisecond, "the screen was not cleared, so the replay assertion below would prove nothing")
	require.NoError(t, term.SendLine(h.ctx, "upterm attach "+name+"; echo STATUS=$?"))
	require.NoError(t, h.waitForText(term, first, 30*time.Second), "the replay did not carry the earlier output")
	second := fmt.Sprintf("SECOND_%d", time.Now().UnixNano())
	require.NoError(t, term.SendLine(h.ctx, fmt.Sprintf(`echo "SEC""%s"`, strings.TrimPrefix(second, "SEC"))))
	require.NoError(t, h.waitForText(term, second, 10*time.Second))

	// The command's exit ends the session and the attach exits with it. The
	// status is printed by the pane's own shell, from the line that started
	// the attach: nothing is typed into the handover, where an input read
	// abandoned by the exiting attach could still swallow it.
	require.NoError(t, term.SendLine(h.ctx, "exit 3"))
	require.NoError(t, h.waitForText(term, "command exited (status 3)", 10*time.Second))
	require.NoError(t, h.waitForText(term, "STATUS=3", 10*time.Second))
}

// A host whose stdout is a file still puts the command's output there: the
// pipe viewer is what a redirected stdout was before the split.
func TestRedirectedHostOutputReachesTheFile(t *testing.T) {
	h := newTestHarness(t, 200)
	out := filepath.Join(h.tmpDir, "out.txt")
	marker := fmt.Sprintf("PIPE_%d", time.Now().UnixNano())
	hostCmd := fmt.Sprintf("upterm host --accept --skip-host-key-check --server %s --private-key %s -- sh -c 'echo \"PIP\"\"%s\"' > %s 2>&1; echo HOST_EXIT=$?",
		h.serverURL, h.keyFile, strings.TrimPrefix(marker, "PIP"), out)
	require.NoError(t, h.host.SendLine(h.ctx, hostCmd))
	require.NoError(t, h.waitForText(h.host, "HOST_EXIT=0", 30*time.Second))

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Contains(t, string(data), marker, "the command's output must reach a redirected stdout")
}
