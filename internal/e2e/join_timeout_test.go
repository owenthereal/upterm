package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type deadlineSessionInfo struct {
	Name               string `json:"name"`
	LaunchID           string `json:"launchId"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	GuestCount         int    `json:"guestCount"`
	SSHCommand         string `json:"sshCommand"`
	FirstGuestJoinedAt string `json:"firstGuestJoinedAt"`
	JoinTimeout        string `json:"joinTimeout"`
	JoinDeadline       string `json:"joinDeadline"`
}

func newDeadlineHarness(t *testing.T) *testHarness {
	t.Helper()
	h := newTestHarness(t, 200)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	t.Cleanup(cancel)
	h.ctx = ctx
	return h
}

// These are real CLI calls against the harness's session, with output captured
// directly so JSON and exit-status assertions cannot match terminal echo.
func (h *testHarness) runCLI(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(h.ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "upterm", args...)
	cmd.WaitDelay = time.Second
	return cmd.CombinedOutput()
}

func (h *testHarness) deadlineInfo() deadlineSessionInfo {
	h.t.Helper()
	out, err := h.runCLI(5*time.Second, "session", "info", h.name, "-o", "json")
	require.NoError(h.t, err, "%s", out)
	var info deadlineSessionInfo
	require.NoError(h.t, json.Unmarshal(out, &info), "%s", out)
	require.Equal(h.t, h.name, info.Name)
	require.NotEmpty(h.t, info.LaunchID)
	return info
}

func (h *testHarness) startDetachedDeadlineHost(flags []string, command ...string) {
	h.t.Helper()
	args := []string{"host", "--detach", "--accept", "--skip-host-key-check",
		"--server", h.serverURL, "--private-key", h.keyFile, "--name", h.name}
	args = append(args, flags...)
	args = append(args, "--")
	out, err := h.runCLI(30*time.Second, append(args, command...)...)
	require.NoError(h.t, err, "%s", out)
}

// The first guest disarms the deadline permanently, even after that guest
// disconnects. The exact timestamp must also survive this same session ending.
func TestJoinTimeoutGuestLatchSurvivesDisconnectAndSessionEnd(t *testing.T) {
	h := newDeadlineHarness(t)
	const joinTimeout = 5 * time.Second
	startedAt := time.Now()
	h.startDetachedDeadlineHost([]string{"--join-timeout", joinTimeout.String()},
		"bash", "--rcfile", h.rcFile, "--noprofile")
	initial := h.deadlineInfo()
	require.Equal(t, "ready", initial.Status)
	require.Empty(t, initial.FirstGuestJoinedAt)

	guest := h.splitPane(h.host)
	guestExit := filepath.Join(h.tmpDir, "guest-exit")
	h.connectClient(guest, initial.SSHCommand+fmt.Sprintf("; printf '%%s\\n' \"$?\" > %q", guestExit))
	// The daemon adds the client to its repo (what guestCount reads) before it
	// publishes firstGuestJoinedAt to the record (clientLifecycle.joined in
	// host/host.go): repo.Add, then onGuestJoin. A read taken immediately
	// after the guest connects can land between those two steps and see
	// guestCount: 1 with no timestamp yet. Poll until both are published
	// together, then treat that read as live. The window is the deadline
	// itself, longer than one attempt's timeout; the assertion that the guest
	// left before the deadline still bounds the whole sequence.
	var live deadlineSessionInfo
	require.Eventually(t, func() bool {
		out, err := h.runCLI(2*time.Second, "session", "info", h.name, "-o", "json")
		var info deadlineSessionInfo
		if err != nil || json.Unmarshal(out, &info) != nil {
			return false
		}
		live = info
		return info.GuestCount == 1 && info.FirstGuestJoinedAt != ""
	}, joinTimeout, 100*time.Millisecond, "the daemon must publish guestCount and firstGuestJoinedAt from the same join")
	require.Equal(t, "ready", live.Status)
	require.Equal(t, 1, live.GuestCount)
	require.Equal(t, initial.LaunchID, live.LaunchID)
	joinedAt, err := time.Parse(time.RFC3339Nano, live.FirstGuestJoinedAt)
	require.NoError(t, err)
	require.False(t, joinedAt.IsZero(), "a live guest must publish a real first-join timestamp")

	// OpenSSH's escape ends only the guest connection, leaving the shared
	// shell running. The file proves ssh returned; the live count proves the
	// daemon has processed the disconnect, not just the guest's local exit.
	require.NoError(t, guest.SendKeys(h.ctx, "Enter"))
	require.NoError(t, guest.SendKeys(h.ctx, "~."))
	require.NoError(t, waitForFile(guestExit, 5*time.Second))
	status, err := os.ReadFile(guestExit)
	require.NoError(t, err)
	require.Equal(t, "255\n", string(status))
	require.Eventually(t, func() bool {
		out, err := h.runCLI(2*time.Second, "session", "info", h.name, "-o", "json")
		var info deadlineSessionInfo
		return err == nil && json.Unmarshal(out, &info) == nil &&
			info.LaunchID == live.LaunchID && info.Status == "ready" && info.GuestCount == 0
	}, 5*time.Second, 100*time.Millisecond, "the guest must actually disconnect")
	require.Less(t, time.Since(startedAt), joinTimeout,
		"the guest must leave before the original deadline, not keep it alive until it fires")

	// Waiting a whole deadline after disconnect also rejects re-arming when
	// the last guest leaves. A new CLI read cannot reuse a stale pane screen.
	time.Sleep(joinTimeout + 500*time.Millisecond)
	afterDeadline := h.deadlineInfo()
	require.Equal(t, "ready", afterDeadline.Status)
	require.Equal(t, 0, afterDeadline.GuestCount)
	require.Equal(t, live.LaunchID, afterDeadline.LaunchID)
	require.Equal(t, live.FirstGuestJoinedAt, afterDeadline.FirstGuestJoinedAt)

	out, err := h.runCLI(40*time.Second, "session", "stop", h.name)
	require.NoError(t, err, "%s", out)
	ended := h.deadlineInfo()
	require.Equal(t, "ended", ended.Status)
	require.Equal(t, "stopped", ended.Reason)
	require.Equal(t, live.LaunchID, ended.LaunchID)
	require.Equal(t, live.FirstGuestJoinedAt, ended.FirstGuestJoinedAt)
}

func TestDetachedJoinTimeoutWithoutGuestExitsZero(t *testing.T) {
	h := newDeadlineHarness(t)
	h.startDetachedDeadlineHost([]string{"--join-timeout", "2s"},
		"bash", "--rcfile", h.rcFile, "--noprofile")
	out, err := h.runCLI(15*time.Second, "session", "wait", h.name)
	require.NoError(t, err, "join timeout must exit 0: %s", out)
	ended := h.deadlineInfo()
	require.Equal(t, "ended", ended.Status)
	require.Equal(t, "join_timeout", ended.Reason)
	require.Empty(t, ended.FirstGuestJoinedAt)
	require.Equal(t, 0, ended.GuestCount)
}

// The local terminal is attached when the first-guest deadline fires, but it
// is not a guest. Its SSH exit status alone cannot explain why the session
// ended, so the terminal must not describe the timeout as a command exit.
func TestAttachReportsJoinTimeoutWithoutClaimingCommandExit(t *testing.T) {
	h := newDeadlineHarness(t)
	h.startDetachedDeadlineHost([]string{"--join-timeout", "10s"},
		"bash", "--rcfile", h.rcFile, "--noprofile")

	statusFile := filepath.Join(h.tmpDir, "attach-exit")
	script := h.writeFile("attach-timeout.sh", fmt.Sprintf(
		"upterm attach %q\nprintf '%%s\\n' \"$?\" > %q\n", h.name, statusFile), 0700)
	term := h.splitPane(h.host)
	require.NoError(t, term.SendLine(h.ctx, fmt.Sprintf("sh %q", script)))
	require.NoError(t, h.waitForText(term, uptermPrompt, 30*time.Second), "attach did not reach the session's prompt before the deadline")
	require.NoError(t, waitForFile(statusFile, 20*time.Second))
	status, err := os.ReadFile(statusFile)
	require.NoError(t, err)
	require.Equal(t, "0\n", string(status), "the attached terminal must exit successfully")

	out, err := term.Capture(h.ctx)
	require.NoError(t, err)
	require.Contains(t, out, "upterm: no guest joined within the join timeout; session ended")
	require.Contains(t, out, "upterm: session "+h.name+" ended (status 0)")
	require.NotContains(t, out, "command exited")

	ended := h.deadlineInfo()
	require.Equal(t, "ended", ended.Status)
	require.Equal(t, "join_timeout", ended.Reason)
	require.Empty(t, ended.FirstGuestJoinedAt)
}

func TestSessionWaitReturnsCommandExitStatus(t *testing.T) {
	h := newDeadlineHarness(t)
	h.startDetachedDeadlineHost(nil, "sh", "-c", "exit 7")
	out, err := h.runCLI(15*time.Second, "session", "wait", h.name)
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "%s", out)
	require.Equal(t, 7, exitErr.ExitCode(), "%s", out)
	ended := h.deadlineInfo()
	require.Equal(t, "ended", ended.Status)
	require.Equal(t, "exited", ended.Reason)
}

// A foreground host exits through its attached client; detached session wait
// succeeding does not establish that this separate exit-status path is correct.
func TestForegroundJoinTimeoutWithoutGuestExitsZero(t *testing.T) {
	h := newDeadlineHarness(t)
	statusFile := filepath.Join(h.tmpDir, "foreground-exit")
	script := h.writeFile("foreground-timeout.sh", fmt.Sprintf(
		"upterm host --accept --skip-host-key-check --server %q --private-key %q --name %q --join-timeout 2s -- bash --rcfile %q --noprofile\nprintf '%%s\\n' \"$?\" > %q\n",
		h.serverURL, h.keyFile, h.name, h.rcFile, statusFile), 0700)
	require.NoError(t, h.host.SendLine(h.ctx, fmt.Sprintf("sh %q", script)))
	require.NoError(t, h.waitForText(h.host, uptermPrompt, 30*time.Second), "the foreground client must attach")
	require.NoError(t, waitForFile(statusFile, 15*time.Second))
	status, err := os.ReadFile(statusFile)
	require.NoError(t, err)
	require.Equal(t, "0\n", string(status), "the foreground host must exit 0")
	ended := h.deadlineInfo()
	require.Equal(t, "ended", ended.Status)
	require.Equal(t, "join_timeout", ended.Reason)
	require.Empty(t, ended.FirstGuestJoinedAt, "the host's own attachment is not a guest")
}

// Open during the build, counted after it: the window set once the build is
// done ends the session, and a build longer than that window did not.
func TestSessionSetArmsTheJoinTimeoutAfterLaunch(t *testing.T) {
	h := newDeadlineHarness(t)
	h.startDetachedDeadlineHost(nil, "bash", "--rcfile", h.rcFile, "--noprofile")
	require.Equal(t, "ready", h.deadlineInfo().Status)

	time.Sleep(4 * time.Second) // the build: longer than the window set below
	require.Equal(t, "ready", h.deadlineInfo().Status)

	out, err := h.runCLI(10*time.Second, "session", "set", h.name, "--join-timeout", "3s")
	require.NoError(t, err, "%s", out)
	require.Contains(t, string(out), "unless a guest joins")
	counting := h.deadlineInfo()
	require.Equal(t, "3s", counting.JoinTimeout)
	require.NotEmpty(t, counting.JoinDeadline)

	out, err = h.runCLI(30*time.Second, "session", "wait", h.name)
	require.NoError(t, err, "a join timeout exits 0: %s", out)
	ended := h.deadlineInfo()
	require.Equal(t, "join_timeout", ended.Reason)
	require.Equal(t, counting.JoinDeadline, ended.JoinDeadline, "the ended record shows the deadline that fired")
}

// A guest who visited during the build claimed the session: the window set
// afterwards arms nothing.
func TestSessionSetAfterAJoinDuringTheBuildArmsNothing(t *testing.T) {
	h := newDeadlineHarness(t)
	h.startDetachedDeadlineHost(nil, "bash", "--rcfile", h.rcFile, "--noprofile")
	initial := h.deadlineInfo()

	guest := h.splitPane(h.host)
	guestExit := filepath.Join(h.tmpDir, "guest-exit")
	h.connectClient(guest, initial.SSHCommand+fmt.Sprintf("; printf '%%s\\n' \"$?\" > %q", guestExit))
	require.Eventually(t, func() bool { return h.deadlineInfo().FirstGuestJoinedAt != "" },
		10*time.Second, 100*time.Millisecond, "the guest's join is published")
	require.NoError(t, guest.SendKeys(h.ctx, "Enter"))
	require.NoError(t, guest.SendKeys(h.ctx, "~."))
	require.NoError(t, waitForFile(guestExit, 5*time.Second))

	out, err := h.runCLI(10*time.Second, "session", "set", h.name, "--join-timeout", "1s")
	require.NoError(t, err, "%s", out)
	require.Contains(t, string(out), "automatic join timeout disabled")

	time.Sleep(3 * time.Second)
	require.Equal(t, "ready", h.deadlineInfo().Status, "a claimed session is not ended by a later set")
	out, err = h.runCLI(40*time.Second, "session", "stop", h.name)
	require.NoError(t, err, "%s", out)
}

func TestFailedBuildRecipeKeepsTheBuildStatus(t *testing.T) {
	h := newDeadlineHarness(t)
	script := h.writeFile("recipe.sh", fmt.Sprintf(`set -e
upterm host --detach --accept --skip-host-key-check --server %[1]q --private-key %[2]q --name %[3]q -- bash --rcfile %[4]q --noprofile
build_exit_code=0
sh -c 'exit 3' || build_exit_code=$?
if [ "$build_exit_code" -ne 0 ]; then
  if upterm session set %[3]q --join-timeout 2s; then
    upterm session wait %[3]q || true
  fi
fi
upterm session stop %[3]q || true
exit "$build_exit_code"
`, h.serverURL, h.keyFile, h.name, h.rcFile), 0700)

	ctx, cancel := context.WithTimeout(h.ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", script)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "%s", out)
	require.Equal(t, 3, exitErr.ExitCode(), "the script exits with the build's status: %s", out)
	require.Contains(t, string(out), "unless a guest joins", "the window opened after the failure")
	require.Equal(t, "join_timeout", h.deadlineInfo().Reason)
}
