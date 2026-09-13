package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/tmux"
	"github.com/stretchr/testify/require"
)

const (
	// Test key material (same as ftests)
	HostPrivateKeyContent = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDgPqzHMFhTyVRNoOhMET5GJjSX2kv/oJMmffWkf+ubswAAAIiu5GOBruRj
gQAAAAtzc2gtZWQyNTUxOQAAACDgPqzHMFhTyVRNoOhMET5GJjSX2kv/oJMmffWkf+ubsw
AAAEDBHlsR95C/pGVHtQGpgrUi+Qwgkfnp9QlRKdEhhx4rxOA+rMcwWFPJVE2g6EwRPkYm
NJfaS/+gkyZ99aR/65uzAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
`

	// Client key (different from host key) for authorized keys tests
	ClientPublicKeyContent = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHzlndir8KtqplpniMvYV3t7xqQz8jgIhP12WURQcQiY
`

	ClientPrivateKeyContent = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB85Z3Yq/CraqZaZ4jL2Fd7e8akM/I4CIT9dllEUHEImAAAAIiFAKMkhQCj
JAAAAAtzc2gtZWQyNTUxOQAAACB85Z3Yq/CraqZaZ4jL2Fd7e8akM/I4CIT9dllEUHEImA
AAAEDcVndogRSlA4iO3Dkr0qIB2PJnH6llmTvAudZtQ84dgnzlndir8KtqplpniMvYV3t7
xqQz8jgIhP12WURQcQiYAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
`
)

// uptermPrompt is the unique prompt used to detect when the shell is ready.
const uptermPrompt = "UPTERM_READY>"

// ansiEscapeRe matches ANSI escape codes for stripping terminal colors.
var ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// testHarness provides common setup and utilities for E2E tests.

type testHarness struct {
	t             *testing.T
	ctx           context.Context
	session       *tmux.Session
	host          *tmux.Pane
	serverURL     string
	keyFile       string
	clientKeyFile string
	rcFile        string
	tmpDir        string
}

// newTestHarness creates a new test harness with tmux session and host pane.
func newTestHarness(t *testing.T, width int) *testHarness {
	t.Helper()
	skipIfNoTmux(t)

	serverURL := os.Getenv("UPTERM_E2E_SERVER")
	if serverURL == "" {
		t.Fatal("UPTERM_E2E_SERVER environment variable is required")
	}

	ctx := context.Background()
	tm, err := tmux.Default()
	require.NoError(t, err)

	sessionName := fmt.Sprintf("upterm-e2e-%s-%d", t.Name(), time.Now().UnixNano())
	session, err := tm.NewSession(ctx, &tmux.SessionOptions{
		Name:         sessionName,
		Width:        width,
		Height:       24,
		ShellCommand: "bash --norc --noprofile",
	})
	require.NoError(t, err)

	windows, err := session.ListWindows(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, windows)

	panes, err := windows[0].ListPanes(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, panes)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "id_ed25519")
	require.NoError(t, os.WriteFile(keyFile, []byte(HostPrivateKeyContent), 0600))

	// Create a client key for SSH connections
	clientKeyFile := filepath.Join(tmpDir, "client_key")
	require.NoError(t, os.WriteFile(clientKeyFile, []byte(ClientPrivateKeyContent), 0600))

	// Create a bashrc file that sets a unique, deterministic prompt
	rcFile := filepath.Join(tmpDir, "bashrc")
	require.NoError(t, os.WriteFile(rcFile, fmt.Appendf(nil, "PS1='%s '\n", uptermPrompt), 0644))

	h := &testHarness{
		t:             t,
		ctx:           ctx,
		session:       session,
		host:          panes[0],
		serverURL:     serverURL,
		keyFile:       keyFile,
		clientKeyFile: clientKeyFile,
		rcFile:        rcFile,
		tmpDir:        tmpDir,
	}

	t.Cleanup(func() {
		_ = session.Kill(ctx)
	})

	return h
}

// startHost starts upterm host with the given extra flags and returns the SSH command.
func (h *testHarness) startHost(extraFlags string) string {
	h.t.Helper()

	hostCmd := fmt.Sprintf("upterm host --server %s --private-key %s --skip-host-key-check %s -- bash --rcfile %s --noprofile",
		h.serverURL, h.keyFile, extraFlags, h.rcFile)
	require.NoError(h.t, h.host.SendLine(h.ctx, hostCmd))
	require.NoError(h.t, h.waitForText(h.host, "SSH:", 30*time.Second), "host failed to establish session")

	output, err := h.host.Capture(h.ctx)
	require.NoError(h.t, err)

	sshCmd := extractSSHCommand(output)
	require.NotEmpty(h.t, sshCmd, "failed to extract SSH command from output:\n%s", output)
	h.t.Logf("Extracted SSH command: %s", sshCmd)

	return sshCmd
}

// splitPane creates a new client pane by splitting the given pane.
func (h *testHarness) splitPane(from *tmux.Pane) *tmux.Pane {
	h.t.Helper()
	pane, err := from.SplitWindow(h.ctx, &tmux.SplitWindowOptions{
		SplitDirection: tmux.PaneSplitDirectionHorizontal,
		ShellCommand:   "bash --norc --noprofile",
	})
	require.NoError(h.t, err)
	return pane
}

// connectClient connects a client pane using the SSH command with the default client key.
func (h *testHarness) connectClient(client *tmux.Pane, sshCmd string) {
	h.t.Helper()
	sshCmdWithOpts := strings.Replace(sshCmd, "ssh ",
		fmt.Sprintf("ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ", h.clientKeyFile), 1)
	require.NoError(h.t, client.SendLine(h.ctx, sshCmdWithOpts))
	// Wait for client to connect and see the deterministic prompt
	err := h.waitForText(client, uptermPrompt, 30*time.Second)
	if err != nil {
		// Debug: capture client pane content on failure
		content, _ := client.Capture(h.ctx)
		h.t.Logf("Client pane content:\n%s", content)
	}
	require.NoError(h.t, err, "client failed to connect")
}

// connectClientWithKey connects using a specific identity file.
func (h *testHarness) connectClientWithKey(client *tmux.Pane, sshCmd, keyFile string) {
	h.t.Helper()
	sshCmdWithOpts := strings.Replace(sshCmd, "ssh ",
		fmt.Sprintf("ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ", keyFile), 1)
	require.NoError(h.t, client.SendLine(h.ctx, sshCmdWithOpts))
	// Wait for client to connect and see the deterministic prompt
	err := h.waitForText(client, uptermPrompt, 30*time.Second)
	if err != nil {
		content, _ := client.Capture(h.ctx)
		h.t.Logf("Client pane content:\n%s", content)
	}
	require.NoError(h.t, err, "client failed to connect")
}

// waitForText polls pane content until expected string appears or timeout.
func (h *testHarness) waitForText(pane *tmux.Pane, expected string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		content, err := pane.Capture(h.ctx)
		if err != nil {
			return err
		}
		if strings.Contains(content, expected) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	content, _ := pane.Capture(h.ctx)
	return fmt.Errorf("timeout waiting for %q after %v\nPane content:\n%s", expected, timeout, content)
}

// writeFile writes content to a file in the test's temp directory.
func (h *testHarness) writeFile(name, content string, perm os.FileMode) string {
	h.t.Helper()
	path := filepath.Join(h.tmpDir, name)
	require.NoError(h.t, os.WriteFile(path, []byte(content), perm))
	return path
}

func skipIfNoTmux(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skip("tmux not installed, skipping E2E test")
	}
}

func extractSSHCommand(output string) string {
	clean := ansiEscapeRe.ReplaceAllString(output, "")

	// Remove newlines/extra spaces caused by terminal wrapping
	clean = regexp.MustCompile(`\s+`).ReplaceAllString(clean, " ")

	// A shell argument can concatenate quoted text and escaped apostrophes.
	// Preserve the whole ProxyCommand, including its nested URL quoting.
	re := regexp.MustCompile(`SSH:\s*(ssh\s+(?:-o\s+ProxyCommand=(?:'[^']*'|\\.|[^\s'\\])+\s+)?\S+(?:\s+-p\s+\d+)?)`)
	matches := re.FindStringSubmatch(clean)
	if len(matches) < 2 {
		return ""
	}
	return strings.TrimSpace(matches[1])
}

func TestExtractSSHCommand(t *testing.T) {
	for _, command := range []string{
		"ssh sid@example.com -p 2222",
		"ssh -o ProxyCommand='upterm proxy wss://sid@example.com' sid@example.com:443",
		`ssh -o ProxyCommand='upterm proxy '\''wss://sid@example.com/ws'\''' sid@example.com:443`,
		`ssh -o ProxyCommand='upterm proxy '\''wss://sid@example.com/team'\''\'\'''\''s/ws?q=a&b=c'\''' sid@example.com:443`,
	} {
		t.Run(command, func(t *testing.T) {
			output := "Session: sid\nSSH: " + command + "\nClients: none\n"
			require.Equal(t, command, extractSSHCommand(output))
		})
	}
}

// extractScpUserHost extracts user and host separately from SSH command.
// This is needed because upterm usernames contain ':' which scp misinterprets
// as the host:path separator. By extracting them separately, we can use
// scp -o User=username host:/path instead of user@host:/path.
// e.g., "ssh sessionid:base64@localhost -p 2222" -> ("sessionid:base64", "localhost")
func extractScpUserHost(sshCmd string) (string, string) {
	parts := strings.Fields(sshCmd)
	if len(parts) < 2 {
		return "", ""
	}
	// parts[1] should be user@host
	userHost := parts[1]
	atIndex := strings.LastIndex(userHost, "@")
	if atIndex == -1 {
		return "", userHost
	}
	return userHost[:atIndex], userHost[atIndex+1:]
}

// extractScpPortFlag extracts the -P flag for scp from an SSH command's -p flag.
// e.g., "ssh user@host -p 2222" -> "-P 2222"
// Note: scp uses -P (uppercase) for port, ssh uses -p (lowercase)
func extractScpPortFlag(sshCmd string) string {
	parts := strings.Fields(sshCmd)
	for i, part := range parts {
		if part == "-p" && i+1 < len(parts) {
			return "-P " + parts[i+1]
		}
	}
	return ""
}

// TestSync validates bidirectional real-time PTY sync between host and client.
func TestSync(t *testing.T) {
	h := newTestHarness(t, 200)

	sshCmd := h.startHost("--accept")

	client := h.splitPane(h.host)
	h.connectClient(client, sshCmd)

	// Test Client -> Host sync
	clientText := "hello from client"
	require.NoError(t, client.SendKeys(h.ctx, clientText))
	require.NoError(t, h.waitForText(h.host, clientText, 10*time.Second), "host did not receive keystrokes from client")

	// Clear line and test Host -> Client sync
	require.NoError(t, h.host.SendKeys(h.ctx, "C-u"))
	time.Sleep(500 * time.Millisecond)

	hostText := "hello from host"
	require.NoError(t, h.host.SendKeys(h.ctx, hostText))
	require.NoError(t, h.waitForText(client, hostText, 10*time.Second), "client did not receive keystrokes from host")
}

// TestMultipleClients validates that multiple clients can connect and see each other's keystrokes.
func TestMultipleClients(t *testing.T) {
	h := newTestHarness(t, 200)

	sshCmd := h.startHost("--accept")

	client1 := h.splitPane(h.host)
	client2 := h.splitPane(client1)

	h.connectClient(client1, sshCmd)
	h.connectClient(client2, sshCmd)

	// Client1 types, Client2 and Host should see it
	client1Text := "from_client1"
	require.NoError(t, client1.SendKeys(h.ctx, client1Text))
	require.NoError(t, h.waitForText(h.host, client1Text, 10*time.Second), "host did not see client1 keystrokes")
	require.NoError(t, h.waitForText(client2, client1Text, 10*time.Second), "client2 did not see client1 keystrokes")

	// Clear and test Client2 types
	require.NoError(t, h.host.SendKeys(h.ctx, "C-u"))
	time.Sleep(500 * time.Millisecond)

	client2Text := "from_client2"
	require.NoError(t, client2.SendKeys(h.ctx, client2Text))
	require.NoError(t, h.waitForText(h.host, client2Text, 10*time.Second), "host did not see client2 keystrokes")
	require.NoError(t, h.waitForText(client1, client2Text, 10*time.Second), "client1 did not see client2 keystrokes")
}

// TestForceCommand validates that --force-command restricts client to the specified command.
func TestForceCommand(t *testing.T) {
	h := newTestHarness(t, 200)

	sshCmd := h.startHost("--accept -f 'echo FORCED_OUTPUT'")

	client := h.splitPane(h.host)
	// Don't use connectClient here - force command runs and closes connection immediately
	// (no interactive shell, so no prompt to wait for)
	sshCmdWithOpts := strings.Replace(sshCmd, "ssh ",
		fmt.Sprintf("ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ", h.clientKeyFile), 1)
	require.NoError(t, client.SendLine(h.ctx, sshCmdWithOpts))

	require.NoError(t, h.waitForText(client, "FORCED_OUTPUT", 30*time.Second), "client did not see forced command output")
}

// TestAuthorizedKeys validates that only clients with authorized keys can connect.
func TestAuthorizedKeys(t *testing.T) {
	h := newTestHarness(t, 200)

	// Setup client keys
	clientKeyFile := h.writeFile("client_key", ClientPrivateKeyContent, 0600)
	authorizedKeysFile := h.writeFile("authorized_keys", ClientPublicKeyContent, 0644)

	// Use both --accept (to auto-approve) and --authorized-keys (to restrict by key)
	sshCmd := h.startHost(fmt.Sprintf("--accept --authorized-keys %s", authorizedKeysFile))

	// Test 1: Authorized client should connect successfully
	client := h.splitPane(h.host)
	h.connectClientWithKey(client, sshCmd, clientKeyFile)

	testText := "auth_success"
	require.NoError(t, client.SendKeys(h.ctx, testText))
	require.NoError(t, h.waitForText(h.host, testText, 10*time.Second), "authorized client could not connect")

	// Test 2: Unauthorized client (using host key, not in authorized_keys) should be rejected
	unauthorizedClient := h.splitPane(client)
	sshCmdWithOpts := strings.Replace(sshCmd, "ssh ",
		fmt.Sprintf("ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ", h.keyFile), 1)
	require.NoError(t, unauthorizedClient.SendLine(h.ctx, sshCmdWithOpts))

	// Should see permission denied or connection closed
	// Use "denied" to avoid terminal line-wrapping splitting "Permission denied"
	require.NoError(t, h.waitForText(unauthorizedClient, "denied", 30*time.Second),
		"unauthorized client should be rejected")
}

// TestBackgroundedHost validates that `upterm host … &` survives being put in
// the background: the job keeps running rather than stopping on SIGTTIN, the
// pane it was launched from stays usable, and the session is reachable.
func TestBackgroundedHost(t *testing.T) {
	h := newTestHarness(t, 200)

	// startHost only knows how to launch in the foreground, and the trailing
	// `&` is the entire point here, so send the line directly.
	hostCmd := fmt.Sprintf("upterm host --accept --skip-host-key-check --server %s --private-key %s -- bash --rcfile %s --noprofile &",
		h.serverURL, h.keyFile, h.rcFile)
	require.NoError(t, h.host.SendLine(h.ctx, hostCmd))
	require.NoError(t, h.waitForText(h.host, "SSH:", 30*time.Second),
		"backgrounded host failed to establish a session")

	output, err := h.host.Capture(h.ctx)
	require.NoError(t, err)
	sshCmd := extractSSHCommand(output)
	require.NotEmpty(t, sshCmd, "failed to extract SSH command from output:\n%s", output)

	// 1. The prompt came back and the job is running. A host stopped by SIGTTIN
	// would be reported as `Stopped (tty input)` instead.
	require.NoError(t, h.host.SendLine(h.ctx, "jobs"))
	require.NoError(t, h.waitForText(h.host, "Running", 10*time.Second),
		"backgrounded host is not running")
	jobsOutput, err := h.host.Capture(h.ctx)
	require.NoError(t, err)
	require.NotContains(t, ansiEscapeRe.ReplaceAllString(jobsOutput, ""), "Stopped",
		"backgrounded host was stopped by the terminal")

	// 2. The pane still belongs to its own shell: a line typed into it reaches
	// bash and bash's output comes back. A background host that had registered
	// an input actor would be reading the same terminal and would eat some or
	// all of these keystrokes.
	//
	// The marker is split across a shell concatenation so that the typed line
	// does not itself contain it. Matching on text we just sent would match the
	// terminal's echo of our own keystrokes and prove nothing about the shell
	// having run anything; only bash's output spells the marker whole.
	cooked := fmt.Sprintf("COOKED_%d", time.Now().UnixNano())
	require.NoError(t, h.host.SendLine(h.ctx, fmt.Sprintf(`echo "COO""%s"`, strings.TrimPrefix(cooked, "COO"))))
	require.NoError(t, h.waitForText(h.host, cooked, 10*time.Second),
		"the pane's shell did not run a typed line; the backgrounded host is stealing its input")

	// 3. The session is reachable: a guest sees the command's prompt.
	client := h.splitPane(h.host)
	h.connectClient(client, sshCmd)

	// 4. After `fg`, input from the pane still does not reach the command.
	//
	// This pins the stage-1 limit rather than papering over it: terminal
	// ownership is decided once, in command.Run, so a session started in the
	// background registers no input actor and `fg` cannot create one
	// afterwards. Getting a local terminal onto a backgrounded session is what
	// `upterm attach` is for, which is stage 2.
	require.NoError(t, h.host.SendLine(h.ctx, "fg"))
	time.Sleep(time.Second)
	require.NoError(t, h.host.SendLine(h.ctx, "echo FG_MARKER"))
	time.Sleep(3 * time.Second)
	clientOutput, err := client.Capture(h.ctx)
	require.NoError(t, err)
	require.NotContains(t, clientOutput, "FG_MARKER",
		"fg must not restore input forwarding to a backgrounded session")

	// ...and the session is still alive, so the absence above is the input path
	// staying closed rather than the host having died at `fg`. Assertion 3
	// proved liveness before `fg`; this proves it after. Same split-marker
	// trick: in the guest pane local echo is off, but only the remote shell
	// having run the line spells the marker whole.
	alive := fmt.Sprintf("ALIVE_%d", time.Now().UnixNano())
	require.NoError(t, client.SendLine(h.ctx, fmt.Sprintf(`echo "ALI""%s"`, strings.TrimPrefix(alive, "ALI"))))
	require.NoError(t, h.waitForText(client, alive, 10*time.Second),
		"the session did not survive fg, so the FG_MARKER assertion above proved nothing")
}

// TestSessionInfo validates that the TUI displays correct session information.
func TestSessionInfo(t *testing.T) {
	h := newTestHarness(t, 200)

	h.startHost("--accept")

	output, err := h.host.Capture(h.ctx)
	require.NoError(t, err)

	// Strip ANSI codes for easier verification
	clean := ansiEscapeRe.ReplaceAllString(output, "")

	require.Contains(t, clean, "Session:", "TUI should show Session ID")
	require.Contains(t, clean, "Command:", "TUI should show Command")
	require.Contains(t, clean, "bash", "TUI should show the command being run")
	require.Contains(t, clean, "Host:", "TUI should show Host")
	require.Contains(t, clean, "SSH:", "TUI should show SSH")
	require.Contains(t, clean, "SFTP:", "TUI should show SFTP")
	require.Contains(t, clean, "SCP:", "TUI should show SCP")
}
