package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Sharing a tmux client and attaching each guest to tmux are both supported
// workflows. Exercise real terminals so cursor movement, pane redraws and
// window-change requests are checked alongside ordinary shell output.
func TestTmux(t *testing.T) {
	for _, mode := range []string{"shared", "forced attach"} {
		t.Run(mode, func(t *testing.T) {
			// After the outer window is split, host and guest each have 100 columns.
			h := newTestHarness(t, 201)
			socket := fmt.Sprintf("upterm-tmux-output-%d", time.Now().UnixNano())
			tmuxQuery := func(args ...string) (string, error) {
				out, err := exec.CommandContext(t.Context(), "tmux", append([]string{"-L", socket}, args...)...).CombinedOutput()
				return strings.TrimSpace(string(out)), err
			}
			tmuxCommand := func(args ...string) string {
				t.Helper()
				out, err := tmuxQuery(args...)
				require.NoError(t, err, "tmux %v: %s", args, out)
				return out
			}
			// Use a separate tmux server from the one rendering the test's host
			// and guest terminals. Cleanup touches only this test's server.
			t.Cleanup(func() { _ = exec.Command("tmux", "-L", socket, "kill-server").Run() })
			rc := h.writeFile("tmux-bashrc", "PS1='"+uptermPrompt+" '\nprintf '\033[H\033[2JTMUX_READY\\n'\n", 0600)
			shell := fmt.Sprintf("bash --rcfile %q --noprofile", rc)
			tmuxCommand("-f", "/dev/null", "new-session", "-d", "-s", "shared", "-x", "100", "-y", "23", shell)
			tmuxCommand("set-option", "-g", "status", "off")

			attach := fmt.Sprintf("env -u TMUX tmux -L %s attach-session -t shared", socket)
			flags := "--accept"
			if mode == "forced attach" {
				flags += " --force-command '" + attach + "'"
			}
			sshCmd := h.startHost(flags)
			require.NoError(t, h.host.SendLine(h.ctx, attach))
			require.NoError(t, h.waitForText(h.host, "TMUX_READY", 10*time.Second))
			client := h.splitPane(h.host)
			h.connectClient(client, sshCmd)
			require.NoError(t, h.waitForText(client, "TMUX_READY", 10*time.Second))

			// Require rendered whitespace, which cannot match the echoed command.
			require.NoError(t, client.SendLine(h.ctx, "printf '\\n%8s%s\\n' '' GUEST_INPUT"))
			require.NoError(t, h.waitForText(h.host, "\n        GUEST_INPUT\n", 10*time.Second))
			require.NoError(t, h.host.SendLine(h.ctx, "printf '\\n%8s%s\\n' '' HOST_INPUT"))
			require.NoError(t, h.waitForText(client, "\n        HOST_INPUT\n", 10*time.Second))

			// Split inside tmux, then check input from the guest reaches the new
			// pane and both terminals render the same layout.
			tmuxCommand("split-window", "-h", "-t", "shared:0", shell)
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				out, err := tmuxQuery("capture-pane", "-p", "-t", "shared:0.1")
				require.NoError(c, err)
				require.Contains(c, out, uptermPrompt)
			}, 10*time.Second, 100*time.Millisecond)
			require.NoError(t, client.SendLine(h.ctx, "printf '\\n%8s%s\\n' '' SPLIT_INPUT"))
			require.NoError(t, h.waitForText(h.host, "        SPLIT_INPUT", 10*time.Second))
			require.NoError(t, h.waitForText(client, "        SPLIT_INPUT", 10*time.Second))

			// Resize the outer terminals and require the nested tmux window to
			// adopt the new dimensions delivered through Upterm's PTY handling.
			out, err := exec.CommandContext(t.Context(), "tmux", "resize-window", "-t", h.session.Name+":0", "-x", "161", "-y", "20").CombinedOutput()
			require.NoError(t, err, "%s", out)
			out, err = exec.CommandContext(t.Context(), "tmux", "display-message", "-p", "-t", h.host.Id, "#{pane_width}x#{pane_height}").Output()
			require.NoError(t, err)
			wantSize := strings.TrimSpace(string(out))
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				out, err := tmuxQuery("display-message", "-p", "-t", "shared:0", "#{window_width}x#{window_height}")
				require.NoError(c, err)
				require.Equal(c, wantSize, out)
			}, 10*time.Second, 100*time.Millisecond, "tmux did not receive the terminal resize to %s", wantSize)

			for _, tty := range strings.Fields(tmuxCommand("list-clients", "-F", "#{client_name}")) {
				tmuxCommand("refresh-client", "-t", tty)
			}
			require.NoError(t, h.waitForText(client, "        SPLIT_INPUT", 10*time.Second))
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				hostScreen, hostErr := h.host.Capture(h.ctx)
				guestScreen, guestErr := client.Capture(h.ctx)
				require.NoError(c, hostErr)
				require.NoError(c, guestErr)
				require.Equal(c, hostScreen, guestScreen)
			}, 10*time.Second, 100*time.Millisecond, "host and guest tmux displays differ after redraw and resize")
		})
	}
}
