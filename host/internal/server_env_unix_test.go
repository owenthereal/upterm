//go:build !windows

package internal

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/owenthereal/upterm/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Exercise the server as well as its child processes: testing the forced
// command's launcher alone would miss the CommandEnv dropped between Server
// and sessionHandler (#331).
func TestServerCommandEnvironment(t *testing.T) {
	const socket = "/tmp/upterm-current.sock"
	command := []string{"sh", "-c", `stty -echo -opost; printf 'SOCKET=%s\nTERM=%s\nINHERITED=%s\004' "$UPTERM_ADMIN_SOCKET" "$TERM" "$UPTERM_TEST_INHERITED"; IFS= read -r line`}
	for _, tc := range []struct {
		name      string
		inherited string
		unset     bool
	}{
		{name: "unset", unset: true},
		{name: "empty"},
		{name: "stale", inherited: "/tmp/upterm-outer.sock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv is what restores the variable on cleanup; the unset case
			// then removes it so the host has no inherited socket at all.
			t.Setenv("UPTERM_ADMIN_SOCKET", tc.inherited)
			if tc.unset {
				require.NoError(t, os.Unsetenv("UPTERM_ADMIN_SOCKET"))
			}
			t.Setenv("TERM", "host-term")
			t.Setenv("UPTERM_TEST_INHERITED", "inherited-ok")

			h := startHost(t, &Server{
				Command: command, ForceCommand: command,
				CommandEnv: []string{"UPTERM_ADMIN_SOCKET=" + socket},
			})
			// A viewer on the host door: the replay carries the output the
			// command already wrote, so what the host's own client sees is
			// what the host used to print on its stdout.
			_, out, _ := h.connectHost(t, nil)
			got, err := bufio.NewReader(out).ReadString('\x04')
			require.NoError(t, err)
			assert.Equal(t, "SOCKET=/tmp/upterm-current.sock\nTERM=host-term\nINHERITED=inherited-ok\x04", got, "host environment")

			_, guestOutput := h.connectGuest(t)
			got, err = bufio.NewReader(guestOutput).ReadString('\x04')
			require.NoError(t, err)
			assert.Equal(t, "SOCKET=/tmp/upterm-current.sock\nTERM=xterm\nINHERITED=inherited-ok\x04", got, "forced command environment")
		})
	}
}

// A guest's private command runs on a pty or pipes of its own, not in the
// multiplexer pane the host started upterm from, so it isn't told it is:
// tmux, screen, zellij and Herdr would take a guest's own to be nested in the
// host's pane, and refuse or reach for it, or for the Herdr session,
// workspace or tab that pane is in. The hosted command is in that pane and
// keeps them, and every command keeps where a Herdr server listens and where
// its binary is.
func TestGuestCommandsDontInheritTheHostsPane(t *testing.T) {
	pane := []string{"TMUX", "TMUX_PANE", "STY", "ZELLIJ", "ZELLIJ_SESSION_NAME", "ZELLIJ_PANE_ID", "HERDR_ENV", "HERDR_PANE_ID", "HERDR_SESSION", "HERDR_TAB_ID", "HERDR_WORKSPACE_ID"}
	kept := map[string]string{"HERDR_SOCKET_PATH": "/tmp/herdr.sock", "HERDR_BIN_PATH": "/opt/homebrew/bin/herdr"}
	hostEnv := maps.Clone(kept)
	for i, name := range pane {
		hostEnv[name] = "host-pane-" + strconv.Itoa(i)
	}
	for name, value := range hostEnv {
		t.Setenv(name, value)
	}
	t.Setenv("SHELL", "/bin/sh")
	var report strings.Builder
	for _, name := range append(slices.Clone(pane), slices.Sorted(maps.Keys(kept))...) {
		fmt.Fprintf(&report, `printf '%s=%%s\n' "${%s-unset}"; `, name, name)
	}
	report.WriteString(`printf '\004'`)
	script := report.String()
	parse := func(out string) map[string]string {
		got := map[string]string{}
		for _, line := range strings.FieldsFunc(strings.TrimSuffix(out, "\x04"), func(r rune) bool { return r == '\r' || r == '\n' }) {
			name, value, _ := strings.Cut(line, "=")
			got[name] = value
		}
		return got
	}
	guestWant := maps.Clone(kept)
	for _, name := range pane {
		guestWant[name] = "unset"
	}

	t.Run("hosted and login", func(t *testing.T) {
		h := startHost(t, &Server{
			Command:      []string{"sh", "-c", "stty -echo -opost; " + script + "; IFS= read -r line"},
			LoginCommand: []string{"sh", "-c", script + "; IFS= read -r line"},
		})
		_, out, _ := h.connectHost(t, nil)
		got, err := bufio.NewReader(out).ReadString('\x04')
		require.NoError(t, err)
		assert.Equal(t, hostEnv, parse(got), "the hosted command")

		_, guestOutput := h.connectGuest(t)
		got, err = bufio.NewReader(guestOutput).ReadString('\x04')
		require.NoError(t, err)
		assert.Equal(t, guestWant, parse(got), "the login command")
	})
	t.Run("forced", func(t *testing.T) {
		h := startHost(t, &Server{Command: readsALine("HOST", 0), ForceCommand: []string{"sh", "-c", script}})
		out, err := execSession(t, h.guestClient(t), false).Output("ignored")
		require.NoError(t, err)
		assert.Equal(t, guestWant, parse(string(out)))
	})
	t.Run("exec", func(t *testing.T) {
		h := startHost(t, &Server{Command: readsALine("HOST", 0), AcceptExec: true})
		out, err := execSession(t, h.guestClient(t), false).Output(script)
		require.NoError(t, err)
		assert.Equal(t, guestWant, parse(string(out)))
	})
}

// A guest's forced command is that guest's SSH session as far as the programs
// in it can tell. Herdr, for one, copies with OSC 52 to the terminal it is
// shown on when SSH_CONNECTION or SSH_TTY says it is remote, and with the
// host's own clipboard otherwise. So the command is told where the guest is
// and which terminal it has, and nothing the host inherited from its own
// login says otherwise.
func TestForcedCommandIsTheGuestsSSHSession(t *testing.T) {
	command := []string{"sh", "-c", `stty -echo -opost; printf 'CONNECTION=%s\nCLIENT=%s\nTTY=%s\nREAL=%s\004' "${SSH_CONNECTION-unset}" "${SSH_CLIENT-unset}" "${SSH_TTY-unset}" "$(tty)"; IFS= read -r line`}
	for _, tc := range []struct {
		name           string
		hideClientIP   bool
		relayEnd       string
		wantConnection string
		wantClient     string
	}{
		{
			name:           "relay names both ends",
			relayEnd:       "198.51.100.1:22",
			wantConnection: "203.0.113.7 51234 198.51.100.1 22",
			wantClient:     "203.0.113.7 51234 22",
		},
		{
			// Absent rather than false: the inherited values are gone too.
			name:           "client IP hidden",
			hideClientIP:   true,
			relayEnd:       "198.51.100.1:22",
			wantConnection: "unset",
			wantClient:     "unset",
		},
		{
			name:           "relay too old to name its end",
			wantConnection: "unset",
			wantClient:     "unset",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// What a host started from its own ssh login inherits.
			t.Setenv("SSH_CONNECTION", "10.0.0.1 40000 10.0.0.2 22")
			t.Setenv("SSH_CLIENT", "10.0.0.1 40000 22")
			t.Setenv("SSH_TTY", "/dev/host-login-tty")

			h := startHost(t, &Server{
				Command:      []string{"sh", "-c", "sleep 30"},
				ForceCommand: command,
				HideClientIP: tc.hideClientIP,
			})
			// The credential the relay mints, naming both ends of the guest's
			// connection to it.
			cert, err := (&server.UserCertSigner{
				SessionID: t.Name(),
				User:      "guest",
				AuthRequest: &server.AuthRequest{
					RemoteAddr:    "203.0.113.7:51234",
					LocalAddr:     tc.relayEnd,
					AuthorizedKey: ssh.MarshalAuthorizedKey(h.relaySigner.PublicKey()),
				},
			}).SignCert(h.relaySigner)
			require.NoError(t, err)

			_, guestOutput := h.connectGuest(t, withGuestSigners(cert))
			out, err := bufio.NewReader(guestOutput).ReadString('\x04')
			require.NoError(t, err)
			got := map[string]string{}
			for _, line := range strings.Split(strings.TrimSuffix(out, "\x04"), "\n") {
				k, v, _ := strings.Cut(line, "=")
				got[k] = v
			}

			assert.Equal(t, tc.wantConnection, got["CONNECTION"], "SSH_CONNECTION")
			assert.Equal(t, tc.wantClient, got["CLIENT"], "SSH_CLIENT")
			assert.True(t, strings.HasPrefix(got["REAL"], "/dev/"), "the command's own terminal: %q", got["REAL"])
			assert.Equal(t, got["REAL"], got["TTY"], "SSH_TTY names the guest's pty, not the host's login")
		})
	}
}
