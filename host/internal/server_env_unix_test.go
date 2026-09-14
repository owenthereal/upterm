//go:build !windows

package internal

import (
	"bufio"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			got, err := bufio.NewReader(h.stdout).ReadString('\x04')
			require.NoError(t, err)
			assert.Equal(t, "SOCKET=/tmp/upterm-current.sock\nTERM=host-term\nINHERITED=inherited-ok\x04", got, "host environment")

			_, guestOutput := h.connectGuest(t)
			got, err = bufio.NewReader(guestOutput).ReadString('\x04')
			require.NoError(t, err)
			assert.Equal(t, "SOCKET=/tmp/upterm-current.sock\nTERM=xterm\nINHERITED=inherited-ok\x04", got, "forced command environment")
		})
	}
}
