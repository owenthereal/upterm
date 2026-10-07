package ftests

import (
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testForcedCommandSeesTheGuestsConnection pins, through a real relay, what a
// guest's forced command is told about the guest: SSH_CONNECTION and
// SSH_CLIENT name the two ends of the guest's connection to the relay it
// joined by -- the entry node, on a hop -- and SSH_TTY names the command's
// own pty. Under --hide-client-ip the addresses are left out and the
// terminal is not.
func testForcedCommandSeesTheGuestsConnection(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	if runtime.GOOS == "windows" {
		t.Skip("the forced command is a POSIX shell script, and a ConPTY has no tty name")
	}

	for _, hide := range []bool{false, true} {
		t.Run(fmt.Sprintf("hideClientIP=%t", hide), func(t *testing.T) {
			session := shareHost(t, &Host{
				Command:                  getTestShell(),
				ForceCommand:             []string{"sh", "-c", `printf 'CONNECTION=%s\nCLIENT=%s\nTTY=%s\nREAL=%s\n' "${SSH_CONNECTION-unset}" "${SSH_CLIENT-unset}" "${SSH_TTY-unset}" "$(tty)"; sleep 30`},
				PrivateKeys:              []string{HostPrivateKey},
				AdminSocketFile:          setupAdminSocket(t),
				PermittedClientPublicKey: ClientPublicKeyContent,
				HideClientIP:             hide,
			}, hostShareURL, hostNodeAddr)

			c := &Client{PrivateKeys: []string{ClientPrivateKey}}
			require.NoError(t, c.Join(session, clientJoinURL))
			t.Cleanup(c.Close)

			_, out := c.InputOutput()
			s := scanner(out)
			got := map[string]string{}
			for len(got) < 4 {
				k, v, ok := strings.Cut(scan(s), "=")
				require.True(t, ok, "the forced command's output: %q", k)
				got[k] = v
			}

			assert.True(t, strings.HasPrefix(got["REAL"], "/dev/"), "the command's own terminal: %q", got["REAL"])
			assert.Equal(t, got["REAL"], got["TTY"], "SSH_TTY")

			if hide {
				assert.Equal(t, "unset", got["CONNECTION"], "SSH_CONNECTION")
				assert.Equal(t, "unset", got["CLIENT"], "SSH_CLIENT")
				return
			}

			u, err := url.Parse(clientJoinURL)
			require.NoError(t, err)
			if u.Scheme != "ssh" {
				// A WebSocket guest reaches the SSH proxy through a
				// connection the relay makes itself, so that connection's
				// ends are the ones the relay knows -- as `session info`
				// shows. Only their presence is pinned.
				assert.NotEqual(t, "unset", got["CONNECTION"], "SSH_CONNECTION")
				assert.NotEqual(t, "unset", got["CLIENT"], "SSH_CLIENT")
				return
			}
			guest := c.sshClient.LocalAddr().(*net.TCPAddr)
			relayHost, relayPort, err := net.SplitHostPort(u.Host)
			require.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("%s %d %s %s", guest.IP, guest.Port, relayHost, relayPort), got["CONNECTION"], "SSH_CONNECTION")
			assert.Equal(t, fmt.Sprintf("%s %d %s", guest.IP, guest.Port, relayPort), got["CLIENT"], "SSH_CLIENT")
		})
	}
}
