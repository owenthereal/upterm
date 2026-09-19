//go:build !windows

package internal

import (
	"bufio"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// Screen uses LF to move down without changing the cursor column. Rewriting
// it to CRLF loses indentation on redraw (#288) and misplaces pane output
// (#278). Exercise the real host SSH server: a fake Session.Write would hide
// the SSH library's additional newline processing.
func TestServerPreservesPTYOutput(t *testing.T) {
	const output = "\x1b[H\x1b[2JHELLO   \nHELLO\r\n\x1b[12;9Hpane\nnext\r\r\n\x04"
	command := []string{"sh", "-c", `stty -echo -opost; printf READY; IFS= read -r line; printf '\033[H\033[2JHELLO   \nHELLO\r\n\033[12;9Hpane\nnext\r\r\n\004'; IFS= read -r line`}

	for _, mode := range []string{"shared replay", "shared live", "forced command"} {
		t.Run(mode, func(t *testing.T) {
			srv := &Server{Command: command}
			if mode == "forced command" {
				srv.ForceCommand = command
			}
			h := startHost(t, srv)

			ready := make([]byte, len("READY"))
			// The local terminal is a client of the host door now, so the
			// host's own view of the session is one of these.
			in, out, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
			_, err := io.ReadFull(out, ready)
			require.NoError(t, err)
			require.Equal(t, "READY", string(ready))
			if mode == "shared replay" {
				_, err = io.WriteString(in, "\n")
				require.NoError(t, err)
				got, err := bufio.NewReader(out).ReadString('\x04')
				require.NoError(t, err)
				require.Equal(t, output, got)
			}

			guestInput, guestOutput := h.connectGuest(t)
			_, err = io.ReadFull(guestOutput, ready)
			require.NoError(t, err)
			require.Equal(t, "READY", string(ready))
			if mode != "shared replay" {
				_, err = io.WriteString(guestInput, "\n")
				require.NoError(t, err)
			}
			got, err := bufio.NewReader(guestOutput).ReadString('\x04')
			require.NoError(t, err)
			require.Equal(t, output, got, "SSH must preserve the bytes produced by the PTY")
		})
	}
}
