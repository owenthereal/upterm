//go:build !windows

package internal

import (
	"bufio"
	"io"
	"strings"
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
			if mode == "shared replay" {
				// The ring's own bytes, as the raw replay hands them to a
				// viewer and to every join that falls back. A terminal's join
				// is otherwise handed a reconstruction of the screen, which
				// is other bytes by design.
				installReplayer(t, nil)
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

	// A terminal's join is handed a reconstruction of the screen, which is
	// other bytes, so what it must keep is what the bytes drew: the guest's
	// screen is the one the output draws, its rows where the bare LFs left
	// them. And the reconstruction's own line feeds are CRLFs, since the
	// joiner's terminal, unlike the pty without opost, would take a bare LF
	// to keep the column. The command repaints once the guest is attached,
	// which marks where the guest's replay ends.
	t.Run("shared replay, reconstructed", func(t *testing.T) {
		const repainted = "REPAINTED"
		h := startHost(t, &Server{Command: []string{"sh", "-c", `stty -echo -opost; printf READY; IFS= read -r line; printf '\033[H\033[2JHELLO   \nHELLO\r\n\033[12;9Hpane\nnext\r\r\n\004'; trap 'printf ` + repainted + `' WINCH; while :; do sleep 0.05; done`}})
		in, out, _ := h.connectHost(t, &hostPty{term: "xterm", cols: 80, rows: 24})
		readUntil(t, out, "READY")
		_, err := io.WriteString(in, "\n")
		require.NoError(t, err)
		readUntil(t, out, "\x04")

		_, guestOutput := h.connectGuest(t, withWindow(desktop))
		got := readUntil(t, guestOutput, repainted)
		got = got[:strings.Index(got, repainted)]
		for i := range len(got) {
			if got[i] == '\n' && (i == 0 || got[i-1] != '\r') {
				t.Fatalf("the reconstruction has a bare LF at %d: %q", i, got)
			}
		}
		// Everything the pty wrote, READY included, which the clear puts
		// into the scrollback.
		require.Empty(t, sameScreen(newTerminal(t, desktop, "READY"+output), newTerminal(t, desktop, got)))
	})
}
