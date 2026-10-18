//go:build !windows

package command

import (
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	ptylib "github.com/creack/pty"
	"github.com/owenthereal/upterm/host/api"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/stretchr/testify/require"
)

// runCLIOnTerminal is runCLI with stdout a terminal cols wide, which is what
// decides whether the listing fits its cells to a width.
func runCLIOnTerminal(t *testing.T, cols uint16, args ...string) (stdout string, code int) {
	t.Helper()

	master, slave, err := ptylib.Open()
	require.NoError(t, err)
	t.Cleanup(func() { _ = master.Close() })
	require.NoError(t, ptylib.Setsize(slave, &ptylib.Winsize{Cols: cols, Rows: 24}))

	// Drained as it is written, and ended by a marker the test writes after
	// the command returns: a pty hands on what is still unread when its slave
	// closes on some systems and drops it on others.
	const done = "\x00done\x00"
	out := make(chan string, 1)
	go func() {
		var got strings.Builder
		buf := make([]byte, 4096)
		for !strings.HasSuffix(got.String(), done) {
			n, err := master.Read(buf)
			got.Write(buf[:n])
			if err != nil {
				break
			}
		}
		out <- strings.TrimSuffix(got.String(), done)
	}()

	origOut := os.Stdout
	os.Stdout = slave
	defer func() { os.Stdout = origOut }()

	root := cliRoot()
	root.SetArgs(append([]string{}, args...))
	cmd, err := root.ExecuteC()
	code = Exit(cmd, err, os.Stderr)
	if logger := uptermctx.Logger(cmd.Context()); logger != nil {
		_ = logger.Close()
	}
	_, err = slave.WriteString(done)
	require.NoError(t, err)

	select {
	case stdout = <-out:
	case <-time.After(10 * time.Second):
		t.Fatal("the terminal never reported the end of the output")
	}
	require.NoError(t, slave.Close())
	return stdout, code
}

func TestListFitsTheCellsToTheTerminalItPrintsOn(t *testing.T) {
	setupSessionRoots(t)
	d := heldReady(t, "build")
	serveStubAdmin(t, d.AdminSocket(), &api.GetSessionResponse{
		SessionId: "sid",
		Host:      "wss://a-relay-with-a-very-long-host-name.example.com:8443",
		NodeAddr:  "127.0.0.1:2222",
		Command:   []string{"/usr/local/bin/some-very-long-wrapper", "--with", "--many", "--flags", "--and-then-some-more", "/a/long/path"},
	})

	const cols = 60
	stdout, code := runCLIOnTerminal(t, cols, "session", "list")
	require.Equal(t, 0, code)

	// The terminal ends each line with CR LF.
	lines := strings.Split(strings.TrimSuffix(strings.ReplaceAll(stdout, "\r\n", "\n"), "\n"), "\n")
	require.Len(t, lines, 2, stdout)
	for _, line := range lines {
		require.LessOrEqual(t, utf8.RuneCountInString(line), cols, line)
	}
	require.Contains(t, lines[1], "build")
	require.Contains(t, lines[1], "sid")
	require.Equal(t, 2, strings.Count(lines[1], "…"), "both long cells are shortened: %q", lines[1])

	// The same listing into a pipe is whole.
	piped, _, code := runCLI(t, "session", "list")
	require.Equal(t, 0, code)
	require.Contains(t, piped, "/usr/local/bin/some-very-long-wrapper --with --many --flags --and-then-some-more /a/long/path")
	require.Contains(t, piped, "wss://a-relay-with-a-very-long-host-name.example.com:8443")
}
