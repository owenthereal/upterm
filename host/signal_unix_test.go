//go:build !windows

package host

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// childTimeout bounds the child below. It is a hang detector: the child dials
// a port nothing listens on and exits, so anything approaching this means it
// is stuck rather than slow.
const childTimeout = 30 * time.Second

// Test_Host_ClosedStdoutReaderDoesNotKillAnEmbedder covers the process-wide
// policy from the side that owns it. SIGPIPE is fatal for writes to fd 1 and
// 2, so `upterm host … | head` — or any embedder whose stdout reader goes
// away — died the instant the reader closed, before the sink could see EPIPE
// and before the final record was published. The conversion was installed by
// the CLI's main, which an embedder of Host.Run never runs.
//
// The child is therefore an embedder: it builds a Host over the process's own
// stdout and calls Run, and Run is what has to install the policy. Calling
// setupSignalHandler directly instead would assert something narrower than
// this test's name — Run writes to Stdout before it ever assembles the signal
// actor, so the policy has to be in force before that, and only a call
// through Run can show it is.
//
// No relay: the host dials a port nothing listens on, so Run returns from
// Establish. Everything this test is about has already happened by then.
func Test_Host_ClosedStdoutReaderDoesNotKillAnEmbedder(t *testing.T) {
	if os.Getenv("UPTERM_HOST_SIGPIPE_CHILD") == "1" {
		h := &Host{
			// Port 1 is privileged and unbound: the dial fails fast and
			// locally, without a relay to stand up or a network to reach.
			Host:    "ssh://127.0.0.1:1",
			Command: []string{"true"},
			// Supplying a socket is how a caller says it manages the paths
			// itself, which keeps this run from claiming a session name. The
			// path is never bound, so nothing is created under it.
			AdminSocketFile: filepath.Join(os.TempDir(), "upterm-sigpipe-child-admin.sock"),
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
			Stdout:          os.Stdout,
		}
		if err := h.Run(context.Background()); err == nil {
			_, _ = fmt.Fprintln(os.Stderr, "the host reached a relay that should not exist")
			os.Exit(1)
		}

		for i := 0; i < 1000; i++ {
			fmt.Println(strings.Repeat("x", 1024))
		}

		_, _ = fmt.Fprintln(os.Stderr, "SURVIVED")
		os.Exit(7)
	}

	ctx, cancel := context.WithTimeout(context.Background(), childTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=Test_Host_ClosedStdoutReaderDoesNotKillAnEmbedder")
	cmd.Env = append(os.Environ(), "UPTERM_HOST_SIGPIPE_CHILD=1")

	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	require.NoError(t, cmd.Start())
	// Belt and braces with the context above, which only kills the child once
	// childTimeout expires: a child that outlives this test for any other
	// reason goes with it.
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	// Close the read end immediately: every subsequent child write is a
	// broken-pipe write to fd 1.
	require.NoError(t, stdout.Close())

	err = cmd.Wait()

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 7, exitErr.ExitCode(),
		"a host whose stdout reader closed must reach its own exit, not die of SIGPIPE; stderr: %s", stderr.String())
	require.Contains(t, stderr.String(), "SURVIVED")
}
