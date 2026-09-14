//go:build !windows

package host

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/oklog/run"
	"github.com/stretchr/testify/require"
)

// Test_Host_ClosedStdoutReaderDoesNotKillAnEmbedder covers the process-wide
// policy from the side that owns it. SIGPIPE is fatal for writes to fd 1 and
// 2, so `upterm host … | head` -- or any embedder whose stdout reader goes
// away -- died the instant the reader closed, before the sink could see EPIPE
// and before the final record was published. The conversion was installed by
// the CLI's main, which an embedder of Host.Run never runs.
//
// The child is therefore an embedder: it calls setupSignalHandler and nothing
// else, which is the smallest thing a program can do with this package that
// has to be enough. Installing the policy anywhere further in -- inside
// Run's actors, say -- would leave a startup banner written before the group
// exists unprotected.
func Test_Host_ClosedStdoutReaderDoesNotKillAnEmbedder(t *testing.T) {
	if os.Getenv("UPTERM_HOST_SIGPIPE_CHILD") == "1" {
		// Never run: the group's actors are not what is under test, and the
		// policy has to be in force by the time the group is assembled rather
		// than by the time it runs.
		var g run.Group
		var shutdownRequested atomic.Bool
		setupSignalHandler(&g, context.Background(), &shutdownRequested)

		for i := 0; i < 1000; i++ {
			fmt.Println(strings.Repeat("x", 1024))
		}

		_, _ = fmt.Fprintln(os.Stderr, "SURVIVED")
		os.Exit(7)
	}

	cmd := exec.Command(os.Args[0], "-test.run=Test_Host_ClosedStdoutReaderDoesNotKillAnEmbedder")
	cmd.Env = append(os.Environ(), "UPTERM_HOST_SIGPIPE_CHILD=1")

	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	require.NoError(t, cmd.Start())
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
