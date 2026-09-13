//go:build !windows

package command

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/oklog/run"
	"github.com/stretchr/testify/require"
)

func Test_ClosedStdoutReaderDoesNotKillProcess(t *testing.T) {
	if os.Getenv("UPTERM_SIGPIPE_CHILD") == "1" {
		// Child: install the *production* policy — not a local signal.Notify.
		// An earlier draft called signal.Notify here directly, which tested Go
		// rather than upterm: deleting the production call would have left this
		// test green.
		InstallSignalPolicy()
		for i := 0; i < 1000; i++ {
			fmt.Println(strings.Repeat("x", 1024))
		}

		// Also cover shutdown, which is where a session-scoped policy would
		// have reopened the hole. run.SignalHandler — the same primitive
		// host_unix.go uses — calls signal.Stop on its own channel when its
		// interrupt path runs, so cancelling the context here exercises that
		// stop. The second burst below then pins that an unrelated handler's
		// signal.Stop does not strip the process-wide SIGPIPE conversion.
		ctx, cancel := context.WithCancel(context.Background())
		var g run.Group
		g.Add(run.SignalHandler(ctx, os.Interrupt, syscall.SIGTERM))
		cancel()
		_ = g.Run()

		for i := 0; i < 1000; i++ {
			fmt.Println(strings.Repeat("x", 1024))
		}
		_, _ = fmt.Fprintln(os.Stderr, "SURVIVED")
		os.Exit(7)
	}

	cmd := exec.Command(os.Args[0], "-test.run=Test_ClosedStdoutReaderDoesNotKillProcess")
	cmd.Env = append(os.Environ(), "UPTERM_SIGPIPE_CHILD=1")

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
		"the child must reach its own exit, not die of SIGPIPE; stderr: %s", stderr.String())
	require.Contains(t, stderr.String(), "SURVIVED")
}
