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
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
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

// Test_InstallSignalPolicy_IgnoresTheJobControlStops covers the other two
// dispositions the policy owns. SIGTTIN and SIGTTOU used to be ignored at the
// end of setupSignalHandler, which Run reaches only after the reverse tunnel
// is up, the version warning is printed and SessionCreatedCallback has written
// the banner. `upterm host --accept … &` from a terminal with `stty tostop`
// set was sent SIGTTOU by the first of those writes and stopped before the
// ignore existed; the prompting host-key callback's read of stdin was sent
// SIGTTIN the same way. InstallSignalPolicy is Run's first act, so the ignores
// have to be its doing and nothing else's.
//
// A child, for the same reason as above: the dispositions are process-wide,
// and by the time this runs another test in the package has already called
// setupSignalHandler, so an in-process check would pass whatever
// InstallSignalPolicy did. The child's os/signal bookkeeping starts clear
// whatever disposition it inherited across exec -- signal.Ignored reports
// what this process asked for, not what the kernel holds -- so the check
// before the call pins that, and only a signal.Ignore inside the child can
// satisfy the checks after it.
func Test_InstallSignalPolicy_IgnoresTheJobControlStops(t *testing.T) {
	if os.Getenv("UPTERM_HOST_SIGNAL_POLICY_CHILD") == "1" {
		require.False(t, signal.Ignored(syscall.SIGTTIN) || signal.Ignored(syscall.SIGTTOU),
			"the child must start with nothing ignored on its own account")

		InstallSignalPolicy()

		require.True(t, signal.Ignored(syscall.SIGTTIN), "InstallSignalPolicy alone must ignore SIGTTIN")
		require.True(t, signal.Ignored(syscall.SIGTTOU), "InstallSignalPolicy alone must ignore SIGTTOU")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), childTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=Test_InstallSignalPolicy_IgnoresTheJobControlStops")
	cmd.Env = append(os.Environ(), "UPTERM_HOST_SIGNAL_POLICY_CHILD=1")

	// The child's exit status is this one test's verdict: the filter runs
	// nothing else there, and a require failure in the child fails its binary.
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "child output:\n%s", out)
}
