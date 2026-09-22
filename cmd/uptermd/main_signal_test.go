//go:build !windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	// childEnvVar makes a test binary run uptermd instead of the test.
	childEnvVar = "UPTERMD_TEST_MAIN_CHILD"
	// childCleanExit is written once main has returned. A child that exits 0
	// without it never reached main at all, and the marker keeps that from
	// reading as a pass.
	childCleanExit = "uptermd-main-returned"
	// shutdownLogged is what Server.Shutdown logs, at Debug, once
	// SessionManager.Shutdown has deleted this node's sessions. It is the line
	// issue #573 is about: before the fix nothing ever cancelled the context
	// reaching server.Start, so it was reachable only from ftests and
	// in-process embedders and never ran in production.
	shutdownLogged = "cleaned up sessions during shutdown"
)

// A deploy stops uptermd with a signal, so that is what has to be tested: not a
// context cancelled by hand, and not a seam below main. The child below runs the
// real main -- the same ExecuteContext wiring, the same signal handler, the same
// os.Exit -- and the assertions are the two things an operator can observe.
//
// Exit status 0. main turns a non-nil error into os.Exit(1), and a process with
// no handler at all is killed by the signal outright, which a supervisor sees as
// 128+signo. Only a shutdown that ran and reported success comes back 0.
//
// The shutdown actually ran. Exit 0 already implies it -- oklog/run calls its
// interrupts synchronously before Run returns, and server.Start's interrupt is
// Server.Shutdown -- but the log line names the specific work the issue said
// never happened, so a future refactor that returns cleanly without deleting
// this node's sessions still fails here.
//
// Both signals are covered because both are load-bearing, and SIGINT is the one
// this issue turns on: fly.toml sets kill_signal = "SIGINT", so a handler that
// caught only SIGTERM would be a no-op on the very deployment #573 describes.
// Pinning each separately keeps shutdownSignals from being trimmed back to one
// without a test noticing.
func TestMainExitsZeroOnShutdownSignal(t *testing.T) {
	if os.Getenv(childEnvVar) == "1" {
		// Configuration comes entirely from UPTERMD_* below: cobra would reject
		// the -test.run the test binary was started with, so strip the
		// arguments before handing over to main.
		os.Args = os.Args[:1]
		main()
		fmt.Fprintln(os.Stderr, childCleanExit)
		os.Exit(0)
	}

	for _, tc := range []struct {
		name   string
		signal syscall.Signal
	}{
		{name: "SIGINT", signal: syscall.SIGINT},
		{name: "SIGTERM", signal: syscall.SIGTERM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireCleanExitOnSignal(t, tc.signal)
		})
	}
}

func requireCleanExitOnSignal(t *testing.T, sig syscall.Signal) {
	t.Helper()

	clearUptermdEnv(t)
	wsAddr := freeLoopbackAddr(t)

	// The child re-runs this file's parent test, whose first statement is the
	// env guard above, so it hands over to main before reaching the spawn: the
	// recursion is exactly one level deep.
	child := exec.Command(os.Args[0], "-test.run=^TestMainExitsZeroOnShutdownSignal$")
	child.Env = append(os.Environ(),
		childEnvVar+"=1",
		"UPTERMD_SSH_ADDR=127.0.0.1:0",
		"UPTERMD_WS_ADDR="+wsAddr,
		// Debug logging is what puts shutdownLogged on stderr.
		"UPTERMD_DEBUG=true",
	)

	var mu sync.Mutex
	var stderr bytes.Buffer
	child.Stderr = &lockedWriter{mu: &mu, w: &stderr}

	require.NoError(t, child.Start())

	waited := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		waited <- child.Wait()
	}()
	t.Cleanup(func() {
		select {
		case <-stopped:
		default:
			_ = child.Process.Kill()
		}
	})

	requireHealthy(t, wsAddr, stopped)

	require.NoError(t, child.Process.Signal(sig))

	select {
	case err := <-waited:
		mu.Lock()
		out := stderr.String()
		mu.Unlock()
		require.NoError(t, err, "uptermd did not exit 0 after %s:\n%s", sig, out)
		require.Contains(t, out, childCleanExit, "uptermd exited 0 without main returning:\n%s", out)
		require.Contains(t, out, shutdownLogged, "uptermd exited without cleaning up its sessions:\n%s", out)
	case <-time.After(60 * time.Second):
		t.Fatalf("uptermd did not exit after %s", sig)
	}
}

// lockedWriter serialises the child's stderr against the test goroutine reading
// it, which the race detector otherwise flags: exec writes from a goroutine of
// its own and only joins it in Wait.
type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
