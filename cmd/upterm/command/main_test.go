package command

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
)

// TestMain stands between this package's tests and the real spawn.
//
// upterm host starts its daemon by re-executing os.Args. In a test binary
// that argv is the test runner's, so a test that reaches spawnDaemon starts a
// second copy of this binary running the whole suite — which reaches
// spawnDaemon again, once per test that does, and so on until the machine
// stops. That has happened. Two guards, one on each side of the exec:
//
//   - The parent side: hostSpawn is replaced with a tripwire that fails the
//     test and names runHostInProcess, the seam every test that drives
//     `upterm host` end to end must use. runHostInProcess swaps in the real
//     in-process daemon for its own duration and restores this afterwards.
//   - The child side: a copy of this binary that finds the daemon's
//     descriptor in its environment but not the marker the one legitimate
//     re-exec test sets (TestSpawnHelperProcess, UPTERM_SPAWN_HELPER) was
//     started by accident. It exits before running anything.
func TestMain(m *testing.M) {
	if os.Getenv(daemonFDEnv) != "" && os.Getenv("UPTERM_SPAWN_HELPER") != "1" {
		fmt.Fprintln(os.Stderr, "command tests: this test binary was re-executed as a daemon; a test reached the real spawn instead of runHostInProcess")
		os.Exit(2)
	}
	hostSpawn = func(spawnOptions) (net.Conn, *os.Process, error) {
		return nil, nil, errors.New("test reached the real spawn: drive upterm host through runHostInProcess")
	}
	os.Exit(m.Run())
}
