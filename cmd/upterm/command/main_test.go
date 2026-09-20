package command

import (
	"fmt"
	"os"
	"testing"
)

// TestMain is the child-side half of the guard around the real spawn.
//
// upterm host starts its daemon by re-executing os.Args. In a test binary
// that argv is the test runner's, so a test that reaches spawnDaemon starts a
// second copy of this binary running the whole suite — which reaches
// spawnDaemon again, once per test that does, and so on until the machine
// stops. That has happened. Two guards, one on each side of the exec:
//
//   - The parent side is production code: hostSpawn's default is
//     guardedSpawn, which refuses inside a test binary and names
//     runHostInProcess, the seam every test that drives `upterm host` end to
//     end must use. It lives in host.go rather than here because a TestMain
//     protects one package and every other package that can reach the root
//     command needs the same refusal.
//   - The child side is here: a copy of this binary that finds a daemon's
//     handoff in its environment — either transport's variable, see
//     startedAsDaemon — but not the marker the one legitimate re-exec test
//     sets (TestSpawnHelperProcess, UPTERM_SPAWN_HELPER) was started by
//     accident. It exits before running anything, so even a deliberately
//     broken parent-side guard costs one process, not the machine.
func TestMain(m *testing.M) {
	if startedAsDaemon() && os.Getenv("UPTERM_SPAWN_HELPER") != "1" {
		fmt.Fprintln(os.Stderr, "command tests: this test binary was re-executed as a daemon; a test reached the real spawn instead of runHostInProcess")
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// startedAsDaemon reports whether this process's environment says it was
// re-executed as the daemon.
//
// Both transports' handoffs, not just this build's: UPTERM_DAEMON_FD is the
// descriptor the Unix socketpair is passed on, UPTERM_DAEMON_SOCKET the path
// the Windows child dials. Named as strings rather than through the platform
// constants on purpose — only one of those constants exists in any given
// build, and a guard that knew only its own platform's variable could not be
// proved anywhere but on that platform. This one can be tripped from a Mac
// with a Windows-shaped environment, which is the whole point: the machine
// this fork bomb has already taken down twice is the one where the Windows
// variables cannot otherwise be exercised.
//
// spawn_test.go's TestTestMainGuardKnowsThisPlatformsHandoff keeps the list
// honest against the constants.
func startedAsDaemon() bool {
	return os.Getenv("UPTERM_DAEMON_FD") != "" || os.Getenv("UPTERM_DAEMON_SOCKET") != ""
}
