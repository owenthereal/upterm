package command

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
	"github.com/owenthereal/upterm/host/api"
	"github.com/stretchr/testify/require"
)

// TestSpawnHelperProcess is the child of TestSpawnDaemonHandsTheChildItsChannel:
// the test binary re-executed with UPTERM_SPAWN_HELPER=1. It reports what it
// finds on its stdout, which the parent pointed at the log file, and exits.
//
// The two transports have almost nothing in common — one inherits a
// socketpair, the other dials a listener — and this is what they are both
// held to: the daemon's name arrives, the variables that carried it are gone
// before the hosted command can see them, and the child learns when the
// parent leaves. What only one platform can answer is reported by
// reportPlatformFindings and required by requirePlatformReports.
func TestSpawnHelperProcess(t *testing.T) {
	if os.Getenv("UPTERM_SPAWN_HELPER") != "1" {
		return
	}
	defer os.Exit(0)
	report := func(k, v string) { fmt.Printf("REPORT %s=%s\n", k, v) }

	// Read before bootstrapConn, which unsets it. What the parent does with
	// it is the platform's business: a descriptor number on one side, a
	// socket path whose directory must already be gone on the other.
	report("handoff", os.Getenv(daemonHandoffEnv))
	conn, name, err := bootstrapConn()
	if err != nil || conn == nil {
		report("bootstrap", fmt.Sprintf("err=%v nil=%v", err, conn == nil))
		return
	}
	report("name", name)
	report("env_unset", strconv.FormatBool(daemonEnvCleared()))
	reportPlatformFindings(report, conn)
	fmt.Fprintln(os.Stderr, "STDERR_MARKER")

	// Echo one message, then wait for the parent to go: the only proof that
	// this process holds no copy of the parent's end.
	c := bootstrap.NewConn(conn)
	if m, err := c.Recv(); err == nil {
		_ = c.Send(m)
	}
	_, err = c.Recv()
	// Any read error is what bootstrap.Child treats as the parent leaving.
	// EOF is the shape a graceful close takes, which is stricter than the
	// contract and so is required only where the transport guarantees it.
	report("parent_gone", strconv.FormatBool(err != nil))
	report("eof", strconv.FormatBool(errors.Is(err, io.EOF)))
}

func TestSpawnDaemonHandsTheChildItsChannel(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "upterm.log")
	conn, proc, err := spawnDaemon(spawnOptions{
		executable: os.Args[0],
		args:       []string{"-test.run=^TestSpawnHelperProcess$"},
		env:        append(os.Environ(), "UPTERM_SPAWN_HELPER=1"),
		name:       "helper-1",
		logPath:    logPath,
	})
	require.NoError(t, err)
	require.NotNil(t, proc)
	defer func() { _ = conn.Close() }()

	c := bootstrap.NewConn(conn)
	require.NoError(t, c.Send(&api.Startup{Msg: &api.Startup_Print{Print: &api.Print{Text: "ping"}}}))
	m, err := c.Recv()
	require.NoError(t, err)
	require.Equal(t, "ping", m.GetPrint().GetText(), "the child answers on the channel it was given")

	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool {
		b, _ := os.ReadFile(logPath)
		return strings.Contains(string(b), "REPORT parent_gone=")
	}, 10*time.Second, 50*time.Millisecond, "the child never noticed the parent close: it holds a copy of the parent's end")

	b, err := os.ReadFile(logPath)
	require.NoError(t, err)
	log := string(b)
	for _, want := range []string{
		"REPORT name=helper-1",
		"REPORT env_unset=true",
		"REPORT parent_gone=true",
		"STDERR_MARKER",
	} {
		require.Contains(t, log, want)
	}
	requirePlatformReports(t, log)
}

func TestSpawnDaemonRequiresANameAndALog(t *testing.T) {
	_, _, err := spawnDaemon(spawnOptions{logPath: filepath.Join(t.TempDir(), "x")})
	require.Error(t, err)
	_, _, err = spawnDaemon(spawnOptions{name: "x"})
	require.Error(t, err)
}

func TestBootstrapConnIsNilOutsideADaemon(t *testing.T) {
	t.Setenv(daemonHandoffEnv, "")
	_ = os.Unsetenv(daemonHandoffEnv)
	conn, name, err := bootstrapConn()
	require.NoError(t, err)
	require.Nil(t, conn)
	require.Empty(t, name)
}

// TestMain's fork-bomb guard names both transports' handoff variables
// literally rather than through a constant, because it has to fire for a
// Windows-shaped environment inside a binary built for this platform — that
// is the only place it can be proved before the Windows job runs it for real.
// This is what keeps the literals honest: whichever platform runs, the
// variable this build actually hands a daemon is one the guard knows.
func TestTestMainGuardKnowsThisPlatformsHandoff(t *testing.T) {
	t.Setenv(daemonHandoffEnv, "set")
	require.True(t, startedAsDaemon(),
		"TestMain's guard does not know %s: a test that reached the real spawn would re-run this whole suite in a child, once per spawn", daemonHandoffEnv)
}
