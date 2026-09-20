//go:build !windows

package command

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
	"github.com/owenthereal/upterm/host/api"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestSpawnHelperProcess is the child of TestSpawnDaemonHandsTheChildItsChannel:
// the test binary re-executed with UPTERM_SPAWN_HELPER=1. It reports what it
// finds on its stdout, which the parent pointed at the log file, and exits.
func TestSpawnHelperProcess(t *testing.T) {
	if os.Getenv("UPTERM_SPAWN_HELPER") != "1" {
		return
	}
	defer os.Exit(0)
	report := func(k, v string) { fmt.Printf("REPORT %s=%s\n", k, v) }

	conn, name, err := bootstrapConn()
	if err != nil || conn == nil {
		report("bootstrap", fmt.Sprintf("err=%v nil=%v", err, conn == nil))
		return
	}
	report("name", name)
	var unixSockets int
	for fd := 3; fd < 256; fd++ {
		typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		if err != nil || typ != unix.SOCK_STREAM {
			continue
		}
		if sa, err := unix.Getsockname(fd); err == nil {
			if _, ok := sa.(*unix.SockaddrUnix); ok {
				unixSockets++
			}
		}
	}
	report("unix_sockets", strconv.Itoa(unixSockets))
	report("env_unset", strconv.FormatBool(os.Getenv(daemonFDEnv) == "" && os.Getenv(daemonNameEnv) == ""))
	sid, _ := unix.Getsid(0)
	report("session_leader", strconv.FormatBool(sid == os.Getpid()))
	stdinInfo, _ := os.Stdin.Stat()
	nullInfo, _ := os.Stat(os.DevNull)
	report("stdin_devnull", strconv.FormatBool(os.SameFile(stdinInfo, nullInfo)))
	var flags int
	rc, _ := conn.(syscall.Conn).SyscallConn()
	_ = rc.Control(func(fd uintptr) { flags, _ = unix.FcntlInt(fd, unix.F_GETFD, 0) })
	report("cloexec", strconv.FormatBool(flags&unix.FD_CLOEXEC != 0))
	fmt.Fprintln(os.Stderr, "STDERR_MARKER")

	// Echo one message, then wait for the parent's EOF: the only proof that
	// this process holds no copy of the parent's end.
	c := bootstrap.NewConn(conn)
	if m, err := c.Recv(); err == nil {
		_ = c.Send(m)
	}
	_, err = c.Recv()
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
	require.Equal(t, "ping", m.GetPrint().GetText(), "the child answers on the inherited channel")

	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool {
		b, _ := os.ReadFile(logPath)
		return strings.Contains(string(b), "REPORT eof=")
	}, 10*time.Second, 50*time.Millisecond, "the child never saw EOF after the parent closed: it holds a copy of the parent's end")

	b, err := os.ReadFile(logPath)
	require.NoError(t, err)
	log := string(b)
	for _, want := range []string{
		"REPORT name=helper-1",
		"REPORT env_unset=true",
		"REPORT session_leader=true",
		"REPORT stdin_devnull=true",
		"REPORT cloexec=true",
		"REPORT eof=true",
		"STDERR_MARKER",
	} {
		require.Contains(t, log, want)
	}
	// Anchored at the end of the line, not a substring: "unix_sockets=10"
	// contains "unix_sockets=1", and ten leaked descriptors is exactly what
	// this is meant to catch.
	require.Regexp(t, `(?m)REPORT unix_sockets=1$`, log,
		"the one is net.FileConn's close-on-exec dup of the child's own end; a second would be the child's inherited copy of that same end")
}

func TestSpawnDaemonRequiresANameAndALog(t *testing.T) {
	_, _, err := spawnDaemon(spawnOptions{logPath: "/tmp/x"})
	require.Error(t, err)
	_, _, err = spawnDaemon(spawnOptions{name: "x"})
	require.Error(t, err)
}

func TestBootstrapConnIsNilOutsideADaemon(t *testing.T) {
	t.Setenv(daemonFDEnv, "")
	_ = os.Unsetenv(daemonFDEnv)
	conn, name, err := bootstrapConn()
	require.NoError(t, err)
	require.Nil(t, conn)
	require.Empty(t, name)
}
