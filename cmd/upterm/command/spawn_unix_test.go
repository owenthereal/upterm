//go:build !windows

package command

import (
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// daemonHandoffEnv is the variable whose presence makes this process the
// daemon on this platform: here, the descriptor the socketpair was handed
// over on.
const daemonHandoffEnv = daemonFDEnv

// daemonEnvCleared reports whether bootstrapConn removed every variable this
// transport hands a daemon, so the hosted command cannot inherit any of them.
func daemonEnvCleared() bool {
	return os.Getenv(daemonFDEnv) == "" && os.Getenv(daemonNameEnv) == ""
}

// reportPlatformFindings adds what only a Unix child can answer: that it is a
// session of its own, that its stdin is /dev/null, that the channel it holds
// is marked close-on-exec, and that it holds exactly one AF_UNIX stream.
func reportPlatformFindings(report func(k, v string), conn net.Conn) {
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
	sid, _ := unix.Getsid(0)
	report("session_leader", strconv.FormatBool(sid == os.Getpid()))
	stdinInfo, _ := os.Stdin.Stat()
	nullInfo, _ := os.Stat(os.DevNull)
	report("stdin_devnull", strconv.FormatBool(os.SameFile(stdinInfo, nullInfo)))
	var flags int
	rc, _ := conn.(syscall.Conn).SyscallConn()
	_ = rc.Control(func(fd uintptr) { flags, _ = unix.FcntlInt(fd, unix.F_GETFD, 0) })
	report("cloexec", strconv.FormatBool(flags&unix.FD_CLOEXEC != 0))
}

func requirePlatformReports(t *testing.T, log string) {
	t.Helper()
	for _, want := range []string{
		// ExtraFiles[0], and nothing about that is negotiable: the child
		// looks the descriptor up by the number this hands it.
		"REPORT handoff=3",
		"REPORT session_leader=true",
		"REPORT stdin_devnull=true",
		"REPORT cloexec=true",
		// A socketpair whose peer is closed is EOF, not a reset, so the
		// stricter shape is required here rather than only parent_gone.
		"REPORT eof=true",
	} {
		require.Contains(t, log, want)
	}
	// Anchored at the end of the line, not a substring: "unix_sockets=10"
	// contains "unix_sockets=1", and ten leaked descriptors is exactly what
	// this is meant to catch.
	require.Regexp(t, `(?m)REPORT unix_sockets=1$`, log,
		"the one is net.FileConn's close-on-exec dup of the child's own end; a second would be the child's inherited copy of that same end")
}
