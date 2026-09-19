//go:build windows

package command

import (
	"errors"
	"net"
	"os"
)

const (
	daemonFDEnv   = "UPTERM_DAEMON_FD"
	daemonNameEnv = "UPTERM_DAEMON_NAME"
)

// spawnSupported is false until the Windows transport lands: ExtraFiles is
// not supported there and there is no socketpair, so upterm host runs the
// daemon in-process as stage 2 did.
const spawnSupported = false

type spawnOptions struct {
	executable string
	args       []string
	env        []string
	name       string
	logPath    string
}

var errSpawnUnsupported = errors.New("running the session in a separate process is not supported on Windows yet")

func spawnDaemon(spawnOptions) (net.Conn, *os.Process, error) {
	return nil, nil, errSpawnUnsupported
}

func bootstrapConn() (net.Conn, string, error) { return nil, "", nil }
