//go:build !windows

package command

import (
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

// InstallSignalPolicy sets process-wide signal dispositions. It is called once,
// before any output, and nothing removes what it installs.
//
// SIGPIPE is fatal for writes to fd 1 and 2 and only for those; Go turns it
// into EPIPE everywhere else. So `upterm host … | head` would kill the whole
// session the instant head exits, taking the hosted command with it — the one
// failure mode headless operation must not have. Calling Notify converts it to
// EPIPE, and the error then travels the ordinary path: the stdout sink fails
// and is dropped.
//
// Process-wide and permanent is the point. Scoping it to a session would leave
// the startup banner unprotected at one end and the shutdown drain unprotected
// at the other.
func InstallSignalPolicy() {
	sigPipe := make(chan os.Signal, 1)
	signal.Notify(sigPipe, unix.SIGPIPE)
	go func() {
		for range sigPipe {
		}
	}()
}
