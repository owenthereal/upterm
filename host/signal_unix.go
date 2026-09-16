//go:build !windows

package host

import (
	"os"
	"os/signal"
	"sync"

	"golang.org/x/sys/unix"
)

// installOnce keeps the drain goroutine below to one per process. The
// dispositions it installs are process-wide, so installing them twice buys
// nothing and leaks a goroutine per call — and Run may be called repeatedly,
// by a supervisor or a test.
var installOnce sync.Once

// InstallSignalPolicy sets the process-wide signal dispositions a host needs:
// SIGPIPE converted to EPIPE, and SIGTTIN and SIGTTOU ignored. Starting a host
// installs it before it touches its terminal; an embedder that writes to the
// same stdout or reads the same stdin before then may call it earlier, and
// calling it twice is free.
//
// SIGPIPE is fatal for writes to fd 1 and 2 and only for those; Go turns it
// into EPIPE everywhere else. So `upterm host … | head` would kill the whole
// session the instant head exits, taking the hosted command with it — the one
// failure mode headless operation must not have. Calling Notify converts it to
// EPIPE, and the error then travels the ordinary path: the stdout sink fails
// and is dropped.
//
// SIGTTIN and SIGTTOU get SIG_IGN, not a handler. A backgrounded process
// reading its controlling terminal is sent SIGTTIN, and the default
// disposition stops it — so `upterm host … &` would suspend. With a handler
// installed the read returns EINTR and Go retries, which spins. Ignored, it
// returns EIO, which the host's stdin actor survives. SIGTTOU is the same
// story for writes, and it is why the ignores are installed here rather than
// beside the signal actor, where they used to be: Run assembles that only
// after the reverse tunnel is up, the version warning is printed and
// SessionCreatedCallback has written the banner, and from a terminal with
// `stty tostop` set the first of those writes stopped the host before the
// ignore existed. The prompting host-key callback's read of stdin was sent
// SIGTTIN the same way.
//
// Ignoring SIGTTOU also means a background tcsetattr would succeed, which is
// why command.Run checks foreground ownership before touching terminal modes
// at all.
//
// It belongs to this package rather than to the CLI, which is where the
// SIGPIPE conversion used to live and still is: an application that embeds
// Host.Run with Stdout set to its own os.Stdout never runs upterm's main, so
// it inherited the fatal disposition and died on its reader's close — before
// the sink could report the broken pipe and before the final session record
// was published.
//
// Process-wide and permanent is the point. Scoping any of it to a session
// would leave the startup banner unprotected at one end and the shutdown
// drain unprotected at the other, and nothing here may ever call signal.Stop
// or signal.Reset: that would strip the policy from every other session in
// the same process. An embedder that calls Host.Run in-process inherits all
// three for the rest of the process's life, and so does everything else in
// that process — a library of its own that reads a background terminal would
// find the read returning EIO instead of the caller being stopped.
func InstallSignalPolicy() {
	installOnce.Do(func() {
		sigPipe := make(chan os.Signal, 1)
		signal.Notify(sigPipe, unix.SIGPIPE)
		go func() {
			for range sigPipe {
			}
		}()

		signal.Ignore(unix.SIGTTIN, unix.SIGTTOU)
	})
}
