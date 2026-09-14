//go:build !windows

package host

import (
	"os"
	"os/signal"
	"sync"

	"golang.org/x/sys/unix"
)

// installOnce keeps the drain goroutine below to one per process. The
// disposition it installs is process-wide, so installing it twice buys
// nothing and leaks a goroutine per call -- and Run may be called repeatedly,
// by a supervisor or a test.
var installOnce sync.Once

// InstallSignalPolicy sets the process-wide signal dispositions a host needs
// before it writes anything. Run calls it; an embedder may call it earlier,
// and calling it twice is free.
//
// SIGPIPE is fatal for writes to fd 1 and 2 and only for those; Go turns it
// into EPIPE everywhere else. So `upterm host … | head` would kill the whole
// session the instant head exits, taking the hosted command with it -- the one
// failure mode headless operation must not have. Calling Notify converts it to
// EPIPE, and the error then travels the ordinary path: the stdout sink fails
// and is dropped.
//
// It belongs to this package rather than to the CLI, which is where it used to
// live and still is: an application that embeds Host.Run with Stdout set to
// its own os.Stdout never runs upterm's main, so it inherited the fatal
// disposition and died on its reader's close -- before the sink could report
// the broken pipe and before the final session record was published.
//
// Process-wide and permanent is the point. Scoping it to a session would leave
// the startup banner unprotected at one end and the shutdown drain unprotected
// at the other, and nothing here may ever call signal.Stop: that would strip
// the conversion from every other session in the same process.
func InstallSignalPolicy() {
	installOnce.Do(func() {
		sigPipe := make(chan os.Signal, 1)
		signal.Notify(sigPipe, unix.SIGPIPE)
		go func() {
			for range sigPipe {
			}
		}()
	})
}
