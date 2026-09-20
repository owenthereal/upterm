//go:build !windows

package command

import (
	"os"
	"os/signal"
	"syscall"
)

// suspendSupported says whether this platform can stop a process the way a
// job-control shell expects. InstallSignalPolicy ignores only SIGTTIN and
// SIGTTOU, so SIGTSTP keeps whatever disposition this process inherited.
const suspendSupported = true

// suspendAvailable reports whether this process can actually be stopped. A
// child of a non-interactive shell inherits SIGTSTP ignored, and raising an
// ignored SIGTSTP is a no-op — which, with a stop that waits to be
// continued, would be a wait that never ends. Decided once, when the hook is
// installed: with no hook, ~^Z is not offered and both bytes reach the
// session, exactly as on a platform without job control.
func suspendAvailable() bool { return !signal.Ignored(syscall.SIGTSTP) }

// stopSelf stops this process and returns once it has been continued.
//
// The signal goes to this pid, not the group, exactly as ssh's ~^Z does: the
// shell that started us reports "Stopped" and fg is what comes back. Unlike
// ssh's, this returns only when SIGCONT arrives, because kill(2) to ourselves
// returns before the group stop lands: the kernel stops the group from
// whichever thread dequeues the signal, and in a multithreaded process that
// is rarely the raising thread. Measured on Linux — the thread that raised
// SIGTSTP re-entered raw mode in the same millisecond, the process stopped
// afterwards in raw mode, the shell put its own cooked modes back, and fg
// brought it back cooked. SIGCONT is registered for before the raise so a
// continue cannot be missed, and the kernel resumes a stopped process on
// SIGCONT whether or not anything handles it.
func stopSelf() error {
	cont := make(chan os.Signal, 1)
	signal.Notify(cont, syscall.SIGCONT)
	defer signal.Stop(cont)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTSTP); err != nil {
		return err
	}
	<-cont
	return nil
}
