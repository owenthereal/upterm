//go:build !windows

package command

import (
	"os"
	"syscall"
)

// suspendSupported says whether this process can stop itself the way a
// job-control shell expects. InstallSignalPolicy ignores only SIGTTIN and
// SIGTTOU, so SIGTSTP keeps its default disposition and really stops us.
const suspendSupported = true

// stopSelf stops this process. The signal goes to this pid, not the group,
// exactly as ssh's ~^Z does: the shell that started us reports "Stopped" and
// fg is what comes back.
func stopSelf() error { return syscall.Kill(os.Getpid(), syscall.SIGTSTP) }
