package ftests

import (
	"os"
	"runtime"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// A guest's private exec runs its command text with the host's $SHELL,
	// and every exec test here sends POSIX shell syntax. Pin /bin/sh so a
	// developer's fish or nu login shell can't fail them for reasons that
	// aren't upterm's.
	if runtime.GOOS != "windows" {
		_ = os.Setenv("SHELL", "/bin/sh")
	}
	// Host's process-wide SIGPIPE policy lasts until process exit.
	goleak.VerifyTestMain(m, goleak.IgnoreTopFunction("github.com/owenthereal/upterm/host.drainSIGPIPE"))
}
