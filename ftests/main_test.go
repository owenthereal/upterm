package ftests

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// Host's process-wide SIGPIPE policy lasts until process exit.
	goleak.VerifyTestMain(m, goleak.IgnoreTopFunction("github.com/owenthereal/upterm/host.drainSIGPIPE"))
}
