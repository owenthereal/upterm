package host

import (
	"testing"

	"github.com/owenthereal/upterm/internal/testhelpers/legacyssh"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// Host's process-wide SIGPIPE policy lasts until process exit.
	goleak.VerifyTestMain(legacyssh.Suite{M: m}, goleak.IgnoreTopFunction("github.com/owenthereal/upterm/host.drainSIGPIPE"))
}
