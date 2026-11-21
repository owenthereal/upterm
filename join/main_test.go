package join

import (
	"testing"

	"github.com/owenthereal/upterm/internal/testhelpers/legacyssh"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(legacyssh.Suite{M: m})
}
