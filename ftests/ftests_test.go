package ftests

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
)

var (
	singleNodeServer TestServer
)

func TestMain(m *testing.M) {
	remove, err := SetupKeyPairs()
	if err != nil {
		log.Fatal(err)
	}
	defer remove()

	// start the single-node server
	singleNodeServer, err = NewServer(ServerPrivateKeyContent)
	if err != nil {
		log.Fatal(err)
	}

	exitCode := m.Run()

	singleNodeServer.Shutdown()

	os.Exit(exitCode)
}

func Test_ftest(t *testing.T) {
	RunServerTest(t, "single node server", singleNodeServer, TestCases)
}
