package main

import (
	"fmt"
	"os"

	"github.com/owenthereal/upterm/cmd/uptermd/command"
	log "github.com/sirupsen/logrus"
)

func main() {
	logger := log.New()

	flyAppName := os.Getenv("FLY_APP_NAME")
	if flyAppName == "" {
		logger.Fatal("FLY_APP_NAME is not set")
	}

	flyMachineID := os.Getenv("FLY_MACHINE_ID")
	if flyMachineID == "" {
		logger.Fatal("FLY_MACHINE_ID is not set")
	}

	os.Setenv("UPTERMD_NODE_ADDR", fmt.Sprintf("%s.vm.%s.internal:2222", flyMachineID, flyAppName))
	os.Setenv("UPTERMD_SSH_ADDR", "0.0.0.0:2222")
	os.Setenv("UPTERMD_WS_ADDR", "0.0.0.0:8080")
	os.Setenv("UPTERMD_HOSTNAME", "uptermd.upterm.dev")

	if err := command.Root(logger).Execute(); err != nil {
		logger.Fatal(err)
	}
}
