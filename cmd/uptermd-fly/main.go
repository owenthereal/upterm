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

	flyConsulURL := os.Getenv("FLY_CONSUL_URL")
	if flyConsulURL == "" {
		logger.Fatal("FLY_CONSUL_URL is not set")
	}

	// Configure uptermd for Fly.io deployment with Consul routing
	config := map[string]any{
		"UPTERMD_NODE_ADDR":          fmt.Sprintf("%s.vm.%s.internal:2222", flyMachineID, flyAppName),
		"UPTERMD_SSH_ADDR":           "0.0.0.0:2222",
		"UPTERMD_WS_ADDR":            "0.0.0.0:8080",
		"UPTERMD_HOSTNAME":           "uptermd.upterm.dev",
		"UPTERMD_ROUTING":            "consul",
		"UPTERMD_CONSUL_ADDR":        flyConsulURL,
		"UPTERMD_CONSUL_SESSION_TTL": "1h",
	}

	// Set environment variables
	for key, value := range config {
		if err := os.Setenv(key, fmt.Sprintf("%v", value)); err != nil {
			logger.WithError(err).WithField("key", key).Fatal("Failed to set environment variable")
		}
	}

	logger.WithFields(log.Fields(config)).Info("Starting uptermd on Fly.io with Consul routing")

	if err := command.Root(logger).Execute(); err != nil {
		logger.Fatal(err)
	}
}
