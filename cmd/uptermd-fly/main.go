package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/owenthereal/upterm/cmd/uptermd/command"
)

func main() {
	flyAppName := os.Getenv("FLY_APP_NAME")
	if flyAppName == "" {
		slog.Error("FLY_APP_NAME is not set")
		os.Exit(1)
	}

	flyMachineID := os.Getenv("FLY_MACHINE_ID")
	if flyMachineID == "" {
		slog.Error("FLY_MACHINE_ID is not set")
		os.Exit(1)
	}

	config := map[string]any{
		"UPTERMD_SSH_ADDR":           "0.0.0.0:2222",
		"UPTERMD_WS_ADDR":            "0.0.0.0:8080",
		"UPTERMD_NODE_ADDR":          fmt.Sprintf("%s.vm.%s.internal:2222", flyMachineID, flyAppName),
		"UPTERMD_SSH_PROXY_PROTOCOL": "true",
		"UPTERMD_METRIC_ADDR":        "0.0.0.0:9091",
	}

	flyConsulURL := os.Getenv("FLY_CONSUL_URL")
	if flyConsulURL != "" {
		config["UPTERMD_ROUTING"] = "consul"
		config["UPTERMD_CONSUL_URL"] = flyConsulURL
		config["UPTERMD_CONSUL_SESSION_TTL"] = "1h"
		slog.Info("Using Consul routing for multi-machine deployment")
	} else {
		config["UPTERMD_ROUTING"] = "embedded"
		slog.Info("Using embedded routing for single-machine deployment")
	}

	for key, value := range config {
		if err := os.Setenv(key, fmt.Sprintf("%v", value)); err != nil {
			slog.Error("failed to set environment variable", "key", key, "error", err)
			os.Exit(1)
		}
	}

	slog.Info("Starting uptermd on Fly.io", "config", config)
	if err := command.Root().Execute(); err != nil {
		slog.Error("command execution failed", "error", err)
		os.Exit(1)
	}
}
