package main

import (
	"log/slog"
	"os"

	"github.com/owenthereal/upterm/cmd/upterm/command"
)

func main() {
	if err := command.Root().Execute(); err != nil {
		slog.Error("Error executing command", "error", err)
		os.Exit(1)
	}
}
