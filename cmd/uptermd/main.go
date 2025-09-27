package main

import (
	"log/slog"
	"os"

	"github.com/owenthereal/upterm/cmd/uptermd/command"
)

func main() {
	if err := command.Root().Execute(); err != nil {
		slog.Error("command execution failed", "error", err)
		os.Exit(1)
	}
}
