package main

import (
	"errors"
	"log/slog"
	"os"

	"github.com/owenthereal/upterm/cmd/upterm/command"
)

func main() {
	if err := command.Root().Execute(); err != nil {
		// Don't log errors that have already been displayed to the user
		var silentErr command.SilentError
		if !errors.As(err, &silentErr) {
			slog.Error("Error executing command", "error", err)
		}
		os.Exit(1)
	}
}
