package main

import (
	"errors"
	"log/slog"
	"os"

	"github.com/owenthereal/upterm/cmd/upterm/command"
)

func main() {
	command.InstallSignalPolicy()

	if err := command.Root().Execute(); err != nil {
		// A command that carries its own exit status decides it, before the
		// catch-all below turns everything into 1: `upterm attach` reports
		// the hosted command's status, and a script that branches on it
		// cannot tell 1-because-the-command-failed from 1-because-upterm-did.
		// Nothing is logged here — cobra has already printed whatever the
		// user needs to read, and repeating it is how one failure became
		// three stanzas on stderr.
		var ec command.ExitCodeError
		if errors.As(err, &ec) {
			os.Exit(ec.Code)
		}

		// Don't log errors that have already been displayed to the user
		var silentErr command.SilentError
		if !errors.As(err, &silentErr) {
			slog.Error("Error executing command", "error", err)
		}
		os.Exit(1)
	}
}
