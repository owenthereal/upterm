// Command uptermd-test is uptermd composed with an enabled test authority,
// which accepts every registration of the test extension's protocol, for
// tests that drive the built CLI.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/owenthereal/upterm/cmd/uptermd/command"
	"github.com/owenthereal/upterm/internal/testhelpers/testauthority"
	"github.com/owenthereal/upterm/internal/testhelpers/testextension/calls"
	"github.com/owenthereal/upterm/server"
)

func main() {
	ctx, stop := command.NotifyShutdownSignals(context.Background())
	defer stop()

	ext := &command.Extension{
		Name: "test",
		New: func(context.Context, command.Config) (server.Extensions, error) {
			return server.Extensions{Authority: testauthority.New(), Enabled: true, Protocols: []string{calls.Protocol}}, nil
		},
	}
	if err := command.RootWith(ext).ExecuteContext(ctx); err != nil {
		slog.Error("command execution failed", "error", err)
		os.Exit(1)
	}
}
