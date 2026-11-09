// Command darkrelay is uptermd with a test authority composed, dark, for the
// mixed-version suite: a node that gates its own hops and still accepts
// legacy ones.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/owenthereal/upterm/cmd/uptermd/command"
	"github.com/owenthereal/upterm/internal/testhelpers/testauthority"
	"github.com/owenthereal/upterm/server"
)

func main() {
	ctx, stop := command.NotifyShutdownSignals(context.Background())
	defer stop()
	root := command.RootWith(&command.Extension{Name: "testauthority", New: func(context.Context, command.Config) (server.Extensions, error) {
		return server.Extensions{Authority: testauthority.New(), Protocols: []string{"test_v1"}}, nil
	}})
	if err := root.ExecuteContext(ctx); err != nil {
		slog.Error("command execution failed", "error", err)
		os.Exit(1)
	}
}
