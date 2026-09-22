package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/owenthereal/upterm/cmd/uptermd/command"
)

func main() {
	// A signal is how every supervisor uptermd runs under -- Fly, Docker,
	// Kubernetes, systemd -- asks it to stop, and the shutdown it is asking for
	// is the one that deletes this node's entries from the session store.
	// Executing without a cancellable context left Server.Shutdown reachable
	// only from ftests and in-process embedders, so a deploy killed the process
	// where it stood; under Consul routing the entries then outlived the node
	// and kept joiners being routed to it until their TTL expired.
	ctx, stop := command.NotifyShutdownSignals(context.Background())
	defer stop()

	// A stop that was asked for comes back nil: ServeWithContext reports the
	// cancellation as a requested stop rather than a failure, so this exits 0
	// instead of telling the supervisor the deploy failed.
	if err := command.Root().ExecuteContext(ctx); err != nil {
		slog.Error("command execution failed", "error", err)
		os.Exit(1)
	}
}
