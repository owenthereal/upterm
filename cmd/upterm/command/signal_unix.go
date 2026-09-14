//go:build !windows

package command

import "github.com/owenthereal/upterm/host"

// InstallSignalPolicy sets the process-wide signal dispositions a host needs.
// main calls it before anything can write a byte, which is earlier than
// Host.Run can install it for itself — the version warning and the session
// banner both go out before that.
//
// The policy itself belongs to host, not here: an application that embeds
// Host.Run never runs upterm's main, and the disposition it needs is a
// property of hosting a session rather than of being this CLI.
func InstallSignalPolicy() {
	host.InstallSignalPolicy()
}
