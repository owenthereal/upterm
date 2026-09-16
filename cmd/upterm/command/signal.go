package command

import "github.com/owenthereal/upterm/host"

// InstallSignalPolicy sets the process-wide signal dispositions a host needs.
//
// main calls it first, and not because Host.Run would be late to: Run installs
// it as its own first statement. It is because most of what this CLI writes
// never reaches Run at all — cobra's usage and flag errors, `session list`,
// `version` — and `upterm session list | head` has to survive its reader going
// away for the same reason `upterm host … | head` does.
//
// The policy itself belongs to host, not here: an application that embeds
// Host.Run never runs upterm's main, and the disposition is a property of
// hosting a session rather than of being this CLI. The platform difference
// lives there too — Windows has no SIGPIPE to convert — which is why this file
// needs no build tag.
func InstallSignalPolicy() {
	host.InstallSignalPolicy()
}
