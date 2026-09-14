//go:build windows

package command

import "github.com/owenthereal/upterm/host"

// InstallSignalPolicy sets the process-wide signal dispositions a host needs.
// See the Unix file for why main calls it; the platform difference now lives
// in host, which has nothing to install on Windows.
func InstallSignalPolicy() {
	host.InstallSignalPolicy()
}
