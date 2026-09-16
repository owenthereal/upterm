//go:build windows

package host

// InstallSignalPolicy sets process-wide signal dispositions. Windows has no
// SIGPIPE to convert — a write to a broken pipe already surfaces as an ordinary
// error — and no job-control stops to ignore, so there is nothing to install
// here; see the Unix counterpart for the three dispositions a host needs there.
func InstallSignalPolicy() {}
