//go:build windows

package host

// InstallSignalPolicy sets process-wide signal dispositions. Windows has no
// SIGPIPE to convert — a write to a broken pipe already surfaces as an ordinary
// error — so there is nothing to install here.
func InstallSignalPolicy() {}
