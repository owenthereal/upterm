//go:build windows

package internal

// signalName has no answer on Windows: a process there is terminated with a
// status rather than signalled, so the wait carries no signal to name. The
// empty string is the honest result, not a placeholder.
func signalName(err error) string {
	return ""
}
