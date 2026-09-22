//go:build windows

package command

// signalNumber has no answer on Windows: host/internal records no signal
// there because Windows terminates a process with a status instead.
func signalNumber(string) int { return 0 }
