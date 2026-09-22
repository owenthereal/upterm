//go:build !windows

package command

import "syscall"

// signalNumber maps a recorded signal name onto its number.
//
// Keyed to syscall.Signal.String(), because that is what signalName persists
// (host/internal/command_unix.go) -- "terminated", not "TERM". A mapping
// written against the SIG* names would match nothing a real signalled command
// produces, and every signal death would read as unavailable.
//
// The current runtime's spellings come from syscall values so they stay in
// lockstep with the names it records. Compatibility aliases below cover
// Linux and Darwin spellings of SIGABRT.
var signalNumbers = func() map[string]int {
	m := map[string]int{}
	// Unix WaitStatus stores the terminating signal in its low seven bits:
	// zero means exited and 0x7f means stopped. Cover the whole recordable
	// range, including unnamed real-time signals spelled "signal N".
	for s := syscall.Signal(1); s < 0x7f; s++ {
		m[s.String()] = int(s)
	}
	// Linux records SIGABRT as "aborted", while Darwin calls it "abort trap".
	// A retained record may be read on a different Unix platform, so accept the
	// literal persisted form as well as the current runtime's spelling.
	m["aborted"] = int(syscall.SIGABRT)
	m["abort trap"] = int(syscall.SIGABRT)
	return m
}()

func signalNumber(name string) int { return signalNumbers[name] }
