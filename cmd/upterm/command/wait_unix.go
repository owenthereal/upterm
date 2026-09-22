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
// lockstep with the names it records. A compatibility alias below covers the
// one Unix spelling that differs across platforms.
var signalNumbers = func() map[string]int {
	m := map[string]int{}
	for _, s := range []syscall.Signal{
		syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT,
		syscall.SIGABRT, syscall.SIGKILL, syscall.SIGSEGV,
		syscall.SIGPIPE, syscall.SIGALRM, syscall.SIGTERM,
	} {
		m[s.String()] = int(s)
	}
	// Linux records SIGABRT as "aborted", while Darwin calls it "abort trap".
	// A retained record may be read on a different Unix platform, so accept the
	// literal persisted form as well as the current runtime's spelling.
	m["aborted"] = int(syscall.SIGABRT)
	return m
}()

func signalNumber(name string) int { return signalNumbers[name] }
