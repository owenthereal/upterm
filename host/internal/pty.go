package internal

import "io"

// PTY represents a pseudo-terminal abstraction that works across platforms.
// On Unix, it wraps a traditional PTY created via creack/pty.
// On Windows, it wraps a ConPTY (Console Pseudo Terminal).
//
// The interface provides a common abstraction for:
//   - Reading/writing terminal I/O (via io.ReadWriteCloser)
//   - Resizing the terminal window
//   - Managing process lifecycle (Wait/Kill)
//
// Platform-specific implementations:
//   - Unix: see pty_unix.go
//   - Windows: see pty_windows.go
type PTY interface {
	io.ReadWriteCloser

	// Setsize changes the terminal dimensions.
	// On Unix, this sends a SIGWINCH to the slave process.
	// On Windows, this resizes the ConPTY buffer.
	Setsize(h, w int) error

	// Wait waits for the process associated with this PTY to exit.
	// On Unix, this delegates to exec.Cmd.Wait().
	// On Windows, this waits on the process handle.
	Wait() error

	// Kill terminates the process associated with this PTY.
	// On Unix, this delegates to exec.Cmd.Process.Kill().
	// On Windows, this calls TerminateProcess on the handle.
	Kill() error
}
