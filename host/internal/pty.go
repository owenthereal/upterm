package internal

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
)

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

// ExitError reports that a PTY's process exited with a non-zero status.
//
// Unix gets this for free from exec.Cmd.Wait, which returns *exec.ExitError.
// Windows waits on a process handle rather than an exec.Cmd, so it has no
// such error to return and needs this to carry the code instead of burying it
// in a message string.
type ExitError struct {
	// Code is the status GetExitCodeProcess reported, kept unsigned because
	// that is what Windows produces and what SSH puts on the wire. On a
	// 32-bit build, narrowing it to int would make every status with the high
	// bit set negative -- an unhandled exception such as 0xC0000005, or a
	// deliberate "exit -1" -- and exitCode would then read it as a process
	// that never exited under its own control.
	Code uint32
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit status %d", e.Code)
}

// exitCode reports the status a PTY's process exited with, given the error
// from Wait. The second return is false when the process did not exit under
// its own control: exec reports -1 for a process stopped by a signal, which is
// what happens when the session is torn down and the pty is closed underneath
// a still-running command. A caller reporting an exit status to an SSH client
// must not pass that on, because the status is marshalled as a uint32.
//
// That -1 check belongs to exec alone. Windows has no signals to report here,
// so every ExitError carries a real status, and the int it is returned as is
// only a courier: ssh.Session.Exit converts back to uint32, so a status that
// does not fit a 32-bit int arrives intact anyway.
func exitCode(err error) (int, bool) {
	if err == nil {
		return 0, true
	}

	var (
		execErr *exec.ExitError
		ptyErr  *ExitError
	)
	switch {
	case errors.As(err, &execErr):
		code := execErr.ExitCode()
		return code, code >= 0
	case errors.As(err, &ptyErr):
		return int(ptyErr.Code), true
	}

	return 0, false
}
