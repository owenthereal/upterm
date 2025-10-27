//go:build windows
// +build windows

package internal

import (
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"

	"github.com/charmbracelet/x/conpty"
)

// startPty starts a PTY for the given command on Windows using ConPTY
func startPty(c *exec.Cmd) (*pty, error) {
	// Create ConPTY with default size (80x30)
	cpty, err := conpty.New(80, 30, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create conpty: %w", err)
	}

	// Spawn the process
	pid, handle, err := cpty.Spawn(c.Path, c.Args, &syscall.ProcAttr{
		Dir: c.Dir,
		Env: c.Env,
		Sys: c.SysProcAttr,
	})
	if err != nil {
		cpty.Close()
		return nil, fmt.Errorf("failed to spawn process: %w", err)
	}

	return &pty{
		cpty:   cpty,
		handle: handle,
		pid:    pid,
	}, nil
}

// Pty is a wrapper of the ConPTY that provides a read/write mutex.
type pty struct {
	cpty   *conpty.ConPty
	handle uintptr
	pid    int
	closed bool
	sync.RWMutex
}

func (p *pty) Setsize(h, w int) error {
	p.RLock()
	defer p.RUnlock()

	if p.closed || p.cpty == nil {
		return nil // Silently ignore resize on closed pty
	}

	return p.cpty.Resize(w, h)
}

func (p *pty) Read(data []byte) (n int, err error) {
	p.RLock()
	closed := p.closed
	cpty := p.cpty
	p.RUnlock()

	if closed || cpty == nil {
		return 0, io.EOF
	}

	return cpty.Read(data)
}

func (p *pty) Write(data []byte) (n int, err error) {
	p.RLock()
	closed := p.closed
	cpty := p.cpty
	p.RUnlock()

	if closed || cpty == nil {
		return 0, io.ErrClosedPipe
	}

	return cpty.Write(data)
}

func (p *pty) Close() error {
	p.Lock()
	defer p.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true // Mark as closed immediately so Read/Write return EOF

	var err error
	if p.cpty != nil {
		err = p.cpty.Close()
		p.cpty = nil
	}
	return err
}

// Windows doesn't return EIO like Linux, so this is a no-op
func ptyError(err error) error {
	return err
}

// Wait waits for the process to exit on Windows
func (p *pty) Wait() error {
	if p.handle == 0 {
		return fmt.Errorf("no process handle")
	}

	// Wait for the process to exit
	s, err := syscall.WaitForSingleObject(syscall.Handle(p.handle), syscall.INFINITE)
	if err != nil {
		return fmt.Errorf("WaitForSingleObject failed: %w", err)
	}
	if s != 0 {
		return fmt.Errorf("WaitForSingleObject returned %d", s)
	}

	// Get exit code
	var exitCode uint32
	if err := syscall.GetExitCodeProcess(syscall.Handle(p.handle), &exitCode); err != nil {
		return fmt.Errorf("GetExitCodeProcess failed: %w", err)
	}

	// Close the process handle
	syscall.CloseHandle(syscall.Handle(p.handle))

	// Don't close ConPTY here - let the run.Group interrupt handler do it
	// This ensures proper shutdown order

	if exitCode != 0 {
		return fmt.Errorf("exit status %d", exitCode)
	}

	return nil
}

// Kill terminates the process on Windows
func (p *pty) Kill() error {
	if p.handle == 0 {
		return nil
	}

	// Terminate the process
	err := syscall.TerminateProcess(syscall.Handle(p.handle), 1)
	if err != nil {
		return fmt.Errorf("TerminateProcess failed: %w", err)
	}

	return nil
}

// waitForCommand waits for a command started via ConPTY to exit.
// On Windows, we use the PTY's Wait method since the command was spawned
// via ConPTY.Spawn() which bypasses Go's normal exec.Cmd.Start() flow.
func waitForCommand(cmd *exec.Cmd, ptmx *pty) error {
	return ptmx.Wait()
}
