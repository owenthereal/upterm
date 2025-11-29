//go:build windows

package internal

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/charmbracelet/x/conpty"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

// Windows API proc handles (cached to avoid repeated lazy DLL loading)
var (
	modkernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procSetInformationJobObject = modkernel32.NewProc("SetInformationJobObject")
)

// startPty starts a PTY for the given command on Windows using ConPTY
func startPty(c *exec.Cmd, stdin *os.File) (PTY, error) {
	// Get the actual terminal size from stdin if available
	// Otherwise, use default dimensions
	height := conpty.DefaultHeight
	width := conpty.DefaultWidth

	if stdin != nil {
		// Try to get the terminal size from stdin
		h, w, err := getPtysize(stdin)
		if err == nil && w > 0 && h > 0 {
			width = w
			height = h
		}
		// If GetSize fails or returns invalid dimensions, we'll use the defaults
	}

	// conpty.New expects (width, height, flags)
	cpty, err := conpty.New(width, height, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create conpty: %w", err)
	}

	// Spawn the process with process attributes from the command
	pid, handle, err := cpty.Spawn(c.Path, c.Args, &syscall.ProcAttr{
		Dir: c.Dir,
		Env: c.Env,
		Sys: c.SysProcAttr,
	})
	if err != nil {
		cpty.Close()
		return nil, fmt.Errorf("failed to spawn process: %w", err)
	}

	// Create a job object to ensure child processes are killed when upterm exits
	// This provides parity with Unix behavior where closing terminal kills all processes
	job, err := createJobObject(syscall.Handle(handle))
	if err != nil {
		syscall.TerminateProcess(syscall.Handle(handle), 1)
		syscall.CloseHandle(syscall.Handle(handle))
		cpty.Close()
		return nil, fmt.Errorf("failed to create job object: %w", err)
	}

	return &pty{
		cpty:   cpty,
		handle: handle,
		pid:    pid,
		job:    job,
	}, nil
}

// Pty is a wrapper of the ConPTY that provides a read/write mutex.
type pty struct {
	cpty                *conpty.ConPty
	handle              uintptr
	pid                 int
	job                 syscall.Handle // Job object handle
	conptyClosed        bool           // Tracks if ConPTY I/O has been closed
	processHandleClosed bool           // Tracks if process handle has been closed
	sync.RWMutex
}

func (p *pty) Setsize(h, w int) error {
	p.RLock()
	defer p.RUnlock()

	if p.conptyClosed || p.cpty == nil {
		return nil // Silently ignore resize on closed pty
	}

	return p.cpty.Resize(w, h)
}

func (p *pty) Read(data []byte) (n int, err error) {
	p.RLock()
	conptyClosed := p.conptyClosed
	cpty := p.cpty
	p.RUnlock()

	if conptyClosed || cpty == nil {
		return 0, io.EOF
	}

	return cpty.Read(data)
}

func (p *pty) Write(data []byte) (n int, err error) {
	p.RLock()
	conptyClosed := p.conptyClosed
	cpty := p.cpty
	p.RUnlock()

	if conptyClosed || cpty == nil {
		return 0, io.ErrClosedPipe
	}

	return cpty.Write(data)
}

func (p *pty) Close() error {
	p.Lock()
	defer p.Unlock()

	if p.conptyClosed {
		return nil
	}

	p.conptyClosed = true // Mark as closed immediately so Read/Write return EOF

	// Close job object first - this will terminate all processes in the job
	if p.job != 0 {
		syscall.CloseHandle(p.job)
		p.job = 0
	}

	var err error
	if p.cpty != nil {
		err = p.cpty.Close()
		p.cpty = nil
	}
	return err
}

// getPtysize gets the terminal size from a file descriptor on Windows
func getPtysize(f *os.File) (h, w int, err error) {
	w, h, err = term.GetSize(int(f.Fd()))
	return h, w, err
}

// Windows doesn't return EIO like Linux, so this is a no-op
func ptyError(err error) error {
	return err
}

// Wait waits for the process to exit on Windows
func (p *pty) Wait() error {
	p.Lock()
	handle := p.handle
	processHandleClosed := p.processHandleClosed
	p.Unlock()

	if handle == 0 {
		return fmt.Errorf("no process handle")
	}
	if processHandleClosed {
		return fmt.Errorf("process handle already closed")
	}

	// Close the process handle when done, regardless of error paths
	defer func() {
		p.Lock()
		if !p.processHandleClosed {
			syscall.CloseHandle(syscall.Handle(p.handle))
			p.processHandleClosed = true
		}
		p.Unlock()
	}()

	// Wait for the process to exit
	s, err := syscall.WaitForSingleObject(syscall.Handle(handle), syscall.INFINITE)
	if err != nil {
		return fmt.Errorf("WaitForSingleObject failed: %w", err)
	}
	if s != 0 {
		return fmt.Errorf("WaitForSingleObject returned %d", s)
	}

	// Get exit code
	var exitCode uint32
	if err := syscall.GetExitCodeProcess(syscall.Handle(handle), &exitCode); err != nil {
		return fmt.Errorf("GetExitCodeProcess failed: %w", err)
	}

	// Don't close ConPTY here - let the run.Group interrupt handler do it
	// This ensures proper shutdown order

	if exitCode != 0 {
		return fmt.Errorf("exit status %d", exitCode)
	}

	return nil
}

// Kill terminates the process on Windows
func (p *pty) Kill() error {
	p.RLock()
	handle := p.handle
	processHandleClosed := p.processHandleClosed
	p.RUnlock()

	if handle == 0 {
		return nil
	}
	if processHandleClosed {
		// Process already exited and handle closed, nothing to kill
		return nil
	}

	// Terminate the process
	err := syscall.TerminateProcess(syscall.Handle(handle), 1)
	if err != nil {
		return fmt.Errorf("TerminateProcess failed: %w", err)
	}

	return nil
}

// Windows job object structures and constants
const (
	JobObjectExtendedLimitInformation  = 9
	JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
)

type JOBOBJECT_BASIC_LIMIT_INFORMATION struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type IO_COUNTERS struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type JOBOBJECT_EXTENDED_LIMIT_INFORMATION struct {
	BasicLimitInformation JOBOBJECT_BASIC_LIMIT_INFORMATION
	IoInfo                IO_COUNTERS
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// createJobObject creates a job object and assigns the process to it
// The job object is configured with KILL_ON_JOB_CLOSE, ensuring all processes
// in the job are terminated when the job handle is closed.
func createJobObject(processHandle syscall.Handle) (syscall.Handle, error) {
	// Create an unnamed job object
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject failed: %w", err)
	}

	// Configure the job to kill all processes when the job handle is closed
	var info JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

	// SetInformationJobObject
	ret, _, err := procSetInformationJobObject.Call(
		uintptr(job),
		uintptr(JobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Sizeof(info)),
	)
	if ret == 0 {
		windows.CloseHandle(job)
		if err != nil {
			return 0, fmt.Errorf("SetInformationJobObject failed: %w", err)
		}
		return 0, fmt.Errorf("SetInformationJobObject failed")
	}

	// Assign the process to the job object
	// Convert syscall.Handle to windows.Handle
	err = windows.AssignProcessToJobObject(job, windows.Handle(processHandle))
	if err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("AssignProcessToJobObject failed: %w", err)
	}

	// Convert windows.Handle back to syscall.Handle for return
	return syscall.Handle(job), nil
}
