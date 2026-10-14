//go:build windows

package internal

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/charmbracelet/x/conpty"
	"github.com/owenthereal/upterm/internal/termsize"
	"golang.org/x/sys/windows"
)

// Windows API proc handles (cached to avoid repeated lazy DLL loading)
var (
	modkernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procSetInformationJobObject = modkernel32.NewProc("SetInformationJobObject")
)

// startPty starts a PTY for the given command on Windows using ConPTY.
//
// r hears of the pty's size: once at start, before startPty returns, and for
// each Setsize that changes it; see sizeReporter. Nil reports nothing, as a
// forced command's pty does (startSessionPty).
func startPty(c *exec.Cmd, size termsize.Size, pinned bool, r sizeReporter) (PTY, error) {
	if !size.Valid() {
		size = termsize.Default
	}

	// conpty.New expects (width, height, flags)
	cpty, err := conpty.New(size.Cols, size.Rows, 0)
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

	p := &pty{
		cpty:   cpty,
		handle: handle,
		pid:    pid,
		job:    job,
		pinned: pinned,
		report: r,
	}
	p.lastH.Store(int32(size.Rows))
	p.lastW.Store(int32(size.Cols))
	reportStart(r, size, pinned)
	return p, nil
}

// startSessionPty is startPty for a command a guest runs on a pty of its own.
// The Unix one also sets SSH_TTY; a ConPTY has no device name to put in it, so
// here it is left unset rather than made up.
func startSessionPty(c *exec.Cmd, size termsize.Size) (PTY, error) {
	return startPty(c, size, false, nil)
}

// Pty is a wrapper of the ConPTY that provides a read/write mutex.
type pty struct {
	cpty                *conpty.ConPty
	handle              uintptr
	pid                 int
	job                 syscall.Handle // Job object handle
	conptyClosed        bool           // Tracks if ConPTY I/O has been closed
	processHandleClosed bool           // Tracks if process handle has been closed
	pinned              bool
	// report hears of each resize Setsize makes, in two steps; see startPty.
	// Nil reports nothing.
	report sizeReporter

	// lastH, lastW are the geometry the ConPTY was last set to. Windows has no
	// SIGWINCH, so Redraw nudges by resizing out and back, and it needs a size
	// to come back to; and Setsize compares a resize with it, to report only
	// a change. Atomic rather than guarded by the lock below, because
	// Setsize runs under the read lock, which does not exclude another Setsize.
	lastH, lastW atomic.Int32

	sync.RWMutex
}

func (p *pty) Setsize(h, w int) error {
	p.RLock()
	defer p.RUnlock()

	if p.conptyClosed || p.cpty == nil {
		return nil // Silently ignore resize on closed pty
	}

	// --pty-size promises the geometry will not move. Every resize in the
	// process funnels through here — the host's SIGWINCH handler and a guest's
	// window-change request both reach it via event.go — so this is the only
	// place the promise has to be kept. Reporting success is deliberate: a
	// client asking to resize a pinned session has done nothing wrong.
	if p.pinned {
		return nil
	}

	// conpty.Resize narrows each dimension to an int16, so a larger one would
	// wrap: clamped here instead, so that what is compared, reported and
	// recorded below is the size the ConPTY is actually asked for, which is
	// what the command is told and lays its output out at.
	h, w = min(h, math.MaxInt16), min(w, math.MaxInt16)

	report := p.report
	if report != nil && int(p.lastH.Load()) == h && int(p.lastW.Load()) == w {
		// A resize to the size the ConPTY has changes nothing, so there is
		// nothing to report: the fan-out takes every ResizeBegin for a real
		// change, and a same-size one would reset the region it is weighing.
		// The check and the resize are not one step, so Setsize calls must be
		// serialized, as their callers do: terminalWindows under its mu, and
		// sharedPTY's set under its own.
		report = nil
	}

	// Begun before the resize, not after it: a console program repaints on
	// the resize event, and a repaint that reached the fan-out ahead of the
	// report would count as drawn at the old size, and a joiner at the new
	// one would be replayed without it. See the Unix pty's Setsize.
	var seq uint64
	if report != nil {
		seq = report.ResizeBegin(termsize.Size{Cols: w, Rows: h})
	}
	err := p.cpty.Resize(w, h)
	if report != nil {
		// A failed resize is ended, not undone with a report of the old
		// size: the bytes that followed are the old size's, and the fan-out
		// drops the event.
		report.ResizeEnd(seq, err == nil)
	}
	if err != nil {
		return err
	}
	// Recorded only once the ConPTY is actually at this size: Redraw comes
	// back to what it finds here, and a size that failed to apply would make
	// the nudge a resize rather than a round-trip.
	p.lastH.Store(int32(h))
	p.lastW.Store(int32(w))
	return nil
}

// Redraw asks the console application to repaint. There is no SIGWINCH on
// Windows, so the nudge is a resize round-trip: one column wider, then back to
// the size it was. A pinned session gets no nudge at all — the promise that
// the geometry will not move is the stronger of the two.
//
// The write lock, not the read lock that guards a single Resize: the two calls
// below must land back to back, and under RLock a concurrent Setsize could run
// between them and be overwritten by the second.
func (p *pty) Redraw() error {
	p.Lock()
	defer p.Unlock()

	if p.conptyClosed || p.cpty == nil {
		return nil // Silently ignore a nudge on a closed pty
	}
	if p.pinned {
		return nil
	}

	h, w := int(p.lastH.Load()), int(p.lastW.Load())
	if h <= 0 || w <= 0 {
		return nil
	}
	// The ConPTY directly, not Setsize, and reported to no one: the round-trip
	// ends at the size it started from, so the size has not changed, and
	// ConPTY repaints at that final size rather than at the one column wider
	// it passes through. Reporting the intermediate size would only stamp a
	// repaint's bytes with a size the command ends up not having.
	if err := p.cpty.Resize(w+1, h); err != nil {
		return err
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
		return &ExitError{Code: exitCode}
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

// Signal is unsupported: ConPTY has no process groups to signal. The caller
// goes straight to Kill.
func (p *pty) Signal(syscall.Signal) error { return errors.ErrUnsupported }

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
