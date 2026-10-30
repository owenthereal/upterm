//go:build !windows

package internal

import (
	"os/exec"
	"syscall"

	gssh "charm.land/ssh"
	"golang.org/x/sys/unix"
)

func startGuestPipeCommand(cmd *exec.Cmd) (func(), error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() {}, nil
}
func (p *guestPipes) Signal(sig syscall.Signal) error { return unix.Kill(-p.cmd.Process.Pid, sig) }
func guestSignal(sig gssh.Signal) (syscall.Signal, bool) {
	switch sig {
	case "ABRT":
		return syscall.SIGABRT, true
	case "ALRM":
		return syscall.SIGALRM, true
	case "FPE":
		return syscall.SIGFPE, true
	case "HUP":
		return syscall.SIGHUP, true
	case "ILL":
		return syscall.SIGILL, true
	case "INT":
		return syscall.SIGINT, true
	case "KILL":
		return syscall.SIGKILL, true
	case "PIPE":
		return syscall.SIGPIPE, true
	case "QUIT":
		return syscall.SIGQUIT, true
	case "SEGV":
		return syscall.SIGSEGV, true
	case "TERM":
		return syscall.SIGTERM, true
	case "USR1":
		return syscall.SIGUSR1, true
	case "USR2":
		return syscall.SIGUSR2, true
	case "WINCH":
		return syscall.SIGWINCH, true
	}
	return 0, false
}
