//go:build !windows

package command

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// daemonFDEnv names the descriptor the daemon inherits its bootstrap
	// channel on. Its presence is what makes a process the daemon.
	daemonFDEnv = "UPTERM_DAEMON_FD"
	// daemonNameEnv is the session name the daemon claims: the parent draws
	// it, and redraws it when the daemon reports it taken.
	daemonNameEnv = "UPTERM_DAEMON_NAME"
)

// spawnOptions describes the child. executable, args and env default to
// this process's own.
type spawnOptions struct {
	executable string
	args       []string
	env        []string
	name       string
	logPath    string
}

// spawnDaemon starts the daemon and returns the parent's end of the
// bootstrap channel.
//
// The child is this executable with the same arguments, in a session of its
// own (Setsid: a terminal hangup reaches nothing in it), with stdin from
// /dev/null and stdout and stderr appended to the log — anything it prints
// outside its logger, a panic above all, has to land somewhere a person can
// find. The channel is a socketpair rather than a pipe because both sides
// write, and because the child sees EOF the moment the parent's end is
// gone, whichever way it went.
//
// Both ends are marked close-on-exec before the fork. ExtraFiles clears the
// flag on the child's copy of its own end, and nothing else; the parent's
// end would otherwise be inherited too, and a child holding a copy of the
// end it reads EOF from would never read it.
func spawnDaemon(opts spawnOptions) (net.Conn, *os.Process, error) {
	if opts.name == "" || opts.logPath == "" {
		return nil, nil, errors.New("spawnDaemon: a name and a log path are required")
	}
	executable := opts.executable
	if executable == "" {
		var err error
		if executable, err = os.Executable(); err != nil {
			return nil, nil, err
		}
	}
	args := opts.args
	if args == nil {
		args = os.Args[1:]
	}
	env := opts.env
	if env == nil {
		env = os.Environ()
	}

	// Under the fork lock, as os.Pipe does on the platforms without an atomic
	// SOCK_CLOEXEC. fds[1]'s flag is load-bearing: without it, a child
	// inherits a second copy of its own end at this raw fd number, on top
	// of the dup ExtraFiles gives it at fd 3 — and since bootstrapConn only
	// marks fd 3 close-on-exec, the hosted command would inherit that
	// stray copy in turn. fds[0]'s flag is belt and braces: parentFile,
	// the only handle on that end, is closed below before Start forks, so
	// it only matters if some other goroutine forks between here and
	// there.
	syscall.ForkLock.RLock()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err == nil {
		unix.CloseOnExec(fds[0])
		unix.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}
	parentFile := os.NewFile(uintptr(fds[0]), "bootstrap-parent")
	childFile := os.NewFile(uintptr(fds[1]), "bootstrap-child")
	defer func() { _ = childFile.Close() }()

	conn, err := net.FileConn(parentFile)
	_ = parentFile.Close() // FileConn duplicated it
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrap channel: %w", err)
	}

	devnull, err := os.Open(os.DevNull)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	defer func() { _ = devnull.Close() }()
	logFile, err := os.OpenFile(opts.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("open log: %w", err)
	}
	defer func() { _ = logFile.Close() }()

	cmd := exec.Command(executable, args...)
	cmd.Env = append(append([]string{}, env...),
		daemonFDEnv+"="+strconv.Itoa(3), // ExtraFiles[0]
		daemonNameEnv+"="+opts.name)
	cmd.Stdin = devnull
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.ExtraFiles = []*os.File{childFile}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("start daemon: %w", err)
	}
	// Reaped whenever it exits, so a daemon that ends first is not a zombie
	// for the life of a foreground parent. Never waited on otherwise: the
	// daemon is meant to outlive this process.
	go func() { _ = cmd.Wait() }()
	return conn, cmd.Process, nil
}

// bootstrapConn returns the channel this process inherited, and the name it
// was given, or nil when this process was not started as a daemon.
//
// The variables are unset before anything else can read them: the hosted
// command's environment is os.Environ(), and a shell started by the daemon
// must not believe it is one. The descriptor is marked close-on-exec for the
// same reason — ExtraFiles cleared the flag, and the command must not
// inherit the parent's channel.
func bootstrapConn() (net.Conn, string, error) {
	v, ok := os.LookupEnv(daemonFDEnv)
	if !ok {
		return nil, "", nil
	}
	name := os.Getenv(daemonNameEnv)
	_ = os.Unsetenv(daemonFDEnv)
	_ = os.Unsetenv(daemonNameEnv)
	fd, err := strconv.Atoi(v)
	if err != nil || fd < 0 {
		return nil, "", fmt.Errorf("%s=%q is not a descriptor", daemonFDEnv, v)
	}
	unix.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), "bootstrap")
	conn, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return nil, "", fmt.Errorf("bootstrap channel on fd %d: %w", fd, err)
	}
	return conn, name, nil
}
