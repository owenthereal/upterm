//go:build windows

package command

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/sessiondir"
	"golang.org/x/sys/windows"
)

const (
	// daemonSocketEnv names the AF_UNIX socket the daemon calls back on. Its
	// presence is what makes a process the daemon, as UPTERM_DAEMON_FD is on
	// Unix: Windows inherits no descriptor, so the channel is a connection
	// the child makes rather than one it is handed.
	daemonSocketEnv = "UPTERM_DAEMON_SOCKET"
	// daemonNonceEnv is what the child proves itself with. The socket's
	// directory is already the current user's alone, so this is the second
	// lock rather than the first: it says the connection came from the
	// process this parent started, not from another of the user's own.
	daemonNonceEnv = "UPTERM_DAEMON_NONCE"
	// daemonNameEnv is the session name the daemon claims: the parent draws
	// it, and redraws it when the daemon reports it taken.
	daemonNameEnv = "UPTERM_DAEMON_NAME"
)

// spawnSupported says whether this platform can run the daemon in a child
// of its own. Where it cannot, upterm host runs the daemon in-process.
const spawnSupported = true

// bootstrapTimeout bounds both halves of the callback: the wait for a
// connection, and the wait for the hello on it. Neither covers more than a
// process creation, a dial and twenty bytes — everything the daemon does that
// can be slow, resolving keys and dialling the relay, happens after the hello
// and is bounded by the exchange's own gates rather than by this.
const bootstrapTimeout = 10 * time.Second

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
// The child is this executable with the same arguments, detached from this
// console (a window closing reaches nothing in it), with stdin from NUL and
// stdout and stderr appended to the log — anything it prints outside its
// logger, a panic above all, has to land somewhere a person can find.
//
// The channel is an AF_UNIX socket rather than the socketpair Unix inherits,
// because Windows has neither socketpair nor ExtraFiles. That difference is
// the whole of this file: a listener has to be bound somewhere, and anything
// that can open the path can connect to it. So the path is a temp directory
// given a DACL naming this user alone, and the first thing the child sends
// is a nonce only its environment carries. One connection is accepted, the
// listener closes, and the directory is gone before this returns — the door
// exists for as long as it takes one child to walk through it.
//
// The property the rest of stage 3 reads is unchanged: the child's next read
// fails the moment the parent's end is gone, whichever way it went. Go opens
// sockets here with WSA_FLAG_NO_HANDLE_INHERIT and os/exec passes only the
// three standard handles, so the child provably holds no copy of the parent's
// end — the Windows analogue of the close-on-exec flag the Unix side sets.
// Whether that read fails as EOF or as a reset is Winsock's to choose;
// bootstrap.Child treats either as the parent leaving, which is why the
// Windows test asserts the failure and not its shape.
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

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, nil, fmt.Errorf("bootstrap nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	dir, err := os.MkdirTemp("", "upterm-launch")
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrap directory: %w", err)
	}
	// Removed on every path out, including the one that succeeds: the
	// connection outlives the path it was made through.
	//
	// The error is dropped because there is nothing here to report it
	// through — spawnDaemon has no logger, and a session that started is not
	// worth failing over a temp directory. What would go unnoticed is a
	// removal that fails every time, leaving one boot.sock per invocation
	// under %TMP%; spawn_windows_test.go asserts the directory is gone, so
	// that would be caught in CI rather than in the field.
	removeDir := func() { _ = os.RemoveAll(dir) }
	if err := sessiondir.SecureDir(dir); err != nil {
		removeDir()
		return nil, nil, err
	}
	socket := filepath.Join(dir, "boot.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		removeDir()
		return nil, nil, fmt.Errorf("bootstrap channel: %w", err)
	}
	listening := true
	closeListener := func() {
		if listening {
			listening = false
			_ = ln.Close()
		}
	}
	defer func() {
		closeListener()
		removeDir()
	}()

	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = devnull.Close() }()
	logFile, err := os.OpenFile(opts.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, nil, fmt.Errorf("open log: %w", err)
	}
	defer func() { _ = logFile.Close() }()

	// Built twice on the breakaway retry, because an exec.Cmd is not
	// restartable. The files are passed as *os.File and so are the caller's
	// to close, not exec's: handing the same three to a second Cmd is safe.
	newCmd := func(flags uint32) *exec.Cmd {
		cmd := exec.Command(executable, args...)
		cmd.Env = append(append([]string{}, env...),
			daemonSocketEnv+"="+socket,
			daemonNonceEnv+"="+nonce,
			daemonNameEnv+"="+opts.name)
		cmd.Stdin = devnull
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags}
		return cmd
	}

	// DETACHED_PROCESS is the Setsid of this platform: no console, so closing
	// the one this process is attached to sends the daemon no control event.
	// CREATE_NEW_PROCESS_GROUP keeps a ^C typed at that console from reaching
	// it either.
	//
	// CREATE_BREAKAWAY_FROM_JOB is best effort and never promised. A job
	// object whose limits forbid breakaway answers ERROR_ACCESS_DENIED, and
	// the only thing to do about it is to start inside the job: CI runners
	// and some terminals put every child in one, and a daemon that shares the
	// parent's job dies when the job does. That is a worse daemon, not a
	// failed spawn.
	const detached = windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS
	cmd := newCmd(detached | windows.CREATE_BREAKAWAY_FROM_JOB)
	if err := cmd.Start(); err != nil {
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, nil, fmt.Errorf("start daemon: %w", err)
		}
		cmd = newCmd(detached)
		if err := cmd.Start(); err != nil {
			return nil, nil, fmt.Errorf("start daemon: %w", err)
		}
	}
	// Waited on so the process handle is released whenever it exits, as the
	// Unix side reaps for the same reason. Never waited on otherwise: the
	// daemon is meant to outlive this process.
	go func() { _ = cmd.Wait() }()
	// A child that never calls back, or calls back as somebody else, is a
	// daemon nobody is going to talk to: it would claim a name and run the
	// command with no parent to answer its prompts.
	kill := func() { _ = cmd.Process.Kill() }

	if err := ln.SetDeadline(time.Now().Add(bootstrapTimeout)); err != nil {
		kill()
		return nil, nil, fmt.Errorf("bootstrap channel: %w", err)
	}
	conn, err := ln.Accept()
	if err != nil {
		kill()
		return nil, nil, fmt.Errorf("the session daemon did not call back: %w", err)
	}
	// Nothing else is coming through this door, and the child is already
	// connected: the path can go now, and a second caller finds nothing.
	// Before the nonce is checked, deliberately, so that a connection that
	// fails it cannot leave the door open behind it.
	//
	// One accept and no more means a process that wins the connect race
	// fails this spawn rather than being let in. Only another process of
	// this user can try — that is what the DACL is for — and one of those
	// can do worse things than deny a session, so the loud failure is the
	// trade taken here rather than looping until the deadline.
	closeListener()
	removeDir()

	// A hello the child never sends would otherwise park this forever; the
	// deadline is dropped again before the connection is handed on, because
	// from here the exchange has its own gates.
	if err := conn.SetReadDeadline(time.Now().Add(bootstrapTimeout)); err != nil {
		_ = conn.Close()
		kill()
		return nil, nil, fmt.Errorf("bootstrap hello: %w", err)
	}
	if err := checkHelloNonce(conn, nonce); err != nil {
		_ = conn.Close()
		kill()
		return nil, nil, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		kill()
		return nil, nil, fmt.Errorf("bootstrap hello: %w", err)
	}
	return conn, cmd.Process, nil
}

// bootstrapConn returns the channel this process was started to connect on,
// and the name it was given, or nil when this process was not started as a
// daemon.
//
// The variables are unset before anything else can read them: the hosted
// command's environment is os.Environ(), and a shell started by the daemon
// must not believe it is one — nor be handed a nonce, even a spent one.
func bootstrapConn() (net.Conn, string, error) {
	socket, ok := os.LookupEnv(daemonSocketEnv)
	if !ok {
		return nil, "", nil
	}
	nonce := os.Getenv(daemonNonceEnv)
	name := os.Getenv(daemonNameEnv)
	_ = os.Unsetenv(daemonSocketEnv)
	_ = os.Unsetenv(daemonNonceEnv)
	_ = os.Unsetenv(daemonNameEnv)
	if socket == "" || nonce == "" {
		return nil, "", fmt.Errorf("%s and %s must both be set to start as a daemon", daemonSocketEnv, daemonNonceEnv)
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, "", fmt.Errorf("bootstrap channel on %s: %w", socket, err)
	}
	hello := &api.Startup{Msg: &api.Startup_Hello{Hello: &api.Hello{Nonce: nonce}}}
	if err := bootstrap.NewConn(conn).Send(hello); err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("bootstrap hello: %w", err)
	}
	return conn, name, nil
}
