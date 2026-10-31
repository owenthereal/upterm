//go:build windows

package internal

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	gssh "charm.land/ssh"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestGuestProcessWindowsHelper(t *testing.T) {
	if os.Getenv("UPTERM_GUEST_PROCESS_HELPER") != "1" {
		return
	}
	if os.Getenv("UPTERM_GUEST_PROCESS_PTY") == "1" {
		fmt.Printf("PTYTERM=%s TTY=%s", os.Getenv("TERM"), os.Getenv("SSH_TTY"))
		os.Exit(7)
	}
	if os.Getenv("UPTERM_GUEST_PROCESS_LEADER") == "1" {
		_, _ = io.ReadFull(os.Stdin, make([]byte, 3))
		child := exec.Command(os.Args[0], "-test.run=^TestGuestProcessWindowsHelper$")
		child.Env = append(os.Environ(), "UPTERM_GUEST_PROCESS_LEADER=0", "UPTERM_GUEST_PROCESS_WAIT=1", "UPTERM_GUEST_PROCESS_QUIET=1")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			panic(err)
		}
		fmt.Printf("%d\nTAIL", child.Process.Pid)
		os.Exit(7)
	}
	if os.Getenv("UPTERM_GUEST_PROCESS_BIG") == "1" {
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), 4<<20))
		os.Exit(7)
	}
	if os.Getenv("UPTERM_GUEST_PROCESS_WAIT") == "1" {
		if os.Getenv("UPTERM_GUEST_PROCESS_QUIET") != "1" {
			fmt.Print("READY")
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	_, _ = os.Stdout.Write([]byte{'a', 0, '\n', 0xff})
	_, _ = io.WriteString(os.Stderr, "error\n")
	os.Exit(7)
}

type guestWindowsSession struct {
	gssh.Session
	ctx         guestWindowsContext
	in          io.Reader
	out         io.Writer
	stderr      bytes.Buffer
	pty         bool
	closeOutput func()
}
type guestWindowsContext struct {
	fakeGuestContext
	context.Context
}

func (c guestWindowsContext) Done() <-chan struct{}        { return c.Context.Done() }
func (c guestWindowsContext) Err() error                   { return c.Context.Err() }
func (c guestWindowsContext) Value(k any) any              { return c.Context.Value(k) }
func (c guestWindowsContext) Deadline() (time.Time, bool)  { return c.Context.Deadline() }
func (s *guestWindowsSession) Read(p []byte) (int, error)  { return s.in.Read(p) }
func (s *guestWindowsSession) Write(p []byte) (int, error) { return s.out.Write(p) }
func (s *guestWindowsSession) Stderr() io.ReadWriter       { return &s.stderr }
func (s *guestWindowsSession) Context() gssh.Context       { return s.ctx }
func (s *guestWindowsSession) Pty() (gssh.Pty, <-chan gssh.Window, bool) {
	return gssh.Pty{Term: "guest-term", Window: gssh.Window{Width: 97, Height: 31}}, nil, s.pty
}
func (s *guestWindowsSession) Signals(chan<- gssh.Signal) {}
func (s *guestWindowsSession) Close() error {
	if s.closeOutput != nil {
		s.closeOutput()
	}
	return nil
}

func TestGuestProcessPipes(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var output bytes.Buffer
	s := &guestWindowsSession{ctx: guestWindowsContext{Context: ctx}, in: bytes.NewReader([]byte("input")), out: &output}
	spec := guestProcessSpec{Argv: []string{os.Args[0], "-test.run=^TestGuestProcessWindowsHelper$"}, Env: append(os.Environ(), "UPTERM_GUEST_PROCESS_HELPER=1")}
	h := &sessionHandler{logger: discardLogger()}
	code, err := h.runGuestProcess(ctx, s, spec)
	require.NoError(t, err)
	require.Equal(t, 7, code)
	require.Equal(t, []byte{'a', 0, '\n', 0xff}, output.Bytes())
	require.Equal(t, "error\n", s.stderr.String())
}

func TestGuestProcessWindowsJob(t *testing.T) {
	command := func() *exec.Cmd {
		c := exec.Command(os.Args[0], "-test.run=^TestGuestProcessWindowsHelper$")
		c.Env = append(os.Environ(), "UPTERM_GUEST_PROCESS_HELPER=1", "UPTERM_GUEST_PROCESS_WAIT=1")
		return c
	}
	t.Run("retained job closes and reaps", func(t *testing.T) {
		c := command()
		var job syscall.Handle
		release, err := startGuestPipeCommandWithJob(c, func(process syscall.Handle) (syscall.Handle, error) {
			var err error
			job, err = createJobObject(process)
			return job, err
		})
		require.NoError(t, err)
		t.Cleanup(func() { release(); _ = c.Process.Kill(); _ = c.Wait() })
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(c.Process.Pid))
		require.NoError(t, err)
		defer windows.CloseHandle(handle)
		release()
		release()
		var duplicate windows.Handle
		err = windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(job), windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS)
		if err == nil {
			_ = windows.CloseHandle(duplicate)
		}
		require.ErrorIs(t, err, windows.ERROR_INVALID_HANDLE, "retained job handle must close")
		result, err := windows.WaitForSingleObject(handle, 2000)
		require.NoError(t, err)
		require.Equal(t, uint32(windows.WAIT_OBJECT_0), result)
		// Closing the job ended a process that waits forever. The status it
		// ended with is Windows' choice -- a kill-on-close job's processes have
		// reported 0 -- so what is asserted is that Wait then reaps it.
		_ = c.Wait()
		require.NotNil(t, c.ProcessState, "the process the job ended must be reaped")
	})
	t.Run("assignment failure reaps child", func(t *testing.T) {
		c := command()
		release, err := startGuestPipeCommandWithJob(c, func(syscall.Handle) (syscall.Handle, error) { return 0, errors.New("assignment denied") })
		require.ErrorContains(t, err, "assignment denied")
		require.Nil(t, release)
		require.NotNil(t, c.ProcessState, "failed startup must reap its owned child")
	})
}

func guestWindowsSpec(extra ...string) guestProcessSpec {
	return guestProcessSpec{Argv: []string{os.Args[0], "-test.run=^TestGuestProcessWindowsHelper$"}, Env: append(append(os.Environ(), "UPTERM_GUEST_PROCESS_HELPER=1"), extra...)}
}
func TestGuestProcessPTY(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var output bytes.Buffer
	session := &guestWindowsSession{ctx: guestWindowsContext{Context: ctx}, in: strings.NewReader(""), out: &output, pty: true}
	spec := guestWindowsSpec("UPTERM_GUEST_PROCESS_PTY=1", "SSH_TTY=stale")
	spec.ReadOnly = true
	code, err := (&sessionHandler{logger: discardLogger()}).runGuestProcess(ctx, session, spec)
	require.NoError(t, err)
	require.Equal(t, 7, code)
	require.Contains(t, output.String(), "PTYTERM=guest-term TTY=")
	require.NotContains(t, output.String(), "stale")
}

func TestGuestProcessShutdown(t *testing.T) {
	for _, pty := range []bool{false, true} {
		t.Run(fmt.Sprintf("blocked stdin pty=%v", pty), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			output, writer := io.Pipe()
			defer output.Close()
			defer writer.Close()
			session := &guestWindowsSession{ctx: guestWindowsContext{Context: ctx}, in: bytes.NewReader(bytes.Repeat([]byte("x"), 8<<20)), out: writer, pty: pty, closeOutput: func() { _ = writer.Close() }}
			done := make(chan error, 1)
			go func() {
				code, err := (&sessionHandler{logger: discardLogger()}).runGuestProcess(ctx, session, guestWindowsSpec("UPTERM_GUEST_PROCESS_WAIT=1"))
				if code == 0 {
					err = errors.New("canceled child returned zero")
				}
				done <- err
			}()
			// ConPTY may prepend terminal sequences, so scan the stream for readiness.
			ready := make(chan error, 1)
			go func() {
				reader := bufio.NewReader(output)
				var text string
				for !strings.Contains(text, "READY") {
					b, err := reader.ReadByte()
					if err != nil {
						ready <- err
						return
					}
					text += string(b)
				}
				ready <- nil
			}()
			select {
			case err := <-ready:
				require.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("child readiness timed out")
			}
			cancel()
			select {
			case err := <-done:
				require.Error(t, err)
			case <-time.After(8 * time.Second):
				t.Fatal("canceled process did not return")
			}
		})
	}
}

func TestGuestProcessLeaderExit(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	output, writer := io.Pipe()
	defer output.Close()
	defer writer.Close()
	session := &guestWindowsSession{ctx: guestWindowsContext{Context: ctx}, in: strings.NewReader("go\n"), out: writer, closeOutput: func() { _ = writer.Close() }}
	done := make(chan error, 1)
	go func() {
		code, err := (&sessionHandler{logger: discardLogger()}).runGuestProcess(ctx, session, guestWindowsSpec("UPTERM_GUEST_PROCESS_LEADER=1"))
		if code != 7 {
			err = fmt.Errorf("status %d: %w", code, err)
		}
		done <- err
	}()
	reader := bufio.NewReader(output)
	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	require.NoError(t, err)
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
	require.NoError(t, err)
	defer windows.CloseHandle(handle)
	defer windows.TerminateProcess(handle, 1) // test owns this exact retained handle
	tail := make([]byte, 4)
	_, err = io.ReadFull(reader, tail)
	require.NoError(t, err)
	require.Equal(t, "TAIL", string(tail))
	start := time.Now()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("descendant kept runner open")
	}
	require.LessOrEqual(t, time.Since(start), forceCommandDrainTimeout+2*time.Second)
	result, err := windows.WaitForSingleObject(handle, 2000)
	require.NoError(t, err)
	require.Equal(t, uint32(windows.WAIT_OBJECT_0), result)
}

func TestGuestProcessExitDuringEscalation(t *testing.T) {
	fake := newSignalPTY(0)
	fake.unsupported = true
	owner := &guestProcessOwner{PTY: fake}
	reaped := make(chan struct{})
	go func() { _ = owner.Wait(); close(reaped) }()
	terminateWith(owner, newPTYCloser(owner), reaped, time.Millisecond, time.Millisecond, discardLogger(), "guest")
	<-reaped
	require.True(t, fake.killed)
	require.ErrorIs(t, owner.Signal(syscall.SIGTERM), os.ErrProcessDone)
}

// A slow output sink is released only by channel Close, just like SSH window
// backpressure; this tests the runner's bounded writer-release path.
func TestGuestProcessUnreadOutput(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sink := &guestWindowsBlockedWriter{started: make(chan struct{}), closed: make(chan struct{})}
	session := &guestWindowsSession{ctx: guestWindowsContext{Context: ctx}, in: strings.NewReader(""), out: sink, closeOutput: func() { sink.closeOnce.Do(func() { close(sink.closed) }) }}
	defer session.Close()
	done := make(chan error, 1)
	go func() {
		_, err := (&sessionHandler{logger: discardLogger()}).runGuestProcess(ctx, session, guestWindowsSpec("UPTERM_GUEST_PROCESS_BIG=1"))
		done <- err
	}()
	select {
	case <-sink.started:
	case <-time.After(5 * time.Second):
		t.Fatal("child output never reached sink")
	}
	cancel()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(8 * time.Second):
		t.Fatal("unread output held shutdown")
	}
}

type guestWindowsBlockedWriter struct {
	started, closed chan struct{}
	once, closeOnce sync.Once
}

func (w *guestWindowsBlockedWriter) Write([]byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.closed
	return 0, io.ErrClosedPipe
}
