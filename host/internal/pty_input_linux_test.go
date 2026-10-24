//go:build linux

package internal

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	ptylib "github.com/creack/pty"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// A subprocess also bounds the old blocking-descriptor failure: a kernel write
// on that path cannot be released even by killing and reaping its command.
func ptyTestProcess(t *testing.T) bool {
	t.Helper()
	if os.Getenv("UPTERM_PTY_TEST_PROCESS") == t.Name() {
		return true
	}
	exe, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(exe, "-test.v", "-test.timeout=10s", "-test.cpu="+fmt.Sprint(runtime.GOMAXPROCS(0)), "-test.run=^"+regexp.QuoteMeta(t.Name())+"$")
	cmd.Env = append(os.Environ(), "UPTERM_PTY_TEST_PROCESS="+t.Name())
	out, err := cmd.CombinedOutput()
	t.Logf("fixture process:\n%s", out)
	require.NoError(t, err, "PTY fixture process failed")
	return false
}

func parkedPTYRead(p PTY, done chan<- error) {
	_, err := p.Read(make([]byte, 1))
	done <- err
}

func parkedPTYWrite(p PTY, done chan<- error) {
	_, err := p.Write(bytes.Repeat([]byte("x"), 4<<20))
	done <- err
}

func ptyWorkerParked(name string) bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	for _, stack := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(stack, name+"(") &&
			(strings.Contains(stack, "internal/poll.runtime_pollWait(") ||
				strings.Contains(stack, "syscall.read(") || strings.Contains(stack, "syscall.write(")) {
			return true
		}
	}
	return false
}

func TestPTYCloseReleasesParkedIO(t *testing.T) {
	if !ptyTestProcess(t) {
		return
	}
	cmd := exec.Command("sh", "-c", "stty raw -echo; printf READY; exec sleep 60")
	p, err := startPty(cmd, termsize.Size{}, false, nil)
	require.NoError(t, err)
	var readDone, writeDone, closeDone chan error
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if closeDone == nil {
			closeDone = make(chan error, 1)
			go func() { closeDone <- p.Close() }()
		}
		for name, ch := range map[string]chan error{"read": readDone, "write": writeDone, "close": closeDone} {
			if ch == nil {
				continue
			}
			select {
			case err := <-ch:
				if err != nil {
					t.Logf("PTY %s cleanup completed with shutdown error: %v", name, err)
				}
			case <-time.After(100 * time.Millisecond):
				t.Errorf("cleanup could not release PTY %s", name)
			}
		}
	})
	ready := make([]byte, 5)
	_, err = io.ReadFull(p, ready)
	require.NoError(t, err)
	require.Equal(t, "READY", string(ready))
	readDone, writeDone = make(chan error, 1), make(chan error, 1)
	go parkedPTYRead(p, readDone)
	go parkedPTYWrite(p, writeDone)
	require.Eventually(t, func() bool { return ptyWorkerParked("parkedPTYRead") }, time.Second, time.Millisecond, "PTY read did not park")
	require.Eventually(t, func() bool { return ptyWorkerParked("parkedPTYWrite") }, time.Second, time.Millisecond, "PTY input queue did not fill and park the write")
	require.NoError(t, cmd.Process.Signal(syscall.Signal(0)), "the slave owner must be alive at close entry")
	closeDone = make(chan error, 1)
	go func() { closeDone <- p.Close() }()
	until := time.Now().Add(time.Second)
	for _, worker := range []struct {
		name string
		ch   chan error
	}{{"read", readDone}, {"write", writeDone}, {"close", closeDone}} {
		timer := time.NewTimer(time.Until(until))
		select {
		case err := <-worker.ch:
			worker.ch <- err // cleanup joins the same completion even after a Fatal
			if worker.name == "close" {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, os.ErrClosed)
			}
		case <-timer.C:
			t.Errorf("Close did not release parked PTY %s within 1s", worker.name)
		}
		timer.Stop()
	}
}

func TestPreparePTYMasterOwnsItsFiles(t *testing.T) {
	if !ptyTestProcess(t) {
		return
	}
	master, slave, err := ptylib.Open()
	require.NoError(t, err)
	defer func() { _ = slave.Close(); _ = master.Close() }()
	// Initial sizing uses Fd and leaves the original Go File blocking.
	require.NoError(t, ptylib.Setsize(master, &ptylib.Winsize{Rows: 24, Cols: 80}))
	prepared, err := preparePTYMaster(master)
	require.NoError(t, err)
	defer func() { _ = prepared.Close() }()
	_, err = master.Stat()
	require.ErrorIs(t, err, os.ErrClosed, "preparation must consume the original File")
	require.NoError(t, prepared.SetWriteDeadline(time.Now().Add(time.Second)), "prepared master must support poller deadlines")
	require.NoError(t, prepared.SetWriteDeadline(time.Time{}))
	rc, err := prepared.SyscallConn()
	require.NoError(t, err)
	var flags, fdflags int
	var ferr error
	require.NoError(t, rc.Control(func(fd uintptr) {
		flags, ferr = unix.FcntlInt(fd, unix.F_GETFL, 0)
		if ferr == nil {
			fdflags, ferr = unix.FcntlInt(fd, unix.F_GETFD, 0)
		}
	}))
	require.NoError(t, ferr)
	require.NotZero(t, flags&unix.O_NONBLOCK, "prepared descriptor must stay nonblocking")
	require.NotZero(t, fdflags&unix.FD_CLOEXEC, "duplicate must not escape through exec")
	fdCount := func() int { files, err := os.ReadDir("/proc/self/fd"); require.NoError(t, err); return len(files) }
	before := fdCount()
	for range 16 {
		f, err := os.Open("/dev/null")
		require.NoError(t, err)
		got, err := preparePTYMaster(f)
		require.Error(t, err, "unsupported descriptors must fail preparation")
		require.Nil(t, got)
		_, err = f.Stat()
		require.ErrorIs(t, err, os.ErrClosed, "failure must consume the original File too")
		f, err = os.Open("/dev/null")
		require.NoError(t, err)
		require.NoError(t, f.Close())
		got, err = preparePTYMaster(f)
		require.Error(t, err, "closed descriptors must fail preparation")
		require.Nil(t, got)
	}
	require.Equal(t, before, fdCount(), "preparation failures leaked a descriptor")
}

func TestPTYStartupClosesFilesOnLaunchFailure(t *testing.T) {
	if !ptyTestProcess(t) {
		return
	}
	// Warm up the runtime poller before counting descriptors.
	r, w, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, r.Close())
	require.NoError(t, w.Close())
	count := func() int { files, err := os.ReadDir("/proc/self/fd"); require.NoError(t, err); return len(files) }
	before := count()
	for range 8 {
		for _, forced := range []bool{false, true} {
			c := exec.Command("/nonexistent/upterm-pty-start")
			var p PTY
			if forced {
				p, err = startSessionPty(c, termsize.Default)
			} else {
				p, err = startPty(c, termsize.Default, false, nil)
			}
			require.Error(t, err)
			require.Nil(t, p)
			require.Nil(t, c.Process, "a failed launch must not publish a process")
		}
	}
	require.Equal(t, before, count(), "failed startup leaked a master or slave")
}

func TestPTYPreparationFailureDoesNotStartCommand(t *testing.T) {
	if !ptyTestProcess(t) {
		return
	}
	var limit unix.Rlimit
	require.NoError(t, unix.Getrlimit(unix.RLIMIT_NOFILE, &limit))
	if limit.Cur > 64 {
		limit.Cur = 64
	}
	require.NoError(t, unix.Setrlimit(unix.RLIMIT_NOFILE, &limit))
	for _, forced := range []bool{false, true} {
		var held []*os.File
		for {
			f, err := os.Open("/dev/null")
			if err != nil {
				require.ErrorIs(t, err, syscall.EMFILE)
				break
			}
			held = append(held, f)
		}
		require.GreaterOrEqual(t, len(held), 2)
		// Exactly two free slots permit master/slave open, but not preparation's dup.
		require.NoError(t, held[len(held)-1].Close())
		require.NoError(t, held[len(held)-2].Close())
		held = held[:len(held)-2]
		c := exec.Command("/bin/sh", "-c", "exit 0")
		var p PTY
		var err error
		if forced {
			p, err = startSessionPty(c, termsize.Default)
		} else {
			p, err = startPty(c, termsize.Default, false, nil)
		}
		for _, f := range held {
			_ = f.Close()
		}
		require.ErrorIs(t, err, syscall.EMFILE)
		require.Nil(t, p)
		require.Nil(t, c.Process, "preparation failure must precede command launch")
		require.Nil(t, c.Stdin, "preparation must fail before wiring child stdio")
		require.Nil(t, c.Stdout)
		require.Nil(t, c.Stderr)
	}
}

// A control operation holding the mutex must not stop Linux Close from reaching
// the poller, or a read from observing that close.
func TestPTYCloseDoesNotWaitOnTheMutex(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	ptmx, err := startPty(cmd, termsize.Default, false, nil)
	require.NoError(t, err)
	p := ptmx.(*pty)
	p.Lock()
	release := sync.OnceFunc(p.Unlock)
	readDone, closeDone := make(chan error, 1), make(chan error, 1)
	t.Cleanup(func() {
		release()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = p.Close()
		for _, ch := range []chan error{readDone, closeDone} {
			select {
			case err := <-ch:
				if err != nil {
					t.Logf("PTY worker cleanup completed with shutdown error: %v", err)
				}
			case <-time.After(time.Second):
				t.Error("PTY worker survived mutex release")
			}
		}
	})
	go parkedPTYRead(p, readDone)
	go func() { closeDone <- p.Close() }()
	until := time.Now().Add(time.Second)
	for _, worker := range []struct {
		name string
		ch   chan error
	}{{"read", readDone}, {"close", closeDone}} {
		timer := time.NewTimer(time.Until(until))
		select {
		case err := <-worker.ch:
			worker.ch <- err
			if worker.name == "read" {
				require.ErrorIs(t, err, os.ErrClosed)
			} else {
				require.NoError(t, err)
			}
		case <-timer.C:
			t.Errorf("Close did not release PTY %s while its control mutex was held", worker.name)
		}
		timer.Stop()
	}
}

type ptyInputResult struct {
	n   int
	err error
}

func cancelablePTYWrite(ctx context.Context, p PTY, b []byte, done chan<- ptyInputResult) {
	w, ok := p.(interface {
		WriteContext(context.Context, []byte) (int, error)
	})
	if !ok {
		done <- ptyInputResult{err: fmt.Errorf("PTY has no cancelable input owner")}
		return
	}
	n, err := w.WriteContext(ctx, b)
	done <- ptyInputResult{n, err}
}

func inputCancellationPTY(t *testing.T) (PTY, *exec.Cmd, string) {
	t.Helper()
	release := filepath.Join(t.TempDir(), "read-count")
	cmd := exec.Command("sh", "-c", `stty raw -echo; printf READY; while [ ! -f "$1" ]; do sleep 0.01; done; head -c "$(cat "$1")" | wc -c; head -c 6; printf END; exec sleep 60`, "pty-input", release)
	p, err := startPty(cmd, termsize.Default, false, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ready := make([]byte, 5)
	_, err = io.ReadFull(p, ready)
	require.NoError(t, err)
	require.Equal(t, "READY", string(ready))
	require.NoError(t, p.(*pty).SetReadDeadline(time.Now().Add(time.Second)))
	return p, cmd, release
}

func awaitPTYInput(t *testing.T, done <-chan ptyInputResult) ptyInputResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(time.Second):
		t.Fatal("canceled PTY input did not return within 1s")
		return ptyInputResult{}
	}
}

func TestPTYInputCancellationReleasesOnlyItsWriter(t *testing.T) {
	if !ptyTestProcess(t) {
		return
	}
	p, cmd, release := inputCancellationPTY(t)
	require.NoError(t, p.(*pty).SetReadDeadline(time.Now().Add(-time.Second)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan ptyInputResult, 1)
	go cancelablePTYWrite(ctx, p, bytes.Repeat([]byte("x"), 4<<20), done)
	require.Eventually(t, func() bool { return ptyWorkerParked("cancelablePTYWrite") }, time.Second, time.Millisecond, "owned PTY write did not park")
	cancel()
	result := awaitPTYInput(t, done)
	require.ErrorIs(t, result.err, context.Canceled)
	require.Greater(t, result.n, 0, "accepted prefix must be preserved")
	require.Less(t, result.n, 4<<20)
	require.NoError(t, cmd.Process.Signal(syscall.Signal(0)))
	_, readErr := p.Read(make([]byte, 1))
	require.ErrorIs(t, readErr, os.ErrDeadlineExceeded, "write cancellation must preserve the read deadline")
	require.NoError(t, p.(*pty).SetReadDeadline(time.Now().Add(time.Second)))
	require.NoError(t, os.WriteFile(release, []byte(fmt.Sprint(result.n)), 0600))
	reader := bufio.NewReader(p)
	count, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%d\n", result.n), count)
	n, err := p.Write([]byte("MARKER"))
	require.NoError(t, err)
	require.Equal(t, 6, n)
	want := "MARKEREND"
	got := make([]byte, len(want))
	_, err = io.ReadFull(reader, got)
	require.NoError(t, err)
	require.Equal(t, want, string(got), "accepted prefix and later marker must each arrive exactly once")
}

func TestPTYInputWaiterCannotCancelTheActiveWriter(t *testing.T) {
	if !ptyTestProcess(t) {
		return
	}
	p, _, release := inputCancellationPTY(t)
	active := make(chan ptyInputResult, 1)
	go cancelablePTYWrite(context.Background(), p, bytes.Repeat([]byte("x"), 256<<10), active)
	require.Eventually(t, func() bool { return ptyWorkerParked("cancelablePTYWrite") }, time.Second, time.Millisecond, "active PTY write did not park")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiter := make(chan ptyInputResult, 1)
	go cancelablePTYWrite(ctx, p, []byte("BAD"), waiter)
	cancel()
	result := awaitPTYInput(t, waiter)
	require.ErrorIs(t, result.err, context.Canceled)
	require.Zero(t, result.n)
	select {
	case result := <-active:
		t.Fatalf("waiter canceled the active writer: %+v", result)
	default:
	}
	require.NoError(t, os.WriteFile(release, []byte("262144"), 0600))
	result = awaitPTYInput(t, active)
	require.NoError(t, result.err)
	require.Equal(t, 256<<10, result.n)
	reader := bufio.NewReader(p)
	count, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%d\n", result.n), count)
	n, err := p.Write([]byte("MARKER"))
	require.NoError(t, err)
	require.Equal(t, 6, n)
	want := "MARKEREND"
	got := make([]byte, len(want))
	_, err = io.ReadFull(reader, got)
	require.NoError(t, err)
	require.Equal(t, want, string(got))
}

func TestHandlerOwnerCancellationReleasesActiveAndQueuedPTYInput(t *testing.T) {
	if !ptyTestProcess(t) {
		return
	}
	h := startHost(t, &Server{AwaitInitialClient: true,
		Command: []string{"sh", "-c", `stty raw -echo; printf READY; exec sleep 60`}})
	aIn, aOut, _, _ := h.connectHostGated(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, aOut, "READY")
	bIn, bOut, _, _ := h.connectHostGated(t, &hostPty{term: "xterm", cols: 80, rows: 24})
	readUntil(t, bOut, "READY")
	for _, in := range []io.Writer{aIn, bIn} {
		_, err := in.Write(bytes.Repeat([]byte("x"), 256<<10))
		require.NoError(t, err)
	}
	count := func() int {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		return strings.Count(string(buf[:n]), "(*ptyInput).WriteContext(")
	}
	require.Eventually(t, func() bool { return count() == 2 }, time.Second, time.Millisecond, "handler inputs did not reach active and queued write ownership")
	require.True(t, ptyWorkerParked("WriteContext"), "active handler input must be parked in the runtime poller")
	h.cancel()
	select {
	case <-h.stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("owner shutdown did not join active and queued input actors")
	}
	require.Zero(t, count(), "owned PTY write survived handler owner shutdown")
}
