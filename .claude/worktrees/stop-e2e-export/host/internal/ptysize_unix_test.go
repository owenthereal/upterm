//go:build !windows

package internal

import (
	"bytes"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	ptylib "github.com/creack/pty"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/require"
)

func Test_StartPty_AppliesInitialSize(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	p, err := startPty(cmd, termsize.Size{Cols: 132, Rows: 43}, false)
	require.NoError(t, err)
	defer func() { _ = p.Kill(); _ = p.Close() }()

	f, ok := p.(*pty)
	require.True(t, ok)

	rows, cols, err := ptylib.Getsize(f.File)
	require.NoError(t, err)
	require.Equal(t, 43, rows)
	require.Equal(t, 132, cols)
}

func Test_StartPty_PinnedIgnoresResize(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	p, err := startPty(cmd, termsize.Size{Cols: 132, Rows: 43}, true)
	require.NoError(t, err)
	defer func() { _ = p.Kill(); _ = p.Close() }()

	// A pinned pty reports success and changes nothing: a caller that cannot
	// resize is not an error, it is the promise --pty-size makes.
	require.NoError(t, p.Setsize(24, 80))

	f, ok := p.(*pty)
	require.True(t, ok)
	rows, cols, err := ptylib.Getsize(f.File)
	require.NoError(t, err)
	require.Equal(t, 43, rows)
	require.Equal(t, 132, cols)
}

func Test_StartPty_UnpinnedHonoursResize(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	p, err := startPty(cmd, termsize.Size{Cols: 132, Rows: 43}, false)
	require.NoError(t, err)
	defer func() { _ = p.Kill(); _ = p.Close() }()

	require.NoError(t, p.Setsize(24, 80))

	f, ok := p.(*pty)
	require.True(t, ok)
	rows, cols, err := ptylib.Getsize(f.File)
	require.NoError(t, err)
	require.Equal(t, 24, rows)
	require.Equal(t, 80, cols)
}

// Test_Pty_IoctlsDoNotRaceAParkedWriteAtClose asserts nothing itself: it is a
// shape the race detector judges, and make test runs under -race; without
// -race it only checks that the calls succeed.
//
// The resize calls run on their own goroutine, concurrently with Close, and
// hand nothing back to the test goroutine until after Close returns: a
// serial loop's own reference-taking (Fd's SetBlocking incref/decref) and a
// synchronous Close would each become a release the parked write's final
// decref acquires from, ordering every read before the write and hiding the
// exact race the real event goroutine — which never synchronises with
// whoever closes — can hit.
//
// The read is what releases a parked master write, on either OS, and here
// it happens on demand — the round signals the command to read — rather
// than by killing or closing anything. The command's exit releases it too
// on macOS, where the slave's close fails the write, but not on Linux,
// where a parked write outlives the slave; and the master's Go-level Close
// releases nothing while the writer holds its reference, on either OS.
//
// Eight rounds, not one: the race detector reports a given racing pair only
// once per process, so under -count=N only the first run that observes a
// pair can fail and every later run is silent — most of what made a single
// round red 2 of 3 times on macOS and 1 of 3 on Linux. A round's own
// detection is also below certainty, measured at roughly 60% per round on
// both OSes. One round is therefore red only about half the time against a
// broken pty; eight rounds in the same process are red every time, while a
// fixed pty stays clean in all eight. -count=N against a broken pty
// consequently only ever fails on its first run — the rounds inside a
// single run are what make failure reliable.
func Test_Pty_IoctlsDoNotRaceAParkedWriteAtClose(t *testing.T) {
	for i := 0; i < 8; i++ {
		ioctlsAgainstAParkedWrite(t)
	}
}

// ioctlsAgainstAParkedWrite is one round of
// Test_Pty_IoctlsDoNotRaceAParkedWriteAtClose.
func ioctlsAgainstAParkedWrite(t *testing.T) {
	// The trap is installed before READY is printed, so the marker proves it
	// exists: a USR1 arriving before the trap is the shell's default
	// disposition and kills the command, which on Linux leaves the parked
	// write with nothing left to release it.
	cmd := exec.Command("sh", "-c", "stty raw -echo; trap 'exec cat >/dev/null' USR1; printf READY; while :; do sleep 0.05; done")
	p, err := startPty(cmd, termsize.Size{Cols: 80, Rows: 24}, false)
	require.NoError(t, err)

	stop := make(chan struct{})
	var stopOnce sync.Once
	stopResizing := func() { stopOnce.Do(func() { close(stop) }) }
	// A failing require below would Goexit with the resizer still spinning
	// and the command still parked: stop the resizer and tear down the pty
	// regardless of how the round ends. stopResizing is the only thing that
	// closes stop, so the explicit call near the bottom of the body and this
	// one can never double-close it.
	defer func() {
		stopResizing()
		_ = p.Kill()
		_ = p.Close()
		// Reaped, not just killed: eight rounds per run, and a test that
		// leaves a zombie behind every round is a test nobody wants in
		// make test.
		_ = p.Wait()
	}()

	readUntil(t, p, "READY")

	done := make(chan struct{})
	go func() {
		_, _ = p.Write(bytes.Repeat([]byte("x"), 64<<10))
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)

	resizing := make(chan struct{})
	go func() {
		defer close(resizing)
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Errors are expected once the file is closed; what matters is
			// that every call before that went through the descriptor.
			_ = p.Setsize(43, 132)
			_ = p.Setsize(24, 80)
			_ = p.Redraw()
		}
	}()
	time.Sleep(50 * time.Millisecond) // the loop is running against the parked write

	require.NoError(t, p.Close())
	// The command reads only when told: released on demand, within ~50 ms,
	// rather than by the command's exit — which macOS alone would honour.
	require.NoError(t, cmd.Process.Signal(syscall.SIGUSR1))

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("parked write never returned")
	}

	stopResizing()
	<-resizing

	require.NoError(t, p.Kill())
}

// Test_Pty_IoctlsOnAClosedPtyAreNotErrors matches the Windows pty's contract
// (pty_windows.go's Setsize and Redraw): a resize or nudge that loses the
// race with the end of the session is nothing to anyone, so both silently
// ignore a closed pty rather than reporting the ioctl's error.
func Test_Pty_IoctlsOnAClosedPtyAreNotErrors(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	p, err := startPty(cmd, termsize.Size{Cols: 80, Rows: 24}, false)
	require.NoError(t, err)
	defer func() { _ = p.Kill(); _ = p.Close() }()

	require.NoError(t, p.Kill())
	require.NoError(t, p.Close())

	require.NoError(t, p.Setsize(24, 80))
	require.NoError(t, p.Redraw())
}
