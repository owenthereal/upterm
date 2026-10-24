//go:build !windows

package internal

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Inspect geometry without Fd, which would disable Linux master pollability.
func ptyFileSize(f *os.File) (rows, cols int, err error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var ws *unix.Winsize
	var ioctlErr error
	if err := rc.Control(func(fd uintptr) { ws, ioctlErr = unix.IoctlGetWinsize(int(fd), unix.TIOCGWINSZ) }); err != nil {
		return 0, 0, err
	}
	if ioctlErr != nil {
		return 0, 0, ioctlErr
	}
	return int(ws.Row), int(ws.Col), nil
}

func Test_StartPty_AppliesInitialSize(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	p, err := startPty(cmd, termsize.Size{Cols: 132, Rows: 43}, false, nil)
	require.NoError(t, err)
	defer func() { _ = p.Kill(); _ = p.Close() }()

	f, ok := p.(*pty)
	require.True(t, ok)

	rows, cols, err := ptyFileSize(f.File)
	require.NoError(t, err)
	require.Equal(t, 43, rows)
	require.Equal(t, 132, cols)
}

func Test_StartPty_PinnedIgnoresResize(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	p, err := startPty(cmd, termsize.Size{Cols: 132, Rows: 43}, true, nil)
	require.NoError(t, err)
	defer func() { _ = p.Kill(); _ = p.Close() }()

	// A pinned pty reports success and changes nothing: a caller that cannot
	// resize is not an error, it is the promise --pty-size makes.
	require.NoError(t, p.Setsize(24, 80))

	f, ok := p.(*pty)
	require.True(t, ok)
	rows, cols, err := ptyFileSize(f.File)
	require.NoError(t, err)
	require.Equal(t, 43, rows)
	require.Equal(t, 132, cols)
}

func Test_StartPty_UnpinnedHonoursResize(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	p, err := startPty(cmd, termsize.Size{Cols: 132, Rows: 43}, false, nil)
	require.NoError(t, err)
	defer func() { _ = p.Kill(); _ = p.Close() }()

	require.NoError(t, p.Setsize(24, 80))

	f, ok := p.(*pty)
	require.True(t, ok)
	rows, cols, err := ptyFileSize(f.File)
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
// Linux Close releases the prepared master's poll operations. On other Unix
// platforms the child reads on demand to release the blocking write after the
// Go-level Close, while the resizer continues exercising descriptor control.
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
	p, err := startPty(cmd, termsize.Size{Cols: 80, Rows: 24}, false, nil)
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
	// Linux Close releases the pollable write and may hang up the child. Other
	// Unix platforms release the blocking write by asking the child to read.
	if runtime.GOOS != "linux" {
		require.NoError(t, cmd.Process.Signal(syscall.SIGUSR1))
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("parked write never returned")
	}

	stopResizing()
	<-resizing
	// The deferred cleanup kills/reaps the child if Close has not hung it up.
}

// Test_Pty_IoctlsOnAClosedPtyAreNotErrors matches the Windows pty's contract
// (pty_windows.go's Setsize and Redraw): a resize or nudge that loses the
// race with the end of the session is nothing to anyone, so both silently
// ignore a closed pty rather than reporting the ioctl's error.
func Test_Pty_IoctlsOnAClosedPtyAreNotErrors(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	p, err := startPty(cmd, termsize.Size{Cols: 80, Rows: 24}, false, nil)
	require.NoError(t, err)
	defer func() { _ = p.Kill(); _ = p.Close() }()

	require.NoError(t, p.Kill())
	require.NoError(t, p.Close())

	require.NoError(t, p.Setsize(24, 80))
	require.NoError(t, p.Redraw())
}

// sizeCall is one call the fan-out would have heard from the pty.
type sizeCall struct {
	Kind    string        // "begin", "end" or "pinned"
	Size    termsize.Size // begin and pinned: the size reported
	Seq     uint64        // begin: the Seq handed out; end: the Seq it closes
	Applied bool          // end: the outcome
	// Before is, for a begin, the size the pty had when it was reported. Zero
	// for the report startPty makes before there is a pty to ask.
	Before termsize.Size
}

// sizeRecorder is a sizeReporter that writes down what it hears, and for each
// ResizeBegin asks the pty what size it has at that moment: a report made
// before the ioctl sees the old size, one made after it the new.
type sizeRecorder struct {
	mu    sync.Mutex
	calls []sizeCall
	seq   uint64
	file  *os.File // the pty's master, once there is one
}

func (r *sizeRecorder) ResizeBegin(size termsize.Size) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	c := sizeCall{Kind: "begin", Size: size, Seq: r.seq}
	if r.file != nil {
		rows, cols, err := ptyFileSize(r.file)
		if err == nil {
			c.Before = termsize.Size{Cols: cols, Rows: rows}
		}
	}
	r.calls = append(r.calls, c)
	return r.seq
}

func (r *sizeRecorder) ResizeEnd(seq uint64, applied bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, sizeCall{Kind: "end", Seq: seq, Applied: applied})
}

func (r *sizeRecorder) Pinned(size termsize.Size) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, sizeCall{Kind: "pinned", Size: size})
}

func (r *sizeRecorder) got() []sizeCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]sizeCall(nil), r.calls...)
}

// TestPtyReportsEachResizeInTwoSteps pins what the pty tells the fan-out about
// its geometry: a ResizeBegin before each ioctl and a ResizeEnd after it, for
// a resize that changes the size and for nothing else. The fan-out stamps the
// ring's bytes with the size they were written at from these calls, so a size
// reported but never applied, or applied but never reported, or reported
// after the command's repaint was already in the ring, would decide a join's
// replay against a geometry the command never drew at.
func TestPtyReportsEachResizeInTwoSteps(t *testing.T) {
	var (
		initial = termsize.Size{Cols: 80, Rows: 24}
		resized = termsize.Size{Cols: 45, Rows: 30}
	)
	start := func(t *testing.T, size termsize.Size, pinned bool) (*pty, *sizeRecorder) {
		t.Helper()
		rec := &sizeRecorder{}
		p, err := startPty(exec.Command("sleep", "5"), size, pinned, rec)
		require.NoError(t, err)
		t.Cleanup(func() { _ = p.Kill(); _ = p.Close() })
		f := p.(*pty)
		rec.mu.Lock()
		rec.file = f.File
		rec.mu.Unlock()
		return f, rec
	}
	winsize := func(t *testing.T, p *pty) termsize.Size {
		t.Helper()
		rows, cols, err := ptyFileSize(p.File)
		require.NoError(t, err)
		return termsize.Size{Cols: cols, Rows: rows}
	}

	t.Run("start reports the initial size, begun and ended, before startPty returns", func(t *testing.T) {
		_, rec := start(t, initial, false)
		require.Equal(t, []sizeCall{
			{Kind: "begin", Size: initial, Seq: 1},
			{Kind: "end", Seq: 1, Applied: true},
		}, rec.got())
	})

	t.Run("start reports the size the pty opened at, not the one asked for", func(t *testing.T) {
		_, rec := start(t, termsize.Size{}, false)
		require.Equal(t, []sizeCall{
			{Kind: "begin", Size: termsize.Default, Seq: 1},
			{Kind: "end", Seq: 1, Applied: true},
		}, rec.got())
	})

	t.Run("a resize is begun before the ioctl and ended after it", func(t *testing.T) {
		p, rec := start(t, initial, false)
		require.NoError(t, p.Setsize(30, 45))
		require.Equal(t, resized, winsize(t, p))
		require.Equal(t, []sizeCall{
			{Kind: "begin", Size: initial, Seq: 1},
			{Kind: "end", Seq: 1, Applied: true},
			// The recorder asked the pty for its size inside ResizeBegin, and
			// it still had the old one: the report came before the ioctl.
			{Kind: "begin", Size: resized, Seq: 2, Before: initial},
			{Kind: "end", Seq: 2, Applied: true},
		}, rec.got())
	})

	// The tracker takes every ResizeBegin for a real size change: a same-size
	// report would reset the region its candidate is weighing, over bytes
	// that were never at another size.
	t.Run("a resize to the size the pty has reports nothing", func(t *testing.T) {
		p, rec := start(t, initial, false)
		opening := rec.got()

		require.NoError(t, p.Setsize(24, 80))
		require.Equal(t, opening, rec.got(), "the size it opened at")

		require.NoError(t, p.Setsize(30, 45))
		applied := rec.got()
		require.NoError(t, p.Setsize(30, 45))
		require.Equal(t, applied, rec.got(), "the size a Setsize gave it")
		require.Equal(t, resized, winsize(t, p))
	})

	t.Run("a failed ioctl ends the report as not applied, and reports no size after it", func(t *testing.T) {
		p, rec := start(t, initial, false)
		p.setWinsize = func(int, *unix.Winsize) error { return syscall.EIO }

		require.ErrorIs(t, p.Setsize(30, 45), syscall.EIO)
		require.Equal(t, initial, winsize(t, p), "nothing applied")
		require.Equal(t, []sizeCall{
			{Kind: "begin", Size: initial, Seq: 1},
			{Kind: "end", Seq: 1, Applied: true},
			{Kind: "begin", Size: resized, Seq: 2, Before: initial},
			{Kind: "end", Seq: 2, Applied: false},
		}, rec.got())

		// The pty is still at the old size, so asking for the new one again is
		// a change again and is reported again, rather than taken for one
		// already made.
		p.setWinsize = nil
		require.NoError(t, p.Setsize(30, 45))
		require.Equal(t, resized, winsize(t, p))
		require.Equal(t, []sizeCall{
			{Kind: "begin", Size: resized, Seq: 3, Before: initial},
			{Kind: "end", Seq: 3, Applied: true},
		}, rec.got()[4:])
	})

	// A winsize holds each dimension in 16 bits, and a request past that is
	// applied wrapped. The fan-out stamps the ring's bytes with what is
	// reported, so the report is the size the command was given, not the one
	// asked for: 65537 columns is one.
	t.Run("a size past what a winsize holds is reported as the size the ioctl applied", func(t *testing.T) {
		p, rec := start(t, initial, false)
		applied := termsize.Size{Cols: 1, Rows: 24}

		require.NoError(t, p.Setsize(24, termsize.Max+2))
		require.Equal(t, applied, winsize(t, p))
		require.Equal(t, []sizeCall{
			{Kind: "begin", Size: applied, Seq: 2, Before: initial},
			{Kind: "end", Seq: 2, Applied: true},
		}, rec.got()[2:])
	})

	// Not being able to read the size is not a reason to hide a resize that
	// may well apply: the report is deleted by its outcome when it does not.
	t.Run("a size that cannot be read is reported anyway", func(t *testing.T) {
		// Not a terminal: neither TIOCGWINSZ nor TIOCSWINSZ works on it.
		f, err := os.Open(os.DevNull)
		require.NoError(t, err)
		defer func() { _ = f.Close() }()
		rec := &sizeRecorder{}
		p := wrapPty(f, exec.Command("true"), false, rec)

		require.Error(t, p.Setsize(30, 45))
		require.Equal(t, []sizeCall{
			{Kind: "begin", Size: resized, Seq: 1},
			{Kind: "end", Seq: 1, Applied: false},
		}, rec.got())
	})

	t.Run("a closed pty reports nothing", func(t *testing.T) {
		p, rec := start(t, initial, false)
		opening := rec.got()
		require.NoError(t, p.Kill())
		require.NoError(t, p.Close())

		require.NoError(t, p.Setsize(30, 45))
		require.Equal(t, opening, rec.got())
	})

	t.Run("a pinned pty reports Pinned once and nothing on Setsize", func(t *testing.T) {
		p, rec := start(t, initial, true)
		require.Equal(t, []sizeCall{{Kind: "pinned", Size: initial}}, rec.got())

		require.NoError(t, p.Setsize(30, 45))
		require.NoError(t, p.Setsize(24, 80))
		require.Equal(t, []sizeCall{{Kind: "pinned", Size: initial}}, rec.got())
		require.Equal(t, initial, winsize(t, p))
	})

	t.Run("no reporter reports nothing", func(t *testing.T) {
		p, err := startPty(exec.Command("sleep", "5"), initial, false, nil)
		require.NoError(t, err)
		defer func() { _ = p.Kill(); _ = p.Close() }()
		require.NoError(t, p.Setsize(30, 45))
	})
}
