//go:build windows

package internal

import (
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/stretchr/testify/require"
)

// The Windows half of ptysize_unix_test.go. A ConPTY has no descriptor to ask
// for its geometry the way a Unix pty does -- conpty.Size only reports back the
// number it was last told -- so the size is read the only way that proves
// anything: from inside the session, by the command the ConPTY is attached to.
// `mode con` prints the console it is attached to, which under a pseudoconsole
// is the pseudoconsole: ResizePseudoConsole sizes the buffer as well as the
// window, so the lines MODE reads out of GetConsoleScreenBufferInfo are the
// pty's rows rather than a scrollback height. The labels below are the English
// ones, which is what the runner this is written for speaks.
var (
	modeConLines   = regexp.MustCompile(`Lines:\s+(\d+)`)
	modeConColumns = regexp.MustCompile(`Columns:\s+(\d+)`)
)

// resizeDelay is how long a resizing case waits before resizing.
//
// The commands below spend their first seconds in `ping -n 3 127.0.0.1`, which
// is three pings a second apart and so a little over two seconds, before they
// print anything. 200ms is therefore comfortably after the ConPTY exists --
// startPty has returned by then -- and comfortably before the size is read,
// with an order of magnitude of slack at both ends for a loaded runner.
const resizeDelay = 200 * time.Millisecond

func Test_StartPty_AppliesInitialSize(t *testing.T) {
	// Composed into the command line as `cmd /c "mode con"`: the argument has
	// a space in it, so it is quoted, and cmd strips the surrounding quotes
	// before running what is inside them.
	p, err := startPty(exec.Command("cmd", "/c", "mode con"), termsize.Size{Cols: 132, Rows: 43}, false)
	require.NoError(t, err)
	defer func() { _ = p.Close() }()

	out := readPtyInBackground(p)
	rows, cols := awaitModeCon(t, p, out)
	require.Equal(t, 43, rows)
	require.Equal(t, 132, cols)
}

func Test_StartPty_PinnedIgnoresResize(t *testing.T) {
	p, err := startPty(
		exec.Command("cmd", "/c", "ping -n 3 127.0.0.1 >nul & mode con"),
		termsize.Size{Cols: 132, Rows: 43},
		true,
	)
	require.NoError(t, err)
	defer func() { _ = p.Close() }()

	out := readPtyInBackground(p)

	time.Sleep(resizeDelay)
	// A pinned pty reports success and changes nothing: a caller that cannot
	// resize is not an error, it is the promise --pty-size makes.
	require.NoError(t, p.Setsize(50, 100))

	rows, cols := awaitModeCon(t, p, out)
	require.Equal(t, 43, rows, "a pinned session must keep the geometry it opened with")
	require.Equal(t, 132, cols, "a pinned session must keep the geometry it opened with")
}

func Test_StartPty_UnpinnedHonoursResize(t *testing.T) {
	p, err := startPty(
		exec.Command("cmd", "/c", "ping -n 3 127.0.0.1 >nul & mode con"),
		termsize.Size{Cols: 132, Rows: 43},
		false,
	)
	require.NoError(t, err)
	defer func() { _ = p.Close() }()

	out := readPtyInBackground(p)

	time.Sleep(resizeDelay)
	require.NoError(t, p.Setsize(50, 100))

	rows, cols := awaitModeCon(t, p, out)
	require.Equal(t, 50, rows)
	require.Equal(t, 100, cols)
}

// ptyOutput collects what a pty produced while a test was doing something
// else. Guarded because the reading happens on its own goroutine: conhost
// writes as the session runs, and a test that only read at the end could be
// waiting on a pipe nobody is draining.
type ptyOutput struct {
	mu  sync.Mutex
	buf []byte
}

func (o *ptyOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return string(o.buf)
}

func readPtyInBackground(p PTY) *ptyOutput {
	out := &ptyOutput{}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := p.Read(buf)
			if n > 0 {
				out.mu.Lock()
				out.buf = append(out.buf, buf[:n]...)
				out.mu.Unlock()
			}
			if err != nil {
				// Including the read that fails when the deferred Close takes
				// the ConPTY away, which is how this goroutine ends.
				return
			}
		}
	}()
	return out
}

// awaitModeCon waits for the command to exit and returns the geometry it
// printed. It keeps looking after the exit because the ConPTY's output is a
// pipe: the process can be gone before its last line has reached this side.
func awaitModeCon(t *testing.T, p PTY, out *ptyOutput) (rows, cols int) {
	t.Helper()

	require.NoError(t, p.Wait(), "the command must run to completion")

	const settle = 10 * time.Second
	deadline := time.Now().Add(settle)
	for {
		got := out.String()
		lines := modeConLines.FindStringSubmatch(got)
		columns := modeConColumns.FindStringSubmatch(got)
		if lines != nil && columns != nil {
			r, err := strconv.Atoi(lines[1])
			require.NoError(t, err)
			c, err := strconv.Atoi(columns[1])
			require.NoError(t, err)
			return r, c
		}
		if time.Now().After(deadline) {
			t.Fatalf("mode con did not report a geometry within %s of exiting; pty output was %q", settle, got)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
