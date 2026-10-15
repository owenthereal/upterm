//go:build windows

package internal

import (
	"errors"
	"math"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/charmbracelet/x/conpty"
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
//
// What arrives here is VT, not the screen, so the labels are looked for in the
// text with the escape sequences taken out first: conhost may lay out the gap
// between a label and its number as spaces or as a cursor-forward sequence,
// and that sequence carries digits of its own -- a pattern that simply skipped
// to the next number would read the column count out of ESC[10C.
var ansiSequence = regexp.MustCompile(`\x1b\[[^\x40-\x7e]*[\x40-\x7e]|\x1b\][^\x07]*\x07`)

var (
	modeConLines   = regexp.MustCompile(`Lines:\s*(\d+)`)
	modeConColumns = regexp.MustCompile(`Columns:\s*(\d+)`)
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
	p, err := startPty(exec.Command("cmd", "/c", "mode con"), termsize.Size{Cols: 132, Rows: 43}, false, nil)
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
		nil,
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
		nil,
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

	// Bounded, because Wait is a WaitForSingleObject(INFINITE) on the process
	// handle: a cmd that never exits would otherwise hold this goroutine until
	// the whole package's test timeout expired, and take every other result in
	// the binary down with it.
	const exitTimeout = 30 * time.Second
	waited := make(chan error, 1)
	go func() { waited <- p.Wait() }()
	select {
	case err := <-waited:
		require.NoError(t, err, "the command must run to completion")
	case <-time.After(exitTimeout):
		t.Fatalf("the command did not exit within %s; pty output was %q", exitTimeout, out.String())
	}

	const settle = 10 * time.Second
	deadline := time.Now().Add(settle)
	for {
		raw := out.String()
		got := ansiSequence.ReplaceAllString(raw, "")
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
			t.Fatalf("mode con did not report a geometry within %s of exiting; pty output was %q", settle, raw)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// sizeCall is one call the fan-out would have heard from the pty.
type sizeCall struct {
	Kind    string        // "begin", "end" or "pinned"
	Size    termsize.Size // begin and pinned: the size reported
	Seq     uint64        // begin: the Seq handed out; end: the Seq it closes
	Applied bool          // end: the outcome
	// Before is, for a begin, the size the ConPTY had when it was reported.
	// Zero for the report startPty makes before there is a pty to ask.
	Before termsize.Size
}

// sizeRecorder is a sizeReporter that writes down what it hears, and for each
// ResizeBegin asks the ConPTY what size it has at that moment: a report made
// before the resize sees the old size, one made after it the new.
type sizeRecorder struct {
	mu    sync.Mutex
	calls []sizeCall
	seq   uint64
	cpty  *conpty.ConPty // once there is one
}

func (r *sizeRecorder) ResizeBegin(size termsize.Size) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	c := sizeCall{Kind: "begin", Size: size, Seq: r.seq}
	if r.cpty != nil {
		// What the ConPTY was last told, which ConPty.Resize updates only
		// once ResizePseudoConsole has succeeded.
		w, h, err := r.cpty.Size()
		if err == nil {
			c.Before = termsize.Size{Cols: w, Rows: h}
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

// TestConPTYReportsEachResizeInTwoSteps is the Windows twin of
// ptysize_unix_test.go's TestPtyReportsEachResizeInTwoSteps: a ResizeBegin
// before each ConPTY resize and a ResizeEnd after it, for a resize that
// changes the size and for nothing else. Redraw is the case the Unix pty has
// no form of: its resize out and back ends at the size it started from, so it
// reports nothing, and ConPTY repaints at the final size.
//
// The Unix test also fails the ioctl and checks the report is ended as not
// applied. A ConPTY resize is failed through the pty's resize field, as the
// Unix pty's is through setWinsize, and the case that matters here is Redraw's
// second leg failing.
func TestConPTYReportsEachResizeInTwoSteps(t *testing.T) {
	var (
		initial = termsize.Size{Cols: 80, Rows: 24}
		resized = termsize.Size{Cols: 45, Rows: 30}
	)
	// Outlives each case by far; the cleanup's Kill ends it.
	longRunning := func() *exec.Cmd { return exec.Command("cmd", "/c", "ping -n 30 127.0.0.1 >nul") }
	start := func(t *testing.T, size termsize.Size, pinned bool) (*pty, *sizeRecorder) {
		t.Helper()
		rec := &sizeRecorder{}
		p, err := startPty(longRunning(), size, pinned, rec)
		require.NoError(t, err)
		t.Cleanup(func() { _ = p.Kill(); _ = p.Close() })
		readPtyInBackground(p)
		f := p.(*pty)
		rec.mu.Lock()
		rec.cpty = f.cpty
		rec.mu.Unlock()
		return f, rec
	}
	winsize := func(t *testing.T, p *pty) termsize.Size {
		t.Helper()
		w, h, err := p.cpty.Size()
		require.NoError(t, err)
		return termsize.Size{Cols: w, Rows: h}
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

	t.Run("a resize is begun before the ConPTY is resized and ended after it", func(t *testing.T) {
		p, rec := start(t, initial, false)
		require.NoError(t, p.Setsize(30, 45))
		require.Equal(t, resized, winsize(t, p))
		require.Equal(t, []sizeCall{
			{Kind: "begin", Size: initial, Seq: 1},
			{Kind: "end", Seq: 1, Applied: true},
			// The recorder asked the ConPTY for its size inside ResizeBegin,
			// and it still had the old one: the report came before the resize.
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

	// conpty.Resize narrows each dimension to an int16, where 65537 columns
	// would wrap to one. Setsize clamps instead, and reports the clamped
	// size, which is the one the ConPTY is asked for: the fan-out stamps the
	// ring's bytes with what is reported. Whether ConPTY then takes that many
	// columns is its own business, and the outcome says.
	t.Run("a size past what a ConPTY holds is reported as the size it is asked for", func(t *testing.T) {
		p, rec := start(t, initial, false)
		asked := termsize.Size{Cols: math.MaxInt16, Rows: 24}

		err := p.Setsize(24, termsize.Max+2)
		got := rec.got()[2:]
		require.Len(t, got, 2)
		require.Equal(t, sizeCall{Kind: "begin", Size: asked, Seq: 2, Before: initial}, got[0])
		require.Equal(t, sizeCall{Kind: "end", Seq: 2, Applied: err == nil}, got[1])
		if err == nil {
			require.Equal(t, asked, winsize(t, p))
		}
	})

	t.Run("a redraw reports nothing", func(t *testing.T) {
		p, rec := start(t, initial, false)
		require.NoError(t, p.Setsize(30, 45))
		applied := rec.got()

		require.NoError(t, p.Redraw())
		require.Equal(t, applied, rec.got(), "ConPTY repaints at the final size, which is the one it had")
		require.Equal(t, resized, winsize(t, p))
	})

	// Neither leg of a redraw is reported when both succeed. When the first
	// does and the second fails, the ConPTY is left a column wider than the
	// size the fan-out's log and lastW hold, and a later Setsize back to that
	// size would resize it but go unreported, taken for no change.
	t.Run("a redraw whose first leg fails changes and reports nothing", func(t *testing.T) {
		p, rec := start(t, initial, false)
		opening := rec.got()
		errFirst := errors.New("the first leg fails")
		p.resize = func(int, int) error { return errFirst }

		require.ErrorIs(t, p.Redraw(), errFirst)
		require.Equal(t, opening, rec.got())
		require.Equal(t, initial, winsize(t, p))
		require.EqualValues(t, initial.Cols, p.lastW.Load())
	})

	t.Run("a redraw whose second leg fails reports the size the ConPTY is left at", func(t *testing.T) {
		p, rec := start(t, initial, false)
		wider := termsize.Size{Cols: initial.Cols + 1, Rows: initial.Rows}
		errSecond := errors.New("the second leg fails")
		legs := 0
		p.resize = func(w, h int) error {
			legs++
			if legs == 2 {
				return errSecond
			}
			return p.cpty.Resize(w, h)
		}

		require.ErrorIs(t, p.Redraw(), errSecond)
		require.Equal(t, 2, legs)
		require.Equal(t, wider, winsize(t, p), "the first leg is what the ConPTY is left at")
		require.EqualValues(t, wider.Cols, p.lastW.Load())
		require.EqualValues(t, wider.Rows, p.lastH.Load())
		require.Equal(t, []sizeCall{
			{Kind: "begin", Size: initial, Seq: 1},
			{Kind: "end", Seq: 1, Applied: true},
			// Late, after the first leg: the recorder found the ConPTY already
			// at the size it is told of.
			{Kind: "begin", Size: wider, Seq: 2, Before: wider},
			{Kind: "end", Seq: 2, Applied: true},
		}, rec.got())

		// The size the pty was meant to have is a change again, so the next
		// Setsize to it is reported and brings the ConPTY back, not taken for
		// one already made.
		p.resize = nil
		require.NoError(t, p.Setsize(int(initial.Rows), int(initial.Cols)))
		require.Equal(t, initial, winsize(t, p))
		require.EqualValues(t, initial.Cols, p.lastW.Load())
		require.Equal(t, []sizeCall{
			{Kind: "begin", Size: initial, Seq: 3, Before: wider},
			{Kind: "end", Seq: 3, Applied: true},
		}, rec.got()[4:])
	})

	t.Run("a closed pty reports nothing", func(t *testing.T) {
		p, rec := start(t, initial, false)
		opening := rec.got()
		require.NoError(t, p.Close())

		require.NoError(t, p.Setsize(30, 45))
		require.Equal(t, opening, rec.got())
	})

	t.Run("a pinned pty reports Pinned once and nothing on Setsize or Redraw", func(t *testing.T) {
		p, rec := start(t, initial, true)
		require.Equal(t, []sizeCall{{Kind: "pinned", Size: initial}}, rec.got())

		require.NoError(t, p.Setsize(30, 45))
		require.NoError(t, p.Setsize(24, 80))
		require.NoError(t, p.Redraw())
		require.Equal(t, []sizeCall{{Kind: "pinned", Size: initial}}, rec.got())
		require.Equal(t, initial, winsize(t, p))
	})

	t.Run("no reporter reports nothing", func(t *testing.T) {
		p, err := startPty(longRunning(), initial, false, nil)
		require.NoError(t, err)
		defer func() { _ = p.Kill(); _ = p.Close() }()
		readPtyInBackground(p)
		require.NoError(t, p.Setsize(30, 45))
	})
}
