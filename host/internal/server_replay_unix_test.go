//go:build !windows

package internal

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/owenthereal/x/vt"
	"github.com/stretchr/testify/require"

	"github.com/owenthereal/upterm/host/internal/replay"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
)

// repaintsOnWinch prints first once, and then, on every SIGWINCH, the size
// its terminal has at that moment, rows first, as `stty size` prints it: a
// full-screen program repainting at the size it is told. first is printf's
// format, so octal escapes in it are sequences.
//
// The trap's body is single-quoted so that $(stty size) runs each time the
// trap does. Double-quoted, the shell would expand it once, as the trap is
// set, and every repaint would report the size the command started at.
func repaintsOnWinch(first string) []string {
	return []string{"sh", "-c", `trap 'printf "REPAINT %s\n" "$(stty size)"' WINCH; printf '` + first + `'; while :; do sleep 0.05; done`}
}

// replayed reads what a client of a repaintsOnWinch session is sent until
// the repaint at size, and returns everything before it: what the client was
// handed as it joined. Every join is followed by a repaint, since the door
// nudges the command once the client is attached. A repaint the client gets
// as output, live or as the raw end of its replay, ends in the CRLF the pty
// makes of its newline; one the reconstruction took in is drawn row by row,
// with no CRLF. So what comes before the first one holds the whole
// reconstruction.
func replayed(t *testing.T, r io.Reader, size termsize.Size) string {
	t.Helper()
	repaint := fmt.Sprintf("REPAINT %d %d\r\n", size.Rows, size.Cols)
	got := readUntil(t, r, repaint)
	return got[:strings.Index(got, repaint)]
}

// terminal is a test's own terminal of a given size, fed what a client was
// sent: what the client's screen shows, and the lines that scrolled off it.
type terminal struct {
	*vt.Emulator
	scrolled []string
}

func newTerminal(t *testing.T, size termsize.Size, sent string) *terminal {
	t.Helper()
	term := &terminal{Emulator: vt.NewEmulator(size.Cols, size.Rows)}
	term.SetReplyFunc(func([]byte) {})
	term.SetScrollOffFunc(func(line uv.Line) { term.scrolled = append(term.scrolled, line.String()) })
	_, err := term.Write([]byte(sent))
	require.NoError(t, err)
	return term
}

// rows is the text of each row of the screen showing, its trailing blanks
// trimmed.
func (term *terminal) rows() []string {
	scr := term.ActiveScreen()
	rows := make([]string, scr.Height())
	for y := range rows {
		rows[y] = scr.Line(y).String()
	}
	return rows
}

// count is how many times s appears on the screen and in what scrolled off.
func (term *terminal) count(s string) int {
	n := 0
	for _, line := range append(term.rows(), term.scrolled...) {
		n += strings.Count(line, s)
	}
	return n
}

// sameScreen reports the first difference between two terminals' screens, or
// "": a cell, the cursor, or the lines that scrolled off.
func sameScreen(a, b *terminal) string {
	for y := range a.Height() {
		for x := range a.Width() {
			if ca, cb := a.CellAt(x, y), b.CellAt(x, y); !ca.Equal(cb) {
				return fmt.Sprintf("the cell at %d,%d: %+v vs %+v", x, y, ca, cb)
			}
		}
	}
	if pa, pb := a.CursorPosition(), b.CursorPosition(); pa != pb {
		return fmt.Sprintf("the cursor: %v vs %v", pa, pb)
	}
	if !slices.Equal(a.scrolled, b.scrolled) {
		return fmt.Sprintf("what scrolled off: %q vs %q", a.scrolled, b.scrolled)
	}
	return ""
}

// sessionLog is what a session logged, which a test can wait on.
type sessionLog struct {
	mu  sync.Mutex
	buf []byte
	// more is closed and replaced at each write.
	more chan struct{}
}

func newSessionLog() *sessionLog { return &sessionLog{more: make(chan struct{})} }

func (l *sessionLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	close(l.more)
	l.more = make(chan struct{})
	return len(p), nil
}

// await waits for marker in the log, and returns all of it.
func (l *sessionLog) await(t *testing.T, marker string) string {
	t.Helper()
	timeout := time.After(harnessTimeout)
	for {
		l.mu.Lock()
		got, more := string(l.buf), l.more
		l.mu.Unlock()
		if strings.Contains(got, marker) {
			return got
		}
		select {
		case <-more:
		case <-timeout:
			t.Fatalf("the session never logged %q; it logged %q", marker, got)
		}
	}
}

// cursorMoves are the sequences that move the cursor which the tests'
// commands draw with, as they draw them: a redraw that a terminal of another
// size would carry out in other places.
var cursorMoves = []string{"\x1b[H", "\x1b[1A"}

// The session is 80x24, held there by a viewer, and its command draws a
// status line and then redraws it in place, as an ink-style renderer does:
// up a row, the row erased, the line drawn again. A 45x30 guest gets the
// screen that redraw left, at its own size: one RING-MARK, its row cut at 45
// columns, as a terminal that doesn't reflow cuts it. Replayed raw, the same
// bytes would wrap the line at 45 and redraw only the half the cursor went
// back up to, leaving two. So the guest's first bytes hold none of the ring's
// cursor moves.
func TestASmallerGuestGetsTheEmulatedScreen(t *testing.T) {
	line := ringMark + strings.Repeat("x", 60)
	h := startHost(t, &Server{Command: repaintsOnWinch(`\033[H\033[2J` + line + `\n\033[1A\033[K` + line + `\n`)})
	_, viewer, _ := h.connectHost(t, nil)
	readUntil(t, viewer, line+"\r\n\x1b[1A\x1b[K"+line)

	_, out := h.connectGuest(t, withWindow(phone))
	got := replayed(t, out, phone)
	for _, move := range cursorMoves {
		require.NotContains(t, got, move, "the guest was handed the ring's redraw")
	}
	term := newTerminal(t, phone, got)
	require.Equal(t, 1, term.count(ringMark), "the guest's screen: %q", term.rows())
	require.Equal(t, line[:phone.Cols], term.rows()[0])
}

// An 80x24 guest of an 80x24 session gets the screen exactly: fed to a
// terminal of that size, its first bytes leave the same cells, cursor and
// scrolled-off lines as the ring does fed to another. The ring scrolls,
// styles text, moves the cursor, erases, and ends in text with no newline.
// The bytes are a reconstruction, not the ring: the viewer, which keeps the
// session at its size, is handed the ring.
func TestAnEqualGuestGetsExactGeometry(t *testing.T) {
	var first strings.Builder
	first.WriteString(`\033[1;31mRED\033[m plain\n`)
	for i := range 30 {
		fmt.Fprintf(&first, `line %02d\n`, i+1)
	}
	first.WriteString(`\033[5;10H\033[4munder\033[m\033[2A\033[Kup\033[12;1HEQUAL-MARK`)
	h := startHost(t, &Server{Command: repaintsOnWinch(first.String())})
	_, viewer, _ := h.connectHost(t, nil)
	ring := readUntil(t, viewer, "EQUAL-MARK")

	_, out := h.connectGuest(t, withWindow(desktop))
	got := replayed(t, out, desktop)
	ring += replayed(t, viewer, desktop)
	require.NotEqual(t, ring, got, "the guest was handed the raw ring")

	reference := newTerminal(t, desktop, ring)
	term := newTerminal(t, desktop, got)
	require.Empty(t, sameScreen(reference, term))
	require.NotEmpty(t, reference.scrolled, "nothing scrolled off, so history was never compared")
}

// A session pinned at 80x24 keeps that size whoever joins, and a 100x40
// guest gets the screen as it is at 80x24, at the top left of its own: a line
// of 85 columns wrapped at the pty's 80, where replayed raw on 100 columns it
// would not wrap at all.
func TestAPinnedSessionEmulatesAtItsSize(t *testing.T) {
	line := "PINNED-MARK" + strings.Repeat("x", 74)
	h := startHost(t, &Server{Command: repaintsOnWinch(line + `\n`), PtySize: desktop, PinPtySize: true})
	_, viewer, _ := h.connectHost(t, nil)
	readUntil(t, viewer, line)

	big := termsize.Size{Cols: 100, Rows: 40}
	_, out := h.connectGuest(t, withWindow(big))
	// The pinned pty's own size is what the command repaints at.
	term := newTerminal(t, big, replayed(t, out, desktop))
	rows := term.rows()
	require.Equal(t, []string{line[:desktop.Cols], line[desktop.Cols:], ""}, rows[:3])
	require.Equal(t, uv.Pos(0, 2), term.CursorPosition())
}

// A session in origin mode holds state the reconstruction doesn't restore,
// so a guest's join falls back: it is handed the raw ring, as the viewer is,
// and the session's log has one line at Info saying why.
func TestAnIneligibleJoinFallsBackAndSaysWhy(t *testing.T) {
	logs := newSessionLog()
	h := startHost(t, &Server{
		Command: repaintsOnWinch(`\033[?6hORIGIN-MARK`),
		Logger:  slog.New(slog.NewTextHandler(logs, nil)),
	})
	_, viewer, _ := h.connectHost(t, nil)
	ring := readUntil(t, viewer, "ORIGIN-MARK")

	_, out := h.connectGuest(t, withWindow(desktop))
	got := replayed(t, out, desktop)
	ring += replayed(t, viewer, desktop)
	require.Equal(t, ring, got, "the guest wasn't handed the raw ring")

	var fellBack []string
	for line := range strings.Lines(logs.await(t, "replay fell back")) {
		if strings.Contains(line, `msg="replay fell back to the raw ring"`) {
			fellBack = append(fellBack, line)
		}
	}
	require.Len(t, fellBack, 1)
	require.Contains(t, fellBack[0], "level=INFO")
	require.Contains(t, fellBack[0], "origin mode")
}

// A join that falls back is logged at Info, with why: the screen held state
// the reconstruction doesn't restore, which is expected. One whose replayer
// panicked is logged at Error, with the panic's stack: that is a bug.
func TestAFallbackIsLoggedWithItsReason(t *testing.T) {
	var logs bytes.Buffer
	report := logReplayFallback(slog.New(slog.NewTextHandler(&logs, nil)))
	report(&replay.IneligibleError{State: "origin mode"})
	report(&uio.ReplayPanic{Value: "boom", Stack: []byte("goroutine 7 [running]:\nthe replayer's frame")})

	lines := strings.Split(strings.TrimSuffix(logs.String(), "\n"), "\n")
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], `level=INFO msg="replay fell back to the raw ring" reason="replay: the render can't restore origin mode"`)
	require.Contains(t, lines[1], `level=ERROR msg="replay fell back to the raw ring" reason="multiwriter: the replay panicked: boom"`)
	require.Contains(t, lines[1], `the replayer's frame`)
}
