//go:build !windows

package internal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
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
// format, so octal escapes in it are sequences. Once it has set its trap and
// printed first it creates the file ready.
//
// The trap's body is single-quoted so that $(stty size) runs each time the
// trap does. Double-quoted, the shell would expand it once, as the trap is
// set, and every repaint would report the size the command started at.
func repaintsOnWinch(first, ready string) []string {
	return []string{"sh", "-c", `trap 'printf "REPAINT %s\n" "$(stty size)"' WINCH; printf '` + first + `'; : > "$1"; while :; do sleep 0.05; done`, "sh", ready}
}

// startRepainting is startHost for a session whose command is
// repaintsOnWinch(first), returned once the command has printed first. Every
// client that joins is nudged, but a nudge that reaches the shell before it
// has set its trap is lost, so a client joining while the command starts is
// repainted or not by how fast the shell gets to its trap. A client joining
// after this returns always is.
func startRepainting(t *testing.T, first string, srv *Server) *hostHarness {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	srv.Command = repaintsOnWinch(first, ready)
	h := startHost(t, srv)
	require.Eventually(t, func() bool { _, err := os.Stat(ready); return err == nil },
		harnessTimeout, time.Millisecond, "the command never signalled ready")
	return h
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

// The session is at its 80x24 start size, which a viewer doesn't change, and
// its command draws a status line and then redraws it in place, as an
// ink-style renderer does: up a row, the row erased, the line drawn again. A
// 45x30 guest, the first terminal, takes the pty to its own size, and gets the
// screen that redraw left at that size: one RING-MARK, its row cut at 45
// columns, as a terminal that doesn't reflow cuts it. Replayed raw, the same
// bytes would wrap the line at 45 and redraw only the half the cursor went
// back up to, leaving two. So the guest's first bytes hold none of the ring's
// cursor moves.
func TestASmallerGuestGetsTheEmulatedScreen(t *testing.T) {
	line := ringMark + strings.Repeat("x", 60)
	h := startRepainting(t, `\033[H\033[2J`+line+`\n\033[1A\033[K`+line+`\n`, &Server{})
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
// styles text, moves the cursor and erases, and ends in the repaint the
// viewer's join prompted. The bytes are a reconstruction, not the ring, which
// the viewer, counting towards no size, is handed.
func TestAnEqualGuestGetsExactGeometry(t *testing.T) {
	var first strings.Builder
	first.WriteString(`\033[1;31mRED\033[m plain\n`)
	for i := range 30 {
		fmt.Fprintf(&first, `line %02d\n`, i+1)
	}
	first.WriteString(`\033[5;10H\033[4munder\033[m\033[2A\033[Kup\033[12;1HEQUAL-MARK`)
	h := startRepainting(t, first.String(), &Server{})
	_, viewer, _ := h.connectHost(t, nil)
	// The viewer's own join nudged the command, and its repaint follows the
	// mark. It is waited for before the guest joins, so that it is in the ring
	// the guest captures and in the reference alike: left to chance, it would
	// reach the ring before the capture on some runs and after it on others,
	// and only on the first would the guest's screen show it.
	ring := readUntil(t, viewer, "EQUAL-MARKREPAINT 24 80\r\n")

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
	h := startRepainting(t, line+`\n`, &Server{PtySize: desktop, PinPtySize: true})
	_, viewer, _ := h.connectHost(t, nil)
	// The viewer's own join nudged the command, and its repaint follows the
	// line. It is waited for before the guest joins, so that the screen the
	// guest is handed always shows it: left to chance, it would reach the ring
	// before the capture on some runs and after it on others.
	readUntil(t, viewer, line+"\r\nREPAINT 24 80\r\n")

	big := termsize.Size{Cols: 100, Rows: 40}
	_, out := h.connectGuest(t, withWindow(big))
	// The pinned pty's own size is what the command repaints at.
	term := newTerminal(t, big, replayed(t, out, desktop))
	rows := term.rows()
	require.Equal(t, []string{line[:desktop.Cols], line[desktop.Cols:], "REPAINT 24 80"}, rows[:3])
	require.Equal(t, uv.Pos(0, 3), term.CursorPosition())
}

// A session in origin mode holds state the reconstruction doesn't restore,
// so a guest's join falls back: it is handed the raw ring, as the viewer is,
// and the session's log has one line at Info saying why.
func TestAnIneligibleJoinFallsBackAndSaysWhy(t *testing.T) {
	logs := newSessionLog()
	h := startRepainting(t, `\033[?6hORIGIN-MARK`, &Server{
		Logger: slog.New(slog.NewTextHandler(logs, nil)),
	})
	_, viewer, _ := h.connectHost(t, nil)
	// The viewer is read up to the repaint its own join prompted, so that
	// the repaint is in the ring the guest is handed. Each stream is cut at
	// its first repaint, that one, wherever its reads happen to split it.
	ring := replayed(t, viewer, desktop)

	_, out := h.connectGuest(t, withWindow(desktop))
	got := replayed(t, out, desktop)
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

// The session's command runs under tmux's TERM and sends a window title
// string, ESC k title ST, as oh-my-zsh does at every prompt there, which a
// terminal that is tmux takes as the window's name and draws none of. The
// session's replayer is built for the TERM its command runs under, whether
// the host names it, over the one the host inherited, or names none and the
// command inherits the host's, so the guest is handed a reconstruction, none
// of the title drawn. Where the host names xterm's over an inherited tmux,
// a TERM the replayer doesn't know to be screen's or tmux's, the join falls
// back: the guest is handed the raw ring, as the viewer is.
func TestTheReplayerReadsTheSessionsTERM(t *testing.T) {
	for _, tc := range []struct {
		name, inherited, term string
		renders               bool
	}{
		{"the host names it", "xterm-256color", "tmux-256color", true},
		{"the host names none", "tmux-256color", "", true},
		{"the host names another", "tmux-256color", "xterm-256color", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TERM", tc.inherited)
			h := startRepainting(t, `\033kzsh\033\\TITLE-MARK`, &Server{Term: tc.term})
			_, viewer, _ := h.connectHost(t, nil)
			// The viewer, counting towards no size, is handed the raw ring,
			// here up to the repaint its own join prompted, which the guest
			// then captures.
			ring := replayed(t, viewer, desktop)

			_, out := h.connectGuest(t, withWindow(desktop))
			got := replayed(t, out, desktop)
			if !tc.renders {
				require.Equal(t, ring, got, "the guest wasn't handed the raw ring")
				return
			}
			require.NotEqual(t, ring, got, "the guest was handed the raw ring")
			require.Equal(t, "TITLE-MARKREPAINT 24 80", newTerminal(t, desktop, got).rows()[0])
		})
	}
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

// slowReplayer is the session's own replayer, slowed down: each Start waits
// until the session's pacer holds the command, or for a second if it never
// does, then emulates. It stands for an emulation that takes a while.
type slowReplayer struct {
	uio.Replayer
	pacer *guestPacer // the session's, handed over as ServeWithContext builds it
}

func (r *slowReplayer) Start(ctx context.Context, deadline time.Time, c *uio.Capture, size termsize.Size) (uio.Emulation, error) {
	// Polled: the pacer announces nothing when it starts to hold.
	for until := time.Now().Add(time.Second); r.pacer.waiting.Load() == 0 && time.Now().Before(until); {
		time.Sleep(time.Millisecond)
	}
	return r.Replayer.Start(ctx, deadline, c, size)
}

// A command writing flat out, in a session with no primary, and a guest
// joining it, which paces. While the guest's screen is reconstructed the
// command is held to it, so the output since the capture stays within the
// low mark and a write, and the guest is handed the reconstruction, which
// starts with sequences. Without the hold, the second the slowed emulation
// waits is far more output than the ring holds, the output since the capture
// is evicted before the handoff, and the guest is handed the raw ring, in
// which a command printing only "y" lines puts no sequence at all.
func TestAGuestJoiningAFloodGetsItsScreenReconstructed(t *testing.T) {
	// The budget covers the slowed emulation either way, so a join that
	// falls back does so for the output it lost, not for time.
	r := &slowReplayer{Replayer: replay.New()}
	srv := &Server{Command: []string{"yes"}, replayBudget: 10 * time.Second}
	srv.onGuestPacer = func(p *guestPacer) { r.pacer = p }
	installReplayer(srv, r)
	h := startHost(t, srv)
	// A viewer, which counts towards no size and paces nothing, sees the
	// flood under way, so the ring holds output by the time the guest joins:
	// a join to an empty ring has nothing to reconstruct. Then it drains the
	// rest, so that it isn't dropped.
	_, viewer, _ := h.connectHost(t, nil)
	readUntil(t, viewer, "y\r\ny\r\n")
	go func() { _, _ = io.Copy(io.Discard, viewer) }()

	_, out := h.connectGuest(t, withWindow(desktop))
	first := make([]byte, 64)
	_, err := io.ReadFull(out, first)
	require.NoError(t, err)
	require.Contains(t, string(first), "\x1b[", "the guest was handed the raw ring")
}

// Each Serve owns its replayer and takes one replay budget at startup. A nil
// factory selects the shipped emulator; a factory returning nil selects raw.
func TestReplayConfigurationBelongsToItsServer(t *testing.T) {
	a, b := newDoorReplayer(), newDoorReplayer()
	srvA := &Server{Command: printsTheRing, replayBudget: 3 * time.Second, replayerFactory: func(string) uio.Replayer { return a }}
	srvB := &Server{Command: printsTheRing, replayBudget: 7 * time.Second, replayerFactory: func(string) uio.Replayer { return b }}
	hA, hB := startHost(t, srvA), startHost(t, srvB)
	for _, h := range []*hostHarness{hA, hB} {
		_, out, _ := h.connectHost(t, nil)
		readUntil(t, out, ringMark)
	}
	_, outA := hA.connectGuest(t, withWindow(phone))
	gotA := readUntil(t, outA, ringMark)
	require.Contains(t, gotA, emulatedMark)
	require.Len(t, a.seen(), 1)
	require.Empty(t, b.seen(), "A's join must not use B's factory")
	_, outB := hB.connectGuest(t, withWindow(phone))
	require.Contains(t, readUntil(t, outB, ringMark), emulatedMark)
	require.Len(t, a.seen(), 1)
	require.Len(t, b.seen(), 1)
	require.InDelta(t, float64(3*time.Second), float64(a.seen()[0].left), float64(time.Second))
	require.InDelta(t, float64(7*time.Second), float64(b.seen()[0].left), float64(time.Second))
	for _, tc := range []struct {
		name    string
		budget  time.Duration
		raw     bool
		factory func(string) uio.Replayer
	}{
		{name: "zero inherits startup budget", factory: func(string) uio.Replayer { return newDoorReplayer() }},
		{name: "nil factory uses emulator"},
		{name: "negative falls back immediately", budget: -time.Nanosecond, raw: true, factory: func(string) uio.Replayer { return newDoorReplayer() }},
		{name: "nil replayer uses raw", raw: true, factory: func(string) uio.Replayer { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r *doorReplayer
			factory := tc.factory
			if factory != nil {
				result := factory("xterm")
				r, _ = result.(*doorReplayer)
				factory = func(string) uio.Replayer { return result }
			}
			srv := &Server{Command: printsTheRing, replayBudget: tc.budget, replayerFactory: factory}
			h := startHost(t, srv)
			_, viewer, _ := h.connectHost(t, nil)
			readUntil(t, viewer, ringMark)
			_, out := h.connectGuest(t, withWindow(phone))
			got := readUntil(t, out, ringMark)
			if tc.raw {
				require.NotContains(t, got, emulatedMark)
				require.NotContains(t, got, "\x1b[")
				if r != nil {
					require.Empty(t, r.seen(), "negative budget must bypass the emulator")
				}
				return
			}
			if r != nil {
				require.Contains(t, got, emulatedMark)
				require.Len(t, r.seen(), 1)
				require.Greater(t, r.seen()[0].left, time.Duration(0))
				require.LessOrEqual(t, r.seen()[0].left, uio.ReplayBudget)
			} else {
				require.Contains(t, got, "\x1b[", "nil factory must retain the shipped emulator")
			}
		})
	}
}
