package replay

import (
	"bytes"
	"context"
	"fmt"
	"image/color"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/owenthereal/x/ansi"
	"github.com/owenthereal/x/vt"
	"github.com/stretchr/testify/require"

	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
)

// startFor runs the replayer's Start on c for a joiner of size, which must
// succeed.
func startFor(t *testing.T, c *uio.Capture, size termsize.Size) *emulation {
	t.Helper()
	em, err := New().Start(context.Background(), time.Now().Add(time.Minute), c, size)
	require.NoError(t, err)
	return em.(*emulation)
}

// joined is a join at one size, which is the joiner's too: a is the
// session's own terminal, fed the stream whole, and b a fresh terminal fed
// the render, then the deferred tail raw, as io sends them.
type joined struct {
	render         []byte
	a, b           *vt.Emulator
	aHist, bHist   *[][]byte
	aNames, bNames *names
	// own is, for joinOwn, the joiner's own lines the render left at the
	// front of b's scrollback, which bHist no longer holds.
	own [][]byte
}

// joinAt emulates stream on a cols x rows terminal for a joiner of that
// size, and requires b to be in a's state.
func joinAt(t *testing.T, cols, rows int, stream string) *joined {
	t.Helper()
	e := startFor(t, captureOf(stream, event(1, 0, cols, rows)), termsize.Size{Cols: cols, Rows: rows})
	render, err := e.Render()
	require.NoError(t, err)
	h, _ := e.Handoff()

	j := &joined{render: render}
	j.a, j.aHist = newReference(cols, rows)
	j.aNames = watchTitle(j.a)
	_, _ = j.a.WriteString(stream)
	j.b, j.bHist = newReference(cols, rows)
	j.bNames = watchTitle(j.b)
	_, _ = j.b.Write(render)
	_, _ = j.b.WriteString(stream[h:])
	j.requireSame(t)
	return j
}

// then feeds s to both terminals, which must then still be in one state.
func (j *joined) then(t *testing.T, s string) {
	t.Helper()
	_, _ = j.a.WriteString(s)
	_, _ = j.b.WriteString(s)
	j.requireSame(t)
}

func (j *joined) requireSame(t *testing.T) {
	t.Helper()
	require.Empty(t, sameState(j.a, j.b, *j.aHist, *j.bHist, *j.aNames, *j.bNames), "the render: %q", j.render)
}

// renderAt is the render of stream emulated on a cols x rows terminal, for a
// joiner of that size.
func renderAt(t *testing.T, cols, rows int, stream string) ([]byte, error) {
	t.Helper()
	e := startFor(t, captureOf(stream, event(1, 0, cols, rows)), termsize.Size{Cols: cols, Rows: rows})
	return e.Render()
}

// requireIneligible requires err to name state as what the render can't
// restore.
func requireIneligible(t *testing.T, err error, state string) {
	t.Helper()
	var ie *IneligibleError
	require.ErrorAs(t, err, &ie)
	require.Equal(t, state, ie.State)
}

// cellAt is the cell of e's active screen at x, y.
func cellAt(e *vt.Emulator, x, y int) uv.Cell {
	return *e.ActiveScreen().CellAt(x, y)
}

func fgOf(seq string) color.Color { return penOf(seq).Fg }

func bgOf(seq string) color.Color { return penOf(seq).Bg }

// A DECSC on each screen, each with its own pen, and on the main screen a
// link and a line-drawing G0 too: a live DECRC on either screen restores
// what the session saved there.
func TestReplayRestoresBothSavedCursors(t *testing.T) {
	const stream = "main text\r\n" +
		"\x1b[3;5H\x1b[1;32m\x1b]8;;https://m.example\x07\x1b(0\x1b7" +
		"\x1b(B\x1b]8;;\x07\x1b[m" +
		"\x1b[?47h\x1b[7;9H\x1b[4;35m\x1b7\x1b[m\x1b[?47l" +
		"\x1b[10;1Hend"
	j := joinAt(t, 80, 24, stream)

	j.then(t, "\x1b8q")
	c := cellAt(j.b, 4, 2)
	require.Equal(t, "─", c.Content, "the main slot's G0")
	require.True(t, c.Style.Attrs&uv.AttrBold != 0)
	require.Equal(t, "https://m.example", c.Link.URL)

	j.then(t, "\x1b[?47h\x1b8Y")
	c = cellAt(j.b, 8, 6)
	require.Equal(t, "Y", c.Content)
	require.Equal(t, fgOf("\x1b[35m"), c.Style.Fg)
}

// ?1049h saves the main screen's cursor with its pen: after ?1049l the pen
// is the bold red it saved.
func TestReplay1049SavesTheMainPen(t *testing.T) {
	j := joinAt(t, 80, 24, "prompt$ ls\r\n\x1b[1;31m\x1b[?1049h\x1b[m\x1b[Halt screen\r\n")
	j.then(t, "\x1b[?1049l")
	pen := j.b.ActiveScreen().Cursor().Pen
	require.True(t, pen.Attrs&uv.AttrBold != 0)
	require.Equal(t, fgOf("\x1b[31m"), pen.Fg)
	j.then(t, "x")
}

// The charsets a DECSC saved come back with a live DECRC.
func TestReplayRestoresSavedCharsets(t *testing.T) {
	j := joinAt(t, 80, 24, "text\r\n\x1b(0\x1b7\x1b(Bmore\r\n")
	j.then(t, "\x1b8q")
	require.Equal(t, "─", cellAt(j.b, 0, 1).Content)
}

// A shell that designated line drawing, then a program on the alternate
// screen, which designated ASCII there, and whose output has evicted all of
// that from the ring: the joiner leaves the alternate screen with the main
// screen's saved G0, line drawing, as the session's terminal does. The
// tracker fills the main screen's slot ahead of the switch it replays, by
// the ?1049h itself or by an ESC 7 ahead of a ?47h or ?1047h, and the render
// saves the slot the emulator was primed with the same way.
func TestReplayLeavesTheAlternateScreenWithAnEvictedMainG0(t *testing.T) {
	var out strings.Builder
	for i := 0; out.Len() < 8<<10; i++ {
		fmt.Fprintf(&out, "line %d of the program's output\r\n", i)
	}
	for _, tc := range []struct{ name, enter, leave string }{
		{"?1049h", "\x1b[?1049h", "\x1b[?1049l"},
		{"ESC 7 and ?47h", "\x1b7\x1b[?47h", "\x1b[?47l\x1b8"},
		{"ESC 7 and ?1047h", "\x1b7\x1b[?1047h", "\x1b[?1047l\x1b8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			head := "$ vim\r\n\x1b(0" + tc.enter + "\x1b(B"
			stream := []byte(head + out.String())
			capt := &capturing{r: New()}
			joined, fellBack := fanOut(t, capt, stream, []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
			require.NoError(t, fellBack)
			require.True(t, bytes.HasPrefix(joined, []byte(preamble)), "the render, not the raw ring")
			require.Greater(t, capt.c.Start, uint64(len(head)), "the designations and the switch are still in the ring")

			a := vt.NewEmulator(80, 24)
			_, _ = a.Write(stream)
			b := vt.NewEmulator(80, 24)
			_, _ = b.Write(joined)
			for _, term := range []*vt.Emulator{a, b} {
				g, _, _ := term.Charsets()
				require.Equal(t, byte('B'), g[0], "the alternate screen's G0")
				_, _ = term.WriteString(tc.leave)
				g, _, _ = term.Charsets()
				require.Equal(t, byte('0'), g[0], "the main screen's saved G0")
			}
		})
	}
}

// G1 shifted into GL stays there for the live bytes.
func TestReplayG1ShiftContinues(t *testing.T) {
	j := joinAt(t, 80, 24, "text\r\n\x1b)0\x0e")
	j.then(t, "q")
	require.Equal(t, "─", cellAt(j.b, 0, 1).Content)
}

// GL can invoke G2 and G3 too, by the locking shifts LS2 and LS3.
func TestReplayRestoresGL2AndGL3(t *testing.T) {
	for _, tc := range []struct{ name, stream string }{
		{"G2 by LS2", "text\r\n\x1b*0\x1bn"},
		{"G3 by LS3", "text\r\n\x1b+0\x1bo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := joinAt(t, 80, 24, tc.stream)
			j.then(t, "q")
			require.Equal(t, "─", cellAt(j.b, 0, 1).Content)
		})
	}
}

// The render tracks the pen it has set, so the live pen is the session's
// default, though the render last set red: the saved slot's, then REP's
// character's cell's.
func TestReplayTracksThePenAcrossTheSavedSlot(t *testing.T) {
	j := joinAt(t, 80, 24, "\x1b[31mtext\x1b[m\r\n\x1b[31m\x1b7\x1b[m")
	j.then(t, "x")
	require.Nil(t, cellAt(j.b, 0, 1).Style.Fg)
	j.then(t, "\x1b8y")
	require.Equal(t, fgOf("\x1b[31m"), cellAt(j.b, 0, 1).Style.Fg)
}

// A slot saved inside a link restores the link.
func TestReplayRestoresTheSavedLink(t *testing.T) {
	j := joinAt(t, 80, 24, "text\r\n\x1b]8;;https://l.example\x07\x1b7\x1b]8;;\x07")
	j.then(t, "\x1b8z")
	require.Equal(t, "https://l.example", cellAt(j.b, 0, 1).Link.URL)
}

// The pending-wrap reprint is in the reprinted cell's own pen and link, and
// the live pen after it is the session's.
func TestReplayReprintsInTheCellsOwnPen(t *testing.T) {
	j := joinAt(t, 4, 3, "abc\x1b[1m\x1b]8;;https://w.example\x07d\x1b[m\x1b]8;;\x07")
	require.True(t, j.b.PendingWrap())
	d := cellAt(j.b, 3, 0)
	require.True(t, d.Style.Attrs&uv.AttrBold != 0)
	require.Equal(t, "https://w.example", d.Link.URL)

	j.then(t, "e")
	e := cellAt(j.b, 0, 1)
	require.Equal(t, "e", e.Content, "no wrap")
	require.Equal(t, uv.Style{}, e.Style)
	require.Equal(t, uv.Link{}, e.Link)
}

// REP repeats the last character printed, which the rows drawn after it
// would otherwise change: here B, drawn after X.
func TestReplayReconstructsREPsLastCharacter(t *testing.T) {
	j := joinAt(t, 80, 24, "A\r\nB\x1b[1;1H\x1b[31mX\x1b[m\x1b[3;1H")
	j.then(t, "\x1b[1b")
	require.Equal(t, "X", cellAt(j.b, 0, 2).Content)
}

// With no cell left holding REP's character, it is printed on a blank cell
// and erased there in the cell's own background.
func TestReplayPrimesREPOnABlankCell(t *testing.T) {
	j := joinAt(t, 80, 24, "X\ré\r\n\x1b[44m\x1b[K\x1b[m")
	require.Equal(t, bgOf("\x1b[44m"), cellAt(j.b, 0, 1).Style.Bg, "the erase kept the cell's background")
	j.then(t, "\x1b[1b")
	require.Equal(t, "X", cellAt(j.b, 0, 1).Content)
}

// With neither a cell holding REP's character nor a blank one to print it
// on, or nothing printed to repeat, the render can't set it.
func TestReplayFailsWhenREPCantBeReconstructed(t *testing.T) {
	for _, tc := range []struct{ name, stream string }{
		// X is overwritten by é, two bytes, which sets no REP character.
		{"no blank cell", "X\réé\x1b[m"},
		{"a blank cell only in the last column", "X\ré\x1b[m"},
		// REP repeats only a one-byte character.
		{"nothing to repeat", "é\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := renderAt(t, 2, 1, tc.stream)
			requireIneligible(t, err, "REP's last character")
		})
	}
}

// The alternate screen keeps what was drawn on it while it is hidden, and a
// later ?47h shows it: its cells, its saved cursor and its kitty keyboard
// stack.
func TestReplayReconstructsTheHiddenAlternateScreen(t *testing.T) {
	t.Run("its cells", func(t *testing.T) {
		j := joinAt(t, 80, 24, "\x1b[?47h\x1b[HTEXT\x1b[?47l")
		j.then(t, "\x1b[?47h")
		require.Equal(t, "TEXT", j.b.AltScreen().Line(0).String())
	})

	t.Run("its saved cursor", func(t *testing.T) {
		j := joinAt(t, 80, 24, "\x1b[?47h\x1b[3;3H\x1b[31m\x1b7\x1b[m\x1b[?47l\x1b[Hmain\r\n")
		j.then(t, "\x1b[?47h\x1b8Z")
		z := cellAt(j.b, 2, 2)
		require.Equal(t, "Z", z.Content)
		require.Equal(t, fgOf("\x1b[31m"), z.Style.Fg)
	})

	t.Run("its kitty stack", func(t *testing.T) {
		render, err := renderAt(t, 80, 24, "main\r\n\x1b[?47h\x1b[>1u\x1b[?47l")
		require.NoError(t, err)
		require.Regexp(t, regexp.MustCompile(`\x1b\[\?1049h.*\x1b\[>1u.*\x1b\[\?1049l`), string(render))
	})
}

// afterAnEditor is a shell session in which an editor ran and exited: ?1049l
// leaves the editor's last screen on the hidden alternate screen, which the
// render rebuilds.
const afterAnEditor = "$ ls\r\nfile1 file2\r\n$ vim notes\r\n" +
	"\x1b[?1049h\x1b[H\x1b[34mVIM LINE 1\r\nVIM LINE 2\r\n~\x1b[m\x1b[?1049l$ "

// without47 is p as a terminal that has ?1049 but not ?47 reads it, as
// Alacritty and Windows Terminal do: ?47h and ?47l do nothing.
func without47(p []byte) []byte {
	p = bytes.ReplaceAll(p, []byte("\x1b[?47h"), nil)
	return bytes.ReplaceAll(p, []byte("\x1b[?47l"), nil)
}

// The render goes to the hidden alternate screen and back by ?1049, never by
// ?47, which some terminals with ?1049 ignore: on one of those, a trip by ?47
// would erase the shell's screen and draw the editor's in its place. Its save
// and restore are the main screen's slot's, as ESC 7 and ESC 8 are, so a live
// DECRC on either screen still restores what the session saved there.
func TestReplayRebuildsTheHiddenAlternateScreenBy1049(t *testing.T) {
	t.Run("the trip's switch", func(t *testing.T) {
		render, err := renderAt(t, 80, 24, afterAnEditor)
		require.NoError(t, err)
		require.NotContains(t, string(render), "\x1b[?47h")
		require.NotContains(t, string(render), "\x1b[?47l")
		require.Regexp(t, regexp.MustCompile(`\x1b\[\?1049h.*VIM LINE 2.*\x1b\[\?1049l`), string(render))
	})

	t.Run("on a terminal with ?47", func(t *testing.T) {
		j := joinAt(t, 80, 24, afterAnEditor)
		j.then(t, "\x1b8X")
		j.then(t, "\x1b[?47h\x1b8Y")
		require.Equal(t, "YIM LINE 1", j.b.AltScreen().Line(0).String())
		j.then(t, "\x1b[?47l\r\n$ ")
	})

	t.Run("on a terminal without ?47", func(t *testing.T) {
		e := startFor(t, captureOf(afterAnEditor, event(1, 0, 80, 24)), termsize.Size{Cols: 80, Rows: 24})
		render, err := e.Render()
		require.NoError(t, err)
		h, _ := e.Handoff()
		a, aHist := newReference(80, 24)
		_, _ = a.WriteString(afterAnEditor)
		b, bHist := newReference(80, 24)
		_, _ = b.Write(without47(render))
		_, _ = b.WriteString(afterAnEditor[h:])
		require.Empty(t, sameState(a, b, *aHist, *bHist, names{}, names{}), "the render: %q", render)
		require.Equal(t, "$ vim notes", b.MainScreen().Line(2).String())
		for _, term := range []*vt.Emulator{a, b} {
			_, _ = term.WriteString("echo hi\r\nhi\r\n$ ")
		}
		require.Empty(t, sameState(a, b, *aHist, *bHist, names{}, names{}))
	})
}

// The region comes from the emulator, which a resize resets, wherever the
// DECSTBM was: in the ring, or in the state the ring starts in. The render
// sets none after its preamble, whose own resets the joiner's.
func TestReplayMarginsComeFromTheEmulator(t *testing.T) {
	decstbm := regexp.MustCompile(`\x1b\[[0-9;]*r`)
	tall := termsize.Size{Cols: 80, Rows: 30}

	t.Run("in the ring", func(t *testing.T) {
		const stream = "\x1b[2;10rtext\r\n"
		e := startFor(t, captureOf(stream, event(1, 0, 80, 24), event(2, len(stream), 80, 30)), tall)
		render, err := e.Render()
		require.NoError(t, err)
		require.NotRegexp(t, decstbm, string(bytes.TrimPrefix(render, []byte(preamble))))

		a, aHist := newReference(80, 24)
		_, _ = a.WriteString(stream)
		a.Resize(80, 30)
		b, bHist := newReference(80, 30)
		_, _ = b.Write(render)
		require.Empty(t, sameState(a, b, *aHist, *bHist, names{}, names{}))
	})

	t.Run("in the state the ring starts in", func(t *testing.T) {
		modes := uio.NewModeTracker()
		_, _ = modes.Write([]byte("\x1b[2;10r"))
		const stream = "text\r\n"
		c := &uio.Capture{
			Modes:  modes,
			Chunks: [][]byte{[]byte(stream)},
			Sizes:  []uio.SizeEvent{event(1, 0, 80, 24), event(2, 100+len(stream), 80, 30)},
			Start:  100,
			End:    100 + uint64(len(stream)),
		}
		e := startFor(t, c, tall)
		render, err := e.Render()
		require.NoError(t, err)
		require.NotRegexp(t, decstbm, string(bytes.TrimPrefix(render, []byte(preamble))))
		require.Equal(t, uv.Rect(0, 0, 80, 30), e.term.ActiveScreen().ScrollRegion())
	})
}

// State the render doesn't restore fails it, named.
func TestReplayFailsOnUnsupportedState(t *testing.T) {
	full := strings.Repeat("x", 80)
	for _, tc := range []struct{ name, stream, state string }{
		{"origin mode", "\x1b[?6htext\r\n", "origin mode"},
		{"left and right margins", "\x1b[?69h\x1b[2;10stext\r\n", "DECSLRM left and right margins"},
		{"LNM", "\x1b[20htext\r\n", "LNM"},
		{"a single shift", "text\r\n\x1bN", "a pending single shift"},
		{"GR", "text\r\n\x1b~", "GR other than G2"},
		// CBT moves the cursor left and keeps the wrap.
		{"a wrap off the last column", full + "\x1b[Z", "a pending wrap off the last column"},
		{"a mode it doesn't restore", "\x1b[?1001htext\r\n", "mode ?1001"},
		{"DECLRMM with no margins", "\x1b[?69htext\r\n", "mode ?69"},
		{"reverse wraparound", "\x1b[?45htext\r\n", "mode ?45"},
		{"a mode no terminal has", "\x1b[?9999htext\r\n", "mode ?9999"},
		{"an ANSI mode", "\x1b[2htext\r\n", "mode 2"},
		{"a screen switch left set", "\x1b[?1049htext\r\n\x1b[?47l", "mode ?1049"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := renderAt(t, 80, 24, tc.stream)
			requireIneligible(t, err, tc.state)
		})
	}

	// A widening leaves a wrap where it was, off the new last column, on the
	// cursor and in a slot.
	for _, tc := range []struct{ name, stream, state string }{
		{"a wrap a widening left", full + "\x1b[m", "a pending wrap off the last column"},
		{"a saved wrap a widening left", full + "\x1b7\r\n", "the main screen's saved pending wrap off the last column"},
		{"an alternate saved wrap a widening left", "\x1b[?47h" + full + "\x1b7\x1b[?47l\r\n", "the alternate screen's saved pending wrap off the last column"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wide := termsize.Size{Cols: 100, Rows: 24}
			e := startFor(t, captureOf(tc.stream, event(1, 0, 80, 24), event(2, len(tc.stream), 100, 24)), wide)
			_, err := e.Render()
			requireIneligible(t, err, tc.state)
		})
	}

	// Appearance only: the cursor's blink and a synchronized update.
	t.Run("modes it ignores", func(t *testing.T) {
		_, err := renderAt(t, 80, 24, "\x1b[?12h\x1b[?2026htext\r\n")
		require.NoError(t, err)
	})
}

// A saved slot holding origin mode or GR other than G2 fails the render, on
// either screen.
func TestReplayFailsOnASavedOriginMode(t *testing.T) {
	for _, tc := range []struct{ name, stream, state string }{
		{"main", "\x1b[?6h\x1b7\x1b[?6ltext\r\n", "the main screen's saved origin mode"},
		{"alternate", "\x1b[?47h\x1b[?6h\x1b7\x1b[?6l\x1b[?47ltext\r\n", "the alternate screen's saved origin mode"},
		{"GR", "\x1b~\x1b7\x1b}text\r\n", "the main screen's saved GR other than G2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := renderAt(t, 80, 24, tc.stream)
			requireIneligible(t, err, tc.state)
		})
	}
}

// The history fills what the rest leaves of the budget, newest lines first,
// cut at whole lines; the rest over the budget alone fails, and so does a
// joiner smaller than the render.
func TestReplayBudget(t *testing.T) {
	var lines []string
	for i := range 30 {
		lines = append(lines, fmt.Sprintf("line %02d %s", i, strings.Repeat("=", 20)))
	}
	stream := strings.Join(lines, "\r\n") + "\r\n"
	setBudget := func(n int) {
		old := budget
		budget = n
		t.Cleanup(func() { budget = old })
	}

	full := joinAt(t, 80, 5, stream)
	hist := *full.aHist
	require.Len(t, hist, 26)
	perLine := len(hist[0]) + len(crlf)
	mandatory := len(full.render) - len(hist)*perLine
	// The ED 3 that clears the joiner's scrollback, once the stream cleared
	// history, is part of the rest.
	cleared := "\x1b[3J" + stream
	fullCleared := joinAt(t, 80, 5, cleared)
	require.Len(t, *fullCleared.aHist, 26)
	mandatoryCleared := len(fullCleared.render) - 26*perLine

	t.Run("newest first", func(t *testing.T) {
		setBudget(mandatory + 23*perLine + perLine - 1)
		e := startFor(t, captureOf(stream, event(1, 0, 80, 5)), termsize.Size{Cols: 80, Rows: 5})
		render, err := e.Render()
		require.NoError(t, err)
		require.LessOrEqual(t, len(render), budget)

		a, aHist := newReference(80, 5)
		_, _ = a.WriteString(stream)
		b, bHist := newReference(80, 5)
		_, _ = b.Write(render)
		require.Empty(t, sameState(a, b, (*aHist)[3:], *bHist, names{}, names{}))
	})

	t.Run("newest first, after a clear", func(t *testing.T) {
		setBudget(mandatoryCleared + 23*perLine + perLine - 1)
		e := startFor(t, captureOf(cleared, event(1, 0, 80, 5)), termsize.Size{Cols: 80, Rows: 5})
		render, err := e.Render()
		require.NoError(t, err)
		require.LessOrEqual(t, len(render), budget)

		a, aHist := newReference(80, 5)
		_, _ = a.WriteString(cleared)
		b, bHist := newReference(80, 5)
		_, _ = b.Write(render)
		require.Empty(t, sameState(a, b, (*aHist)[3:], *bHist, names{}, names{}))
	})

	t.Run("the rest over it", func(t *testing.T) {
		setBudget(mandatory - 1)
		e := startFor(t, captureOf(stream, event(1, 0, 80, 5)), termsize.Size{Cols: 80, Rows: 5})
		_, err := e.Render()
		require.ErrorIs(t, err, ErrOverBudget)
	})

	for _, small := range []termsize.Size{{Cols: 79, Rows: 5}, {Cols: 80, Rows: 4}} {
		t.Run(fmt.Sprintf("a joiner at %dx%d", small.Cols, small.Rows), func(t *testing.T) {
			e := startFor(t, captureOf(stream, event(1, 0, 80, 5)), small)
			_, err := e.Render()
			require.ErrorIs(t, err, ErrNotContained)
		})
	}
}

// A URL longer than the budget on linked cells fails the render at the cap,
// and the encoder's buffer, which only grows, never grew past it.
func TestReplayBoundsALongLinkRow(t *testing.T) {
	open := "\x1b]8;;https://" + strings.Repeat("u", 4<<20-64) + "\x07"
	const end = "\x1b]8;;\x07"
	stream := open + "a" + end + "b" + open + "c" + end + "d\r\n"
	e := start(t, captureOf(stream, event(1, 0, 80, 24)))
	_, err := e.Render()
	require.ErrorIs(t, err, ErrOverBudget)
	require.LessOrEqual(t, cap(e.enc.buf), budget)
}

// A wrap pending at the last column, with the joiner as wide as the render,
// is pending in B too, from the reprint of the last column's cell: no CUP
// followed it. The next character wraps in both, and a reprint before the
// continuation state is neither inserted nor remapped.
func TestReplayPendingWrap(t *testing.T) {
	for _, tc := range []struct{ name, stream, next string }{
		{"plain", "abcd\x1b[m", "Y"},
		{"under insert mode", "abcd\x1b[4h", "Y"},
		{"under a line-drawing G0", "abcx\x1b(0", "q"},
		{"after a wide character", "ab中\x1b[m", "Y"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := joinAt(t, 4, 3, tc.stream)
			require.True(t, j.b.PendingWrap())
			require.Equal(t, uv.Pos(3, 0), j.b.CursorPosition())
			j.then(t, tc.next)
			require.Equal(t, uv.Pos(1, 1), j.b.CursorPosition(), "no wrap")
		})
	}
}

// Nothing the render writes after the last print moves the cursor or clears
// a pending wrap: each sequence it can write there, after a wrap set at the
// last column, leaves it.
func TestContinuationStateLeavesThePendingWrap(t *testing.T) {
	for _, seq := range []string{
		"\x1b(0", "\x1b)0", "\x1b*0", "\x1b+0", "\x1b(A", "\x1b(B",
		"\x0f", "\x0e", "\x1bn", "\x1bo",
		"\x1b[4h", "\x1b=", "\x1b[?5h", "\x1b]2;a title\x07", "\x1b]1;an icon name\x07",
		"\x1b[22;0t", "\x1b[22;1t", "\x1b[22;2t", "\x1b[22;3t",
		"\x1b[1 q", "\x1b[2 q", "\x1b[3 q", "\x1b[4 q", "\x1b[5 q", "\x1b[6 q",
		"\x1b[?7l", "\x1b[m", "\x1b[1;4:3;38;2;1;2;3m",
		"\x1b]8;;https://x.example\x07", "\x1b]8;id=1;\x07",
		"\x1b]7;file://host/dir\x07", "\x1b]22;hand2\x07",
		"\x1b[5 t", "\x1b[5 u", "\x1b[ t", "\x1b[ u",
		"\x1b]9;4;1;80\x07", "\x1b]9;4;0\x07",
		"\x1b]52;c;QQ==\x07",
		"\x00",
	} {
		term := vt.NewEmulator(4, 2)
		_, _ = term.WriteString("xxxx")
		require.True(t, term.PendingWrap())
		_, _ = term.WriteString(seq)
		require.True(t, term.PendingWrap(), "%q cleared the wrap", seq)
		require.Equal(t, uv.Pos(3, 0), term.CursorPosition(), "%q moved the cursor", seq)
	}
}

// A line-drawing character in the last column, with the wrap pending after
// it, sets no REP character when reprinted, being three bytes: the q it was
// printed as is set first, and REP repeats it in both.
func TestReplayPrimesBeforeAMultiByteReprint(t *testing.T) {
	j := joinAt(t, 4, 3, "abc\x1b(0q\x1b(B")
	require.True(t, j.b.PendingWrap())
	j.then(t, "\x1b[1b")
	require.Equal(t, "q", cellAt(j.b, 0, 1).Content)
}

// A slot saved with a wrap pending restores it: the next character wraps.
func TestReplayRestoresASavedPendingWrap(t *testing.T) {
	j := joinAt(t, 4, 3, "xxxx\x1b7\x1b[2;1H")
	j.then(t, "\x1b8y")
	require.Equal(t, "y", cellAt(j.b, 0, 1).Content)
}

// The slot's own pen and link are set after its wrap reprint, which leaves
// the cell's: a red last-column cell under a blue linked slot saves blue.
func TestReplaySlotKeepsItsPenAfterAWrapReprint(t *testing.T) {
	const red = "xxx\x1b[31mx\x1b[34m\x1b]8;;https://s.example\x07"
	for _, tc := range []struct{ name, stream, restore string }{
		{"by DECSC", red + "\x1b7\x1b[m\x1b]8;;\x07\x1b[2;1H", "\x1b8z"},
		{"by 1049", red + "\x1b[?1049h\x1b[m\x1b]8;;\x07", "\x1b[?1049lz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := joinAt(t, 4, 3, tc.stream)
			j.then(t, tc.restore)
			z := cellAt(j.b, 0, 1)
			require.Equal(t, "z", z.Content, "no wrap")
			require.Equal(t, fgOf("\x1b[34m"), z.Style.Fg)
			require.Equal(t, "https://s.example", z.Link.URL)
		})
	}
}

// A reprinted one-byte cell sets REP's character itself, so when that isn't
// the session's, the render fails rather than set the wrong one.
func TestReplayFailsWhenAnASCIIReprintDisagreesWithREP(t *testing.T) {
	_, err := renderAt(t, 4, 3, "xxxx\x1b7\x1b[2;1Hy\x1b8")
	requireIneligible(t, err, "REP's last character under a pending wrap")

	j := joinAt(t, 4, 3, "xxxx\x1b7\x1b[2;1Hx\x1b8")
	j.then(t, "\x1b[1b")
	require.Equal(t, "x", cellAt(j.b, 0, 1).Content)
}

// The terminal has one region, kept across screen switches: set on either
// screen, it holds on the other. The render installs it once, after it has
// drawn both screens.
//
// x/vt keeps the one region across switches, so B can't tell where the
// render installed it, and the order is checked directly: a terminal that
// keeps a region per screen gives it to the screen showing then, which
// should be the one showing at the end.
func TestReplayInstallsTheOneRegionAfterBothBuffers(t *testing.T) {
	for _, tc := range []struct{ name, stream, lastSwitch string }{
		{"set on the alternate screen", "main\r\n\x1b[?1049h\x1b[2;10r\x1b[Halt\x1b[?1049l", "\x1b[?1049l"},
		{"shown on the alternate screen", "main\r\n\x1b[2;10r\x1b[?1049h\x1b[Halt", "\x1b[?1049h"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := joinAt(t, 80, 24, tc.stream)
			// The preamble's own resets the joiner's.
			require.Len(t, regexp.MustCompile(`\x1b\[[0-9;]*r`).FindAll(bytes.TrimPrefix(j.render, []byte(preamble)), -1), 1)
			require.Contains(t, string(j.render), tc.lastSwitch)
			require.Greater(t, bytes.Index(j.render, []byte("\x1b[2;10r")), bytes.LastIndex(j.render, []byte(tc.lastSwitch)))
			require.Equal(t, uv.Rect(0, 1, 80, 9), j.b.ActiveScreen().ScrollRegion())
			j.then(t, "\x1b[10;1H\nscrolled\n\n")
		})
	}
}

// A wrap pending under autowrap off is rebuilt with autowrap on, which goes
// off only after it: ?7h then a character wraps in both.
//
// A character that fills the line leaves a wrap pending with autowrap on or
// off, so B can't tell where ?7l came: the render keeps it after the last
// reprint, and the order is checked directly.
func TestReplayRestoresAutowrapAfterTheWrapReprint(t *testing.T) {
	j := joinAt(t, 4, 3, "xxxx\x1b7\x1b[?7l\x1b[2;1H\x1b8")
	requireAfterTheReprints(t, j.render, "\x1b[?7l")
	require.True(t, j.b.PendingWrap())
	require.False(t, j.b.Mode(ansi.ModeAutoWrap).IsSet())
	j.then(t, "\x1b[?7hY")
	require.Equal(t, "Y", cellAt(j.b, 0, 1).Content)
}

// The same for a wrap saved by ?1049h.
func TestReplayRestoresAutowrapAfterA1049SavedWrap(t *testing.T) {
	j := joinAt(t, 4, 3, "xxxx\x1b[?1049h\x1b[?7l")
	requireAfterTheReprints(t, j.render, "\x1b[?7l")
	j.then(t, "\x1b[?1049l\x1b[?7hY")
	require.Equal(t, "Y", cellAt(j.b, 0, 1).Content)
}

// ?47 carries the cursor both ways, so where the alternate screen's cursor
// is when ?47l comes is where the main screen's is after.
func TestReplayAlt47CursorCarriesBack(t *testing.T) {
	j := joinAt(t, 80, 24, "main\r\n\x1b[?47h\x1b[Halt text\r\n")
	j.then(t, "\x1b[5;1H\x1b[?47lX")
	require.Equal(t, "X", j.b.MainScreen().CellAt(0, 4).Content)
}

// apt's progress bar: a region above a status line on the last row, which
// output then scrolls above.
func TestReplayScrollRegion(t *testing.T) {
	const stream = "Reading package lists...\r\n" +
		"\x1b7\x1b[0;23r\x1b8\x1b[1A" +
		"Unpacking foo\r\n" +
		"\x1b7\x1b[24;0f\x1b[42m\x1b[30mProgress: [ 40%]\x1b[49m\x1b[39m [####......]\x1b8"
	j := joinAt(t, 80, 24, stream)
	require.Equal(t, uv.Rect(0, 0, 80, 23), j.b.ActiveScreen().ScrollRegion())
	for i := range 30 {
		j.then(t, fmt.Sprintf("Setting up package %d\r\n", i))
	}
	require.Equal(t, "Progress: [ 40%] [####......]", j.b.MainScreen().Line(23).String())
}

// vim's way: history on the main screen, then the alternate screen filled.
func TestReplayAltScreenOverMainHistory(t *testing.T) {
	var s strings.Builder
	for i := range 20 {
		fmt.Fprintf(&s, "$ make %d\r\n", i)
	}
	s.WriteString("\x1b[?1049h\x1b[?1h\x1b=\x1b[?2004h\x1b[?25l")
	for y := 1; y <= 6; y++ {
		fmt.Fprintf(&s, "\x1b[%d;1H\x1b[34m~%s\x1b[m", y, strings.Repeat(" ", 78))
	}
	s.WriteString("\x1b[1;1H\x1b[?25h")
	j := joinAt(t, 80, 6, s.String())
	require.NotEmpty(t, *j.bHist)
	j.then(t, "\x1b[?1049l\x1b[?1l\x1b>$ ")
}

// The title and a cursor style other than the default are set, and the
// default style isn't, but by the preamble's reset of the joiner's.
func TestReplayTitleAndCursorStyle(t *testing.T) {
	render, err := renderAt(t, 80, 24, "\x1b]2;the title\x07\x1b[4 qtext\r\n")
	require.NoError(t, err)
	b := vt.NewEmulator(80, 24)
	var title string
	b.SetCallbacks(vt.Callbacks{Title: func(s string) { title = s }})
	_, _ = b.Write(render)
	require.Equal(t, "the title", title)
	style, blink := b.CursorStyle()
	require.Equal(t, vt.CursorUnderline, style)
	require.False(t, blink)

	render, err = renderAt(t, 80, 24, "\x1b[4 q\x1b[1 qtext\r\n")
	require.NoError(t, err)
	// The preamble's own DECSCUSR resets the joiner's.
	require.NotContains(t, string(bytes.TrimPrefix(render, []byte(preamble))), " q")
	require.NotContains(t, string(render), "\x1b]2;")
}

// A title the session set and then cleared, by OSC 2 or OSC 0, is cleared on
// the joiner's terminal too, as the raw ring clears it there. A session that
// never set one, or set only the icon name, by OSC 1, sends none, and leaves
// the joiner's own.
func TestReplayClearsATitleTheSessionCleared(t *testing.T) {
	join := func(t *testing.T, stream string) (joined []byte, title string) {
		t.Helper()
		joined, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		require.NoError(t, fellBack)
		require.True(t, bytes.HasPrefix(joined, []byte(preamble)), "the render, not the raw ring")
		b, _ := newReference(80, 24)
		got := watchTitle(b)
		_, _ = b.WriteString("\x1b]2;the joiner's own\x07")
		_, _ = b.Write(joined)
		return joined, got.title
	}
	for _, clear := range []string{"\x1b]2;\x07", "\x1b]0;\x1b\\"} {
		_, title := join(t, "\x1b]2;the title\x07text\r\n"+clear+"more\r\n")
		require.Empty(t, title, "cleared by %q", clear)
	}
	for _, stream := range []string{"text\r\n", "\x1b]1;an icon name\x07text\r\n"} {
		joined, title := join(t, stream)
		require.NotContains(t, string(joined), "\x1b]2;")
		require.Equal(t, "the joiner's own", title)
	}
}

// A colour the session set by OSC, which the query filter lets into the ring
// as it drops only the queries, and which the render doesn't restore, fails
// it, named, until its reset: an entry of xterm's colour table, a palette
// entry or a special colour, by OSC 4 or 5, until OSC 104 or 105 resets it,
// and a dynamic colour, by OSC 10 to 19, by any specification, one of several
// in one OSC included, until its own reset, OSC 110 to 119. A change xterm
// and other terminals read apart counts as a setting too: OSC 110 to 119 with
// anything after the ';', which xterm ignores and others read as a reset, and
// an OSC 4, 5, 104 or 105 naming an entry xterm can't read, which it stops
// at. A colour set and then reset renders, as do a reset alone and a query,
// which never reaches the ring.
func TestReplayFailsOnAChangedColour(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte(stream+"text\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"a palette entry", "\x1b]4;1;rgb:ff/00/00\x07"},
		{"a special colour", "\x1b]5;0;rgb:ff/00/00\x1b\\"},
		{"a special colour by its palette number", "\x1b]4;256;rgb:ff/00/00\x07"},
		{"the foreground", "\x1b]10;#ffffff\x07"},
		{"the background", "\x1b]11;rgb:00/00/80\x07"},
		{"the background by a name", "\x1b]11;navy\x1b\\"},
		{"the cursor colour", "\x1b]12;rgb:ff/00/00\x07"},
		{"the highlight background", "\x1b]17;rgb:ff/00/00\x07"},
		{"the last dynamic colour, and one past it", "\x1b]19;rgb:ff/00/00;rgb:00/ff/00\x07"},
		{"the background after the foreground", "\x1b]10;rgb:ff/ff/ff;rgb:00/00/00\x07\x1b]110\x07"},
		{"another colour's reset", "\x1b]11;rgb:00/00/80\x07\x1b]110\x07"},
		{"the background reset, then set", "\x1b]111\x07\x1b]11;rgb:00/00/80\x07"},
		{"the background reset with more than xterm reads", "\x1b]11;rgb:00/00/80\x07\x1b]111;rgb:00/00/80\x07"},
		{"the whole table reset, then an entry set", "\x1b]104\x07\x1b]4;1;rgb:ff/00/00\x07"},
		{"two entries set, the first reset", "\x1b]4;1;rgb:ff/00/00;2;rgb:00/ff/00\x07\x1b]104;1\x07"},
		{"a special colour set, the palette reset", "\x1b]5;0;rgb:ff/00/00\x07\x1b]104;0\x07"},
		{"the special colours reset, then one set", "\x1b]105\x07\x1b]5;4;rgb:ff/00/00\x07"},
		{"an entry xterm can't read", "\x1b]4;1x;rgb:ff/00/00\x07"},
		{"an entry past the table", "\x1b]4;261;rgb:ff/00/00\x07"},
		{"a reset list xterm stops in", "\x1b]104;1;x;2\x07"},
		{"a reset list with an empty entry", "\x1b]104;;1\x07"},
		{"a special colour past the last", "\x1b]105;5\x07"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a changed palette or dynamic colour")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"the background reset", "\x1b]11;rgb:00/00/80\x07\x1b]111\x07"},
		{"each one reset", "\x1b]10;red;blue;green\x07\x1b]110\x07\x1b]111;\x07\x1b]112\x1b\\"},
		{"a palette entry reset", "\x1b]4;1;rgb:ff/00/00\x07\x1b]104;1\x07"},
		{"the whole table reset", "\x1b]4;1;rgb:ff/00/00\x07\x1b]5;0;rgb:ff/00/00\x07\x1b]104\x07"},
		{"a special colour reset", "\x1b]4;258;rgb:ff/00/00\x07\x1b]105;2\x07"},
		{"a palette reset alone", "\x1b]104\x07"},
		{"a query", "\x1b]11;?\x07\x1b]4;1;?\x07"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
		})
	}
}

// xtermColours is what xterm holds of the colours a program sets by OSC, each
// as the specification that set it, and "", or no entry, where it is at its
// default: the ten dynamic colours, OSC 10 to 19, and the colour table, the
// 256 palette entries and then the five special colours, OSC 4 and 5.
type xtermColours struct {
	dynamic [10]string
	table   map[int]string
}

// coloursOf is what xterm holds of those colours once a terminal at its
// defaults is given p, the OSCs these tests send read as xterm reads them:
// each specification of OSC 10 to 19 sets the next dynamic colour on, and
// OSC 110 to 119 with nothing after the number or its ';' resets one; OSC 4
// and 5 set the entries each pair names, OSC 5 numbering the special colours
// from 0, and OSC 104 and 105 reset those listed, or with none listed, the
// whole table, or every special colour.
func coloursOf(p []byte) xtermColours {
	c := xtermColours{table: map[int]string{}}
	term := vt.NewEmulator(80, 24)
	term.SetReplyFunc(func([]byte) {})
	for i := range c.dynamic {
		term.RegisterOscHandler(10+i, func(data []byte) bool {
			for k, colour := range strings.Split(string(data), ";")[1:] {
				if i+k < len(c.dynamic) && colour != "" {
					c.dynamic[i+k] = colour
				}
			}
			return true
		})
		term.RegisterOscHandler(110+i, func(data []byte) bool {
			if _, rest, _ := strings.Cut(string(data), ";"); rest == "" {
				c.dynamic[i] = ""
			}
			return true
		})
	}
	for _, osc := range []struct{ set, reset, first int }{{4, 104, 0}, {5, 105, 256}} {
		term.RegisterOscHandler(osc.set, func(data []byte) bool {
			f := strings.Split(string(data), ";")[1:]
			for k := 0; k+1 < len(f); k += 2 {
				n, _ := strconv.Atoi(f[k])
				c.table[osc.first+n] = f[k+1]
			}
			return true
		})
		term.RegisterOscHandler(osc.reset, func(data []byte) bool {
			_, list, _ := strings.Cut(string(data), ";")
			if list == "" {
				maps.DeleteFunc(c.table, func(n int, _ string) bool { return n >= osc.first })
				return true
			}
			for _, f := range strings.Split(list, ";") {
				n, _ := strconv.Atoi(f)
				delete(c.table, osc.first+n)
			}
			return true
		})
	}
	_, _ = term.Write(p)
	return c
}

// A colour the session reset, which a raw replay resets on the joiner's
// terminal as well, the render resets there too, at its end: each dynamic
// colour whose last change was its reset, by that reset, OSC 110 to 119; and
// the entries of xterm's colour table whose last change was a reset, the
// palette's by one OSC 104 listing them, then the special colours' by one
// OSC 105 listing them, numbered from 0, as every terminal that has OSC 105
// reads them, where only some read them in OSC 104. Each lists none once
// every entry it resets was reset, but OSC 104 only once the whole table was,
// as xterm's OSC 104 alone resets the special colours too. A joiner whose own
// programs left it colours of their own then ends with the ones a raw replay
// leaves it, those the session reset at their defaults and the rest its own,
// as xterm reads the OSCs (see coloursOf). The first case is x/vt's own
// background too, which x/vt reads only from a reset with nothing after the
// number.
func TestReplayResetsTheColoursTheSessionReset(t *testing.T) {
	const own = "\x1b]10;rgb:aa/aa/aa\x07\x1b]11;rgb:00/00/80\x07\x1b]12;rgb:ff/00/00\x07\x1b]17;rgb:00/ff/00\x07" +
		"\x1b]4;1;rgb:ff/00/00;200;rgb:00/ff/00\x07\x1b]5;0;rgb:00/00/ff\x07"
	join := func(t *testing.T, stream, resets string) []byte {
		t.Helper()
		sent, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
		require.NoError(t, fellBack)
		require.True(t, bytes.HasPrefix(sent, []byte(preamble)), "the render, not the raw ring")
		require.True(t, bytes.HasSuffix(sent, []byte(resets)), "%q", sent)
		require.Equal(t, strings.Count(resets, "\x1b]1"), bytes.Count(sent, []byte("\x1b]1")), "%q", sent)
		require.Equal(t, coloursOf([]byte(own+stream)), coloursOf([]byte(own+string(sent))), "the joiner's colours: %q", sent)
		return sent
	}

	var entries strings.Builder
	for i := range 256 {
		fmt.Fprintf(&entries, ";%d", i)
	}
	everyEntry := entries.String()

	t.Run("the background, on x/vt", func(t *testing.T) {
		const stream = "\x1b]11;rgb:00/80/00\x07text\r\n\x1b]111\x07more\r\n"
		sent := join(t, stream, "\x1b]111\x07")
		a, _ := newReference(80, 24)
		_, _ = a.WriteString(stream)
		b, _ := newReference(80, 24)
		_, _ = b.WriteString(own)
		before := b.BackgroundColor()
		_, _ = b.Write(sent)
		require.NotEqual(t, before, b.BackgroundColor(), "the joiner's own background")
		require.Equal(t, a.BackgroundColor(), b.BackgroundColor())
	})

	for _, tc := range []struct{ name, stream, resets string }{
		{"none", "text\r\n", ""},
		{"the background", "text\r\n\x1b]111\x07more\r\n", "\x1b]111\x07"},
		{"the foreground and the cursor colour, ended by ST", "text\r\n\x1b]110\x1b\\\x1b]112\x1b\\more\r\n", "\x1b]110\x07\x1b]112\x07"},
		{"the background, by a reset with nothing after its ';'", "\x1b]11;navy\x07\x1b]111;\x07text\r\n", "\x1b]111\x07"},
		{"the highlight colours", "\x1b]17;rgb:00/00/80\x07\x1b]117\x07\x1b]119\x07text\r\n", "\x1b]117\x07\x1b]119\x07"},
		{"three set by one, each reset", "\x1b]10;red;blue;green\x07\x1b]112\x07\x1b]110\x07\x1b]111\x07text\r\n", "\x1b]110\x07\x1b]111\x07\x1b]112\x07"},
		{"the whole table", "text\r\n\x1b]104\x07more\r\n", "\x1b]104\x07\x1b]105\x07"},
		{"the whole table, by an empty list", "\x1b]104;\x07text\r\n", "\x1b]104\x07\x1b]105\x07"},
		{"a palette entry", "\x1b]104;1\x07text\r\n", "\x1b]104;1\x07"},
		{"a palette entry, set and then reset", "\x1b]4;1;rgb:00/00/80\x07text\r\n\x1b]104;1\x07more\r\n", "\x1b]104;1\x07"},
		{"palette entries, in the table's order", "\x1b]4;7;red;3;blue\x07\x1b]104;7;3\x07text\r\n", "\x1b]104;3;7\x07"},
		{"a special colour", "\x1b]5;0;rgb:00/00/80\x07\x1b]105;0\x07text\r\n", "\x1b]105;0\x07"},
		{"a special colour by its palette number", "\x1b]4;258;red\x07\x1b]104;258\x07text\r\n", "\x1b]105;2\x07"},
		{"special colours, in their order", "\x1b]105;4;1\x07text\r\n", "\x1b]105;1;4\x07"},
		{"every special colour", "\x1b]105\x07text\r\n", "\x1b]105\x07"},
		{"every special colour, by their palette numbers", "\x1b]104;260;259;258;257;256\x07text\r\n", "\x1b]105\x07"},
		{"a palette entry and a special colour", "\x1b]105;1\x07\x1b]104;3\x07text\r\n", "\x1b]104;3\x07\x1b]105;1\x07"},
		{"every palette entry, listed", "\x1b]104" + everyEntry + "\x07text\r\n", "\x1b]104" + everyEntry + "\x07"},
		{"every palette entry, listed, and every special colour", "\x1b]104" + everyEntry + "\x07\x1b]105\x07text\r\n", "\x1b]104\x07\x1b]105\x07"},
		{"the whole table, then an entry again", "\x1b]4;1;red\x07\x1b]104\x07\x1b]104;1\x07text\r\n", "\x1b]104\x07\x1b]105\x07"},
		{"an entry, then the whole table", "\x1b]104;1\x07\x1b]4;2;red\x07\x1b]104\x07text\r\n", "\x1b]104\x07\x1b]105\x07"},
		{"a palette entry and the background", "\x1b]111\x07\x1b]104;200\x07text\r\n", "\x1b]104;200\x07\x1b]111\x07"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			join(t, tc.stream, tc.resets)
		})
	}
}

// An OSC 6, or its alias OSC 106, fails the render, named, whatever follows:
// xterm turns on or off, for each pair of a special colour and a flag, whether
// it draws bold, underlined, blinking, reversed or italic text in that colour,
// which x/vt doesn't keep, where a raw replay sets each on the joiner's
// terminal, and its RIS leaves them. Every one counts: iTerm2 reads OSC 6 as a
// tab's colour, which xterm ignores. xterm has no query of them, and the
// query filter drops none. The special colours' own reset renders, and their
// query, which the filter drops, does too.
func TestReplayFailsOnASpecialColourMode(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"underlined text in its colour", "\x1b]6;1;1\x07"},
		{"bold text not, by OSC 106", "\x1b]106;0;0\x1b\\"},
		{"several", "\x1b]6;0;1;3;1;4;0\x07"},
		{"one turned on, then off", "\x1b]6;1;1\x07\x1b]6;1;0\x07"},
		{"one, then RIS", "\x1b]106;2;1\x07\x1bc"},
		{"one, then the special colours reset", "\x1b]6;1;1\x07\x1b]105\x07"},
		{"iTerm2's tab colour", "\x1b]6;1;bg;red;brightness;255\x07"},
		{"one with no data, which xterm ignores", "\x1b]6\x07"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a special colour mode")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"the special colours reset", "\x1b]105\x07"},
		{"one special colour reset", "\x1b]105;1\x07"},
		{"a special colour asked for", "\x1b]5;1;?\x07"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
		})
	}
}

// An image the session drew, which the query filter lets into the ring, fails
// the render, named, as x/vt draws none and the render has none to send: a
// sixel, a kitty graphics command (an APC whose first byte is G) other than
// the query the filter drops, and an iTerm2 inline image, whole or in parts.
// Another APC, and an OSC 1337 that draws nothing, render.
func TestReplayFailsOnTerminalGraphics(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"a sixel", "\x1bPq#0;2;100;0;0#0~~-~~\x1b\\"},
		{"a sixel with parameters", "\x1bP0;1;0q\"1;1;2;2#0~~\x1b\\"},
		{"a kitty image", "\x1b_Ga=T,f=100,i=1;iVBORw0KGgo=\x1b\\"},
		{"a kitty placement", "\x1b_Ga=p,i=1\x1b\\"},
		{"an iTerm2 image", "\x1b]1337;File=inline=1;size=8:iVBORw0KGgo=\x07"},
		{"an iTerm2 image in parts", "\x1b]1337;MultipartFile=inline=1\x07\x1b]1337;FilePart=iVBORw0KGgo=\x07\x1b]1337;FileEnd\x07"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "terminal graphics")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"a kitty graphics query", "\x1b_Gi=31,a=q;AAAA\x1b\\"},
		{"another APC", "\x1b_Xan application's own\x1b\\"},
		{"an OSC 1337 that draws nothing", "\x1b]1337;RequestAttention=yes\x07"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
		})
	}
}

// A DCS the session sent that changes the terminal's state, which x/vt has no
// handler for and drops, fails the render, named, as a raw replay carries it
// to the joiner's terminal, which acts on it: a tmux passthrough, which a
// joiner running in tmux hands on to the terminal tmux runs in; DECUDK's keys,
// DECDLD's soft font, ReGIS, under whose final iTerm2's tmux integration
// begins too, DECRSTS's and DECRSPS's restores, XTSETTCAP, DECAUPSS, DECDMAC's
// macros and kitty's remote control, which runs a command in a kitty joiner
// that allows it. So does one whose first byte is an ESC or a C0 control,
// which x/vt reads as the string's data, where a DEC terminal ends the string
// at the ESC, or ignores the control and reads the string after it, here
// DECUDK: the filter drops either after an ESC P, so each comes by the 8-bit
// introducer, which the filter passes. An image in a tmux passthrough is read
// as a DEC terminal reads it, the DCS ended by its first ESC and the image a
// sequence of its own, so it is named as the image.
//
// Any other DCS renders, as xterm ignores it, and so a raw replay hands the
// joiner something it drops too: vim's probe of whether the terminal
// does, one under a final no terminal acts on, one under a private prefix,
// with a parameter after its intermediate or under a listed final after a
// private prefix, which xterm reads as the final, and one under tmux's final
// that isn't its passthrough. So do the queries the filter drops, and
// synchronized output's DCS form, DCS = 1 s and DCS = 2 s, which only holds
// back the drawing, as ?2026 does; anything else under its key doesn't.
func TestReplayFailsOnADeviceControlString(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"a tmux passthrough", "\x1bPtmux;\x1b\x1b[31mX\x1b\\"},
		{"a tmux passthrough of text", "\x1bPtmux;hello\x1b\\"},
		{"DECUDK", "\x1bP1;1|17/736F6D65\x1b\\"},
		{"DECDLD", "\x1bP0;1;1;4;0;0{ @~~~~/~~~~\x1b\\"},
		{"ReGIS", "\x1bP0pS(E)\x1b\\"},
		{"iTerm2's tmux integration", "\x1bP1000p%exit\r\n\x1b\\"},
		{"DECRSTS", "\x1bP2$p1;2;100;0;0\x1b\\"},
		{"DECRSPS's cursor", "\x1bP1$t1;1;1;@;@;@;0;2;@;BB%5%5\x1b\\"},
		{"DECRSPS's tab stops", "\x1bP2$t9/17/25\x1b\\"},
		{"XTSETTCAP", "\x1bP+p544e=787465726d\x1b\\"},
		{"DECAUPSS", "\x1bP1!uA\x1b\\"},
		{"DECDMAC", "\x1bP1;0;0!zA\x1b\\"},
		{"kitty's remote control", "\x1bP@kitty-cmd{\"cmd\":\"ls\"}\x1b\\"},
		{"an ESC first", "\x90\x1b[31mX\x1b\\"},
		{"a C0 control first", "\x90\r1;1|17/736F6D65\x1b\\"},
		{"the synchronized output key with another value", "\x1bP=3s\x1b\\"},
		{"the synchronized output key with two parameters", "\x1bP=1;2s\x1b\\"},
		{"the synchronized output key with data", "\x1bP=1sx\x1b\\"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a device control string")
		})
	}
	t.Run("an image in a tmux passthrough", func(t *testing.T) {
		requireIneligible(t, join(t, "\x1bPtmux;\x1b\x1b_Ga=T,f=100;AAAA\x1b\x1b\\\x1b\\"), "terminal graphics")
	})
	for _, tc := range []struct{ name, stream string }{
		{"vim's probe", "\x1b[3;1H\x1bPzz\x1b\\\x1b[0%m"},
		{"an unknown final", "\x1bP1;2xsome data\x1b\\"},
		{"a private prefix", "\x1bP?1x\x1b\\"},
		{"a parameter after the intermediate", "\x1bP$1x\x1b\\"},
		{"DECUDK's final after a private prefix", "\x1bP?1;1|17/736F6D65\x1b\\"},
		{"tmux's final, not its passthrough", "\x1bPtmux\x1b\\"},
		{"DECRQSS", "\x1bP$qm\x1b\\"},
		{"XTGETTCAP", "\x1bP+q544e\x1b\\"},
		{"a synchronized update begun", "\x1bP=1s\x1b\\"},
		{"a synchronized update ended", "\x1bP=2s\x1b\\"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
		})
	}
}

// vimStartup is what Vim 9.2 sent an 80x24 terminal from its start until it
// waited for a key, and vimQuit what it sent then for a typed :q, captured by
// script(1) with no vimrc (so defaults.vim), TERM=xterm-256color and a UTF-8
// locale. Among the probes it sends at startup is its check that the
// terminal ignores what it doesn't know: on the third row, a DCS no terminal
// acts on and a CSI with an intermediate, then a cursor position request, to
// see whether the cursor moved.
const (
	vimStartup = "\x1b[?1006;1000h\x1b[?1002h\x1b[?1049h\x1b[22;0;0t\x1b[>4;2m\x1b[?1h\x1b=\x1b[?2004h\x1b[?1004h" +
		"\x1b[1;24r\x1b[?12h\x1b[?12l\x1b[22;2t\x1b[22;1t\x1b[27m\x1b[23m\x1b[29m\x1b[m" +
		"\x1b[H\x1b[2J\x1b[2;1H▽\x1b[6n\x1b[2;1H  \x1b[3;1H\x1bPzz\x1b\\\x1b[0%m\x1b[6n" +
		"\x1b[3;1H           \x1b[1;1H\x1b[>c\x1b]10;?\x07\x1b]11;?\x07\x1b[?25l" +
		"\x1b[2;1H\x1b[94m~                                                                               " +
		"\x1b[3;1H~                                                                               " +
		"\x1b[4;1H~                                                                               " +
		"\x1b[5;1H~                                                                               " +
		"\x1b[6;1H~                                                                               " +
		"\x1b[7;1H~                                                                               " +
		"\x1b[8;1H~                                                                               " +
		"\x1b[9;1H~                                                                               " +
		"\x1b[10;1H~                                                                               " +
		"\x1b[11;1H~                                                                               " +
		"\x1b[12;1H~                                                                               " +
		"\x1b[13;1H~                                                                               " +
		"\x1b[14;1H~                                                                               " +
		"\x1b[15;1H~                                                                               " +
		"\x1b[16;1H~                                                                               " +
		"\x1b[17;1H~                                                                               " +
		"\x1b[18;1H~                                                                               " +
		"\x1b[19;1H~                                                                               " +
		"\x1b[20;1H~                                                                               " +
		"\x1b[21;1H~                                                                               " +
		"\x1b[22;1H~                                                                               " +
		"\x1b[23;1H~                                                                               \x1b[m" +
		"\x1b[24;63H0,0-1\x1b[9CAll\x1b[7;32HVIM - Vi IMproved\x1b[9;33Hversion 9.2.1200" +
		"\x1b[10;29Hby Bram Moolenaar et al.\x1b[11;19HVim is open source and freely distributable" +
		"\x1b[13;26HHelp poor children in Uganda!" +
		"\x1b[14;18Htype  :help Kuwasha\x1b[34m<Enter>\x1b[m    for information " +
		"\x1b[16;18Htype  :q\x1b[34m<Enter>\x1b[m               to exit         " +
		"\x1b[17;18Htype  :help\x1b[34m<Enter>\x1b[m  or  \x1b[34m<F1>\x1b[m  for on-line help" +
		"\x1b[18;18Htype  :help version9\x1b[34m<Enter>\x1b[m   for version info\x1b[?25h" +
		"\x1b[1;1H\x1b[?4m"
	vimQuit = "\x1b[?25l\x1b[24;63H\x1b[K" +
		"\x1b[24;1H:q\r\x1b[?1006;1000l\x1b[?1002l\x1b[?2004l\x1b[>4;m\x1b[23;2t\x1b[23;1t" +
		"\x1b[24;1H\x1b[K" +
		"\x1b[24;1H\x1b[?1004l\x1b[?2004l\x1b[?1l\x1b>\x1b[?1049l\x1b[23;0;0t\x1b[?25h\x1b[>4;m"
)

// A join while vim's startup is in the ring renders, its probe among it, and
// leaves the joiner as the session's terminal, before vim quits and after.
func TestReplayRendersVimsStartup(t *testing.T) {
	j := joinOwn(t, 80, 24, "", vimStartup)
	j.then(t, vimQuit)
}

// dcsLog is a logger for x/vt that records, of the DCS x/vt logged as having
// no handler for, whether one changes the terminal's state and whether one
// draws, as dcsEffect reads each. It reads x/vt's own message, so it knows
// nothing of the keys the emulation registers.
type dcsLog struct{ logged, changes, draws bool }

func (l *dcsLog) Printf(format string, v ...any) {
	if format != "unhandled sequence: DCS %q %q" || len(v) != 2 {
		return
	}
	l.logged = true
	head, _ := v[0].(string)
	data, _ := v[1].([]byte)
	changes, draws := dcsEffect(head, data)
	l.changes = l.changes || changes
	l.draws = l.draws || draws
}

// dcsEffect is whether a DCS changes the terminal's state, and whether it
// draws a sixel, from head, its prefix, parameters, intermediate and final as
// x/vt writes them, and its data. x/vt writes a prefix only first, the
// parameters as numbers, ';' and ':', an intermediate only just before the
// final, and nothing at all for a string whose first byte was a C0 control or
// an ESC, which a DEC terminal reads otherwise. The ones that change it are
// tmux's passthrough, by its data under any prefix, parameters and
// intermediate, as tmux reads it; DECUDK, DECDLD, ReGIS, DECRSTS, DECRSPS,
// XTSETTCAP, DECAUPSS, DECDMAC and kitty's own, under @, under no prefix;
// and synchronized output's key with anything but DCS = 1 s or DCS = 2 s.
func dcsEffect(head string, data []byte) (changes, draws bool) {
	if head == "" {
		return true, false
	}
	var prefix, inter byte
	final := head[len(head)-1]
	if len(head) > 1 && strings.IndexByte("<=>?", head[0]) >= 0 {
		prefix = head[0]
	}
	if len(head) > 1 && head[len(head)-2] >= 0x20 && head[len(head)-2] <= 0x2f {
		inter = head[len(head)-2]
	}
	switch {
	case final == 't' && bytes.HasPrefix(data, []byte("mux;")):
		return true, false
	case prefix == '=' && inter == 0 && final == 's':
		return (head != "=1s" && head != "=2s") || len(data) != 0, false
	case prefix != 0:
		return false, false
	}
	switch [2]byte{inter, final} {
	case [2]byte{0, 'q'}:
		return false, true
	case [2]byte{0, '|'}, [2]byte{0, '{'}, [2]byte{0, 'p'}, [2]byte{'$', 'p'}, [2]byte{'$', 't'}, [2]byte{'+', 'p'}, [2]byte{'!', 'u'}, [2]byte{'!', 'z'}, [2]byte{0, '@'}:
		return true, false
	}
	return false, false
}

// The emulation notes a DCS, as one that changes the terminal's state or as a
// sixel, exactly when x/vt drops one that dcsEffect says does, by x/vt's own
// log: for each introducer, 7-bit and 8-bit, and each terminator, around
// every body of up to four bytes drawn from C0 controls, DEL, a C1 byte,
// every prefix, parameter bytes, the intermediates and the finals at each end
// of their ranges, and every such body after an ESC; and around every header
// of at most a prefix, a parameter and an intermediate before any byte from
// 0x30 to 0x7E, with no data, data, the mux; of tmux's passthrough, alone
// or before more, or mux, which falls short of it. A key the emulation misses, or one it notes beyond
// those, fails it, and so does a DCS x/vt comes to handle itself, which it
// then no longer logs.
func TestReplayNotesTheDCSThatChangeState(t *testing.T) {
	e := start(t, captureOf("", event(1, 0, 80, 24)))
	log := &dcsLog{}
	e.term.SetLogger(log)
	alphabet := []byte{
		0x00, 0x07, 0x08, 0x0d, 0x0e, 0x18, 0x1a, 0x7f, 0x80, // C0 controls, DEL and a C1 byte
		'<', '=', '>', '?', // the prefixes, '?' also the last final after an intermediate
		'0', '1', ';', ':', // parameters, '0' also the first final after an intermediate
		0x20, 0x2f, // the intermediates' ends
		0x40, 0x7e, 's', 'q', // finals
	}
	bodies := [][]byte{nil}
	for n, from := 0, 0; n < 4; n++ {
		to := len(bodies)
		for _, b := range bodies[from:to] {
			for _, c := range alphabet {
				bodies = append(bodies, append(append([]byte(nil), b...), c))
			}
		}
		from = to
	}
	for _, b := range bodies {
		if len(b) < 4 {
			bodies = append(bodies, append([]byte{0x1b}, b...))
		}
	}
	inters := []byte{0} // none
	for b := byte(0x20); b <= 0x2f; b++ {
		inters = append(inters, b)
	}
	for _, prefix := range []string{"", "<", "=", ">", "?"} {
		for _, param := range []string{"", "1"} {
			for _, inter := range inters {
				for final := byte(0x30); final <= 0x7e; final++ {
					for _, data := range []string{"", "x", "mux;", "mux;x", "mux"} {
						b := []byte(prefix + param)
						if inter != 0 {
							b = append(b, inter)
						}
						bodies = append(bodies, append(append(b, final), data...))
					}
				}
			}
		}
	}

	var seq []byte
	logged, changes, draws := 0, 0, 0
	for _, intro := range []string{"\x1bP", "\x90"} {
		for _, end := range []string{"\x1b\\", "\x9c"} {
			for _, body := range bodies {
				// A CAN after each puts the parser back in ground, whatever
				// the body left it in, and dispatches nothing.
				seq = append(append(append(append(seq[:0], intro...), body...), end...), 0x18)
				e.dcs, e.graphics = false, false
				*log = dcsLog{}
				if _, err := e.term.Write(seq); err != nil {
					t.Fatalf("%q: %v", seq, err)
				}
				if e.dcs != log.changes || e.graphics != log.draws {
					t.Fatalf("%q: the emulation noted a DCS: %v, an image: %v; x/vt dropped one that changes the state: %v, that draws: %v",
						seq, e.dcs, e.graphics, log.changes, log.draws)
				}
				if log.logged {
					logged++
				}
				if log.changes {
					changes++
				}
				if log.draws {
					draws++
				}
			}
		}
	}
	t.Logf("%d sequences, %d with a DCS x/vt logged: %d that change the state, %d that draw", 4*len(bodies), logged, changes, draws)
	require.Positive(t, logged, "x/vt's log was read")
	require.Positive(t, changes, "a DCS that changes the state was sent")
	require.Positive(t, draws, "a sixel was sent")
}

// selectionsOf is what xterm's selections hold once a terminal that holds
// none is given p: each OSC 52 that writes one applied in turn, as xterm does.
// An empty Pc names s and 0, a character xterm has no selection for names
// nothing, a Pd of ? asks rather than writes, and an OSC 52 with no ';' after
// Pc does nothing.
func selectionsOf(p []byte) map[byte]string {
	held := map[byte]string{}
	term := vt.NewEmulator(80, 24)
	term.SetReplyFunc(func([]byte) {})
	term.RegisterOscHandler(52, func(data []byte) bool {
		f := strings.SplitN(string(data), ";", 3)
		if len(f) < 3 || f[2] == "?" {
			return true
		}
		pc := f[1]
		if pc == "" {
			pc = "s0"
		}
		for _, c := range []byte(pc) {
			if strings.IndexByte("cpqs01234567", c) >= 0 {
				held[c] = f[2]
			}
		}
		return true
	})
	_, _ = term.Write(p)
	return held
}

// The clipboard writes the session made by OSC 52, which the query filter
// lets into the ring and a raw replay hands the joiner in order, end on the
// joiner as they would: the render sends, last, each write that is still
// the last to one of xterm's selections, in the stream's order, as the stream
// sent it, and no other. A session that wrote none sends none.
func TestReplayReplaysTheClipboard(t *testing.T) {
	join := func(t *testing.T, stream string) []byte {
		t.Helper()
		joined, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
		require.NoError(t, fellBack)
		require.True(t, bytes.HasPrefix(joined, []byte(preamble)), "the render, not the raw ring")
		require.Equal(t, selectionsOf([]byte(stream)), selectionsOf(joined), "the joiner's selections: %q", joined)
		return joined
	}

	joined := join(t, "\x1b]52;c;Zmlyc3Q=\x07text\r\n\x1b]52;p;cHJpbWFyeQ==\x1b\\\x1b]52;c;bGFzdA==\x07more\r\n")
	require.True(t, bytes.HasSuffix(joined, []byte("\x1b]52;p;cHJpbWFyeQ==\x07\x1b]52;c;bGFzdA==\x07")), "%q", joined)
	require.Equal(t, 2, bytes.Count(joined, []byte("\x1b]52;")), "%q", joined)

	for _, tc := range []struct {
		name, stream string
		sent         int
	}{
		{"none", "", 0},
		{"one write to two selections, then one of them", "\x1b]52;cp;QQ==\x07\x1b]52;c;Qg==\x07", 2},
		{"the default, then both its selections", "\x1b]52;;QQ==\x07\x1b]52;s0;Qg==\x07", 1},
		{"the default, then one of its selections", "\x1b]52;;QQ==\x07\x1b]52;s;Qg==\x07", 2},
		{"a clear", "\x1b]52;c;QQ==\x07\x1b]52;c;!\x07", 1},
		{"a selection xterm doesn't have", "\x1b]52;c;QQ==\x07\x1b]52;x;Qg==\x07", 1},
		{"no data", "\x1b]52;c;QQ==\x07\x1b]52;c\x07", 1},
		{"a query, which the filter drops", "\x1b]52;c;QQ==\x07\x1b]52;c;?\x07", 1},
		{"a number with a leading zero", "\x1b]052;c;QQ==\x07", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			joined := join(t, tc.stream+"text\r\n")
			require.Equal(t, tc.sent, bytes.Count(joined, []byte("\x1b]52;")), "%q", joined)
		})
	}

	// A query that reached the emulation all the same is no write.
	render, err := renderAt(t, 80, 24, "\x1b]52;c;?\x07text\r\n")
	require.NoError(t, err)
	require.NotContains(t, string(render), "\x1b]52;")

	// A write the stream is still inside at the join reaches the joiner once,
	// raw, after the render, and the rest of the stream completes it there:
	// a short one the query filter still holds, and one past the filter's
	// hold, which the ring ends inside, after the handoff point.
	for _, data := range []string{"QQ==", strings.Repeat("A", 400)} {
		head := "text\r\n\x1b]52;c;" + data
		joined, fellBack := fanOut(t, New(), []byte(head), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
		require.NoError(t, fellBack)
		require.True(t, bytes.HasPrefix(joined, []byte(preamble)), "the render, not the raw ring")
		require.True(t, bytes.HasSuffix(joined, []byte("\x1b]52;c;"+data)), "%q", joined)
		whole := append(joined, "\x07more\r\n"...)
		require.Equal(t, 1, bytes.Count(whole, []byte("\x1b]52;")), "%q", whole)
		require.Equal(t, selectionsOf([]byte(head+"\x07more\r\n")), selectionsOf(whole))
	}
}

// cwdOf is the working directory a terminal fed p was last told of, by
// OSC 7, and whether it was told of one at all.
func cwdOf(p []byte) (dir string, told bool) {
	term := vt.NewEmulator(80, 24)
	term.SetReplyFunc(func([]byte) {})
	term.SetCallbacks(vt.Callbacks{WorkingDirectory: func(d string) { dir, told = d, true }})
	_, _ = term.Write(p)
	return dir, told
}

// The working directory the session last reported by OSC 7, which the query
// filter lets into the ring and a raw replay hands the joiner with every
// earlier one, ends on the joiner as it would: the render sends the last one,
// as the stream sent it, ended by BEL, near its end, before the clipboard
// writes. An empty one too, which clears it; one x/vt reads as no report, with
// no ';' after the number, and a session that reported none, send none.
func TestReplayReplaysTheWorkingDirectory(t *testing.T) {
	join := func(t *testing.T, stream string) []byte {
		t.Helper()
		joined, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
		require.NoError(t, fellBack)
		require.True(t, bytes.HasPrefix(joined, []byte(preamble)), "the render, not the raw ring")
		wantDir, wantTold := cwdOf([]byte(stream))
		gotDir, gotTold := cwdOf(joined)
		require.Equal(t, wantTold, gotTold, "told of one: %q", joined)
		require.Equal(t, wantDir, gotDir, "%q", joined)
		return joined
	}

	joined := join(t, "\x1b]7;file://host/first\x07text\r\n\x1b]7;file://host/the;last\x1b\\more\r\n")
	require.True(t, bytes.HasSuffix(joined, []byte("\x1b]7;file://host/the;last\x07")), "%q", joined)
	require.Equal(t, 1, bytes.Count(joined, []byte("\x1b]7;")), "%q", joined)

	joined = join(t, "\x1b]52;c;QQ==\x07\x1b]7;file://host/dir\x07text\r\n")
	require.True(t, bytes.HasSuffix(joined, []byte("\x1b]7;file://host/dir\x07\x1b]52;c;QQ==\x07")), "%q", joined)

	for _, tc := range []struct {
		name, stream string
		sent         int
	}{
		{"none", "", 0},
		{"an empty one", "\x1b]7;file://host/dir\x07\x1b]7;\x07", 1},
		{"one with no ';'", "\x1b]7\x07", 0},
		{"a number with a leading zero", "\x1b]07;file://host/dir\x07", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			joined := join(t, tc.stream+"text\r\n")
			require.Equal(t, tc.sent, bytes.Count(joined, []byte("\x1b]7;")), "%q", joined)
		})
	}
}

// A working directory the render can't fit in its budget with everything
// else fails it, named; one that fits exactly renders.
func TestReplayFailsOnAWorkingDirectoryTooLongToReplay(t *testing.T) {
	setBudget(t, 8<<10)
	join := func(t *testing.T, n int) ([]byte, error) {
		t.Helper()
		stream := "text\r\n\x1b]7;file://host/" + strings.Repeat("a", n) + "\x07more\r\n"
		return fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
	}
	empty, err := join(t, 0)
	require.NoError(t, err)
	fits := budget - len(empty)

	joined, err := join(t, fits)
	require.NoError(t, err)
	require.Len(t, joined, budget)
	_, err = join(t, fits+1)
	requireIneligible(t, err, "a working directory too long to replay")
	_, err = join(t, budget)
	requireIneligible(t, err, "a working directory too long to replay")
}

// The pointer shape the session last set by OSC 22, which the query filter
// lets into the ring and a raw replay hands the joiner with every earlier
// one, ends on the joiner as it would: the render sends the last one xterm
// acts on, its name as the stream sent it, ended by BEL, after the working
// directory and before the clipboard writes. xterm acts on every OSC 22 with
// a name after its ';', one it has no shape for too, which puts back its own
// pointer, and keeps it through RIS; it ignores one with no name, with no
// ';', or with anything but digits before the ';', and a session that set
// none sends none.
func TestReplayReplaysThePointerShape(t *testing.T) {
	join := func(t *testing.T, stream string) []byte {
		t.Helper()
		joined, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
		require.NoError(t, fellBack)
		require.True(t, bytes.HasPrefix(joined, []byte(preamble)), "the render, not the raw ring")
		return joined
	}

	joined := join(t, "\x1b]22;watch\x07text\r\n\x1b]22;hand2\x1b\\more\r\n")
	require.True(t, bytes.HasSuffix(joined, []byte("\x1b]22;hand2\x07")), "%q", joined)
	require.Equal(t, 1, bytes.Count(joined, []byte("\x1b]22;")), "%q", joined)

	joined = join(t, "\x1b]52;c;QQ==\x07\x1b]22;hand2\x07\x1b]7;file://host/dir\x07text\r\n")
	require.True(t, bytes.HasSuffix(joined, []byte("\x1b]7;file://host/dir\x07\x1b]22;hand2\x07\x1b]52;c;QQ==\x07")), "%q", joined)

	for _, tc := range []struct{ name, stream, sent string }{
		{"none", "", ""},
		{"one with no name", "\x1b]22;watch\x07\x1b]22;\x07", "watch"},
		{"one with no ';'", "\x1b]22;watch\x07\x1b]22\x07", "watch"},
		{"one with more than digits before the ';'", "\x1b]22;watch\x07\x1b]22x;hand2\x07", "watch"},
		{"a number with a leading zero", "\x1b]022;hand2\x07", "hand2"},
		{"a name xterm has no shape for", "\x1b]22;hand2\x07\x1b]22;no such shape\x07", "no such shape"},
		{"then RIS", "\x1b]22;hand2\x07\x1bc", "hand2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			joined := join(t, tc.stream+"text\r\n")
			if tc.sent == "" {
				require.Zero(t, bytes.Count(joined, []byte("\x1b]22")), "%q", joined)
				return
			}
			require.True(t, bytes.HasSuffix(joined, []byte("\x1b]22;"+tc.sent+"\x07")), "%q", joined)
			require.Equal(t, 1, bytes.Count(joined, []byte("\x1b]22")), "%q", joined)
		})
	}
}

// A pointer shape the render can't fit in its budget with everything else
// fails it, named, and one longer than the whole budget too, which keeps none
// of its bytes; one that fits exactly renders, and so does one too long that
// a later one replaces.
func TestReplayFailsOnAPointerShapeTooLongToReplay(t *testing.T) {
	setBudget(t, 8<<10)
	stream := func(n int) string {
		return "text\r\n\x1b]22;" + strings.Repeat("a", n) + "\x07more\r\n"
	}
	join := func(t *testing.T, s string) ([]byte, error) {
		t.Helper()
		return fanOut(t, New(), []byte(s), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
	}
	one, err := join(t, stream(1))
	require.NoError(t, err)
	fits := budget - len(one) + 1

	joined, err := join(t, stream(fits))
	require.NoError(t, err)
	require.Len(t, joined, budget)
	_, err = join(t, stream(fits+1))
	requireIneligible(t, err, "a pointer shape too long to replay")
	_, err = join(t, stream(budget))
	requireIneligible(t, err, "a pointer shape too long to replay")

	e := startFor(t, captureOf(stream(budget), event(1, 0, 80, 24)), termsize.Size{Cols: 80, Rows: 24})
	require.True(t, e.pointerOver)
	require.Empty(t, e.pointer)

	joined, err = join(t, "text\r\n\x1b]22;"+strings.Repeat("a", budget)+"\x07\x1b]22;hand2\x07more\r\n")
	require.NoError(t, err)
	require.True(t, bytes.HasSuffix(joined, []byte("\x1b]22;hand2\x07")), "%q", joined)
}

// bellVolumes matches DECSWBV (CSI Ps SP t) and DECSMBV (CSI Ps SP u) with a
// parameter or none.
var bellVolumes = regexp.MustCompile(`\x1b\[[0-9;:]* [tu]`)

// The warning and margin bells' volumes the session last set by DECSWBV
// (CSI Ps SP t) and DECSMBV (CSI Ps SP u), which the query filter lets into
// the ring and a raw replay hands the joiner with every earlier one, end on
// the joiner as they would: the render sends the last of each, by the first
// parameter the stream sent, or none where it sent none, after the pointer
// shape and before the clipboard writes. xterm reads the first parameter
// alone, an omitted one as 0, and every value sets a volume, those it doesn't
// list off; it ignores one with a sub-parameter, and its RIS keeps both. A
// session that set neither sends neither, and neither kitty's keyboard forms
// of CSI u, which carry a prefix, nor DECSCUSR (CSI Ps SP q) is one.
func TestReplayReplaysTheBellVolumes(t *testing.T) {
	join := func(t *testing.T, stream string) []byte {
		t.Helper()
		joined, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
		require.NoError(t, fellBack)
		require.True(t, bytes.HasPrefix(joined, []byte(preamble)), "the render, not the raw ring")
		return joined
	}

	joined := join(t, "\x1b[2 t\x1b[0 utext\r\n\x1b[8 t\x1b[3 umore\r\n")
	require.True(t, bytes.HasSuffix(joined, []byte("\x1b[8 t\x1b[3 u")), "%q", joined)
	require.Len(t, bellVolumes.FindAll(joined, -1), 2, "%q", joined)

	joined = join(t, "\x1b]52;c;QQ==\x07\x1b[3 u\x1b[5 t\x1b]22;hand2\x07text\r\n")
	require.True(t, bytes.HasSuffix(joined, []byte("\x1b]22;hand2\x07\x1b[5 t\x1b[3 u\x1b]52;c;QQ==\x07")), "%q", joined)

	for _, tc := range []struct{ name, stream, sent string }{
		{"none", "", ""},
		{"an omitted parameter", "\x1b[5 t\x1b[ t\x1b[5 u\x1b[ u", "\x1b[ t\x1b[ u"},
		{"an omitted first parameter", "\x1b[;5 t", "\x1b[ t"},
		{"more than one parameter", "\x1b[5;1 t\x1b[2;8 u", "\x1b[5 t\x1b[2 u"},
		{"a value xterm doesn't list", "\x1b[9 t\x1b[100 u", "\x1b[9 t\x1b[100 u"},
		{"a value a window report has", "\x1b[14 t", "\x1b[14 t"},
		{"one with a sub-parameter", "\x1b[5 t\x1b[2:1 t\x1b[5 u\x1b[2:1 u", "\x1b[5 t\x1b[5 u"},
		{"the warning bell alone", "\x1b[4 t", "\x1b[4 t"},
		{"the margin bell alone", "\x1b[4 u", "\x1b[4 u"},
		{"then RIS", "\x1b[6 t\x1b[7 u\x1bc", "\x1b[6 t\x1b[7 u"},
		{"a private prefix", "\x1b[?5 t\x1b[>5 u", ""},
		{"kitty's keyboard forms and DECSCUSR", "\x1b[>1u\x1b[<u\x1b[=1;1u\x1b[?u\x1b[4 q", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			joined := join(t, tc.stream+"text\r\n")
			require.Equal(t, tc.sent, string(bytes.Join(bellVolumes.FindAll(joined, -1), nil)), "%q", joined)
			require.True(t, bytes.HasSuffix(joined, []byte(tc.sent)), "%q", joined)
		})
	}
}

// The progress indicator the session last set, by ConEmu's
// OSC 9 ; 4 ; state ; value, which Windows Terminal and kitty show until a
// state of 0 removes it, and which the query filter lets into the ring and a
// raw replay hands the joiner with every earlier one, ends on the joiner as
// it would: the render sends the last, after the bell's volumes and before
// the clipboard writes, its numbers as both read them. A last one of state 0
// is sent too, which removes the joiner's own indicator, as a raw replay's
// does. Only one both read alike counts, and both keep it through RIS.
// iTerm2's notifications, every other OSC 9, are shown once, and none is
// sent.
func TestReplayReplaysTheProgress(t *testing.T) {
	join := func(t *testing.T, stream string) []byte {
		t.Helper()
		joined, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
		require.NoError(t, fellBack)
		require.True(t, bytes.HasPrefix(joined, []byte(preamble)), "the render, not the raw ring")
		return joined
	}

	joined := join(t, "\x1b]9;4;1;50\x1b\\text\r\n\x1b]9;4;1;80\x07more\r\n")
	require.True(t, bytes.HasSuffix(joined, []byte("\x1b]9;4;1;80\x07")), "%q", joined)
	require.Equal(t, 1, bytes.Count(joined, []byte("\x1b]9;")), "%q", joined)

	joined = join(t, "\x1b]52;c;QQ==\x07\x1b]9;4;1;80\x07\x1b[5 t\x1b]22;hand2\x07text\r\n")
	require.True(t, bytes.HasSuffix(joined, []byte("\x1b]22;hand2\x07\x1b[5 t\x1b]9;4;1;80\x07\x1b]52;c;QQ==\x07")), "%q", joined)

	const set = "\x1b]9;4;1;50\x07"
	for _, tc := range []struct{ name, stream, sent string }{
		{"none", "", ""},
		{"removed", set + "\x1b]9;4;0\x07", "\x1b]9;4;0\x07"},
		{"removed, with a value", set + "\x1b]9;4;0;0\x07", "\x1b]9;4;0;0\x07"},
		{"an error, with no value", "\x1b]9;4;2\x07", "\x1b]9;4;2\x07"},
		{"indeterminate", "\x1b]9;4;3\x07", "\x1b]9;4;3\x07"},
		{"paused, with a value", "\x1b]9;4;4;60\x07", "\x1b]9;4;4;60\x07"},
		{"leading zeros", "\x1b]09;4;01;050\x07", set},
		{"a value past 100", "\x1b]9;4;1;150\x07", "\x1b]9;4;1;100\x07"},
		{"more numbers after the value", "\x1b]9;4;1;50;7\x07", set},
		{"an iTerm2 notification", "\x1b]9;build done\x07", ""},
		{"an iTerm2 notification after it", set + "\x1b]9;build done\x07", set},
		{"a state neither has", set + "\x1b]9;4;5;80\x07", set},
		{"a value that isn't a number", set + "\x1b]9;4;1;x\x07", set},
		{"an empty state", set + "\x1b]9;4;;80\x07", set},
		{"an empty value", set + "\x1b]9;4;1;\x07", set},
		{"no state", set + "\x1b]9;4\x07", set},
		{"a 4 with a leading zero", set + "\x1b]9;04;1;80\x07", set},
		{"more than digits before the ';'", set + "\x1b]9x;4;1;80\x07", set},
		{"then RIS", set + "\x1bc", set},
	} {
		t.Run(tc.name, func(t *testing.T) {
			joined := join(t, tc.stream+"text\r\n")
			if tc.sent == "" {
				require.Zero(t, bytes.Count(joined, []byte("\x1b]9")), "%q", joined)
				return
			}
			require.True(t, bytes.HasSuffix(joined, []byte(tc.sent)), "%q", joined)
			require.Equal(t, 1, bytes.Count(joined, []byte("\x1b]9")), "%q", joined)
		})
	}
}

// A write that supersedes every earlier one leaves none of them past the
// clipboard's length, where its array would still hold their bytes.
func TestReplayClipboardLetsGoOfSupersededWrites(t *testing.T) {
	var c clipboard
	c.write([]byte("c"), []byte("QQ=="))
	c.write([]byte("p"), []byte("Qg=="))
	c.write([]byte("cp"), []byte("Qw=="))
	require.Equal(t, clipboard{{sel: 0b11, pc: "cp", pd: "Qw=="}}, c)
	for _, w := range c[len(c):cap(c)] {
		require.Zero(t, w)
	}
}

// A clipboard write the render can't fit in its budget with everything else
// fails it, named; one longer than the whole budget keeps none of its bytes.
// One that fits exactly renders, and so does one too long that a later write
// supersedes, where one it supersedes only in part still fails it.
func TestReplayFailsOnAClipboardWriteTooLargeToReplay(t *testing.T) {
	setBudget(t, 8<<10)
	stream := func(n int) []byte {
		return []byte("text\r\n\x1b]52;c;" + strings.Repeat("A", n) + "\x07more\r\n")
	}
	join := func(t *testing.T, n int) ([]byte, error) {
		t.Helper()
		return fanOut(t, New(), stream(n), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
	}
	empty, err := join(t, 0)
	require.NoError(t, err)
	fits := budget - len(empty)

	joined, err := join(t, fits)
	require.NoError(t, err)
	require.Len(t, joined, budget)
	_, err = join(t, fits+1)
	requireIneligible(t, err, "a clipboard write too large to replay")
	_, err = join(t, budget)
	requireIneligible(t, err, "a clipboard write too large to replay")

	e := startFor(t, captureOf(string(stream(budget)), event(1, 0, 80, 24)), termsize.Size{Cols: 80, Rows: 24})
	require.Len(t, e.clips, 1)
	require.True(t, e.clips[0].over)
	require.Empty(t, e.clips[0].pd)

	long := "\x1b]52;cp;" + strings.Repeat("A", budget) + "\x07"
	joined, err = fanOut(t, New(), []byte("text\r\n"+long+"\x1b]52;pc;QQ==\x07more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
	require.NoError(t, err)
	require.True(t, bytes.HasSuffix(joined, []byte("\x1b]52;pc;QQ==\x07")), "%q", joined)
	require.Equal(t, 1, bytes.Count(joined, []byte("\x1b]52;")))
	_, err = fanOut(t, New(), []byte("text\r\n"+long+"\x1b]52;c;QQ==\x07more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
	requireIneligible(t, err, "a clipboard write too large to replay")
}

// DECSCA's character protection, which x/vt doesn't keep, fails the render,
// named, once the session turned it on: the cells printed under it are
// protected from DECSED and DECSEL on the session's terminal, and wouldn't be
// on the joiner's. x/vt can't say which cells those are, so protection turned
// off again with nothing printed between fails it too. DECSCA reads only its
// first parameter, as xterm does: 1 protects, 0 (the default) and 2 don't,
// and any other value changes nothing. One that doesn't protect renders.
func TestReplayFailsOnCharacterProtection(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"protected text", "\x1b[1\"qprotected\x1b[0\"q"},
		{"protection left on", "\x1b[1\"q"},
		{"protection turned off with nothing printed", "\x1b[1\"q\x1b[\"q"},
		{"the first parameter protecting", "\x1b[1;0\"q"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "character protection")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"DECSCA 0", "\x1b[0\"q"},
		{"the default", "\x1b[\"q"},
		{"DECSCA 2", "\x1b[2\"q"},
		{"a value that changes nothing", "\x1b[3\"q"},
		{"a later parameter protecting", "\x1b[0;1\"q"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
		})
	}
}

// A selective erase the session sent, DECSED (CSI ? Ps J) or DECSEL
// (CSI ? Ps K), fails the render, named: x/vt ignores both, so the cells the
// session's terminal erased are still in the emulator, and the render would
// draw them. ED and EL, which x/vt does erase by, render.
func TestReplayFailsOnASelectiveErase(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"DECSED", "\x1b[?J"},
		{"DECSED of the whole screen", "\x1b[?2J"},
		{"DECSEL", "\x1b[?K"},
		{"DECSEL of the whole line", "\x1b[?2K"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a selective erase")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"ED", "\x1b[2J"},
		{"EL", "\x1b[K"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
		})
	}
}

// titlesJoin joins a terminal to a session whose stream is stream, and
// requires the render, not the raw ring. It returns what the joiner was sent,
// and then, which feeds live to the session's terminal and the joiner's and
// requires the two to show the same window title and the same icon name: each
// terminal has names of its own, so a pop that puts back the terminal's own
// leaves each showing its own, and one that puts back a name the stream set
// leaves both showing it. The title stack is kept as xterm keeps it (see
// xtermTitles). joinerStack, if given, goes to the joiner's terminal first:
// its own stack, which the joiner had before it joined.
func titlesJoin(t *testing.T, stream, joinerStack string) (joined []byte, then func(live string)) {
	t.Helper()
	joined, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
	require.NoError(t, fellBack)
	require.True(t, bytes.HasPrefix(joined, []byte(preamble)), "the render, not the raw ring")
	sessionsOwn := names{"the session's own", "the session's own icon"}
	joinersOwn := names{"the joiner's own", "the joiner's own icon"}
	a, b := vt.NewEmulator(80, 24), vt.NewEmulator(80, 24)
	a.SetReplyFunc(func([]byte) {})
	b.SetReplyFunc(func([]byte) {})
	aNames, bNames := watchTitleFrom(a, sessionsOwn), watchTitleFrom(b, joinersOwn)
	_, _ = b.WriteString(joinerStack)
	*bNames = joinersOwn
	shown := func(n, own names) names {
		if n.title == own.title {
			n.title = "the terminal's own"
		}
		if n.icon == own.icon {
			n.icon = "the terminal's own"
		}
		return n
	}
	same := func(after string) {
		t.Helper()
		require.Equal(t, shown(*aNames, sessionsOwn), shown(*bNames, joinersOwn), "the names after %q; the render: %q", after, joined)
	}
	_, _ = a.WriteString(stream)
	_, _ = b.Write(joined)
	same("the join")
	return joined, func(live string) {
		t.Helper()
		_, _ = a.WriteString(live)
		_, _ = b.WriteString(live)
		same(live)
	}
}

// The title stack the session pushed onto, by XTWINOPS 22 (CSI 22 ; Ps t),
// and popped, by XTWINOPS 23, which x/vt keeps none of, is pushed again on
// the joiner's terminal, oldest first, each entry under the window title and
// the icon name it saved: one the stream set is set again first; where the
// stream had set none, the joiner's own still shows, and is what the joiner
// pushes, as a raw replay would have it push. A pop the joiner's terminal
// then makes puts back what the session's puts back: the same name the stream
// set, or each one's own. vim pushes the window title and the icon name apart
// as it starts, and pops them as it exits.
func TestReplayRebuildsTheTitleStack(t *testing.T) {
	const vimStart, vimScreen = "\x1b[22;2t\x1b[22;1t", "\x1b[?1049h\x1b[H\x1b[2J~\r\n~\x1b[H"
	for _, tc := range []struct{ name, before, after string }{
		{"no title set", "", ""},
		{"a title the shell set", "\x1b]2;the shell\x07", ""},
		{"a title vim set", "", "\x1b]2;vim\x07"},
		{"both", "\x1b]2;the shell\x07", "\x1b]0;vim\x07"},
		{"an icon name the shell set", "\x1b]1;the shell\x07", ""},
		{"both names vim set, apart", "", "\x1b]2;vim title\x07\x1b]1;vim\x07"},
		{"both names the shell set, and vim", "\x1b]0;the shell\x07", "\x1b]0;vim\x07"},
	} {
		for _, start := range []string{vimStart, "\x1b[22;1t\x1b[22;2t"} {
			for _, exit := range []string{"\x1b[23;2t\x1b[23;1t", "\x1b[23;1t\x1b[23;2t"} {
				t.Run(fmt.Sprintf("%s, %q then %q", tc.name, start, exit), func(t *testing.T) {
					_, then := titlesJoin(t, tc.before+"$ vim\r\n"+start+tc.after+vimScreen, "")
					then("\x1b[?1049l")
					for i := 0; i < len(exit); i += len("\x1b[23;2t") {
						then(exit[i : i+len("\x1b[23;2t")])
					}
				})
			}
		}
	}

	t.Run("two entries, in order", func(t *testing.T) {
		joined, then := titlesJoin(t, "\x1b]2;one\x07\x1b[22;0t\x1b]2;two\x07\x1b[22;2ttext\r\n\x1b]2;three\x07", "")
		require.Contains(t, string(joined), "\x1b]2;one\x07\x1b[22;0t\x1b]2;two\x07\x1b[22;2t\x1b]2;three\x07")
		require.Equal(t, 2, bytes.Count(joined, []byte("\x1b[22;")), "%q", joined)
		then("\x1b[23;2t")
		then("\x1b[23;0t")
		then("\x1b[23;0t")
	})
	t.Run("an entry the stream never titled", func(t *testing.T) {
		joined, then := titlesJoin(t, "\x1b[22;0t\x1b]2;vim\x07text\r\n", "")
		require.Contains(t, string(joined), "\x1b[22;0t\x1b]2;vim\x07")
		require.Equal(t, 1, bytes.Count(joined, []byte("\x1b]2;")), "%q", joined)
		then("\x1b[23;0t")
	})
	t.Run("a push popped in the ring", func(t *testing.T) {
		joined, then := titlesJoin(t, "\x1b]2;one\x07\x1b[22;0t\x1b]2;two\x07\x1b[23;0ttext\r\n", "")
		require.NotContains(t, string(joined), "\x1b[22;")
		then("\x1b[23;0t")
	})
	t.Run("a pop in the ring that puts back the terminal's own", func(t *testing.T) {
		joined, then := titlesJoin(t, "\x1b[22;2t\x1b]2;vim\x07\x1b[23;2ttext\r\n", "")
		require.NotContains(t, string(joined), "\x1b]2;")
		then("\x1b]2;later\x07")
	})
	t.Run("a pop in the ring of an entry that saved only the icon name", func(t *testing.T) {
		joined, then := titlesJoin(t, "\x1b]2;one\x07\x1b[22;0t\x1b]2;two\x07\x1b[22;1t\x1b[23;2ttext\r\n", "")
		require.Contains(t, string(joined), "\x1b]2;one\x07\x1b[22;0t\x1b]2;one\x07")
		then("\x1b[23;0t")
	})
	t.Run("a pop in the ring that finds no title below", func(t *testing.T) {
		joined, then := titlesJoin(t, "\x1b[22;1t\x1b]2;one\x07\x1b[22;1t\x1b[23;2ttext\r\n", "")
		require.Contains(t, string(joined), "\x1b[22;1t\x1b]2;one\x07")
		then("\x1b[23;0t")
	})
	t.Run("a pop of the icon name", func(t *testing.T) {
		joined, then := titlesJoin(t, "\x1b]2;one\x07\x1b[22;0t\x1b]2;two\x07\x1b[23;1ttext\r\n", "")
		require.NotContains(t, string(joined), "\x1b[22;")
		then("\x1b[23;0t")
	})
	t.Run("an entry of neither name", func(t *testing.T) {
		joined, then := titlesJoin(t, "\x1b]2;one\x07\x1b[22t\x1b]2;two\x07\x1b[22;3ttext\r\n", "")
		require.Contains(t, string(joined), "\x1b]2;one\x07\x1b[22;0t\x1b[22;3t\x1b]2;two\x07")
		then("\x1b[23;2t")
		then("\x1b[23;2t")
	})
	t.Run("a pop past the ring's pushes", func(t *testing.T) {
		_, then := titlesJoin(t, "\x1b]2;one\x07\x1b[23;0ttext\r\n", "")
		then("\x1b[23;0t")
	})

	// Past ten, xterm's oldest entry is overwritten, and a pop that comes down
	// to it finds nothing, there or below, on the joiner's terminal as on the
	// session's: the joiner's own stack is gone as well.
	pushes := func(n int) string {
		var s strings.Builder
		for i := range n {
			fmt.Fprintf(&s, "\x1b]2;title %d\x07\x1b]1;icon %d\x07\x1b[22;0t", i, i)
		}
		return s.String()
	}
	const joinerStack = "\x1b]2;the joiner's saved\x07\x1b]1;the joiner's saved icon\x07\x1b[22;0t"
	for _, tc := range []struct {
		name, stream string
		pops         int
	}{
		{"eleven pushes", pushes(11), 13},
		{"twelve pushes, four popped in the ring", pushes(12) + strings.Repeat("\x1b[23;0t", 4), 10},
		{"thirty pushes", pushes(30), 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, then := titlesJoin(t, tc.stream+"\x1b]2;now\x07text\r\n", joinerStack)
			for range tc.pops {
				then("\x1b[23;0t")
			}
		})
	}
	t.Run("twelve pushes, all popped in the ring", func(t *testing.T) {
		joined, _ := titlesJoin(t, pushes(12)+strings.Repeat("\x1b[23;0t", 12)+"text\r\n", "")
		require.NotContains(t, string(joined), "\x1b[22;", "%q", joined)
		require.NotContains(t, string(joined), "\x1b[23;", "%q", joined)
		require.Contains(t, string(joined), "\x1b]2;title 2\x07", "the title the oldest entry put back, which the pops of the lost places left")
		require.Contains(t, string(joined), "\x1b]1;icon 2\x07", "its icon name")
	})

	// Nearby forms: a window op whose later parameter is 22, a refresh, as a
	// window op that changes the window falls back, and a push whose third
	// parameter is 0, which is no index.
	t.Run("a refresh with a parameter of 22", func(t *testing.T) {
		joined, _ := titlesJoin(t, "\x1b[7;22;1ttext\r\n", "")
		require.NotContains(t, string(joined), "\x1b[22;")
	})
	t.Run("a push with no index", func(t *testing.T) {
		joined, then := titlesJoin(t, "\x1b]2;one\x07\x1b[22;0;0ttext\r\n", "")
		require.Contains(t, string(joined), "\x1b]2;one\x07\x1b[22;0t")
		then("\x1b[23;0t")
	})
}

// The icon name the session set, by OSC 1, or by OSC 0 with the window
// title, which x/vt keeps behind no accessor, is set again on the joiner's
// terminal, by OSC 1, as a raw replay sets it there; an empty one too, which
// clears the joiner's. One the session never set isn't, and the joiner's own
// stays. The title stack's entries saved the icon name too, which the render
// sets again before each push that saves it, as it does the window title. An
// entry of both names saves the window's: one the stream set, and the
// terminal's own where it set none, so such an entry is pushed with only the
// name the stream set sent before it, the joiner saving its own as the other,
// and a pop of both then puts back each terminal's own. A pop of an entry that
// saved no icon name takes it from the nearest one below that did, as xterm
// does, in the ring and live.
func TestReplayRebuildsTheIconName(t *testing.T) {
	for _, tc := range []struct{ name, stream, sent string }{
		{"by OSC 1", "\x1b]1;the icon\x07text\r\n", "\x1b]1;the icon\x07"},
		{"by OSC 0, ended by ST", "\x1b]0;both\x1b\\text\r\n", "\x1b]1;both\x07\x1b]2;both\x07"},
		{"by OSC 0, then the title by OSC 2", "\x1b]0;both\x07\x1b]2;the title\x07text\r\n", "\x1b]1;both\x07\x1b]2;the title\x07"},
		{"by OSC 0, then by OSC 1", "\x1b]0;both\x07\x1b]1;the icon\x07text\r\n", "\x1b]1;the icon\x07\x1b]2;both\x07"},
		{"cleared", "\x1b]1;the icon\x07text\r\n\x1b]1;\x07", "\x1b]1;\x07"},
		{"never set", "\x1b]2;the title\x07text\r\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			joined, then := titlesJoin(t, tc.stream, "")
			require.Contains(t, string(joined), tc.sent)
			require.Equal(t, strings.Count(tc.sent, "\x1b]1;"), bytes.Count(joined, []byte("\x1b]1;")), "%q", joined)
			then("\x1b]2;later\x07")
		})
	}

	for _, tc := range []struct {
		name, stream, sent string
		pops               []string
	}{
		{
			"an entry of the icon name", "\x1b]1;one\x07\x1b[22;1t\x1b]1;two\x07text\r\n",
			"\x1b]1;one\x07\x1b[22;1t\x1b]1;two\x07", []string{"\x1b[23;1t", "\x1b[23;1t"},
		},
		{
			"an entry of both, both set", "\x1b]0;one\x07\x1b[22;0t\x1b]0;two\x07text\r\n",
			"\x1b]1;one\x07\x1b]2;one\x07\x1b[22;0t\x1b]1;two\x07\x1b]2;two\x07", []string{"\x1b[23;0t"},
		},
		{
			"an entry of both, only the title set", "\x1b]2;one\x07\x1b[22;0t\x1b]1;two\x07text\r\n",
			"\x1b]2;one\x07\x1b[22;0t\x1b]1;two\x07\x1b]2;one\x07", []string{"\x1b[23;0t"},
		},
		{
			"an entry of both, only the icon name set", "\x1b]1;one\x07\x1b[22;0t\x1b]2;two\x07text\r\n",
			"\x1b]1;one\x07\x1b[22;0t\x1b]1;one\x07\x1b]2;two\x07", []string{"\x1b[23;0t"},
		},
		{
			"an entry of both, neither set", "\x1b[22;0t\x1b]0;vim\x07text\r\n",
			"\x1b[22;0t\x1b]1;vim\x07\x1b]2;vim\x07", []string{"\x1b[23;0t"},
		},
		{
			"an entry of the title on one of the icon name", "\x1b]1;one\x07\x1b[22;1t\x1b]1;two\x07\x1b[22;2ttext\r\n",
			"\x1b]1;one\x07\x1b[22;1t\x1b[22;2t\x1b]1;two\x07", []string{"\x1b[23;1t", "\x1b[23;0t"},
		},
		{
			"a pop in the ring of an entry that saved only the title", "\x1b]1;one\x07\x1b[22;0t\x1b]1;two\x07\x1b[22;2t\x1b[23;1ttext\r\n",
			"\x1b]1;one\x07\x1b[22;0t\x1b]1;one\x07", []string{"\x1b[23;0t"},
		},
		{
			"a pop in the ring of the title alone", "\x1b]0;one\x07\x1b[22;0t\x1b]0;two\x07\x1b[23;2ttext\r\n",
			"\x1b]1;two\x07\x1b]2;one\x07", []string{"\x1b[23;0t"},
		},
		{
			"a pop in the ring that finds no icon name below", "\x1b[22;2t\x1b]1;one\x07\x1b[22;2t\x1b[23;1ttext\r\n",
			"\x1b[22;2t\x1b]1;one\x07", []string{"\x1b[23;0t"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			joined, then := titlesJoin(t, tc.stream, "")
			require.Contains(t, string(joined), tc.sent)
			require.Equal(t, strings.Count(tc.sent, "\x1b]1;"), bytes.Count(joined, []byte("\x1b]1;")), "%q", joined)
			for _, pop := range tc.pops {
				then(pop)
			}
		})
	}
	t.Run("a pop in the ring that puts back the terminal's own", func(t *testing.T) {
		joined, then := titlesJoin(t, "\x1b[22;1t\x1b]1;vim\x07\x1b[23;1ttext\r\n", "")
		require.NotContains(t, string(joined), "\x1b]1;")
		then("\x1b]1;later\x07")
	})

	// Past ten, xterm's oldest entry is overwritten, the joiner's own one
	// with it, which saved an icon name of its own.
	t.Run("eleven pushes of the icon name", func(t *testing.T) {
		var s strings.Builder
		for i := range 11 {
			fmt.Fprintf(&s, "\x1b]1;icon %d\x07\x1b[22;1t", i)
		}
		_, then := titlesJoin(t, s.String()+"\x1b]1;now\x07text\r\n", "\x1b]0;the joiner's saved\x07\x1b[22;0t")
		for range 13 {
			then("\x1b[23;1t")
		}
	})
}

// A title saved or restored by its index on xterm's stack, the third
// parameter of XTWINOPS 22 or 23, fails the render, named: the index counts
// from the bottom of the stack, which the session's terminal may have pushed
// onto before the ring, so neither the entry it saves into nor the one it
// reads can be told.
func TestReplayFailsOnAnIndexedTitleStackEntry(t *testing.T) {
	for _, stream := range []string{"\x1b[22;0;1t", "\x1b[22;2;10t", "\x1b[23;0;3t"} {
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		requireIneligible(t, fellBack, "a title stack entry by index")
	}
}

// The title stack counts against the render's budget: entries that don't fit
// with everything else fail it, over the budget. A saved window title or icon
// name longer than any render may be keeps none of its bytes, and fails the
// render, named, while it is on the stack or a pop has put it back.
func TestReplayFailsOnATitleStackTooLargeToReplay(t *testing.T) {
	setBudget(t, 8<<10)
	for _, tc := range []struct{ name, osc, ps, state string }{
		{"a window title", "\x1b]2;", "2", "a saved title too long to replay"},
		{"an icon name", "\x1b]1;", "1", "a saved icon name too long to replay"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := func(n int) string {
				return "text\r\n" + tc.osc + strings.Repeat("A", n) + "\x07\x1b[22;" + tc.ps + "t" + tc.osc + "now\x07more\r\n"
			}
			join := func(t *testing.T, stream string) ([]byte, error) {
				t.Helper()
				return fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
			}
			empty, err := join(t, stream(0))
			require.NoError(t, err)
			fits := budget - len(empty)
			joined, err := join(t, stream(fits))
			require.NoError(t, err)
			require.Len(t, joined, budget)
			_, err = join(t, stream(fits+1))
			require.ErrorIs(t, err, ErrOverBudget)

			_, err = join(t, stream(budget+1))
			requireIneligible(t, err, tc.state)
			e := startFor(t, captureOf(stream(budget+1), event(1, 0, 80, 24)), termsize.Size{Cols: 80, Rows: 24})
			require.Len(t, e.titles.entries, 1)
			en := e.titles.entries[0]
			over, kept := en.over, en.title
			if tc.ps == "1" {
				over, kept = en.iconOver, en.icon
			}
			require.True(t, over)
			require.Empty(t, kept)

			_, err = join(t, stream(budget+1)+"\x1b[23;"+tc.ps+"t")
			requireIneligible(t, err, tc.state)
		})
	}
}

// A title mode the session set by XTSMTITLE (CSI > Pm t), which makes the
// terminal take the titles a program sets, or report them, in hexadecimal or
// as UTF-8, fails the render, named: x/vt keeps none, so a joiner given the
// render would show a title the program sets in hexadecimal after the
// handoff point as its digits, where the session's terminal, and a joiner
// given the raw ring, decode it. Each parameter from 0 to 3 sets one, as
// xterm reads them, and the note stays once XTRMTITLE (CSI > Pm T) turns
// them off again. XTRMTITLE alone, XTSMTITLE with no parameters, which sets
// the defaults, and a mode xterm doesn't have render, and x/vt, which keys a
// CSI handler by its prefix too, doesn't take XTRMTITLE for SD (CSI Ps T)
// and scroll.
func TestReplayFailsOnATitleMode(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"titles set in hexadecimal", "\x1b[>0t"},
		{"titles reported in hexadecimal", "\x1b[>1t"},
		{"titles set as UTF-8", "\x1b[>2t"},
		{"titles reported as UTF-8", "\x1b[>3t"},
		{"two modes", "\x1b[>0;1t"},
		{"a mode xterm doesn't have, then one it has", "\x1b[>4;1t"},
		{"a mode set, then reset", "\x1b[>1t\x1b[>1T"},
		{"a mode set, then every one reset", "\x1b[>1t\x1b[>T"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a title mode")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"a mode reset", "\x1b[>1T"},
		{"every mode reset", "\x1b[>T"},
		{"the defaults set", "\x1b[>t"},
		{"a mode xterm doesn't have", "\x1b[>4t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
			j := joinAt(t, 80, 24, "text\r\n"+tc.stream+"more\r\n")
			require.Equal(t, "text", j.a.MainScreen().Line(0).String(), "scrolled")
		})
	}
}

// DEC private modes the session saved by XTSAVE (CSI ? Pm s) fail the
// render, named: x/vt keeps none and ignores the XTRESTORE (CSI ? Pm r) that
// puts them back, so the render can't tell what a later restore sets on the
// session's terminal, and a joiner's terminal, which the save never reached,
// would restore its own. Any XTSAVE counts, and still does once restored. A
// restore alone renders: what it puts back was saved before the ring, which
// neither a raw replay nor the render holds. So do SCOSC (CSI s), a CSI s
// without the prefix, and the SCORC after it.
func TestReplayFailsOnSavedDECModes(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"one mode saved", "\x1b[?1049s"},
		{"several saved", "\x1b[?1;25;2004s"},
		{"none named", "\x1b[?s"},
		{"a save restored", "\x1b[?25s\x1b[?25l\x1b[?25r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "saved DEC modes")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"a restore alone", "\x1b[?1049r"},
		{"SCOSC", "\x1b[s"},
		{"SCOSC and SCORC", "\x1b[5;5H\x1b[s\x1b[H\x1b[u"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
		})
	}
}

// A rendition the session pushed by XTPUSHSGR (CSI Pm # {, or its alias
// CSI Pm # p) fails the render, named: x/vt keeps no stack and ignores the
// XTPOPSGR (CSI # }, or CSI # q) that pops it, so the render can't tell what
// pen a later pop gives the session's terminal, and a joiner's terminal,
// which the push never reached, would pop its own. A push of the whole pen or
// of the attributes Pm names counts, and still does once popped. A pop alone
// renders: what it puts back was pushed before the ring, which neither a raw
// replay nor the render holds.
func TestReplayFailsOnASavedRendition(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"the pen pushed", "\x1b[#{"},
		{"some attributes pushed", "\x1b[1;31#{"},
		{"the pen pushed by the alias", "\x1b[#p"},
		{"an attribute pushed by the alias", "\x1b[2#p"},
		{"a push popped", "\x1b[#{\x1b[1m\x1b[#}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a saved rendition")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"a pop alone", "\x1b[#}"},
		{"a pop alone by the alias", "\x1b[#q"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
		})
	}
}

// A palette the session saved by XTPUSHCOLORS (CSI Pm # P), its dynamic and
// ANSI colours, pushed on xterm's stack or stored in a place on it, fails the
// render, named: x/vt keeps no stack and ignores the XTPOPCOLORS
// (CSI Pm # Q) that puts one back, so the render can't tell what colours a
// later pop gives the session's terminal, and a joiner's terminal, which the
// push never reached, would pop its own. Every push counts, and still does
// once popped. A pop alone renders: what it puts back was pushed before the
// ring, which neither a raw replay nor the render holds. So do XTREPORTCOLORS
// (CSI # R), a report, which the filter drops when it has no parameters and
// which, given to the emulation directly, doesn't count either, and DCH
// (CSI Ps P), the same final without the #.
func TestReplayFailsOnASavedPalette(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"the palette pushed", "\x1b[#P"},
		{"the palette stored in a place", "\x1b[3#P"},
		{"the palette stored in two places", "\x1b[1;2#P"},
		{"a push popped", "\x1b[#P\x1b[#Q"},
		{"a push, then text", "\x1b[#Pafter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a saved palette")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"a pop alone", "\x1b[#Q"},
		{"a pop from a place", "\x1b[2#Q"},
		{"the stack reported", "\x1b[#R"},
		{"the stack reported, with a parameter", "\x1b[1#R"},
		{"no intermediate", "\x1b[2P"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
			_, err := renderAt(t, 80, 24, "text\r\n"+tc.stream+"more\r\n")
			require.NoError(t, err, "given to the emulation")
		})
	}
}

// An SGR the session sent with a number x/vt's SGR skips, which changes how
// a terminal draws what is printed after it, fails the render, named, as the
// cells printed under it would be drawn as x/vt keeps them: an alternative
// font, Fraktur, SGR 21, which x/vt doesn't read as a double underline (a
// cell keeps one set by 4:2), proportional spacing, framed, encircled,
// overlined, an ideogram line or stress mark, superscript and subscript. It counts wherever it falls among the SGR's parameters, and
// still does once turned off. The numbers that turn those off render, and so
// does a colour whose own numbers are among the attributes', as SGR reads
// them as the colour.
func TestReplayFailsOnARenditionTheRenderCantDraw(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\x1b[m\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"the first alternative font", "\x1b[11m"},
		{"the last alternative font", "\x1b[19m"},
		{"Fraktur", "\x1b[20m"},
		{"SGR 21", "\x1b[21m"},
		{"proportional spacing", "\x1b[26m"},
		{"framed", "\x1b[51m"},
		{"encircled", "\x1b[52m"},
		{"overlined", "\x1b[53m"},
		{"the first ideogram attribute", "\x1b[60m"},
		{"the last ideogram attribute", "\x1b[64m"},
		{"superscript", "\x1b[73m"},
		{"subscript", "\x1b[74m"},
		{"after other attributes", "\x1b[1;4;53m"},
		{"after an underline style", "\x1b[4:3;53m"},
		{"after an indexed colour", "\x1b[38;5;1;53m"},
		{"after a direct colour", "\x1b[48;2;1;2;3;53m"},
		{"after a direct colour with its colour space", "\x1b[58:2::1:2:3;53m"},
		{"turned off again", "\x1b[53mover\x1b[55m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a rendition the render can't draw")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"the primary font", "\x1b[10m"},
		{"proportional spacing off", "\x1b[50m"},
		{"neither framed nor encircled", "\x1b[54m"},
		{"not overlined", "\x1b[55m"},
		{"no ideogram attribute", "\x1b[65m"},
		{"neither superscript nor subscript", "\x1b[75m"},
		{"a curly underline", "\x1b[4:3m"},
		{"a double underline", "\x1b[4:2m"},
		{"normal intensity after an underline", "\x1b[1;4;22m"},
		{"an indexed foreground", "\x1b[38;5;53m"},
		{"an indexed background", "\x1b[48;5;21m"},
		{"an indexed underline colour", "\x1b[58;5;73m"},
		{"a direct colour", "\x1b[38;2;53;51;52m"},
		{"a direct colour with its colour space", "\x1b[48:2::53:60:74m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
		})
	}
}

// A line the session made double-width or double-height, by DECDWL (ESC # 6)
// or DECDHL (ESC # 3 for the top half, ESC # 4 for the bottom), fails the
// render, named: x/vt keeps no line size, so the render would draw the line
// single-width, where the session's terminal draws it twice as wide and
// shows half as many of its columns. It still does once DECSWL (ESC # 5)
// makes a line single-width again; DECSWL alone renders.
func TestReplayFailsOnADoubleSizeLine(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"the top half of a double-height line", "\x1b#3big"},
		{"the bottom half of a double-height line", "\x1b#4big"},
		{"a double-width line", "\x1b#6wide"},
		{"a double-width line made single-width again", "\x1b#6wide\x1b#5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a double-size line")
		})
	}
	t.Run("a single-width line", func(t *testing.T) {
		require.NoError(t, join(t, "\x1b#5narrow"))
	})
}

// A status line the session made host-writable, by DECSSDT 2 (CSI 2 $ ~), or
// sent its output to, by DECSASD 1 (CSI 1 $ }), fails the render, named: x/vt
// has no status line, so what the program wrote there would be drawn on the
// main display, or not at all, where the session's terminal shows it on a
// line of its own. It still does once put away. Each reads only its first
// parameter, as xterm's do. The rest render: no status line, the default;
// the main display; and the indicator line, DECSSDT 1, which the terminal
// draws itself and a program can't write to, so the render loses only the
// line, not anything the program sent.
func TestReplayFailsOnAStatusLine(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"a host-writable status line", "\x1b[2$~"},
		{"the status line active", "\x1b[1$}"},
		{"a status line written and put away", "\x1b[2$~\x1b[1$}status\x1b[0$}\x1b[0$~"},
		{"the first parameter selecting it", "\x1b[2;0$~"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a status line")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"no status line", "\x1b[0$~"},
		{"the default type", "\x1b[$~"},
		{"an indicator line", "\x1b[1$~"},
		{"the main display", "\x1b[0$}"},
		{"the default display", "\x1b[$}"},
		{"a later parameter selecting it", "\x1b[0;1$}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
		})
	}
}

// A synchronized update the session is inside at the handoff point, a frame
// the program began with ?2026h and has yet to end, holds the session's
// terminal's display until the program's own ?2026l, which the live bytes
// carry: the render starts with ?2026h, so the joiner's terminal holds its
// display, the render included, until then too. An update ended, or never
// begun, sends no ?2026 at all. The ?2026h counts against the budget, as
// everything the render sends does, the history included.
func TestReplayStartsInsideAnOpenSynchronizedUpdate(t *testing.T) {
	join := func(t *testing.T, stream string) []byte {
		t.Helper()
		joined, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
		require.NoError(t, fellBack)
		return joined
	}

	joined := join(t, "text\r\n\x1b[?2026h\x1b[Hframe")
	require.True(t, bytes.HasPrefix(joined, []byte("\x1b[?2026h"+preamble)), "%q", joined)
	require.Equal(t, 1, bytes.Count(joined, []byte("\x1b[?2026")), "%q", joined)
	b, _ := newReference(80, 24)
	_, _ = b.Write(joined)
	require.True(t, b.Mode(ansi.ModeSynchronizedOutput).IsSet())

	for _, stream := range []string{"text\r\n", "text\r\n\x1b[?2026h\x1b[Hframe\x1b[?2026l"} {
		joined := join(t, stream)
		require.True(t, bytes.HasPrefix(joined, []byte(preamble)), "%q", joined)
		require.NotContains(t, string(joined), "\x1b[?2026", "%q", joined)
	}

	setBudget(t, 1<<10)
	over := func(n int) []byte {
		return []byte("text\r\n\x1b[?2026h\x1b]52;c;" + strings.Repeat("A", n) + "\x07")
	}
	empty, err := fanOut(t, New(), over(0), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
	require.NoError(t, err)
	fits := budget - len(empty)
	joined, err = fanOut(t, New(), over(fits), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
	require.NoError(t, err)
	require.Len(t, joined, budget)
	_, err = fanOut(t, New(), over(fits+1), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
	requireIneligible(t, err, "a clipboard write too large to replay")

	// Lines of history cost 3 bytes each, so the cut leaves less than the
	// 8 bytes of the ?2026h over.
	joined = join(t, strings.Repeat("x\r\n", budget)+"\x1b[?2026h")
	require.True(t, bytes.HasPrefix(joined, []byte("\x1b[?2026h"+preamble)), "%q", joined[:min(len(joined), 32)])
	require.LessOrEqual(t, len(joined), budget)
}

// Synchronized output's DCS form begins and ends the same update ?2026 does:
// DCS = 1 s begins one, as ?2026h does, DCS = 2 s ends it, as ?2026l does,
// either end closes what either beginning opened, a second beginning leaves
// it open, and an end with none open does nothing. A terminal that takes only
// one form follows that form's last. So the render starts with the last of
// each form the stream sent, in the stream's order, but for an end that
// comes first, which closes nothing: on a terminal that takes either form or
// both, the joiner's update then ends where the session's does. A full reset
// ends it, as it resets ?2026.
func TestReplayStartsInsideAnUpdateTheDCSFormBegan(t *testing.T) {
	const bsu, esu, bsm, esm = "\x1bP=1s\x1b\\", "\x1bP=2s\x1b\\", "\x1b[?2026h", "\x1b[?2026l"
	for _, tc := range []struct{ name, stream, lead string }{
		{"begun", bsu + "\x1b[Hframe", bsu},
		{"begun and ended", bsu + "\x1b[Hframe" + esu, ""},
		{"begun twice", bsu + "a" + bsu + "b", bsu},
		{"begun, then another mode set", bsu + "\x1b[?2004h", bsu},
		{"ended with none begun", esu, ""},
		{"begun, then a full reset", bsu + "a\x1bcb\r", ""},
		{"begun by both, the DCS form first", bsu + bsm + "a", bsu + bsm},
		{"begun by both, ?2026 first", bsm + bsu + "a", bsm + bsu},
		{"begun by the DCS form, ended by ?2026", bsu + "a" + esm, bsu + esm},
		{"begun by ?2026, ended by the DCS form", bsm + "a" + esu, bsm + esu},
		{"begun by the DCS form after a ?2026 end", esm + bsu + "a", bsu},
		{"begun by ?2026 after a DCS end", esu + bsm + "a", bsm},
		{"begun by both, ended by both", bsu + bsm + "a" + esu + esm, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := "text\r\n" + tc.stream
			joined, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
			require.NoError(t, fellBack)
			require.True(t, bytes.HasPrefix(joined, []byte(tc.lead+preamble)), "%q", joined)
			for _, seq := range []string{"\x1bP=", "\x1b[?2026"} {
				require.Equal(t, strings.Count(tc.lead, seq), bytes.Count(joined, []byte(seq)), "%q in %q", seq, joined)
			}
			// x/vt keeps ?2026 alone, which the joiner's then holds as the
			// session's does.
			a, _ := newReference(80, 24)
			_, _ = a.WriteString(stream)
			b, _ := newReference(80, 24)
			_, _ = b.Write(joined)
			require.Equal(t, a.Mode(ansi.ModeSynchronizedOutput).IsSet(), b.Mode(ansi.ModeSynchronizedOutput).IsSet())
		})
	}
}

// Insert mode, the application keypad and reverse video are set for the
// live bytes, which they change.
func TestReplayRestoresInsertKeypadAndReverseVideo(t *testing.T) {
	j := joinAt(t, 80, 24, "abc\r\nxyz\x1b[4h\x1b=\x1b[?5h\x1b[1;1H")
	require.True(t, j.b.Mode(ansi.ModeInsertReplace).IsSet())
	require.True(t, j.b.Mode(ansi.ModeNumericKeypad).IsSet())
	require.True(t, j.b.Mode(ansi.DECMode(5)).IsSet())
	j.then(t, "-")
	require.Equal(t, "-abc", j.b.MainScreen().Line(0).String())
}

// The render ends with a control even when the reprint is its last action,
// so the live bytes extend no cluster the render printed: a combining mark
// first is dropped in B as it is in A.
func TestReplayClosesTheClusterAfterAReprint(t *testing.T) {
	j := joinAt(t, 4, 3, "abcd\x1b[m")
	require.False(t, j.b.Carrying())
	j.then(t, "\u0301")
	require.Equal(t, "d", cellAt(j.b, 3, 0).Content)
}

// Tab stops other than every 8 columns are set again, so a live tab lands
// where the session's did.
func TestReplayRestoresTabStops(t *testing.T) {
	j := joinAt(t, 80, 24, "\x1b[3g\x1b[5G\x1bH\x1b[20G\x1bH\rtext\r\n")
	require.Equal(t, []int{4, 19}, j.b.TabStops())
	j.then(t, "\tX\tY")
	require.Equal(t, "X", cellAt(j.b, 4, 1).Content)
	require.Equal(t, "Y", cellAt(j.b, 19, 1).Content)
}

// A terminal keeps its tab stops past the screen's right edge, for a
// widening to bring back: those of the columns a wider screen had, as they
// were when a narrowing took them off it, and past every width it has had,
// one every 8 columns, as it starts, unless the stream cleared every stop
// (TBC 3 or DECST8C) since it started or since the last RIS. A joiner wider
// than the pty gets those in the columns past the pty's width, so a live
// tab there lands where the session's does once the pty is as wide.
func TestReplaySetsTheTabStopsPastThePtysWidth(t *testing.T) {
	every8 := func(from, to int) []int {
		var stops []int
		for x := from; x < to; x += 8 {
			stops = append(stops, x)
		}
		return stops
	}
	plus := func(stops []int, xs ...int) []int {
		s := append(slices.Clone(stops), xs...)
		slices.Sort(s)
		return s
	}
	without := func(stops []int, x int) []int {
		return slices.DeleteFunc(slices.Clone(stops), func(s int) bool { return s == x })
	}
	at80 := []uio.SizeEvent{event(1, 0, 80, 24)}
	// narrowed is the pty at cols, narrowed to 80 after head.
	narrowed := func(cols int, head string) []uio.SizeEvent {
		return []uio.SizeEvent{event(1, 0, cols, 24), event(2, len(head), 80, 24)}
	}
	const at100, at90 = "\x1b[101G\x1bH\r", "\x1b[91G\x1bH\r"
	for _, tc := range []struct {
		name, stream string
		sizes        []uio.SizeEvent
		want         []int // the joiner's
	}{
		{"the default stops", "", at80, every8(0, 120)},
		{"an HTS", "\x1b[6G\x1bH\r", at80, plus(every8(0, 120), 5)},
		{"a TBC", "\x1b[9G\x1b[g\r", at80, without(every8(0, 120), 8)},
		{"TBC 3, then an HTS", "\x1b[3g\x1b[6G\x1bH\r", at80, []int{5}},
		{"TBC 3, then RIS", "\x1b[3g\x1bc", at80, every8(0, 120)},
		{"DECST8C", "\x1b[6G\x1bH\x1b[?5W\r", at80, every8(0, 80)},
		{"DECST8C, then RIS", "\x1b[?5W\x1bc", at80, every8(0, 120)},
		{"an HTS a narrowing left past the pty's width", at100, narrowed(120, at100), plus(every8(0, 120), 100)},
		{"TBC 3 and an HTS a narrowing left past it", "\x1b[3g" + at100, narrowed(120, "\x1b[3g"+at100), []int{100}},
		{"a TBC a narrowing left past it", "\x1b[113G\x1b[g\r", narrowed(120, "\x1b[113G\x1b[g\r"), without(every8(0, 120), 112)},
		{"DECST8C at a width a narrowing left", "\x1b[?5W\r", narrowed(100, "\x1b[?5W\r"), every8(0, 100)},
		{"TBC 3 after a narrowing", at100 + "\x1b[3g", narrowed(120, at100), nil},
		{"RIS after a narrowing", "\x1b[3g" + at100 + "\x1bc", narrowed(120, "\x1b[3g"+at100), every8(0, 120)},
		{"two narrowings", at100 + "\r" + at90, []uio.SizeEvent{
			event(1, 0, 120, 24), event(2, len(at100), 80, 24),
			event(3, len(at100)+1, 100, 24), event(4, len(at100)+1+len(at90), 80, 24),
		}, plus(every8(0, 120), 90, 100)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := tc.stream + "text\r\n"
			sent, fellBack := fanOutTo(t, New(), []byte(stream), tc.sizes, 4<<10, termsize.Size{Cols: 120, Rows: 24})
			require.NoError(t, fellBack)
			require.True(t, bytes.HasPrefix(sent, []byte(preamble)), "the render, not the raw ring")

			first := tc.sizes[0].Size
			a, aHist := newReference(first.Cols, first.Rows)
			feedSized(a, []byte(stream), 0, first, tc.sizes[1:])
			b, bHist := newReference(120, 24)
			_, _ = b.Write(sent)
			require.Equal(t, tc.want, b.TabStops(), "the joiner's")

			// The pty widens to the joiner's width, and the session's
			// terminal with it, which then holds the same stops.
			a.Resize(120, 24)
			require.Equal(t, tc.want, a.TabStops(), "the session's, widened")
			// A tab from column 85 lands on the first stop past it, or in the
			// last column, on both.
			land := 119
			if i := slices.IndexFunc(tc.want, func(x int) bool { return x > 85 }); i >= 0 {
				land = tc.want[i]
			}
			for _, term := range []*vt.Emulator{a, b} {
				_, _ = term.WriteString("\x1b[86G\tX\r\n\tY\tZ")
			}
			require.Equal(t, "X", cellAt(b, land, 1).Content)
			require.Empty(t, sameState(a, b, *aHist, *bHist, names{}, names{}))
		})
	}
}

// Each screen's kitty keyboard stack is pushed while that screen shows: the
// main one's before the alternate screen is entered, the alternate one's
// after.
func TestReplayRestoresTheKittyKeyboardStacks(t *testing.T) {
	render, err := renderAt(t, 80, 24, "\x1b[>1umain\r\n\x1b[?1049h\x1b[>3ualt\r\n")
	require.NoError(t, err)
	require.Regexp(t, regexp.MustCompile(`\x1b\[>1u.*\x1b\[\?1049h.*\x1b\[>3u`), string(render))
}

// The joiner's alternate screen may hold what it last showed there, which
// ?47h shows again and neither ?47h nor ?1047h clears: the render erases it,
// in the default background, before drawing the session's.
func TestReplayErasesTheJoinersAlternateScreen(t *testing.T) {
	for _, tc := range []struct{ name, stream, show string }{
		{"hidden", "\x1b[?47h\x1b[HTEXT\x1b[?47lmain\r\n", "\x1b[?47h"},
		{"showing, under a saved background", "main\r\n\x1b[44m\x1b7\x1b[m\x1b[?1047h\x1b[Halt\r\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := startFor(t, captureOf(tc.stream, event(1, 0, 80, 24)), termsize.Size{Cols: 80, Rows: 24})
			render, err := e.Render()
			require.NoError(t, err)
			a, aHist := newReference(80, 24)
			_, _ = a.WriteString(tc.stream + tc.show)
			b, bHist := newReference(80, 24)
			_, _ = b.WriteString("\x1b[?47h\x1b[H" + strings.Repeat("STALE", 16) + "\x1b[?47l\x1b[H")
			_, _ = b.Write(render)
			_, _ = b.WriteString(tc.show)
			require.Empty(t, sameState(a, b, *aHist, *bHist, names{}, names{}))
		})
	}
}

// A slot keeps the position it was saved at through a resize that leaves it
// off the screen, for DECRC to clamp: the render sets that position, which a
// joiner the render's size clamps as the session's terminal does, and a
// wider one keeps.
func TestReplayEmitsASlotsRawPosition(t *testing.T) {
	const stream = "\x1b[1;80H\x1b7\x1b[Htext\r\n"
	sizes := []uio.SizeEvent{event(1, 0, 80, 24), event(2, len(stream), 60, 24)}

	e := startFor(t, captureOf(stream, sizes...), termsize.Size{Cols: 80, Rows: 24})
	render, err := e.Render()
	require.NoError(t, err)
	require.Contains(t, string(render), "\x1b[1;80H\x1b7")

	e = startFor(t, captureOf(stream, sizes...), termsize.Size{Cols: 60, Rows: 24})
	render, err = e.Render()
	require.NoError(t, err)
	a, _ := newReference(80, 24)
	_, _ = a.WriteString(stream)
	a.Resize(60, 24)
	b, _ := newReference(60, 24)
	_, _ = b.Write(render)
	for _, term := range []*vt.Emulator{a, b} {
		_, _ = term.WriteString("\x1b8X")
	}
	require.Equal(t, "X", cellAt(a, 59, 0).Content)
	require.Equal(t, "X", cellAt(b, 59, 0).Content)
}

// requireAfterTheReprints requires seq to follow every print in render's
// last column, 4 here: a CUP there and the character after it.
func requireAfterTheReprints(t *testing.T, render []byte, seq string) {
	t.Helper()
	reprints := regexp.MustCompile(`\x1b\[\d+;4H[^\x1b]`).FindAllIndex(render, -1)
	require.NotEmpty(t, reprints)
	require.Greater(t, bytes.Index(render, []byte(seq)), reprints[len(reprints)-1][0], "%q", render)
}

// A mode that only changes what the keyboard or the mouse sends, or how the
// terminal shows its own view of the output (where it scrolls, its
// selection, how it repaints), is neither restored nor a reason to fall back,
// whichever way the stream left it, as a terminal starts with it set or not:
// the join renders without it, as the raw replay's mode snapshot leaves it
// out. readline sends ?1034h, the meta key's, at every prompt where the
// terminfo entry has it, as xterm-256color's does.
func TestReplayIgnoresInputOnlyModes(t *testing.T) {
	for _, n := range []int{35, 67, 1007, 1010, 1014, 1015, 1034, 1035, 1036, 1037, 1039, 1040, 1050, 1051, 1052, 1053, 1060, 1061, 9001} {
		for _, hl := range []string{"h", "l"} {
			t.Run(fmt.Sprintf("?%d%s", n, hl), func(t *testing.T) {
				seq := fmt.Sprintf("\x1b[?%d%s", n, hl)
				j := joinAt(t, 80, 24, seq+"$ ls\r\n")
				require.NotContains(t, string(j.render), seq)
			})
		}
	}

	t.Run("a join at a bash prompt", func(t *testing.T) {
		w := uio.NewMultiWriter(1 << 10)
		var fellBack []error
		w.SetReplayer(New(), func(err error) { fellBack = append(fellBack, err) })
		w.Pinned(joiner)
		_, _ = w.Write([]byte("$ ls\r\nREADME\r\n\x1b[?1034h$ "))

		var got bytes.Buffer
		require.NoError(t, w.AppendSized(t.Context(), time.Now().Add(time.Minute), joiner, &got))
		require.Empty(t, fellBack)
		require.NotContains(t, got.String(), "\x1b[?1034h", "the raw ring")
		require.True(t, strings.HasSuffix(got.String(), "$ "), "%q", got.String())
	})
}

// ConPTY starts every Windows session with a DA1, which the ring's query
// filter takes out, then focus reporting and win32-input-mode: a join to it
// renders, restores focus reporting, and leaves win32-input-mode, which only
// changes how the keyboard is encoded, as the joiner's terminal has it.
func TestReplayJoinsAConPTYSession(t *testing.T) {
	w := uio.NewMultiWriter(1 << 10)
	var fellBack []error
	w.SetReplayer(New(), func(err error) { fellBack = append(fellBack, err) })
	w.Pinned(joiner)
	_, _ = w.Write([]byte("\x1b[c\x1b[?1004h\x1b[?9001h"))
	_, _ = w.Write([]byte("Microsoft Windows [Version 10.0.22631.4602]\r\n" +
		"(c) Microsoft Corporation. All rights reserved.\r\n\r\nC:\\Users\\guest>"))

	var got bytes.Buffer
	require.NoError(t, w.AppendSized(t.Context(), time.Now().Add(time.Minute), joiner, &got))
	require.Empty(t, fellBack)
	require.True(t, strings.HasPrefix(got.String(), preamble), "the render, not the raw ring: %q", got.String())
	require.Contains(t, got.String(), "\x1b[?1004h")
	require.NotContains(t, got.String(), "9001")
	require.True(t, strings.HasSuffix(got.String(), "C:\\Users\\guest>"), "%q", got.String())
}

// Claude Code and nvim ask for colour-scheme reports (?2031) as they start,
// after which the terminal reports each change unasked. A join to either
// renders instead of falling back until their startup leaves the ring, and
// sets the mode, since the program asked for the reports and the raw replay
// passes the mode through.
func TestReplayRestoresTheColourSchemeReports(t *testing.T) {
	for _, tc := range []struct{ name, stream string }{
		{"Claude Code", "\x1b[?25l\x1b[?1004h\x1b[?2004h\x1b[?2026h\x1b[?2031h" +
			"\x1b[2J\x1b[H\x1b[1mClaude Code\x1b[m\r\n\r\n> Try \"fix the failing test\"\r\n"},
		{"nvim", "\x1b[?1h\x1b[?25l\x1b[?1002h\x1b[?1004h\x1b[?1006h\x1b[?1049h\x1b[?2004h\x1b[?2026h\x1b[?2031h" +
			"\x1b[H\x1b[2J~\r\n~\r\n~\x1b[H\x1b[?25h"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := joinAt(t, 80, 24, tc.stream)
			require.Contains(t, string(j.render), "\x1b[?2031h")
			require.True(t, j.b.Mode(ansi.ModeLightDark).IsSet())
		})
	}
}

// In-band resize reports (?2048) don't make a join fall back, and aren't
// set on the joiner: setting them makes a terminal report its own size at
// once, which from a joiner is not the session's.
func TestReplayLeavesInBandResizeReportsOff(t *testing.T) {
	j := joinAt(t, 80, 24, "\x1b[?2048h$ ls\r\nREADME\r\n$ ")
	require.NotContains(t, string(j.render), "\x1b[?2048")
	require.False(t, j.b.Mode(ansi.ModeInBandResize).IsSet())
}

// The colour-scheme report mode goes out with the tracker's, after them, as
// focus reporting does; and a program that turned it off again leaves the
// joiner's terminal as it is.
func TestReplaySetsTheReportModesWithTheTrackers(t *testing.T) {
	j := joinAt(t, 80, 24, "\x1b[?2048h\x1b[?2031h\x1b[?2004h\x1b[?1004h$ ls\r\n")
	require.Contains(t, string(j.render), "\x1b[?1004h\x1b[?2004h\x1b[?2031h")
	require.NotContains(t, string(j.render), "\x1b[?2048")

	j = joinAt(t, 80, 24, "\x1b[?2031h\x1b[?2048h$ ls\r\n\x1b[?2031l\x1b[?2048l")
	require.NotContains(t, string(j.render), "\x1b[?2031")
	require.NotContains(t, string(j.render), "\x1b[?2048")
}

// ?1048h is xterm's DECSC by another name, not a mode: its bit, which
// nothing reads back, is ignored, and the slot it filled is restored with
// the saved cursors, for ESC 8 and ?1048l alike.
func TestReplayIgnoresTheSaveCursorMode(t *testing.T) {
	j := joinAt(t, 80, 24, "\x1b[3;5H\x1b[31m\x1b[?1048h\x1b[m\x1b[Htext\r\n")
	require.NotContains(t, string(j.render), "1048")
	j.then(t, "\x1b8X")
	x := cellAt(j.b, 4, 2)
	require.Equal(t, "X", x.Content)
	require.Equal(t, fgOf("\x1b[31m"), x.Style.Fg)
	j.then(t, "\x1b[m\x1b[H\x1b[?1048lY")
	require.Equal(t, "Y", cellAt(j.b, 4, 2).Content)
}

// A status line drawn at the top between SCOSC and SCORC, as a prompt draws
// one: the bare CSI u takes the cursor back to where the CSI s saved it, so
// the joiner's cursor is there, not after the status line, and the next
// character lands there, as it does on the session's terminal.
func TestReplayRestoresTheCursorSCORCReturnsTo(t *testing.T) {
	const stream = "\x1b[5;10H\x1b[s\x1b[1;1Hstatus\x1b[u"
	joined, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
	require.NoError(t, fellBack)
	require.True(t, bytes.HasPrefix(joined, []byte(preamble)), "the render, not the raw ring")

	a, aHist := newReference(80, 24)
	_, _ = a.WriteString(stream)
	b, bHist := newReference(80, 24)
	_, _ = b.Write(joined)
	require.Equal(t, uv.Pos(9, 4), b.CursorPosition(), "the joiner's cursor")
	for _, term := range []*vt.Emulator{a, b} {
		_, _ = term.WriteString("X")
		require.Equal(t, "X", cellAt(term, 9, 4).Content)
	}
	require.Empty(t, sameState(a, b, *aHist, *bHist, names{}, names{}))
}

// joinOwn joins, through the fan-out, a joiner whose terminal, b, a program
// left in the state own sets, as joinAt does one at its defaults: b is given
// own, then what the joiner was sent, and must then be in a's state. The rows
// own left above b's cursor on its main screen are the joiner's earlier
// screen, which the render scrolls into b's scrollback from the cursor's row
// on, before the history: b's history must hold what own scrolled off, then
// those rows, then a's history, and is compared from a's on. A stream that
// clears history, by ED 3 or RIS, clears a's scrollback, and a raw replay's
// joiner's: then b's must hold those rows and a's history alone. For b left
// on its alternate screen, that row is the one the main screen's slot holds,
// which ?1049l, bringing b back, restores: where ?1049h saved the cursor, or
// home for a slot nothing filled.
func joinOwn(t *testing.T, cols, rows int, own, stream string) *joined {
	t.Helper()
	sent, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, cols, rows)}, 64<<10)
	require.NoError(t, fellBack)
	require.True(t, bytes.HasPrefix(sent, []byte(preamble)), "the render, not the raw ring")

	j := &joined{render: sent}
	j.a, j.aHist = newReference(cols, rows)
	cleared := false
	j.a.SetScrollbackClearFunc(func() { *j.aHist, cleared = nil, true })
	j.aNames = watchTitle(j.a)
	_, _ = j.a.WriteString(stream)
	j.b, j.bHist = newReference(cols, rows)
	j.bNames = watchTitle(j.b)
	_, _ = j.b.WriteString(own)
	row := j.b.CursorPosition().Y
	if j.b.IsAltScreen() {
		row = min(j.b.MainScreen().SavedCursor().Y, rows-1)
	}
	var earlier [][]byte
	if !cleared {
		earlier = slices.Clone(*j.bHist)
	}
	for y := range row {
		line, err := encodeLine(j.b.MainScreen().Line(y), budget)
		require.NoError(t, err)
		earlier = append(earlier, line)
	}
	_, _ = j.b.Write(sent)
	got := *j.bHist
	require.True(t, len(got) >= len(earlier) && slices.EqualFunc(earlier, got[:len(earlier)], bytes.Equal),
		"the joiner's earlier screen, above its cursor, in its scrollback: %q, then %q", earlier, got)
	j.own, *j.bHist = got[:len(earlier):len(earlier)], got[len(earlier):]
	j.requireSame(t)
	return j
}

// A clear of history the session sent, ED 3 or RIS, emptied the session's
// terminal's scrollback, and a raw replay empties the joiner's. So the render
// empties the joiner's too, once the preamble has left the joiner's earlier
// screen above the cursor: that screen then scrolls into a scrollback that
// holds nothing older, and the session's history since the clear follows it.
// With no clear in the ring, the joiner keeps the scrollback of its own.
func TestReplayClearsTheJoinersScrollbackTheSessionCleared(t *testing.T) {
	lines := func(prefix string, from, to int) string {
		var s strings.Builder
		for i := from; i < to; i++ {
			fmt.Fprintf(&s, "%s %d\r\n", prefix, i)
		}
		return s.String()
	}
	// 30 lines and a prompt on 12 rows: own 0 to own 18 in the joiner's
	// scrollback, own 19 to own 29 above its cursor.
	own := lines("own", 0, 30) + "prompt$ upterm join"
	var all []string
	for i := range 30 {
		all = append(all, fmt.Sprintf("own %d", i))
	}
	screen := all[19:]
	for _, tc := range []struct {
		name, stream string
		own          []string
	}{
		{"no clear", lines("line", 0, 30) + "the end", all},
		{"ED 3", lines("line", 0, 10) + "\x1b[3J" + lines("line", 10, 30) + "the end", screen},
		{"ED 3, nothing scrolled off after it", lines("line", 0, 30) + "\x1b[3Jthe end", screen},
		{"ED 2 then ED 3, as clear(1) sends", lines("line", 0, 30) + "\x1b[H\x1b[2J\x1b[3J" + lines("line", 30, 35) + "the end", screen},
		{"RIS", lines("line", 0, 10) + "\x1bc" + lines("line", 10, 30) + "the end", screen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := joinOwn(t, 80, 12, own, tc.stream)
			var got []string
			for _, line := range j.own {
				got = append(got, string(line))
			}
			require.Equal(t, tc.own, got, "the joiner's own lines in its scrollback")
			j.then(t, "\r\nafter\r\n"+lines("live", 0, 15))
		})
	}
}

// A program can leave the joiner's terminal with a scroll region, left and
// right margins, insert mode, LNM or origin mode set: one killed mid-draw, or
// a pager left in a region. The render draws from none of them, so it resets
// each first, where the cursor stays, on whatever row the joiner's own output
// left it: the rows above it still scroll into the joiner's scrollback, as
// they do from a terminal at its defaults, before the history, and the live
// bytes after the render land as on the session's terminal. Origin mode goes
// off too, but only after the history (see draw).
func TestReplayResetsTheJoinersRegionAndEditingModes(t *testing.T) {
	var stream strings.Builder
	for i := range 20 {
		fmt.Fprintf(&stream, "line %d\r\n", i)
	}
	stream.WriteString("the end")
	const earlier, prompt = "own 0\r\nown 1\r\nown 2\r\n", "prompt$ upterm join"
	for _, tc := range []struct{ name, own string }{
		{"none of them", ""},
		{"a scroll region, the cursor in it", "\x1b[5;10r\x1b[6;1H"},
		{"a scroll region, the cursor below it", "\x1b[3;6r\x1b[9;1H"},
		{"a scroll region, the cursor above it", "\x1b[5;10r\x1b[3;1H"},
		{"insert mode", "\x1b[4h"},
		{"LNM", "\x1b[20h"},
		{"left and right margins, the cursor inside them", "\x1b[?69h\x1b[10;40s\x1b[5;12H"},
		{"left and right margins, the cursor left of them", "\x1b[?69h\x1b[30;60s\x1b[5;3H"},
		{"left and right margins, the cursor right of them", "\x1b[?69h\x1b[10;40s\x1b[5;60H"},
		{"origin mode in a scroll region", "\x1b[5;10r\x1b[?6h\x1b[2;3H"},
		{"all of them", "\x1b[5;10r\x1b[?69h\x1b[10;40s\x1b[?6h\x1b[4h\x1b[20h\x1b[2;3H"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := joinOwn(t, 80, 12, earlier+tc.own+prompt, stream.String())
			require.False(t, j.b.Mode(ansi.ModeOrigin).IsSet(), "origin mode")
			// A line feed at the bottom, a print, and a bare line feed, which
			// returns the carriage under LNM only.
			j.then(t, "\r\nafter\nmore")
			// A print over a drawn cell, which insert mode would shift.
			j.then(t, "\x1b[1;1Hover")
			// A region and a CUP, which origin mode would place inside it.
			j.then(t, "\x1b[3;8r\x1b[2;1Hin the region\r\n\x1b[8;1H\nscrolled")
		})
	}
}

// The render draws from no link and the ASCII charsets, G0 in GL and G2 in
// GR, as a terminal starts. A joiner's terminal that a program left with a
// link open or other charsets in place, as a program that exits or is killed
// mid-link does, or a binary file printed to it, is made so before the
// history and the screen are drawn, so each prints as itself, unlinked where
// the session's isn't, and the live bytes after it land as on the session's.
func TestReplayStartsFromNoLinkAndTheASCIICharsets(t *testing.T) {
	var stream strings.Builder
	stream.WriteString("qx plain lqkj\r\n\x1b]8;;https://s.example\x07qx linked\x1b]8;;\x07 lqkj\r\n")
	for i := range 8 {
		fmt.Fprintf(&stream, "line %d qxlj\r\n", i)
	}
	stream.WriteString("\x1b]8;;https://s.example\x07qx\x1b]8;;\x07 at the end")
	for _, own := range []struct{ name, state string }{
		{"an open link", "\x1b]8;;https://joiner.example\x07"},
		{"an open link with an id", "\x1b]8;id=1;https://joiner.example\x07"},
		{"line drawing in G0", "\x1b(0"},
		{"G1 shifted in", "\x1b)0\x0e"},
		{"G2 and G3 designated, G2 shifted in", "\x1b*0\x1b+A\x1bn"},
		{"G3 shifted in", "\x1b+0\x1bo"},
		{"GR shifted", "\x1b|"},
		{"all of them", "\x1b]8;;https://joiner.example\x07\x1b(0\x1b)A\x1b*0\x1b+A\x1bo\x1b~"},
	} {
		t.Run(own.name, func(t *testing.T) {
			j := joinOwn(t, 80, 5, own.state, stream.String())
			j.then(t, "\r\nqx after\r\n\x1b]8;;https://s.example\x07qx\x1b]8;;\x07")
		})
	}
}

// A terminal that has no SCS for G2 or G3, as the Linux console's doesn't,
// takes an ESC * or ESC + alone and prints the final byte after it. The
// preamble designates before its CR, so its erase from the row's start
// clears what such a terminal printed there, wherever the joiner's cursor
// was on the row, and none of it is left on the screen or carried into the
// history drawn after it.
func TestReplayErasesWhatAnUnknownDesignationPrints(t *testing.T) {
	var stream strings.Builder
	for i := range 8 {
		fmt.Fprintf(&stream, "line %d\r\n", i)
	}
	stream.WriteString("the end")
	sent, fellBack := fanOut(t, New(), []byte(stream.String()), []uio.SizeEvent{event(1, 0, 80, 5)}, 64<<10)
	require.NoError(t, fellBack)
	// What such a terminal is given: each ESC * or ESC + taken alone, and the
	// final byte after it printed.
	printed := regexp.MustCompile(`\x1b[*+]([\x30-\x7e])`).ReplaceAll(sent, []byte("$1"))
	require.NotEqual(t, sent, printed, "the render designates G2 and G3")

	for _, own := range []string{"", "prompt$ upterm join"} {
		t.Run(fmt.Sprintf("the cursor after %q", own), func(t *testing.T) {
			a, aHist := newReference(80, 5)
			_, _ = a.WriteString(stream.String())
			b, bHist := newReference(80, 5)
			_, _ = b.WriteString(own)
			_, _ = b.Write(printed)
			for y := range b.Height() {
				require.NotContains(t, b.MainScreen().Line(y).String(), "B", "row %d", y)
			}
			require.NotContains(t, string(bytes.Join(*bHist, nil)), "B", "the history")
			require.Empty(t, sameState(a, b, *aHist, *bHist, names{}, names{}), "%q", printed)
		})
	}
}

// A program can also leave the joiner's terminal with autowrap off, in
// reverse video, with the cursor hidden or in a style of its own, with tab
// stops of its own, or on its alternate screen: one killed mid-draw, or a
// full-screen program that crashed. The render draws on the main screen at
// its defaults, and sets the tab stops in every render, so it brings
// the joiner back to its main screen first, the cursor where it was there,
// then sets each to its default, before anything is drawn: the rows above
// the cursor on the main screen still scroll into the joiner's scrollback,
// and the live bytes after the render, a print that reaches the last column
// among them, land as on the session's terminal.
//
// A joiner left on its alternate screen also has that screen cleared, and
// its slot there filled by the preamble's DECSC, which the render sets again
// only when it draws on that screen. So each joiner here leaves the cursor on
// its alternate screen home in the default pen, where the slot so filled
// restores what an unfilled one does, but where the session's alternate
// screen holds cells, and the render sets that slot.
func TestReplayResetsTheJoinersOwnModesAndScreen(t *testing.T) {
	var lines strings.Builder
	for i := range 20 {
		fmt.Fprintf(&lines, "line %d\r\n", i)
	}
	stream := lines.String() + "the end"
	// The session's alternate screen holds cells, hidden: the render goes there.
	withAlt := lines.String() + "\x1b[?1049h\x1b[3;3Hthe session's\x1b[?1049lthe end"
	// The session's own tab stops.
	tabbed := "\x1b[3g\x1b[13G\x1bH\x1b[41G\x1bH\r" + stream
	const earlier = "own 0\r\nown 1\r\nown 2\r\nprompt$ upterm join"
	for _, tc := range []struct{ name, own, stream string }{
		{"autowrap off", "\x1b[?7l", stream},
		{"reverse video", "\x1b[?5h", stream},
		{"the cursor hidden, a steady bar", "\x1b[?25l\x1b[6 q", stream},
		{"tab stops of its own", "\x1b[3g\x1b[5G\x1bH\x1b[30G\x1bH", stream},
		{"no tab stops", "\x1b[3g", stream},
		{"tab stops of its own, the session's of its own", "\x1b[3g\x1b[5G\x1bH\x1b[30G\x1bH", tabbed},
		{"on its alternate screen by ?1049h", "\x1b[?1049h\x1b[2;5Hvim's screen\x1b[H", stream},
		{"on its alternate screen by ?47h", "\x1b[?47h\x1b[2;5Hold screen\x1b[H", stream},
		{"on its alternate screen by ?47h, its main slot filled", "\x1b7\x1b[?47h\x1b[2;5Hold screen\x1b[H", stream},
		{"on its alternate screen by ?1047h", "\x1b[?1047h\x1b[2;5Hless\x1b[H", stream},
		{"on its alternate screen by ?1049h, the cursor anywhere there", "\x1b[?1049h\x1b[5;10H\x1b[31mvim's screen", withAlt},
		{"all of them", "\x1b[?7l\x1b[?5h\x1b[?25l\x1b[6 q\x1b[3g\x1b[5G\x1bH\x1b[?1049h\x1b[2;5Hvim's screen\x1b[H", stream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := joinOwn(t, 80, 12, earlier+tc.own, tc.stream)
			// A print that reaches the last column and wraps, scrolling at the
			// bottom, which autowrap off would keep in the last column.
			j.then(t, "\x1b[12;75Hwrapping at the end")
			// A tab, and a line feed at the bottom.
			j.then(t, "\r\n\tafter a tab\t|\r\nlast")
		})
	}
}

// keyboard is what io's tracker, given p, holds of what a terminal sends of
// the keyboard and the mouse: the DEC modes it tracks, each screen's kitty
// keyboard stack, as the pushes that rebuild it, and modifyOtherKeys; and the
// pops that would empty each stack, which say how deep it is past the
// entries the tracker keeps. x/vt keeps neither the stacks nor
// modifyOtherKeys, so a joiner's are compared by this.
func keyboard(p ...string) string {
	m := uio.NewModeTracker()
	for _, s := range p {
		_, _ = m.Write([]byte(s))
	}
	r := m.ReplayParts()
	pops := regexp.MustCompile(`\x1b\[<\d+u`).FindAllString(string(m.Restore()), -1)
	return fmt.Sprintf("modes %v, main %q, alternate %q, hidden alternate %q, pops %q",
		r.DECModes, r.MainKeys, r.AltKeys, r.HiddenAltKeys, pops)
}

// A program can also leave the joiner's terminal sending the keyboard or the
// mouse otherwise than a terminal starts: the cursor keys or the keypad in
// application mode, mouse reports of any kind in an encoding of their own,
// urxvt's among them, which the render otherwise leaves as it is, focus and
// colour-scheme reports, bracketed paste, modifyOtherKeys, or flags on either
// screen's kitty keyboard stack, which a program killed before it put them
// back leaves. The render sets each only where the session's terminal has it
// otherwise than a terminal starts, so it resets them all first, and the
// joiner's terminal then sends the program what the
// session's does, the stacks as deep as the session's: a stack's pops reach
// the joiner's own flags otherwise. The rows above the joiner's cursor still
// scroll into its scrollback (see joinOwn). A session that set them gets
// them set after the resets. The alternate screen's stack is popped where
// the render goes to that screen for the session's (see hiddenAlt and alt).
//
// A joiner left on its alternate screen leaves its cursor home there, for
// the slot the preamble's DECSC fills there to restore what an unfilled one
// does (see TestReplayResetsTheJoinersOwnModesAndScreen).
func TestReplayResetsTheJoinersInputModes(t *testing.T) {
	var lines strings.Builder
	for i := range 20 {
		fmt.Fprintf(&lines, "line %d\r\n", i)
	}
	stream := lines.String() + "the end"
	// The session's alternate screen showing, and hidden with cells on it,
	// which the render goes to.
	showing := stream + "\x1b[?1049h\x1b[Hvim"
	hidden := "\x1b[?1049h\x1b[Hvim\x1b[?1049l" + stream
	const on = "\x1b[?1h\x1b=\x1b[?1002h\x1b[?1006h\x1b[?1004h\x1b[?2004h\x1b[?2031h\x1b[>4;2m\x1b[>1u\x1b[>3u"
	const earlier = "own 0\r\nown 1\r\nown 2\r\nprompt$ upterm join"
	for _, tc := range []struct{ name, own, stream string }{
		{"the cursor keys", "\x1b[?1h", stream},
		{"the keypad", "\x1b=", stream},
		{"the keypad, by DECNKM", "\x1b[?66h", stream},
		{"mouse reports of presses, in SGR's encoding", "\x1b[?1000h\x1b[?1006h", stream},
		{"mouse reports of drags, in UTF-8's", "\x1b[?1002h\x1b[?1005h", stream},
		{"mouse reports of any motion", "\x1b[?1003h", stream},
		{"X10 mouse reports", "\x1b[?9h", stream},
		{"highlight mouse tracking", "\x1b[?1001h", stream},
		{"mouse reports in urxvt's encoding", "\x1b[?1000h\x1b[?1015h", stream},
		{"mouse reports in SGR's pixels", "\x1b[?1000h\x1b[?1016h", stream},
		{"focus reports", "\x1b[?1004h", stream},
		{"bracketed paste", "\x1b[?2004h", stream},
		{"colour-scheme reports", "\x1b[?2031h", stream},
		{"modifyOtherKeys", "\x1b[>4;2m", stream},
		{"modifyOtherKeys disabled", "\x1b[>4n", stream},
		{"a kitty keyboard stack", "\x1b[>1u\x1b[>3u", stream},
		{"kitty keyboard flags set on the empty stack", "\x1b[=5;1u", stream},
		{"a kitty keyboard stack deeper than kitty's", strings.Repeat("\x1b[>1u", 9), stream},
		{"a kitty keyboard stack on its alternate screen, the session's showing", "\x1b[?1049h\x1b[>3u\x1b[H", showing},
		{"a kitty keyboard stack on its alternate screen, the session's hidden", "\x1b[?1049h\x1b[>3u\x1b[H", hidden},
		{"a kitty keyboard stack on its hidden alternate screen, the session's showing", "\x1b[?1049h\x1b[>3uold\x1b[?1049l", showing},
		{"a kitty keyboard stack on its hidden alternate screen, the session's hidden", "\x1b[?1049h\x1b[>3uold\x1b[?1049l", hidden},
		{"both kitty keyboard stacks, on its alternate screen", "\x1b[>1u\x1b[?1049h\x1b[>3u\x1b[H", showing},
		{"all of them", "\x1b[?1h\x1b=\x1b[?1003h\x1b[?1006h\x1b[?1004h\x1b[?2004h\x1b[?2031h\x1b[>4;2m\x1b[>1u\x1b[?1049h\x1b[>3u\x1b[H", showing},
		{"the session's set, the joiner's not", "", on + stream},
		{"the session's set, the joiner's otherwise", "\x1b[?1000h\x1b[?1005h\x1b[>4;1m\x1b[>7u\x1b[>7u", on + stream},
		{"the session's alternate screen's stack, the joiner's own there", "\x1b[?1049h\x1b[>7u", on + stream + "\x1b[?1049h\x1b[>5u\x1b[Hvim"},
		{"the session's hidden alternate screen's stack, the joiner's own there", "\x1b[?1049h\x1b[>7u\x1b[?1049l", on + "\x1b[?1049h\x1b[>5u\x1b[?1049l" + stream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := joinOwn(t, 80, 12, earlier+tc.own, tc.stream)
			require.Equal(t, keyboard(tc.stream), keyboard(earlier+tc.own, string(j.render)))
			urxvt := ansi.DECMode(1015)
			require.Equal(t, j.a.Mode(urxvt).IsSet(), j.b.Mode(urxvt).IsSet(), "urxvt's mouse encoding, which sameState leaves out")
			if strings.HasPrefix(tc.stream, on) {
				require.True(t, j.b.Mode(ansi.ModeBracketedPaste).IsSet(), "the session's modes, set after the resets")
			}
			// A pop of one entry, which reaches whatever the stack holds under
			// its top.
			const live = "\x1b[<u\r\nafter"
			j.then(t, live)
			require.Equal(t, keyboard(tc.stream, live), keyboard(earlier+tc.own, string(j.render), live))
		})
	}

	// A session whose alternate screen holds nothing the render rebuilds
	// sends it no trip there, so the stack a joiner's own program left there
	// stays, for one that enters it later to find, as after a raw replay.
	t.Run("a kitty keyboard stack on its alternate screen, the session's untouched", func(t *testing.T) {
		for _, own := range []string{"\x1b[?1049h\x1b[>3u\x1b[H", "\x1b[?1049h\x1b[>3u\x1b[?1049l"} {
			j := joinOwn(t, 80, 12, earlier+own, stream)
			require.Contains(t, keyboard(earlier+own, string(j.render)), `main "", alternate "", hidden alternate "\x1b[>3u"`)
			require.NotContains(t, string(j.render), "\x1b[?1049h", "no trip to the alternate screen")
		}
	})
}

// A slot no DECSC has filled restores the cursor home in the default pen,
// link and charsets, as xterm's does. The render sets the slot of each screen
// it draws on, as the session's holds it, filled or not, so a live DECRC
// restores the same on a joiner whose own programs saved a slot of their own
// there. The hidden alternate screen's is set when the render goes there for
// its cells.
func TestReplaySetsASlotTheSessionNeverSaved(t *testing.T) {
	// Each leaves the cursor home, so the render scrolls none of the
	// joiner's own rows into its scrollback.
	const ownMain = "\x1b[4;9H\x1b[1;31m\x1b]8;;https://joiner.example\x07\x1b(0\x1b7\x1b(B\x1b]8;;\x07\x1b[m\x1b[H"
	const ownAlt = "\x1b[?1049h\x1b[3;7H\x1b[4;32m\x1b)0\x0e\x1b7\x0f\x1b[m\x1b[?1049l\x1b[H"
	for _, tc := range []struct{ name, own, stream, live string }{
		{"the main screen's", ownMain, "text\r\nmore", "\x1b8"},
		{"the main screen's, under the alternate screen by ?47", ownMain, "text\r\n\x1b[?47h\x1b[Halt", "\x1b[?47l\x1b8"},
		{"the alternate screen's, by ?1049", ownMain + ownAlt, "text\r\n\x1b[?1049h\x1b[Halt", "\x1b8"},
		{"the alternate screen's, by ?47", ownMain + ownAlt, "text\r\n\x1b[?47h\x1b[Halt", "\x1b8"},
		{"the alternate screen's, by ?1047", ownMain + ownAlt, "text\r\n\x1b[?1047h\x1b[Halt", "\x1b8"},
		{"the hidden alternate screen's", ownMain + ownAlt, "text\r\n\x1b[?1049h\x1b[Halt\x1b[?1049lmore", "\x1b[?47h\x1b8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := joinOwn(t, 80, 24, tc.own, tc.stream)
			j.then(t, tc.live)
			j.then(t, "qx")
		})
	}
}

// A font the session's terminal was told to use, by OSC 50, fails the render,
// named: x/vt keeps no font, so a joiner given the render would draw in its
// own, where one given the raw ring changes font as the session's did. Every
// OSC 50 that doesn't ask counts, as xterm reads one: a font name, a font by
// its index (#), an empty one, which xterm answers with the bell, and iTerm2's
// and Konsole's key=value settings, such as the cursor's shape. A query, whose
// font starts with ?, the filter drops before the ring, and the emulation,
// given one directly, doesn't count either.
func TestReplayFailsOnAFontChange(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"a font name", "\x1b]50;fixed\x07"},
		{"a font name ended by ST", "\x1b]50;-misc-fixed-medium-r-normal--20-*\x1b\\"},
		{"the next font", "\x1b]50;#+1\x07"},
		{"a font by its index, with a name", "\x1b]50;#3 9x15\x07"},
		{"a cursor shape", "\x1b]50;CursorShape=1\x07"},
		{"an empty font", "\x1b]50;\x07"},
		{"no font at all", "\x1b]50\x07"},
		{"a font, then text", "\x1b]50;fixed\x07after"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a font change")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"the font asked for", "\x1b]50;?\x07"},
		{"the next font asked for", "\x1b]50;?+1\x07"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
			_, err := renderAt(t, 80, 24, "text\r\n"+tc.stream+"more\r\n")
			require.NoError(t, err, "the query given to the emulation")
		})
	}
}

// DECSACE 2 (CSI 2 * x), which makes DECCARA and DECRARA change the exact
// rectangle they name instead of the stream of cells from its first corner to
// its last, fails the render, named: x/vt keeps no extent, so a joiner given
// the render would apply a live DECCARA to the stream, where the session's
// terminal applies it to the rectangle. It still does once the stream is
// selected again. DECSACE reads only its first parameter, as xterm's does,
// and the stream, 0, 1 or none, is the default; DECREQTPARM, the same final
// with no intermediate, isn't DECSACE.
func TestReplayFailsOnARectangularAttributeExtent(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"the rectangle", "\x1b[2*x"},
		{"the rectangle by the first parameter", "\x1b[2;1*x"},
		{"the rectangle, then the stream again", "\x1b[2*x\x1b[0*x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a rectangular attribute extent")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"the stream", "\x1b[1*x"},
		{"the stream by 0", "\x1b[0*x"},
		{"the default", "\x1b[*x"},
		{"the rectangle by a later parameter", "\x1b[1;2*x"},
		{"no intermediate", "\x1b[2x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
		})
	}
}

// DECSCL (CSI Pl ; Pc " p), which sets the terminal's conformance level and
// whether it sends 7-bit or 8-bit controls, fails the render, named, once the
// stream has sent one, whatever its parameters, and still after a DECSTR:
// x/vt does nothing for it, where xterm's soft-resets the terminal as well.
// DECSTR (CSI ! p) and DECRQM (CSI Ps $ p, CSI ? Ps $ p), the same final
// with another intermediate, aren't DECSCL, nor is a CSI p with none; DECRQM,
// which the filter drops, doesn't count given to the emulation directly
// either.
func TestReplayFailsOnAConformanceLevel(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"a VT100, with 7-bit controls", "\x1b[61;1\"p"},
		{"a VT200", "\x1b[62\"p"},
		{"a VT500, with 8-bit controls", "\x1b[65;2\"p"},
		{"no parameters", "\x1b[\"p"},
		{"a level xterm doesn't have", "\x1b[60\"p"},
		{"a level, then a soft reset", "\x1b[61\"p\x1b[!p"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a conformance level")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"a soft reset", "\x1b[!p"},
		{"a DEC mode asked for", "\x1b[?2026$p"},
		{"an ANSI mode asked for", "\x1b[4$p"},
		{"no intermediate", "\x1b[61;1p"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
			_, err := renderAt(t, 80, 24, "text\r\n"+tc.stream+"more\r\n")
			require.NoError(t, err, "given to the emulation")
		})
	}
}

// A terminal starts with some DEC private modes set. A reset of one that the
// render neither restores nor ignores fails it, sticky, named, while a set of
// one leaves it as it starts: DECANM's reset puts xterm in VT52 mode, which
// reads the bytes after it by other rules, x/vt following none of them, and a
// joiner given the render would read the live VT52 sequences as ANSI ones.
// The reset of a mode a terminal starts with reset changes nothing.
func TestReplayFallsBackOnADefaultModeReset(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, n := range []int{2, 1046, 1070} {
		set, reset := fmt.Sprintf("\x1b[?%dh", n), fmt.Sprintf("\x1b[?%dl", n)
		// x/vt's RIS forgets a mode it doesn't know, where xterm's keeps
		// ?1046 as it is and a VT52 reads no RIS, and a set undoes neither
		// VT52 mode nor what xterm ignored while ?1046 was reset: the reset
		// stands.
		for _, tc := range []struct {
			name, stream string
			fails        bool
		}{
			{"reset", reset, true},
			{"set, as it starts", set, false},
			{"reset, then set", reset + set, true},
			{"reset, then RIS", reset + "\x1bc", true},
		} {
			t.Run(fmt.Sprintf("?%d %s", n, tc.name), func(t *testing.T) {
				err := join(t, tc.stream)
				if !tc.fails {
					require.NoError(t, err)
					return
				}
				requireIneligible(t, err, fmt.Sprintf("a default mode reset (?%d)", n))
			})
		}
	}
	t.Run("among others", func(t *testing.T) {
		requireIneligible(t, join(t, "\x1b[?1;2;1046l"), "a default mode reset (?2)")
	})
	t.Run("a mode that starts reset", func(t *testing.T) {
		for _, stream := range []string{"\x1b[?1l", "\x1b[?45l", "\x1b[?9999l"} {
			require.NoError(t, join(t, stream), "%q", stream)
		}
	})
}

// ANSI's SRM (mode 12) is one a terminal starts with set, as xterm does, where
// its reset turns local echo on: a joiner given the render would echo nothing
// the joiner types, where a raw replay makes its terminal echo each key. Left
// reset at the handoff, it fails the render, named; a set leaves it as it
// starts, and so does RIS on xterm, as x/vt's forgets it, while DECSTR leaves
// it reset on both.
func TestReplayFallsBackOnSRMReset(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"reset", "\x1b[12l"},
		{"set, then reset", "\x1b[12h\x1b[12l"},
		{"reset, then a soft reset", "\x1b[12l\x1b[!p"},
		{"reset among others", "\x1b[4;12;20l"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a default mode reset (12)")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"set, as it starts", "\x1b[12h"},
		{"reset, then set", "\x1b[12l\x1b[12h"},
		{"reset, then RIS", "\x1b[12l\x1bc"},
		{"DEC's mode 12 reset", "\x1b[?12l"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
		})
	}
}

// A 96-character set designated into G1, G2 or G3 (ESC - F, ESC . F,
// ESC / F) fails the render, named, whatever follows: x/vt drops the
// designation and keeps the set designated before, where xterm takes ESC - A
// as ISO Latin-1's supplemental set, so the cells printed under it and the
// live text a shift sends there land otherwise on a joiner given the render.
// Every final counts, one xterm ignores too, and neither a 94-character set
// designated after it nor RIS clears the note. A 94-character set renders,
// and the live text printed under it lands as on the session's terminal.
func TestReplayFailsOnA96CharacterSet(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"Latin-1's supplement into G1", "\x1b-A"},
		{"Latin-1's supplement into G2", "\x1b.A"},
		{"Latin-1's supplement into G3", "\x1b/A"},
		{"shifted in and printed", "\x1b-A\x0eAB\x0f"},
		{"a set xterm takes only at a VT510's level", "\x1b.F"},
		{"a final xterm ignores", "\x1b/Z"},
		{"then a 94-character set into the same G-set", "\x1b-A\x1b)B"},
		{"then RIS", "\x1b-A\x1bc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a 96-character set")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"line drawing into G0", "\x1b(0"},
		{"line drawing into G1", "\x1b)0"},
		{"the UK set into G2", "\x1b*A"},
		{"ASCII into G3", "\x1b+B"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
			j := joinAt(t, 80, 24, "text\r\n"+tc.stream+"more\r\n")
			j.then(t, "\x0eqx\x1bnqx\x1boqx\x0fqx\r\n")
		})
	}
}

// A 94-character set designated by a final other than B, A or 0 that xterm
// acts on fails the render, named, whatever follows: x/vt drops the
// designation and keeps the set designated before, where xterm, at its
// default VT420 level, takes ESC ( < as DEC's user-preferred supplemental
// set, ESC ( > as DEC Technical and ESC ( % 5 as DEC's supplemental graphic
// set, and resets the G-set to ASCII for the rest, national sets among them,
// which a terminal in NRCS mode takes. One with " or & ahead of its final is
// a VT510's. Neither ASCII designated after it nor RIS clears the note, and
// one the ring has evicted, which the snapshot primes the emulator with, is
// noted too. ASCII, the UK set and line drawing render, as does a final
// xterm ignores, which leaves the set before on both, and the live text
// printed under each lands as on the session's terminal.
func TestReplayFailsOnAnother94CharacterSet(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	const state = "a 94-character set other than ASCII, British or line drawing"
	for _, final := range "124567<=CEHIJKQRYZf9>`" {
		t.Run(fmt.Sprintf("ESC ( %c", final), func(t *testing.T) {
			requireIneligible(t, join(t, "\x1b("+string(final)), state)
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"DEC Technical into G1", "\x1b)>"},
		{"DEC's user-preferred supplemental set into G2", "\x1b*<"},
		{"German into G3", "\x1b+K"},
		{"DEC's supplemental graphic set", "\x1b(%5"},
		{"Portuguese", "\x1b)%6"},
		{"DEC Turkish", "\x1b*%0"},
		{"Turkish", "\x1b+%2"},
		{"the SCS NRCS", "\x1b(%3"},
		{"Hebrew", "\x1b(%="},
		{"DEC Hebrew", "\x1b(\"4"},
		{"Greek", "\x1b)\">"},
		{"DEC Greek", "\x1b*\"?"},
		{"DEC Cyrillic", "\x1b+&4"},
		{"Russian", "\x1b(&5"},
		{"shifted in and printed", "\x1b)>\x0eab\x0f"},
		{"then ASCII into the same G-set", "\x1b(<\x1b(B"},
		{"then RIS", "\x1b(<\x1bc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), state)
		})
	}
	// A designation the ring has evicted is the session's G0 still, which
	// the snapshot primes the emulator with.
	for _, tc := range []struct{ head, state string }{{"\x1b(<", state}, {"\x1b(0", ""}} {
		t.Run(fmt.Sprintf("%q evicted", tc.head), func(t *testing.T) {
			stream := []byte(tc.head + strings.Repeat("line of text\r\n", 1000))
			sizes := []uio.SizeEvent{event(1, 0, 80, 24)}
			capt := &capturing{}
			_, _ = fanOut(t, capt, stream, sizes, 4<<10)
			require.Greater(t, capt.c.Start, uint64(len(tc.head)), "the designation is evicted")
			_, fellBack := fanOut(t, New(), stream, sizes, 4<<10)
			if tc.state == "" {
				require.NoError(t, fellBack)
			} else {
				requireIneligible(t, fellBack, tc.state)
			}
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"ASCII into G0", "\x1b(B"},
		{"line drawing into G0", "\x1b(0"},
		{"the UK set into G0", "\x1b(A"},
		{"line drawing into G1", "\x1b)0"},
		{"the UK set into G2", "\x1b*A"},
		{"ASCII into G3", "\x1b+B"},
		{"a final xterm ignores", "\x1b(3\x1b)U"},
		{"a final xterm ignores after %", "\x1b(%G"},
		{"UTF-8 selected", "\x1b%G"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
			j := joinAt(t, 80, 24, "text\r\n"+tc.stream+"more\r\n")
			j.then(t, "\x0eqx\x1bnqx\x1boqx\x0fqx\r\n")
		})
	}
}

// An XTWINOPS that changes the terminal's window (CSI Ps ; Ps ; Ps t) fails
// the render, named, whatever follows: a raw replay iconifies, moves,
// resizes, raises, lowers, maximizes the joiner's window or makes it full
// screen as the session's was, and DECSLPP (Ps 24 and up) resizes it to Ps
// lines, which xterm allows by default, where x/vt keeps no window. So do
// DECSCPP (CSI Ps $ |), which resizes it to 80 or 132 columns, and DECSNLS
// (CSI Ps * |), to Ps lines. A later operation can't be told to undo one, as
// what the joiner's window was before isn't known. A refresh, which only
// redraws, an operation xterm doesn't have, the title stack, which the
// render rebuilds, and the reports render: the filter drops the reports, and
// given to the emulation they don't count either. So do a DECSCPP to another
// width and a DECSNLS to no lines or past 255, which xterm ignores.
func TestReplayFailsOnAWindowOperation(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"de-iconify", "\x1b[1t"},
		{"iconify", "\x1b[2t"},
		{"a move", "\x1b[3;10;20t"},
		{"a resize in pixels", "\x1b[4;400;600t"},
		{"raise", "\x1b[5t"},
		{"lower", "\x1b[6t"},
		{"a resize in characters", "\x1b[8;40;100t"},
		{"maximize", "\x1b[9;1t"},
		{"full screen", "\x1b[10;1t"},
		{"DECSLPP", "\x1b[24t"},
		{"DECSLPP to 72 lines", "\x1b[72t"},
		{"a resize, then the title pushed", "\x1b[8;40;100t\x1b[22;0t"},
		{"a resize, then a resize back", "\x1b[8;40;100t\x1b[8;24;80t"},
		{"DECSCPP", "\x1b[$|"},
		{"DECSCPP to 0 columns, which is 80", "\x1b[0$|"},
		{"DECSCPP to 80 columns", "\x1b[80$|"},
		{"DECSCPP to 132 columns", "\x1b[132$|"},
		{"DECSNLS to 1 line", "\x1b[1*|"},
		{"DECSNLS to 36 lines", "\x1b[36*|"},
		{"DECSNLS to 255 lines", "\x1b[255*|"},
		{"DECSNLS, then a resize back", "\x1b[36*|\x1b[24*|"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a window operation")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"a refresh", "\x1b[7t"},
		{"no operation", "\x1b[t"},
		{"operation 0", "\x1b[0t"},
		{"an operation xterm doesn't have", "\x1b[12t\x1b[17t"},
		{"the title pushed and popped", "\x1b[22;0t\x1b[23;0t"},
		{"the window's state asked for", "\x1b[11t"},
		{"its size in pixels asked for", "\x1b[14t"},
		{"its size in characters asked for", "\x1b[18t"},
		{"its title asked for", "\x1b[21t"},
		{"DECSCPP to another width", "\x1b[100$|"},
		{"DECSNLS", "\x1b[*|"},
		{"DECSNLS to 0 lines", "\x1b[0*|"},
		{"DECSNLS to 256 lines", "\x1b[256*|"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
			_, err := renderAt(t, 80, 24, "text\r\n"+tc.stream+"more\r\n")
			require.NoError(t, err, "given to the emulation")
		})
	}
}

// Printer controller mode (CSI 5 i) fails the render, named, once the stream
// has turned it on, ended before the handoff or not: a joiner's terminal that
// has a printer sends the bytes the mode covers to it instead of drawing them,
// so a raw replay of a span the mode closed leaves them off its screen, where
// the render draws them, as x/vt drew them. Auto print (CSI ? 5 i), which
// prints each line the cursor leaves and draws it all the same, fails it too,
// named, until CSI ? 4 i or CSI 4 i, and RIS doesn't end it. Auto print ended
// before the handoff renders, as do the media copies that only print.
func TestReplayFailsOnAPrinterMode(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream, state string }{
		{"the controller", "\x1b[5i", "printer controller mode"},
		{"the controller, then text", "\x1b[5itext", "printer controller mode"},
		{"the controller ended, then on again", "\x1b[5ix\x1b[4i\x1b[5i", "printer controller mode"},
		{"auto print, then the controller", "\x1b[?5i\x1b[5i", "printer controller mode"},
		{"the controller, then auto print's end", "\x1b[5i\x1b[?4i", "printer controller mode"},
		{"the controller, then RIS", "\x1b[5i\x1bc", "printer controller mode"},
		{"the controller, then an end with another parameter", "\x1b[5i\x1b[4;0i", "printer controller mode"},
		{"the controller ended", "\x1b[5itext\x1b[4i", "printer controller mode"},
		{"the controller ended, then auto print", "\x1b[5ix\x1b[4i\x1b[?5i", "printer controller mode"},
		{"the controller ended, then RIS", "\x1b[5ix\x1b[4i\x1bc", "printer controller mode"},
		{"auto print", "\x1b[?5i", "auto print mode"},
		{"auto print, then RIS", "\x1b[?5i\x1bc", "auto print mode"},
		{"auto print ended, then on again", "\x1b[?5ix\x1b[?4i\x1b[?5i", "auto print mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), tc.state)
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"auto print ended", "\x1b[?5ix\x1b[?4i"},
		{"auto print ended by the controller's end", "\x1b[?5i\x1b[4i"},
		{"auto print ended by an end with another parameter", "\x1b[?5i\x1b[4;0i"},
		{"the ends alone", "\x1b[4i\x1b[?4i"},
		{"the screen printed", "\x1b[i\x1b[0i"},
		{"the cursor's line printed", "\x1b[?1i"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
		})
	}
}

// HP's memory lock (ESC l) and unlock (ESC m) fail the render, named, once
// either moves the scroll region's top margin, as xterm implements them: a
// lock moves it to the cursor's row and an unlock back to the screen's top.
// Once it has moved, xterm scrolls only the rows from it down and moves the
// cursor up no further than it, which x/vt, implementing neither, doesn't, so
// the emulator's screen may differ from the session's terminal's whatever
// follows, an unlock or a DECSTBM among it. A lock or an unlock that leaves
// the margin where it is renders: a lock on the region's top row, on its
// bottom row or below it, where xterm sets no region that ends at or above
// its top, and an unlock with the region at the screen's top.
func TestReplayFailsOnAMemoryLock(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream string }{
		{"a lock", "\x1bl"},
		{"a lock, then an unlock", "\x1bl\x1bm"},
		{"a lock, then lines that scroll, then an unlock", "\x1bl" + strings.Repeat("line\r\n", 30) + "\x1bm"},
		{"a lock, then a region", "\x1bl\x1b[r"},
		{"a lock above the region", "\x1b[5;20r\x1b[2H\x1bl"},
		{"a lock inside the region", "\x1b[5;20r\x1b[10H\x1bl"},
		{"an unlock under a region below the screen's top", "\x1b[5;20r\x1bm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), "a memory lock")
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"an unlock", "\x1bm"},
		{"a lock on the screen's top row", "\x1b[H\x1bl"},
		{"a lock on the region's top row", "\x1b[5;20r\x1b[5H\x1bl"},
		{"a lock on the region's bottom row", "\x1b[24H\x1bl"},
		{"a lock below the region", "\x1b[1;10r\x1b[15H\x1bl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
		})
	}
}

// A key format the tracker doesn't restore fails the render, named, whatever
// follows: XTMODKEYS (CSI > Pp ; Pv m) for any resource but modifyOtherKeys
// (4), XTFMTKEYS (CSI > Pp ; Pv f) for any, and XTMODKEYS's disable
// (CSI > Pp n), the bare one too, which xterm reads as disabling
// modifyFunctionKeys, but CSI > 4 n. Each changes how the joiner's terminal
// encodes a key it sends the program, where a raw replay sets it there.
// modifyOtherKeys, which the tracker restores, renders, and so does a
// sequence that moves no resource off the value a terminal starts with, as
// the tracker reads CSI > 4 ; m: a resource with nothing after it, which puts
// it back, or no parameters, which ctlseqs documents as putting every
// resource back and xterm reads as naming none. So do XTQMODKEYS
// (CSI ? Pp m), which the query filter drops, and SGR.
func TestReplayFailsOnAKeyFormat(t *testing.T) {
	join := func(t *testing.T, stream string) ([]byte, error) {
		t.Helper()
		return fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
	}
	for _, tc := range []struct{ name, stream string }{
		{"modifyCursorKeys", "\x1b[>1;2m"},
		{"modifyFunctionKeys", "\x1b[>2;1m"},
		{"modifyKeyboard", "\x1b[>0;1m"},
		{"with a mask of the modifiers to ignore", "\x1b[>1;2:4m"},
		{"with a mask on the resource", "\x1b[>1:4m"},
		{"formatOtherKeys", "\x1b[>4;1f"},
		{"formatCursorKeys", "\x1b[>1;1f"},
		{"modifyCursorKeys disabled", "\x1b[>1n"},
		{"modifyFunctionKeys disabled, with no parameter", "\x1b[>n"},
		{"modifyOtherKeys disabled in a form the tracker doesn't read", "\x1b[>4;1n"},
		{"one, then put back", "\x1b[>1;2m\x1b[>1m"},
		{"one, then RIS", "\x1b[>1;2m\x1bc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := join(t, tc.stream)
			requireIneligible(t, err, "a key format")
		})
	}
	for _, tc := range []struct{ name, stream, carries string }{
		{"modifyOtherKeys", "\x1b[>4;2m", "\x1b[>4;2m"},
		{"modifyOtherKeys disabled", "\x1b[>4n", "\x1b[>4n"},
		{"modifyOtherKeys put back", "\x1b[>4;2m\x1b[>4;m", ""},
		{"no parameters", "\x1b[>m\x1b[>f", ""},
		{"a resource put back", "\x1b[>1m\x1b[>4f", ""},
		{"a resource asked for", "\x1b[?1m", ""},
		{"SGR", "\x1b[1;31m", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			joined, err := join(t, tc.stream)
			require.NoError(t, err)
			if tc.carries != "" {
				require.True(t, bytes.HasPrefix(joined, []byte(preamble)), "the render: %q", joined)
				require.Contains(t, string(joined), tc.carries)
			}
			_, err = renderAt(t, 80, 24, "text\r\n"+tc.stream+"more\r\n")
			require.NoError(t, err, "given to the emulation")
		})
	}
}

// DEC locator reporting turned on, by DECELR 1 or 2 (CSI Ps ; Pu ' z), fails
// the render, named, whatever follows: the joiner's terminal would report
// the mouse to the program on its own, where a raw replay turns it on there.
// So does DECSLE (CSI Pm ' {) selecting a button event to report, by a
// parameter of 1 (a press) or 3 (a release), named apart: xterm keeps the
// selection, RIS included, for a DECELR that turns reporting on later, the
// program's live one among them, which would then report otherwise on a
// joiner given the render. DECELR 0, or any other value, turns reporting off,
// and alone renders, as does a DECSLE that only clears events (0, 2 or 4),
// and DECEFR (CSI Pt ; Pl ; Pb ; Pr ' w), which xterm ignores while
// reporting is off. DECRQLP (CSI Ps ' |), which asks for the locator's
// position, the query filter drops.
func TestReplayFailsOnLocatorReporting(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream, state string }{
		{"on", "\x1b[1'z", "locator reporting"},
		{"on for one report", "\x1b[2'z", "locator reporting"},
		{"on, in pixels", "\x1b[1;1'z", "locator reporting"},
		{"on, with the events selected", "\x1b[1'z\x1b[1;3'{", "locator reporting"},
		{"the events selected, then on", "\x1b[1;3'{\x1b[1'z", "locator reporting"},
		{"on, then off", "\x1b[1'z\x1b[0'z", "locator reporting"},
		{"on, then RIS", "\x1b[2'z\x1bc", "locator reporting"},
		{"the events selected", "\x1b[1;3'{", "locator events"},
		{"a press selected", "\x1b[1'{", "locator events"},
		{"a release selected", "\x1b[3'{", "locator events"},
		{"a press selected among clears", "\x1b[0;2;1;4'{", "locator events"},
		{"a press selected, then cleared", "\x1b[1'{\x1b[0'{", "locator events"},
		{"a release selected, then RIS", "\x1b[3'{\x1bc", "locator events"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), tc.state)
		})
	}
	for _, tc := range []struct{ name, stream string }{
		{"off", "\x1b[0'z"},
		{"off, with no parameter", "\x1b['z"},
		{"a value xterm reads as off", "\x1b[3'z"},
		{"every event cleared", "\x1b[0'{"},
		{"every event cleared, with no parameter", "\x1b['{"},
		{"an empty parameter, which xterm reads as 0", "\x1b[2;'{"},
		{"a press and a release cleared", "\x1b[2;4'{"},
		{"an event xterm doesn't have", "\x1b[5'{"},
		{"a filter rectangle", "\x1b[1;1;10;10'w"},
		{"the position asked for", "\x1b[1'|"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, join(t, tc.stream))
			_, err := renderAt(t, 80, 24, "text\r\n"+tc.stream+"more\r\n")
			require.NoError(t, err, "given to the emulation")
		})
	}
}

// screenTitleString is a window title string of GNU screen's and tmux's, as
// tmux reads one: ESC k after an ESC and any C0 controls tmux executes where
// they stand but CAN and SUB, then the title, up to the ESC, CAN or SUB that
// ends it, BEL included (tmux's rename_string state).
var screenTitleString = regexp.MustCompile("\x1b([\x00-\x17\x19\x1c-\x1f\x7f]*)k[^\x1b\x18\x1a]*")

// tmuxReads is stream as a terminal that is tmux draws it: each window title
// string taken out, as tmux takes it as the window's name and draws none of
// it, and the controls inside its ESC, which tmux executes, kept.
func tmuxReads(stream string) string {
	return screenTitleString.ReplaceAllString(stream, "$1")
}

// The session's own terminal may be tmux or GNU screen, under whose TERM
// oh-my-zsh sends a window title string, ESC k title ST, at every prompt,
// and which take it as the window's name and draw none of it. x/vt, as
// xterm, would read ESC k as a sequence done at the k and draw the title, so
// the emulation hands x/vt each as a string it consumes, and the join
// renders: a joiner's tmux, given the render and the raw bytes after it, is
// left as the session's tmux is, none of the title drawn. tmux ends the title only at an ESC, CAN or SUB,
// not at BEL; an ESC with controls inside it before the k is one, as tmux
// executes them there; and neither one with an intermediate nor one an ESC,
// CAN or SUB cancelled before the k is one. A title that starts with G, as
// kitty's graphics commands do, is no image.
func TestReplayConsumesAScreenTitleString(t *testing.T) {
	var prompts strings.Builder
	for i := range 3 {
		fmt.Fprintf(&prompts, "\x1bkzsh\x1b\\\x1b]2;owen@host: ~\x07~/src $ ls\r\n\x1bkls\x1b\\file%d\r\n", i)
	}
	for _, tc := range []struct{ name, stream string }{
		{"at every prompt", prompts.String() + "\x1bkzsh\x1b\\~/src $ "},
		{"ended by ST", "\x1bkzsh\x1b\\$ "},
		{"ended by BEL, which tmux reads as more of it", "\x1bkzsh\x07zsh too\x1b\\$ "},
		{"ended by the sequence after it", "\x1bkzsh\x1b[1m$ \x1b[m"},
		{"ended by CAN", "\x1bkzsh\x18$ "},
		{"empty", "\x1bk\x1b\\$ "},
		{"a name not in ASCII", "\x1bk✳ zsh\x1b\\$ "},
		{"a name that starts with G", "\x1bkGzsh\x1b\\$ "},
		{"a control inside its ESC", "\x1b\rkzsh\x1b\\$ "},
		{"an ESC k with an intermediate", "\x1b kzsh$ "},
		{"an ESC cancelled before the k", "\x1b\x18kzsh$ "},
		{"an ESC before the k's ESC", "\x1b\x1bkzsh\x1b\\$ "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := "text\r\n" + tc.stream
			joined, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 64<<10)
			require.NoError(t, fellBack)
			require.True(t, bytes.HasPrefix(joined, []byte(preamble)), "the render, not the raw ring")
			require.NotContains(t, string(joined), "\x1b^", "the stream's raw bytes, which the emulation's reading leaves as they are")
			a, aHist := newReference(80, 24)
			aNames := watchTitle(a)
			_, _ = a.WriteString(tmuxReads(stream))
			// The joiner's terminal is tmux too, which reads the raw bytes after
			// the handoff point, here those after an ESC k a CAN ends, which
			// closes nothing a handoff point needs, as the session's did.
			b, bHist := newReference(80, 24)
			bNames := watchTitle(b)
			_, _ = b.WriteString(tmuxReads(string(joined)))
			require.Empty(t, sameState(a, b, *aHist, *bHist, *aNames, *bNames), "the render: %q", joined)
			if !strings.Contains(tmuxReads(stream), "zsh") {
				for y := range b.Height() {
					require.NotContains(t, b.MainScreen().Line(y).String(), "zsh", "row %d", y)
				}
			}
		})
	}
}

// The emulation reads a screen title string as x/vt's parser would read
// ESC k, wherever the k lands: the ring may start after its ESC, which the
// tracker's snapshot then ends with, and the stream may be offered in pieces,
// at Start or later, split between the ESC and the k, or between an ESC, a
// control x/vt executes inside it and the k. A second ESC begins the escape
// anew; one a CAN cancels before the k, or one with an intermediate, makes
// no title string of the k, which x/vt then prints or reads as the final of
// another sequence. (io's query filter leaves the ring a lone ESC for two,
// and the control before the ESC, but what reaches the emulation is read as
// x/vt would read it whatever the filter leaves.)
func TestReplayConsumesAScreenTitleStringInPieces(t *testing.T) {
	t.Run("the ring starting after its ESC", func(t *testing.T) {
		const ring = "kzsh\x1b\\$ ls\r\n"
		modes := uio.NewModeTracker()
		_, _ = modes.Write([]byte("before\r\n\x1b"))
		c := &uio.Capture{Modes: modes, Chunks: [][]byte{[]byte(ring)}, Sizes: []uio.SizeEvent{event(1, 9, 80, 24)}, Start: 9, End: 9 + uint64(len(ring))}
		e := startFor(t, c, termsize.Size{Cols: 80, Rows: 24})
		_, err := e.Render()
		require.NoError(t, err)
		require.Equal(t, "$ ls", e.term.MainScreen().Line(0).String())
	})
	for _, tc := range []struct {
		name   string
		pieces []string
		row    string // what x/vt then draws on the row after "text"
	}{
		{"split after the ESC", []string{"text\r\n\x1b", "kzsh\x1b\\$ ls\r\n"}, "$ ls"},
		{"a control inside the ESC, in three pieces", []string{"text\r\n\x1b", "\r", "kzsh\x1b\\$ ls\r\n"}, "$ ls"},
		{"a second ESC before the k", []string{"text\r\n\x1b", "\x1bkzsh\x1b\\$ ls\r\n"}, "$ ls"},
		{"an ESC a CAN cancels before the k", []string{"text\r\n\x1b", "\x18kzsh\x1b\\$ ls\r\n"}, "kzsh$ ls"},
		{"an ESC with an intermediate", []string{"text\r\n\x1b", " kzsh$ ls\r\n"}, "zsh$ ls"},
	} {
		t.Run(tc.name+", at Start", func(t *testing.T) {
			c := captureOf("", event(1, 0, 80, 24))
			c.Chunks = nil
			for _, p := range tc.pieces {
				c.Chunks = append(c.Chunks, []byte(p))
				c.End += uint64(len(p))
			}
			e := startFor(t, c, termsize.Size{Cols: 80, Rows: 24})
			_, err := e.Render()
			require.NoError(t, err)
			require.Equal(t, "text", e.term.MainScreen().Line(0).String())
			require.Equal(t, tc.row, e.term.MainScreen().Line(1).String())
		})
		t.Run(tc.name+", fed after Start", func(t *testing.T) {
			e := startFor(t, captureOf(tc.pieces[0], event(1, 0, 80, 24)), termsize.Size{Cols: 80, Rows: 24})
			for _, p := range tc.pieces[1:] {
				require.NoError(t, e.Feed([][]byte{[]byte(p)}, nil))
			}
			_, err := e.Render()
			require.NoError(t, err)
			require.Equal(t, "text", e.term.MainScreen().Line(0).String())
			require.Equal(t, tc.row, e.term.MainScreen().Line(1).String())
		})
	}
}
