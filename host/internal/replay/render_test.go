package replay

import (
	"bytes"
	"context"
	"fmt"
	"image/color"
	"regexp"
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
	aTitle, bTitle *string
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
	j.aTitle = watchTitle(j.a)
	_, _ = j.a.WriteString(stream)
	j.b, j.bHist = newReference(cols, rows)
	j.bTitle = watchTitle(j.b)
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
	require.Empty(t, sameState(j.a, j.b, *j.aHist, *j.bHist, *j.aTitle, *j.bTitle), "the render: %q", j.render)
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
		require.Empty(t, sameState(a, b, *aHist, *bHist, "", ""), "the render: %q", render)
		require.Equal(t, "$ vim notes", b.MainScreen().Line(2).String())
		for _, term := range []*vt.Emulator{a, b} {
			_, _ = term.WriteString("echo hi\r\nhi\r\n$ ")
		}
		require.Empty(t, sameState(a, b, *aHist, *bHist, "", ""))
	})
}

// The region comes from the emulator, which a resize resets, wherever the
// DECSTBM was: in the ring, or in the state the ring starts in.
func TestReplayMarginsComeFromTheEmulator(t *testing.T) {
	decstbm := regexp.MustCompile(`\x1b\[[0-9;]*r`)
	tall := termsize.Size{Cols: 80, Rows: 30}

	t.Run("in the ring", func(t *testing.T) {
		const stream = "\x1b[2;10rtext\r\n"
		e := startFor(t, captureOf(stream, event(1, 0, 80, 24), event(2, len(stream), 80, 30)), tall)
		render, err := e.Render()
		require.NoError(t, err)
		require.NotRegexp(t, decstbm, string(render))

		a, aHist := newReference(80, 24)
		_, _ = a.WriteString(stream)
		a.Resize(80, 30)
		b, bHist := newReference(80, 30)
		_, _ = b.Write(render)
		require.Empty(t, sameState(a, b, *aHist, *bHist, "", ""))
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
		require.NotRegexp(t, decstbm, string(render))
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
		require.Empty(t, sameState(a, b, (*aHist)[3:], *bHist, "", ""))
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
		"\x1b[4h", "\x1b=", "\x1b[?5h", "\x1b]2;a title\x07",
		"\x1b[1 q", "\x1b[2 q", "\x1b[3 q", "\x1b[4 q", "\x1b[5 q", "\x1b[6 q",
		"\x1b[?7l", "\x1b[m", "\x1b[1;4:3;38;2;1;2;3m",
		"\x1b]8;;https://x.example\x07", "\x1b]8;id=1;\x07",
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
			require.Len(t, regexp.MustCompile(`\x1b\[[0-9;]*r`).FindAll(j.render, -1), 1)
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
// default style isn't.
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
	require.NotContains(t, string(render), " q")
	require.NotContains(t, string(render), "\x1b]2;")
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
			require.Empty(t, sameState(a, b, *aHist, *bHist, "", ""))
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

// A mode that only changes how the terminal encodes the keyboard or the
// mouse is neither restored nor a reason to fall back: the join renders
// without it, as the raw replay's mode snapshot leaves it out. readline
// sends ?1034h, the meta key's, at every prompt where the terminfo entry has
// it, as xterm-256color's does.
func TestReplayIgnoresInputOnlyModes(t *testing.T) {
	for _, n := range []int{1007, 1015, 1034, 1035, 1036, 1037, 1039, 1050, 1051, 1052, 1053, 1060, 1061, 9001} {
		t.Run(fmt.Sprintf("?%d", n), func(t *testing.T) {
			set := fmt.Sprintf("\x1b[?%dh", n)
			j := joinAt(t, 80, 24, set+"$ ls\r\n")
			require.NotContains(t, string(j.render), set)
		})
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
