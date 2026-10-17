package replay

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
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

// joiner is the joining terminal's size in these tests, which only the
// render reads.
var joiner = termsize.Size{Cols: 80, Rows: 24}

// event is a committed size event.
func event(seq uint64, offset int, cols, rows int) uio.SizeEvent {
	return uio.SizeEvent{Seq: seq, Offset: uint64(offset), Size: termsize.Size{Cols: cols, Rows: rows}}
}

// captureOf is a capture of stream from offset 0, with a fresh tracker:
// sizes[0] in effect at its start, the rest placed in it.
func captureOf(stream string, sizes ...uio.SizeEvent) *uio.Capture {
	return &uio.Capture{
		Modes:  uio.NewModeTracker(),
		Chunks: [][]byte{[]byte(stream)},
		Sizes:  sizes,
		End:    uint64(len(stream)),
	}
}

// start runs the replayer's Start on c, which must succeed.
func start(t *testing.T, c *uio.Capture) *emulation {
	t.Helper()
	em, err := New().Start(context.Background(), time.Now().Add(time.Minute), c, joiner)
	require.NoError(t, err)
	return em.(*emulation)
}

// feed offers e more of the stream, which must succeed.
func feed(t *testing.T, e *emulation, chunk string, sizes ...uio.SizeEvent) {
	t.Helper()
	require.NoError(t, e.Feed([][]byte{[]byte(chunk)}, sizes))
}

// requireHandoff checks e's handoff point.
func requireHandoff(t *testing.T, e *emulation, h int, lastSeq uint64) {
	t.Helper()
	gotH, gotSeq := e.Handoff()
	require.Equal(t, uint64(h), gotH, "the handoff offset")
	require.Equal(t, lastSeq, gotSeq, "the last event passed")
}

// countResizes counts the emulator's resizes through the test hook.
func countResizes(t *testing.T) *int {
	t.Helper()
	n := new(int)
	testHookResize = func(termsize.Size) { *n++ }
	t.Cleanup(func() { testHookResize = nil })
	return n
}

// The handoff is never inside a rune, nor right after a print, which a later
// mark could extend.
func TestReplayHandsOffBeforeASplitRune(t *testing.T) {
	const head = "abc\r\n"
	e := start(t, captureOf(head+"\xe2\x9c", event(1, 0, 80, 24)))
	requireHandoff(t, e, len(head), 1)

	feed(t, e, "\xb3")
	requireHandoff(t, e, len(head), 1)

	feed(t, e, "\r\n")
	requireHandoff(t, e, len(head)+len("✳\r\n"), 1)
	require.Equal(t, "✳", e.term.CellAt(0, 1).Content)
}

// A C0 control inside an unfinished CSI is the joiner's to execute, from the
// raw gap: the emulator never consumed it.
func TestReplayDefersTheUnfinishedTail(t *testing.T) {
	const head = "x\r\n"
	e := start(t, captureOf(head+"\x1b[1;\n", event(1, 0, 80, 24)))
	requireHandoff(t, e, len(head), 1)
	require.Equal(t, uv.Pos(0, 1), e.term.CursorPosition(), "the LF in the tail moved the cursor")

	ref, refHist := newReference(80, 24)
	_, _ = ref.WriteString(head)
	require.Empty(t, sameState(ref, e.term, *refHist, historyOf(e), "", e.title))
}

// A cluster that can still be extended waits in the tail, and the handoff
// moves past it once anything but printing follows.
func TestReplayDefersAnExtendibleCluster(t *testing.T) {
	const head = "ab\r\n"
	e := start(t, captureOf(head+"e", event(1, 0, 80, 24)))
	requireHandoff(t, e, len(head), 1)
	require.Equal(t, " ", e.term.CellAt(0, 1).Content)

	feed(t, e, "\u0301\r\n")
	requireHandoff(t, e, len(head)+len("e\u0301\r\n"), 1)
	require.Equal(t, "e\u0301", e.term.CellAt(0, 1).Content)
}

// The same inside a ZWJ sequence.
func TestReplayDefersWithinAZWJSequence(t *testing.T) {
	const head = "ab\r\n"
	e := start(t, captureOf(head+"\U0001F468\u200d", event(1, 0, 80, 24)))
	requireHandoff(t, e, len(head), 1)

	feed(t, e, "\U0001F469\r\n")
	requireHandoff(t, e, len(head)+len("\U0001F468\u200d\U0001F469\r\n"), 1)
	require.Equal(t, "\U0001F468\u200d\U0001F469", e.term.CellAt(0, 1).Content)
}

// A resize closes the cluster it follows, so the resize the door makes for a
// joiner before its capture, the ring's last event, is a handoff point after a
// prompt: no wait for more output.
func TestReplayClosesAClusterAtAResize(t *testing.T) {
	const stream = "x\r\n$ "
	e := start(t, captureOf(stream, event(1, 0, 80, 24), event(2, len(stream), 60, 24)))
	requireHandoff(t, e, len(stream), 2)
	require.False(t, e.term.Carrying())
	require.Equal(t, 60, e.term.Width())
}

// An event inside an unfinished sequence isn't applied until the sequence
// completes, and then between the bytes it fell between: the 60 X's after it
// wrap at 45 columns.
func TestReplayAppliesNoEventInsideTheTail(t *testing.T) {
	const head = "x\r\n"
	const stream = head + "\x1b[3"
	e := start(t, captureOf(stream, event(1, 0, 80, 24), event(2, len(stream), 45, 30)))
	requireHandoff(t, e, len(head), 1)
	require.Equal(t, 80, e.term.Width())

	rest := "1m" + strings.Repeat("X", 60) + "\r\n"
	feed(t, e, rest)
	requireHandoff(t, e, len(stream)+len(rest), 2)

	ref, refHist := newReference(80, 24)
	_, _ = ref.WriteString(stream)
	ref.Resize(45, 30)
	_, _ = ref.WriteString(rest)
	require.Empty(t, sameState(ref, e.term, *refHist, historyOf(e), "", e.title))
}

// Inside a batch, an event can fall inside a sequence, as it did in the
// stream. Ground state is needed only at the batch's end.
func TestReplayResizesInsideASequence(t *testing.T) {
	const before = "\x1b[3"
	after := "1m" + strings.Repeat("X", 60) + "\r\n"
	e := start(t, captureOf(before+after, event(1, 0, 80, 24), event(2, len(before), 45, 30)))
	requireHandoff(t, e, len(before)+len(after), 2)

	ref, refHist := newReference(80, 24)
	_, _ = ref.WriteString(before)
	ref.Resize(45, 30)
	_, _ = ref.WriteString(after)
	require.Empty(t, sameState(ref, e.term, *refHist, historyOf(e), "", e.title))
	require.NotNil(t, e.term.CellAt(0, 0).Style.Fg, "the SGR split by the event was lost")
}

// A stop inside a batch spends the emulation, and publishes nothing of the
// batch: neither its offset nor its events.
func TestReplayPublishesNoPartialBatch(t *testing.T) {
	t.Run("inside a write", func(t *testing.T) {
		e := start(t, captureOf("x\r\n", event(1, 0, 80, 24)))
		calls := 0
		e.stop = func() bool {
			calls++
			return calls > 1
		}

		long := strings.Repeat("y", 300<<10) + "\r\n"
		err := e.Feed([][]byte{[]byte(long)}, []uio.SizeEvent{event(2, 3, 60, 24)})
		require.ErrorIs(t, err, uio.ErrReplayDeadline)
		require.Greater(t, calls, 1, "the stop function never fired")
		requireHandoff(t, e, 3, 1)

		_, err = e.Render()
		require.ErrorIs(t, err, uio.ErrReplayDeadline)
		require.ErrorIs(t, e.Feed([][]byte{[]byte("\r\n")}, nil), uio.ErrReplayDeadline)
	})

	// Resize returns no error, so a stop inside the batch's last
	// resize is only seen by the next Write.
	t.Run("inside the resize at its end", func(t *testing.T) {
		e := start(t, captureOf("x\r\n", event(1, 0, 80, 24)))
		resizing := false
		testHookResize = func(termsize.Size) { resizing = true }
		t.Cleanup(func() { testHookResize = nil })
		e.stop = func() bool { return resizing }

		err := e.Feed(nil, []uio.SizeEvent{event(2, 3, 512, 256)})
		require.ErrorIs(t, err, uio.ErrReplayDeadline)
		requireHandoff(t, e, 3, 1)
		_, err = e.Render()
		require.ErrorIs(t, err, uio.ErrReplayDeadline)
	})
}

// 80 → 45 → 80 with no output between truncates the rows at 45,
// which 80 alone wouldn't.
func TestReplayKeepsEveryResizeEvent(t *testing.T) {
	stream := strings.Repeat("A", 80) + "\r\n"
	e := start(t, captureOf(stream, event(1, 0, 80, 24), event(2, len(stream), 45, 24), event(3, len(stream), 80, 24)))
	requireHandoff(t, e, len(stream), 3)
	require.Equal(t, 80, e.term.Width())
	require.Equal(t, strings.Repeat("A", 45), e.term.MainScreen().Line(0).String())
}

// A width shrink truncates the rows on screen, and moves nothing
// into history.
func TestReplayTruncatesAtAWidthShrink(t *testing.T) {
	stream := strings.Repeat("A", 80) + "\r\nshort\r\n"
	e := start(t, captureOf(stream, event(1, 0, 80, 24), event(2, len(stream), 45, 24)))
	requireHandoff(t, e, len(stream), 2)
	require.Equal(t, strings.Repeat("A", 45), e.term.MainScreen().Line(0).String())
	require.Equal(t, "short", e.term.MainScreen().Line(1).String())
	require.Empty(t, historyOf(e))
}

// A height shrink keeps the cursor's row, moving the rows above it that
// no longer fit into history.
func TestReplayKeepsTheCursorLineAtAHeightShrink(t *testing.T) {
	var lines []string
	for i := 1; i <= 23; i++ {
		lines = append(lines, fmt.Sprintf("L%02d", i))
	}
	stream := strings.Join(lines, "\r\n")
	e := start(t, captureOf(stream, event(1, 0, 80, 24), event(2, len(stream), 80, 10)))
	requireHandoff(t, e, len(stream), 2)

	require.Equal(t, uv.Pos(3, 9), e.term.CursorPosition())
	for y := range 10 {
		require.Equal(t, lines[13+y], e.term.MainScreen().Line(y).String())
	}
	var want [][]byte
	for _, l := range lines[:13] {
		want = append(want, []byte(l))
	}
	require.Equal(t, want, historyOf(e))
}

// Claude Code's resize repaint clears the screen and the
// history, then draws its transcript again; the history holds it once.
func TestReplayED3ClearsHistory(t *testing.T) {
	var transcript strings.Builder
	for i := 1; i <= 12; i++ {
		fmt.Fprintf(&transcript, "T%02d\r\n", i)
	}
	stream := transcript.String() + "\x1b[2J\x1b[3J\x1b[H" + transcript.String()
	e := start(t, captureOf(stream, event(1, 0, 80, 5)))

	var want [][]byte
	for i := 1; i <= 8; i++ {
		want = append(want, fmt.Appendf(nil, "T%02d", i))
	}
	require.Equal(t, want, historyOf(e))
}

// A size over the cap fails the replay, wherever it is in the
// capture.
func TestReplayCapsTheSize(t *testing.T) {
	over := event(2, 3, 600, 300)
	for _, sizes := range [][]uio.SizeEvent{
		{event(1, 0, 600, 300)},
		{event(1, 0, 80, 24), over},
	} {
		resizes := countResizes(t)
		_, err := New().Start(context.Background(), time.Now().Add(time.Minute), captureOf("x\r\n", sizes...), joiner)
		require.ErrorIs(t, err, ErrSizeCap)
		require.Zero(t, *resizes)
	}

	// At the cap is within it.
	e := start(t, captureOf("x\r\n", event(1, 0, 80, 24), event(2, 3, 512, 256)))
	require.Equal(t, 512, e.term.Width())
}

// Feed validates every size it is offered before it resizes or
// allocates anything, and either failure spends the emulation.
func TestFeedValidatesEveryNewSizeFirst(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  uio.SizeEvent
		want error
	}{
		{"over the cap", event(3, 6, 600, 300), ErrSizeCap},
		{"0x0", event(3, 6, 0, 0), uio.ErrReplayCoverage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := start(t, captureOf("x\r\n", event(1, 0, 80, 24)))
			resizes := countResizes(t)

			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			err := e.Feed([][]byte{[]byte("y\r\nz\r\n")}, []uio.SizeEvent{event(2, 3, 60, 24), tc.bad})
			runtime.ReadMemStats(&after)

			require.ErrorIs(t, err, tc.want)
			require.Zero(t, *resizes, "a size was applied before every size was validated")
			require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(64<<10))
			requireHandoff(t, e, 3, 1)
			require.ErrorIs(t, e.Feed([][]byte{[]byte("\r\n")}, nil), tc.want)
			_, err = e.Render()
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// The tracker and the emulator must agree on the screen showing and on
// every DEC mode both track, both ways.
func TestReplayFailsWhenTheTrackerDisagrees(t *testing.T) {
	for _, tc := range []struct {
		name            string
		tracker, emulat string
	}{
		{"the tracker on the alternate screen", "\x1b[?1049h", ""},
		{"the emulator on the alternate screen", "", "\x1b[?1049h"},
		{"a mode only the tracker set", "\x1b[?2004h", ""},
		{"a mode only the emulator set", "", "\x1b[?1000h"},
		{"a mode only the emulator reset", "", "\x1b[?25l"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := start(t, captureOf("x\r\n", event(1, 0, 80, 24)))
			require.NoError(t, e.consistent())
			_, _ = e.modes.Write([]byte(tc.tracker))
			_, _ = e.term.WriteString(tc.emulat)

			_, err := e.Render()
			require.ErrorIs(t, err, ErrTrackerDisagrees)
		})
	}

	t.Run("agreeing", func(t *testing.T) {
		e := start(t, captureOf("\x1b[?2004h\x1b[?1000h\x1b[?25l\x1b[?1049hx\r\n", event(1, 0, 80, 24)))
		require.NoError(t, e.consistent())
	})
}

// At each handoff point the tracker clone is outside every sequence
// too, or the two parsers disagree on where one ends.
func TestReplayFailsWhenTheTrackerIsInsideASequence(t *testing.T) {
	e := start(t, captureOf("x\r\n", event(1, 0, 80, 24)))
	// An OSC only the tracker opened: the CR and LF that end the emulator's
	// batch are its payload.
	_, _ = e.modes.Write([]byte("\x1b]0;"))

	require.ErrorIs(t, e.Feed([][]byte{[]byte("y\r\n")}, nil), ErrTrackerDisagrees)
	requireHandoff(t, e, 3, 1)
	_, err := e.Render()
	require.ErrorIs(t, err, ErrTrackerDisagrees)
}

// A batch that ended where the emulator still carries a cluster is
// a broken invariant, never a handoff point.
func TestReplayFailsAtAHandoffThatCarriesACluster(t *testing.T) {
	e := start(t, captureOf("x\r\ne", event(1, 0, 80, 24)))
	requireHandoff(t, e, 3, 1)

	require.ErrorIs(t, e.consume(4, 0), ErrHandoffInvariant)
	requireHandoff(t, e, 3, 1)
}

// An event of the size already in effect is a no-op the emulation skips,
// in the emulator and the tracker both, since a resize would reset the
// margins and the tab stops. It is still passed, so the handoff reports it:
// otherwise io would wait for the emulation to reach it.
func TestReplaySkipsASameSizeEvent(t *testing.T) {
	const head = "\x1b[2;5r\x1b[3g"
	stream := head + "x\r\n"
	resizes := countResizes(t)
	e := start(t, captureOf(stream, event(1, 0, 80, 24), event(2, len(head), 80, 24)))
	requireHandoff(t, e, len(stream), 2)
	require.Zero(t, *resizes)

	require.Equal(t, uv.Rect(0, 1, 80, 4), e.term.ActiveScreen().ScrollRegion())
	require.Empty(t, e.term.TabStops())
	require.Equal(t, []byte("\x1b[2;5r"), e.modes.Snapshot())
}

// The emulator starts in the state the tracker clone describes as
// of the ring's first byte, a sequence the ring starts inside included.
func TestReplayPrimesTheEmulatorWithTheTrackersSnapshot(t *testing.T) {
	modes := uio.NewModeTracker()
	_, _ = modes.Write([]byte("\x1b[?2004h\x1b[?1049h\x1b[3"))
	snapshot := modes.Snapshot()
	const stream = "1mX\r\n"
	c := &uio.Capture{
		Modes:  modes,
		Chunks: [][]byte{[]byte(stream)},
		Sizes:  []uio.SizeEvent{event(1, 0, 80, 24)},
		Start:  100,
		End:    100 + uint64(len(stream)),
	}
	e := start(t, c)

	requireHandoff(t, e, 100+len(stream), 1)
	require.True(t, e.term.IsAltScreen())
	require.True(t, e.term.Mode(ansi.ModeBracketedPaste).IsSet())
	ref, refHist := newReference(80, 24)
	_, _ = ref.Write(snapshot)
	_, _ = ref.WriteString(stream)
	require.Empty(t, sameState(ref, e.term, *refHist, historyOf(e), "", e.title))
	require.NotNil(t, e.term.CellAt(0, 0).Style.Fg, "the SGR the ring starts inside was lost")
	require.NoError(t, e.consistent())
}

// No scrollback on either screen, the history kept through the
// scroll-off function instead; replies discarded, so a query in the stream
// doesn't block the emulator on a pipe nobody reads; the title kept.
func TestReplaySetsUpTheEmulator(t *testing.T) {
	stream := "\x1b[c\x1b]2;the title\x07" + strings.Repeat("line\r\n", 30)
	type started struct {
		em  uio.Emulation
		err error
	}
	done := make(chan started, 1)
	go func() {
		em, err := New().Start(context.Background(), time.Now().Add(time.Minute), captureOf(stream, event(1, 0, 80, 24)), joiner)
		done <- started{em, err}
	}()
	var s started
	select {
	case s = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a reply blocked the emulator")
	}
	require.NoError(t, s.err)
	e := s.em.(*emulation)

	requireHandoff(t, e, len(stream), 1)
	require.Equal(t, "the title", e.title)
	require.Zero(t, e.term.MainScreen().Scrollback().MaxLines())
	require.Zero(t, e.term.ScrollbackLen())
	require.Nil(t, e.term.AltScreen().Scrollback())
	require.Len(t, historyOf(e), 7)
}

// The history keeps the newest lines that fit its budget, each
// costing its bytes and the CRLF the render follows it with; a line over the
// whole budget is dropped, and the clear function empties it.
func TestHistoryKeepsTheNewestLinesWithinItsBudget(t *testing.T) {
	line := func(s string) uv.Line {
		l := uv.NewLine(20)
		for i, r := range s {
			l.Set(i, &uv.Cell{Content: string(r), Width: 1})
		}
		return l
	}
	// "aaa" costs 3 + 2: two such lines fit, and a third pushes one out.
	h := history{max: 10}
	for _, s := range []string{"aaa", "bbb", "ccc"} {
		h.push(line(s))
	}
	require.Equal(t, [][]byte{[]byte("bbb"), []byte("ccc")}, collect(&h))

	h.push(line("ddddddddddddd"))
	require.Equal(t, [][]byte{[]byte("bbb"), []byte("ccc")}, collect(&h), "a line over the budget alone")

	h.push(line(""))
	require.Equal(t, [][]byte{[]byte("ccc"), {}}, collect(&h))

	h.clear()
	require.Empty(t, collect(&h))
	h.push(line("eee"))
	require.Equal(t, [][]byte{[]byte("eee")}, collect(&h))
}

// The history takes at most its budget, and keeps as many lines as fit
// it, even of lines that cost the render only their CRLF.
func TestHistoryStaysWithinItsBudget(t *testing.T) {
	h := history{max: budget}
	blank := uv.NewLine(8)
	// Three times what it keeps, so the oldest lines have gone, twice over.
	for range 3 * budget / len(crlf) {
		h.push(blank)
	}
	kept := 0
	for range h.all() {
		kept++
	}
	require.Equal(t, budget/len(crlf), kept)
	require.LessOrEqual(t, len(h.data), budget)
}

// The history tells its lines apart by the CRLF the render follows each
// with, which no line holds of its own: the parser leaves the C0 controls out
// of an OSC string, so a line linked by an OSC 8 written with a CR LF inside
// it scrolls off as one line, within the budget.
func TestHistoryKeepsALinkedLineWhole(t *testing.T) {
	h := history{max: 64}
	term := vt.NewEmulator(10, 1)
	term.SetScrollbackSize(0)
	term.SetScrollOffFunc(h.push)
	_, _ = term.WriteString("\x1b]8;;http://a\r\nb\x07x\r\n")
	lines := collect(&h)
	require.Len(t, lines, 1, "%q", h.data)
	require.Contains(t, string(lines[0]), "x")
	require.LessOrEqual(t, len(h.data), h.max)
}

func collect(h *history) [][]byte {
	lines := [][]byte{}
	for l := range h.all() {
		lines = append(lines, append([]byte{}, l...))
	}
	return lines
}

// captureFrom is a capture of stream from offset 100, whose first byte the
// tracker modes describes.
func captureFrom(modes *uio.ModeTracker, stream string) *uio.Capture {
	return &uio.Capture{
		Modes:  modes,
		Chunks: [][]byte{[]byte(stream)},
		Sizes:  []uio.SizeEvent{event(1, 0, 80, 24)},
		Start:  100,
		End:    100 + uint64(len(stream)),
	}
}

// A ring that starts inside a sequence it doesn't end has no handoff point:
// the emulator is still inside the sequence the tracker primed it with, and a
// render of that state, followed by the ring, would print the sequence's
// rest as text.
func TestReplayFailsWhenTheRingStartsInsideAnEndlessSequence(t *testing.T) {
	modes := uio.NewModeTracker()
	_, _ = modes.Write([]byte("\x1b]0;a ti"))
	_, err := New().Start(context.Background(), time.Now().Add(time.Minute), captureFrom(modes, "tle still going"), joiner)
	require.ErrorIs(t, err, errNoHandoff)
}

// A sequence longer than the tracker keeps, in flight at the ring's first
// byte, leaves the tracker inside it with nothing to prime the emulator
// with, which would print its rest as text. That is the tracker's bound, not
// a disagreement between the two parsers: the join falls back, saying so.
func TestReplayFallsBackWhenTheRingStartsInsideALongSequence(t *testing.T) {
	w := uio.NewMultiWriter(1 << 10)
	var fellBack []error
	w.SetReplayer(New(), func(err error) { fellBack = append(fellBack, err) })
	w.Pinned(joiner)
	// An OSC 52 copy of 8 KiB, the ring's 1 KiB inside it.
	_, _ = w.Write([]byte("\x1b]52;c;" + strings.Repeat("QUFB", 2<<10)))
	_, _ = w.Write([]byte("\x07x\r\n"))

	var got bytes.Buffer
	require.NoError(t, w.AppendSized(t.Context(), time.Now().Add(time.Minute), joiner, &got))
	require.Len(t, fellBack, 1)
	require.ErrorIs(t, fellBack[0], errRingStartsInsideALongSequence)
	require.NotErrorIs(t, fellBack[0], ErrTrackerDisagrees)
	require.True(t, bytes.HasSuffix(got.Bytes(), []byte("QUFB\x07x\r\n")), "the raw ring: %q", got.Bytes())
}

// A same-size event closes no cluster, since it is skipped, so it is no
// candidate for a batch's end: after a prompt, it waits in the tail.
func TestReplayEndsNoBatchAtASameSizeEvent(t *testing.T) {
	const head = "x\r\n"
	stream := head + "$ "
	e := start(t, captureOf(stream, event(1, 0, 80, 24), event(2, len(stream), 80, 24)))
	requireHandoff(t, e, len(head), 1)

	feed(t, e, "\r\n")
	requireHandoff(t, e, len(stream)+2, 2)
}

// An event io couldn't have offered, out of Seq order or outside what was
// offered, spends the emulation rather than being placed somewhere.
func TestFeedRefusesAnEventItCantPlace(t *testing.T) {
	for _, tc := range []struct {
		name  string
		event uio.SizeEvent
	}{
		{"offered before", event(1, 3, 60, 24)},
		{"before the end of what was offered", event(2, 2, 60, 24)},
		{"past the end of what is offered", event(2, 7, 60, 24)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := start(t, captureOf("x\r\n", event(1, 0, 80, 24)))
			resizes := countResizes(t)
			err := e.Feed([][]byte{[]byte("y\r\n")}, []uio.SizeEvent{tc.event})
			require.ErrorIs(t, err, uio.ErrReplayCoverage)
			require.Zero(t, *resizes)
			requireHandoff(t, e, 3, 1)
		})
	}
}

// The lookahead rescans the tail once for each event that could
// end the batch, so events inside a span that ends without a closure (a
// string CAN aborts, then text) cost a rescan each: about 1,024 of 256 KiB
// at worst. The stop function is asked before each, and once it says stop,
// no further rescan runs, so the overshoot is one rescan of at most the tail,
// here under one meter interval.
func TestReplayChecksItsStopBeforeEachRescan(t *testing.T) {
	e := start(t, captureOf("x\r\n", event(1, 0, 80, 24)))
	calls := 0
	e.stop = func() bool {
		calls++
		return calls > 3
	}

	const open = "\x1b]0;"
	payload := strings.Repeat("a", 32<<10)
	chunk := open + payload + "\x18abc"
	require.Less(t, len(chunk), vt.MeterInterval)
	var events []uio.SizeEvent
	for i := range 200 {
		cols := 60
		if i%2 == 1 {
			cols = 80
		}
		events = append(events, event(uint64(2+i), 3+len(open)+100*(i+1), cols, 24))
	}

	err := e.Feed([][]byte{[]byte(chunk)}, events)
	require.ErrorIs(t, err, uio.ErrReplayDeadline)
	require.Equal(t, 4, calls, "a rescan ran after the stop function said stop, or none asked it")
	requireHandoff(t, e, 3, 1)
}
