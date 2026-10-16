package replay

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/owenthereal/x/vt"
	"github.com/stretchr/testify/require"

	uio "github.com/owenthereal/upterm/io"
)

// sgrParams is the vocabulary randomSGR draws from: every attribute, its
// reset, and each colour in each of the forms ultraviolet's ReadStyle keeps
// apart, the palette's first 16 among them both as basic and as indexed
// colours, which ultraviolet compares equal.
func sgrParams(rnd *rand.Rand) string {
	switch rnd.IntN(12) {
	case 0:
		return []string{"0", "1", "2", "3", "5", "6", "7", "8", "9"}[rnd.IntN(9)]
	case 1:
		return []string{"22", "23", "24", "25", "27", "28", "29", "39", "49", "59"}[rnd.IntN(10)]
	case 2:
		return []string{"4", "4:0", "4:1", "4:2", "4:3", "4:4", "4:5"}[rnd.IntN(7)]
	case 3:
		return fmt.Sprint(30 + rnd.IntN(8))
	case 4:
		return fmt.Sprint(90 + rnd.IntN(8))
	case 5:
		return fmt.Sprint(40 + rnd.IntN(8))
	case 6:
		return fmt.Sprint(100 + rnd.IntN(8))
	case 7:
		return fmt.Sprintf("38;5;%d", rnd.IntN(20))
	case 8:
		return fmt.Sprintf("48;5;%d", rnd.IntN(256))
	case 9:
		return fmt.Sprintf("58;5;%d", rnd.IntN(16))
	case 10:
		return fmt.Sprintf("38;2;%d;%d;%d", rnd.IntN(2)*128, rnd.IntN(2)*128, rnd.IntN(256))
	default:
		return fmt.Sprintf("%d;2;%d;%d;%d", []int{48, 58}[rnd.IntN(2)], rnd.IntN(256), 0, 0)
	}
}

func randomSGR(rnd *rand.Rand) string {
	params := make([]string, 1+rnd.IntN(4))
	for i := range params {
		params[i] = sgrParams(rnd)
	}
	return "\x1b[" + strings.Join(params, ";") + "m"
}

// penOf is the pen an emulator holds after seq.
func penOf(seq string) uv.Style {
	term := vt.NewEmulator(10, 1)
	_, _ = term.WriteString(seq)
	return term.ActiveScreen().Cursor().Pen
}

// penTo takes an emulator whose pen is the model to the pen asked for,
// exactly, colour types included: SGR 31 and 38;5;1, which ultraviolet
// compares equal, are kept apart, as the joiner's terminal keeps them.
func TestEncoderPenToReachesThePen(t *testing.T) {
	rnd := rand.New(rand.NewPCG(7, 22))
	pairs := [][2]string{
		{"\x1b[31m", "\x1b[38;5;1m"},
		{"\x1b[38;5;9m", "\x1b[91m"},
		{"\x1b[1;4:3;31m", "\x1b[2;4:4m"},
		{"\x1b[5;6m", "\x1b[6m"},
	}
	for range 3000 {
		pairs = append(pairs, [2]string{randomSGR(rnd), randomSGR(rnd)})
	}
	// One emulator for every pair: each NewEmulator allocates its parser's
	// 4 MiB buffer. SGR 0 resets the whole pen.
	term := vt.NewEmulator(10, 1)
	pen := func(sgr string) uv.Style {
		_, _ = term.WriteString("\x1b[m" + sgr)
		return term.ActiveScreen().Cursor().Pen
	}
	for _, p := range pairs {
		to := pen(p[1])
		from := pen(p[0])

		enc := encoder{max: 1 << 10, pen: from}
		require.NoError(t, enc.penTo(to))
		_, _ = term.Write(enc.buf)

		got := term.ActiveScreen().Cursor().Pen
		require.True(t, got == to, "%q then %q: %+v, want %+v", p[0], enc.buf, got, to)
		require.True(t, enc.pen == to)
		if from == to {
			require.Empty(t, enc.buf, "%q to itself", p[0])
		}
	}
}

// linkTo takes an emulator whose link is the model to the link asked for.
func TestEncoderLinkToReachesTheLink(t *testing.T) {
	links := []uv.Link{
		{},
		{URL: "https://a.example/x;y"},
		{URL: "https://b.example", Params: "id=1"},
		{Params: "id=2"},
	}
	for _, from := range links {
		for _, to := range links {
			term := vt.NewEmulator(10, 1)
			_, _ = term.WriteString("\x1b]8;" + from.Params + ";" + from.URL + "\x1b\\")

			enc := encoder{max: 1 << 10, link: from}
			require.NoError(t, enc.linkTo(to))
			_, _ = term.Write(enc.buf)

			require.Equal(t, to, term.ActiveScreen().Cursor().Link, "%+v to %+v", from, to)
			require.Equal(t, to, enc.link)
			if from == to {
				require.Empty(t, enc.buf)
			}
		}
	}
}

// A row is drawn from wherever the cursor is, each cell in its own pen and
// link, a wide character once, and its trailing blanks left out; it ends at
// the zero pen and link, so the next row starts from them.
func TestEncoderRowReproducesTheRow(t *testing.T) {
	const drawn = "\x1b[1;31mab\x1b[m 中e\u0301\x1b]8;;https://x.example\x07link\x1b]8;;\x07\x1b[44m  \x1b[m"
	a := vt.NewEmulator(40, 1)
	_, _ = a.WriteString(drawn)

	enc := encoder{max: 1 << 10}
	require.NoError(t, enc.row(a.MainScreen().Line(0)))
	require.True(t, enc.pen == uv.Style{})
	require.Equal(t, uv.Link{}, enc.link)

	b := vt.NewEmulator(40, 1)
	_, _ = b.Write(enc.buf)
	require.Empty(t, sameScreen(a.MainScreen(), b.MainScreen()))
	require.Equal(t, uv.Pos(12, 0), b.CursorPosition(), "the trailing blanks were drawn")
	require.True(t, b.ActiveScreen().Cursor().Pen == uv.Style{})
	require.Equal(t, uv.Link{}, b.ActiveScreen().Cursor().Link)
}

// The cap is hard: a call that would cross it fails and appends nothing,
// later calls fail too, and the buffer never grows past it.
func TestEncoderFailsBeforeCrossingItsCap(t *testing.T) {
	enc := encoder{max: 8}
	require.NoError(t, enc.bytes([]byte("12345")))
	require.ErrorIs(t, enc.bytes([]byte("6789")), ErrOverBudget)
	require.Equal(t, "12345", string(enc.buf))
	require.ErrorIs(t, enc.bytes([]byte("6")), ErrOverBudget, "a failure sticks")
	require.LessOrEqual(t, cap(enc.buf), 8)

	big := encoder{max: 1000}
	for range 9 {
		require.NoError(t, big.bytes(make([]byte, 111)))
		require.LessOrEqual(t, cap(big.buf), 1000)
	}
}

// A failed call leaves the model as it was too: a cell whose pen fits but
// whose content doesn't leaves the pen unchanged.
func TestEncoderLeavesItsModelOnFailure(t *testing.T) {
	red := penOf("\x1b[31m")
	link := uv.Link{URL: "https://x.example"}
	enc := encoder{max: len(uv.StyleDiff(&uv.Style{}, &red)) + 1}
	err := enc.cell(&uv.Cell{Content: "中", Width: 2, Style: red, Link: link})
	require.ErrorIs(t, err, ErrOverBudget)
	require.Empty(t, enc.buf)
	require.True(t, enc.pen == uv.Style{})
	require.Equal(t, uv.Link{}, enc.link)

	line := uv.NewLine(4)
	line.Set(0, &uv.Cell{Content: "x", Width: 1, Style: red})
	enc = encoder{max: 1 << 10}
	require.NoError(t, enc.bytes([]byte("kept")))
	enc.max = len("kept") + 6
	require.ErrorIs(t, enc.row(line), ErrOverBudget)
	require.Equal(t, "kept", string(enc.buf))
	require.True(t, enc.pen == uv.Style{})
}

// The encoder checks its stop function once per row.
func TestEncoderChecksItsStopOncePerRow(t *testing.T) {
	calls := 0
	enc := encoder{max: 1 << 10, stop: func() bool {
		calls++
		return calls > 2
	}}
	line := uv.NewLine(4)
	line.Set(0, &uv.Cell{Content: "x", Width: 1})
	require.NoError(t, enc.row(line))
	require.NoError(t, enc.row(line))
	require.Equal(t, 2, calls)
	require.ErrorIs(t, enc.row(line), uio.ErrReplayDeadline)
	require.Equal(t, "xx", string(enc.buf))
}

// encodeLine is a row on its own, from and back to the zero pen and link, in
// at most max bytes.
func TestEncodeLine(t *testing.T) {
	a := vt.NewEmulator(20, 1)
	_, _ = a.WriteString("\x1b[31mred\x1b[m plain   ")
	line := a.MainScreen().Line(0)

	got, err := encodeLine(line, 1<<10)
	require.NoError(t, err)
	b := vt.NewEmulator(20, 1)
	_, _ = b.Write(got)
	require.Empty(t, sameScreen(a.MainScreen(), b.MainScreen()))
	require.True(t, b.ActiveScreen().Cursor().Pen == uv.Style{})

	_, err = encodeLine(line, len(got)-1)
	require.ErrorIs(t, err, ErrOverBudget)
}

// cup moves to a 1-based row and column.
func TestEncoderCupMovesTheCursor(t *testing.T) {
	enc := encoder{max: 1 << 10}
	require.NoError(t, enc.cup(3, 5))
	require.Equal(t, "\x1b[3;5H", string(enc.buf))
}

// charsetsTo takes an emulator whose charsets are the model to the charsets
// asked for, with one SCS per designation that differs and one shift for GL.
func TestEncoderCharsetsToReachesTheCharsets(t *testing.T) {
	sets := []charsets{
		ascii,
		{g: [4]byte{'0', 'B', 'B', 'B'}},
		{g: [4]byte{'B', '0', 'B', 'B'}, gl: 1},
		{g: [4]byte{'A', 'B', '0', 'B'}, gl: 2},
		{g: [4]byte{'B', 'B', 'B', '0'}, gl: 3},
	}
	// One emulator for every pair: SCS and the shifts set all there is.
	term := vt.NewEmulator(10, 1)
	for _, from := range sets {
		for _, to := range sets {
			var reset encoder
			reset.reset(1 << 10)
			require.NoError(t, reset.charsetsTo(from))
			_, _ = term.WriteString("\x1b(B\x1b)B\x1b*B\x1b+B\x0f")
			_, _ = term.Write(reset.buf)
			enc := encoder{max: 1 << 10, cs: from}
			require.NoError(t, enc.charsetsTo(to))
			_, _ = term.Write(enc.buf)

			d, gl, _ := term.Charsets()
			require.Equal(t, to, charsets{g: d, gl: gl}, "%+v to %+v: %q", from, to, enc.buf)
			require.Equal(t, to, enc.cs)
			if from == to {
				require.Empty(t, enc.buf)
			}
		}
	}
}

// save records the modelled pen, link and charsets as a screen's slot, and
// restore takes the model back from it, as ESC 7 and ESC 8 take the
// terminal's. A slot never saved holds the defaults.
func TestEncoderRestoreTakesTheModelFromTheSlot(t *testing.T) {
	red, blue := penOf("\x1b[31m"), penOf("\x1b[34m")
	link := uv.Link{URL: "https://x.example"}
	lines := charsets{g: [4]byte{'0', 'B', 'B', 'B'}, gl: 0}

	var enc encoder
	enc.reset(1 << 10)
	require.NoError(t, enc.penTo(red))
	require.NoError(t, enc.linkTo(link))
	require.NoError(t, enc.charsetsTo(lines))
	require.NoError(t, enc.save(mainScreen))
	require.NoError(t, enc.penTo(blue))
	require.NoError(t, enc.linkTo(uv.Link{}))
	require.NoError(t, enc.charsetsTo(ascii))
	require.NoError(t, enc.restore(mainScreen))

	term := vt.NewEmulator(10, 1)
	_, _ = term.Write(enc.buf)
	cur := term.ActiveScreen().Cursor()
	require.True(t, cur.Pen == red && enc.pen == red)
	require.Equal(t, link, cur.Link)
	require.Equal(t, link, enc.link)
	d, gl, _ := term.Charsets()
	require.Equal(t, lines, charsets{g: d, gl: gl})
	require.Equal(t, lines, enc.cs)

	enc.reset(1 << 10)
	require.NoError(t, enc.penTo(blue))
	require.NoError(t, enc.charsetsTo(lines))
	require.NoError(t, enc.restore(altScreen))
	require.True(t, enc.pen == uv.Style{})
	require.Equal(t, uv.Link{}, enc.link)
	require.Equal(t, ascii, enc.cs)
}
