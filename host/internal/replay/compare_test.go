package replay

import (
	"bytes"
	"fmt"
	"image/color"
	"maps"
	"slices"
	"testing"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/owenthereal/x/ansi"
	"github.com/owenthereal/x/vt"
	"github.com/stretchr/testify/require"
)

// newReference returns an emulator fed by a test directly, as the stream's
// own terminal was, with the lines that scroll off its main screen collected
// through encodeLine, as the replay's history collects them, and cleared when
// the stream clears history.
func newReference(cols, rows int) (*vt.Emulator, *[][]byte) {
	ref := vt.NewEmulator(cols, rows)
	ref.SetReplyFunc(func([]byte) {})
	var hist [][]byte
	ref.SetScrollOffFunc(func(line uv.Line) {
		enc, err := encodeLine(line, budget)
		if err != nil {
			panic(err)
		}
		hist = append(hist, enc)
	})
	ref.SetScrollbackClearFunc(func() { hist = nil })
	return ref, &hist
}

// historyOf returns the lines the replay's history holds, oldest first.
func historyOf(e *emulation) [][]byte {
	var lines [][]byte
	for line := range e.hist.all() {
		lines = append(lines, bytes.Clone(line))
	}
	return lines
}

// sameState reports the first difference between two emulators, or "" when
// there is none: their sizes, the screen showing, the cells and styles on
// both screens (the hidden one included), the active screen's current
// cursor (position, pen, link, pending wrap; the other screen's is never seen
// again, spec A15), both screens' saved slots, compared by what DECRC would
// restore, the modes, the charsets and a pending single shift, the one
// scroll region, the tab stops, REP's last character, a carried cluster, and
// the history lines each side collected.
func sameState(a, b *vt.Emulator, aHist, bHist [][]byte) string {
	if a.Width() != b.Width() || a.Height() != b.Height() {
		return fmt.Sprintf("size: %dx%d vs %dx%d", a.Width(), a.Height(), b.Width(), b.Height())
	}
	if a.IsAltScreen() != b.IsAltScreen() {
		return fmt.Sprintf("alternate screen showing: %v vs %v", a.IsAltScreen(), b.IsAltScreen())
	}
	for _, s := range []struct {
		name   string
		sa, sb *vt.Screen
	}{
		{"main", a.MainScreen(), b.MainScreen()},
		{"alternate", a.AltScreen(), b.AltScreen()},
	} {
		if d := sameScreen(s.sa, s.sb); d != "" {
			return s.name + " screen: " + d
		}
		if d := sameSlot(s.sa.SavedCursor(), s.sb.SavedCursor()); d != "" {
			return s.name + " saved slot: " + d
		}
	}
	ca, cb := a.ActiveScreen().Cursor(), b.ActiveScreen().Cursor()
	if ca.Position != cb.Position {
		return fmt.Sprintf("cursor: %v vs %v", ca.Position, cb.Position)
	}
	if canonical(ca.Pen) != canonical(cb.Pen) {
		return fmt.Sprintf("pen: %+v vs %+v", ca.Pen, cb.Pen)
	}
	if ca.Link != cb.Link {
		return fmt.Sprintf("link: %+v vs %+v", ca.Link, cb.Link)
	}
	if a.PendingWrap() != b.PendingWrap() {
		return fmt.Sprintf("pending wrap: %v vs %v", a.PendingWrap(), b.PendingWrap())
	}
	if d := sameModes(a.Modes(), b.Modes()); d != "" {
		return d
	}
	da, gla, gra := a.Charsets()
	db, glb, grb := b.Charsets()
	if da != db || gla != glb || gra != grb {
		return fmt.Sprintf("charsets: %q GL %d GR %d vs %q GL %d GR %d", da[:], gla, gra, db[:], glb, grb)
	}
	if a.SingleShift() != b.SingleShift() {
		return fmt.Sprintf("single shift: %d vs %d", a.SingleShift(), b.SingleShift())
	}
	if ra, rb := a.ActiveScreen().ScrollRegion(), b.ActiveScreen().ScrollRegion(); ra != rb {
		return fmt.Sprintf("scroll region: %v vs %v", ra, rb)
	}
	if ta, tb := a.TabStops(), b.TabStops(); !slices.Equal(ta, tb) {
		return fmt.Sprintf("tab stops: %v vs %v", ta, tb)
	}
	if a.LastChar() != b.LastChar() {
		return fmt.Sprintf("REP's last character: %q vs %q", a.LastChar(), b.LastChar())
	}
	if a.Carrying() != b.Carrying() {
		return fmt.Sprintf("carrying a cluster: %v vs %v", a.Carrying(), b.Carrying())
	}
	if !slices.EqualFunc(aHist, bHist, bytes.Equal) {
		return fmt.Sprintf("history: %q vs %q", aHist, bHist)
	}
	return ""
}

// sameScreen compares two screens of one size cell by cell, styles by
// canonical.
func sameScreen(a, b *vt.Screen) string {
	for y := range a.Height() {
		la, lb := a.Line(y), b.Line(y)
		for x := range la {
			ca, cb := la[x], lb[x]
			ca.Style, cb.Style = canonical(ca.Style), canonical(cb.Style)
			if ca != cb {
				return fmt.Sprintf("cell %d,%d: %+v vs %+v", x, y, la[x], lb[x])
			}
		}
	}
	return ""
}

// canonical is a pen as compared here: exactly, colour types included, so
// SGR 31 and 38;5;1, which ultraviolet compares equal by value, stay apart,
// as a terminal with its own palette keeps them. Both sides' colours are the
// upstream ansi types ultraviolet's ReadStyle makes, so == compares them.
//
// Every colour but the palette's two forms is taken as the RGB the render
// writes it as, 38;2 at 8 bits a channel, since that is all a reader of the
// render can get back: CMYK and transparent (spec A30), and the alpha of an
// RGBA.
func canonical(s uv.Style) uv.Style {
	s.Fg, s.Bg, s.UnderlineColor = rgb(s.Fg), rgb(s.Bg), rgb(s.UnderlineColor)
	return s
}

func rgb(c color.Color) color.Color {
	switch c.(type) {
	case color.RGBA, color.RGBA64, color.NRGBA, color.NRGBA64, color.CMYK,
		color.Alpha, color.Alpha16, color.Gray, color.Gray16:
		r, g, b, _ := c.RGBA()
		return color.RGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: 0xff}
	}
	return c
}

// sameSlot compares two saved slots by what DECRC restores from each: a slot
// no DECSC filled reports those defaults already, so only Saved itself, and
// the cursor's Hidden, Style and Steady, which DECRC never restores, are left
// out.
func sameSlot(a, b vt.Cursor) string {
	sa, sb := a.Saved, b.Saved
	sa.Saved, sb.Saved = false, false
	switch {
	case a.Position != b.Position:
		return fmt.Sprintf("position %v vs %v", a.Position, b.Position)
	case canonical(a.Pen) != canonical(b.Pen):
		return fmt.Sprintf("pen %+v vs %+v", a.Pen, b.Pen)
	case a.Link != b.Link:
		return fmt.Sprintf("link %+v vs %+v", a.Link, b.Link)
	case sa != sb:
		return fmt.Sprintf("state %+v vs %+v", sa, sb)
	}
	return ""
}

// sameModes compares two emulators' modes by whether each is set: a mode one
// side never heard of is as unset as one the other reset.
func sameModes(a, b ansi.Modes) string {
	modes := slices.Collect(maps.Keys(a))
	for m := range b {
		if _, ok := a[m]; !ok {
			modes = append(modes, m)
		}
	}
	for _, m := range modes {
		if a[m].IsSet() != b[m].IsSet() {
			return fmt.Sprintf("mode %v: %v vs %v", m, a[m], b[m])
		}
	}
	return ""
}

// sameState keeps SGR 31 and 38;5;1 apart, which ultraviolet compares equal,
// so a render that loses a colour's type is caught. CMYK and transparent
// colours, which the render can only write as RGB (spec A30), compare as
// that RGB.
func TestSameStateTellsColourTypesApart(t *testing.T) {
	differ := func(sa, sb string) string {
		a, b := vt.NewEmulator(10, 2), vt.NewEmulator(10, 2)
		_, _ = a.WriteString(sa)
		_, _ = b.WriteString(sb)
		return sameState(a, b, nil, nil)
	}
	require.Contains(t, differ("\x1b[31mx", "\x1b[38;5;1mx"), "cell 0,0")
	require.Contains(t, differ("\x1b[31m", "\x1b[38;5;1m"), "pen")
	require.Contains(t, differ("\x1b[41m\x1b7", "\x1b[48;5;1m\x1b7"), "saved slot")

	r, g, b, _ := color.CMYK{C: 10, M: 20, Y: 30}.RGBA()
	rgb := fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r>>8, g>>8, b>>8)
	require.Empty(t, differ("\x1b[38:3::10:20:30mx", rgb+"x"))
	require.Empty(t, differ("\x1b[38;1mx", "\x1b[38;2;0;0;0mx"))
}
