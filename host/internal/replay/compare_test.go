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

// scrollOff collects the lines that scroll off an emulator's main screen, as
// the replay's history collects them: each through encodeLine, with the
// columns it takes, up to its trailing blanks, and its text. A clear of
// history, by ED 3 or RIS, empties it, and is counted.
//
// canon is each line encoded from its cells' canonical styles, as the render
// can write them. A joiner that draws a line from the render and scrolls it
// off again holds those, and encodes them by another path where a colour
// changes type only (an opaque black next to a palette one, where the line
// it was drawn from had a transparent black), so lines it drew compare by
// canon.
type scrollOff struct {
	lines  [][]byte
	canon  [][]byte
	widths []int
	texts  []string
	clears int
}

// collectScrollOff collects what scrolls off term's main screen from now on.
func collectScrollOff(term *vt.Emulator) *scrollOff {
	s := &scrollOff{}
	term.SetScrollOffFunc(func(line uv.Line) {
		enc, err := encodeLine(line, budget)
		if err != nil {
			panic(err)
		}
		drawn := slices.Clone(line)
		for i := range drawn {
			drawn[i].Style = canonical(drawn[i].Style)
		}
		canon, err := encodeLine(drawn, budget)
		if err != nil {
			panic(err)
		}
		end := len(line)
		for end > 0 && line[end-1] == uv.EmptyCell {
			end--
		}
		s.lines = append(s.lines, enc)
		s.canon = append(s.canon, canon)
		s.widths = append(s.widths, end)
		s.texts = append(s.texts, line.String())
	})
	term.SetScrollbackClearFunc(func() {
		s.lines, s.canon, s.widths, s.texts = nil, nil, nil, nil
		s.clears++
	})
	return s
}

// sameState reports the first difference between two emulators, or "" when
// there is none: their sizes, the screen showing, the cells and styles on
// both screens (the hidden one included), the active screen's current
// cursor (position, pen, link, pending wrap, style; the other screen's is
// never seen again), both screens' saved slots, compared by what DECRC would
// restore, the modes but those the render ignores, the charsets and a
// pending single shift, the one scroll region, the tab stops, REP's last
// character, a carried cluster, the title, and the history lines each side
// collected. The title is what each one's Title callback last reported, as
// the emulator keeps it behind no accessor: "" for one never set.
//
// A slot keeps the position it was saved at through a resize, even off the
// screen, and DECRC clamps it as it moves there. A terminal fresh at this
// size, given the slot's position, clamps it already, and DECRC restores the
// same cell from both, so a slot's position is compared clamped to the
// screen.
func sameState(a, b *vt.Emulator, aHist, bHist [][]byte, aTitle, bTitle string) string {
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
		if d := sameSlot(clampSlot(s.sa), clampSlot(s.sb)); d != "" {
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
	if d := sameCursorStyle(a, b); d != "" {
		return d
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
	if aTitle != bTitle {
		return fmt.Sprintf("title: %q vs %q", aTitle, bTitle)
	}
	if !slices.EqualFunc(aHist, bHist, bytes.Equal) {
		return fmt.Sprintf("history: %q vs %q", aHist, bHist)
	}
	return ""
}

// sameCursorStyle compares the cursor's style, and whether it blinks.
func sameCursorStyle(a, b *vt.Emulator) string {
	sa, blinkA := a.CursorStyle()
	sb, blinkB := b.CursorStyle()
	if sa != sb || blinkA != blinkB {
		return fmt.Sprintf("cursor style: %v blinking %v vs %v blinking %v", sa, blinkA, sb, blinkB)
	}
	return ""
}

// watchTitle has term report each title it is set to into title, and
// returns title.
func watchTitle(term *vt.Emulator) *string {
	title := new(string)
	term.SetCallbacks(vt.Callbacks{Title: func(s string) { *title = s }})
	return title
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
// render can get back: CMYK and transparent, and the alpha of an RGBA.
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

// clampSlot is scr's saved slot with its position where DECRC would move the
// cursor: inside the screen. A slot holding origin mode is clamped to the
// margins instead, but no render restores one.
func clampSlot(scr *vt.Screen) vt.Cursor {
	c := scr.SavedCursor()
	c.X, c.Y = min(c.X, scr.Width()-1), min(c.Y, scr.Height()-1)
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
// side never heard of is as unset as one the other reset. The modes the
// render ignores are left out, as it leaves them as the joiner's terminal
// has them.
func sameModes(a, b ansi.Modes) string {
	modes := slices.Collect(maps.Keys(a))
	for m := range b {
		if _, ok := a[m]; !ok {
			modes = append(modes, m)
		}
	}
	for _, m := range modes {
		if dec, ok := m.(ansi.DECMode); ok && ignoredModes[dec] {
			continue
		}
		if a[m].IsSet() != b[m].IsSet() {
			return fmt.Sprintf("mode %v: %v vs %v", m, a[m], b[m])
		}
	}
	return ""
}

// sameState keeps SGR 31 and 38;5;1 apart, which ultraviolet compares equal,
// so a render that loses a colour's type is caught. CMYK and transparent
// colours, which the render can only write as RGB, compare as that RGB.
func TestSameStateTellsColourTypesApart(t *testing.T) {
	differ := func(sa, sb string) string {
		a, b := vt.NewEmulator(10, 2), vt.NewEmulator(10, 2)
		_, _ = a.WriteString(sa)
		_, _ = b.WriteString(sb)
		return sameState(a, b, nil, nil, "", "")
	}
	require.Contains(t, differ("\x1b[31mx", "\x1b[38;5;1mx"), "cell 0,0")
	require.Contains(t, differ("\x1b[31m", "\x1b[38;5;1m"), "pen")
	require.Contains(t, differ("\x1b[41m\x1b7", "\x1b[48;5;1m\x1b7"), "saved slot")

	r, g, b, _ := color.CMYK{C: 10, M: 20, Y: 30}.RGBA()
	rgb := fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r>>8, g>>8, b>>8)
	require.Empty(t, differ("\x1b[38:3::10:20:30mx", rgb+"x"))
	require.Empty(t, differ("\x1b[38;1mx", "\x1b[38;2;0;0;0mx"))
}
