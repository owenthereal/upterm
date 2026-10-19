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
// character, a carried cluster, the window title and the icon name, and the
// history lines each side collected. The names are what each one's Title and
// IconName callbacks last reported, as the emulator keeps them behind no
// accessor, with each pop of the title stack (see watchTitleFrom): "" for one
// never set.
//
// A slot keeps the position it was saved at through a resize, even off the
// screen, and DECRC clamps it as it moves there. A terminal fresh at this
// size, given the slot's position, clamps it already, and DECRC restores the
// same cell from both, so a slot's position is compared clamped to the
// screen.
func sameState(a, b *vt.Emulator, aHist, bHist [][]byte, aNames, bNames names) string {
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
	if ra, rb := a.ActiveScreen().ScrollRegion(), b.ActiveScreen().ScrollRegion(); ra != rb {
		return fmt.Sprintf("scroll region: %v vs %v", ra, rb)
	}
	if ta, tb := a.TabStops(), b.TabStops(); !slices.Equal(ta, tb) {
		return fmt.Sprintf("tab stops: %v vs %v", ta, tb)
	}
	return sameRest(a, b, aHist, bHist, aNames, bNames)
}

// sameStateInside is sameState for b, the terminal of a joiner larger than
// a, the session's, given the render: the render sits at b's top left, and
// the bytes after it were laid out for a's size, as they are for a live
// client larger than the pty, so the two are compared at the handoff, where
// the render is all b holds. a's cells, on both screens, are compared in b's
// top left, and the rest of b is blank. Where the sizes part, b holds what
// the render leaves it:
//   - a wrap pending at the cursor only on a joiner as wide, since a wider
//     live client has none;
//   - each slot at the position it was saved at, which a's own size clamps
//     there and b's here, but a slot's pending wrap only on a joiner as wide,
//     set by a print in the last column of the row a's DECRC would restore;
//   - b's own whole screen as the region where a's is its whole screen, and
//     a's rows otherwise;
//   - a stop every 8 columns of b's width where a's are a's default, and a's
//     stops alone otherwise.
func sameStateInside(a, b *vt.Emulator, aHist, bHist [][]byte, aNames, bNames names) string {
	w, h := a.Width(), a.Height()
	if b.Width() < w || b.Height() < h {
		return fmt.Sprintf("size: %dx%d isn't inside %dx%d", w, h, b.Width(), b.Height())
	}
	fits := b.Width() == w
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
		if d := sameScreenInside(s.sa, s.sb); d != "" {
			return s.name + " screen: " + d
		}
		c := s.sa.SavedCursor()
		c.Saved.Wrap = c.Saved.Wrap && fits
		if c.Saved.Wrap {
			c.Y = min(c.Y, h-1)
		}
		c.X, c.Y = min(c.X, b.Width()-1), min(c.Y, b.Height()-1)
		if d := sameSlot(c, s.sb.SavedCursor()); d != "" {
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
	if want := a.PendingWrap() && fits; b.PendingWrap() != want {
		return fmt.Sprintf("pending wrap: %v, where %v is wanted", b.PendingWrap(), want)
	}
	ra, rb := a.ActiveScreen().ScrollRegion(), b.ActiveScreen().ScrollRegion()
	want := uv.Rect(0, ra.Min.Y, b.Width(), ra.Dy())
	if ra == uv.Rect(0, 0, w, h) {
		want = uv.Rect(0, 0, b.Width(), b.Height())
	}
	if rb != want {
		return fmt.Sprintf("scroll region: %v, where %v is wanted for %v", rb, want, ra)
	}
	stops := a.TabStops()
	if slices.Equal(stops, defaultTabStops(w)) {
		stops = defaultTabStops(b.Width())
	}
	if tb := b.TabStops(); !slices.Equal(stops, tb) {
		return fmt.Sprintf("tab stops: %v, where %v is wanted", tb, stops)
	}
	return sameRest(a, b, aHist, bHist, aNames, bNames)
}

// sameRest is what sameState and sameStateInside compare alike, with no
// regard to the screen's size: the cursor's style, the modes, the charsets
// and a pending single shift, REP's last character, a carried cluster, the
// window title and the icon name, and the history.
func sameRest(a, b *vt.Emulator, aHist, bHist [][]byte, aNames, bNames names) string {
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
	if a.LastChar() != b.LastChar() {
		return fmt.Sprintf("REP's last character: %q vs %q", a.LastChar(), b.LastChar())
	}
	if a.Carrying() != b.Carrying() {
		return fmt.Sprintf("carrying a cluster: %v vs %v", a.Carrying(), b.Carrying())
	}
	if aNames != bNames {
		return fmt.Sprintf("title and icon name: %q vs %q", aNames, bNames)
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

// names are the window title and the icon name a terminal shows.
type names struct{ title, icon string }

// watchTitle has term report the window title and the icon name it shows,
// where it returns them: "" for each until the stream sets it, as for a
// terminal whose own names are "" (see watchTitleFrom).
func watchTitle(term *vt.Emulator) *names { return watchTitleFrom(term, names{}) }

// watchTitleFrom has term, a terminal whose own window title and icon name are
// own, report the names it shows, where it returns them: each one it is set
// to, the window title by OSC 0 or OSC 2 and the icon name by OSC 0 or OSC 1,
// and each one a pop of its title stack puts back, the stack kept as xterm
// keeps it (see xtermTitles). x/vt keeps no title stack, so without it
// a pop would leave each name as the last OSC set it.
func watchTitleFrom(term *vt.Emulator, own names) *names {
	x := &xtermTitles{shown: own}
	term.SetCallbacks(vt.Callbacks{
		Title:    func(s string) { x.shown.title = s },
		IconName: func(s string) { x.shown.icon = s },
	})
	term.RegisterCsiHandler('t', func(params ansi.Params) bool {
		op, _, _ := params.Param(0, 0)
		ps, _, _ := params.Param(1, 0)
		which, _, _ := params.Param(2, 0)
		switch op {
		case 22:
			x.push(ps, which)
		case 23:
			x.pop(ps, which)
		}
		return false
	})
	return &x.shown
}

// xtermTitles is xterm's title stack, as its xtermPushTitle and
// xtermPopTitle (misc.c) keep it, and the names it shows: ten slots, a count
// of pushes that wraps round them, a pop that takes each name its entry lacks
// from the nearest of the nine slots below that has one, and that empties the
// slot it pops; a third parameter from 1 stores into, or reads, a slot in
// place. A push saves the names the window has, whether a program set them
// or they are the terminal's own: Ps 0 both, 1 the icon name, 2 the window
// title, any other neither. A pop puts back those its Ps names, so a pop of
// both after a push of both puts back a name the stream never set as the
// terminal's own. A name not saved, or a slot emptied, is nil, and putting
// back nil changes nothing, as xterm's ChangeGroup ignores it.
type xtermTitles struct {
	shown names
	used  int
	data  [10]savedNames
}

// savedNames is a slot of xterm's title stack: the names it saved, each nil
// where it saved none.
type savedNames struct{ icon, window *string }

func (x *xtermTitles) push(ps, which int) {
	var item savedNames
	icon, title := x.shown.icon, x.shown.title
	switch ps {
	case 0:
		item = savedNames{icon: &icon, window: &title}
	case 1:
		item.icon = &icon
	case 2:
		item.window = &title
	}
	if which--; which < 0 {
		which = x.used
		x.used++
	}
	x.data[which%10] = item
}

func (x *xtermTitles) pop(ps, which int) {
	popped := false
	switch {
	case which > 0:
		which = (which - 1) % 10
	case x.used > 0:
		x.used--
		which = x.used % 10
		popped = true
	default:
		return
	}
	item := x.data[which]
	for n := 1; n < 10; n++ {
		below := x.data[(which-n+10)%10]
		if item.icon == nil {
			item.icon = below.icon
		}
		if item.window == nil {
			item.window = below.window
		}
	}
	if popped {
		x.data[which] = savedNames{}
	}
	if (ps == 0 || ps == 1) && item.icon != nil {
		x.shown.icon = *item.icon
	}
	if (ps == 0 || ps == 2) && item.window != nil {
		x.shown.title = *item.window
	}
}

// The title stack's model follows xterm: a pop of an entry that saved only
// one name puts back the other's from the nearest one below it that saved
// it, as vim's exit relies on for the title, and the icon name the same way;
// a pop of both puts back both an entry of both saved, the terminal's own
// for one the stream never set; past ten pushes the oldest is overwritten,
// and a pop that comes down to it finds nothing; a pop of an empty stack does
// nothing. A terminal watched shows the names its OSCs set, and those its
// pops put back.
func TestXtermTitlesFollowsXterm(t *testing.T) {
	own := names{"own", "own icon"}
	term := vt.NewEmulator(10, 2)
	shown := watchTitleFrom(term, own)
	_, _ = term.WriteString("\x1b]1;icon\x07\x1b[22;1t\x1b]0;both\x07")
	require.Equal(t, names{"both", "both"}, *shown)
	_, _ = term.WriteString("\x1b]2;title\x07\x1b[23;1t")
	require.Equal(t, names{"title", "icon"}, *shown)

	x := &xtermTitles{shown: own}
	x.push(2, 0)
	x.shown = names{"vim", "vim icon"}
	x.push(1, 0)
	x.pop(2, 0)
	require.Equal(t, names{"own", "vim icon"}, x.shown, "the title from the entry below")
	x.pop(1, 0)
	require.Equal(t, names{"own", "vim icon"}, x.shown, "no icon name below")

	x = &xtermTitles{shown: own}
	x.shown.icon = "one"
	x.push(1, 0)
	x.shown.icon = "two"
	x.push(2, 0)
	x.shown = names{"now", "now"}
	x.pop(1, 0)
	require.Equal(t, names{"now", "one"}, x.shown, "the icon name from the entry below")

	x = &xtermTitles{shown: own}
	x.shown.title = "set"
	x.push(0, 0)
	x.shown = names{"later", "later"}
	x.pop(0, 0)
	require.Equal(t, names{"set", "own icon"}, x.shown, "the terminal's own icon name, which the push saved")

	x = &xtermTitles{shown: own}
	for i := range 11 {
		x.shown = names{fmt.Sprint(i), fmt.Sprint("icon ", i)}
		x.push(0, 0)
	}
	x.shown = names{"now", "now"}
	for i := 10; i >= 1; i-- {
		x.pop(0, 0)
		require.Equal(t, names{fmt.Sprint(i), fmt.Sprint("icon ", i)}, x.shown)
	}
	x.pop(0, 0)
	require.Equal(t, names{"1", "icon 1"}, x.shown, "the overwritten entry")
	x.pop(0, 0)
	require.Equal(t, names{"1", "icon 1"}, x.shown, "the empty stack")
	require.Zero(t, x.used)
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

// sameScreenInside compares a's cells with those at b's top left, as
// sameScreen does, and requires the rest of b, a screen at least as large,
// to be blank.
func sameScreenInside(a, b *vt.Screen) string {
	for y := range b.Height() {
		lb := b.Line(y)
		for x := range lb {
			if x < a.Width() && y < a.Height() {
				ca, cb := *a.CellAt(x, y), lb[x]
				ca.Style, cb.Style = canonical(ca.Style), canonical(cb.Style)
				if ca != cb {
					return fmt.Sprintf("cell %d,%d: %+v vs %+v", x, y, *a.CellAt(x, y), lb[x])
				}
			} else if lb[x] != uv.EmptyCell {
				return fmt.Sprintf("cell %d,%d, outside %dx%d: %+v", x, y, a.Width(), a.Height(), lb[x])
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
// has them, but for synchronized output, which a render begins again when
// the stream is inside an update at the handoff point.
func sameModes(a, b ansi.Modes) string {
	modes := slices.Collect(maps.Keys(a))
	for m := range b {
		if _, ok := a[m]; !ok {
			modes = append(modes, m)
		}
	}
	for _, m := range modes {
		if dec, ok := m.(ansi.DECMode); ok && ignoredModes[dec] && dec != ansi.ModeSynchronizedOutput {
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
		return sameState(a, b, nil, nil, names{}, names{})
	}
	require.Contains(t, differ("\x1b[31mx", "\x1b[38;5;1mx"), "cell 0,0")
	require.Contains(t, differ("\x1b[31m", "\x1b[38;5;1m"), "pen")
	require.Contains(t, differ("\x1b[41m\x1b7", "\x1b[48;5;1m\x1b7"), "saved slot")

	r, g, b, _ := color.CMYK{C: 10, M: 20, Y: 30}.RGBA()
	rgb := fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r>>8, g>>8, b>>8)
	require.Empty(t, differ("\x1b[38:3::10:20:30mx", rgb+"x"))
	require.Empty(t, differ("\x1b[38;1mx", "\x1b[38;2;0;0;0mx"))
}
