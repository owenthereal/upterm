package replay

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"image/color"
	"maps"
	"math/rand/v2"
	"regexp"
	"slices"
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

// The property's cases are drawn from a seed, so a failing case can be run
// again, and more of them can be run than a test run has time for; and a
// failing case is shrunk for a while before it is reported.
var (
	propertySeed   = flag.Uint64("replay.seed", 1, "the seed the continuation properties draw their cases from")
	propertyCases  = flag.Int("replay.cases", 2000, "how many cases TestReplayContinuesEquivalently runs")
	propertyShrink = flag.Duration("replay.shrink", time.Minute, "how long a failing case of a continuation property is shrunk for")
)

// streamGen writes terminal output from rnd, a token at a time: the bytes,
// the committed size events among them, and the offsets right after
// printable text or inside a grapheme cluster, where a cut leaves text in the
// deferred tail for the next bytes to extend.
type streamGen struct {
	rnd   *rand.Rand
	out   []byte
	sizes []uio.SizeEvent
	cuts  []int
	// wraps are offsets right after an action that leaves a wrap pending,
	// which the render rebuilds by a reprint.
	wraps []int
	// size is the terminal's, which a resize changes; the zero size while
	// writing a suffix, which has no resizes.
	size termsize.Size
	// alt is the mode the program on the alternate screen entered it by, so
	// that it leaves by the same one, or 0 while the main screen shows. A
	// screen switch left set by another mode is state no render restores.
	alt   int
	links int
}

// token is one kind of output, drawn by weight.
type token struct {
	weight int
	emit   func(*streamGen)
}

// streamTokens is genStream's vocabulary. State a render can't restore
// (origin mode, LNM, DECSLRM, GR other than G2, a mode nothing knows) is in
// it, but rarely, and mostly undone soon after, so that most cases are
// reconstructions and not fallbacks.
var streamTokens = []token{
	{14, (*streamGen).text},
	{14, (*streamGen).line},
	{4, (*streamGen).shell},
	{8, (*streamGen).sgr},
	{3, (*streamGen).truecolor},
	{4, (*streamGen).link},
	{10, (*streamGen).move},
	{5, (*streamGen).erase},
	{5, (*streamGen).mode},
	{3, (*streamGen).altProgram},
	{4, (*streamGen).saveRestore},
	{4, (*streamGen).charset},
	{3, (*streamGen).region},
	{3, (*streamGen).tabs},
	{3, (*streamGen).rep},
	{2, (*streamGen).c0InCSI},
	{4, (*streamGen).wide},
	{4, (*streamGen).cluster},
	{2, (*streamGen).splitCluster},
	{4, (*streamGen).wrap},
	{2, (*streamGen).ink},
	{1, (*streamGen).title},
	{1, (*streamGen).cursorStyle},
	{2, (*streamGen).kitty},
	{2, (*streamGen).misc},
	{2, (*streamGen).resize},
	{1, (*streamGen).resizeInside},
}

// suffixTokens is genSuffix's: the same vocabulary without resizes, weighted
// towards what reads the state the render left: REP, DECRC and SCORC, a
// return to the alternate screen, text in whatever pen and link are set,
// relative moves, tabs, text under each charset, and a mark that would
// extend a cluster.
var suffixTokens = []token{
	{10, (*streamGen).rep},
	{8, (*streamGen).restore},
	{6, (*streamGen).reenter},
	{14, (*streamGen).text},
	{8, (*streamGen).upDown},
	{6, (*streamGen).tab},
	{6, (*streamGen).shifted},
	{4, (*streamGen).mark},
	{6, (*streamGen).line},
	{4, (*streamGen).move},
	{3, (*streamGen).erase},
	{3, (*streamGen).sgr},
	{2, (*streamGen).link},
	{3, (*streamGen).wide},
	{3, (*streamGen).cluster},
	{3, (*streamGen).wrap},
	{2, (*streamGen).mode},
	{2, (*streamGen).saveRestore},
	{2, (*streamGen).altProgram},
	{1, (*streamGen).cursorStyle},
	{1, (*streamGen).misc},
}

// genStream returns a stream and its committed size events, from rnd:
// shell output, ink-style live regions, alternate-screen programs entering
// and leaving by 47, 1047 and 1049 (leaving content behind), DECSC, SCOSC,
// DECRC and SCORC on both screens with styled pens and open links, SCS with
// SI, SO, LS2 and LS3, DECSTBM, IRM, tab stops, REP, C0 controls inside
// CSIs, wide characters, combining marks, ZWJ emoji, truecolor SGR, OSC 8
// links, several events at one offset.
func genStream(rnd *rand.Rand) (stream []byte, sizes []uio.SizeEvent) {
	g := newStream(rnd)
	return g.out, g.sizes
}

// newStream writes a stream of between 256 bytes and about 8 KiB from rnd,
// starting with the size event every capture starts with.
func newStream(rnd *rand.Rand) *streamGen {
	g := &streamGen{rnd: rnd}
	g.size = g.randomSize()
	g.event(g.size)
	for n := 256 + rnd.IntN(8<<10); len(g.out) < n; {
		g.pick(streamTokens)
	}
	return g
}

// genSuffix is genStream's vocabulary without size events, weighted towards
// what reads continuation state: REP, ESC 8 and CSI u, ?47h/?1047h/?1049h
// re-entry, SGR-less text, CUU/CUD, HT, text under each charset.
func genSuffix(rnd *rand.Rand) []byte {
	g := &streamGen{rnd: rnd}
	for n := 16 + rnd.IntN(1<<10); len(g.out) < n; {
		g.pick(suffixTokens)
	}
	return g.out
}

func (g *streamGen) pick(tokens []token) {
	total := 0
	for _, t := range tokens {
		total += t.weight
	}
	n := g.rnd.IntN(total)
	for _, t := range tokens {
		if n < t.weight {
			t.emit(g)
			return
		}
		n -= t.weight
	}
}

func (g *streamGen) put(s ...string) {
	for _, p := range s {
		g.out = append(g.out, p...)
	}
}

func (g *streamGen) putf(format string, args ...any) {
	g.out = fmt.Appendf(g.out, format, args...)
}

// cut records the end of the output so far as a place to cut it.
func (g *streamGen) cut() { g.cuts = append(g.cuts, len(g.out)) }

// between is from lo to hi, or lo when hi is less, as on a screen too small
// for the range.
func (g *streamGen) between(lo, hi int) int { return lo + g.rnd.IntN(max(hi-lo, 0)+1) }

func (g *streamGen) one(s ...string) string { return s[g.rnd.IntN(len(s))] }

func (g *streamGen) chance(p float64) bool { return g.rnd.Float64() < p }

// cols and rows are the terminal's, or a typical one's in a suffix, whose
// size the generator doesn't know.
func (g *streamGen) cols() int {
	if g.size.Cols == 0 {
		return 80
	}
	return g.size.Cols
}

func (g *streamGen) rows() int {
	if g.size.Rows == 0 {
		return 24
	}
	return g.size.Rows
}

func (g *streamGen) randomSize() termsize.Size {
	return termsize.Size{Cols: g.between(4, 100), Rows: g.between(2, 40)}
}

// event commits a resize to size at the end of the output so far.
func (g *streamGen) event(size termsize.Size) {
	g.sizes = append(g.sizes, uio.SizeEvent{Seq: uint64(len(g.sizes) + 1), Offset: uint64(len(g.out)), Size: size})
}

const wordChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:=+,()[]{}<>!?#%&*'\"@$~^|;`"

func (g *streamGen) word() string {
	b := make([]byte, g.between(1, 10))
	for i := range b {
		b[i] = wordChars[g.rnd.IntN(len(wordChars))]
	}
	return string(b)
}

// text prints a few words, in whatever pen and link are set.
func (g *streamGen) text() {
	for i := range g.between(1, 4) {
		if i > 0 {
			g.put(" ")
		}
		g.put(g.word())
	}
	g.cut()
}

func (g *streamGen) line() {
	g.text()
	g.put("\r\n")
}

// shell is a command at a prompt, and its output.
func (g *streamGen) shell() {
	g.put("$ ", g.word(), " ", g.word(), "\r\n")
	for range g.between(0, 6) {
		if g.chance(0.2) {
			g.put("\x1b[1;34m", g.word(), "\x1b[0m  ")
		}
		g.line()
	}
	g.put("$ ")
	g.cut()
}

func (g *streamGen) sgr() { g.put(randomSGR(g.rnd)) }

// truecolor is runs of text in RGB colours, as Claude Code writes them.
func (g *streamGen) truecolor() {
	for range g.between(1, 3) {
		g.putf("\x1b[38;2;%d;%d;%dm", g.rnd.IntN(256), g.rnd.IntN(256), g.rnd.IntN(256))
		if g.chance(0.3) {
			g.putf("\x1b[48;2;%d;%d;%dm", g.rnd.IntN(256), g.rnd.IntN(256), g.rnd.IntN(256))
		}
		g.text()
	}
	if g.chance(0.6) {
		g.put("\x1b[m")
	}
}

// link opens or closes an OSC 8 link, or changes it between two cells whose
// clusters would join, printed back to back.
func (g *streamGen) link() {
	g.links++
	switch g.rnd.IntN(5) {
	case 0, 1:
		g.put("\x1b]8;;\x07")
	case 2:
		g.putf("\x1b]8;id=%d;https://l.example/%d\x07", g.links, g.links)
	case 3:
		g.putf("\x1b]8;;https://l.example/%d\x1b\\", g.links)
	default:
		pair := []rune(g.one("\U0001F1FA\U0001F1F8", "\U0001F44D\U0001F3FD"))
		g.putf("\x1b]8;;https://a.example/%d\x07%c\x1b]8;;https://b.example/%d\x07%c", g.links, pair[0], g.links, pair[1])
		g.cut()
	}
}

// move moves the cursor, by every means a program has, sometimes past the
// screen's edges.
func (g *streamGen) move() {
	n := g.between(1, 3*g.rows())
	switch g.rnd.IntN(16) {
	case 0:
		g.putf("\x1b[%d;%dH", g.between(1, g.rows()+2), g.between(1, g.cols()+2))
	case 1:
		g.put("\x1b[H")
	case 2:
		g.putf("\x1b[%dA", n)
	case 3:
		g.putf("\x1b[%dB", n)
	case 4:
		g.putf("\x1b[%dC", g.between(1, g.cols()))
	case 5:
		g.putf("\x1b[%dD", g.between(1, g.cols()))
	case 6:
		g.putf("\x1b[%dG", g.between(1, g.cols()+2))
	case 7:
		g.putf("\x1b[%dd", g.between(1, g.rows()+2))
	case 8:
		g.putf("\x1b[%dE", n)
	case 9:
		g.putf("\x1b[%dF", n)
	case 10:
		g.put("\r")
	case 11:
		g.put("\n")
	case 12:
		g.put("\b")
	case 13:
		g.put("\x1bM")
	case 14:
		// NEL as what it does, an IND then a CR: x/vt has no NEL, so on the
		// terminals compared here an ESC E would move nothing.
		g.put(g.one("\x1bD", "\x1bD\r"))
	default:
		g.putf(g.one("\x1b[%d`", "\x1b[%da", "\x1b[%de"), g.between(1, g.cols()))
	}
}

// erase erases, inserts and deletes, and scrolls.
func (g *streamGen) erase() {
	n := g.between(1, g.cols())
	switch g.rnd.IntN(10) {
	case 0:
		g.put(g.one("\x1b[J", "\x1b[0J"))
	case 1:
		g.put("\x1b[1J")
	case 2:
		g.put("\x1b[2J")
	case 3:
		g.put("\x1b[3J")
	case 4:
		g.put(g.one("\x1b[K", "\x1b[1K", "\x1b[2K"))
	case 5:
		g.putf("\x1b[%dX", n)
	case 6:
		g.putf("\x1b[%dP", n)
	case 7:
		g.putf("\x1b[%d@", n)
	case 8:
		g.putf(g.one("\x1b[%dL", "\x1b[%dM"), g.between(1, g.rows()))
	default:
		g.putf(g.one("\x1b[%dS", "\x1b[%dT"), g.between(1, g.rows()))
	}
}

// The DEC private modes the tracker tracks, apart from the screen switches;
// those the render restores itself, which make the terminal send reports
// unasked; and those the render leaves as the joiner's terminal has them.
var (
	trackedModes = []int{1, 7, 25, 1000, 1002, 1003, 1004, 1005, 1006, 2004}
	reportNums   = []int{2031}
	ignoredNums  = []int{12, 2026, 35, 67, 1007, 1010, 1014, 1015, 1034, 1035, 1036, 1037, 1039, 1040, 1050, 1051, 1052, 1053, 1060, 1061, 2048, 9001}
)

// mode sets or resets a mode: mostly the ones the render restores or
// ignores, and now and then one it doesn't, mostly put back soon after.
func (g *streamGen) mode() {
	hl := g.one("h", "l")
	switch r := g.rnd.IntN(100); {
	case r < 45:
		g.putf("\x1b[?%d%s", trackedModes[g.rnd.IntN(len(trackedModes))], hl)
	case r < 50:
		g.putf("\x1b[?%d;%d%s", trackedModes[g.rnd.IntN(len(trackedModes))], trackedModes[g.rnd.IntN(len(trackedModes))], hl)
	case r < 60:
		g.put("\x1b[4" + hl)
	case r < 67:
		g.put("\x1b[?5" + hl)
	case r < 75:
		g.put(g.one("\x1b=", "\x1b>", "\x1b[?66h", "\x1b[?66l"))
	case r < 80:
		g.putf("\x1b[?%d%s", reportNums[g.rnd.IntN(len(reportNums))], hl)
	case r < 92:
		g.putf("\x1b[?%d%s", ignoredNums[g.rnd.IntN(len(ignoredNums))], hl)
	default:
		set, reset := g.unrestorable()
		g.put(set)
		if g.chance(0.8) {
			g.text()
			g.put(reset)
		}
	}
}

// unrestorable is a state no render restores, and what undoes it.
func (g *streamGen) unrestorable() (set, reset string) {
	switch g.rnd.IntN(6) {
	case 0:
		return "\x1b[?6h", "\x1b[?6l"
	case 1:
		return "\x1b[20h", "\x1b[20l"
	case 2:
		return "\x1b[?1001h", "\x1b[?1001l"
	case 3:
		return "\x1b[?69h\x1b[2;10s", "\x1b[?69l"
	case 4:
		return "\x1b[?45h", "\x1b[?45l"
	default:
		return g.one("\x1b~", "\x1b|"), "\x1b}"
	}
}

// altProgram is a full-screen program on the alternate screen: it enters by
// 47, 1047 or 1049, draws, and leaves, by the mode it entered by, what it
// drew behind, or leaves later.
func (g *streamGen) altProgram() {
	if g.alt != 0 {
		g.putf("\x1b[?%dl", g.alt)
		g.alt = 0
		return
	}
	g.alt = []int{47, 1047, 1049}[g.rnd.IntN(3)]
	g.putf("\x1b[?%dh", g.alt)
	if g.alt != 1049 && g.chance(0.5) {
		g.put("\x1b[2J")
	}
	for range g.between(1, 5) {
		g.putf("\x1b[%d;%dH", g.between(1, g.rows()), g.between(1, g.cols()))
		if g.chance(0.4) {
			g.sgr()
		}
		g.text()
	}
	if g.chance(0.3) {
		g.saveRestore()
	}
	if g.chance(0.5) {
		g.putf("\x1b[?%dl", g.alt)
		g.alt = 0
	}
}

// reenter goes back to the alternate screen by any of the modes, which shows
// what was left there, or saves the cursor on the way in.
func (g *streamGen) reenter() {
	v := g.one("47", "1047", "1049")
	g.put("\x1b[?" + v + "h")
	g.text()
	if g.chance(0.5) {
		g.put("\x1b[?" + v + "l")
	}
}

// saveRestore saves the cursor, with a styled pen, an open link or another
// charset, or restores it. DECSC and SCOSC save to the one slot of the
// screen showing, which DECRC and SCORC both restore, so either save is
// restored by either restore. While DECLRMM is set, as unrestorable can
// leave it, a CSI s sets the margins instead.
func (g *streamGen) saveRestore() {
	switch g.rnd.IntN(5) {
	case 0, 1:
		if g.chance(0.8) {
			g.putf("\x1b[%d;%dH", g.between(1, g.rows()), g.between(1, g.cols()))
		}
		if g.chance(0.6) {
			g.sgr()
		}
		if g.chance(0.3) {
			g.links++
			g.putf("\x1b]8;;https://s.example/%d\x07", g.links)
		}
		if g.chance(0.3) {
			g.put(g.one("\x1b(0", "\x1b)0\x0e", "\x1b*A\x1bn"))
		}
		g.put(g.one("\x1b7", "\x1b[s"))
		if g.chance(0.6) {
			g.put("\x1b[m\x1b]8;;\x07\x1b(B\x1b)B\x1b*B\x0f")
		}
	case 2, 3:
		g.restore()
	default:
		g.put(g.one("\x1b[?1048h", "\x1b[?1048l"))
	}
}

// restore restores the cursor by DECRC or SCORC.
func (g *streamGen) restore() { g.put(g.one("\x1b8", "\x1b[u")) }

// charset designates and invokes character sets, with G2 kept in GR, or
// prints through a single shift.
func (g *streamGen) charset() {
	switch g.rnd.IntN(10) {
	case 0, 1, 2:
		g.put("\x1b", g.one("(", ")", "*", "+"), g.one("0", "A", "B"))
	case 3, 4:
		g.put(g.one("\x0f", "\x0e", "\x1bn", "\x1bo"))
	case 5:
		g.put("\x1b}")
	case 6:
		g.put(g.one("\x1bN", "\x1bO"), g.one("q", "x", "a", "#"))
	default:
		g.lineDrawing()
	}
}

// shifted is text under each charset GL can invoke.
func (g *streamGen) shifted() {
	g.put(g.one("\x0f", "\x0e", "\x1bn", "\x1bo"))
	g.lineDrawing()
}

func (g *streamGen) lineDrawing() {
	const box = "jklmnqtuvwx`afg~_#"
	for range g.between(1, 8) {
		g.out = append(g.out, box[g.rnd.IntN(len(box))])
	}
	g.cut()
}

// region sets the scroll region, sometimes one a terminal ignores, which
// leaves the one before it.
func (g *streamGen) region() {
	switch g.rnd.IntN(6) {
	case 0:
		g.put("\x1b[r")
	case 1:
		g.putf("\x1b[%d;%dr", g.between(0, g.rows()), g.between(0, g.rows()+2))
	case 2:
		g.putf("\x1b[%dr", g.between(1, g.rows()+2))
	case 3:
		g.putf("\x1b[;%dr", g.between(1, g.rows()+2))
	case 4:
		// Its bottom is past the screen, so it is the screen's last row, which
		// is above its top.
		top := g.between(g.rows(), g.rows()+3)
		g.putf("\x1b[%d;%dr\x1b[%d;%dr", g.between(1, 2), g.between(3, g.rows()), top, g.between(top+1, top+3))
	default:
		// apt's progress bar keeps the last row out of the region.
		g.putf("\x1b7\x1b[0;%dr\x1b8\x1b[1A", g.rows()-1)
	}
}

// tabs sets and clears tab stops, and tabs.
func (g *streamGen) tabs() {
	switch g.rnd.IntN(6) {
	case 0, 1:
		g.putf("\x1b[%dG\x1bH", g.between(1, g.cols()))
	case 2:
		g.put("\x1b[g")
	case 3:
		g.put("\x1b[3g")
	case 4:
		g.tab()
	default:
		g.putf(g.one("\x1b[%dI", "\x1b[%dI", "\x1b[%dZ"), g.between(1, 3))
	}
}

func (g *streamGen) tab() {
	g.put(strings.Repeat("\t", g.between(1, 3)))
	g.text()
}

// upDown moves up or down, by CUU or CUD, and prints.
func (g *streamGen) upDown() {
	g.putf(g.one("\x1b[%dA", "\x1b[%dB"), g.between(1, 5))
	g.text()
}

// rep repeats the last character printed, a new one or the one before.
func (g *streamGen) rep() {
	if g.chance(0.6) {
		g.put(g.one("x", "-", "=", "é", "中"))
	}
	g.putf("\x1b[%db", g.between(0, 3*g.cols()))
}

// c0InCSI is a CSI with a C0 control among its parameters, which a terminal
// executes where it stands, going on with the CSI.
func (g *streamGen) c0InCSI() {
	c0 := g.one("\r", "\n", "\b", "\t", "\x0b", "\x07", "\x00", "\x0e", "\x0f")
	switch g.rnd.IntN(5) {
	case 0:
		g.putf("\x1b[%d%s;%dH", g.between(1, g.rows()), c0, g.between(1, g.cols()))
	case 1:
		g.put("\x1b[" + c0 + "2K")
	case 2:
		g.putf("\x1b[%d%sA", g.between(1, 5), c0)
	case 3:
		g.putf("\x1b[%d%s;%dr", g.between(1, 3), c0, g.between(4, g.rows()+1))
	default:
		g.put("\x1b[?"+c0, g.one("25", "2004", "1"), g.one("h", "l"))
	}
}

// wide prints wide characters, sometimes from the last column, which wraps
// them.
func (g *streamGen) wide() {
	if g.chance(0.3) {
		g.put("\x1b[999G")
	}
	for range g.between(1, 4) {
		g.put(g.one("中", "文", "字", "😀", "🎉", "Ａ", "あ"))
	}
	g.cut()
}

// clusterParts are grapheme clusters split where the first part is a whole
// cluster that the second extends.
var clusterParts = [][2]string{
	{"e", "\u0301"},
	{"a\u0308", "\u0301"},
	{"\U0001F468\u200d", "\U0001F469"},
	{"\U0001F468", "\u200d\U0001F469\u200d\U0001F467"},
	{"\u2764", "\ufe0f"},
	{"\U0001F44D", "\U0001F3FD"},
	{"\U0001F1FA", "\U0001F1F8"},
	{"\u0915", "\u093e"},
	{"\u1100", "\u1161"},
}

// cluster prints a cluster whole, with a place to cut it inside.
func (g *streamGen) cluster() {
	p := clusterParts[g.rnd.IntN(len(clusterParts))]
	g.put(p[0])
	g.cut()
	g.put(p[1])
	g.cut()
}

// splitCluster prints the two parts of a cluster into two cells, with an
// action between them that ends the first.
func (g *streamGen) splitCluster() {
	p := [][2]string{
		{"\U0001F1FA", "\U0001F1F8"},
		{"\U0001F44D", "\U0001F3FD"},
		{"e", "\u093e"},
		{"\u1100", "\u1161"},
	}[g.rnd.IntN(4)]
	g.put(p[0], g.one("\x1b[m", "\x1b[1m", "\x00", "\x1b]8;;\x07"), p[1])
	g.cut()
}

// mark is a combining mark, which extends a cluster the bytes before it
// left open, or is dropped.
func (g *streamGen) mark() {
	g.put(g.one("\u0301", "\u200d\U0001F469", "\ufe0f", "\U0001F3FD", "\u093e"))
	g.cut()
}

// wrap prints at the last column, under autowrap on or off, which leaves a
// wrap pending, then sometimes ends the print and keeps the wrap, or prints
// on.
func (g *streamGen) wrap() {
	if g.chance(0.4) {
		g.put(g.one("\x1b[?7l", "\x1b[?7h"))
	}
	g.put("\x1b[999G", g.one("x", "y", "中", "\u00e9", "q"))
	switch g.rnd.IntN(3) {
	case 0:
		g.cut()
	case 1:
		g.put(g.one("\x1b[m", "\x1b[31m", "\x1b]8;;\x07", "\x1b(0", "\x1b[4h"))
		g.wraps = append(g.wraps, len(g.out))
	default:
		g.text()
	}
}

// ink is an ink-style live region: a few lines, erased and drawn again, as
// Claude Code's renderer repaints them.
func (g *streamGen) ink() {
	k := g.between(1, 4)
	draw := func() {
		for i := range k {
			if i > 0 {
				g.put("\r\n")
			}
			g.put(g.one("✳ ", "✶ ", "⏺ ", "· "))
			g.text()
		}
	}
	draw()
	for range g.between(0, 3) {
		g.put(strings.Repeat("\x1b[2K\x1b[1A", k-1), "\x1b[2K\x1b[G")
		draw()
	}
	if g.chance(0.5) {
		g.put("\r\n")
	}
}

func (g *streamGen) title() {
	g.put(g.one("\x1b]0;", "\x1b]2;"), g.one(g.word(), "✳ Claude Code"), g.one("\x07", "\x1b\\"))
}

// cursorStyle sets the cursor's style by DECSCUSR: a block, an underline or
// a bar, blinking or steady, or the default.
func (g *streamGen) cursorStyle() { g.putf("\x1b[%d q", g.rnd.IntN(7)) }

// kitty pushes, pops and sets the kitty keyboard flags, or sets
// modifyOtherKeys, which the tracker keeps and x/vt ignores.
func (g *streamGen) kitty() {
	switch g.rnd.IntN(6) {
	case 0, 1:
		g.putf("\x1b[>%du", g.rnd.IntN(32))
	case 2:
		g.put(g.one("\x1b[<u", "\x1b[<2u"))
	case 3:
		g.putf("\x1b[=%d;%du", g.rnd.IntN(32), g.between(1, 3))
	case 4:
		g.put(g.one("\x1b[>4;1m", "\x1b[>4;2m", "\x1b[>4m"))
	default:
		g.put("\x1b[>4n")
	}
}

// misc is the rest: controls that do nothing, queries whose replies go
// nowhere, a mark with nothing to join, a string CAN aborts, bytes that
// aren't UTF-8, and now and then a reset.
func (g *streamGen) misc() {
	switch g.rnd.IntN(12) {
	case 0:
		g.put(g.one("\x00", "\x07", "\x7f"))
	case 1:
		g.put(g.one("\x1b[c", "\x1b[6n", "\x1b[>c", "\x1b[?2004$p"))
	case 2:
		g.put("\r\u0301")
	case 3:
		g.put("\x1b]0;", g.word(), "\x18")
	case 4:
		g.put(g.one("\xff", "\xe2\x9c"), "x")
		g.cut()
	case 5:
		if g.chance(0.2) {
			g.put("\x1bc")
			g.alt = 0
		}
	case 6:
		if g.chance(0.2) {
			g.put("\x1b[!p")
		}
	case 7:
		g.put("\x1b[2J\x1b[3J\x1b[H")
		g.line()
	default:
		g.put(g.one("\x1bD", "\x1bD\r", "\x1bM"))
	}
}

// resize commits a resize, now and then two or three at one offset, and
// sometimes one to the size already in effect, as an event deleted between
// two leaves them. Claude Code repaints after one.
func (g *streamGen) resize() {
	n := 1
	if r := g.rnd.IntN(20); r >= 18 {
		n = 3
	} else if r >= 15 {
		n = 2
	}
	for range n {
		size := g.size
		if g.chance(0.9) {
			for size == g.size {
				size = g.randomSize()
			}
		}
		g.size = size
		g.event(size)
	}
	if g.chance(0.3) {
		g.put("\x1b[2J\x1b[3J\x1b[H")
		for range g.between(1, 4) {
			g.line()
		}
	}
}

// resizeInside commits a resize inside a sequence, as the pty can resize
// between two writes of one.
func (g *streamGen) resizeInside() {
	head, tail := g.one("\x1b[3", "\x1b]0;ti", "\x1b[?20"), ""
	switch head {
	case "\x1b[3":
		tail = "1m"
	case "\x1b]0;ti":
		tail = "tle\x07"
	default:
		tail = "04h"
	}
	g.put(head)
	size := g.randomSize()
	for size == g.size {
		size = g.randomSize()
	}
	g.size = size
	g.event(size)
	g.put(tail)
}

// contCase is one case of the property: a stream cut into a prefix, which
// the replayer emulates, with the committed size events in it, and a
// suffix, which follows on both terminals.
type contCase struct {
	prefix []byte
	sizes  []uio.SizeEvent // the first at 0
	suffix []byte
	// offers is how io offers the prefix: the end of what Start is offered,
	// then of what each Feed is, the last len(prefix). nil is Start alone.
	offers []int
	// join is the joiner's terminal, or the zero size for one the size of
	// the last event, which the render is at.
	join termsize.Size
}

// joiner is the size of c's joiner's terminal.
func (c contCase) joiner() termsize.Size {
	if c.join == (termsize.Size{}) {
		return c.sizes[len(c.sizes)-1].Size
	}
	return c.join
}

// largerThan draws a joiner's terminal larger than r, the render's size:
// wider, taller, or both.
func largerThan(rnd *rand.Rand, r termsize.Size) termsize.Size {
	j := r
	switch rnd.IntN(3) {
	case 0:
		j.Cols += 1 + rnd.IntN(40)
	case 1:
		j.Rows += 1 + rnd.IntN(20)
	default:
		j.Cols += 1 + rnd.IntN(40)
		j.Rows += 1 + rnd.IntN(20)
	}
	return j
}

// genCase draws a case from rnd: a stream from genStream, cut half the time
// where the cut leaves printable text or part of a cluster in the tail, or
// now and then a wrap pending at the handoff point, and otherwise anywhere;
// the suffix is the stream's next bytes, up to its next
// size event, so that a cluster cut in two goes on, then genSuffix's. Half
// the time, io's offers split the prefix between Start and one to three
// Feeds.
func genCase(rnd *rand.Rand) contCase {
	g := newStream(rnd)
	p := rnd.IntN(len(g.out) + 1)
	switch r := rnd.IntN(8); {
	case r == 0 && len(g.wraps) > 0:
		p = g.wraps[rnd.IntN(len(g.wraps))]
	case r < 4 && len(g.cuts) > 0:
		p = g.cuts[rnd.IntN(len(g.cuts))]
	}
	c := contCase{prefix: g.out[:p:p]}
	next := len(g.out)
	for _, ev := range g.sizes {
		if int(ev.Offset) > p {
			next = int(ev.Offset)
			break
		}
		c.sizes = append(c.sizes, ev)
	}
	c.suffix = append(bytes.Clone(g.out[p:next]), genSuffix(rnd)...)
	if rnd.IntN(2) == 0 && p > 1 {
		for range rnd.IntN(3) + 1 {
			c.offers = append(c.offers, 1+rnd.IntN(p-1))
		}
		slices.Sort(c.offers)
		c.offers = append(slices.Compact(c.offers), p)
	}
	return c
}

// contRun is what a case came to: the two terminals, A, the session's own,
// fed the prefix with its resizes, then the suffix, and B, a terminal fresh
// at the joiner's size, fed the render, the deferred tail and the suffix (a
// joiner larger than the render, only the render, and A only up to the
// handoff point); and the outcome. Both read the stream's screen title
// strings as tmux does, under whose TERM the replay runs (see contTERM). A
// case that rendered and held has none of skip, bug and diff.
type contRun struct {
	a, b       *vt.Emulator
	aOff, bOff *scrollOff
	render     []byte
	// skip is why the case was skipped: the replay fell back, or a size
	// event waits in the deferred tail, so io would feed it more first.
	skip string
	// bug is an error no replay should return: the tracker and the emulator
	// read the stream apart, or a handoff point carries a cluster.
	bug error
	// diff is the first difference between A and B.
	diff string
}

// contTERM is the TERM the property's session runs its program under:
// tmux's, so that the replay hands x/vt each screen title string the stream
// sends, as A and B read them (see screenTitlesRead), rather than falling
// back on it.
const contTERM = "tmux-256color"

// screenTitleOpener is ESC k as x/vt's parser reads it: after an ESC, and any
// C0 controls but CAN and SUB, which it executes in its escape state, and
// DEL, which it ignores there.
var screenTitleOpener = regexp.MustCompile("\x1b([\x00-\x17\x19\x1c-\x1f\x7f]*)k")

// screenTitlesRead is p as a session's terminal that is GNU screen or tmux
// reads its window title strings, ESC k title ST, for x/vt to read them so:
// each k of an ESC k made a ^, which makes the title a PM that x/vt's parser
// consumes to the ESC, CAN or SUB that ends it, as tmux consumes the title,
// the length kept. The emulation reads the stream so too, under tmux's TERM.
func screenTitlesRead(p []byte) []byte {
	return screenTitleOpener.ReplaceAll(p, []byte("\x1b$1^"))
}

// eventsUpTo is how many of sizes are at or before offset.
func eventsUpTo(sizes []uio.SizeEvent, offset int) int {
	n := 0
	for n < len(sizes) && int(sizes[n].Offset) <= offset {
		n++
	}
	return n
}

// replay emulates c's prefix as io does: from the ring's first byte, with a
// fresh tracker, by Start and then each Feed, offering each piece of the
// prefix with the events in it, for c's joiner, by the replayer for a
// session whose program runs under contTERM.
func (c contCase) replay(deadline time.Time) (uio.Emulation, error) {
	ends := c.offers
	if ends == nil {
		ends = []int{len(c.prefix)}
	}
	k := eventsUpTo(c.sizes, ends[0])
	em, err := NewForTerm(contTERM).Start(context.Background(), deadline, &uio.Capture{
		Modes:  uio.NewModeTracker(),
		Chunks: [][]byte{c.prefix[:ends[0]]},
		Sizes:  c.sizes[:k],
		End:    uint64(ends[0]),
	}, c.joiner())
	for i := 1; err == nil && i < len(ends); i++ {
		j := eventsUpTo(c.sizes, ends[i])
		err = em.Feed([][]byte{c.prefix[ends[i-1]:ends[i]]}, c.sizes[k:j])
		k = j
	}
	return em, err
}

// run runs c: the replay, through io's Start and Feeds, of the prefix for
// c's joiner, the render being at the size of the last event once every
// event is passed; then A and B, and sameState between them before the
// suffix and after it. B is a terminal of the joiner's size: for one larger
// than the render, the two are compared by sameStateInside at the handoff
// point, before the deferred tail. The replay's history is kept whole,
// budget permitting, so set the budget large. Everything stops at wait,
// which is a skip.
func (c contCase) run(wait time.Duration) contRun {
	var r contRun
	deadline := time.Now().Add(wait)
	last := c.sizes[len(c.sizes)-1]
	em, err := c.replay(deadline)
	if err != nil {
		return r.failed(err)
	}
	h, lastSeq := em.Handoff()
	if lastSeq != last.Seq {
		r.skip = "a size event waits in the deferred tail"
		return r
	}
	if r.render, err = em.Render(); err != nil {
		return r.failed(err)
	}
	e := em.(*emulation)
	rendered := historyOf(e)

	stop := func() bool { return !time.Now().Before(deadline) }
	// The stream as A and B read it, offsets kept, the replay having read
	// the raw prefix.
	read := screenTitlesRead(slices.Concat(c.prefix, c.suffix))
	prefix, suffix := read[:len(c.prefix)], read[len(c.prefix):]
	first := c.sizes[0].Size
	r.a = vt.NewEmulator(first.Cols, first.Rows)
	r.a.SetReplyFunc(func([]byte) {})
	r.a.SetStopFunc(stop)
	r.aOff = collectScrollOff(r.a)
	aNames := watchTitle(r.a)
	var werr error
	write := func(term *vt.Emulator, p []byte) {
		if _, err := term.Write(p); err != nil && werr == nil {
			werr = err
		}
	}
	// A, as the session's terminal: resized where each event is, unless it
	// is to the size the terminal has, which it never sees as a resize.
	// Every event is at or before h, the replay having passed them all.
	size, pos := first, 0
	for _, ev := range c.sizes[1:] {
		write(r.a, prefix[pos:ev.Offset])
		pos = int(ev.Offset)
		if ev.Size != size {
			r.a.Resize(ev.Size.Cols, ev.Size.Rows)
			size = ev.Size
		}
	}
	write(r.a, prefix[pos:h])
	// A render starts with what ends a synchronized update the joiner's
	// terminal was left inside, and one begun inside an update with what
	// begins it again (see synced), which sameState checks of ?2026, as it
	// compares that mode; x/vt keeps nothing of the DCS form. Once the
	// stream has cleared history before the handoff point, as A's clears
	// count, the render clears the joiner's scrollback, by ED 3, before the
	// history it sends.
	full := []byte(e.synced() + preamble)
	if r.aOff.clears > 0 {
		full = append(full, "\x1b[3J"...)
	}
	for _, line := range rendered {
		full = append(append(full, line...), crlf...)
	}
	if werr == nil && !bytes.HasPrefix(r.render, full) {
		r.diff = "the render doesn't start with the history the replay kept, after a clear of the joiner's only where A's was cleared"
		return r
	}
	// A line of history wider than the joiner wraps when the render prints
	// it on B, as it would on any terminal of that width, so B's own
	// scroll-off then holds more lines than the render emitted.
	join := c.joiner()
	wider := slices.ContainsFunc(r.aOff.widths, func(w int) bool { return w > join.Cols })
	if join != last.Size {
		if werr != nil {
			r.skip = "the terminals ran out of time"
			return r
		}
		return r.inside(join, rendered, *aNames, wider, stop)
	}
	write(r.a, prefix[h:])

	r.b = vt.NewEmulator(e.term.Width(), e.term.Height())
	r.b.SetReplyFunc(func([]byte) {})
	r.b.SetStopFunc(stop)
	r.bOff = collectScrollOff(r.b)
	bNames := watchTitle(r.b)
	write(r.b, r.render)
	nb, clears := len(r.bOff.lines), r.bOff.clears
	write(r.b, prefix[h:])

	// What B holds of history is the lines the render emitted, then what
	// scrolled off B after them, unless the stream cleared history since,
	// on both terminals. The render's lines encode the session's own cells,
	// as A's do, so they compare exactly; a line B scrolled off, it may have
	// drawn from the render's colours, so those compare as the render can
	// write them (see scrollOff).
	check := func(when string) string {
		aHist, bHist := r.aOff.canon, r.bOff.canon
		if r.bOff.clears == clears && len(r.aOff.lines) >= len(rendered) {
			aHist = append(slices.Clip(r.aOff.lines[:len(rendered)]), r.aOff.canon[len(rendered):]...)
			bHist = append(slices.Clip(rendered), r.bOff.canon[nb:]...)
		}
		if d := sameState(r.a, r.b, aHist, bHist, *aNames, *bNames); d != "" {
			return when + ": " + d
		}
		if !wider && !slices.EqualFunc(r.aOff.canon, r.bOff.canon, bytes.Equal) {
			return fmt.Sprintf("%s: the history B scrolled off: %q vs %q", when, r.aOff.canon, r.bOff.canon)
		}
		return ""
	}
	if werr == nil {
		r.diff = check("before the suffix")
	}
	if r.diff == "" && werr == nil {
		write(r.a, suffix)
		write(r.b, suffix)
		if werr == nil {
			r.diff = check("after the suffix")
		}
	}
	if werr != nil {
		r.diff = ""
		r.skip = "the terminals ran out of time"
	}
	return r
}

// inside compares r.a, the session's terminal at the handoff point, with B,
// a terminal of join's size, larger than the render's, given the render:
// sameStateInside, and B's own scroll-off, which holds the render's history
// lines as A's holds them, unless one is wider than the joiner. Then, for a
// joiner wider than A, the pty widens to its width, and A with it: A's tab
// stops are then B's, the ones A kept past its width included.
func (r contRun) inside(join termsize.Size, rendered [][]byte, aNames names, wider bool, stop func() bool) contRun {
	r.b = vt.NewEmulator(join.Cols, join.Rows)
	r.b.SetReplyFunc(func([]byte) {})
	r.b.SetStopFunc(stop)
	r.bOff = collectScrollOff(r.b)
	bNames := watchTitle(r.b)
	if _, err := r.b.Write(r.render); err != nil || stop() {
		r.skip = "the terminals ran out of time"
		return r
	}
	switch d := sameStateInside(r.a, r.b, r.aOff.lines, rendered, aNames, *bNames); {
	case d != "":
		r.diff = "at the handoff: " + d
	case !wider && !slices.EqualFunc(r.aOff.canon, r.bOff.canon, bytes.Equal):
		r.diff = fmt.Sprintf("at the handoff: the history B scrolled off: %q vs %q", r.aOff.canon, r.bOff.canon)
	}
	if r.diff != "" || join.Cols == r.a.Width() {
		return r
	}
	r.a.Resize(join.Cols, r.a.Height())
	if _, err := r.a.Write(nil); err != nil || stop() {
		r.skip = "the terminals ran out of time"
		return r
	}
	if ta, tb := r.a.TabStops(), r.b.TabStops(); !slices.Equal(ta, tb) {
		r.diff = fmt.Sprintf("once the pty is as wide: tab stops: %v vs %v", ta, tb)
	}
	return r
}

// failed records why the replay failed: a bug, or a fallback, by what it
// names.
func (r contRun) failed(err error) contRun {
	var ie *IneligibleError
	switch {
	case errors.Is(err, ErrTrackerDisagrees), errors.Is(err, ErrHandoffInvariant):
		r.bug = err
	case errors.As(err, &ie):
		r.skip = "ineligible: " + ie.State
	default:
		r.skip = err.Error()
	}
	return r
}

// failure is how the case failed, or "".
func (r contRun) failure() string {
	if r.bug != nil {
		return r.bug.Error()
	}
	return r.diff
}

// kind is what failed, without the details, which shrinking a case changes:
// the error, or which state differs.
func (r contRun) kind() string {
	switch {
	case errors.Is(r.bug, ErrTrackerDisagrees):
		return ErrTrackerDisagrees.Error()
	case errors.Is(r.bug, ErrHandoffInvariant):
		return ErrHandoffInvariant.Error()
	case r.diff == "":
		return ""
	}
	what := r.diff
	if _, rest, ok := strings.Cut(what, ": "); ok {
		what, _, _ = strings.Cut(rest, ":")
	}
	return what
}

// requireContinues requires r to have rendered and continued as the
// session's terminal did.
func requireContinues(t *testing.T, c contCase, r contRun) {
	t.Helper()
	require.Empty(t, r.skip, "the replay fell back")
	require.Empty(t, r.failure(), "the render: %q\n%s", r.render, c.repro())
}

// setBudget sets the replay's budget until the test ends.
func setBudget(t testing.TB, n int) {
	old := budget
	budget = n
	t.Cleanup(func() { budget = old })
}

// repro is c as Go, to paste into a test.
func (c contCase) repro() string {
	var b strings.Builder
	fmt.Fprintf(&b, "contCase{\n\tprefix: []byte(%q),\n\tsizes:  []uio.SizeEvent{", c.prefix)
	for i, ev := range c.sizes {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "event(%d, %d, %d, %d)", ev.Seq, ev.Offset, ev.Size.Cols, ev.Size.Rows)
	}
	fmt.Fprintf(&b, "},\n\tsuffix: []byte(%q),\n\toffers: %#v,\n", c.suffix, c.offers)
	if c.join != (termsize.Size{}) {
		fmt.Fprintf(&b, "\tjoin:   termsize.Size{Cols: %d, Rows: %d},\n", c.join.Cols, c.join.Rows)
	}
	b.WriteString("}")
	return b.String()
}

// shrink returns a smaller case that fails as c does, by kind.
func shrink(c contCase, kind string) contCase {
	return shrinkCase(c, func(d contCase) bool { return d.run(time.Minute).kind() == kind })
}

// shrinkCase returns a smaller case for which fails holds, as it does for c,
// the smallest it finds in the time -replay.shrink allows: it cuts bytes
// from the suffix and from the prefix, its events and offers moving with
// them, and drops events and Feeds, for as long as fails holds.
func shrinkCase(c contCase, failing func(contCase) bool) contCase {
	stop := time.Now().Add(*propertyShrink)
	fails := func(d contCase) bool { return time.Now().Before(stop) && failing(d) }
	if d := c; d.offers != nil {
		if d.offers = nil; fails(d) {
			c = d
		}
	}
	for progress := true; progress && time.Now().Before(stop); {
		progress = false
		if s, ok := shrinkBytes(c.suffix, func(s []byte) bool {
			d := c
			d.suffix = s
			return fails(d)
		}); ok {
			c.suffix, progress = s, true
		}
		for n := len(c.prefix); n >= 1; n /= 2 {
			for i := 0; i+n <= len(c.prefix); {
				if d := c.without(i, n); fails(d) {
					c, progress = d, true
				} else {
					i += n
				}
			}
		}
		for i := len(c.sizes) - 1; i >= 1; i-- {
			d := c
			d.sizes = renumber(slices.Delete(slices.Clone(c.sizes), i, i+1))
			if fails(d) {
				c, progress = d, true
			}
		}
	}
	return c
}

// shrinkBytes removes what it can of b, in pieces from all of it down to a
// byte, while fails holds.
func shrinkBytes(b []byte, fails func([]byte) bool) ([]byte, bool) {
	shrunk := false
	for n := len(b); n >= 1; n /= 2 {
		for i := 0; i+n <= len(b); {
			if d := slices.Concat(b[:i], b[i+n:]); fails(d) {
				b, shrunk = d, true
			} else {
				i += n
			}
		}
	}
	return b, shrunk
}

// without is c with the prefix's bytes from i to i+n removed: the events
// and offers after them move back by n, and those among them to i.
func (c contCase) without(i, n int) contCase {
	move := func(off int) int {
		switch {
		case off >= i+n:
			return off - n
		case off > i:
			return i
		}
		return off
	}
	d := contCase{prefix: slices.Concat(c.prefix[:i], c.prefix[i+n:]), suffix: c.suffix, join: c.join}
	for _, ev := range c.sizes {
		ev.Offset = uint64(move(int(ev.Offset)))
		d.sizes = append(d.sizes, ev)
	}
	if c.offers != nil {
		for _, off := range c.offers {
			if off = move(off); off > 0 && (len(d.offers) == 0 || off > d.offers[len(d.offers)-1]) {
				d.offers = append(d.offers, off)
			}
		}
		if len(d.offers) == 0 || d.offers[len(d.offers)-1] != len(d.prefix) {
			d.offers = append(d.offers, len(d.prefix))
		}
	}
	return d
}

// renumber gives sizes the Seqs 1, 2 and on, in order.
func renumber(sizes []uio.SizeEvent) []uio.SizeEvent {
	for i := range sizes {
		sizes[i].Seq = uint64(i + 1)
	}
	return sizes
}

// The main property: a terminal fresh at the render's size, given the render
// at the handoff point and then the stream from there on, is in the state of
// the terminal that was given the whole stream, before the next bytes and
// after them, for every case the replay renders. A replay that falls back is
// skipped and counted, and fails the test only when there are too many
// skips, which would mean the generator drifted into testing nothing; but the
// tracker and the emulator disagreeing, or a handoff point that carries a
// cluster, fails it at once, since neither is a fallback the stream asked for.
func TestReplayContinuesEquivalently(t *testing.T) {
	property(t, "rendered and continued alike", genCase)
}

// The property for a joiner larger than the render, as a joiner is when a
// smaller client shares the session or the pty's size is pinned: B, a
// terminal of the joiner's size given the render, holds at its top left what
// A, the session's terminal, holds at the handoff point, and elsewhere what
// the render leaves it (see sameStateInside). The cases are the main
// property's, each with a larger joiner drawn after it.
func TestReplayRendersInsideALargerJoiner(t *testing.T) {
	property(t, "rendered alike inside the joiner", func(rnd *rand.Rand) contCase {
		c := genCase(rnd)
		c.join = largerThan(rnd, c.sizes[len(c.sizes)-1].Size)
		return c
	})
}

// property runs -replay.cases cases that draw draws from -replay.seed, and
// fails on the first that rendered and didn't hold, with that case shrunk;
// held says, in its log, what the others did.
func property(t *testing.T, held string, draw func(*rand.Rand) contCase) {
	setBudget(t, 64<<20)
	seed, n := *propertySeed, *propertyCases
	skipped := map[string]int{}
	for i := range n {
		c := draw(rand.New(rand.NewPCG(seed, uint64(i))))
		r := c.run(time.Minute)
		if f := r.failure(); f != "" {
			t.Fatalf("-replay.seed=%d, case %d: %s\nA minimal case that fails the same way:\n%s",
				seed, i, f, shrink(c, r.kind()).repro())
		}
		if r.skip != "" {
			skipped[r.skip]++
		}
	}
	total := 0
	var reasons []string
	for _, why := range slices.Sorted(maps.Keys(skipped)) {
		total += skipped[why]
		reasons = append(reasons, fmt.Sprintf("%d %s", skipped[why], why))
	}
	t.Logf("-replay.seed=%d: %d of %d cases (%.1f%%) %s; skipped: %s",
		seed, n-total, n, 100*float64(n-total)/float64(n), held, strings.Join(reasons, "; "))
	require.LessOrEqual(t, 5*total, n, "more than a fifth of the cases fell back")
}

// capturing is a Replayer that keeps each capture a join takes, and the
// snapshot of the tracker it starts from, before r, if there is one,
// emulates it; without r, every join falls back.
type capturing struct {
	r    uio.Replayer
	c    *uio.Capture
	snap []byte
}

var errCaptured = errors.New("replay: captured, not emulated")

func (c *capturing) Start(ctx context.Context, deadline time.Time, capt *uio.Capture, size termsize.Size) (uio.Emulation, error) {
	// The emulation writes to the tracker, so its snapshot is taken first.
	c.c, c.snap = capt, capt.Modes.Snapshot()
	if c.r == nil {
		return nil, errCaptured
	}
	return c.r.Start(ctx, deadline, capt, size)
}

// fanOut writes stream to a fan-out whose ring keeps the last ring bytes, in
// 4 KiB writes, reporting each of sizes where it is in the stream, as the pty
// reports a resize it made, and joins a terminal the size of the last
// through r. It returns what the joiner was sent, and why the join fell
// back, if it did.
func fanOut(t testing.TB, r uio.Replayer, stream []byte, sizes []uio.SizeEvent, ring int) (joined []byte, fellBack error) {
	t.Helper()
	return fanOutTo(t, r, stream, sizes, ring, sizes[len(sizes)-1].Size)
}

// fanOutTo is fanOut for a joiner whose terminal is join, which may be
// larger than the pty.
func fanOutTo(t testing.TB, r uio.Replayer, stream []byte, sizes []uio.SizeEvent, ring int, join termsize.Size) (joined []byte, fellBack error) {
	t.Helper()
	w := uio.NewMultiWriter(ring)
	w.SetReplayer(r, func(err error) { fellBack = err })
	write := func(p []byte) {
		for len(p) > 0 {
			n := min(len(p), 4<<10)
			_, _ = w.Write(p[:n])
			p = p[n:]
		}
	}
	pos := 0
	for _, ev := range sizes {
		write(stream[pos:ev.Offset])
		pos = int(ev.Offset)
		w.ResizeEnd(w.ResizeBegin(ev.Size), true)
	}
	write(stream[pos:])
	var out bytes.Buffer
	require.NoError(t, w.AppendSized(context.Background(), time.Now().Add(time.Minute), join, &out))
	return out.Bytes(), fellBack
}

// feedSized writes p to term, which starts at size, from stream offset
// start, resizing it where each of sizes is, unless it already has that
// size, as a terminal never sees such a resize.
func feedSized(term *vt.Emulator, p []byte, start uint64, size termsize.Size, sizes []uio.SizeEvent) {
	pos := 0
	for _, ev := range sizes {
		k := int(ev.Offset - start)
		_, _ = term.Write(p[pos:k])
		pos = k
		if ev.Size != size {
			term.Resize(ev.Size.Cols, ev.Size.Rows)
			size = ev.Size
		}
	}
	_, _ = term.Write(p[pos:])
}

// primingDiff reports the first difference, in what the tracker models,
// between a terminal fed stream with its resizes and one fresh at the
// capture's first size, primed with the snapshot a join's capture starts
// from, then fed the ring the same way: the scroll region's rows, the
// tracked DEC modes, the screen showing, G0, and the kitty keyboard stacks,
// which x/vt doesn't keep, so a tracker fed each side stands in for a
// terminal that does. It is "" when they agree, and when the ring was empty
// and nothing was captured.
//
// G0 is compared unless the ring restored it from a saved cursor no snapshot
// can prime, which leaves the two apart however the joiner's is primed; see
// lostG0.
//
// The joiner's terminal is primed the same way, by the raw replay and by the
// emulation the replayer primes, so the region the tracker decided a DECSTBM
// at, at the height of its moment, has to be the terminal's.
func primingDiff(t testing.TB, stream []byte, sizes []uio.SizeEvent, ring int) string {
	t.Helper()
	capt := &capturing{}
	_, _ = fanOut(t, capt, stream, sizes, ring)
	c := capt.c
	if c == nil {
		return ""
	}
	ringBytes := bytes.Join(c.Chunks, nil)
	// The ring's offsets are in the stream its query filter kept.
	var kept bytes.Buffer
	_, _ = uio.NewTerminalQueryFilter(&kept).Write(stream)
	require.True(t, bytes.Equal(kept.Bytes()[c.Start:], ringBytes), "the ring is the end of what the filter kept")
	first := c.Sizes[0].Size
	primed := vt.NewEmulator(first.Cols, first.Rows)
	primed.SetReplyFunc(func([]byte) {})
	_, _ = primed.Write(capt.snap)
	feedSized(primed, ringBytes, c.Start, first, c.Sizes[1:])
	ref := vt.NewEmulator(sizes[0].Size.Cols, sizes[0].Size.Rows)
	ref.SetReplyFunc(func([]byte) {})
	feedSized(ref, stream, 0, sizes[0].Size, sizes[1:])

	ra, rb := ref.ActiveScreen().ScrollRegion(), primed.ActiveScreen().ScrollRegion()
	if ra.Min.Y != rb.Min.Y || ra.Max.Y != rb.Max.Y {
		return fmt.Sprintf("scroll region rows: %d-%d vs %d-%d", ra.Min.Y, ra.Max.Y, rb.Min.Y, rb.Max.Y)
	}
	for _, n := range trackedModes {
		if a, b := ref.Mode(ansi.DECMode(n)).IsSet(), primed.Mode(ansi.DECMode(n)).IsSet(); a != b {
			return fmt.Sprintf("mode ?%d: %v vs %v", n, a, b)
		}
	}
	if a, b := ref.IsAltScreen(), primed.IsAltScreen(); a != b {
		return fmt.Sprintf("alternate screen showing: %v vs %v", a, b)
	}
	if !lostG0(kept.Bytes(), int(c.Start)) {
		a, _, _ := ref.Charsets()
		if b, _, _ := primed.Charsets(); a[0] != b[0] {
			return fmt.Sprintf("G0: %q vs %q", a[0], b[0])
		}
	}
	kRef, kPrimed := uio.NewModeTracker(), uio.NewModeTracker()
	_, _ = kRef.Write(stream)
	_, _ = kPrimed.Write(capt.snap)
	_, _ = kPrimed.Write(ringBytes)
	pa, pb := kRef.ReplayParts(), kPrimed.ReplayParts()
	if !bytes.Equal(pa.MainKeys, pb.MainKeys) || !bytes.Equal(pa.AltKeys, pb.AltKeys) || !bytes.Equal(pa.HiddenAltKeys, pb.HiddenAltKeys) {
		return fmt.Sprintf("kitty stacks: %q %q %q vs %q %q %q", pa.MainKeys, pa.AltKeys, pa.HiddenAltKeys, pb.MainKeys, pb.AltKeys, pb.HiddenAltKeys)
	}
	return ""
}

// lostG0 reports whether the ring leaves the two terminals primingDiff
// compares on different G0s even when the snapshot primes all it can, by
// restoring G0 from a saved cursor no snapshot can prime. p is the stream as
// the ring has it, which the ring starts start bytes into.
//
// A cursor save keeps G0 in the slot of the screen showing, and a restore
// brings it back: ESC 7, CSI s while DECLRMM (?69) is reset, ?1048h and
// ?1049h save; ESC 8, a bare CSI u and ?1048l restore from the slot of the
// screen showing, and ?1049l from the main screen's, once it has switched
// back. A RIS, which leaves the alternate screen, fills the main screen's
// slot with ASCII, and a DECSTR the slot of the screen showing, as each puts
// G0 back to ASCII; a slot nothing filled restores ASCII too.
//
// So lostG0 follows G0 and both slots on each terminal: the session's from
// the stream's first byte, and the primed one from the ring's, as a snapshot
// that primes all it can leaves it. That holds the session's G0; and while
// the alternate screen shows, the session's main screen's slot, which the
// snapshot fills by designating the G0 saved there ahead of the ?1049h it
// replays, or ahead of an ESC 7 of its own before a ?47h or ?1047h. Either
// fill saves the joiner's cursor and pen of the moment with G0, as any save
// would; what sets them apart from a fill of another slot is that they are
// made while the alternate screen shows, where the main screen's cursor
// isn't live. The snapshot fills no other slot, so the main screen's slot
// while the main screen shows, and the alternate screen's always, hold
// ASCII on the primed terminal, whatever the session saved there before the
// ring. A save in the ring is made on both, so only such a slot, restored in
// the ring, can leave them apart.
//
// The stream is read as x/vt reads it, since both terminals are x/vt. That
// is the tracker's reading but for two sequences: x/vt designates G0 only by
// an SCS whose final is 0, A or B (see xvtESC), and ignores any other,
// where the tracker keeps whatever final it is given; and x/vt saves on a
// CSI s with parameters too, where the tracker, as xterm, saves on a bare one
// alone. A stream that tells the readings apart before the ring is primed
// with the tracker's, which the terminal fed the whole stream doesn't hold,
// and primingDiff reports it.
func lostG0(p []byte, start int) bool {
	// charsets is one terminal's G0, and the G0 each screen's saved slot
	// holds, by mainScreen and altScreen, as the final byte of the SCS that
	// designated it: 'B' for ASCII.
	type charsets struct {
		g0    byte
		slots [2]byte
	}
	session := &charsets{'B', [2]byte{'B', 'B'}}
	var primed *charsets // from the ring's first byte on
	each := func(f func(c *charsets)) {
		f(session)
		if primed != nil {
			f(primed)
		}
	}
	var alt, lrmm bool // the alternate screen shows; DECLRMM, under which CSI s sets margins
	screen := func() int {
		if alt {
			return altScreen
		}
		return mainScreen
	}
	save := func() {
		s := screen()
		each(func(c *charsets) { c.slots[s] = c.g0 })
	}
	restore := func(s int) { each(func(c *charsets) { c.g0 = c.slots[s] }) }
	reset := func(s int) { each(func(c *charsets) { c.g0, c.slots[s] = 'B', 'B' }) }
	parser := ansi.NewParser()
	parser.SetHandler(ansi.Handler{
		HandleEsc: func(cmd ansi.Cmd) {
			switch {
			case cmd.Intermediate() == '(' && xvtESC[int(cmd)]:
				each(func(c *charsets) { c.g0 = cmd.Final() })
			case cmd == '7':
				save()
			case cmd == '8':
				restore(screen())
			case cmd == 'c':
				alt, lrmm = false, false
				reset(mainScreen)
			}
		},
		HandleCsi: func(cmd ansi.Cmd, params ansi.Params) {
			switch {
			case cmd == 's' && !lrmm:
				save()
			case cmd == 'u' && len(params) == 0:
				restore(screen())
			case cmd == ansi.Cmd(ansi.Command(0, '!', 'p')):
				lrmm = false
				reset(screen())
			case cmd == ansi.Cmd(ansi.Command('?', 0, 'h')), cmd == ansi.Cmd(ansi.Command('?', 0, 'l')):
				set := cmd.Final() == 'h'
				params.ForEach(0, func(_, n int, _ bool) {
					switch n {
					case 69:
						lrmm = set
					case 1048:
						if set {
							save()
						} else {
							restore(screen())
						}
					case 47, 1047:
						alt = set
					case 1049:
						if set {
							save()
						} else {
							restore(mainScreen)
						}
						alt = set
					}
				})
			}
		},
	})
	for i, b := range p {
		if i == start {
			primed = &charsets{session.g0, [2]byte{'B', 'B'}}
			if alt {
				primed.slots[mainScreen] = session.slots[mainScreen]
			}
		}
		parser.Advance(b)
	}
	return primed != nil && primed.g0 != session.g0
}

// requirePrimes requires primingDiff to find nothing, and when it does find
// a difference, reports the smallest stream it finds that differs the same
// way, through the smallest ring: a smaller ring lets more of the stream go.
func requirePrimes(t *testing.T, stream []byte, sizes []uio.SizeEvent, ring int, origin string) {
	t.Helper()
	d := primingDiff(t, stream, sizes, ring)
	if d == "" {
		return
	}
	kind, _, _ := strings.Cut(d, ":")
	same := func(c contCase, ring int) bool {
		got, _, _ := strings.Cut(primingDiff(t, c.prefix, c.sizes, ring), ":")
		return got == kind
	}
	min := contCase{prefix: stream, sizes: sizes}
	for ring > 1 && same(min, ring/2) {
		ring /= 2
	}
	min = shrinkCase(min, func(c contCase) bool { return same(c, ring) })
	t.Fatalf("%s: %s\nA minimal stream that differs the same way, through a ring of %d bytes:\n%s",
		origin, d, ring, min.repro())
}

// The priming property: for streams from genStream, with their resizes, fed
// to a fan-out whose ring is small enough that most of each is evicted
// through the tracker, a terminal primed with the tracker's snapshot and
// given the ring agrees with the one given the whole stream on everything
// the tracker models.
func TestTrackerSnapshotPrimesWhatItModels(t *testing.T) {
	// A DECSC and DECRC the ring has lost are the tracker's to follow, so G0
	// is compared after them, here where only G1 was designated.
	requirePrimes(t, []byte("\x1b)0\x1b7text\x1b8\r\nmore text\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 8,
		"a DECRC with no G0 designation")
	// G0 is compared after each of these restores in the ring, since the slot
	// each reads holds on the primed terminal what it holds on the session's:
	// it was saved in the ring; or it is the main screen's, saved before the
	// alternate screen was entered, which the snapshot fills; or a reset in
	// the ring refilled it. In the last row nothing is restored: a CSI u with
	// a parameter isn't SCORC, so the slot the evicted DECSC filled stays
	// unread.
	for _, tc := range []struct{ name, evicted, ring string }{
		{"DECSC and DECRC in the ring, after an evicted designation", "\x1b(0", "\x1b7\x1b(Btext\x1b8"},
		{"SCOSC and ?1048l in the ring, after an evicted designation", "\x1b(0", "\x1b[s\x1b(Btext\x1b[?1048l"},
		{"an evicted ?1049h, restored by ?1049l", "\x1b(0\x1b[?1049h\x1b(B", "\x1b[?1049l"},
		{"an evicted DECSC ahead of ?47h, restored by ?47l and DECRC", "\x1b(0\x1b7\x1b(B\x1b[?47h", "\x1b[?47l\x1b8"},
		{"an evicted DECSC ahead of ?1047h, restored by ?1047l and DECRC", "\x1b(0\x1b7\x1b(B\x1b[?1047h", "\x1b[?1047l\x1b8"},
		{"a RIS in the ring refills the main screen's slot", "\x1b(0\x1b7", "\x1bc\x1b(0\x1b8"},
		{"a DECSTR in the ring refills the slot of the screen showing", "\x1b(0\x1b7", "\x1b[!p\x1b(0\x1b8"},
		{"a CSI u with a parameter, after an evicted DECSC", "\x1b(0\x1b7", "\x1b(B\x1b[1u"},
	} {
		evicted, ring := tc.evicted+"text\r\n", tc.ring+"text\r\n"
		require.False(t, lostG0([]byte(evicted+ring), len(evicted)), "%s: G0 is compared", tc.name)
		requirePrimes(t, []byte(evicted+ring), []uio.SizeEvent{event(1, 0, 80, 24)}, len(ring), tc.name)
	}
	// G0 is skipped after each of these, and has to be: the ring restores a
	// slot whose save it evicted, which held line drawing and which no
	// snapshot can fill, so the two terminals end on different G0s however
	// the joiner's is primed. Such a slot is the main screen's while the main
	// screen shows, read by DECRC or SCORC alike, and the alternate screen's.
	// The last row is the first's with an SCS after the restore whose final
	// x/vt doesn't know, and ignores. It stands apart because a lostG0 that
	// took any final, as the tracker does, would set both G0s to that final
	// and miss the two ending apart.
	for _, tc := range []struct{ name, evicted, ring string }{
		{"an evicted DECSC on the main screen, restored by DECRC", "\x1b(0\x1b7\x1b(B", "\x1b8"},
		{"an evicted DECSC on the main screen, restored by SCORC", "\x1b(0\x1b7\x1b(B", "\x1b[u"},
		{"an evicted DECSC on the alternate screen, restored by DECRC", "\x1b[?1049h\x1b(0\x1b7\x1b(B", "\x1b8"},
		{"an SCS x/vt ignores, after an evicted DECSC restored by DECRC", "\x1b(0\x1b7\x1b(B", "\x1b8\x1b(C"},
	} {
		evicted, ring := tc.evicted+"text\r\n", tc.ring+"text\r\n"
		require.True(t, lostG0([]byte(evicted+ring), len(evicted)), "%s: G0 is skipped", tc.name)
		requirePrimes(t, []byte(evicted+ring), []uio.SizeEvent{event(1, 0, 80, 24)}, len(ring), tc.name)
	}
	seed := *propertySeed
	for i := range 500 {
		rnd := rand.New(rand.NewPCG(seed, 1<<32|uint64(i)))
		stream, sizes := genStream(rnd)
		ring := 256 + rnd.IntN(4<<10)
		requirePrimes(t, stream, sizes, ring, fmt.Sprintf("-replay.seed=%d, case %d", seed, i))
	}
}

// At 8 rows, CSI 2;5r then CSI 10;11r, whose bottom a terminal clamps to 8,
// not past 10, so it ignores it; or CSI 10r, ignored the same way. Both are
// evicted by 300 KiB of output through a 256 KiB ring, which the replay
// starts after: the snapshot the capture starts from primes the region 2-5,
// as the terminal given the whole stream has it, and the joiner continues
// with it.
func TestEvictedRegionPrimesAFreshEmulator(t *testing.T) {
	var out strings.Builder
	for i := 0; out.Len() < 300<<10; i++ {
		fmt.Fprintf(&out, "line %d of the output\r\n", i)
	}
	for _, ignored := range []string{"\x1b[10;11r", "\x1b[10r"} {
		t.Run(fmt.Sprintf("%q", ignored), func(t *testing.T) {
			// The session's output starts inside the region, so it draws
			// nothing outside it. The joiner's emulation starts from the
			// snapshot, whose DECSTBM homes the cursor to the top row, outside
			// the region. So the ring has to start at a line's LF, which moves
			// the cursor into the region before anything prints there: a ring
			// that started inside a line would print the rest of it on the
			// top row, where the session's terminal printed nothing, since
			// what a terminal held before the ring's first byte is unknown to
			// a joiner. Where the ring starts follows from the output's
			// length, so it is checked.
			head := "\x1b[2;5r" + ignored + "\x1b[2H"
			stream := []byte(head + out.String())
			capt := &capturing{r: New()}
			joined, fellBack := fanOut(t, capt, stream, []uio.SizeEvent{event(1, 0, 80, 8)}, uio.DefaultReplayBytes)
			require.NoError(t, fellBack)
			require.Greater(t, capt.c.Start, uint64(len(head)), "the DECSTBMs are still in the ring")
			require.Equal(t, byte('\n'), stream[capt.c.Start], "the ring starts inside a line")

			region := uv.Rect(0, 1, 80, 4)
			ref := vt.NewEmulator(80, 8)
			_, _ = ref.Write(stream)
			require.Equal(t, region, ref.ActiveScreen().ScrollRegion())
			primed := vt.NewEmulator(80, 8)
			_, _ = primed.Write(capt.snap)
			require.Equal(t, region, primed.ActiveScreen().ScrollRegion())

			b := vt.NewEmulator(80, 8)
			_, _ = b.Write(joined)
			require.Empty(t, sameState(ref, b, nil, nil, names{}, names{}))
		})
	}
}

// A ring that starts inside a character, its lead byte evicted, renders as
// the session's terminal holds it. The character's remaining continuation
// bytes complete one the ring doesn't hold, and x/vt, reading them at
// ground, would take those from 0x80 to 0x9F for C1 controls, failing the
// render on one or acting on it, so the emulation skips them. For a cut after
// each byte but the last of a 2-, 3- and 4-byte character whose continuation
// bytes hold C1's range, and of one whose don't, the join renders, and a
// joiner given it holds the session's screen once the ring's lines have
// scrolled the cut line off it; so too with a resize between the bytes
// skipped, and with one back to the first size later in the ring, which the
// emulator applies as a change from the size the first left it at. A cut
// inside a window title's character keeps the title whole:
// the tracker primes the title as a string, whose data the bytes are.
func TestReplayRendersARingThatStartsInsideACharacter(t *testing.T) {
	var lines strings.Builder
	for i := range 40 {
		fmt.Fprintf(&lines, "line %d ┌──┐ █ Ņ 中文 😀\r\n", i)
	}
	join := func(t *testing.T, head, ring string, sizes []uio.SizeEvent) {
		t.Helper()
		stream := []byte(head + ring)
		capt := &capturing{r: New()}
		joined, fellBack := fanOut(t, capt, stream, sizes, len(ring))
		require.NoError(t, fellBack)
		require.Equal(t, uint64(len(head)), capt.c.Start, "the ring starts at the cut")
		first, last := sizes[0].Size, sizes[len(sizes)-1].Size
		a, _ := newReference(first.Cols, first.Rows)
		aNames := watchTitle(a)
		feedSized(a, stream, 0, first, sizes[1:])
		b, _ := newReference(last.Cols, last.Rows)
		bNames := watchTitle(b)
		_, _ = b.Write(joined)
		require.Empty(t, sameState(a, b, nil, nil, *aNames, *bNames))
	}
	for _, char := range []string{"\xc5\x85", "\xe2\x96\x88", "\xf0\x9f\x98\x80", "\xe4\xb8\xad"} {
		for cut := 1; cut < len(char); cut++ {
			t.Run(fmt.Sprintf("%s after %d of its bytes", char, cut), func(t *testing.T) {
				join(t, "text\r\nab"+char[:cut], char[cut:]+"cd\r\n"+lines.String(), []uio.SizeEvent{event(1, 0, 80, 24)})
			})
		}
	}
	t.Run("a resize between the bytes skipped", func(t *testing.T) {
		head := "text\r\nab\xf0"
		join(t, head, "\x9f\x98\x80cd\r\n"+lines.String(), []uio.SizeEvent{event(1, 0, 80, 24), event(2, len(head)+1, 100, 24)})
	})
	t.Run("a resize between the bytes skipped, and one back later", func(t *testing.T) {
		head, ring := "text\r\nab\xf0", "\x9f\x98\x80cd\r\n"+lines.String()
		back := len(head) + strings.Index(ring, "line 10 ")
		join(t, head, ring, []uio.SizeEvent{event(1, 0, 80, 24), event(2, len(head)+1, 100, 24), event(3, back, 80, 24)})
	})
	t.Run("a window title's", func(t *testing.T) {
		join(t, "\x1b]2;the title \xe2\x96", "\x88 more\x07"+lines.String(), []uio.SizeEvent{event(1, 0, 80, 24)})
	})
}

// The bytes skipped at a ring that starts inside a character end where the
// character does: at a byte that isn't a continuation byte, which ends it
// early, or after as many as its lead byte said. What follows is read as the
// stream has it, so a sequence there that the render doesn't rebuild still
// fails it.
func TestReplayReadsWhatFollowsACutCharacter(t *testing.T) {
	for _, tc := range []struct{ name, head, ring, state string }{
		{"a byte that ends it early", "text\r\nab\xe2", "\x96\x1b#8more\r\n", "an unhandled ESC # 8"},
		{"a byte past it", "text\r\nab\xc5", "\x85\x85more\r\n", "a C1 control 0x85"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capt := &capturing{r: New()}
			_, fellBack := fanOut(t, capt, []byte(tc.head+tc.ring), []uio.SizeEvent{event(1, 0, 80, 24)}, len(tc.ring))
			require.Equal(t, uint64(len(tc.head)), capt.c.Start, "the ring starts at the cut")
			requireIneligible(t, fellBack, tc.state)
		})
	}
}

// A lone C1 byte the ring no longer holds doesn't fail the join: the session's
// terminal drew it, or acted on it, before the ring's first byte, which is as
// far back as a raw replay reaches too.
func TestReplayRendersPastAnEvictedC1Byte(t *testing.T) {
	for _, c1 := range []string{"\x84", "\x85", "\x9b", "\x9c"} {
		head := "text" + c1
		capt := &capturing{r: New()}
		_, fellBack := fanOut(t, capt, []byte(head+strings.Repeat("line\r\n", 1000)), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		require.Greater(t, capt.c.Start, uint64(len(head)), "%q is still in the ring", c1)
		require.NoError(t, fellBack, "%q", c1)
	}
}

// shellOutput is about n bytes of a shell session at 80 columns, none of its
// lines wrapping: commands at a prompt, listings with names in colour as ls
// colours them, numbered lines of output, so that a line lost or out of
// place shows; then a prompt.
func shellOutput(n int) []byte {
	rnd := rand.New(rand.NewPCG(13, 0))
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		switch {
		case i%20 == 0:
			fmt.Fprintf(&b, "$ ls -la src/%d", i)
		case i%7 == 3:
			fmt.Fprintf(&b, "drwxr-xr-x  5 user staff  160 Oct 16 12:00 \x1b[1;34mdir%05d\x1b[0m", i)
		default:
			fmt.Fprintf(&b, "%06d %s", i, strings.Repeat("x", 1+rnd.IntN(60)))
		}
		b.WriteString("\r\n")
	}
	b.WriteString("$ ")
	return []byte(b.String())
}

// sgr matches the SGR sequences shellOutput writes.
var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")

// textLines is the text of each line of p, a stretch of shellOutput's lines,
// without its colours or its trailing blanks, as a terminal holds it, and
// how many bytes of p each takes, its CRLF included.
func textLines(p []byte) (lines []string, sizes []int) {
	for raw := range bytes.SplitSeq(p, []byte(crlf)) {
		lines = append(lines, strings.TrimRight(string(sgr.ReplaceAll(raw, nil)), " "))
		sizes = append(sizes, len(raw)+len(crlf))
	}
	return lines, sizes
}

// heldLines is the text a terminal holds, oldest first: the lines that
// scrolled off it, then its screen's rows, each without its trailing blanks,
// to the last that isn't blank.
func heldLines(term *vt.Emulator, off *scrollOff) []string {
	var held []string
	for _, s := range off.texts {
		held = append(held, strings.TrimRight(s, " "))
	}
	for y := range term.Height() {
		held = append(held, strings.TrimRight(term.MainScreen().Line(y).String(), " "))
	}
	for len(held) > 0 && held[len(held)-1] == "" {
		held = held[:len(held)-1]
	}
	return held
}

// A plain shell session with no resizes, the common case, joined through a
// fan-out: with the whole session in the ring, the joiner's history and
// screen hold every line of it, in order. With the ring full, they hold its
// newest lines, in order, to the session's last, and leave out at most
// 2 KiB of the oldest the ring held, which the rest of the render's budget
// is spent on: the ring's first line, partway through as the ring starts
// there, counts as one of them.
func TestReplayPlainShellKeepsEveryLine(t *testing.T) {
	join := func(t *testing.T, stream []byte) (*vt.Emulator, *scrollOff, uint64) {
		t.Helper()
		capt := &capturing{r: New()}
		joined, fellBack := fanOut(t, capt, stream, []uio.SizeEvent{event(1, 0, 80, 24)}, uio.DefaultReplayBytes)
		require.NoError(t, fellBack)
		require.LessOrEqual(t, len(joined), uio.DefaultReplayBytes)
		b := vt.NewEmulator(80, 24)
		off := collectScrollOff(b)
		_, _ = b.Write(joined)
		return b, off, capt.c.Start
	}

	t.Run("every line", func(t *testing.T) {
		stream := shellOutput(200 << 10)
		b, off, start := join(t, stream)
		require.Zero(t, start, "the ring evicted some of the session")
		lines, _ := textLines(stream)
		require.Equal(t, lines, heldLines(b, off))
	})

	t.Run("a full ring", func(t *testing.T) {
		stream := shellOutput(320 << 10)
		b, off, start := join(t, stream)
		// The ring starts inside one of the numbered lines, which hold no
		// colours, so its text from there on is what the joiner is given.
		lines, sizes := textLines(stream[start:])
		held := heldLines(b, off)
		left := len(lines) - len(held)
		require.GreaterOrEqual(t, left, 0)
		require.Equal(t, lines[left:], held, "the newest lines, to the last")
		dropped := 0
		for _, n := range sizes[:left] {
			dropped += n
		}
		require.LessOrEqual(t, dropped, 2<<10, "the oldest lines the ring held, left out")
	})
}

// Wide characters, combining marks and ZWJ emoji, in history and on the
// screen, at the last column, cut by a narrowing, and split across the
// emulator's 4 KiB pieces and across io's offers; and clusters the stream
// put in two cells, which the render keeps apart.
func TestReplayWideAndCombiningCharacters(t *testing.T) {
	setBudget(t, 64<<20)
	cjk := "中文字 e\u0301 a\u0308\u0301 \U0001F468\u200d\U0001F469\u200d\U0001F467 \u2764\ufe0f \U0001F44D\U0001F3FD"
	split := "\U0001F1FA\x1b[m\U0001F1F8 \U0001F44D\x1b[1m\U0001F3FD e\x00\u093e \u1100\x1b[m\u1161\x1b[m"
	pad := strings.Repeat("x", piece-1)
	for _, tc := range []struct {
		name string
		c    contCase
	}{
		{"in history and on the screen", contCase{
			prefix: []byte(strings.Repeat(cjk+"\r\n", 6) + cjk),
			sizes:  []uio.SizeEvent{event(1, 0, 40, 3)},
			suffix: []byte("\u0301x中\r\n" + cjk),
		}},
		{"at the last column, which wraps it", contCase{
			prefix: []byte("abcdefghi中\r\nabcdefghi\x1b[m"),
			sizes:  []uio.SizeEvent{event(1, 0, 10, 4)},
			suffix: []byte("中x"),
		}},
		{"cut by a narrowing", contCase{
			prefix: []byte("abcdefgh中\r\n"),
			sizes:  []uio.SizeEvent{event(1, 0, 10, 4), event(2, 13, 9, 4)},
			suffix: []byte("\x1b[1;9Hz"),
		}},
		{"in two cells", contCase{
			prefix: []byte(split + "\r\n" + split),
			sizes:  []uio.SizeEvent{event(1, 0, 40, 2)},
			suffix: []byte("\r\n" + split),
		}},
		{"across the emulator's pieces", contCase{
			prefix: []byte(pad + "e\u0301 \U0001F468\u200d\U0001F469\r\n"),
			sizes:  []uio.SizeEvent{event(1, 0, 80, 24)},
			suffix: []byte("x"),
		}},
		{"across io's offers", func() contCase {
			// Each offer ends inside a cluster.
			c := contCase{sizes: []uio.SizeEvent{event(1, 0, 20, 4)}, suffix: []byte("x")}
			for _, part := range []string{"ab\U0001F468", "\u200d", "\U0001F469 e", "\u0301", "\u0308 cd\r\n"} {
				c.prefix = append(c.prefix, part...)
				c.offers = append(c.offers, len(c.prefix))
			}
			return c
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireContinues(t, tc.c, tc.c.run(time.Minute))
		})
	}
}

// A cut that leaves part of a cluster in the tail: the prefix ends with "e"
// and the suffix starts with its combining mark; the prefix ends inside a
// ZWJ sequence; the prefix ends before a VS16. In each, after the suffix, A
// and B hold the same single cluster, in one cell. REP's character can't show
// it, as none of these is ASCII.
func TestReplayContinuesAcrossASplitCluster(t *testing.T) {
	for _, tc := range []struct{ name, prefix, suffix, cluster string }{
		{"a combining mark", "text\r\ne", "\u0301 more", "e\u0301"},
		{"inside a ZWJ sequence", "text\r\n\U0001F468\u200d", "\U0001F469 more", "\U0001F468\u200d\U0001F469"},
		{"before a VS16", "text\r\n\u2764", "\ufe0f more", "\u2764\ufe0f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := contCase{prefix: []byte(tc.prefix), sizes: []uio.SizeEvent{event(1, 0, 20, 4)}, suffix: []byte(tc.suffix)}
			r := c.run(time.Minute)
			requireContinues(t, c, r)
			require.Equal(t, tc.cluster, cellAt(r.a, 0, 1).Content)
			require.Equal(t, tc.cluster, cellAt(r.b, 0, 1).Content)
		})
	}
}

// A screen title string the stream sends, which a session's terminal that is
// GNU screen or tmux consumes, continues alike, wherever io's offers split
// it, its ESC and its k apart included: the replay, under tmux's TERM,
// reads it as the terminals do (see screenTitlesRead). The first case is
// shaped as one the fuzzer found, a title an ESC 0 ends, ended here by ST; the
// fuzzer's own, whose ESC that ends the title then makes an ESC 0, fails the
// render as an ESC it doesn't know.
func TestReplayContinuesAfterAScreenTitleString(t *testing.T) {
	for _, c := range []contCase{
		{prefix: []byte("000\x1bk0000000000\x1b\\"), suffix: []byte("00000"), offers: []int{5, 17}},
		{prefix: []byte("text\r\n\x1b"), suffix: []byte("kzsh\x1b\\$ ls\r\n")},
		{prefix: []byte("text\r\n\x1bkzsh\x1b\\$ ls\r\n"), suffix: []byte("\x1bkls\x1b\\file\r\n"), offers: []int{7, 8, 19}},
	} {
		c.sizes = []uio.SizeEvent{event(1, 0, 80, 24)}
		requireContinues(t, c, c.run(time.Minute))
	}
	c := contCase{prefix: []byte("000\x1bk0000000000\x1b0"), suffix: []byte("00000"), offers: []int{5, 17}, sizes: []uio.SizeEvent{event(1, 0, 80, 24)}}
	r := c.run(time.Minute)
	require.Empty(t, r.failure())
	require.Equal(t, "ineligible: an unhandled ESC 0", r.skip)
}

// A set of a mode a terminal starts with set (see defaultModes), or of ANSI's
// SRM, leaves the render with nothing to send, so the joiner's terminal keeps
// the mode as it starts and continues as the session's does. A reset of one
// fails the render, which the comparison can't see for itself, as it never
// gets one to compare.
func TestReplayContinuesAfterADefaultModeSet(t *testing.T) {
	run := func(seq string) (contCase, contRun) {
		c := contCase{
			prefix: []byte("text\r\n" + seq),
			sizes:  []uio.SizeEvent{event(1, 0, 20, 4)},
			suffix: []byte("more"),
		}
		return c, c.run(time.Minute)
	}
	for _, mode := range []string{"2", "1046", "1070"} {
		t.Run("?"+mode+" set", func(t *testing.T) {
			c, r := run("\x1b[?" + mode + "h")
			requireContinues(t, c, r)
		})
	}
	t.Run("?2 reset", func(t *testing.T) {
		_, r := run("\x1b[?2l")
		require.Equal(t, "ineligible: a default mode reset (?2)", r.skip)
	})
	for _, tc := range []struct{ name, seq string }{
		{"SRM set", "\x1b[12h"},
		{"SRM reset, then set", "\x1b[12l\x1b[12h"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, r := run(tc.seq)
			requireContinues(t, c, r)
		})
	}
	t.Run("SRM reset", func(t *testing.T) {
		_, r := run("\x1b[12l")
		require.Equal(t, "ineligible: a default mode reset (12)", r.skip)
	})
}

// Claude Code's output: truecolor runs, some of them linked, in history and
// on the screen, and a truecolor pen and an OSC 8 link still open where the
// replay hands off. The joiner's next text is coloured and linked as the
// session's is, whether the open link is in the render or in the tail.
func TestReplayKeepsStylesAndLinks(t *testing.T) {
	setBudget(t, 64<<20)
	var s strings.Builder
	for i := range 8 {
		fmt.Fprintf(&s, "\x1b[38;2;%d;100;0mrun %d \x1b[48;2;0;0;%dmon blue\x1b[m and \x1b]8;id=%d;https://example.com/%d\x07a link\x1b]8;;\x07\r\n",
			30*i, i, 30*i, i, i)
	}
	const open = "\x1b[38;2;1;2;3m\x1b]8;id=7;https://example.com/a\x07"
	for _, tc := range []struct{ name, tail string }{
		{"open in the render", ""},
		{"open, with linked text in the tail", "linked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := contCase{
				prefix: []byte(s.String() + "the cut: " + open + tc.tail),
				sizes:  []uio.SizeEvent{event(1, 0, 40, 4)},
				suffix: []byte("text"),
			}
			r := c.run(time.Minute)
			requireContinues(t, c, r)
			require.NotEmpty(t, r.aOff.lines, "nothing scrolled into history")
			x := len("the cut: ") + len(tc.tail)
			for _, term := range []*vt.Emulator{r.a, r.b} {
				cell := cellAt(term, x, term.CursorPosition().Y)
				require.Equal(t, "t", cell.Content)
				require.Equal(t, color.RGBA{R: 1, G: 2, B: 3, A: 0xff}, cell.Style.Fg)
				require.Equal(t, uv.Link{URL: "https://example.com/a", Params: "id=7"}, cell.Link)
			}
		})
	}
}

// An ink-style live region, as Claude Code repaints it, at 200 columns, then
// 45, then 200 again, each resize followed by Claude's repaint of the whole
// transcript, which clears the screen and the history first: each fact
// appears once across the joiner's history and screen, before the next
// bytes and after them.
func TestReplayKeepsEachFactOnceAcrossResizes(t *testing.T) {
	setBudget(t, 64<<20)
	fact := func(i int) string {
		return fmt.Sprintf("\x1b[38;2;200;200;200m●\x1b[m fact %02d %s\r\n", i, strings.Repeat("lorem ipsum ", 5))
	}
	live := func(n int) string { return fmt.Sprintf("\x1b[38;2;255;120;0m✳\x1b[m Thinking %d…\r\n> ", n) }
	const erase = "\x1b[2K\x1b[1A\x1b[2K\x1b[G"
	const repaint = "\x1b[2J\x1b[3J\x1b[H"
	var s strings.Builder
	sizes := []uio.SizeEvent{event(1, 0, 200, 10)}
	resize := func(cols int) {
		sizes = append(sizes, event(uint64(len(sizes)+1), s.Len(), cols, 10))
	}
	n, facts := 0, 0
	transcript := func() {
		s.WriteString(repaint)
		for i := range facts {
			s.WriteString(fact(i))
		}
		s.WriteString(live(n))
	}
	commit := func() {
		n++
		s.WriteString(erase + fact(facts) + live(n))
		facts++
	}
	s.WriteString(live(n))
	for range 6 {
		commit()
	}
	for range 3 {
		n++
		s.WriteString(erase + live(n))
	}
	resize(45)
	transcript()
	commit()
	commit()
	resize(200)
	transcript()
	commit()

	c := contCase{prefix: []byte(s.String()), sizes: sizes, suffix: []byte(erase + fact(facts) + live(n+1))}
	r := c.run(time.Minute)
	requireContinues(t, c, r)
	held := strings.Join(heldLines(r.b, r.bOff), "\n")
	for i := range facts + 1 {
		require.Equal(t, 1, strings.Count(held, fmt.Sprintf("fact %02d", i)), "fact %02d in %s", i, held)
	}
}

// A colour the render can only write as RGB, as a transparent one (SGR 38;1),
// is the same colour to the joiner, and a history line in it, which the
// joiner draws and scrolls off again, holds the same cells as the session's,
// though the joiner's own encoding of it takes another path to the palette
// black next to it.
func TestReplayHistoryKeepsColoursTheRenderWritesAsRGB(t *testing.T) {
	setBudget(t, 64<<20)
	c := contCase{
		prefix: []byte("\n\x1b[38;5;m8A\x1b[H\x1b[38;1m\nk\x1b[M"),
		sizes:  []uio.SizeEvent{event(1, 0, 26, 16), event(2, 22, 25, 1)},
	}
	requireContinues(t, c, c.run(time.Minute))
}

// A scroll inside left and right margins can move half of a wide character
// across a margin: its placeholder up a row on its own, or a blank over its
// placeholder. No print draws either, as printing the character brings its
// placeholder, so the render can't rebuild that row, and the join falls back,
// on either screen, rather than continue from a different one.
//
// The same holds for a line of history the render sends. In the last case,
// x/vt wraps the emoji to column 0, outside the left margin, and the scroll
// inside the margins takes its placeholder up a row and brings text in after
// it; DECSTR then resets the margins, and the row scrolls off, so neither
// screen holds a split. The history line takes a column more than the
// screen's 7, so a joiner's terminal would wrap it in two, where the
// session's kept one line.
func TestReplayFailsOnAWideCharacterSplitInTwo(t *testing.T) {
	setBudget(t, 64<<20)
	const split = "\x1b[?69h\x1b[2s\x1b[64H中\nh\x1b[?69l"
	for _, tc := range []struct {
		name string
		c    contCase
	}{
		{"its placeholder moved up a row", contCase{
			prefix: []byte(split),
			sizes:  []uio.SizeEvent{event(1, 0, 72, 29)},
		}},
		{"a blank over its placeholder", contCase{
			prefix: []byte("中\x1b[?69h\x1b[2s\x1b[B\xe4\n \x1b[?69l"),
			sizes:  []uio.SizeEvent{event(1, 0, 81, 2)},
		}},
		{"on the alternate screen", contCase{
			prefix: []byte("main\r\n\x1b[?1049h" + split),
			sizes:  []uio.SizeEvent{event(1, 0, 72, 29)},
		}},
		{"on the hidden alternate screen", contCase{
			prefix: []byte("main\r\n\x1b[?47h" + split + "\x1b[?47l"),
			sizes:  []uio.SizeEvent{event(1, 0, 72, 29)},
		}},
		{"in a line of history the render sends", contCase{
			prefix: []byte("\x1b[7d#mf``tn\x1b[?69h\x1b[2s\x1b[9G😀\x1b[56HO(b+Mv ;uzP y|]W[?7h%<sH -nn*\n\x1b[!p\x1b[15b"),
			sizes:  []uio.SizeEvent{event(1, 0, 40, 34), event(2, 0, 7, 19)},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.c.run(time.Minute)
			require.Empty(t, r.failure(), "%s", tc.c.repro())
			require.Equal(t, "ineligible: a wide character split in two", r.skip)
		})
	}
}
