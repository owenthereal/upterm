package replay

import (
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/x/ansi"
	"github.com/owenthereal/x/ansi/parser"
	"github.com/owenthereal/x/vt"
	"github.com/stretchr/testify/require"

	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
)

// csiKeys are every key x/ansi's parser can dispatch a CSI by: no prefix or
// one of 0x3C to 0x3F, no intermediate or the last of 0x20 to 0x2F, and a
// final byte from 0x40 to 0x7E.
func csiKeys() []int {
	var keys []int
	for _, p := range []byte{0, '<', '=', '>', '?'} {
		for _, i := range intermediates() {
			for f := byte(0x40); f <= 0x7e; f++ {
				keys = append(keys, ansi.Command(p, i, f))
			}
		}
	}
	return keys
}

// escKeys are every key x/ansi's parser can dispatch an ESC by: a final from
// 0x30 to 0x7E after any intermediate, or with none, a final that doesn't
// begin a string or a CSI.
func escKeys() []int {
	var keys []int
	for _, i := range intermediates() {
		for f := byte(0x30); f <= 0x7e; f++ {
			if i == 0 && strings.IndexByte("P[]X^_", f) >= 0 {
				continue
			}
			keys = append(keys, ansi.Command(0, i, f))
		}
	}
	return keys
}

// intermediates are none and every intermediate byte.
func intermediates() []byte {
	b := []byte{0}
	for i := byte(0x20); i <= 0x2f; i++ {
		b = append(b, i)
	}
	return b
}

// csiOf is a CSI of key, with params, introduced by intro, ESC [ or the C1
// CSI.
func csiOf(intro string, key int, params string) string {
	c := ansi.Cmd(key)
	s := intro
	if p := c.Prefix(); p != 0 {
		s += string(rune(p))
	}
	s += params
	if i := c.Intermediate(); i != 0 {
		s += string(rune(i))
	}
	return s + string(rune(c.Final()))
}

// escOf is an ESC of key.
func escOf(key int) string {
	c := ansi.Cmd(key)
	if i := c.Intermediate(); i != 0 {
		return "\x1b" + string(rune(i)) + string(rune(c.Final()))
	}
	return "\x1b" + string(rune(c.Final()))
}

// unhandledLog records what x/vt logged of the sequences none of its handlers
// took.
type unhandledLog struct{ lines []loggedLine }

type loggedLine struct {
	format string
	args   []any
}

func (l *unhandledLog) Printf(format string, v ...any) {
	if strings.HasPrefix(format, unhandled) {
		l.lines = append(l.lines, loggedLine{format, v})
	}
}

// logging is a terminal of x/vt's own, or with the replay's handlers too,
// whose unhandled sequences log records.
func logging(t *testing.T, replays bool) (*vt.Emulator, *unhandledLog) {
	t.Helper()
	l := &unhandledLog{}
	if replays {
		e := startFor(t, captureOf("", event(1, 0, 8, 2)), termsize.Size{Cols: 8, Rows: 2})
		e.term.SetLogger(l)
		return e.term, l
	}
	term := vt.NewEmulator(8, 2)
	term.SetReplyFunc(func([]byte) {})
	term.SetLogger(l)
	return term, l
}

// A sequence the render doesn't rebuild fails the join, named by its key, as
// x/vt keys its handlers: one x/vt has no handler for, and a form x/vt's
// handler drops where a terminal acts on it, kitty's ED 22. The name holds
// the sequence's key alone, never its data, and the first such sequence names
// it, whatever follows, RIS included. Every kind counts: a CSI by its 7-bit or
// its 8-bit introducer, an ESC, an OSC, and a C1 control x/vt has no handler
// for, named by its byte alone.
func TestReplayFailsOnASequenceItDoesntKnow(t *testing.T) {
	join := func(t *testing.T, stream string) error {
		t.Helper()
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		return fellBack
	}
	for _, tc := range []struct{ name, stream, state string }{
		{"NEL, which x/vt drops", "\x1bE", "an unhandled ESC E"},
		{"DECALN", "\x1b#8", "an unhandled ESC # 8"},
		{"DECBI", "\x1b6", "an unhandled ESC 6"},
		{"an ANSI conformance level", "\x1b L", "an unhandled ESC SP L"},
		{"a multibyte set", "\x1b$B", "an unhandled ESC $ B"},
		{"DECIC", "\x1b[2'}", "an unhandled CSI Ps ' }"},
		{"DECIC by the 8-bit CSI", "\x9b2'}", "an unhandled CSI Ps ' }"},
		{"SL", "\x1b[1 @", "an unhandled CSI Ps SP @"},
		{"DECCARA", "\x1b[1;1;2;5;1$r", "an unhandled CSI Ps $ r"},
		{"XTSMPOINTER", "\x1b[>1p", "an unhandled CSI > Ps p"},
		{"kitty's ED 22, which x/vt drops", "\x1b[22J", "an unhandled CSI Ps J"},
		{"kitty's colours", "\x1b]21;foreground=red\x1b\\", "an unhandled OSC 21"},
		{"an OSC 777 of urxvt's", "\x1b]777;preexec\x07", "an unhandled OSC 777"},
		{"its data left out of the name", "\x1b]777;secret=hunter2\x07", "an unhandled OSC 777"},
		{"a status of Claude Code's", "\x1b]7501;state=working\x07", "an unhandled OSC 7501"},
		{"NEL by its C1 control", "\x85", "an unhandled C1 control 0x85"},
		{"SSA", "\x86", "an unhandled C1 control 0x86"},
		{"SPA", "\x96", "an unhandled C1 control 0x96"},
		{"the bytes around a C1 control left out of the name", "hunter2\x85hunter2", "an unhandled C1 control 0x85"},
		{"one, then RIS", "\x1bE\x1bc", "an unhandled ESC E"},
		{"the first of two", "\x1b#8\x1bE", "an unhandled ESC # 8"},
		{"a C1 control, the first of two", "\x85\x1b#8", "an unhandled C1 control 0x85"},
		{"a C1 control, the second of two", "\x1b#8\x85", "an unhandled ESC # 8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireIneligible(t, join(t, tc.stream), tc.state)
		})
	}
	t.Run("in a ring that starts inside it", func(t *testing.T) {
		stream := strings.Repeat("x", 5000) + "\x1b]777;" + strings.Repeat("y", 100) + "\x07more"
		_, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 64)
		requireIneligible(t, fellBack, "an unhandled OSC 777")
	})
	t.Run("fed after Start", func(t *testing.T) {
		prefix := "text\r\n\x1b#8more"
		c := contCase{prefix: []byte(prefix), sizes: []uio.SizeEvent{event(1, 0, 80, 24)}, offers: []int{6, len(prefix)}}
		r := c.run(time.Minute)
		require.Empty(t, r.failure())
		require.Equal(t, "ineligible: an unhandled ESC # 8", r.skip)
	})
	t.Run("one the ring no longer holds", func(t *testing.T) {
		stream := "\x1bE" + strings.Repeat("text\r\n", 2000)
		_, fellBack := fanOut(t, New(), []byte(stream), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		require.NoError(t, fellBack)
	})
}

// The sequences the tables allow render, one of each kind, under any TERM and
// under tmux's, as in a session hosted inside tmux: the forms of its own keys
// x/vt drops, as the terminals named in xvtCSI do; those a handler here keeps
// or decides, in a form it doesn't note; kitty's keyboard stack, which the
// tracker keeps; restores whose save the ring doesn't hold; and those that
// leave nothing, vim's probe as vim sends it as it starts among them, and
// Claude Code's, the Linux console's cursor shape as its terminfo entry's
// cnorm sends it, the visual bell tmux's and screen's entries send, and the
// prompt marks and notifications shells and programs send. So do the controls
// x/vt follows or that leave nothing: the C1 controls x/vt handles; the 8-bit
// ST, ending an OSC or alone; a character whose UTF-8 holds a byte of the C1
// range; and C0 controls x/vt has no handler for, as xterm ignores them.
func TestReplayRendersTheSequencesItAllows(t *testing.T) {
	for _, tc := range []struct{ name, stream string }{
		{"EL 3", "\x1b[3K"},
		{"TBC 1", "\x1b[1g"},
		{"DECST8C 1", "\x1b[?1W"},
		{"DA1 1", "\x1b[1c"},
		{"DA2 1", "\x1b[>1c"},
		{"DSR 0", "\x1b[0n"},
		{"DECSTBM, its top below its bottom", "\x1b[5;2r"},
		{"DECSLRM, its left margin right of its right", "\x1b[?69h\x1b[5;2s\x1b[?69l"},
		{"SCORC with a parameter", "\x1b[1u"},
		{"DECSWBV", "\x1b[3 t"},
		{"DECSCA 0", "\x1b[0\"q"},
		{"XTSMTITLE with none", "\x1b[>t"},
		{"XTWINOPS 7, a refresh", "\x1b[7t"},
		{"DECSSDT 1", "\x1b[1$~"},
		{"DECSACE 1", "\x1b[1*x"},
		{"DECSCPP 100", "\x1b[100$|"},
		{"MC 0", "\x1b[i"},
		{"modifyOtherKeys", "\x1b[>4;1m"},
		{"XTMODKEYS's disable of modifyOtherKeys", "\x1b[>4n"},
		{"DECELR 0", "\x1b[0'z"},
		{"kitty's extra cursors' query", "\x1b[>0 q"},
		{"kitty's keyboard pushed", "\x1b[>1u"},
		{"kitty's keyboard popped", "\x1b[<u"},
		{"kitty's keyboard set", "\x1b[=1;1u"},
		{"XTRESTORE", "\x1b[?1049r"},
		{"XTPOPSGR", "\x1b[#}"},
		{"XTPOPCOLORS", "\x1b[#Q"},
		{"DA3 1", "\x1b[=1c"},
		{"DECRQTSR", "\x1b[1$u"},
		{"DECEFR", "\x1b[1;1;2;2'w"},
		{"vim's probe", "\x1bPzz\x1b\\\x1b[0%m"},
		{"DECPS", "\x1b[1;1;1,~"},
		{"the Linux console's cnorm", "\x1b[?25h\x1b[?0c"},
		{"XTRMTITLE", "\x1b[>T"},
		{"ST alone", "\x1b\\"},
		{"UTF-8 selected", "\x1b%G"},
		{"the Linux console's UTF-8 selected", "\x1b%8"},
		{"DECSWL", "\x1b#5"},
		{"S7C1T", "\x1b F"},
		{"the visual bell of tmux's and screen's TERMs", "\x1bg"},
		{"a prompt mark", "\x1b]133;A\x07"},
		{"VS Code's prompt mark and directory", "\x1b]633;A\x07\x1b]633;P;Cwd=/tmp\x07"},
		{"systemd's context marker", "\x1b]3008;start=1;user=u\x1b\\"},
		{"Fig's shell integration", "\x1b]697;StartPrompt\x07\x1b]697;EndPrompt\x07\x1b]697;Dir=/tmp\x07"},
		{"a notification by OSC 777", "\x1b]777;notify;title;body\x07"},
		{"a notification of kitty's", "\x1b]99;;hello\x1b\\"},
		{"a notification of iTerm2's", "\x1b]9;hello\x07"},
		{"kitty's colours popped", "\x1b]30101\x1b\\"},
		{"Claude Code's probe of its status", "\x1b]7501;?\x07"},
		{"Claude Code's probe of its status, ended by ST", "\x1b]7501;?\x1b\\"},
		{"IND by its C1 control", "\x84"},
		{"HTS by its C1 control", "\x88"},
		{"RI by its C1 control", "\x8d"},
		{"SS2 by its C1 control", "\x8e"},
		{"SS3 by its C1 control", "\x8f"},
		{"a prompt mark ended by the 8-bit ST", "\x1b]133;A\x9c"},
		{"the 8-bit ST alone", "\x9c"},
		{"Ņ, whose UTF-8 holds 0x85", "\xc5\x85"},
		{"SOH", "\x01"},
		{"ENQ", "\x05"},
		{"FS", "\x1c"},
		{"DEL", "\x7f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, term := range []string{"", "tmux-256color"} {
				_, fellBack := fanOut(t, NewForTerm(term), []byte("text\r\n"+tc.stream+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
				require.NoError(t, fellBack, "TERM %q", term)
			}
		})
	}
}

// csiForms are the parameters the round trip writes each CSI key with: none,
// one of several values, two, a sub-parameter, two left out, and a control
// inside them, which the parser runs where it is and reads past.
var csiForms = []string{"", "0", "1", "5", "6", "1;1", "1;2", "1:2", ";", "1\x0b2"}

// droppedForms are, for each of x/vt's own CSI keys whose handler drops some
// of csiForms, those it drops, in csiForms' order, on the round trip's
// terminal, of 8x2: x/vt logs each, and takes the rest. DECSTBM drops more of
// them there than on a taller terminal. CSI s drops a form only while DECLRMM
// is set, which none of these sets, and has a case of its own.
var droppedForms = map[int][]string{
	// ED but 0 to 3, and EL but 0 to 2: the form with a control inside it
	// reads as 12.
	ansi.Command(0, 0, 'J'): {"5", "6", "1\x0b2"},
	ansi.Command(0, 0, 'K'): {"5", "6", "1\x0b2"},
	// DECST8C but 5 alone.
	ansi.Command('?', 0, 'W'): {"", "0", "1", "6", "1;1", "1;2", "1:2", ";", "1\x0b2"},
	// TBC but 0 and 3.
	ansi.Command(0, 0, 'g'): {"1", "5", "6", "1;1", "1;2", "1:2", "1\x0b2"},
	// DA1 and DA2 but 0.
	ansi.Command(0, 0, 'c'):   {"1", "5", "6", "1;1", "1;2", "1:2", "1\x0b2"},
	ansi.Command('>', 0, 'c'): {"1", "5", "6", "1;1", "1;2", "1:2", "1\x0b2"},
	// DSR but 5 and 6, and DECXCPR but 6.
	ansi.Command(0, 0, 'n'):   {"", "0", "1", "1;1", "1;2", "1:2", ";", "1\x0b2"},
	ansi.Command('?', 0, 'n'): {"", "0", "1", "5", "1;1", "1;2", "1:2", ";", "1\x0b2"},
	// DECSTBM whose top isn't above its bottom.
	ansi.Command(0, 0, 'r'): {"5", "6", "1;1", "1\x0b2"},
	// SCORC with a parameter.
	ansi.Command(0, 0, 'u'): {"0", "1", "5", "6", "1;1", "1;2", "1:2", ";", "1\x0b2"},
}

// Each key of the tables, given to the emulation, is decided as its row says:
// "" renders, by the check, which leaves whatever else a handler decides to
// the handler; a name fails the render by that name. A join whose stream
// holds a row with "", through the fan-out, its query filter and all,
// renders too, but for the rows a handler here fails it on, deciding them by
// the parameters or data written here, which are listed with why. The forms
// x/vt's own handlers drop are decided as xvtCSI says, and every designation
// of a character set x/vt drops by the name escVerdict gives it.
func TestDispatchCheckFollowsTheTables(t *testing.T) {
	// verdictOnly names the rows with "" that a join holding them, as written
	// here, falls back on, each with why.
	const (
		noEntry  = "x names no entry of the colour table, so all of it counts as set"
		setsOne  = "x sets the colour"
		resetsOn = "a reset with data after its number counts as a setting"
	)
	verdictOnly := map[string]string{
		"CSI Ps $ |": "DECSCPP with none resizes the window to 80 columns",
		"CSI > Ps n": "XTMODKEYS's disable with none disables modifyFunctionKeys",
		"ESC l":      "HP's memory lock below the region's top locks the rows above",
		"ESC SP G":   "S8C1T selects 8-bit controls",
		"OSC 50":     "x names a font",
		// The colours (see watchColours).
		"OSC 4": noEntry, "OSC 5": noEntry, "OSC 104": noEntry, "OSC 105": noEntry,
		"OSC 13": setsOne, "OSC 14": setsOne, "OSC 15": setsOne, "OSC 16": setsOne,
		"OSC 17": setsOne, "OSC 18": setsOne, "OSC 19": setsOne,
		"OSC 113": resetsOn, "OSC 114": resetsOn, "OSC 115": resetsOn, "OSC 116": resetsOn,
		"OSC 117": resetsOn, "OSC 118": resetsOn, "OSC 119": resetsOn,
	}
	check := func(t *testing.T, seq, want string) {
		t.Helper()
		e := startFor(t, captureOf("text\r\n"+seq+"more", event(1, 0, 80, 24)), termsize.Size{Cols: 80, Rows: 24})
		require.Equal(t, want, e.unhandled, "%q", seq)
		if want != "" {
			_, err := e.Render()
			requireIneligible(t, err, want)
		}
	}
	// row checks a row of the tables, named name, by seq: its verdict, and
	// with "", a join, which renders, unless verdictOnly names it.
	row := func(t *testing.T, name, seq, want string) {
		t.Helper()
		check(t, seq, want)
		if _, only := verdictOnly[name]; want != "" || only {
			return
		}
		_, fellBack := fanOut(t, New(), []byte("text\r\n"+seq+"more\r\n"), []uio.SizeEvent{event(1, 0, 80, 24)}, 4<<10)
		require.NoError(t, fellBack, "%s: %q", name, seq)
	}
	for key, want := range csiRules {
		row(t, csiName(key), csiOf("\x1b[", key, ""), want)
	}
	// dropped is what a form x/vt drops of its own key fails the render by,
	// as xvtCSI says.
	dropped := func(key int) string {
		if xvtCSI[key] {
			return ""
		}
		return "an unhandled " + csiName(key)
	}
	for key, forms := range droppedForms {
		for _, params := range forms {
			check(t, csiOf("\x1b[", key, params), dropped(key))
		}
	}
	// DECSLRM's, a left margin not left of the right, which x/vt drops only
	// while DECLRMM makes CSI s one: DECLRMM is reset after it, so the check,
	// not the margins' mode, decides the render.
	check(t, "\x1b[?69h\x1b[5;2s\x1b[?69l", dropped(ansi.Command(0, 0, 's')))
	for key, want := range escRules {
		row(t, escName(key), escOf(key), want)
	}
	for _, key := range escKeys() {
		if _, own := xvtESC[key]; own {
			continue
		}
		switch ansi.Cmd(key).Intermediate() {
		case '(', ')', '*', '+':
			check(t, escOf(key), charset94State)
		case '-', '.', '/':
			check(t, escOf(key), charset96State)
		}
	}
	for n, want := range oscRules {
		seq := fmt.Sprintf("\x1b]%d;x\x07", n)
		if n == parser.MissingCommand {
			seq = "\x1b]x\x07"
		}
		row(t, fmt.Sprintf("OSC %d", n), seq, want)
	}
	check(t, "\x1b]777;notify;title;body\x07", "")
	check(t, "\x1b]777;notify\x07", "an unhandled OSC 777")
	check(t, "\x1b]7501;?\x07", "")
	check(t, "\x1b]7501;?;state=working\x07", "an unhandled OSC 7501")
}

// Every key of the CSIs, ESCs and OSCs no table holds fails the render, named
// by its key, as x/vt dispatches it.
func TestDispatchCheckFailsOnEveryOtherKey(t *testing.T) {
	term, _ := logging(t, false)
	e := &emulation{}
	term.SetLogger(dispatchCheck{e})
	feed := func(seq, want string) {
		t.Helper()
		e.unhandled = ""
		_, _ = term.Write([]byte(seq))
		require.Equal(t, want, e.unhandled, "%q", seq)
	}
	for _, key := range csiKeys() {
		if _, ok := csiRules[key]; ok {
			continue
		}
		if _, own := xvtCSI[key]; own {
			continue
		}
		feed(csiOf("\x1b[", key, "1"), "an unhandled "+csiName(key))
	}
	for _, key := range escKeys() {
		if _, ok := escRules[key]; ok {
			continue
		}
		if _, own := xvtESC[key]; own {
			continue
		}
		switch ansi.Cmd(key).Intermediate() {
		case '(', ')', '*', '+', '-', '.', '/':
			continue
		}
		feed(escOf(key), "an unhandled "+escName(key))
	}
	for n := range 10000 {
		if _, ok := oscRules[n]; ok || n == 777 {
			continue
		}
		if _, own := xvtOSC[n]; own {
			continue
		}
		feed(fmt.Sprintf("\x1b]%d;x\x07", n), fmt.Sprintf("an unhandled OSC %d", n))
	}
}

// xvtControls are the controls x/vt's own handlers take: NUL, BEL, BS, HT,
// LF, VT, FF, CR, SO and SI, and of C1, IND, HTS, RI, SS2 and SS3.
var xvtControls = []byte{
	ansi.NUL, ansi.BEL, ansi.BS, ansi.HT, ansi.LF, ansi.VT, ansi.FF, ansi.CR, ansi.SO, ansi.SI,
	ansi.IND, ansi.HTS, ansi.RI, ansi.SS2, ansi.SS3,
}

// introducers are the controls x/ansi's parser starts a sequence on rather
// than executing: ESC, and of C1, DCS, SOS, CSI, OSC, PM and APC.
var introducers = []byte{ansi.ESC, ansi.DCS, ansi.SOS, ansi.CSI, ansi.OSC, ansi.PM, ansi.APC}

// What the check reads of each sequence x/vt logs is the key x/vt dispatched
// it by, and x/vt is silent on exactly its own keys, for the forms its
// handlers take, with the replay's handlers as without them, which all return
// false: so the tables' x/vt keys are x/vt's, and every other dispatch reaches
// the check. Each CSI goes in each of csiForms, by both introducers: every
// form of a key not x/vt's logs, and of x/vt's own keys, exactly the forms
// droppedForms holds, so a form x/vt starts or stops dropping shows here
// rather than being decided unseen as xvtCSI says. Each OSC goes by its
// number as the parser reads it: with leading zeros, a control the OSC state
// ignores inside it, past an int's range, where it wraps, as large as
// parser.MissingCommand, which the parser reads as no number, or with none.
// Each control of C0 and C1, and DEL, goes alone: x/vt is silent on exactly
// xvtControls and the introducers, and logs every other by its byte, which
// the check reads, so a control handler x/vt adds, or drops, shows.
func TestDispatchCheckReadsTheKeyXVTDispatched(t *testing.T) {
	for _, replays := range []bool{false, true} {
		t.Run(fmt.Sprintf("replay's handlers %v", replays), func(t *testing.T) {
			term, l := logging(t, replays)
			write := func(seq string) []loggedLine {
				l.lines = nil
				_, _ = term.Write([]byte(seq + "\r"))
				return l.lines
			}
			for _, key := range csiKeys() {
				want := csiForms
				if _, own := xvtCSI[key]; own {
					want = droppedForms[key]
				}
				for _, intro := range []string{"\x1b[", "\x9b"} {
					var logged []string
					for _, form := range csiForms {
						lines := write(csiOf(intro, key, form))
						if len(lines) == 0 {
							continue
						}
						logged = append(logged, form)
						require.Len(t, lines, 1)
						require.Equal(t, unhandledCSI, lines[0].format)
						s, _ := lines[0].args[0].(string)
						got, ok := csiKey(s)
						require.True(t, ok, "%q", s)
						require.Equal(t, csiName(key), csiName(got), "%q", s)
					}
					require.Equal(t, want, logged, "%s by %q", csiName(key), intro)
				}
			}
			for _, key := range escKeys() {
				lines := write(escOf(key))
				_, own := xvtESC[key]
				if own {
					require.Empty(t, lines, "%s", escName(key))
					continue
				}
				require.Len(t, lines, 1, "%s", escName(key))
				require.Equal(t, unhandledESC, lines[0].format)
				s, _ := lines[0].args[0].(string)
				got, ok := escKey(s)
				require.True(t, ok, "%q", s)
				require.Equal(t, escName(key), escName(got))
			}
			for n := range 10000 {
				lines := write(fmt.Sprintf("\x1b]%d;x\x07", n))
				_, own := xvtOSC[n]
				if own {
					require.Empty(t, lines, "OSC %d", n)
					continue
				}
				require.Len(t, lines, 1, "OSC %d", n)
				require.Equal(t, unhandledOSC, lines[0].format)
				data, _ := lines[0].args[0].([]byte)
				require.Equal(t, n, oscNumber(data))
			}
			for c := range byte(0xa0) {
				if c >= 0x20 && c < 0x7f {
					continue
				}
				// On a terminal of its own, as the sequence an introducer
				// starts doesn't end.
				term, l := logging(t, replays)
				_, _ = term.Write([]byte{c})
				if slices.Contains(xvtControls, c) || slices.Contains(introducers, c) {
					require.Empty(t, l.lines, "0x%02X", c)
					continue
				}
				require.Len(t, l.lines, 1, "0x%02X", c)
				require.Equal(t, unhandledControl, l.lines[0].format)
				require.Equal(t, []any{c}, l.lines[0].args)
				want := ""
				if c >= 0x80 && c != ansi.ST {
					want = fmt.Sprintf("an unhandled C1 control 0x%02X", c)
				}
				require.Equal(t, want, unhandledName(l.lines[0].format, l.lines[0].args), "0x%02X", c)
			}
		})
	}
	t.Run("an OSC's number as the parser reads it", func(t *testing.T) {
		// wrapped is n, written in decimal, as an int that wraps.
		wrapped := func(n string) int {
			v, _ := new(big.Int).SetString(n, 10)
			return int(new(big.Int).Mod(v, new(big.Int).Lsh(big.NewInt(1), 64)).Uint64())
		}
		for _, tc := range []struct {
			name, seq string
			n         int
		}{
			{"leading zeros", "\x1b]0021;x\x07", 21},
			{"a control inside it", "\x1b]2\x011;x\x07", 21},
			{"no ';' after it", "\x1b]21\x07", 21},
			{"by the 8-bit OSC, ended by the 8-bit ST", "\x9d21;x\x9c", 21},
			{"past an int's range", "\x1b]18446744073709551637;x\x07", wrapped("18446744073709551637")},
			{"to a negative int", "\x1b]9223372036854775808;x\x07", wrapped("9223372036854775808")},
			{"as large as no number", fmt.Sprintf("\x1b]%d;x\x07", parser.MissingCommand), parser.MissingCommand},
			{"none", "\x1b];x\x07", parser.MissingCommand},
			{"none at all", "\x1b]\x07", parser.MissingCommand},
		} {
			t.Run(tc.name, func(t *testing.T) {
				term, l := logging(t, false)
				hit := false
				term.RegisterOscHandler(tc.n, func([]byte) bool {
					hit = true
					return false
				})
				_, _ = term.Write([]byte(tc.seq))
				require.True(t, hit, "x/vt dispatched it by %d", tc.n)
				require.Len(t, l.lines, 1)
				data, _ := l.lines[0].args[0].([]byte)
				require.Equal(t, tc.n, oscNumber(data))
			})
		}
	})
}

// What x/vt logs that the check can't read fails the render, by the kind of
// sequence, as x/vt's logging has changed: a CSI or an ESC whose argument
// isn't one, an OSC whose data isn't bytes, a control whose argument isn't a
// byte of C0 or C1 or DEL, a kind it didn't log before. The kinds with rules
// of their own render, and so does a line that isn't a sequence's. A control
// read is decided as the check decides it: C1's, but for ST, fail, named by
// the byte, and C0's and DEL render. The first sequence noted names it.
func TestDispatchCheckFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, format string
		args         []any
		want         string
	}{
		{"a CSI with another final", unhandledCSI, []any{"1\x01"}, "an unhandled CSI"},
		{"a CSI with another byte", unhandledCSI, []any{"1.5m"}, "an unhandled CSI"},
		{"a CSI not a string", unhandledCSI, []any{42}, "an unhandled CSI"},
		{"a CSI with nothing", unhandledCSI, nil, "an unhandled CSI"},
		{"an empty CSI", unhandledCSI, []any{""}, "an unhandled CSI"},
		{"an ESC of two bytes", unhandledESC, []any{"#8"}, "an unhandled ESC"},
		{"an ESC with another final", unhandledESC, []any{"\x01"}, "an unhandled ESC"},
		{"an OSC not bytes", unhandledOSC, []any{"52;c;YQ=="}, "an unhandled OSC"},
		{"another kind", unhandled + "XYZ %q", []any{"x"}, "an unhandled sequence"},
		{"a DCS", unhandled + "DCS %q %q", []any{"q", []byte("x")}, ""},
		{"an APC", unhandled + "APC %q", []any{[]byte("x")}, ""},
		{"an SOS", unhandled + "SOS %q", []any{[]byte("x")}, ""},
		{"a PM", unhandled + "PM %q", []any{[]byte("x")}, ""},
		{"a C0 control", unhandledControl, []any{byte(ansi.ENQ)}, ""},
		{"DEL", unhandledControl, []any{byte(ansi.DEL)}, ""},
		{"a C1 control", unhandledControl, []any{byte(ansi.NEL)}, "an unhandled C1 control 0x85"},
		{"ST", unhandledControl, []any{byte(ansi.ST)}, ""},
		{"a control not a byte", unhandledControl, []any{"\x85"}, "an unhandled control"},
		{"a control as a rune", unhandledControl, []any{rune(ansi.NEL)}, "an unhandled control"},
		{"a control with nothing", unhandledControl, nil, "an unhandled control"},
		{"a control outside C0 and C1", unhandledControl, []any{byte('A')}, "an unhandled control"},
		{"a mode's change", "setting mode %T(%v) to %v", []any{ansi.DECMode(1), ansi.DECMode(1), ansi.ModeSet}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &emulation{}
			dispatchCheck{e}.Printf(tc.format, tc.args...)
			require.Equal(t, tc.want, e.unhandled)
		})
	}
	t.Run("the first names it", func(t *testing.T) {
		e := &emulation{}
		dispatchCheck{e}.Printf(unhandledESC, "E")
		dispatchCheck{e}.Printf(unhandledESC, "# 8")
		require.Equal(t, "an unhandled ESC E", e.unhandled)
	})
	t.Run("a name stays short", func(t *testing.T) {
		require.Equal(t, "an unhandled CSI ? Ps SP q", csiVerdict(ansi.Command('?', ' ', 'q')))
		require.Equal(t, "an unhandled OSC -9223372036854775808", oscVerdict(-1<<63, nil))
	})
}
