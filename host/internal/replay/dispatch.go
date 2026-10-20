package replay

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/owenthereal/x/ansi"
	"github.com/owenthereal/x/ansi/parser"
)

// The check of every CSI, ESC and OSC the emulator's parser dispatches, and
// every control it executes: one the render doesn't rebuild, and that may
// leave the session's terminal in a state the joiner's wouldn't share, fails
// the render, named, whatever it is, as a raw replay hands the joiner's
// terminal the sequence itself. Only what the tables below allow renders, and
// of the controls, what controlVerdict does.
//
// x/vt says, through its logger, which sequences none of its handlers took:
// for each CSI, ESC and OSC whose every handler returned false, and each
// control none took, its handle function logs the format below, once, from
// inside the parser's dispatch.
// So the check sees the sequences as x/vt's parser read them, the snapshot's
// and every batch's, with screen title strings already read for x/vt (see
// screenTitles), and nothing of the handoff point's lookahead, which runs a
// copy of the state machine that calls no handler. Every handler registered
// here returns false, so none hides a sequence from it.
//
// What x/vt's own handlers take, the check doesn't see. Those are its keys in
// xvtCSI, xvtESC and xvtOSC, and the controls controlVerdict names, each a
// sequence x/vt keeps the effect of in state the render rebuilds, or one that
// leaves nothing, and a test holds them to the keys and controls x/vt is
// silent on, so a handler x/vt adds, or drops, shows.
const (
	unhandled = "unhandled sequence: "
	// The CSI's parameters as x/vt writes them: its prefix, if any, each
	// parameter in decimal, -1 for one left out, joined by ';', or ':' before
	// a sub-parameter, then its intermediate, if any, and its final byte.
	unhandledCSI = unhandled + "CSI %q"
	// "I F" for an ESC with an intermediate, else "F".
	unhandledESC = unhandled + "ESC %q"
	// The OSC's data, all of it, its number first.
	unhandledOSC = unhandled + "OSC %q"
	// The control's byte, which x/vt logs for each control the parser
	// executes that none of its handlers took (see controlVerdict).
	unhandledControl = unhandled + "ControlCode %q"
)

// otherUnhandled are the other formats x/vt logs a sequence none of its
// handlers took by, which the check leaves alone: device control strings
// have rules of their own (see watchDCS), and so do APC, SOS and PM.
var otherUnhandled = []string{
	unhandled + "DCS %q %q",
	unhandled + "APC %q",
	unhandled + "SOS %q",
	unhandled + "PM %q",
}

// dispatchCheck is the emulator's logger, which notes the first sequence the
// tables don't allow (see emulation.unhandled). Every other line x/vt logs,
// such as a mode's change, it ignores.
type dispatchCheck struct{ e *emulation }

// watchDispatch installs the check (see dispatchCheck).
func (e *emulation) watchDispatch() { e.term.SetLogger(dispatchCheck{e}) }

func (d dispatchCheck) Printf(format string, v ...any) {
	if d.e.unhandled != "" || !strings.HasPrefix(format, unhandled) {
		return
	}
	d.e.unhandled = unhandledName(format, v)
}

// unhandledName is what a render fails by for the sequence x/vt logged by
// format, with v, or "" for one it renders. A sequence of the kinds checked
// that can't be read, or a kind x/vt didn't log before, fails it, named only
// by its kind: x/vt's logging changed, and the check can't tell what it was.
func unhandledName(format string, v []any) string {
	var arg any
	if len(v) > 0 {
		arg = v[0]
	}
	switch format {
	case unhandledCSI:
		s, _ := arg.(string)
		key, ok := csiKey(s)
		if !ok {
			return "an unhandled CSI"
		}
		return csiVerdict(key)
	case unhandledESC:
		s, _ := arg.(string)
		key, ok := escKey(s)
		if !ok {
			return "an unhandled ESC"
		}
		return escVerdict(key)
	case unhandledOSC:
		data, ok := arg.([]byte)
		if !ok {
			return "an unhandled OSC"
		}
		return oscVerdict(oscNumber(data), data)
	case unhandledControl:
		b, ok := arg.(byte)
		if !ok {
			return "an unhandled control"
		}
		return controlVerdict(b)
	}
	for _, f := range otherUnhandled {
		if format == f {
			return ""
		}
	}
	return "an unhandled sequence"
}

// csiKey reads the key x/vt keys a CSI's handlers by, ansi.Command's packing
// of its prefix, intermediate and final byte, from the CSI as x/vt logged it.
// The byte before the final is an intermediate when it is one, 0x20 to 0x2F,
// as a parameter ends in a digit: the '-' of an omitted one's -1 is never its
// last.
func csiKey(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	final := s[len(s)-1]
	body := s[:len(s)-1]
	var prefix, inter byte
	if len(body) > 0 && body[0] >= 0x3c && body[0] <= 0x3f {
		prefix, body = body[0], body[1:]
	}
	if n := len(body); n > 0 && body[n-1] >= 0x20 && body[n-1] <= 0x2f {
		inter, body = body[n-1], body[:n-1]
	}
	if final < 0x40 || final > 0x7e || strings.ContainsFunc(body, func(r rune) bool {
		return (r < '0' || r > '9') && r != '-' && r != ';' && r != ':'
	}) {
		return 0, false
	}
	return ansi.Command(prefix, inter, final), true
}

// escKey reads the key x/vt keys an ESC's handlers by, its last intermediate
// and its final byte, from the ESC as x/vt logged it.
func escKey(s string) (int, bool) {
	switch {
	case len(s) == 1 && s[0] >= 0x30 && s[0] <= 0x7e:
		return ansi.Command(0, 0, s[0]), true
	case len(s) == 3 && s[0] >= 0x20 && s[0] <= 0x2f && s[1] == ' ' && s[2] >= 0x30 && s[2] <= 0x7e:
		return ansi.Command(0, s[0], s[2]), true
	}
	return 0, false
}

// oscNumber is the number x/ansi's parser reads for an OSC whose data is
// data, and x/vt keys its handlers by: the digits data starts with, in an int
// that wraps as the parser's does, or parser.MissingCommand for none.
func oscNumber(data []byte) int {
	n := parser.MissingCommand
	for _, d := range data {
		if d < '0' || d > '9' {
			break
		}
		if n == parser.MissingCommand {
			n = 0
		}
		n = n*10 + int(d-'0')
	}
	return n
}

// csiVerdict is what a render fails by for a CSI of key no handler took, or
// "" for one it renders.
func csiVerdict(key int) string {
	if rest, own := xvtCSI[key]; own {
		if rest {
			return ""
		}
	} else if name, ok := csiRules[key]; ok {
		return name
	}
	return "an unhandled " + csiName(key)
}

// escVerdict is csiVerdict's for an ESC. A designation into G0 to G3 of a set
// x/vt doesn't take, by ESC ( to ESC + and a final, is of a 94-character set,
// and one into G1 to G3 by ESC -, ESC . or ESC / of a 96-character set, of
// which x/vt takes none. x/vt keeps the set designated before, where xterm
// takes another, as ESC ( < for DEC's user-preferred supplemental set or
// ESC - A for ISO Latin-1's supplement, or puts ASCII in the G-set for a final
// it knows no set for, which another terminal may take; so the cells printed
// under it may be other than the emulator's, and a live print shifted there
// lands otherwise. Each stays noted whatever follows, as a DECSC saves the
// set for a DECRC to put back. The snapshot designates G0 by the SCS the
// tracker keeps for it, so one the ring has evicted counts too.
func escVerdict(key int) string {
	if rest, own := xvtESC[key]; own {
		if rest {
			return ""
		}
	} else if name, ok := escRules[key]; ok {
		return name
	} else {
		switch ansi.Cmd(key).Intermediate() {
		case '(', ')', '*', '+':
			return charset94State
		case '-', '.', '/':
			return charset96State
		}
	}
	return "an unhandled " + escName(key)
}

// oscVerdict is csiVerdict's for an OSC numbered n, with data, all of it.
// OSC 777 renders only as rxvt's notification, OSC 777 ; notify ; title ;
// body, which shows once, as OSC 9's does: its other commands are urxvt's
// extensions, which may do anything. OSC 7501 renders only as Claude Code's
// probe, OSC 7501 ; ?, which asks whether the terminal takes the status
// Claude Code reports, and leaves nothing, no reply meaning it doesn't: a
// status, which only a terminal that answered is sent, is state the render
// doesn't send again.
func oscVerdict(n int, data []byte) string {
	if rest, own := xvtOSC[n]; own {
		if rest {
			return ""
		}
	} else if n == 777 {
		if bytes.HasPrefix(data, []byte("777;notify;")) {
			return ""
		}
	} else if n == 7501 {
		if bytes.Equal(data, []byte("7501;?")) {
			return ""
		}
	} else if name, ok := oscRules[n]; ok {
		return name
	}
	return "an unhandled OSC " + strconv.Itoa(n)
}

// controlVerdict is csiVerdict's for a control, b, no x/vt handler took.
// x/vt's handlers take NUL, BEL, BS, HT, LF, VT, FF, CR, SO and SI, and of
// C1, IND, HTS, RI, SS2 and SS3, as they take ESC D, ESC H, ESC M, ESC N and
// ESC O (see xvtESC): each leaves nothing, or state the render rebuilds.
// x/vt logs every other control the parser executes, by its byte.
//
// A C0 control x/vt has no handler for, and DEL, render: xterm ignores them,
// and ENQ's answerback is a reply, which changes nothing.
//
// Any other C1 control but ST fails the render, named by its byte alone. A
// terminal that reads 8-bit controls may act on it where x/vt doesn't, as
// xterm's NEL moves the cursor to the next line's start, and its SPA and EPA
// guard the cells printed between them from erasure, and one that reads
// UTF-8 prints a replacement character for the lone byte, where x/vt prints
// nothing: either way, the render isn't the session's screen. A byte of the
// range that continues a UTF-8 character is the character's, and one inside
// an OSC's or a DCS's data the string's, and neither reaches here.
//
// ST renders. The parser dispatches the OSC, DCS, APC, SOS or PM an 8-bit ST
// ends, which the check decides as that string, and x/vt logs nothing of the
// ST itself. It executes one only where no string has begun: alone, or after
// an ESC, a CSI or a DCS's header, which it abandons, dispatching nothing. An
// ST that ends no string does nothing on a terminal that reads 8-bit
// controls, as ESC \ alone does nothing (see escRules), and x/vt reads the C1
// controls as such a terminal does, the ones it follows too; one that reads
// UTF-8 prints a replacement character for it, as for those.
func controlVerdict(b byte) string {
	switch {
	case b <= ansi.US, b == ansi.DEL, b == ansi.ST:
		return ""
	case b >= ansi.PAD && b <= ansi.APC:
		return fmt.Sprintf("an unhandled C1 control 0x%02X", b)
	}
	return "an unhandled control"
}

// csiName is a CSI of key as a fallback names it: CSI, its prefix, if any,
// Ps for its parameters, whichever they were, its intermediate, if any, and
// its final byte, as in CSI ? Ps W. Every byte it shows is printable, a space
// as SP, so the name is short and holds nothing the sequence carried.
func csiName(key int) string {
	c := ansi.Cmd(key)
	var b strings.Builder
	b.WriteString("CSI ")
	if p := c.Prefix(); p != 0 {
		b.WriteString(byteName(p) + " ")
	}
	b.WriteString("Ps ")
	if i := c.Intermediate(); i != 0 {
		b.WriteString(byteName(i) + " ")
	}
	b.WriteString(byteName(c.Final()))
	return b.String()
}

// escName is csiName's for an ESC, as in ESC # 8.
func escName(key int) string {
	c := ansi.Cmd(key)
	if i := c.Intermediate(); i != 0 {
		return "ESC " + byteName(i) + " " + byteName(c.Final())
	}
	return "ESC " + byteName(c.Final())
}

func byteName(b byte) string {
	if b == ' ' {
		return "SP"
	}
	return string(rune(b))
}

// xvtCSI are the CSIs x/vt's own handlers take, by key, each one whose effect
// the render rebuilds from the emulator's state, or that leaves nothing. Some
// of them take only some parameters, and log the rest, which the check then
// sees: the value says whether the rest render too, as each terminal named
// ignores them as x/vt does.
var xvtCSI = map[int]bool{
	// ICH, the cursor's moves, CUP and HVP, CHT and CBT, IL, DL, DCH, SU, SD,
	// ECH, HPA, HPR, VPA and VPR: cells and the cursor, which the render
	// draws, the lines a scroll takes off the top into the history.
	ansi.Command(0, 0, '@'): true,
	ansi.Command(0, 0, 'A'): true,
	ansi.Command(0, 0, 'B'): true,
	ansi.Command(0, 0, 'C'): true,
	ansi.Command(0, 0, 'D'): true,
	ansi.Command(0, 0, 'E'): true,
	ansi.Command(0, 0, 'F'): true,
	ansi.Command(0, 0, 'G'): true,
	ansi.Command(0, 0, 'H'): true,
	ansi.Command(0, 0, 'I'): true,
	ansi.Command(0, 0, 'L'): true,
	ansi.Command(0, 0, 'M'): true,
	ansi.Command(0, 0, 'P'): true,
	ansi.Command(0, 0, 'S'): true,
	ansi.Command(0, 0, 'T'): true,
	ansi.Command(0, 0, 'X'): true,
	ansi.Command(0, 0, 'Z'): true,
	ansi.Command(0, 0, '`'): true,
	ansi.Command(0, 0, 'a'): true,
	ansi.Command(0, 0, 'd'): true,
	ansi.Command(0, 0, 'e'): true,
	ansi.Command(0, 0, 'f'): true,
	// ED 0 to 3, the cells, and the history ED 3 empties. x/vt drops ED 4
	// and up, of which kitty's ED 22 scrolls the screen into its scrollback.
	ansi.Command(0, 0, 'J'): false,
	// EL 0 to 2. x/vt drops EL 3 and up, as xterm does.
	ansi.Command(0, 0, 'K'): true,
	// DECST8C (CSI ? 5 W) and TBC 0 and 3: the tab stops, which the render
	// sets (see watchTabStops). x/vt drops the others, as xterm's TBC does, and
	// xterm takes DECST8C only at a VT510's level, which isn't its default.
	ansi.Command('?', 0, 'W'): true,
	ansi.Command(0, 0, 'g'):   true,
	// REP: the render leaves its character as the emulator holds it.
	ansi.Command(0, 0, 'b'): true,
	// DA1 and DA2, DSR and DECXCPR, DECRQM: requests, whose replies are
	// discarded. x/vt drops the forms it has no reply for, which ask too.
	ansi.Command(0, 0, 'c'):     true,
	ansi.Command('>', 0, 'c'):   true,
	ansi.Command(0, 0, 'n'):     true,
	ansi.Command('?', 0, 'n'):   true,
	ansi.Command(0, '$', 'p'):   true,
	ansi.Command('?', '$', 'p'): true,
	// SM, RM, DECSET and DECRST: modes, which have rules of their own (see
	// unrestoredMode).
	ansi.Command(0, 0, 'h'):   true,
	ansi.Command(0, 0, 'l'):   true,
	ansi.Command('?', 0, 'h'): true,
	ansi.Command('?', 0, 'l'): true,
	// SGR: the pen and the cells' styles (see watchRendition).
	ansi.Command(0, 0, 'm'): true,
	// DECSTR: what x/vt's soft reset leaves, which the render rebuilds.
	ansi.Command(0, '!', 'p'): true,
	// DECSCUSR: the cursor's style.
	ansi.Command(0, ' ', 'q'): true,
	// DECSTBM: the scroll region. x/vt drops one whose top isn't above its
	// bottom, as xterm does.
	ansi.Command(0, 0, 'r'): true,
	// SCOSC or DECSLRM, and SCORC: the saved slot, or the margins (see
	// unrestored). x/vt drops a DECSLRM whose left margin isn't left of its
	// right, while DECLRMM makes CSI s one, and an SCORC with a parameter, as
	// xterm does.
	ansi.Command(0, 0, 's'): true,
	ansi.Command(0, 0, 'u'): true,
}

// csiRules are the CSIs x/vt has no handler for, by key: with "" those that
// render, and with a name those that fail the render by a name of their own.
// Any other fails it as an unhandled CSI.
var csiRules = map[int]string{
	// Kept, or decided by their parameters, by a handler here: the bell's
	// volumes, character protection, title modes and the window operations,
	// a status line, a rectangle's extent, the window's size in columns or
	// lines, the printer's modes, key formats, locator reporting and its
	// events, and kitty's extra cursors.
	ansi.Command(0, ' ', 't'):   "",
	ansi.Command(0, ' ', 'u'):   "",
	ansi.Command(0, '"', 'q'):   "",
	ansi.Command('>', 0, 't'):   "",
	ansi.Command(0, 0, 't'):     "",
	ansi.Command(0, '$', '~'):   "",
	ansi.Command(0, '$', '}'):   "",
	ansi.Command(0, '*', 'x'):   "",
	ansi.Command(0, '$', '|'):   "",
	ansi.Command(0, '*', '|'):   "",
	ansi.Command(0, 0, 'i'):     "",
	ansi.Command('?', 0, 'i'):   "",
	ansi.Command('>', 0, 'm'):   "",
	ansi.Command('>', 0, 'f'):   "",
	ansi.Command('>', 0, 'n'):   "",
	ansi.Command(0, '\'', 'z'):  "",
	ansi.Command(0, '\'', '{'):  "",
	ansi.Command('>', ' ', 'q'): "",
	// kitty's keyboard stack, pushed, popped and set, which the tracker keeps
	// and the render pushes again.
	ansi.Command('>', 0, 'u'): "",
	ansi.Command('<', 0, 'u'): "",
	ansi.Command('=', 0, 'u'): "",
	// Restores, of DEC modes, of a rendition and of the colours: one whose
	// save is in the ring fails on the save, and one whose save the ring no
	// longer holds neither a raw replay nor the render can make the same.
	ansi.Command('?', 0, 'r'): "",
	ansi.Command(0, '#', '}'): "",
	ansi.Command(0, '#', 'q'): "",
	ansi.Command(0, '#', 'Q'): "",
	// Requests, which leave nothing, of which the query filter drops most
	// before the ring: DA3, XTVERSION, XTQMODKEYS, XTQFMTKEYS, XTREPORTSGR,
	// DECRQLP, DECRQPSR, DECRQTSR, DECRQUPSS, DECRQCRA, DECRQDE,
	// DECREQTPARM, XTREPORTCOLORS, XTSMGRAPHICS and kitty's keyboard query.
	ansi.Command('=', 0, 'c'):  "",
	ansi.Command('>', 0, 'q'):  "",
	ansi.Command('?', 0, 'm'):  "",
	ansi.Command('?', 0, 'g'):  "",
	ansi.Command(0, '#', '|'):  "",
	ansi.Command(0, '\'', '|'): "",
	ansi.Command(0, '$', 'w'):  "",
	ansi.Command(0, '$', 'u'):  "",
	ansi.Command(0, '&', 'u'):  "",
	ansi.Command(0, '*', 'y'):  "",
	ansi.Command(0, '"', 'v'):  "",
	ansi.Command(0, 0, 'x'):    "",
	ansi.Command(0, '#', 'R'):  "",
	ansi.Command('?', 0, 'S'):  "",
	ansi.Command('?', 0, 'u'):  "",
	// DECEFR, which xterm takes only while locator reporting is on, which is
	// noted, and forgets at the next DECELR (see watchLocator).
	ansi.Command(0, '\'', 'w'): "",
	// vim's probe of whether the terminal swallows a CSI it doesn't know,
	// CSI 0 % m, which vim sends as it starts, between a DCS z z ST and a
	// cursor report, and which xterm and tmux ignore.
	ansi.Command(0, '%', 'm'): "",
	// DECPS, which plays a sound, as a bell does.
	ansi.Command(0, ',', '~'): "",
	// The Linux console's cursor shape, CSI ? Ps ; Ps ; Ps c, which its
	// terminfo entry's cnorm, civis and cvvis send: appearance only, as ?12
	// is.
	ansi.Command('?', 0, 'c'): "",
	// XTRMTITLE, which turns title modes off, as a terminal starts; one the
	// stream set first is noted (see watchTitles).
	ansi.Command('>', 0, 'T'): "",

	// State no render restores, named, whatever the parameters, and noted
	// whatever follows, RIS included, as the raw ring is exact whatever came
	// after:
	//   - DECSED and DECSEL (CSI ? Ps J, CSI ? Ps K) erase only the cells
	//     DECSCA left unprotected, which the render can't tell, as x/vt keeps
	//     no protection; x/vt ignores both, so the cells either erased are
	//     still in the emulator;
	//   - XTSAVE (CSI ? Pm s) saves DEC modes, XTPUSHSGR (CSI Pm # {, or its
	//     alias CSI Pm # p) the rendition, and XTPUSHCOLORS (CSI Pm # P) the
	//     colours, none of which x/vt keeps, so the render can't tell what a
	//     restore on the session's terminal puts back, and a joiner's, which
	//     the save never reached, would put back its own;
	//   - DECSCL (CSI Pl ; Pc " p) sets the conformance level, and on xterm
	//     soft-resets the terminal, where x/vt does nothing for it;
	//   - DECLL (CSI Ps q) lights or puts out the keyboard's LEDs, a clear
	//     too, as it puts out the joiner's, where x/vt keeps none;
	//   - kitty's unscroll (CSI Ps + T) scrolls the screen down as SD does,
	//     filling the lines it opens from the scrollback, where x/vt
	//     scrolls nothing.
	ansi.Command('?', 0, 'J'): "a selective erase",
	ansi.Command('?', 0, 'K'): "a selective erase",
	ansi.Command('?', 0, 's'): "saved DEC modes",
	ansi.Command(0, '#', '{'): "a saved rendition",
	ansi.Command(0, '#', 'p'): "a saved rendition",
	ansi.Command(0, '#', 'P'): "a saved palette",
	ansi.Command(0, '"', 'p'): "a conformance level",
	ansi.Command(0, 0, 'q'):   "keyboard LEDs",
	ansi.Command(0, '+', 'T'): "an unscroll",
}

// The names of the character sets x/vt drops (see escVerdict).
const (
	charset94State = "a 94-character set other than ASCII, British or line drawing"
	charset96State = "a 96-character set"
)

// xvtESC are the ESCs x/vt's own handlers take, by key, as xvtCSI are the
// CSIs: DECSC and DECRC, the saved slots; DECKPAM and DECKPNM, the keypad;
// IND, RI and HTS, the cursor, the cells and the tab stops; SS2 and SS3, a
// pending single shift (see unrestored); RIS; LS2, LS3, LS1R, LS2R and LS3R,
// GL and GR; and ASCII, the UK set and DEC's line drawing designated into G0
// to G3, the charsets. None of their handlers drops a form.
var xvtESC = map[int]bool{
	ansi.Command(0, 0, '7'):   true,
	ansi.Command(0, 0, '8'):   true,
	ansi.Command(0, 0, '='):   true,
	ansi.Command(0, 0, '>'):   true,
	ansi.Command(0, 0, 'D'):   true,
	ansi.Command(0, 0, 'H'):   true,
	ansi.Command(0, 0, 'M'):   true,
	ansi.Command(0, 0, 'N'):   true,
	ansi.Command(0, 0, 'O'):   true,
	ansi.Command(0, 0, 'c'):   true,
	ansi.Command(0, 0, 'n'):   true,
	ansi.Command(0, 0, 'o'):   true,
	ansi.Command(0, 0, '|'):   true,
	ansi.Command(0, 0, '}'):   true,
	ansi.Command(0, 0, '~'):   true,
	ansi.Command(0, '(', 'A'): true,
	ansi.Command(0, ')', 'A'): true,
	ansi.Command(0, '*', 'A'): true,
	ansi.Command(0, '+', 'A'): true,
	ansi.Command(0, '(', 'B'): true,
	ansi.Command(0, ')', 'B'): true,
	ansi.Command(0, '*', 'B'): true,
	ansi.Command(0, '+', 'B'): true,
	ansi.Command(0, '(', '0'): true,
	ansi.Command(0, ')', '0'): true,
	ansi.Command(0, '*', '0'): true,
	ansi.Command(0, '+', '0'): true,
}

// escRules are the ESCs x/vt has no handler for, as csiRules are the CSIs,
// but for the designations escVerdict names.
var escRules = map[int]string{
	// HP's memory lock and unlock, and S7C1T and S8C1T, which handlers here
	// decide by the emulator's state.
	ansi.Command(0, 0, 'l'):   "",
	ansi.Command(0, 0, 'm'):   "",
	ansi.Command(0, ' ', 'F'): "",
	ansi.Command(0, ' ', 'G'): "",
	// ST, which x/ansi's parser dispatches as an ESC of its own after the
	// string it ends.
	ansi.Command(0, 0, '\\'): "",
	// DECID, a request.
	ansi.Command(0, 0, 'Z'): "",
	// UTF-8, the coding x/vt reads, by ESC % G and the Linux console's older
	// ESC % 8.
	ansi.Command(0, '%', 'G'): "",
	ansi.Command(0, '%', '8'): "",
	// DECSWL: a single-width line, as x/vt draws every line.
	ansi.Command(0, '#', '5'): "",
	// The visual bell of tmux's and screen's terminfo entries, flash=\Eg,
	// which vim's visualbell and readline's visible bell style send: screen
	// flashes its window for it, and tmux and xterm ignore it, so, as a bell,
	// it leaves nothing.
	ansi.Command(0, 0, 'g'): "",

	// State no render restores, named, and noted whatever follows:
	//   - DECDHL and DECDWL (ESC # 3, ESC # 4, ESC # 6) make a line
	//     double-height or double-width, where x/vt keeps no line size and
	//     draws it single-width;
	//   - ESC % @ leaves UTF-8 for ISO-8859-1, as xterm and the Linux console
	//     read it, where x/vt reads UTF-8 alone, so the bytes after it, the
	//     program's own among them, read otherwise on x/vt, and an ESC % G
	//     after it leaves what was printed in between;
	//   - a designation of a 94-character set by two intermediates that
	//     xterm acts on, as ESC ( % 5, DEC's supplemental graphic set, which
	//     x/vt keys by the second alone, where x/vt keeps the set designated
	//     before (see escVerdict);
	//   - ESC k, a screen title string, which x/vt dispatches only under a
	//     TERM that isn't GNU screen's or tmux's, where the session's
	//     terminal may draw the title or take it as one (see screenTitles).
	ansi.Command(0, '#', '3'): "a double-size line",
	ansi.Command(0, '#', '4'): "a double-size line",
	ansi.Command(0, '#', '6'): "a double-size line",
	ansi.Command(0, '%', '@'): "a non-UTF-8 coding",
	ansi.Command(0, '%', '0'): charset94State,
	ansi.Command(0, '%', '2'): charset94State,
	ansi.Command(0, '%', '3'): charset94State,
	ansi.Command(0, '%', '5'): charset94State,
	ansi.Command(0, '%', '6'): charset94State,
	ansi.Command(0, '%', '='): charset94State,
	ansi.Command(0, '"', '4'): charset94State,
	ansi.Command(0, '"', '>'): charset94State,
	ansi.Command(0, '"', '?'): charset94State,
	ansi.Command(0, '&', '4'): charset94State,
	ansi.Command(0, '&', '5'): charset94State,
	// A screen title string, which reaches x/vt as one only under a TERM that
	// isn't GNU screen's or tmux's (see screenTitles).
	ansi.Command(0, 0, 'k'): "a screen title string",
}

// xvtOSC are the OSCs x/vt's own handlers take, by number, as xvtCSI are the
// CSIs: the window title and the icon name, which the render sets; the
// working directory, which it sends; a hyperlink, which the cells keep; and
// the default foreground, background and cursor colours and their resets,
// which watchColours keeps. None of their handlers drops a form.
var xvtOSC = map[int]bool{
	0: true, 1: true, 2: true,
	7:  true,
	8:  true,
	10: true, 11: true, 12: true,
	110: true, 111: true, 112: true,
}

// oscRules are the OSCs x/vt has no handler for, by number, as csiRules are
// the CSIs, but for OSC 777 and OSC 7501 (see oscVerdict).
var oscRules = map[int]string{
	// Kept, or decided by their data, by a handler here: the colours,
	// ConEmu's progress indicator and working directory, the pointer's
	// shape, the font, the clipboard, iTerm2's commands, kitty's clipboard
	// and an OSC with no number.
	4: "", 5: "", 104: "", 105: "",
	13: "", 14: "", 15: "", 16: "", 17: "", 18: "", 19: "",
	113: "", 114: "", 115: "", 116: "", 117: "", 118: "", 119: "",
	9:                     "",
	22:                    "",
	50:                    "",
	52:                    "",
	1337:                  "",
	5522:                  "",
	parser.MissingCommand: "",
	// Prompt marks, FinalTerm's and VS Code's, systemd's context markers,
	// and Fig's shell integration, which Amazon Q's is too, each of which a
	// shell sends at every prompt, and which a fallback would fail every join
	// to it on: none is rebuilt, and the next prompt sends them again.
	133:  "",
	633:  "",
	697:  "",
	3008: "",
	// kitty's notifications, shown once, as OSC 9's are.
	99: "",
	// kitty's pop of the colours, a restore (see csiRules).
	30101: "",

	// State no render restores, named, whatever the data, and noted
	// whatever follows, RIS included:
	//   - OSC 6, and its alias OSC 106, turn on or off whether xterm draws
	//     bold, underlined, blinking, reversed or italic text in a special
	//     colour, none of which x/vt keeps, and which xterm's RIS leaves;
	//     iTerm2 reads OSC 6 as a tab's colour;
	//   - kitty's OSC 30001 pushes the colours, as XTPUSHCOLORS does;
	//   - OSC 46 sets the file xterm logs to, and OSC 3 sets or deletes an X
	//     property of its window, neither of which x/vt keeps, and which
	//     another build or terminal may take though xterm's defaults don't;
	//   - OSC 66, kitty's text sizing, draws its text scaled, or in as many
	//     cells as it says, and moves the cursor past it, where x/vt drops
	//     the whole OSC, its text and the move with it.
	6:     "a special colour mode",
	106:   "a special colour mode",
	30001: "a saved palette",
	46:    "a log file",
	3:     "a window property",
	66:    "sized text",
}
