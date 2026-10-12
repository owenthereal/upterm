package io

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// This file is the oracle the query filter's tests check it against: a
// reference terminal parser (refParse), the query families encoded apart from
// the filter's classifiers (refQuery), and the two properties a filter's
// output must keep (refCheck). Nothing in it calls production code.
//
// The parser transcribes Ghostty's DEC parser, which is MIT-licensed, from
// three git blobs:
//   - src/terminal/parse_table.zig, fa074fa078ae4f46e8e55f3c4bdc75ef6471b270:
//     the transition table, which refGenTable ports call for call;
//   - src/terminal/Parser.zig, 473aef9f4563a0fae6e82e525dfaadaaad2ecf0d: the
//     exit, transition and entry actions of each step, in refParser.apply;
//   - src/terminal/osc.zig, 0c218fe467901784dc5141138d677a24c42fcdf9: an OSC
//     that CAN or SUB ends is discarded, not dispatched (Parser.end).
//
// Where it departs from Ghostty, on purpose:
//   - The C1 "anywhere" transitions (0x80–0x9F) aren't modelled. In UTF-8
//     output those bytes are continuation bytes far more often than
//     introducers, so 0x80–0xFF print in ground and are payload in strings.
//     The fuzz generator never produces 0x80–0x9F. It produces 0xA0–0xFF as
//     they are, which Ghostty's table ignores in an ESC or CSI head and a DCS
//     header, as here, and in an APC, PM or SOS, where this model keeps them
//     as payload. A filter passes a string's payload as it came, so keeping
//     them there only holds it to more.
//   - Ghostty's handler-level limits aren't modelled: it drops a CSI with ':'
//     separators unless its final byte is 'm', a CSI or DCS with more than 24
//     parameters, intermediates past four, and an OSC its own grammar doesn't
//     know. Events here keep the raw bytes instead, so preservation holds a
//     filter to keeping them too, which is stricter.
//   - A private prefix, which Ghostty collects as an intermediate, has a field
//     of its own.
//
// refKitty and refTmux change only where strings end, for the suppression
// check: kitty ends every string at BEL or ST and keeps CAN, SUB and an ESC
// that isn't ST as payload (kitty's vt-parser.c); tmux, as a terminal, ends a
// DCS only at ST (tmux's input.c, dcs_handler and dcs_escape, which alone
// lack INPUT_STATE_ANYWHERE), so its DCS header and DCS-ignore states stay as
// DEC's.

type refMode int

const (
	refDEC   refMode = iota // Ghostty's parser: the filter's model
	refKitty                // every string ends only at BEL or ST; CAN, SUB and ESC-not-ST are payload
	refTmux                 // as refDEC, except a DCS ends only at ST, with CAN, SUB and ESC x as payload
)

func (m refMode) String() string { return [...]string{"DEC", "kitty", "tmux"}[m] }

type refKind int

const (
	refPrint refKind = iota
	refExecute
	refESC
	refCSI
	refOSC
	refDCS
	refAPC
	refPM
	refSOS
)

type refEvent struct {
	kind   refKind
	b      byte   // refPrint: the byte printed; refExecute: the control executed
	prefix byte   // refCSI, refDCS: private prefix byte (0x3C–0x3F), or 0
	params string // refCSI, refDCS: the raw parameter bytes, ';' and ':' included
	inter  string // refESC, refCSI, refDCS: all intermediates, in order
	final  byte   // refESC, refCSI, refDCS: the final byte
	data   string // refOSC, refDCS, refAPC, refPM, refSOS: the payload as collected
	end    byte   // strings: 0x07, '\\' (ST), 0x18, 0x1a, or 0x1b (an ESC that isn't ST)

	// Bookkeeping, used for policy decisions and never compared. Both count
	// raw bytes, ignored control bytes included: dropping an ignored CR from
	// a DCS header changes them without changing the terminal's effect. A
	// byte the escape state executes or ignores between the introducer's ESC
	// and its second byte, such as a CR in ESC CR ], comes before the string
	// begins and isn't counted: the filter forwards or drops it, never holds
	// it.
	held    int // strings: from the introducer through the payload
	numHeld int // OSC: from the introducer up to, not including, the first ';' or the end
}

func (e refEvent) String() string {
	name := [...]string{"print", "execute", "ESC", "CSI", "OSC", "DCS", "APC", "PM", "SOS"}[e.kind]
	switch e.kind {
	case refPrint, refExecute:
		return fmt.Sprintf("%s %q", name, e.b)
	case refESC:
		return fmt.Sprintf("ESC inter %q final %q", e.inter, e.final)
	case refCSI:
		return fmt.Sprintf("CSI prefix %q params %q inter %q final %q", e.prefix, e.params, e.inter, e.final)
	case refDCS:
		return fmt.Sprintf("DCS prefix %q params %q inter %q final %q data %q end %q",
			e.prefix, e.params, e.inter, e.final, e.data, e.end)
	}
	return fmt.Sprintf("%s data %q end %q", name, e.data, e.end)
}

// refHeldAtEnd reports whether the filter, under its bounds, would
// still have been holding ev's string undecided when it ended:
//   - an OSC whose number stayed within the 8-byte guard (numHeld <= 8) and
//     whose whole string stayed within the 256-byte bound (held <= 256);
//   - an APC that ended before its first byte, which says whether it is a
//     graphics command;
//   - a graphics command, an APC whose payload starts with G, whose control
//     data reached neither a ';' nor a BEL that asks (refAPCLatches) within
//     256 raw bytes, framing included. Held to its end, the whole string is
//     within that bound (held <= 256), so neither may appear in it at all.
//
// The filter holds no other string to its end. It holds a DCS only to its
// header's final byte, and a DCS that ends before that has no event under
// DEC, since it never hooked, so there is nothing to remove. Any other APC,
// and a PM or SOS, passes as it streams.
//
// It is computed from the event alone, independently of the filter.
func refHeldAtEnd(ev refEvent) bool {
	switch ev.kind {
	case refOSC:
		return ev.numHeld <= 8 && ev.held <= 256
	case refAPC:
		if ev.data == "" {
			return true
		}
		control, ok := strings.CutPrefix(ev.data, "G")
		return ok && ev.held <= 256 && !strings.Contains(control, ";") && !refAPCLatches(control)
	}
	return false
}

// refState is Ghostty's Parser.State, in its order.
type refState int

const (
	rsGround refState = iota
	rsEscape
	rsEscapeIntermediate
	rsCSIEntry
	rsCSIIntermediate
	rsCSIParam
	rsCSIIgnore
	rsDCSEntry
	rsDCSParam
	rsDCSIntermediate
	rsDCSPassthrough
	rsDCSIgnore
	rsOSCString
	rsSOSPMAPCString
	rsCount
)

// refAction is Ghostty's Parser.TransitionAction.
type refAction int

const (
	raNone refAction = iota
	raIgnore
	raPrint
	raExecute
	raCollect
	raParam
	raEscDispatch
	raCSIDispatch
	raPut
	raOSCPut
	raAPCPut
)

type refTransition struct {
	state  refState
	action refAction
}

// refTable is parse_table.zig's table, indexed by byte, then state.
var refTable = refGenTable()

// refGenTable is genTable, call for call and in the same order. A later call
// overwrites an earlier one for the same byte and state, as in Ghostty, and an
// entry no call sets stays in its state with no action.
func refGenTable() (t [256][rsCount]refTransition) {
	for c := range t {
		for s := range t[c] {
			t[c][s] = refTransition{refState(s), raNone}
		}
	}
	single := func(c int, s0, s1 refState, a refAction) { t[c][s0] = refTransition{s1, a} }
	span := func(from, to int, s0, s1 refState, a refAction) {
		for c := from; c <= to; c++ {
			single(c, s0, s1, a)
		}
	}

	// anywhere
	for source := range rsCount {
		// anywhere => ground
		single(0x18, source, rsGround, raExecute)
		single(0x1A, source, rsGround, raExecute)
		// anywhere => escape
		single(0x1B, source, rsEscape, raNone)
		// Not modelled: 0x80–0x8F, 0x91–0x97, 0x99, 0x9A and 0x9C to ground,
		// and 0x90, 0x98, 0x9B, 0x9D, 0x9E and 0x9F to a sequence's start.
	}
	// In their place, 8-bit bytes print in ground and are payload in the one
	// string state the table leaves them out of. osc_string, dcs_passthrough
	// and dcs_ignore already cover 0x80–0xFF below.
	span(0x80, 0xFF, rsGround, rsGround, raPrint)
	span(0x80, 0xFF, rsSOSPMAPCString, rsSOSPMAPCString, raAPCPut)

	// ground
	single(0x19, rsGround, rsGround, raExecute)
	span(0, 0x17, rsGround, rsGround, raExecute)
	span(0x1C, 0x1F, rsGround, rsGround, raExecute)
	span(0x20, 0x7F, rsGround, rsGround, raPrint)

	// escape_intermediate
	{
		source := rsEscapeIntermediate
		single(0x19, source, source, raExecute)
		span(0, 0x17, source, source, raExecute)
		span(0x1C, 0x1F, source, source, raExecute)
		span(0x20, 0x2F, source, source, raCollect)
		single(0x7F, source, source, raIgnore)
		span(0x30, 0x7E, source, rsGround, raEscDispatch)
	}

	// sos_pm_apc_string
	{
		source := rsSOSPMAPCString
		single(0x19, source, source, raAPCPut)
		span(0, 0x17, source, source, raAPCPut)
		span(0x1C, 0x1F, source, source, raAPCPut)
		span(0x20, 0x7F, source, source, raAPCPut)
	}

	// escape
	{
		source := rsEscape
		single(0x19, source, source, raExecute)
		span(0, 0x17, source, source, raExecute)
		span(0x1C, 0x1F, source, source, raExecute)
		single(0x7F, source, source, raIgnore)
		span(0x30, 0x4F, source, rsGround, raEscDispatch)
		span(0x51, 0x57, source, rsGround, raEscDispatch)
		span(0x60, 0x7E, source, rsGround, raEscDispatch)
		single(0x59, source, rsGround, raEscDispatch)
		single(0x5A, source, rsGround, raEscDispatch)
		single(0x5C, source, rsGround, raEscDispatch)
		span(0x20, 0x2F, source, rsEscapeIntermediate, raCollect)
		single(0x58, source, rsSOSPMAPCString, raNone)
		single(0x5E, source, rsSOSPMAPCString, raNone)
		single(0x5F, source, rsSOSPMAPCString, raNone)
		single(0x50, source, rsDCSEntry, raNone)
		single(0x5B, source, rsCSIEntry, raNone)
		single(0x5D, source, rsOSCString, raNone)
	}

	// dcs_entry
	{
		source := rsDCSEntry
		single(0x19, source, source, raIgnore)
		span(0, 0x17, source, source, raIgnore)
		span(0x1C, 0x1F, source, source, raIgnore)
		single(0x7F, source, source, raIgnore)
		span(0x20, 0x2F, source, rsDCSIntermediate, raCollect)
		single(0x3A, source, rsDCSIgnore, raNone)
		span(0x30, 0x39, source, rsDCSParam, raParam)
		single(0x3B, source, rsDCSParam, raParam)
		span(0x3C, 0x3F, source, rsDCSParam, raCollect)
		span(0x40, 0x7E, source, rsDCSPassthrough, raNone)
	}

	// dcs_intermediate
	{
		source := rsDCSIntermediate
		single(0x19, source, source, raIgnore)
		span(0, 0x17, source, source, raIgnore)
		span(0x1C, 0x1F, source, source, raIgnore)
		span(0x20, 0x2F, source, source, raCollect)
		single(0x7F, source, source, raIgnore)
		span(0x30, 0x3F, source, rsDCSIgnore, raNone)
		span(0x40, 0x7E, source, rsDCSPassthrough, raNone)
	}

	// dcs_ignore
	{
		source := rsDCSIgnore
		single(0x19, source, source, raIgnore)
		span(0, 0x17, source, source, raIgnore)
		span(0x1C, 0x1F, source, source, raIgnore)
		span(0x80, 0xFF, source, source, raIgnore)
	}

	// dcs_param
	{
		source := rsDCSParam
		single(0x19, source, source, raIgnore)
		span(0, 0x17, source, source, raIgnore)
		span(0x1C, 0x1F, source, source, raIgnore)
		span(0x30, 0x39, source, source, raParam)
		single(0x3B, source, source, raParam)
		single(0x7F, source, source, raIgnore)
		single(0x3A, source, rsDCSIgnore, raNone)
		span(0x3C, 0x3F, source, rsDCSIgnore, raNone)
		span(0x20, 0x2F, source, rsDCSIntermediate, raCollect)
		span(0x40, 0x7E, source, rsDCSPassthrough, raNone)
	}

	// dcs_passthrough
	{
		source := rsDCSPassthrough
		single(0x19, source, source, raPut)
		span(0, 0x17, source, source, raPut)
		span(0x1C, 0x1F, source, source, raPut)
		span(0x20, 0x7E, source, source, raPut)
		single(0x7F, source, source, raIgnore)
		span(0x80, 0xFF, source, source, raPut)
	}

	// csi_param
	{
		source := rsCSIParam
		single(0x19, source, source, raExecute)
		span(0, 0x17, source, source, raExecute)
		span(0x1C, 0x1F, source, source, raExecute)
		span(0x30, 0x39, source, source, raParam)
		single(0x3A, source, source, raParam)
		single(0x3B, source, source, raParam)
		single(0x7F, source, source, raIgnore)
		span(0x40, 0x7E, source, rsGround, raCSIDispatch)
		span(0x3C, 0x3F, source, rsCSIIgnore, raNone)
		span(0x20, 0x2F, source, rsCSIIntermediate, raCollect)
	}

	// csi_ignore
	{
		source := rsCSIIgnore
		single(0x19, source, source, raExecute)
		span(0, 0x17, source, source, raExecute)
		span(0x1C, 0x1F, source, source, raExecute)
		span(0x20, 0x3F, source, source, raIgnore)
		single(0x7F, source, source, raIgnore)
		span(0x40, 0x7E, source, rsGround, raNone)
	}

	// csi_intermediate
	{
		source := rsCSIIntermediate
		single(0x19, source, source, raExecute)
		span(0, 0x17, source, source, raExecute)
		span(0x1C, 0x1F, source, source, raExecute)
		span(0x20, 0x2F, source, source, raCollect)
		single(0x7F, source, source, raIgnore)
		span(0x40, 0x7E, source, rsGround, raCSIDispatch)
		span(0x30, 0x3F, source, rsCSIIgnore, raNone)
	}

	// csi_entry
	{
		source := rsCSIEntry
		single(0x19, source, source, raExecute)
		span(0, 0x17, source, source, raExecute)
		span(0x1C, 0x1F, source, source, raExecute)
		single(0x7F, source, source, raIgnore)
		span(0x40, 0x7E, source, rsGround, raCSIDispatch)
		single(0x3A, source, rsCSIIgnore, raNone)
		span(0x20, 0x2F, source, rsCSIIntermediate, raCollect)
		span(0x30, 0x39, source, rsCSIParam, raParam)
		single(0x3B, source, rsCSIParam, raParam)
		span(0x3C, 0x3F, source, rsCSIParam, raCollect)
	}

	// osc_string
	{
		source := rsOSCString
		single(0x19, source, source, raIgnore)
		span(0, 0x06, source, source, raIgnore)
		span(0x08, 0x17, source, source, raIgnore)
		span(0x1C, 0x1F, source, source, raIgnore)
		span(0x20, 0xFF, source, source, raOSCPut)
		single(0x07, source, rsGround, raNone)
	}

	return t
}

// refParser runs refTable over a stream, keeping what Ghostty's Parser keeps
// for the events it reports, plus the offsets behind held and numHeld.
type refParser struct {
	mode   refMode
	state  refState
	events []refEvent

	// What Parser.clear resets: the header of the sequence being parsed.
	prefix byte
	params []byte
	inter  []byte

	str     refEvent // the string being collected: its kind and DCS header
	data    []byte   // its payload so far
	strAt   int      // offset of its introducer's ESC
	strSkip int      // bytes the escape state skipped between that ESC and the introducer's second byte
	semiAt  int      // offset of an OSC's first ';', or -1

	escAt   int // offset of the last ESC that entered the escape state
	escSkip int // bytes the escape state has executed or ignored since escAt
	stEvent int // index of a string event an ESC ended on the last byte, or -1

	// refKitty and refTmux: an ESC inside a string whose next byte decides
	// whether it is ST.
	escHeld   bool
	escHeldAt int
}

// refParse runs in through the model and returns the events, in order.
//
// A string ended by ESC \ records '\' as its end, and the '\' then dispatches
// as an ESC sequence with that final byte: a lone ST, as Ghostty sees it. A
// sequence still open when in runs out reports nothing.
func refParse(mode refMode, in []byte) []refEvent {
	p := refParser{mode: mode, semiAt: -1, stEvent: -1}
	for at, c := range in {
		p.next(c, at)
	}
	return p.events
}

// next takes one byte. Under refKitty and refTmux it first applies their
// string ends, and everything else goes to refTable.
func (p *refParser) next(c byte, at int) {
	if p.escHeld {
		p.escHeld = false
		if c == '\\' {
			// ST: the string ends at the ESC, as it would under DEC.
			p.apply(0x1b, p.escHeldAt, refTable[0x1b][p.state])
			p.apply(c, at, refTable[c][p.state])
			return
		}
		if p.mode == refTmux {
			p.payload(c) // ESC x adds x alone, and ESC ESC one ESC
			return
		}
		// kitty keeps the ESC and reads c afresh, so in ESC ESC \ the second
		// ESC is ST. Ending the string there is the stricter reading for
		// suppression: the bytes after it are parsed as live sequences.
		p.payload(0x1b)
	}
	if p.ownStringEnds() {
		switch c {
		case 0x1b:
			p.escHeld, p.escHeldAt = true, at
			return
		case 0x18, 0x1a:
			p.payload(c)
			return
		case 0x07:
			if p.mode == refKitty {
				p.apply(c, at, refTransition{rsGround, raNone})
				return
			}
		}
	}
	p.apply(c, at, refTable[c][p.state])
}

// ownStringEnds reports whether the mode, not refTable, decides where the
// current state ends.
func (p *refParser) ownStringEnds() bool {
	switch p.mode {
	case refKitty:
		switch p.state {
		case rsOSCString, rsSOSPMAPCString, rsDCSEntry, rsDCSParam,
			rsDCSIntermediate, rsDCSPassthrough, rsDCSIgnore:
			return true
		}
	case refTmux:
		return p.state == rsDCSPassthrough
	}
	return false
}

// payload adds c, which DEC would have taken for the string's end, to the
// string. A DCS header that takes one can no longer be valid, so it becomes
// a DCS-ignore.
func (p *refParser) payload(c byte) {
	switch p.state {
	case rsOSCString, rsDCSPassthrough, rsSOSPMAPCString:
		p.data = append(p.data, c)
	case rsDCSEntry, rsDCSParam, rsDCSIntermediate:
		p.state = rsDCSIgnore
	}
}

// apply is Parser.next: on a change of state the old state's exit action,
// then the transition's action, then the new state's entry action.
func (p *refParser) apply(c byte, at int, t refTransition) {
	if p.stEvent >= 0 {
		if c == '\\' {
			p.events[p.stEvent].end = '\\'
		}
		p.stEvent = -1
	}
	if c == 0x1b && t.state == rsEscape {
		// Every ESC restarts, ESC ESC included, though Ghostty runs no entry
		// action for it: escape to escape isn't a change of state.
		p.escAt, p.escSkip = at, 0
	} else if p.state == rsEscape && t.state == rsEscape {
		// A C0 the escape state executes, or a byte it ignores, comes before
		// any sequence the ESC starts and is no part of it.
		p.escSkip++
	}
	changed := t.state != p.state
	if changed {
		p.exit(c, at)
	}
	p.do(t.action, c, at)
	if changed {
		p.enter(t.state, c)
	}
	p.state = t.state
}

func (p *refParser) exit(c byte, at int) {
	switch p.state {
	case rsOSCString:
		// osc.zig's end: a CAN or SUB discards the OSC.
		if c != 0x18 && c != 0x1a {
			p.endString(c, at)
		}
	case rsDCSPassthrough, rsSOSPMAPCString: // dcs_unhook, apc_end
		p.endString(c, at)
	}
}

func (p *refParser) do(a refAction, c byte, at int) {
	switch a {
	case raPrint:
		p.events = append(p.events, refEvent{kind: refPrint, b: c})
	case raExecute:
		p.events = append(p.events, refEvent{kind: refExecute, b: c})
	case raCollect:
		// The table collects 0x3C–0x3F only right after CSI or DCS: a prefix.
		if c >= 0x3c {
			p.prefix = c
		} else {
			p.inter = append(p.inter, c)
		}
	case raParam:
		p.params = append(p.params, c)
	case raEscDispatch:
		p.events = append(p.events, refEvent{kind: refESC, inter: string(p.inter), final: c})
	case raCSIDispatch:
		p.events = append(p.events, refEvent{kind: refCSI, prefix: p.prefix,
			params: string(p.params), inter: string(p.inter), final: c})
	case raOSCPut:
		if c == ';' && p.semiAt < 0 {
			p.semiAt = at
		}
		p.data = append(p.data, c)
	case raPut, raAPCPut:
		p.data = append(p.data, c)
	}
}

func (p *refParser) enter(s refState, c byte) {
	switch s {
	case rsEscape, rsCSIEntry:
		p.clear()
	case rsDCSEntry:
		p.clear()
		p.beginString(refDCS)
	case rsOSCString:
		p.beginString(refOSC)
	case rsDCSPassthrough: // dcs_hook
		p.str.prefix, p.str.params, p.str.inter, p.str.final = p.prefix, string(p.params), string(p.inter), c
	case rsSOSPMAPCString: // apc_start
		p.beginString(map[byte]refKind{'X': refSOS, '^': refPM, '_': refAPC}[c])
	}
}

func (p *refParser) clear() {
	p.prefix, p.params, p.inter = 0, p.params[:0], p.inter[:0]
}

func (p *refParser) beginString(kind refKind) {
	p.str, p.data, p.strAt, p.strSkip, p.semiAt = refEvent{kind: kind}, p.data[:0], p.escAt, p.escSkip, -1
}

// strHeld is how many raw bytes of the current string come before offset
// end: from its introducer's ESC, less what the escape state skipped.
func (p *refParser) strHeld(end int) int {
	return end - p.strAt - p.strSkip
}

func (p *refParser) endString(c byte, at int) {
	ev := p.str
	ev.data, ev.end, ev.held = string(p.data), c, p.strHeld(at)
	if ev.kind == refOSC {
		ev.numHeld = ev.held
		if p.semiAt >= 0 {
			ev.numHeld = p.strHeld(p.semiAt)
		}
	}
	p.events = append(p.events, ev)
	if c == 0x1b {
		p.stEvent = len(p.events) - 1
	}
}

// refQuery reports whether ev is a request in the query families. It is
// written apart from io/query_classify.go, so a classifier bug can't hide
// itself. Families 1–16 read the same under every mode; the modes differ in
// where a string ends, which the event already reflects.
func refQuery(mode refMode, ev refEvent) bool {
	switch ev.kind {
	case refESC:
		return ev.inter == "" && ev.final == 'Z' // 2: DECID
	case refCSI:
		return refCSIQuery(ev)
	case refOSC:
		return refOSCQuery(ev.data)
	case refDCS:
		// 15: DECRQSS, XTGETTCAP and XTGETXRES, whatever the parameters. The
		// header alone decides, and a rule that names no prefix requires none.
		return ev.prefix == 0 && (ev.inter == "$" && ev.final == 'q' ||
			ev.inter == "+" && (ev.final == 'q' || ev.final == 'Q'))
	case refAPC:
		return refAPCQuery(ev.data)
	}
	return false
}

// refAPCQuery is family 16, kitty's graphics query: an APC whose payload
// starts with G, and whose control data -- the rest of the payload up to its
// first ';', or all of it -- has the pair a=q. So does one where only a prefix
// of the control data, ending just before a BEL, has it (refAPCLatches): kitty
// ends a string at a BEL, so that prefix is all it reads. Under refKitty the
// payload has already ended at its first BEL, and holds none.
func refAPCQuery(data string) bool {
	rest, ok := strings.CutPrefix(data, "G")
	if !ok {
		return false
	}
	control, _, _ := strings.Cut(rest, ";")
	return refGraphicsAsks(control) || refAPCLatches(control)
}

// refAPCLatches reports whether a prefix of a graphics command's control data
// that ends just before a BEL asks: the BEL latch.
func refAPCLatches(control string) bool {
	for i := range len(control) {
		if control[i] == 0x07 && refGraphicsAsks(control[:i]) {
			return true
		}
	}
	return false
}

// refGraphicsAsks reports whether control, split on ',' into key=value pairs,
// has the pair a=q. Every other byte, a control byte included, is part of the
// pair it falls in, as the terminal hands it to the graphics handler.
func refGraphicsAsks(control string) bool {
	return slices.Contains(strings.Split(control, ","), "a=q")
}

// refCSIQuery is families 1 and 3–10. A rule that names no prefix or
// intermediates requires none.
func refCSIQuery(ev refEvent) bool {
	count, first, ok := refParams(ev.params)
	if !ok {
		return false
	}
	pre, in, f := ev.prefix, ev.inter, ev.final
	plain := pre == 0 && in == ""
	switch {
	case f == 'c' && in == "" && (pre == 0 || pre == '>' || pre == '=') && first == 0: // 1: DA
	case f == 'n' && in == "" && (pre == 0 && (first == 5 || first == 6) || pre == '?'): // 3: DSR
	case f == 'p' && in == "$" && (pre == 0 || pre == '?'): // 4: DECRQM
	case f == 'q' && in == "" && pre == '>' && first == 0: // 5: XTVERSION
	case f == 't' && plain && slices.Contains([]int{11, 13, 14, 15, 16, 18, 19, 20, 21}, first): // 6: window reports
	case (f == 'm' || f == 'g') && in == "" && pre == '?': // 7: XTQMODKEYS, XTQFMTKEYS
	case f == 'S' && in == "" && pre == '?': // 8: XTSMGRAPHICS, every action
	case f == 'u' && in == "" && pre == '?': // 9: kitty keyboard, whatever the parameters
	case f == 'x' && plain && (first == 0 || first == 1): // 10: DECREQTPARM
	case pre == 0 && (in == "$" && f == 'w' || in == "&" && f == 'u' || in == `"` && f == 'v' ||
		in == "*" && f == 'y' || in == "#" && f == '|' || in == "'" && f == '|'): // 10: DECRQPSR, DECRQUPSS, DECRQDE, DECRQCRA, XTREPORTSGR, DECRQLP
	case pre == 0 && in == "#" && (f == 'R' || f == 'S') && count == 0: // 10: XTREPORTCOLORS, XTTITLEPOS
	default:
		return false
	}
	return true
}

// refParams reads a CSI's raw parameters as numbers, an empty one being 0.
// count is how many there are ("" has none, ";" two) and first is the first
// one's value: families 1, 3, 5, 6 and 10 look at it alone, as tmux does, so
// "0;1" is DA. ok is false when a ':' brings in sub-parameters, which no
// family accepts.
func refParams(raw string) (count, first int, ok bool) {
	if strings.Contains(raw, ":") {
		return 0, 0, false
	}
	if raw == "" {
		return 0, 0, true
	}
	ps := strings.Split(raw, ";")
	return len(ps), refNumber(ps[0]), true
}

// refNumber reads a run of digits, saturating so a long one can't overflow.
func refNumber(digits string) int {
	n := 0
	for _, d := range []byte(digits) {
		n = min(n*10+int(d-'0'), 1<<20)
	}
	return n
}

// refOSCQuery is families 11–14, read from the payload with the control bytes
// the OSC state ignores removed (refTable says which), then split on ';' into
// the number and its fields.
func refOSCQuery(data string) bool {
	var view []byte
	for _, c := range []byte(data) {
		if refTable[c][rsOSCString].action != raIgnore {
			view = append(view, c)
		}
	}
	num, rest, _ := strings.Cut(string(view), ";")
	if num == "" || strings.Trim(num, "0123456789") != "" {
		return false
	}
	n, fields := refNumber(num), strings.Split(rest, ";")
	switch {
	case n == 4 || n == 5 || (n >= 10 && n <= 19): // 11: colours, any field '?'
		return slices.Contains(fields, "?")
	case n == 52: // 12: clipboard read, second field '?'
		return len(fields) >= 2 && fields[1] == "?"
	case n == 50: // 13: font query, first field starting with '?'
		return strings.HasPrefix(fields[0], "?")
	case n >= 60 && n <= 62: // 14: feature queries, any payload
		return true
	}
	return false
}

// refCheck runs suppression (all three modes) and preservation (refDEC, on
// in+CAN against filter(in+CAN)). It returns "" or a description of the
// first violation. In practice filter runs a TerminalQueryFilter over the
// whole string.
//
// The CAN ends whatever the input left open, so nothing is still held, and
// the filter is fed it too, so what it held resolves the way it resolves it.
// Preservation then compares the DEC events of the input and the output,
// less the input's queries and the strings the filter drops by policy (a
// held string that ends abnormally), and less what has no effect on either
// side (refNoEffect).
func refCheck(in string, filter func(string) string) string {
	x := in + "\x18"
	out := filter(x)
	for _, mode := range []refMode{refDEC, refKitty, refTmux} {
		for _, ev := range refParse(mode, []byte(out)) {
			if refQuery(mode, ev) {
				return fmt.Sprintf("suppression under %v: filter(%q) = %q, which still asks %v", mode, x, out, ev)
			}
		}
	}
	var want, got []refEvent
	for _, ev := range refParse(refDEC, []byte(x)) {
		policy := refHeldAtEnd(ev) && (ev.end == 0x1b || ev.end == 0x18 || ev.end == 0x1a)
		if !refQuery(refDEC, ev) && !policy && !refNoEffect(ev) {
			want = append(want, refSemantic(ev))
		}
	}
	for _, ev := range refParse(refDEC, []byte(out)) {
		if !refNoEffect(ev) {
			got = append(got, refSemantic(ev))
		}
	}
	for i := range max(len(want), len(got)) {
		if i >= len(want) || i >= len(got) || want[i] != got[i] {
			return fmt.Sprintf("preservation: filter(%q) = %q, whose effect %d is %s where the input's is %s",
				x, out, i, refNth(got, i), refNth(want, i))
		}
	}
	return ""
}

// refNoEffect reports whether ev leaves a DEC terminal as it was, so that
// preservation ignores it on both sides:
//   - an executed CAN: it cancels a sequence, which then reports no event, so
//     the cancel itself changes nothing more. The filter's ESC CAN close ends
//     in one, and so does the CAN refCheck appends.
//   - a lone ST, ESC \ with no intermediates: it ends a string, which the
//     string's own event records, or it does nothing.
//   - a tmux wrapper's DCS (final 't', data from "mux;"): only tmux acts on
//     it, and the wrapped sequence after its first ESC is compared as
//     ordinary events.
//
// An executed SUB isn't on the list, which only makes the check stricter.
func refNoEffect(ev refEvent) bool {
	switch ev.kind {
	case refExecute:
		return ev.b == 0x18
	case refESC:
		return ev.inter == "" && ev.final == '\\'
	case refDCS:
		return ev.final == 't' && strings.HasPrefix(ev.data, "mux;")
	}
	return false
}

// refSemantic is ev as a DEC terminal sees it, without its bookkeeping, which
// preservation never compares.
//
// Ghostty ends a string at its ESC and never reads the byte after it: an OSC
// gets the terminator ST whatever follows (osc.zig's Terminator), and a DCS,
// APC, PM or SOS ends the same way on any exit. So a string ended by an ESC
// that isn't ST is, to it, one ended by ST, and the bytes after the ESC are
// compared as events of their own. end keeps the difference for the policy
// that drops a held string ended abnormally, which refCheck reads before
// this: kitty keeps such a string open.
func refSemantic(ev refEvent) refEvent {
	ev.held, ev.numHeld = 0, 0
	if ev.end == 0x1b {
		ev.end = '\\'
	}
	return ev
}

func refNth(evs []refEvent, i int) string {
	if i >= len(evs) {
		return "missing"
	}
	return evs[i].String()
}

// Conformance: the model's cases, pinned before anything relies on them.
func TestRefParse_Conformance(t *testing.T) {
	ev := func(mode refMode, in string) []refEvent { return refParse(mode, []byte(in)) }

	// C0 executes inside a CSI and the CSI still dispatches.
	got := ev(refDEC, "\x1b[6\rn")
	require.Equal(t, refExecute, got[0].kind)
	require.Equal(t, byte('\r'), got[0].b)
	require.Equal(t, refCSI, got[1].kind)
	require.Equal(t, byte('n'), got[1].final)

	// DEL is ignored in a CSI.
	got = ev(refDEC, "\x1b[6\x7fn")
	require.Len(t, got, 1)
	require.Equal(t, "6", got[0].params)

	// ESC abandons a CSI head; the second one dispatches.
	got = ev(refDEC, "\x1b[6\x1b[5n")
	require.Len(t, got, 1)
	require.Equal(t, "5", got[0].params)

	// ESC-intermediate: C0 executes, then the ESC dispatch.
	got = ev(refDEC, "\x1b(\rB")
	require.Equal(t, refExecute, got[0].kind)
	require.Equal(t, refESC, got[1].kind)
	require.Equal(t, "(", got[1].inter)

	// An OSC ended by ESC dispatches; one ended by CAN does not.
	require.Equal(t, refOSC, ev(refDEC, "\x1b]0;t\x1b[m")[0].kind)
	require.Equal(t, byte(0x1b), ev(refDEC, "\x1b]0;t\x1b[m")[0].end)
	for _, e := range ev(refDEC, "\x1b]0;t\x18") {
		require.NotEqual(t, refOSC, e.kind)
	}

	// BEL is DCS payload under DEC, a string end under kitty. The header's
	// final byte (q) is not payload.
	dcs := ev(refDEC, "\x1bPq#0\x07X\x1b\\")[0]
	require.Equal(t, byte('q'), dcs.final)
	require.Equal(t, "#0\x07X", dcs.data)
	require.Equal(t, byte(0x07), ev(refKitty, "\x1bPq#0\x07X\x1b\\")[0].end)

	// A DCS header ignores C0, DEL and 0xA0–0xFF, and still hooks.
	got = ev(refDEC, "\x1bP1\r\x7f\xa0;0+\nq#0\x1b\\")
	require.Equal(t, refEvent{kind: refDCS, params: "1;0", inter: "+", final: 'q', data: "#0", end: '\\'}, refSemantic(got[0]))

	// APC control bytes are payload, not ignored.
	require.Equal(t, "\nGa=q", ev(refDEC, "\x1b_\nGa=q\x1b\\")[0].data)

	// CSI-ignore ends at a final byte; DCS-ignore runs to the string's end.
	require.Equal(t, refPrint, ev(refDEC, "\x1b[1$2qX")[0].kind) // the CSI is ignored, X prints
	for _, e := range ev(refDEC, "\x1bP$1qhidden\x1b\\X") {
		require.NotEqual(t, byte('h'), e.b, "DCS-ignore swallows its payload")
	}

	// Kitty keeps an OSC open past CAN and answers its query.
	got = ev(refKitty, "\x1b]4;0;\x18;1;?\x07")
	require.Len(t, got, 1)
	require.True(t, refQuery(refKitty, got[0]))
}

// How strings end under each model, past what the conformance test pins: ST
// under every model, tmux's DCS rules, kitty's payload, 8-bit bytes, and the
// raw counts behind refHeldAtEnd.
func TestRefParse_StringEnds(t *testing.T) {
	ev := func(mode refMode, in string) []refEvent { return refParse(mode, []byte(in)) }

	// ESC \ ends a string as ST under every model, and records '\' as its
	// end. The '\' then dispatches as a lone ST, which has no effect.
	for _, mode := range []refMode{refDEC, refKitty, refTmux} {
		got := ev(mode, "\x1b]0;t\x1b\\\x1bPq#0\x1b\\")
		require.Len(t, got, 4, "%v", mode)
		require.Equal(t, refOSC, got[0].kind, "%v", mode)
		require.Equal(t, byte('\\'), got[0].end, "%v", mode)
		require.Equal(t, refEvent{kind: refESC, final: '\\'}, got[1], "%v", mode)
		require.Equal(t, refDCS, got[2].kind, "%v", mode)
		require.Equal(t, "#0", got[2].data, "%v", mode)
		require.Equal(t, byte('\\'), got[2].end, "%v", mode)
	}

	// Under DEC the first ESC ends the string, so ESC ESC \ is no ST.
	require.Equal(t, byte(0x1b), ev(refDEC, "\x1b]0;t\x1b\x1b\\")[0].end)

	// tmux keeps a DCS open past CAN, SUB, BEL and ESC x. ESC x adds x
	// alone, and ESC ESC adds one ESC, so a doubled ESC before '\' isn't ST.
	got := ev(refTmux, "\x1bPtmux;\x1b\x1b[6n\x18\x1a\x07\x1bx\x1b\x1b\\\x1b\\")
	require.Len(t, got, 2)
	require.Equal(t, byte('t'), got[0].final)
	require.Equal(t, "mux;\x1b[6n\x18\x1a\x07x\x1b\\", got[0].data)
	require.Equal(t, byte('\\'), got[0].end)

	// tmux leaves every other string to DEC: CAN still discards an OSC.
	for _, e := range ev(refTmux, "\x1b]0;t\x18") {
		require.NotEqual(t, refOSC, e.kind)
	}

	// kitty keeps every string open past CAN, SUB and an ESC that isn't ST,
	// all of them payload, and BEL ends any string.
	got = ev(refKitty, "\x1b_Ga=q\x1b[6n\x18\x07")
	require.Len(t, got, 1)
	require.Equal(t, refAPC, got[0].kind)
	require.Equal(t, "Ga=q\x1b[6n\x18", got[0].data)
	require.Equal(t, byte(0x07), got[0].end)

	// kitty reads the byte after a non-ST ESC afresh: in ESC ESC \ the first
	// ESC is payload and the second is ST.
	got = ev(refKitty, "\x1b]0;t\x1b\x1b\\")
	require.Len(t, got, 2)
	require.Equal(t, "0;t\x1b", got[0].data)
	require.Equal(t, byte('\\'), got[0].end)

	// 8-bit bytes print in ground and are payload in strings.
	got = ev(refDEC, "\xc3\xa9\x1b_\x9c\x1b\\")
	require.Equal(t, refEvent{kind: refPrint, b: 0xc3}, got[0])
	require.Equal(t, refEvent{kind: refPrint, b: 0xa9}, got[1])
	require.Equal(t, "\x9c", got[2].data)

	// held and numHeld count raw bytes, the ignored CR included, though the
	// OSC state drops it from the data.
	osc := ev(refDEC, "\x1b]1\r1;?\x07")[0]
	require.Equal(t, "11;?", osc.data)
	require.Equal(t, 7, osc.held)
	require.Equal(t, 5, osc.numHeld)

	// A CR before the ']' is executed by the escape state, before the OSC
	// begins, so neither counts it, and a DEL there is ignored just the same.
	osc = ev(refDEC, "\x1b\r\x7f]11;?\x07")[1]
	require.Equal(t, "11;?", osc.data)
	require.Equal(t, 6, osc.held)
	require.Equal(t, 4, osc.numHeld)
}

func TestRefQuery_Families(t *testing.T) {
	for _, q := range []string{"\x1b[?2026$p", "\x1b[06n", "\x1b[0;1c", "\x1b[;c",
		"\x1b[?996n", "\x1b[14;2t", "\x1b[?4m", "\x1b[?1;3;256S", "\x1b[?u", "\x1b[?1u",
		"\x1b[01x", "\x1bZ", "\x1b]11;?\x07", "\x1b]4;0;rgb:0/0/0;1;?\x07",
		"\x1b]52;c;?\x07", "\x1b]50;?\x07", "\x1b]60\x07"} {
		evs := refParse(refDEC, []byte(q))
		require.Len(t, evs, 1, "%q", q)
		require.True(t, refQuery(refDEC, evs[0]), "%q", q)
	}
	// A DCS reports its event and then a lone ST, so the query is the first.
	for _, q := range []string{"\x1bP$qm\x1b\\", "\x1bP+q544e\x1b\\", "\x1bP+Q616c\x1b\\", "\x1bP1$qm\x1b\\"} {
		for _, mode := range []refMode{refDEC, refKitty, refTmux} {
			evs := refParse(mode, []byte(q))
			require.Equal(t, refDCS, evs[0].kind, "%q under %v", q, mode)
			require.True(t, refQuery(mode, evs[0]), "%q under %v", q, mode)
		}
	}
	// So does an APC, and a graphics query reads the same under every mode,
	// latched at a BEL included: kitty ends the string at the BEL, and the
	// other two find the pair before it.
	for _, q := range []string{"\x1b_Ga=q\x1b\\", "\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\",
		"\x1b_Gi=1,a=q\x07X;\x1b\\"} {
		for _, mode := range []refMode{refDEC, refKitty, refTmux} {
			evs := refParse(mode, []byte(q))
			require.Equal(t, refAPC, evs[0].kind, "%q under %v", q, mode)
			require.True(t, refQuery(mode, evs[0]), "%q under %v", q, mode)
		}
	}
	// A later BEL latches too, under DEC and tmux. kitty has ended the string
	// at the first BEL, where nothing asks, and reads the rest as text.
	later := "\x1b_Gi=1\x07,a=q\x07X;\x1b\\"
	require.True(t, refQuery(refDEC, refParse(refDEC, []byte(later))[0]))
	require.True(t, refQuery(refTmux, refParse(refTmux, []byte(later))[0]))
	for _, e := range refParse(refKitty, []byte(later)) {
		require.False(t, refQuery(refKitty, e), "%v", e)
	}
	for _, c := range []string{"\x1b[?6c", "\x1b[>4n", "\x1b[!p", "\x1b[2 q",
		"\x1b[22;0t", "\x1b[>4;2m", "\x1b[3S", "\x1b[>1u", "\x1b[2*x",
		"\x1b[38:2::255:0:0m", "\x1b(B", "\x1b]4;1;rgb:ff/00/00\x07",
		"\x1b]52;c;SGVsbG8=\x07", "\x1bP0;1;0q#0\x1b\\", "\x1bP+p78\x1b\\",
		"\x1bP1$r0m\x1b\\", "\x1bP?$qm\x1b\\", "\x1bP$$qm\x1b\\", "\x1bP$Qm\x1b\\",
		"\x1bP$1qm\x1b\\", "\x1bPtmux;\x1b\x1b[31m\x1b\\"} {
		for _, e := range refParse(refDEC, []byte(c)) {
			require.False(t, refQuery(refDEC, e), "%q", c)
		}
	}
	// Graphics commands that ask nothing under any mode: a transmit, a pair
	// after the ';' (payload), a control byte in the pair, a BEL whose prefix
	// asks nothing, and APCs that aren't graphics commands at all.
	for _, c := range []string{"\x1b_Ga=T,f=100,i=1;AAAA\x1b\\", "\x1b_Ga=T;a=q\x1b\\", "\x1b_Ga=q\r\x1b\\",
		"\x1b_Gi=1\x07a=q;\x1b\\", "\x1b_\nGa=q\x1b\\", "\x1b_ Ga=q\x1b\\"} {
		for _, mode := range []refMode{refDEC, refKitty, refTmux} {
			for _, e := range refParse(mode, []byte(c)) {
				require.False(t, refQuery(mode, e), "%q under %v", c, mode)
			}
		}
	}
}

// refHeldAtEnd's APC arm at its edges: an APC is held until its first byte,
// and a graphics command until a ';' or a BEL that asks decides it, within 256
// raw bytes from its ESC.
func TestRefHeldAtEnd_APC(t *testing.T) {
	held := func(in string) bool { return refHeldAtEnd(refParse(refDEC, []byte(in))[0]) }
	require.True(t, held("\x1b_\x18"), "an empty APC")
	require.True(t, held("\x1b_Gi=1\x07a=T\x18"), "a BEL that asks nothing")
	require.True(t, held("\x1b_G"+strings.Repeat("i", 253)+"\x18"), "256 raw bytes")
	require.False(t, held("\x1b_G"+strings.Repeat("i", 254)+"\x18"), "257 raw bytes")
	require.False(t, held("\x1b_Ga=T;\x18"), "decided at its ';'")
	require.False(t, held("\x1b_Gi=1,a=q\x07\x18"), "decided at a BEL")
	require.False(t, held("\x1b_x\x18"), "not a graphics command")
	require.False(t, held("\x1b^\x18"), "a PM")
}

// refCheck catches a splice: the filter's output loses text that the input
// showed, though no query remains.
func TestRefCheck_CatchesASplice(t *testing.T) {
	splice := func(string) string { return "\x1b]0;thello\x18" }
	require.NotEmpty(t, refCheck("\x1b]0;t\x1b[6nhello", splice))
}

// The oracle accepts every transformation the filter is meant to make. Each
// out is filter(in + CAN), written out by hand from the filter's rules.
func TestRefCheck_AcceptsKnownTransformations(t *testing.T) {
	zeros, title := strings.Repeat("0", 31), strings.Repeat("t", 300)
	for _, c := range []struct{ in, out string }{
		{"\x1b]0;t\x1b[6nhello", "hello\x18"},                                         // held OSC ended by ESC: policy drop
		{"\x1b[1$2\x1b[6nX", "\x1b[1$2\x1b\x18X\x18"},                                 // CSI-ignore closed
		{"\x1b[" + zeros + "\x1b[6nhello", "\x1b[" + zeros + "\x1b\x18hello\x18"},     // over-bound CSI closed
		{"\x1b]0;" + title + "\x1b[6nhello", "\x1b]0;" + title + "\x1b\x18hello\x18"}, // over-bound OSC closed
		{"\x1b[6\rn", "\r\x18"},                                                       // C0 forwarded early
		{"\x1b[1\x7fm", "\x1b[1m\x18"},                                                // DEL dropped
		{"\x1b(\rB", "\r\x1b(B\x18"},                                                  // C0 in an ESC-intermediate
		{"\x1bPq\x07\x1b]4;0;\x18;1;?\x07", "\x1bPq\x07\x1b\x18;1;?\x07\x18"},         // cancel with an obligation
		{"\x1b]10;?", "\x18"},                                                         // held query resolved by the CAN
		{"\x1bX0\x1b\x7f\\", "\x1bX0\x1b\\\x18"},                                      // DEL after a string's ESC dropped: it ends at the ESC either way
		{"\x1b]0;t\x1b\x7f\\", "\x1b\\\x18"},                                          // but an OSC that ESC ends is still held and dropped by policy
		// Same events under DEC (the CRs are ignored), different holds: the
		// first trips the 8-byte number guard and passes, the second stays
		// held and is dropped. Only numHeld tells them apart.
		{"\x1b]0" + strings.Repeat("\r", 9) + ";t\x1b[6nhello", "\x1b]0" + strings.Repeat("\r", 9) + ";t\x1b\x18hello\x18"},
		{"\x1b]0;" + strings.Repeat("\r", 9) + "t\x1b[6nhello", "hello\x18"},
		{"\x1bP1\r;0q#0\x1b\\", "\x1bP1;0q#0\x1b\\\x18"},                         // ignored CR dropped from a passed header
		{"ABC\x1bP$\rqm\x1b\\X", "ABCX\x18"},                                     // DCS query with a C0 in its header
		{"\x1bP+q544e\x18X", "\x18X\x18"},                                        // drop ended by CAN
		{"\x1bP$1qhidden\x1b[6nVISIBLE", "\x1bP$1qhidden\x1b\x18VISIBLE\x18"},    // DCS-ignore closed
		{"\x1b_Ga=T\x18X", "\x18X\x18"},                                          // held APC cancelled: policy drop
		{"\x1b_Gi=1,a=q\x07X;\x1b\\", "\x18"},                                    // query latched at a BEL
		{"\x1b_Ga=T,f=100,i=1;AAAA\x1b\\", "\x1b_Ga=T,f=100,i=1;AAAA\x1b\\\x18"}, // transmit passes
		{"\x1b_\nGa=q\x1b\\", "\x1b_\nGa=q\x1b\\\x18"},                           // not a G command
	} {
		out := c.out
		require.Empty(t, refCheck(c.in, func(string) string { return out }), "%q", c.in)
	}
}
