package io

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
)

// maxSequenceBytes caps how much of an in-progress mode sequence the tracker
// will hold. Real mode sequences are a handful of bytes; anything longer is
// either not a mode sequence or is a stream that will never terminate it, and
// neither is worth unbounded memory in a process whose entire point is running
// unattended.
const maxSequenceBytes = 64

// maxStringBytes caps the string sequences the same way, but higher: an OSC,
// DCS, PM, APC or SOS legitimately carries a payload a mode sequence never
// would -- a hyperlink's URL, an OSC 52 clipboard, a terminfo reply -- and
// cutting one short replays a string the joiner's terminal never sees the end
// of. It is still a cap, because a string whose terminator never arrives would
// otherwise let the stream pick the snapshot's size.
const maxStringBytes = 4096

// kittyStackDepth bounds how much of each screen's kitty keyboard stack is
// kept for replay: kitty's own depth, which makes room for a push onto a full
// stack by dropping the oldest entry. The protocol leaves the depth to the
// terminal, though, so the stack's full depth is counted apart; see keyStack.
const kittyStackDepth = 8

// keyStack is one screen's kitty keyboard stack: depth entries in all, of
// which the newest, up to kittyStackDepth, are kept for replay, bottom first.
// A terminal holds at most depth of them -- fewer when its stack is shallower
// and dropped the oldest -- so depth is what a pop of the whole stack pops: a
// pop past the bottom empties a stack, which is where a terminal starts.
//
// The replay is bounded and the count is not, on purpose. A terminal whose
// stack is deeper than kitty's keeps entries this does not, and a joiner given
// the replay finds them missing only once the session pops eight entries past
// where it joined. Keeping every entry instead would let the stream decide how
// much memory an unattended host spends, which nothing else here does.
type keyStack struct {
	entries []int
	depth   int
}

func (k *keyStack) push(flags int) {
	if len(k.entries) == kittyStackDepth {
		k.entries = append(k.entries[:0], k.entries[1:]...)
	}
	k.entries = append(k.entries, flags)
	k.depth++
}

// pop takes the newest n entries off, replayed or not.
func (k *keyStack) pop(n int) {
	n = min(n, k.depth)
	k.depth -= n
	k.entries = k.entries[:len(k.entries)-min(n, len(k.entries))]
}

// top is the entry a set applies to. kitty sets an empty stack's bottom entry
// and counts it as pushed, so a pop takes it back off; and a set on an entry
// the replay no longer holds makes that entry's new value the one to replay.
func (k *keyStack) top() *int {
	if len(k.entries) == 0 {
		k.entries = append(k.entries, 0)
		k.depth = max(k.depth, 1)
	}
	return &k.entries[len(k.entries)-1]
}

// restorable lists the DEC private modes worth putting a reattaching terminal
// back into, mapped to the value a terminal holds them at before anything has
// touched them. Everything else is ignored, which is what keeps both the
// tracked set and the emitted snapshot bounded by a constant rather than by
// whatever the command decided to emit.
//
// The defaults are what let Snapshot stay quiet about state a joiner is
// already in: it joins with a terminal at its own defaults, so replaying them
// back to it is bytes that say nothing.
//
// The three alternate-screen modes are listed here because they are worth
// restoring, but they are not kept in decPrivate: see altScreenModes.
//
// 1048 is not listed: it saves the cursor on set and restores it on reset, as
// DECSC and DECRC do, and leaves the terminal in no mode. Replayed, it would
// save wherever a terminal's cursor happens to be, and undone, it would move
// the cursor to wherever the session last saved it.
var restorable = map[int]bool{
	1:    false, // DECCKM, application cursor keys
	7:    true,  // DECAWM, autowrap
	25:   true,  // DECTCEM, cursor visibility
	47:   false, // legacy alternate screen
	1000: false, // X11 mouse: button events
	1002: false, // mouse: button + drag
	1003: false, // mouse: any motion
	1004: false, // focus reporting
	1005: false, // UTF-8 mouse encoding
	1006: false, // SGR mouse encoding
	1047: false, // alternate screen
	1049: false, // alternate screen + cursor, the common one
	2004: false, // bracketed paste
}

// restorableModes returns the tracked mode numbers. It exists for tests.
func restorableModes() []int {
	out := make([]int, 0, len(restorable))
	for n := range restorable {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// ModeTracker watches terminal output and remembers the modes set on it, so a
// reader joining later can be put into the same modes before it is handed the
// replay ring.
//
// It is deliberately not a terminal emulator: it reconstructs no screen and no
// cursor position. Anything it does not recognise passes through unrecorded.
//
// Not safe for concurrent use. MultiWriter owns one and only touches it under
// writeMu.
type ModeTracker struct {
	decPrivate map[int]bool

	// A terminal has one alternate screen, not one per mode that reaches it,
	// so it is one boolean plus the mode that last entered it. altVia only
	// means anything while altScreen is set; it is what the snapshot replays,
	// because a joiner told to leave by a mode it never entered through is a
	// joiner on the wrong screen.
	altScreen bool
	altVia    int // 47, 1047 or 1049

	// Each screen buffer has its own margins, so the two DECSTBMs are kept
	// apart: replaying the alternate screen's to a joiner sitting on the
	// normal one, or the reverse, confines it to rows nothing set.
	mainRegion []byte // last DECSTBM on the normal screen, verbatim
	altRegion  []byte // last DECSTBM on the alternate screen, verbatim

	charsetG0 []byte // last "ESC ( X", verbatim

	// The kitty keyboard protocol's flag stacks. The protocol gives each
	// screen buffer its own, so that a full-screen program can push what it
	// wants without knowing what the shell beneath it had. A screen switch
	// clears neither -- kitty only swaps which one is current -- so a program
	// that leaves the alternate screen without popping finds its flags there
	// again when it comes back.
	mainKeys keyStack
	altKeys  keyStack

	// modifyOtherKeys is the last sequence that moved xterm's modifyOtherKeys
	// -- the older way of asking for keys a terminal otherwise folds together
	// -- off its initial value, verbatim, or nil while it is there. Kept as
	// written rather than as a level because the level is not all of it: an
	// explicit 0 is not the initial value, which xterm's resource may make
	// something else; CSI > 4 n is a value no level spells; and a mask may
	// ride on the resource, as xterm's documentation has it, or on the value,
	// as its parser does. A joiner replayed the same bytes does whatever the
	// session's own terminal did with them.
	modifyOtherKeys []byte

	// partial is the raw bytes of the sequence the parser is currently
	// inside, ESC included. The tracker is fed the ring's evictions, so the
	// trim boundary can fall anywhere -- including mid-sequence, leaving the
	// ring starting with a sequence's tail and this holding its head. See
	// Snapshot, which replays it so the two halves meet.
	partial []byte

	seq      []byte
	overflow bool // current sequence ran past its cap; discard it
	state    modeState
	kind     stringKind // which string sequence msString is inside
}

type modeState int

const (
	msNormal modeState = iota
	msEsc
	msCSI
	msCharset
	msString    // inside an OSC, DCS, PM, APC or SOS payload
	msStringEsc // an ESC inside one: the next byte says whether it ended
)

// stringKind is which string sequence the parser is inside. It is tracked for
// one decision: BEL terminates an OSC and nothing else -- xterm accepts it
// there, and for a DCS, PM, APC or SOS only ST will do.
//
// CAN (0x18) and SUB (0x1a) end a string too, as they end every other
// sequence; step handles them before any state does.
//
// The 8-bit C1 introducers (0x9b for CSI, 0x9d for OSC, 0x90 for DCS and the
// rest) are out of scope. The tracker decodes no character set, and in the
// UTF-8 a session actually emits those bytes are continuation bytes of
// ordinary characters far more often than they are introducers: honouring them
// would swallow real text to catch a sequence almost nothing sends. A program
// that does send them goes unrecorded, like anything else the tracker does not
// recognise.
type stringKind int

const (
	skNone stringKind = iota
	skOSC             // ESC ]
	skDCS             // ESC P
	skPM              // ESC ^
	skAPC             // ESC _
	skSOS             // ESC X
)

func NewModeTracker() *ModeTracker {
	return &ModeTracker{decPrivate: map[int]bool{}}
}

// bufferedBytes reports the parser's current accumulation: both the CSI
// parameters it is collecting and the raw partial of the same sequence, which
// is what a test asking whether an unterminated sequence can grow the parser
// wants to know. It exists for tests.
func (m *ModeTracker) bufferedBytes() int { return len(m.seq) + len(m.partial) }

// Write consumes output and records mode changes. It never fails and never
// alters the stream; callers use it as an observer, not a filter.
func (m *ModeTracker) Write(p []byte) (int, error) {
	for _, b := range p {
		m.step(b)
	}
	return len(p), nil
}

func (m *ModeTracker) step(b byte) {
	if (b == 0x18 || b == 0x1a) && m.state != msNormal {
		// CAN or SUB: whatever sequence was in progress is cancelled, from
		// any state, as the DEC parser terminals implement has it, and what
		// follows prints. Kept open, its text would be recorded as the
		// sequence's payload and replayed as a partial by Snapshot.
		m.state = msNormal
		m.kind = skNone
		m.reset()
		m.closePartial()
		return
	}
	switch m.state {
	case msNormal:
		if b == 0x1b {
			m.state = msEsc
			m.reset()
			m.openPartial()
		}
	case msEsc:
		switch b {
		case 0x1b:
			// ESC ESC: restart rather than fall out of sync.
			m.reset()
			m.openPartial()
		case '[':
			m.state = msCSI
			m.reset()
			m.partial = append(m.partial, b)
		case '(':
			m.state = msCharset
			m.partial = append(m.partial, b)
		case ']':
			m.startString(skOSC, b)
		case 'P':
			m.startString(skDCS, b)
		case '^':
			m.startString(skPM, b)
		case '_':
			m.startString(skAPC, b)
		case 'X':
			m.startString(skSOS, b)
		case 'c':
			// RIS, a hard reset: the terminal is back at power-on, so
			// everything recorded before it is no longer true of it.
			m.resetToDefaults()
			m.state = msNormal
			m.closePartial()
		default:
			m.state = msNormal
			m.closePartial()
		}
	case msCharset:
		switch {
		case b == 0x1b:
			// The designation was abandoned. Recording the ESC as the
			// designator both loses whatever sequence it opened and leaves
			// the snapshot ending mid-escape.
			m.state = msEsc
			m.reset()
			m.openPartial()
		case b < 0x30 || b > 0x7e:
			// Not a designator at all; no charset was selected.
			m.state = msNormal
			m.closePartial()
		default:
			m.charsetG0 = []byte{0x1b, '(', b}
			m.state = msNormal
			m.closePartial()
		}
	case msCSI:
		if b >= 0x40 && b <= 0x7e {
			if !m.overflow {
				m.finishCSI(b)
			}
			m.state = msNormal
			m.reset()
			m.closePartial()
			return
		}
		if b == 0x1b {
			// An ESC inside a CSI means the sequence was abandoned. Recover
			// rather than swallow everything that follows.
			m.state = msEsc
			m.reset()
			m.openPartial()
			return
		}
		if len(m.seq) >= maxSequenceBytes {
			// Stop accumulating but stay in msCSI, so the sequence's real
			// terminator still returns the parser to normal.
			m.overflow = true

			// An overflowed sequence is never replayed. The tracker has
			// already given up on completing it, so what it holds is a
			// fragment that would print on the joiner's terminal, and
			// keeping it would let the stream set the snapshot's size.
			m.closePartial()
			return
		}
		m.seq = append(m.seq, b)
		m.partial = append(m.partial, b)
	case msString:
		switch {
		case b == 0x1b:
			// Either the ST that ends the string or the start of a sequence
			// that abandons it; the next byte decides. Either way the ESC is
			// part of what has been seen, so it is recorded: a trim boundary
			// here leaves the ring holding the byte that completes it.
			m.appendString(b)
			m.state = msStringEsc
		case b == 0x07 && m.kind == skOSC:
			// BEL is a terminator here and nowhere else; see stringKind.
			m.endString()
		default:
			m.appendString(b)
		}
	case msStringEsc:
		if b == '\\' {
			// ST, which ends any of them.
			m.endString()
			return
		}
		// Anything else and the string was abandoned, which is how a
		// terminal's own parser reads it: the ESC left the string and this
		// byte opens a new sequence. Resync on it rather than swallow
		// everything that follows, as an ESC inside a CSI does.
		m.state = msEsc
		m.kind = skNone
		m.reset()
		m.openPartial()
		m.step(b)
	}
}

// startString enters a string sequence, whose payload the tracker consumes
// without interpreting it: those bytes are a title, a URL or a clipboard, not
// commands, and the terminal they are bound for will not act on them either.
// The raw bytes are the partial, so a joiner attaching mid-string is replayed
// the string from its introducer and its terminal completes it from the ring.
func (m *ModeTracker) startString(kind stringKind, introducer byte) {
	m.state = msString
	m.kind = kind
	m.reset()
	m.partial = append(m.partial, introducer)
}

// appendString records a byte of the string in progress, up to the bound. Past
// it the parser keeps reading -- only the terminator ends a string, so it must
// still be looked for -- but the partial is dropped and not reopened for this
// sequence, the bargain an overflowed CSI already makes.
func (m *ModeTracker) appendString(b byte) {
	if m.overflow {
		return
	}
	if len(m.partial) >= maxStringBytes {
		m.overflow = true
		m.closePartial()
		return
	}
	m.partial = append(m.partial, b)
}

// endString leaves a string at its terminator, which is the one place the
// payload stops being something a joiner still needs.
func (m *ModeTracker) endString() {
	m.state = msNormal
	m.kind = skNone
	m.reset()
	m.closePartial()
}

func (m *ModeTracker) reset() {
	m.seq = m.seq[:0]
	m.overflow = false
}

// openPartial starts recording a sequence at its ESC, replacing whatever the
// previous one was: an ESC arriving mid-sequence abandons that sequence, and
// an abandoned head is not one the ring's first bytes will complete.
func (m *ModeTracker) openPartial() {
	m.partial = append(m.partial[:0], 0x1b)
}

// closePartial drops the recorded sequence, which is what every way out of one
// -- finished, abandoned or not a sequence after all -- calls for.
func (m *ModeTracker) closePartial() {
	m.partial = m.partial[:0]
}

// resetToDefaults forgets everything recorded, which is what a terminal does
// to itself on RIS: it comes back at power-on, on the normal screen.
func (m *ModeTracker) resetToDefaults() {
	clear(m.decPrivate)
	m.altScreen = false
	m.altVia = 0
	m.mainRegion = nil
	m.altRegion = nil
	m.charsetG0 = nil
	m.mainKeys = keyStack{}
	m.altKeys = keyStack{}
	m.modifyOtherKeys = nil
}

// softResetModes are the tracked DEC private modes DECSTR returns to their
// default under the model this tracker implements: xterm's soft reset,
// verified against xterm's ReallyReset. tmux has no handler for CSI ! p at
// all, so it ignores DECSTR and resets nothing -- it keeps this set, and
// everything else the tracker records -- the screen buffer, the mouse modes,
// focus reporting and bracketed paste included -- across it too.
var softResetModes = []int{1, 7, 25} // DECCKM, DECAWM, DECTCEM

// softReset applies DECSTR. It is not RIS with a different spelling: it leaves
// the screen buffer alone, which is why a full-screen program can issue one on
// the alternate screen without dropping back to the normal one.
func (m *ModeTracker) softReset() {
	for _, n := range softResetModes {
		delete(m.decPrivate, n)
	}
	// The margins of the buffer that is showing, and only that one: the other
	// buffer's are not the ones being reset.
	if m.altActive() {
		m.altRegion = nil
	} else {
		m.mainRegion = nil
	}
	m.charsetG0 = nil
	// kitty's soft reset clears both keyboard stacks, as its hard reset does.
	// The protocol is kitty's, so its reset is the one to follow here.
	m.mainKeys = keyStack{}
	m.altKeys = keyStack{}
	// And xterm's puts the key modifiers back to their initial values, mask
	// and all (ReallyReset's modify_now and ignore_now, outside its "full"
	// branch).
	m.modifyOtherKeys = nil
}

// altScreenModes are the DEC private modes that put the alternate screen
// buffer on show. They are three spellings of one piece of state on a real
// terminal, so the tracker keeps one: "\x1b[?47h\x1b[?1049l" returns to the
// normal screen on tmux and on xterm, and tracking the two modes apart had
// the snapshot replay a "?47h" the session was no longer in.
var altScreenModes = map[int]bool{47: true, 1047: true, 1049: true}

func (m *ModeTracker) altActive() bool { return m.altScreen }

func (m *ModeTracker) finishCSI(final byte) {
	params := m.seq

	switch final {
	case 'h', 'l':
		// Only DEC private modes, marked by a leading '?'.
		if len(params) == 0 || params[0] != '?' {
			return
		}
		wasAlt := m.altActive()
		set := final == 'h'
		for _, field := range bytes.Split(params[1:], []byte{';'}) {
			n, err := strconv.Atoi(string(field))
			if err != nil {
				continue
			}
			if _, ok := restorable[n]; !ok {
				continue
			}
			if altScreenModes[n] {
				m.altScreen = set
				if set {
					// Whichever mode entered last is the one to replay, since
					// it is the one the session's own reset will match.
					m.altVia = n
				}
				continue
			}
			m.decPrivate[n] = set
		}
		if m.altActive() != wasAlt {
			// A fresh alternate screen has no margins, and the ones it had
			// are gone the moment it is left.
			m.altRegion = nil
		}
	case 'r':
		// DECSTBM, stored verbatim including a bare reset, against whichever
		// screen buffer is showing.
		seq := make([]byte, 0, len(params)+3)
		seq = append(seq, 0x1b, '[')
		seq = append(seq, params...)
		seq = append(seq, 'r')
		if m.altActive() {
			m.altRegion = seq
		} else {
			m.mainRegion = seq
		}
	case 'p':
		// DECSTR, a soft reset. Its parameter is the intermediate '!', which
		// is what separates it from the several other CSI ... p sequences.
		if len(params) == 1 && params[0] == '!' {
			m.softReset()
		}
	case 'u':
		m.kittyKeyboard(params)
	case 'm':
		// XTMODKEYS is marked by a leading '>'. Without one this is SGR,
		// which is attributes, and attributes are not tracked.
		if len(params) > 0 && params[0] == '>' {
			m.xtmodkeys(params[1:])
		}
	case 'n':
		// XTMODKEYS's other form: CSI > 4 n disables modifyOtherKeys, which
		// is xterm's resource value -1, and no CSI > 4 ; v m can spell it.
		if string(params) == ">4" {
			m.modifyOtherKeys = []byte("\x1b[>4n")
		}
	}
}

// keys returns the kitty keyboard stack of the screen that is showing.
func (m *ModeTracker) keys() *keyStack {
	if m.altActive() {
		return &m.altKeys
	}
	return &m.mainKeys
}

// kittyKeyboard applies one of the kitty keyboard protocol's stack operations
// to the screen that is showing: CSI > flags u pushes, CSI < n u pops n, and
// CSI = flags ; mode u sets the top entry. CSI ? u asks the terminal for its
// flags and changes nothing, and a bare CSI u is not the protocol's at all:
// it restores the cursor, as SCORC.
func (m *ModeTracker) kittyKeyboard(params []byte) {
	if len(params) == 0 {
		return
	}
	stack := m.keys()
	switch params[0] {
	case '>':
		flags, ok := csiNumber(params[1:], 0)
		if !ok {
			return
		}
		stack.push(flags)
	case '<':
		// Only an omitted count is one: kitty pops nothing for an explicit
		// 0.
		n, ok := csiNumber(params[1:], 1)
		if !ok {
			return
		}
		stack.pop(n)
	case '=':
		fields := bytes.Split(params[1:], []byte{';'})
		if len(fields) > 2 {
			// kitty takes at most two parameters for a set and ignores more.
			return
		}
		flags, ok := csiNumber(fields[0], 0)
		if !ok {
			return
		}
		mode := 1
		if len(fields) > 1 {
			if mode, ok = csiNumber(fields[1], 1); !ok {
				return
			}
		}
		if mode < 1 || mode > 3 {
			return
		}
		top := stack.top()
		switch mode {
		case 1:
			*top = flags
		case 2:
			*top |= flags
		case 3:
			*top &^= flags
		}
	}
}

// xtmodkeys applies XTMODKEYS, CSI > resource ; value m, of which only
// modifyOtherKeys, resource 4, is tracked. A value left out -- vim leaves with
// CSI > 4 ; m -- resets it to the initial value, as does a sequence that names
// no resource at all; anything else is kept verbatim (see modifyOtherKeys).
// Each field may carry one subparameter, a mask; a field that is not a number,
// or one with more than one subparameter, makes the sequence one xterm ignores
// too.
func (m *ModeTracker) xtmodkeys(params []byte) {
	if len(params) == 0 {
		m.modifyOtherKeys = nil
		return
	}
	fields := bytes.Split(params, []byte{';'})
	resource, resourceMask, _ := bytes.Cut(fields[0], []byte{':'})
	if n, ok := csiNumber(resource, -1); !ok || n != 4 {
		return
	}
	var value, valueMask []byte
	if len(fields) > 1 {
		value, valueMask, _ = bytes.Cut(fields[1], []byte{':'})
	}
	for _, part := range [][]byte{resourceMask, value, valueMask} {
		if _, ok := csiNumber(part, 0); !ok {
			return
		}
	}
	if len(resourceMask) == 0 && len(value) == 0 && len(valueMask) == 0 {
		m.modifyOtherKeys = nil
		return
	}
	m.modifyOtherKeys = append(append(append(m.modifyOtherKeys[:0], "\x1b[>"...), params...), 'm')
}

// csiNumber parses one CSI parameter: def when it is empty, and not ok when it
// is not a number a terminal would take -- negative, too wide, or with
// anything else in it.
func csiNumber(field []byte, def int) (int, bool) {
	if len(field) == 0 {
		return def, true
	}
	n, err := strconv.Atoi(string(field))
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// kittyPushes is the stack's replayed entries as pushes, bottom first, which
// leaves a terminal with the stack it was replayed from.
func kittyPushes(out []byte, stack keyStack) []byte {
	for _, flags := range stack.entries {
		out = fmt.Appendf(out, "\x1b[>%du", flags)
	}
	return out
}

// kittyPop is one pop of the whole stack. A pop that runs past the bottom
// empties the stack, which is where a terminal starts, so popping the depth
// recorded is safe on a terminal that holds fewer entries than that.
func kittyPop(out []byte, stack keyStack) []byte {
	if stack.depth == 0 {
		return out
	}
	return fmt.Appendf(out, "\x1b[<%du", stack.depth)
}

// Restore returns the bytes that put a terminal this tracker has been
// watching back where it started. It is Snapshot's opposite: Snapshot is for
// the terminal joining a session, this is for the terminal leaving one.
//
// A terminal is left in whatever modes the session put it in, and restoring
// the termios settings says nothing about them: a full-screen program that
// was on screen when its viewer detached leaves that viewer's shell drawing
// on the alternate screen, with no cursor, with the mouse reporting clicks as
// input, and confined to the rows the program had chosen for itself. None of
// that is the shell's doing and none of it goes away on its own.
//
// Only what was actually changed is undone, so a session that never touched a
// mode produces nothing at all — the same property Snapshot has, and the
// reason this is derived from the stream rather than being a fixed list of
// resets sent on the way out. Attributes are not tracked and so are not reset
// here.
//
// "Where it started" means the terminal's power-on defaults, not the state
// the caller's own terminal was in before the attachment. That state is not
// knowable without asking the terminal for it — a DECRQM round-trip per mode,
// before attaching, racing the user's keystrokes on the same stdin, and
// unanswered by terminals that do not implement it. tmux, which has the same
// problem on detach, resets to defaults too rather than asking.
//
// It costs less than it sounds like. At a shell prompt — which is what
// launches a CLI — every mode in restorable is already at its default except
// the ones the shell re-asserts on every prompt: measured here, zsh holds
// DECCKM and bracketed paste and emits both again at the next prompt, bash
// holds bracketed paste and does the same. So for the modes a caller actually
// holds, a reset is undone within one keystroke, and for the rest the default
// is what the caller had. What is left is a caller that is not a shell and
// keeps the mouse or the alternate screen while running a child, which is not
// how a program that shells out behaves.
//
// Being inside a sequence is state too. Output can stop anywhere — between
// the chunks a suspend falls between, or at a session's last byte — and a
// terminal left inside a sequence reads whatever the shell prints next as the
// rest of it: an unfinished OSC swallows the prompt whole. CAN cancels a
// sequence from any state on the DEC parser terminals implement, and does
// nothing outside one.
//
// The keyboard is state too. A program that asked for the kitty keyboard
// protocol or modifyOtherKeys and never put them back leaves the shell it
// returns to receiving Ctrl-letter keys, and with kitty's flags most others,
// as escape sequences it does not read. The kitty stacks are popped whole, in
// one pop each: a pop past the bottom empties a stack, which is where a
// terminal starts, so the depth this tracker recorded is safe to pop even on
// a terminal that was replayed fewer entries than that.
//
// The order is the order a terminal has to receive it in: out of any sequence
// first, so the rest is not read as part of it; then the alternate screen's
// keyboard stack, popped while that screen is still the one showing, since a
// pop applies to the current screen's stack; then off the alternate screen,
// through the mode that entered it, since everything after that applies to
// the screen the terminal is going back to, the main screen's stack included.
func (m *ModeTracker) Restore() []byte {
	var out []byte

	if m.state != msNormal {
		out = append(out, 0x18)
	}

	if m.altActive() {
		out = kittyPop(out, m.altKeys)
		out = append(out, 0x1b, '[', '?')
		out = append(out, []byte(strconv.Itoa(m.altVia))...)
		out = append(out, 'l')
	} else if m.altKeys.depth > 0 {
		// A program left the alternate screen without popping, and kitty
		// keeps that screen's stack: the next program to enter it would
		// inherit the flags. A pop reaches only the screen that is showing,
		// so it is a trip there and back -- through 47, which does not clear
		// the hidden screen as 1049 does, and between a cursor save and
		// restore, because kitty homes the cursor on every switch and 47
		// does not put it back.
		out = append(out, "\x1b7\x1b[?47h"...)
		out = kittyPop(out, m.altKeys)
		out = append(out, "\x1b[?47l\x1b8"...)
	}

	// The normal screen's margins, which outlive whatever set them: a shell
	// returned to a terminal still under a full-screen program's DECSTBM
	// scrolls inside those rows and leaves the rest of the screen frozen.
	// The alternate screen's are not restored because they are gone with it.
	if len(m.mainRegion) > 0 {
		out = append(out, 0x1b, '[', 'r')
	}

	nums := make([]int, 0, len(m.decPrivate))
	for n := range m.decPrivate {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	for _, n := range nums {
		if m.decPrivate[n] == restorable[n] {
			continue
		}
		out = append(out, 0x1b, '[', '?')
		out = append(out, []byte(strconv.Itoa(n))...)
		if restorable[n] {
			out = append(out, 'h')
		} else {
			out = append(out, 'l')
		}
	}

	out = kittyPop(out, m.mainKeys)
	if m.modifyOtherKeys != nil {
		out = append(out, "\x1b[>4m"...)
	}

	if len(m.charsetG0) > 0 {
		// US ASCII into G0, which is where a terminal starts.
		out = append(out, 0x1b, '(', 'B')
	}

	return out
}

// Snapshot returns the bytes that put a fresh terminal into the recorded
// modes. State already at the terminal's default is left out, so a session
// that never changed anything replays nothing. Its length is bounded by
// len(restorable) plus the screen switch, the three verbatim sequences, two
// kitty keyboard stacks of kittyStackDepth entries, modifyOtherKeys and one
// partial sequence. Only the partial is sized by the stream rather than by
// this file, and its own bound is maxSequenceBytes for a mode sequence or
// maxStringBytes for a string: the ceiling is a few kilobytes, not the hundreds
// of bytes everything else comes to.
//
// The order is the order the stream would have had to use to reach this
// state: the normal screen's margins, then the modes, then the normal
// screen's kitty keyboard stack and modifyOtherKeys, then the switch to the
// alternate screen, then that screen's own margins and keyboard stack, and
// only while it is the one showing. While the normal screen is showing, the
// alternate screen's stack is replayed on a trip there and back, because a
// push applies only to the screen that is showing.
//
// The state as of the ring's first byte includes being partway through a
// sequence, so the partial goes last, after the charset. The ring's first
// bytes then complete it on the joiner's terminal instead of printing as text
// -- which is what they did when the trim boundary fell inside a sequence and
// the snapshot said nothing about it.
func (m *ModeTracker) Snapshot() []byte {
	nums := make([]int, 0, len(m.decPrivate))
	for n := range m.decPrivate {
		nums = append(nums, n)
	}
	sort.Ints(nums)

	out := append([]byte(nil), m.mainRegion...)
	for _, n := range nums {
		if m.decPrivate[n] == restorable[n] {
			// Already where a joining terminal starts.
			continue
		}
		out = append(out, 0x1b, '[', '?')
		out = append(out, []byte(strconv.Itoa(n))...)
		if m.decPrivate[n] {
			out = append(out, 'h')
		} else {
			out = append(out, 'l')
		}
	}
	out = kittyPushes(out, m.mainKeys)
	out = append(out, m.modifyOtherKeys...)
	if !m.altActive() && len(m.altKeys.entries) > 0 {
		// The alternate screen's stack, kept while the normal screen shows,
		// replayed on a trip there and back; see Restore.
		out = append(out, "\x1b7\x1b[?47h"...)
		out = kittyPushes(out, m.altKeys)
		out = append(out, "\x1b[?47l\x1b8"...)
	}
	if m.altActive() {
		// Replayed through the mode that entered, so a joiner is left in the
		// state the session's own "l" will match.
		out = append(out, 0x1b, '[', '?')
		out = append(out, []byte(strconv.Itoa(m.altVia))...)
		out = append(out, 'h')
		out = append(out, m.altRegion...)
		out = kittyPushes(out, m.altKeys)
	}
	out = append(out, m.charsetG0...)
	out = append(out, m.partial...)
	return out
}
