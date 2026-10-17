package io

import (
	"bytes"
	"fmt"
	"maps"
	"math"
	"slices"
	"sort"
	"strconv"

	"github.com/owenthereal/upterm/internal/termsize"
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
// the cursor to wherever the session last saved it. It is heard as the save
// and restore it is, for the G0 those carry; see mainSavedG0.
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

// maxUnresolvedResizes bounds the resizes, crossed by eviction while still
// waiting for their outcome, that the tracker keeps a margin candidate for.
// Every DECSTBM is decided under each candidate, so without a bound a report
// that stays stalled would keep adding candidates, and with them the work of
// every DECSTBM. What it bounds is the candidates kept, not the events
// unresolved: an event whose candidate a later commit removed costs nothing,
// so it isn't counted. A resize is crossed unresolved only once a ring's
// worth of output has followed its ResizeBegin before its ResizeEnd, and a
// pty reports the two around a single ioctl: reaching this is a stalled
// report, not a resize storm.
const maxUnresolvedResizes = 16

// marginCandidate is the terminal's size and scrolling region as one
// outcome of the unresolved resizes eviction has crossed has them.
type marginCandidate struct {
	// after is the crossed resize this candidate assumes committed last, every
	// later one deleted; 0 is none of them.
	after uint64
	// size is the terminal's, whose rows a DECSTBM is decided against: the
	// zero size while none is known.
	size termsize.Size
	// top and bottom are the region a terminal holds, 1-based and inclusive,
	// after its defaults and clamping: both 0 while it is the whole screen.
	top, bottom int
	// written stands in for them while no size is known: the last DECSTBM as
	// written, which a terminal replayed it decides at its own height.
	written []byte
}

// decstbm decides a DECSTBM, with its parameters top and bottom, 0 where
// absent, as xterm's CASE_DECSTBM does at this candidate's height: top is 1
// if 0; bottom is the height if 0 or past it; and the region is set only if
// bottom > top, or else nothing changes. seq is the sequence as written.
func (c *marginCandidate) decstbm(top, bottom int, seq []byte) {
	height := heightOf(c.size)
	if height == 0 {
		// With no height to decide it against, it is decided as the tracker
		// decided every DECSTBM before it heard of sizes: each is taken, and
		// the last is replayed as written.
		c.top, c.bottom, c.written = 0, 0, seq
		return
	}
	top = max(top, 1)
	if bottom == 0 || bottom > height {
		bottom = height
	}
	if bottom <= top {
		return
	}
	c.top, c.bottom, c.written = top, bottom, nil
	if top == 1 && bottom == height {
		// The whole screen, which is where a terminal starts.
		c.top, c.bottom = 0, 0
	}
}

func (c marginCandidate) sameRegion(d marginCandidate) bool {
	return c.top == d.top && c.bottom == d.bottom && bytes.Equal(c.written, d.written)
}

// appendRegion appends the DECSTBM that sets this candidate's region on a
// terminal at its default, or nothing for the whole screen.
func (c marginCandidate) appendRegion(out []byte) []byte {
	if len(c.written) > 0 {
		return append(out, c.written...)
	}
	if c.top == 0 {
		return out
	}
	return fmt.Appendf(out, "\x1b[%d;%dr", c.top, c.bottom)
}

// heightOf is the rows of size, or 0 for a size that isn't one.
func heightOf(size termsize.Size) int {
	if !size.Valid() {
		return 0
	}
	return size.Rows
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
// Not safe for concurrent use, Clone included. MultiWriter owns one and only
// touches it under writeMu, which is where a capture clones it too.
type ModeTracker struct {
	decPrivate map[int]bool

	// A terminal has one alternate screen, not one per mode that reaches it,
	// so it is one boolean plus the mode that last entered it. altVia only
	// means anything while altScreen is set; it is what the snapshot replays,
	// because a joiner told to leave by a mode it never entered through is a
	// joiner on the wrong screen.
	altScreen bool
	altVia    int // 47, 1047 or 1049

	// savedBy1049 is whether the alternate screen showing was entered from
	// the normal one by ?1049h, which saved the normal screen's cursor on the
	// way. A ?47h or ?1047h there after it changes altVia and not that: a
	// ?1049l still restores the save. Only meaningful while altScreen is set.
	savedBy1049 bool

	// The scrolling region is the whole terminal's, as in xterm, and no screen
	// switch changes it. A terminal decides a DECSTBM at its height, so the
	// tracker hears resizes too, and while eviction has crossed resizes whose
	// outcome is unknown, the height is one of several. So candidates holds a
	// state per outcome that matters, in Seq order: the first assumes every
	// crossed resize still unresolved was deleted, and each other that its own
	// resize committed last. A resize heard committed in order resets the
	// region whatever came before it, so it leaves one. There is always at
	// least one.
	candidates []marginCandidate
	// overflowed is set while more crossed resizes are unresolved than the
	// tracker keeps candidates for: candidates is then one bounded fallback
	// state, and the region is uncertain until a resize heard in order.
	overflowed bool
	// marginsSet is whether a DECSTBM has been taken since the last RIS or
	// DECSTR, decided or not, for Restore alone. Restore goes to guests' own
	// terminals, which can be taller than the pty: CSI 0;24r is the whole
	// screen at the pty's 24 rows and a region at a guest's 30, and a resize
	// of the pty resets the pty's margins and not a guest's. So no resize
	// clears it, and nothing the candidates decide does.
	marginsSet bool

	// charsetG0 is G0 as the terminal holds it, as the "ESC ( X" that
	// designated it, verbatim, or nil for ASCII, where a terminal starts. A
	// cursor restore sets it too, so it is not simply the last designation.
	charsetG0 []byte

	// mainSavedG0 and altSavedG0 are the G0 each screen's saved cursor holds,
	// in charsetG0's form. A cursor save keeps the charsets with the cursor
	// and a restore brings them back, and xterm keeps one saved cursor per
	// screen buffer, so each save and restore uses the slot of the screen
	// showing. A slot nothing saved restores ASCII, which nil already is.
	// Only G0 is kept, because only G0 is tracked.
	mainSavedG0 []byte
	altSavedG0  []byte

	// leftRightMargins is DECLRMM, ?69, which makes a bare CSI s set the
	// left and right margins rather than save the cursor. It is the
	// terminal's, not a screen's, as in xterm, where it is one bit of the
	// terminal's flags. It is kept only to tell those two apart: the
	// margins it enables aren't tracked, so it is neither replayed nor reset
	// on the way out.
	leftRightMargins bool

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

	// What InSequence knows beyond state, which keeps the DEC reading the
	// bookkeeping above is built on. watchSequence keeps them, ahead of step.
	//
	// escFinal: an ESC sequence has had its intermediates (0x20-0x2F), or a
	// control character or DEL a terminal executes or ignores inside it, and
	// waits for its final byte. The parser completes only a G0 designation,
	// leaves every other one at its introducer and drops one at a control,
	// which costs it nothing: none of them is a mode it tracks.
	//
	// unended: a string the program ended ambiguously -- by CAN, SUB or an ESC
	// that isn't ST -- which a DEC parser ends there and kitty, and tmux for a
	// DCS, keep open, taking what follows as more of it. It is over only at a
	// terminator every terminal shares: ST, or BEL for an OSC. A window title
	// (ESC k), which the parser doesn't know as a string, is one from its
	// start. See openUnended.
	//
	// escAs: what the intermediates of the sequence escFinal waits on make
	// it, so its final byte can be read as a terminal reads it.
	//
	// csiPending: a CSI begun by a "[" after an ESC and controls a terminal
	// executed there, which the parser, having dropped the sequence at the
	// control, reads as text. It waits for the CSI's final byte. A string
	// begun that way is unended from its start: see beginPastControls.
	//
	// afterESC: the byte before was an ESC that isn't the second of a pair,
	// for recognising ST. tmux escapes an ESC inside its passthrough DCS by
	// doubling it, so there ESC ESC \ is an ESC and a backslash, not ST.
	//
	// utf8Pending: the continuation bytes the last UTF-8 lead byte still
	// waits for. A character is a sequence too: text written in the middle of
	// one is drawn as a replacement character where both were meant.
	escFinal    bool
	escAs       escKind
	csiPending  bool
	unended     stringKind
	afterESC    bool
	utf8Pending int

	// The character sets as NonASCIICharset sees them, cautiously: what the
	// terminal may be drawing text in, on any terminal's reading of the
	// output. gl is the set a locking shift last invoked into GL, 0 to 3 for
	// G0 to G3: SI (0x0F) for G0, SO (0x0E) for G1, LS2 (ESC n) and LS3 (ESC o)
	// for G2 and G3. What G1 to G3 hold isn't tracked, so each is taken as a
	// set other than ASCII. g0Graphics is that G0 was designated one.
	// singleShift is an SS2 (ESC N) or SS3 (ESC O) still waiting for the one
	// character it draws from G2 or G3.
	//
	// Anything may raise them, but only what every mainstream terminal takes
	// as putting ASCII back lowers them: an SI, an ESC ( B, or a RIS straight
	// after its ESC, and none of them inside an unended string, which is the
	// string's on a terminal that keeps it open. A DECSTR lowers nothing,
	// since tmux ignores it, and nor does a RIS with a control inside it,
	// since kitty abandons the ESC there. charsetG0 keeps the parser's DEC
	// reading, for the replay; these are for NonASCIICharset and InSequence
	// alone, and nothing is replayed from them.
	//
	// savedGL and savedG0Graphics are the sets a cursor save took with it, as
	// cautiously, one copy for both screens: a save on the main screen and
	// outside an unended string, straight after its ESC or as a CSI whose
	// parameters are read, replaces them; any other save merges with them,
	// not ASCII if either side is; a RIS that lowers the sets clears them;
	// and a restore only ever raises gl and g0Graphics from them, never
	// lowers them.
	gl              int
	g0Graphics      bool
	singleShift     bool
	savedGL         int
	savedG0Graphics bool
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
// recognise. That reason is about those bytes as raw bytes alone: the same
// controls encoded as UTF-8 characters, U+0080 to U+009F, are not followed
// either, for a reason of their own (see watchSequence).
type stringKind int

const (
	skNone  stringKind = iota
	skOSC              // ESC ]
	skDCS              // ESC P
	skPM               // ESC ^
	skAPC              // ESC _
	skSOS              // ESC X
	skTitle            // ESC k, tmux's and GNU screen's window title: the watch's alone
)

// escKind is what an ESC sequence's intermediates make it, for the watch,
// which reads a sequence's final byte as a terminal does: intermediates
// collected, and a control character executed where it stands without being
// part of the sequence.
type escKind int

const (
	ekPlain     escKind = iota // the final byte straight after ESC, as in ESC n
	ekControls                 // no intermediate, but controls executed between ESC and the final byte
	ekG0                       // ESC ( or ESC $ (: a set designated into G0
	ekMultibyte                // ESC $ alone: a multibyte set into G0, at the final byte
	ekOther                    // anything else: a set into G1 to G3, or no designation at all
)

// then is k with the intermediate b after it.
func (k escKind) then(b byte) escKind {
	none := k == ekPlain || k == ekControls
	switch {
	case k == ekG0, b == '(' && (none || k == ekMultibyte):
		return ekG0
	case b == '$' && none:
		return ekMultibyte
	}
	return ekOther
}

// ending is the sequence the byte the watch reads is the final byte of, if
// any, as watchCharsets reads it.
type ending struct {
	esc bool    // an ESC sequence
	as  escKind // what its intermediates, or the controls inside it, made it
	csi bool    // a CSI begun past executed controls (see csiPending)
}

func NewModeTracker() *ModeTracker {
	return &ModeTracker{decPrivate: map[int]bool{}, candidates: []marginCandidate{{}}}
}

// Clone returns an independent copy: writing to either leaves the other's
// Snapshot and Restore unchanged.
//
// A caller that needs the snapshot as of a later point in the ring than its
// first byte gets it by feeding a clone the ring's bytes up to there. The
// tracker itself has to go on describing the ring's first byte, so the copy is
// deep: the parser appends to its slices in place and rewrites a key stack's
// top entry in place, the margin candidates are deleted from and rewritten in
// place, and a shared backing array or map would carry the clone's writes
// back into the original, and the original's into the clone.
func (m *ModeTracker) Clone() *ModeTracker {
	c := *m
	c.decPrivate = maps.Clone(m.decPrivate)
	c.candidates = slices.Clone(m.candidates)
	for i := range c.candidates {
		c.candidates[i].written = slices.Clone(m.candidates[i].written)
	}
	c.charsetG0 = slices.Clone(m.charsetG0)
	c.mainSavedG0 = slices.Clone(m.mainSavedG0)
	c.altSavedG0 = slices.Clone(m.altSavedG0)
	c.mainKeys.entries = slices.Clone(m.mainKeys.entries)
	c.altKeys.entries = slices.Clone(m.altKeys.entries)
	c.modifyOtherKeys = slices.Clone(m.modifyOtherKeys)
	c.partial = slices.Clone(m.partial)
	c.seq = slices.Clone(m.seq)
	return &c
}

// Resized records the terminal's new size and resets the margin region, as a
// terminal resets it on a resize. The size is what DECSTBM is decided against.
// Exported: the replay package's clone hears resizes too.
//
// It is a resize the terminal is known to have made, heard where it fell in
// the stream, so it settles the candidates: whichever crossed resize
// committed last, this one came after it, and their outcomes change nothing
// from here.
func (m *ModeTracker) Resized(size termsize.Size) {
	m.candidates = append(m.candidates[:0], marginCandidate{size: size})
	m.overflowed = false
}

// resizeHeard applies a committed resize to size that eviction reached in
// order. Where the terminal already had that size it is no resize at all: the
// pty sends no SIGWINCH, the terminal resets nothing, and the replay applies no
// such event either. Each candidate is its own terminal for this: one at
// another size is reset to size and the whole screen, one at size keeps its
// region, and only when every one resets is this Resized, which settles them.
//
// Overflowed, there is no comparing: the fallback's size is a guess at the
// terminal's, and a skip decided against a guess could leave the tracker
// certain and wrong. The pty reports a resize only when its size really
// changes (a Setsize to the size it has reports nothing), so every committed
// event is a resize that resets the margins, and it settles the tracker.
func (m *ModeTracker) resizeHeard(size termsize.Size) {
	if m.overflowed {
		m.Resized(size)
		return
	}
	reset := 0
	for i, c := range m.candidates {
		if c.size != size {
			m.candidates[i] = marginCandidate{after: c.after, size: size}
			reset++
		}
	}
	if reset == len(m.candidates) {
		m.Resized(size)
	}
}

// crossTentative records that eviction reached resize seq, to size, before its
// outcome. The bytes after it were written at size if it commits and at the
// size before if it is deleted, and the tracker doesn't guess which: it adds a
// candidate, size and the whole screen, and the candidates already kept stay,
// as its deleted branch, until resolve selects.
//
// The new candidate's region is the whole screen, as a terminal's is after
// a resize, because no ResizeBegin is a same-size resize: the host's pty
// guarantees it, its Setsize reporting nothing for a resize to the size it
// has. A same-size report would reset a region no terminal reset.
//
// Past maxUnresolvedResizes the candidates give way to one fallback state,
// which does guess: that each resize it crosses commits, since a resize's
// ioctl rarely fails. The region is uncertain from then on.
func (m *ModeTracker) crossTentative(seq uint64, size termsize.Size) {
	switch {
	case m.overflowed:
		m.candidates[0] = marginCandidate{size: size}
	case len(m.candidates) > maxUnresolvedResizes:
		// The newest candidate at the overflow, which is this resize's.
		m.candidates = append(m.candidates[:0], marginCandidate{size: size})
		m.overflowed = true
	default:
		m.candidates = append(m.candidates, marginCandidate{after: seq, size: size})
	}
}

// resolve applies crossed resize seq's outcome, from the fan-out's apply, as
// it reaches the log: deleted, its candidate goes; committed, every candidate
// before it goes, since it or a later resize committed last, and its own
// becomes the first, the one with every resize still unresolved deleted. An
// event the tracker never crossed decides nothing, and nor does one whose
// candidate a later commit or a resize heard in order removed already, or any
// while overflowed.
func (m *ModeTracker) resolve(seq uint64, committed bool) {
	if m.overflowed || seq == 0 {
		return
	}
	i := slices.IndexFunc(m.candidates, func(c marginCandidate) bool { return c.after == seq })
	if i < 0 {
		return
	}
	if !committed {
		m.candidates = slices.Delete(m.candidates, i, i+1)
		return
	}
	m.candidates = slices.Delete(m.candidates, 0, i)
	m.candidates[0].after = 0
}

// uncertain reports that the region can't be known yet: the candidates
// disagree on it, or there were too many to keep. A capture fails while it is,
// with ErrReplayMarginsUncertain, because a reconstruction gives the joiner
// one region in its own place and there isn't one to give; the join falls
// back to the raw ring.
func (m *ModeTracker) uncertain() bool {
	if m.overflowed {
		return true
	}
	for _, c := range m.candidates[1:] {
		if !c.sameRegion(m.candidates[0]) {
			return true
		}
	}
	return false
}

// AtGround reports that the tracker is outside every sequence: no partial,
// and no sequence overflowed past its bound either.
func (m *ModeTracker) AtGround() bool { return m.state == msNormal }

// InSequence reports whether the output seen so far may have left the
// terminal inside an escape sequence, where text written now would be read as
// part of it: after ESC; in an ESC sequence still waiting for its final byte
// (any intermediate 0x20-0x2F: ESC ( ) * + - . / # % SP, of which the parser
// completes only "("; or a control character or DEL, which a terminal
// executes or ignores there without ending the sequence); in a CSI; in an OSC, DCS, PM,
// APC or SOS string; in a CSI or string begun after such a control, which a
// DEC parser begins there and the tracker's own parser reads as text; after
// a string the program ended ambiguously -- by CAN,
// SUB or an ESC that isn't ST -- which a DEC parser ends there but kitty and
// tmux keep open (see TerminalQueryFilter); in a window title, ESC k, which
// tmux and GNU screen read as a string; inside a UTF-8 character whose
// continuation bytes haven't all come; or after a single shift, SS2 (ESC N)
// or SS3 (ESC O), whose character hasn't come, which would draw the first
// character written now from G2 or G3. An ambiguous string, and a title,
// stay "inside" until a terminator every terminal shares: ST (ESC \), or BEL
// for an OSC. An ESC \ whose ESC is the second of a pair is no ST: tmux
// escapes an ESC inside its passthrough by doubling it.
//
// It is AtGround's cautious form, for a writer that must not land inside the
// program's sequence on any terminal. The tracker's own mode bookkeeping keeps
// the DEC reading: only this is conservative.
func (m *ModeTracker) InSequence() bool {
	return m.state != msNormal || m.escFinal || m.csiPending || m.unended != skNone || m.utf8Pending > 0 || m.singleShift
}

// NonASCIICharset reports whether text written now would be drawn in a
// character set other than ASCII: G0 designated as anything but ESC ( B as
// written (ESC ( 0, DEC Special Graphics, draws letters as line pieces, and a
// national set swaps some of them; a set with an intermediate of its own, a
// multibyte one, or ESC ( B with a control inside it is taken as not ASCII
// too), or a locking shift that put G1, G2 or G3 in use -- SO, LS2 (ESC n)
// or LS3 (ESC o) -- and no shift-in (SI) since, whatever those sets hold. A
// RIS straight after its ESC puts both back; a DECSTR isn't taken as doing
// so, since tmux ignores it. A cursor restore can only raise it, from one
// copy of the saved sets that both screens share. Text written there is not
// inside a sequence, but it isn't read as the text it is either.
//
// SO and SI are taken wherever a terminal executes them, which is everywhere
// but inside a string: an OSC, PM, APC or SOS ignores them, and a DCS hands
// them to its handler. A string ended ambiguously counts as one until it is
// over, for whatever would put ASCII back -- an SI, an ESC ( B or a RIS: a
// terminal that keeps the string open takes it as the string's, so the
// graphics are kept through it. What would leave ASCII is taken there all the
// same.
func (m *ModeTracker) NonASCIICharset() bool {
	return m.gl != 0 || m.g0Graphics
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
		m.watchSequence(b)
		m.step(b)
	}
	return len(p), nil
}

// watchSequence keeps what InSequence and NonASCIICharset know beyond the
// parser's state, from the state b arrives in, before step moves it on.
//
// It has limits, each where following a terminal further costs more than it
// is worth. The controls from U+0080 to U+009F, encoded as UTF-8 characters,
// aren't followed: some terminals honour them and others don't, and following
// them would leave the guard unsafe for good on the terminals that don't. Nor
// is an ESC followed by a character outside ASCII, which terminals disagree
// on too. VT52 mode, Tektronix mode, the printer controller, DOCS (ESC % @ and
// its kin) and the Linux console's palette sequences aren't known, and the 5-
// and 6-byte lead bytes of the original UTF-8 (0xF8 to 0xFD) aren't waited out
// as characters. A plain CSI s is taken as a cursor save, which it isn't
// under left and right margins mode, and 1048 as one on every terminal: a save
// the terminal doesn't make still replaces the copy of the saved sets, and a
// restore of the terminal's own older save can then draw in sets the copy
// doesn't hold. xterm, VTE and tmux also save and restore the cursor on CSI
// Ps ; Ps s and CSI Ps u while that mode is off, and the watch reads only the
// plain forms.
//
// And the guard can stay unsafe until the program's own explicit reset: after
// a stray SO, ESC n or ESC o, until an SI; in a string only ST ends, until the
// next ESC \ whose ESC isn't the second of a pair; and with a character set
// raised by a designation or a restore, until an ESC ( B, an SI or a RIS
// lowers it. Since the copy of the saved sets is one for both screens, a
// program on the alternate screen that saves its cursor in graphics and
// leaves in ASCII keeps the guard raised until such a reset too.
func (m *ModeTracker) watchSequence(b byte) {
	// Whether b arrives outside every sequence, where a terminal draws it as
	// a character or executes it as a control: read before anything below
	// moves the state on.
	ground := m.state == msNormal && !m.escFinal && !m.csiPending
	cancel := b == 0x18 || b == 0x1a
	intermediate := b >= 0x20 && b <= 0x2f
	// A control character (0x00-0x1F) other than CAN, SUB and ESC is executed
	// inside an ESC sequence, and DEL ignored there; the sequence goes on
	// waiting for its final byte either way. The parser drops the sequence at
	// one, which its bookkeeping can afford and this can't: what follows is
	// still the sequence's on the terminal.
	executed := (b < 0x20 && !cancel && b != 0x1b) || b == 0x7f
	final := b >= 0x30 && b <= 0x7e
	// The sequence b is the final byte of, if it is one, and what the
	// sequence was, for watchCharsets: the shifts, RIS, the designations and
	// the cursor saves are read from it.
	var end ending
	// A CSI the parser didn't see begin ends at its final byte, and CAN, SUB
	// or an ESC abandons it. Anything else -- a parameter, an intermediate, or
	// a control executed there -- is more of it.
	if m.csiPending && ((b >= 0x40 && b <= 0x7e) || cancel || b == 0x1b) {
		m.csiPending = false
		end.csi = b >= 0x40 && b <= 0x7e
	}
	// An ESC sequence past its intermediates ends at its final byte, and CAN,
	// SUB or the ESC of another sequence abandons it. Anything else -- a
	// control character, which a terminal executes there, DEL, or another
	// intermediate -- leaves it waiting.
	if m.escFinal {
		switch {
		case final:
			end.esc, end.as = true, m.escAs
			m.escFinal = false
			if m.escAs == ekControls {
				m.beginPastControls(b)
			}
		case cancel || b == 0x1b:
			m.escFinal = false
		case intermediate:
			m.escAs = m.escAs.then(b)
		}
	}
	switch m.state {
	case msEsc:
		// "(" is the parser's own msCharset.
		if (intermediate && b != '(') || executed {
			m.waitFinal(ekPlain, b)
		} else if final {
			end.esc = true
		}
	case msCharset:
		// A designation with an intermediate of its own, such as ESC ( % 5,
		// which the parser drops as not a designator at all.
		if intermediate || executed {
			m.waitFinal(ekG0, b)
		}
	case msString:
		if cancel {
			m.openUnended(m.kind)
		}
	case msStringEsc:
		if b != '\\' {
			// The ESC was not ST's: the parser resyncs on b as the start of
			// a new sequence, and a terminal that keeps the string open
			// reads both as more of it.
			m.openUnended(m.kind)
			if (intermediate && b != '(') || executed {
				m.waitFinal(ekPlain, b)
			} else if final {
				end.esc = true
			}
		}
	}
	if end.esc && (end.as == ekPlain || end.as == ekControls) && b == 'k' {
		// A window title, which tmux and GNU screen read as a string only
		// ST ends, and oh-my-zsh sends at every prompt under their TERM. The
		// parser takes ESC k as a sequence done at the k.
		m.openUnended(skTitle)
	}
	if m.unended != skNone && ((m.afterESC && b == '\\') || (b == 0x07 && m.unended == skOSC)) {
		m.unended = skNone
	}
	// Paired: the second ESC of two is the first's escape, not an ESC an ST
	// begins with.
	m.afterESC = b == 0x1b && !m.afterESC

	m.watchCharsets(b, ground, end)

	// A lead byte says how many continuation bytes follow it; anything but a
	// continuation byte ends the character, complete or not.
	switch {
	case b >= 0xc2 && b <= 0xdf:
		m.utf8Pending = 1
	case b >= 0xe0 && b <= 0xef:
		m.utf8Pending = 2
	case b >= 0xf0 && b <= 0xf4:
		m.utf8Pending = 3
	case b >= 0x80 && b <= 0xbf:
		if m.utf8Pending > 0 {
			m.utf8Pending--
		}
	default:
		m.utf8Pending = 0
	}
}

// beginPastControls follows the CSI or string b begins on a DEC parser, as
// the final byte of an ESC with controls executed inside it and no
// intermediate: the parser dropped the sequence at the control, and reads
// what follows as text.
//
// The string is taken as unended from its start. That is what unended means
// -- open until a terminator every terminal shares, ST or BEL for an OSC,
// whatever ends it ambiguously first -- and so what this string is on a
// terminal that reads it as one.
func (m *ModeTracker) beginPastControls(b byte) {
	var kind stringKind
	switch b {
	case '[':
		m.csiPending = true
		return
	case ']':
		kind = skOSC
	case 'P':
		kind = skDCS
	case 'X':
		kind = skSOS
	case '^':
		kind = skPM
	case '_':
		kind = skAPC
	default:
		return
	}
	m.openUnended(kind)
}

// openUnended opens the window a string of kind leaves when it is ended
// ambiguously, or begun where the parser doesn't see it, unless a window only
// ST ends is open already: a string begun inside one is more of it on a
// terminal that keeps it open, and the BEL that ends an OSC doesn't end the
// string around it. So only no window, or an OSC's, is replaced.
func (m *ModeTracker) openUnended(kind stringKind) {
	if m.unended == skNone || m.unended == skOSC {
		m.unended = kind
	}
}

// waitFinal has the watch wait for the final byte of an ESC sequence of kind
// k, which b, an intermediate or a control a terminal executes there, has
// kept from ending.
func (m *ModeTracker) waitFinal(k escKind, b byte) {
	m.escFinal = true
	m.escAs = k
	switch {
	case b >= 0x20 && b <= 0x2f:
		m.escAs = k.then(b)
	case k == ekPlain:
		m.escAs = ekControls
	}
}

// saveCharsets is a cursor save's, which takes the character sets with it:
// replacing the copy when replace, and otherwise merging with it, not ASCII
// if either side is. On the alternate screen it always merges: a terminal
// keeps a saved cursor per screen, and leaving through 1049 restores the main
// screen's, which the copy, one for both, still has to hold.
func (m *ModeTracker) saveCharsets(replace bool) {
	if replace && !m.altScreen {
		m.savedGL, m.savedG0Graphics = m.gl, m.g0Graphics
		return
	}
	if m.savedGL == 0 {
		m.savedGL = m.gl
	}
	m.savedG0Graphics = m.savedG0Graphics || m.g0Graphics
}

// restoreCharsets is a cursor restore's, from the copy: it only ever raises
// what NonASCIICharset says, never lowers it, since the terminal's own save
// may hold what the copy doesn't.
func (m *ModeTracker) restoreCharsets() {
	if m.gl == 0 {
		m.gl = m.savedGL
	}
	m.g0Graphics = m.g0Graphics || m.savedG0Graphics
}

// savesCursor reports whether params, a DEC private mode set's or reset's,
// name 1048 or 1049, which save the cursor when set and restore it when
// reset. Read as finishCSI reads them.
func savesCursor(params []byte) bool {
	if len(params) == 0 || params[0] != '?' {
		return false
	}
	for _, field := range bytes.Split(params[1:], []byte{';'}) {
		if n, err := strconv.Atoi(string(field)); err == nil && (n == 1048 || n == 1049) {
			return true
		}
	}
	return false
}

// watchCharsets keeps NonASCIICharset's view of the character sets, the copy
// a cursor save takes of them, and the single shift InSequence waits out,
// from the state b arrives in. It reads each sequence as a terminal does: an
// ESC sequence, or a CSI begun past executed controls, at its final byte,
// which end says b is; ESC ( B as the parser completes it; a cursor save or
// restore in a CSI at its final byte; and SO and SI wherever a terminal
// executes them. watchSequence calls it once it has decided whether b falls
// inside an unended string; ground is that b arrived outside every sequence.
func (m *ModeTracker) watchCharsets(b byte, ground bool, end ending) {
	// A string the program ended ambiguously is still open on a terminal that
	// keeps it so, which takes whatever a DEC parser reads as putting ASCII
	// back as more of the string, and is still in the graphics once ST comes.
	// So inside that window nothing lowers what NonASCIICharset reports, and
	// it waits for the same thing outside it. Whatever raises it is no less
	// cautious there, and raises it.
	lower := m.unended == skNone
	if ground && b >= 0x20 && b != 0x7f {
		// The character a single shift draws from G2 or G3, which spends it.
		// A control character draws nothing, and DEL is ignored: the shift
		// waits on past them.
		m.singleShift = false
	}
	if end.esc {
		switch end.as {
		case ekPlain, ekControls:
			// The final bytes that are a sequence of their own after ESC,
			// also after an ESC that abandoned a string, and past controls a
			// DEC parser executes there. The locking shifts into GR (ESC ~,
			// ESC } and ESC |) reach only 8-bit bytes, which a UTF-8
			// terminal doesn't read as GR, so they are left alone.
			switch b {
			case 'c': // RIS
				// Only straight after its ESC: kitty abandons an ESC at a
				// control, and a RIS past one resets nothing there.
				if end.as == ekPlain && lower {
					m.gl, m.g0Graphics = 0, false
					m.savedGL, m.savedG0Graphics = 0, false
				}
			case 'n': // LS2
				m.gl = 2
			case 'o': // LS3
				m.gl = 3
			case 'N', 'O': // SS2, SS3
				m.singleShift = true
			case '7': // DECSC
				m.saveCharsets(end.as == ekPlain && lower)
			case '8': // DECRC
				m.restoreCharsets()
			}
		case ekG0, ekMultibyte:
			// A set into G0 that isn't ESC ( B as written: one with an
			// intermediate of its own, a multibyte one, or one with a control
			// executed inside it. None of them is taken as ASCII.
			m.g0Graphics = true
		}
	}
	if end.csi {
		// A CSI begun past a control, whose parameters the watch doesn't
		// read: taken as whichever save or restore its final byte could be.
		switch b {
		case 's', 'h':
			m.saveCharsets(false)
		case 'u', 'l':
			m.restoreCharsets()
		}
	}
	switch m.state {
	case msString:
		// A string ignores SO and SI, or hands them to its handler, and
		// nothing else inside it is a sequence.
		return
	case msCharset:
		// A G0 designation, at the byte the parser completes one at: ASCII
		// only as ESC ( B.
		if b >= 0x30 && b <= 0x7e {
			if b != 'B' {
				m.g0Graphics = true
			} else if lower {
				m.g0Graphics = false
			}
		}
	case msCSI:
		// A cursor save or restore: a plain CSI s or u (SCOSC, SCORC), or
		// 1048 or 1049 set or reset. One whose parameters overflowed may
		// have named either mode, so it is taken as a save merged, or a
		// restore. A DECSTR lowers nothing here: tmux ignores it.
		plain := len(m.seq) == 0 && (b == 's' || b == 'u')
		modes := (b == 'h' || b == 'l') && (m.overflow || savesCursor(m.seq))
		switch {
		case (plain || modes) && (b == 's' || b == 'h'):
			m.saveCharsets(lower && !m.overflow)
		case plain || modes:
			m.restoreCharsets()
		}
	}
	switch b {
	case 0x0e:
		m.gl = 1
	case 0x0f:
		if lower {
			m.gl = 0
		}
	}
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
		if isExecuted(b) {
			return
		}
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
		case '7':
			// DECSC.
			m.saveCursor()
			m.state = msNormal
			m.closePartial()
		case '8':
			// DECRC.
			m.restoreCursor()
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
		case isExecuted(b):
			// Acted on, and the designation goes on.
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
		if b < 0x20 || b == 0x7f {
			// A C0 control inside a CSI is executed where it stands and the
			// CSI goes on -- the DEC parser's "execute" in its CSI states,
			// which kitty follows too -- and DEL is ignored there. Neither
			// is one of the sequence's parameters, and neither is replayed
			// with it: the session's terminal has already acted on it. ESC,
			// CAN and SUB, which end a CSI, are handled before this.
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
		switch {
		case b == '\\':
			// ST, which ends any of them.
			m.endString()
			return
		case b == 0x07 && m.kind == skOSC:
			// xterm keeps the string open across the ESC, and a BEL read
			// there still ends an OSC.
			m.endString()
			return
		case isExecuted(b):
			// The ESC is still waiting for the byte that ends the string or
			// opens a sequence.
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

// isExecuted reports a byte a terminal acts on inside an escape sequence
// without leaving it: a C0 control, executed where it stands, or DEL, which is
// ignored. xterm's esc_table and the tables that designate a charset
// (VTPrsTbl.c) share their C0 column with its CSI tables, as the DEC parser
// does. Neither is part of the sequence or replayed with it: the session's
// terminal has already acted on it. ESC is not one, since it restarts a
// sequence, and CAN and SUB, which end one, step handles first.
func isExecuted(b byte) bool { return (b < 0x20 && b != 0x1b) || b == 0x7f }

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
//
// Everything but the alternate screen's saved G0. xterm's RIS leaves the
// alternate screen, then saves the cursor, and the charsets it has just reset
// with it, on the normal screen alone: the alternate screen's saved cursor
// stays as it was, for a restore there to bring back.
func (m *ModeTracker) resetToDefaults() {
	clear(m.decPrivate)
	m.altScreen = false
	m.altVia = 0
	m.savedBy1049 = false
	m.clearRegions()
	m.charsetG0 = nil
	m.mainSavedG0 = nil
	m.leftRightMargins = false
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
	m.clearRegions()
	m.charsetG0 = nil
	// xterm's soft reset ends with a cursor save, after the charsets are
	// reset, so the slot of the screen showing holds ASCII. The other
	// screen's is left alone.
	*m.savedG0() = nil
	// And it resets DECLRMM, as RIS does.
	m.leftRightMargins = false
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

// clearRegions puts the region back to the whole screen, as RIS and DECSTR do
// at any height, on a guest's terminal too: the candidates stay, for the
// sizes they hold.
func (m *ModeTracker) clearRegions() {
	for i := range m.candidates {
		m.candidates[i].top, m.candidates[i].bottom, m.candidates[i].written = 0, 0, nil
	}
	m.marginsSet = false
}

func (m *ModeTracker) altActive() bool { return m.altScreen }

// savedG0 returns the saved cursor's G0 of the screen that is showing.
func (m *ModeTracker) savedG0() *[]byte {
	if m.altActive() {
		return &m.altSavedG0
	}
	return &m.mainSavedG0
}

// saveCursor is a cursor save -- DECSC, SCOSC, ?1048h, and ?1049h before it
// switches -- of the one piece of what it saves that the tracker models: G0.
func (m *ModeTracker) saveCursor() { *m.savedG0() = slices.Clone(m.charsetG0) }

// restoreCursor is a cursor restore -- DECRC, SCORC, ?1048l, and ?1049l after
// it switches back -- which brings back the G0 the save held, or ASCII from a
// slot nothing saved.
func (m *ModeTracker) restoreCursor() { m.charsetG0 = slices.Clone(*m.savedG0()) }

func (m *ModeTracker) finishCSI(final byte) {
	params := m.seq

	switch final {
	case 'h', 'l':
		// Only DEC private modes, marked by a leading '?'.
		if len(params) == 0 || params[0] != '?' {
			return
		}
		set := final == 'h'
		for _, field := range bytes.Split(params[1:], []byte{';'}) {
			n, err := strconv.Atoi(string(field))
			if err != nil {
				continue
			}
			if n == 1048 {
				// A cursor save and restore, not a mode; see restorable.
				if set {
					m.saveCursor()
				} else {
					m.restoreCursor()
				}
				continue
			}
			if n == 69 {
				m.leftRightMargins = set
				continue
			}
			if _, ok := restorable[n]; !ok {
				continue
			}
			if altScreenModes[n] {
				if n == 1049 && set {
					// 1049 saves the cursor before it switches, in the slot
					// of the screen showing: the normal one, unless the
					// alternate one already is.
					m.saveCursor()
				}
				if set && !m.altScreen {
					// Entered from the normal screen: by ?1049h, which has
					// just saved its cursor, or by a mode that saves nothing.
					m.savedBy1049 = n == 1049
				}
				m.altScreen = set
				if set {
					// Whichever mode entered last is the one to replay, since
					// it is the one the session's own reset will match.
					m.altVia = n
				}
				if n == 1049 && !set {
					// And restores it once it has switched back, from the
					// normal screen's slot, whichever screen was showing.
					m.restoreCursor()
				}
				continue
			}
			m.decPrivate[n] = set
		}
	case 'r':
		m.decstbm(params)
	case 'p':
		// DECSTR, a soft reset. Its parameter is the intermediate '!', which
		// is what separates it from the several other CSI ... p sequences.
		if len(params) == 1 && params[0] == '!' {
			m.softReset()
		}
	case 's':
		// SCOSC, while DECLRMM (?69) is reset, and only bare: xterm saves on
		// a CSI s with no parameter at all. While ?69 is set it is DECSLRM,
		// the left and right margins, bare or not. With a prefix it is
		// neither: CSI ? s is XTSAVE.
		if len(params) == 0 && !m.leftRightMargins {
			m.saveCursor()
		}
	case 'u':
		if len(params) == 0 {
			// SCORC; see kittyKeyboard.
			m.restoreCursor()
			return
		}
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

// decstbm applies a DECSTBM to every candidate, each deciding it at its own
// height: candidates aren't merged, so a later DECSTBM that depends on the
// height is still decided under each.
//
// Only an r sequence of plain numeric parameters is one. With a prefix or an
// intermediate it is another sequence -- CSI ? r is XTRESTORE, CSI $ r is
// DECCARA -- and a subparameter makes it one xterm doesn't take either. xterm
// reads the first two parameters, ignores the rest, and holds none past
// termsize.Max, its own bound, which no height reaches.
func (m *ModeTracker) decstbm(params []byte) {
	var tb [2]int
	for i, field := range bytes.Split(params, []byte{';'}) {
		for _, b := range field {
			if b < '0' || b > '9' {
				return
			}
			if i < len(tb) {
				tb[i] = min(tb[i]*10+int(b-'0'), termsize.Max)
			}
		}
	}
	m.marginsSet = true
	seq := append(append([]byte("\x1b["), params...), 'r')
	for i := range m.candidates {
		m.candidates[i].decstbm(tb[0], tb[1], seq)
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
		flags, ok := kittyFlags(params[1:])
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
		flags, ok := kittyFlags(fields[0])
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

// csiNumber parses one CSI parameter at the protocols' own width, an unsigned
// 32-bit number, whatever an int is on this build: def when it is empty, and
// not ok when it is not one -- negative, too wide, or with anything else in
// it. kitty takes a pop's count as a uint32, and a 32-bit client must track a
// stream as a 64-bit one does. Past the largest int32 it is the largest int32,
// on every build, so every build tracks it alike: a count that large is past
// any stack's depth. kitty's flags, whose low bits matter however wide the
// number, are read by kittyFlags instead.
func csiNumber(field []byte, def int) (int, bool) {
	if len(field) == 0 {
		return def, true
	}
	n, err := strconv.ParseUint(string(field), 10, 32)
	if err != nil {
		return 0, false
	}
	if n > math.MaxInt32 {
		return math.MaxInt32, true
	}
	return int(n), true
}

// kittyFlagMask is the bits of a flags value kitty keeps
// (screen_push_key_encoding_flags and screen_set_key_encoding_flags: val &
// 0x7f).
const kittyFlagMask = 0x7f

// kittyFlags parses a kitty flags parameter as kitty does: a 32-bit number of
// which it keeps the low seven bits, so the replay is what the session's
// terminal holds. Masked before it is narrowed, so a number past an int32 keeps
// the bits kitty reads rather than becoming csiNumber's largest int32.
func kittyFlags(field []byte) (int, bool) {
	if len(field) == 0 {
		return 0, true
	}
	n, err := strconv.ParseUint(string(field), 10, 32)
	if err != nil {
		return 0, false
	}
	flags := n & kittyFlagMask
	// The mask is the bound; this states it where the conversion can see it.
	if flags > kittyFlagMask {
		return 0, false
	}
	return int(flags), true
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

	// The margins, which outlive whatever set them: a shell returned to a
	// terminal still under a full-screen program's DECSTBM scrolls inside
	// those rows and leaves the rest of the screen frozen. They are the
	// terminal's, not a screen's, so they are reset once, on the screen it
	// goes back to. They are reset after any DECSTBM since the last RIS or
	// DECSTR, whatever the pty's height decided (see marginsSet), which
	// covers every candidate's region too, since only a DECSTBM sets one:
	// resetting margins a terminal doesn't have is harmless, and missing some
	// is not.
	if m.marginsSet {
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

	// The G0 the terminal holds after all of the above: ?1049l restores the
	// one ?1049h saved, and nothing else here changes it, the trip to the
	// alternate screen's stack saving and restoring it as it is.
	g0 := m.charsetG0
	if m.altActive() && m.altVia == 1049 {
		g0 = m.mainSavedG0
	}
	if len(g0) > 0 {
		// US ASCII into G0, which is where a terminal starts.
		out = append(out, 0x1b, '(', 'B')
	}

	return out
}

// Snapshot returns the bytes that put a fresh terminal into the recorded
// modes. State already at the terminal's default is left out, so a session
// that never changed anything replays nothing. Its length is bounded by
// len(restorable) plus the screen switch, the region, the charset (twice, on
// either side of a ?1049h) and modifyOtherKeys, each one sequence of at most
// maxSequenceBytes parameters, two kitty keyboard stacks of kittyStackDepth
// entries, and one partial sequence. Only the partial is sized by the stream
// rather than by this file, and its own bound is maxSequenceBytes for a mode
// sequence or maxStringBytes for a string: the ceiling is a few kilobytes,
// not the hundreds of bytes everything else comes to.
//
// The order is the order the stream would have had to use to reach this
// state: the margins, then the modes, then the normal screen's kitty keyboard
// stack and modifyOtherKeys, then the switch to the alternate screen and that
// screen's own keyboard stack, only while it is the one showing. While the
// normal screen is showing, the alternate screen's stack is replayed on a
// trip there and back, because a push applies only to the screen that is
// showing. The margins are the terminal's, so no switch moves them.
//
// The region is defined while it is uncertain too, for the raw fallback,
// which replays it then; a capture never does, as it fails while the region
// is uncertain. It is the candidates' common region when they agree, which is
// the newest's; the newest surviving candidate's when they disagree, the
// likeliest, since a resize's ioctl rarely fails and so the newest crossed
// resize most likely committed last; and the fallback's while overflowed, the
// only one kept.
//
// The state as of the ring's first byte includes being partway through a
// sequence, so the partial goes last, after the charset. The ring's first
// bytes then complete it on the joiner's terminal instead of printing as text
// -- which is what they did when the trim boundary fell inside a sequence and
// the snapshot said nothing about it.
//
// Of the saved cursors, only the one ?1049h saves on the normal screen is
// replayed, as the G0 designated ahead of the switch, because the switch saves
// the cursor anyway. Every other save is a limit: a restore in the ring whose
// save was evicted -- ESC 8, ?1048l or CSI u after ESC 7, ?1048h or CSI s,
// on either screen -- reads a slot on the joiner that nothing filled, and
// gives ASCII where the session's gives what it saved. Filling one would take
// a cursor save of the snapshot's own, which saves the joiner's cursor
// position and pen as well, wherever they happen to be.
func (m *ModeTracker) Snapshot() []byte {
	out := m.candidates[len(m.candidates)-1].appendRegion(nil)
	out = m.appendModes(out, 0)
	out = kittyPushes(out, m.mainKeys)
	out = append(out, m.modifyOtherKeys...)
	if !m.altActive() && len(m.altKeys.entries) > 0 {
		// The alternate screen's stack, kept while the normal screen shows,
		// replayed on a trip there and back; see Restore.
		out = append(out, "\x1b7\x1b[?47h"...)
		out = kittyPushes(out, m.altKeys)
		out = append(out, "\x1b[?47l\x1b8"...)
	}
	var savedG0 []byte
	if m.altActive() {
		if m.altVia == 1049 || (m.savedBy1049 && len(m.mainSavedG0) > 0) {
			// ?1049h saves the cursor, G0 with it, for the session's ?1049l
			// to restore, and the joiner's ?1049h saves the joiner's. So the
			// G0 the session saved is designated just ahead of it, which
			// costs no save of its own and changes nothing the joiner sees.
			// When a ?47h or ?1047h came after it, saving nothing, the
			// ?1049h is replayed ahead of that mode anyway, as the session
			// sent it, and that mode finds the joiner on the alternate screen
			// already -- unless the save holds ASCII, which a joiner's slot
			// that nothing filled restores too.
			savedG0 = m.mainSavedG0
			out = append(out, savedG0...)
			out = appendMode(out, 1049, true)
		}
		if m.altVia != 1049 {
			// Replayed through the mode that entered last, so a joiner is
			// left in the state the session's own "l" will match.
			out = appendMode(out, m.altVia, true)
		}
		out = kittyPushes(out, m.altKeys)
	}
	out = append(out, m.charsetG0...)
	if len(m.charsetG0) == 0 && len(savedG0) > 0 {
		// The joiner holds the saved G0 now, and the session ASCII.
		out = append(out, "\x1b(B"...)
	}
	out = append(out, m.partial...)
	return out
}

// ReplayParts is the tracked state a reconstruction needs, in the order
// Snapshot emits it, split where the reconstruction interleaves drawing.
type ReplayParts struct {
	DECModes      map[int]bool // each tracked DEC private mode, the alternate screen's aside, with its value
	Modes         []byte       // those not at their default as CSI ? n h/l, in Snapshot's order, DECAWM (7) excluded
	Autowrap      bool         // DECAWM
	MainKeys      []byte       // the main kitty stack's pushes, then modifyOtherKeys
	HiddenAltKeys []byte       // the hidden alternate stack's pushes, while the main screen shows, or nil
	AltVia        int          // 47, 1047 or 1049 while the alternate screen shows, else 0
	AltKeys       []byte       // the alternate stack's pushes, while it shows
}

// ReplayParts returns Snapshot's pieces but for the region, the charset and
// the partial, which a reconstruction gives in places of its own: Modes, with
// DECAWM put back in its place when it is off, then MainKeys, then either the
// switch through AltVia and AltKeys, or HiddenAltKeys, which Snapshot pushes
// on a trip to the alternate screen and back. The render builds its own trip,
// so the pushes come alone.
//
// It doesn't carry the normal screen's saved G0 either, which Snapshot
// designates ahead of a ?1049h, nor the ?1049h Snapshot replays for it ahead
// of a ?47h or ?1047h that came after one.
func (m *ModeTracker) ReplayParts() ReplayParts {
	p := ReplayParts{DECModes: make(map[int]bool, len(restorable))}
	for n, def := range restorable {
		if altScreenModes[n] {
			continue
		}
		v, ok := m.decPrivate[n]
		if !ok {
			v = def
		}
		p.DECModes[n] = v
	}
	p.Autowrap = p.DECModes[7]
	p.Modes = m.appendModes(nil, 7)
	p.MainKeys = append(kittyPushes(nil, m.mainKeys), m.modifyOtherKeys...)
	if m.altActive() {
		p.AltVia = m.altVia
		p.AltKeys = kittyPushes(nil, m.altKeys)
	} else if len(m.altKeys.entries) > 0 {
		p.HiddenAltKeys = kittyPushes(nil, m.altKeys)
	}
	return p
}

// changedModes returns the tracked DEC private modes not at their default, in
// ascending order, so what is emitted from them is deterministic.
func (m *ModeTracker) changedModes() []int {
	nums := make([]int, 0, len(m.decPrivate))
	for n, set := range m.decPrivate {
		if set != restorable[n] {
			nums = append(nums, n)
		}
	}
	sort.Ints(nums)
	return nums
}

// appendModes appends the modes not at their default as they are set, but for
// skip.
func (m *ModeTracker) appendModes(out []byte, skip int) []byte {
	for _, n := range m.changedModes() {
		if n != skip {
			out = appendMode(out, n, m.decPrivate[n])
		}
	}
	return out
}

// appendMode appends CSI ? n h, or l when !set.
func appendMode(out []byte, n int, set bool) []byte {
	out = append(out, 0x1b, '[', '?')
	out = strconv.AppendInt(out, int64(n), 10)
	if set {
		return append(out, 'h')
	}
	return append(out, 'l')
}
