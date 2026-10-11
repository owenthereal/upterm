package io

import (
	"io"
	"slices"
)

// TerminalQueryFilter wraps an io.Writer and filters out terminal query
// sequences from the output. This prevents queries sent by the host's shell
// from reaching connected clients, whose terminals would otherwise respond
// and pollute the PTY input.
//
// What counts as a query is decided by family, in query_classify.go. The
// filter itself only follows the stream the way a terminal's DEC parser does
// -- where each sequence starts, where it ends, and what the terminal does
// with the bytes in between -- and holds a sequence until its classifier can
// decide it: an ESC sequence or a CSI to its final byte, an OSC to its
// terminator. A DCS, APC, PM or SOS is passed as it streams, so a sixel or an
// image is never buffered, and a well-formed tmux passthrough wrapper passes
// byte for byte.
//
// Terminals disagree on where a malformed string ends. A DEC parser ends one
// at a CAN, a SUB or an ESC that isn't ST; kitty keeps any string open there,
// and tmux a DCS, and each takes what follows as more of it. So an OSC the
// filter is still holding when it ends one of those ways is dropped whole,
// query or not: passed through, "ESC ]4;0; CAN ;1;? BEL" is a palette query to
// kitty. What that costs is a malformed OSC's effect on a DEC terminal, such
// as a title ended by a stray ESC.
//
// A sequence the filter has emitted before its end -- a string it passes, a
// tmux wrapper among them, a CSI a terminal ignores, or one it gave up on past
// its bound -- is always closed. The terminal stays inside it until it sees
// the ESC that ended it in the input, and that ESC starts a sequence the
// filter holds. If the held sequence passes, its ESC is the close; if it is
// dropped, the filter sends ESC CAN in its place, whose ESC ends the emitted
// sequence the way the input's did and whose CAN cancels the escape it
// starts. Without the close, whatever came after a dropped query landed
// inside the emitted sequence.
type TerminalQueryFilter struct {
	w      io.Writer
	state  queryFilterState
	seqBuf []byte // the sequence being decided: held, so neither emitted nor dropped yet
	outBuf []byte // reusable output buffer to reduce allocations

	// closeOwed is set while the terminal downstream is still inside a
	// sequence the filter emitted unfinished, which the input has ended with
	// the ESC that starts seqBuf. That ESC is held, so the terminal hasn't
	// seen the end yet; see endPassAtESC and settleClose.
	closeOwed bool

	// wrapAt is how much of tmuxPrefix a DCS's first bytes have matched, in
	// qfStateDCS. The bytes have gone out; only the count is kept.
	wrapAt int
}

type queryFilterState int

const (
	qfStateNormal       queryFilterState = iota
	qfStateEsc                           // holding ESC
	qfStateEscInter                      // holding ESC and intermediates (0x20–0x2F)
	qfStateEscOverBound                  // passing an ESC sequence the filter gave up on, to its final byte
	qfStateCSI                           // holding ESC [ (CSI-entry)
	qfStateCSIParam                      // holding ESC [ and a prefix or parameter bytes
	qfStateCSIInter                      // holding a CSI head and its intermediates (0x20–0x2F)
	qfStateCSIIgnore                     // passing a CSI a terminal ignores, to its final byte
	qfStateCSIOverBound                  // passing a CSI past its bound, to its final byte
	qfStateOSCNum                        // holding ESC ] and what comes before the first ';'
	qfStateOSC                           // holding an OSC past its first ';'
	qfStateOSCEsc                        // holding an OSC and an ESC: ST if '\' follows, else the OSC ended there
	qfStateOSCOverBound                  // passing an OSC past its bound, to its end
	qfStateDCS                           // passing a DCS whose first bytes may yet be tmuxPrefix
	qfStateString                        // passing a DCS, APC, PM or SOS to its end
	qfStateWrapper                       // passing a tmux wrapper to its unescaped ST
	qfStateWrapperEsc                    // holding an ESC inside a tmux wrapper, to see the byte it escapes
)

// NewTerminalQueryFilter creates a filter that removes terminal query
// sequences from output before writing to the underlying writer.
func NewTerminalQueryFilter(w io.Writer) *TerminalQueryFilter {
	return &TerminalQueryFilter{
		w:      w,
		seqBuf: make([]byte, 0, 64),
		outBuf: make([]byte, 0, 4096),
	}
}

// Write filters terminal query sequences from p and writes the result to the
// underlying writer. Returns len(p) on success to indicate all input bytes were
// processed. On error, returns 0 because the filtered output is written atomically
// (all or nothing) and input bytes don't map 1:1 to output bytes due to filtering.
func (f *TerminalQueryFilter) Write(p []byte) (int, error) {
	// Reuse output buffer, reset to zero length but keep capacity
	f.outBuf = f.outBuf[:0]

	// Process each byte, filtering out query sequences
	for _, b := range p {
		f.processByte(b)
	}

	// Write filtered output atomically
	if len(f.outBuf) > 0 {
		_, err := f.w.Write(f.outBuf)
		if err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

// The most an ESC sequence with intermediates and a CSI head are held for,
// framing included. The bound counts what is held before the final byte: a
// final byte that arrives with the head full is still classified, and the next
// byte that isn't one gives the head up, so it passes unclassified to its end.
// Queries are a handful of bytes; one padded past its bound passes, which is a
// stated limit of the design.
const (
	maxEscHeld = 8
	maxCSIHeld = 32
)

// The most an OSC is held for, counted in raw bytes from its ESC ], the
// control bytes it ignores included and its terminator not. Before its first
// ';' an OSC is reading its number, which is four digits at the outside, so
// one still reading it after 8 bytes is given up on there rather than at the
// whole bound. An ESC held to see whether '\' follows comes on top of either
// bound. The next byte that would be held past a bound gives the OSC up: what
// is held goes out, and the rest passes unclassified to its end.
const (
	maxOSCNumHeld = 8
	maxOSCHeld    = 256
)

// tmuxPrefix is what a DCS's first bytes are when it is a tmux passthrough
// wrapper: ESC P tmux; then a sequence with each ESC doubled, then ESC \.
const tmuxPrefix = "tmux;"

// maxPendingBytes is the most the filter will ever be holding, and so the most
// Pending can return. Every state that accumulates gives up at a bound of its
// own, counted in raw bytes with the sequence's framing included: 8 of an ESC
// sequence with intermediates, 32 of a CSI head, 8 of an OSC number and 256 of
// an OSC, introducer through payload. The largest is the OSC's 256. On top of
// it comes the one ESC that Pending can return beyond a bound: an OSC held to
// its bound can still be waiting to see whether the ESC that follows begins its
// ST, and that ESC is not counted in the 256. So 256 + 1 = 257.
//
// It matters because Pending is replayed to every joining writer after the
// ring: what the filter holds is output no reader has seen yet, and it is held
// outside the ring's byte budget.
const maxPendingBytes = 257

// Pending returns the bytes that put a fresh filter in this one's state. Fed
// everything this filter has written, then Pending(), a fresh filter ends in the
// state this one is in: where it is in a sequence, the match so far against
// "tmux;" at the start of a DCS, whether it is passing a sequence it gave up
// on, and whether it owes a close. A joiner's filter takes its state from the
// result (MultiWriter.Append), and a newly promoted primary is handed it raw
// (hostSink.promote). What it returns depends on the state:
//
//   - While deciding, the held bytes: a head, or an OSC to its terminator.
//   - In a pass state, where the head went out with the stream, an ESC held to
//     see what the next byte makes of it, or nothing. A DCS, APC, PM or SOS, a
//     tmux wrapper, a CSI the terminal ignores and a sequence past its bound
//     are all in this state.
//   - With a close owed, the held sequence that will settle it. It begins with
//     the ESC that ended the emitted sequence, so the joiner's filter owes the
//     same close.
//
// The result restores a parse state; it does not recover history. It never
// contains a byte the filter dropped, since those are gone and are not coming
// back, nor a C0 it forwarded, which went out ahead of the hold and would be
// sent twice. It is a copy, and never longer than maxPendingBytes.
func (f *TerminalQueryFilter) Pending() []byte {
	return slices.Clone(f.seqBuf)
}

// processByte processes a single byte, appending non-filtered output to f.outBuf.
func (f *TerminalQueryFilter) processByte(b byte) {
	// CAN and SUB end every sequence but a tmux wrapper, which takes them as
	// payload. After an ESC in a wrapper one isn't payload: the ESC escapes
	// neither an ESC nor a '\', so it has ended the wrapper (wrapperByte), and
	// the cancel then cancels the ESC as it would any held one.
	if (b == 0x18 || b == 0x1a) && f.state != qfStateNormal && f.state != qfStateWrapper {
		f.cancel(b)
		return
	}
	switch f.state {
	case qfStateNormal:
		if b == 0x1b { // ESC
			f.state = qfStateEsc
			f.seqBuf = append(f.seqBuf[:0], b)
			return // Don't output yet, might be a query
		}
		f.outBuf = append(f.outBuf, b)

	case qfStateEsc, qfStateEscInter:
		f.escByte(b)

	case qfStateCSI, qfStateCSIParam, qfStateCSIInter:
		f.csiByte(b)

	case qfStateOSCNum, qfStateOSC:
		f.oscByte(b)

	case qfStateOSCEsc:
		f.oscEscByte(b)

	case qfStateWrapper, qfStateWrapperEsc:
		f.wrapperByte(b)

	case qfStateEscOverBound, qfStateCSIIgnore, qfStateCSIOverBound,
		qfStateOSCOverBound, qfStateDCS, qfStateString:
		f.passByte(b)
	}
}

// cancel takes a CAN or SUB, which ends a sequence from any state on the DEC
// parser terminals implement; the terminal goes back to ground and executes
// it. Inside a tmux wrapper they are payload instead, and never get here but
// straight after an ESC, which they find held as the wrapper's close.
func (f *TerminalQueryFilter) cancel(b byte) {
	switch f.state {
	case qfStateOSCEsc:
		// The OSC ended at its ESC already, a byte before the cancel, so it
		// goes as any OSC ended there does, and the cancel then cancels the
		// ESC on its own.
		f.endOSCAtESC()
	case qfStateOSCNum, qfStateOSC:
		// A held OSC is dropped whole, query or not, and none of it goes out
		// with the cancel: kitty keeps a string open past a CAN or SUB, so
		// "ESC ]4;0; CAN ;1;? BEL" reaches it as a palette query. That holds
		// with a close owed too: kitty may have ended the emitted string
		// already, at a BEL in a DCS, and would read the OSC's head as live.
		// Only the OSC's own ESC goes out, ahead of the cancel, as the close.
		keep := 0
		if f.closeOwed {
			keep = 1
		}
		f.seqBuf = append(f.seqBuf[:keep], b)
		f.flushAndReset()
		return
	}
	// What is held is a head, which goes out with the cancel, and the
	// terminal discards it -- a query included, which a terminal answers only
	// at its final byte. Held back, it kept the cancel from the terminal: a
	// session's last reset to a guest is a lone CAN when all it left open was
	// a sequence, and nothing after it would push it out. When a close is
	// owed, the held ESC going out is that close, so the cancel needs no
	// second one. In a pass state nothing is held, and the cancel goes out
	// alone.
	f.seqBuf = append(f.seqBuf, b)
	f.flushAndReset()
}

// escByte takes a byte after ESC, with or without intermediates. An ESC
// sequence is ESC, then intermediates (0x20–0x2F), then a final byte
// (0x30–0x7E), except that ESC [ starts a CSI, ESC ] an OSC, and ESC P, ESC _,
// ESC ^ and ESC X a DCS, APC, PM and SOS instead.
func (f *TerminalQueryFilter) escByte(b byte) {
	if f.headControl(b) {
		return
	}
	switch {
	case b >= 0x80:
		// 0x80–0x9F, the 8-bit C1 controls the design leaves uncovered (in
		// UTF-8 they are continuation bytes far more often), give the head up
		// as they do a CSI's: what is held goes out, and the rest passes to
		// its final byte. 0xA0–0xFF never get here; headControl drops them.
		f.passFrom(b, qfStateEscOverBound)
	case b <= 0x2f:
		// An intermediate, which a terminal collects until the final byte.
		// Flushing the head here instead let the final byte go out on its
		// own when the ESC after it was a query: "ESC ( ESC [6n B" became
		// "ESC ( B", and the B a charset designation.
		f.hold(b, qfStateEscInter, maxEscHeld, qfStateEscOverBound)
	case f.state == qfStateEsc && b == '[':
		f.seqBuf = append(f.seqBuf, b)
		f.state = qfStateCSI
	case f.state == qfStateEsc && b == ']':
		f.seqBuf = append(f.seqBuf, b)
		f.state = qfStateOSCNum
	case f.state == qfStateEsc && b == 'P':
		// No DCS is classified, so its introducer goes out at once, and
		// the DCS passes as it streams. Its first bytes are watched for a
		// tmux wrapper, whose doubled ESCs would otherwise each end it.
		f.passFrom(b, qfStateDCS)
		f.wrapAt = 0
	case f.state == qfStateEsc && (b == '_' || b == '^' || b == 'X'):
		// An APC, PM or SOS goes out at once and passes as it streams.
		f.passFrom(b, qfStateString)
	default:
		f.seqBuf = append(f.seqBuf, b)
		f.decide(escQuery(f.seqBuf))
	}
}

// csiByte takes a byte of a CSI head: ESC [, then an optional prefix
// (0x3C–0x3F), parameter bytes (0x30–0x3B), intermediates (0x20–0x2F), and a
// final byte (0x40–0x7E). Out of that order a terminal ignores the CSI.
func (f *TerminalQueryFilter) csiByte(b byte) {
	if f.headControl(b) {
		return
	}
	switch {
	case b >= 0x40 && b <= 0x7e:
		f.seqBuf = append(f.seqBuf, b)
		f.decide(csiQuery(f.seqBuf))
	case b >= 0x80 || f.csiIgnores(b):
		// Out of order, the CSI puts a terminal in CSI-ignore, which
		// dispatches nothing, so it is no query: what is held goes out, and
		// the rest passes to the final byte, which CSI-ignore still waits
		// for. A byte of 0x80–0x9F, a C1 control the design leaves
		// uncovered, gives the head up the same way.
		f.passFrom(b, qfStateCSIIgnore)
	case b <= 0x2f:
		f.hold(b, qfStateCSIInter, maxCSIHeld, qfStateCSIOverBound)
	default: // a prefix or parameter byte, 0x30–0x3F
		f.hold(b, qfStateCSIParam, maxCSIHeld, qfStateCSIOverBound)
	}
}

// csiIgnores reports whether b, a byte from 0x20 to 0x3F, puts a terminal in
// CSI-ignore from the current CSI state: a ':' straight after the '[', a
// prefix byte after a parameter, or a parameter or prefix byte after an
// intermediate.
func (f *TerminalQueryFilter) csiIgnores(b byte) bool {
	switch f.state {
	case qfStateCSI:
		return b == ':'
	case qfStateCSIParam:
		return b >= 0x3c && b <= 0x3f
	case qfStateCSIInter:
		return b >= 0x30 && b <= 0x3f
	}
	return false
}

// headControl takes the bytes a terminal treats the same way in every ESC and
// CSI state, and reports whether b was one of them. CAN and SUB never get
// here; processByte cancels on them first.
func (f *TerminalQueryFilter) headControl(b byte) bool {
	switch {
	case b == 0x1b:
		// An ESC abandons the head, and the terminal executes nothing of it,
		// so it is dropped rather than flushed. Flushed, it would splice onto
		// whatever goes out next: with the query after it dropped,
		// "ESC [6 ESC [6n hello" would reach the terminal as the CSI
		// "ESC [6h" and the text "ello". This ESC starts a new sequence.
		f.drop()
		f.seqBuf = append(f.seqBuf, b)
		f.state = qfStateEsc
	case b == 0x7f, b >= 0xa0:
		// The terminal ignores DEL here, so it is dropped. It is never held,
		// so it doesn't count toward the head's bound either. Ghostty's parse
		// table ignores 0xA0–0xFF in these states just the same, so they are
		// dropped too. Giving the head up on one instead let "ESC 0xA0 [6n"
		// through, which the terminal reads as ESC [6n.
	case b < 0x20:
		// The terminal executes a C0 where it stands and carries on with the
		// head, so it goes out now and the head stays held. Taken for the
		// head's final byte instead, it let "ESC [6 CR n" through whole, and
		// a terminal still answers that.
		f.settleClose()
		f.outBuf = append(f.outBuf, b)
	default:
		return false
	}
	return true
}

// hold adds b, which doesn't end the held sequence, and moves to state next.
// A sequence that already holds bound bytes is given up on instead: it goes
// out with b, and the rest passes in state over, so a query padded past the
// bound passes, but the filter still knows where the sequence ends.
func (f *TerminalQueryFilter) hold(b byte, next queryFilterState, bound int, over queryFilterState) {
	if len(f.seqBuf) >= bound {
		f.passFrom(b, over)
		return
	}
	f.seqBuf = append(f.seqBuf, b)
	f.state = next
}

// passFrom emits what is held and b, and passes the rest of the sequence in
// state pass. The terminal is then inside a sequence the filter emitted
// unfinished.
func (f *TerminalQueryFilter) passFrom(b byte, pass queryFilterState) {
	f.seqBuf = append(f.seqBuf, b)
	f.flushAndReset()
	f.state = pass
}

// passByte takes a byte of a sequence the filter emitted unfinished: an ESC
// sequence, a CSI or an OSC it gave up on, a CSI a terminal ignores, or a DCS,
// APC, PM or SOS it passes. Each byte goes out as it comes, and the end the
// terminal would see returns the filter to ground: a final byte, or a BEL for
// an OSC. A DCS, APC, PM or SOS ends only at an ESC, a CAN or a SUB, so a BEL
// in one is payload.
func (f *TerminalQueryFilter) passByte(b byte) {
	if b == 0x1b {
		f.endPassAtESC()
		return
	}
	f.outBuf = append(f.outBuf, b)
	switch f.state {
	case qfStateEscOverBound:
		if b >= 0x30 && b <= 0x7e {
			f.state = qfStateNormal
		}
	case qfStateCSIIgnore, qfStateCSIOverBound:
		if b >= 0x40 && b <= 0x7e {
			f.state = qfStateNormal
		}
	case qfStateOSCOverBound:
		if b == 0x07 {
			f.state = qfStateNormal
		}
	case qfStateDCS:
		// tmux takes a DCS whose first bytes are tmuxPrefix for a wrapper;
		// one byte off, and it is an ordinary DCS to its end.
		switch {
		case b != tmuxPrefix[f.wrapAt]:
			f.state = qfStateString
		case f.wrapAt+1 == len(tmuxPrefix):
			f.state = qfStateWrapper
		default:
			f.wrapAt++
		}
	}
}

// endPassAtESC ends a sequence the filter emitted unfinished at an ESC in the
// input. The ESC starts a new sequence, held like any other, so the terminal
// hasn't seen the end of the emitted one, and the filter owes it a close
// until the held sequence settles it (settleClose). Without the close, a
// query dropped from behind an emitted head let whatever came next land
// inside that head: "ESC [1$2 ESC [6n X" became "ESC [1$2 X", which a
// terminal reads as one ignored CSI ending at the X. In a string the ESC may
// begin ST, and ESC \ then passes as an ESC sequence of its own, which is
// how the terminal reads it once the string has ended at the ESC; that ESC is
// the close.
func (f *TerminalQueryFilter) endPassAtESC() {
	f.closeOwed = true
	f.seqBuf = append(f.seqBuf[:0], 0x1b)
	f.state = qfStateEsc
}

// oscByte takes a byte of an OSC the filter is holding. The OSC is held whole
// to its terminator, BEL or ST, and classified there by oscQuery, since its
// number and every field can decide it. Every other byte is payload, held and
// counted toward the bounds: the control bytes the terminal ignores in an
// OSC, DEL, and bytes 0x80–0xFF, so UTF-8 in a title passes as it came.
func (f *TerminalQueryFilter) oscByte(b byte) {
	switch {
	case b == 0x07:
		query := oscQuery(f.seqBuf)
		f.seqBuf = append(f.seqBuf, b)
		f.decide(query)
	case b == 0x1b:
		f.seqBuf = append(f.seqBuf, b)
		f.state = qfStateOSCEsc
	case f.state == qfStateOSCNum && b == ';':
		f.seqBuf = append(f.seqBuf, b)
		f.state = qfStateOSC
	case f.state == qfStateOSCNum:
		f.hold(b, qfStateOSCNum, maxOSCNumHeld, qfStateOSCOverBound)
	default:
		f.hold(b, qfStateOSC, maxOSCHeld, qfStateOSCOverBound)
	}
}

// oscEscByte takes the byte after an ESC inside a held OSC. A '\' makes the
// ESC ST, which ends the OSC as BEL does; anything else means the OSC ended at
// the ESC, and the byte is the first after that ESC.
func (f *TerminalQueryFilter) oscEscByte(b byte) {
	if b == '\\' {
		query := oscQuery(f.seqBuf[:len(f.seqBuf)-1])
		f.seqBuf = append(f.seqBuf, b)
		f.decide(query)
		return
	}
	f.endOSCAtESC()
	f.escByte(b)
}

// endOSCAtESC ends a held OSC at an ESC that isn't ST. A DEC terminal
// dispatches the OSC there, but kitty keeps it open and reads on into what
// follows, so it is dropped whole, query or not. Passed through as it
// used to be, "ESC ]11; ESC [6n ? BEL" lost only the query and went out as
// "ESC ]11;? BEL", a colour query glued back together. The ESC starts a new
// sequence, held like any other, and a close owed is settled as for any drop.
func (f *TerminalQueryFilter) endOSCAtESC() {
	f.drop()
	f.seqBuf = append(f.seqBuf, 0x1b)
	f.state = qfStateEsc
}

// wrapperByte takes a byte of a tmux wrapper, which follows tmux's own DCS
// rules for the pairs a well-formed wrapper is made of: ESC ESC is one ESC of
// the wrapped sequence, so a doubled ESC doesn't end the wrapper, and only an
// unescaped ESC \ does. CAN and SUB are payload. The wrapped sequence isn't
// classified: every byte goes out as it came, and the ESC is held, as in a
// passed string, only until the byte after it says what it escapes. Read by
// the DEC rules instead, every doubled ESC restarted a sequence and lost the
// first of the pair.
//
// Any other byte after the ESC ends the wrapper there, as a DEC terminal ends
// the DCS. The wrapper went out unfinished, so the ESC owes it a close, as one
// that ends a passed string does: it is held as the start of a new sequence,
// and the byte is parsed as that sequence's next. A well-formed wrapper never
// has such a pair, since it doubles every ESC it wraps. Kept open, as tmux
// keeps it, a malformed or interrupted wrapper, such as an image cut off by
// Ctrl-C, let every query through until the next unescaped ST. A CAN or SUB
// after the ESC never gets here: processByte cancels the held ESC on it, which
// ends the wrapper the same way, and the ESC goes out with the cancel as the
// close.
func (f *TerminalQueryFilter) wrapperByte(b byte) {
	if f.state == qfStateWrapper {
		if b == 0x1b {
			f.seqBuf = append(f.seqBuf[:0], b)
			f.state = qfStateWrapperEsc
			return
		}
		f.outBuf = append(f.outBuf, b)
		return
	}
	switch b {
	case 0x1b:
		f.seqBuf = append(f.seqBuf, b)
		f.flushAndReset()
		f.state = qfStateWrapper
	case '\\':
		f.seqBuf = append(f.seqBuf, b)
		f.flushAndReset()
	default:
		f.closeOwed = true
		f.state = qfStateEsc
		f.escByte(b)
	}
}

// decide ends the held sequence at its final byte, already held: a query is
// dropped, and anything else goes out as it came in.
func (f *TerminalQueryFilter) decide(query bool) {
	if query {
		f.drop()
		return
	}
	f.flushAndReset()
}

// drop discards the held sequence: a query, a head the input abandoned, or an
// OSC that ended abnormally.
func (f *TerminalQueryFilter) drop() {
	f.seqBuf = f.seqBuf[:0]
	f.state = qfStateNormal
	f.settleClose()
}

// settleClose emits the close a sequence the filter emitted unfinished is
// owed, when the held ESC that was to be it can't go out first: the held
// sequence was dropped, or a C0 is due, which must not land inside a sequence
// the input had already ended. The close is ESC CAN. The ESC ends the emitted
// sequence the way the input's ESC did, and the CAN cancels the new escape,
// leaving the terminal in ground with nothing else done; a bare CAN would
// cancel the emitted sequence rather than end it, which discards a string.
func (f *TerminalQueryFilter) settleClose() {
	if f.closeOwed {
		f.outBuf = append(f.outBuf, 0x1b, 0x18)
		f.closeOwed = false
	}
}

// flushAndReset appends buffered bytes to outBuf and resets state. Whatever is
// held starts with the ESC that ended any sequence owed a close, so emitting
// it is that close.
func (f *TerminalQueryFilter) flushAndReset() {
	f.outBuf = append(f.outBuf, f.seqBuf...)
	f.state = qfStateNormal
	f.seqBuf = f.seqBuf[:0]
	f.closeOwed = false
}
