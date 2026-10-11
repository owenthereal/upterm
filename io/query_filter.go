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
// What counts as a query is decided by family, in query_classify.go, from the
// tables in the terminal query families design
// (designs/2026-10-11-terminal-query-families-design.md). The filter itself
// only follows the stream the way a terminal's DEC parser does -- where each
// sequence starts, where it ends, and what the terminal does with the bytes
// in between -- and holds a sequence until its classifier can decide it.
type TerminalQueryFilter struct {
	w      io.Writer
	state  queryFilterState
	seqBuf []byte // the sequence being decided: held, so neither emitted nor dropped yet
	outBuf []byte // reusable output buffer to reduce allocations
	oscCmd int    // OSC command number being parsed

	// closeOwed is set while the terminal downstream is still inside a
	// sequence the filter emitted unfinished, which the input has ended with
	// the ESC that starts seqBuf. That ESC is held, so the terminal hasn't
	// seen the end yet; see endPassAtESC and settleClose.
	closeOwed bool
}

type queryFilterState int

const (
	qfStateNormal        queryFilterState = iota
	qfStateEsc                            // holding ESC
	qfStateEscInter                       // holding ESC and intermediates (0x20–0x2F)
	qfStateEscOverBound                   // passing an ESC sequence the filter gave up on, to its final byte
	qfStateCSI                            // holding ESC [ (CSI-entry)
	qfStateCSIParam                       // holding ESC [ and a prefix or parameter bytes
	qfStateCSIInter                       // holding a CSI head and its intermediates (0x20–0x2F)
	qfStateCSIIgnore                      // passing a CSI a terminal ignores, to its final byte
	qfStateCSIOverBound                   // passing a CSI past its bound, to its final byte
	qfStateOSC                            // saw ESC ]
	qfStateOSCParam                       // saw OSC number
	qfStateOSCSemi                        // saw OSC number ;
	qfStateOSCQuery                       // saw OSC N ; ? (query for color)
	qfStateOSCQueryEsc                    // saw ESC in OSC query (ST if '\' follows, else the query ends there)
	qfStateOSCContent                     // saw OSC N ; <non-?> (not a query, pass through)
	qfStateOSCContentEsc                  // saw ESC in OSC content, or right after the ; (ST if '\' follows, else the OSC ends there)
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

// maxPendingBytes is the most the filter will ever be holding, and so the most
// Pending can return. Every state that accumulates gives up at a bound of its
// own: 32 bytes of a CSI head, 8 of an ESC sequence with intermediates, 32 of
// an OSC colour query, 256 of OSC content, and 8 of an OSC number. The largest
// is the OSC content bound, plus the byte that overshoots it and the ESC of a
// string terminator that turned out not to be one; 260 covers that with room
// to spare.
//
// It matters because Pending is replayed to every joining writer ahead of the
// ring: what the filter holds is output no reader has seen yet, and it is held
// outside the ring's byte budget.
const maxPendingBytes = 260

// Pending returns a copy of the bytes of an escape sequence the filter is
// still holding because it has not yet seen the sequence's end. They are
// not in the underlying writer yet. The result never exceeds maxPendingBytes.
func (f *TerminalQueryFilter) Pending() []byte {
	return slices.Clone(f.seqBuf)
}

// processByte processes a single byte, appending non-filtered output to f.outBuf.
func (f *TerminalQueryFilter) processByte(b byte) {
	if (b == 0x18 || b == 0x1a) && f.state != qfStateNormal {
		// CAN or SUB cancels a sequence from any state on the DEC parser
		// terminals implement. What is held goes out with the cancel, and the
		// terminal discards it -- a query included, which a terminal answers
		// only at its terminator. Held back, it kept the cancel from the
		// terminal: a session's last reset to a guest is a lone CAN when all
		// it left open was a sequence, and nothing after it would push it out.
		// When a close is owed, the held ESC going out is that close, so the
		// cancel needs no second one.
		f.seqBuf = append(f.seqBuf, b)
		f.flushAndReset()
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

	case qfStateEscOverBound, qfStateCSIIgnore, qfStateCSIOverBound:
		f.passByte(b)

	case qfStateOSC:
		f.seqBuf = append(f.seqBuf, b)
		if b >= '0' && b <= '9' {
			f.oscCmd = f.oscCmd*10 + int(b-'0')
			f.state = qfStateOSCParam
			return
		}
		// Invalid OSC, output it
		f.flushAndReset()

	case qfStateOSCParam:
		f.seqBuf = append(f.seqBuf, b)
		// The oscCmd guard below counts value, not digits, so a run of zeros
		// slips past it forever. An OSC number is four digits at the outside,
		// making "ESC ] dddd ;" seven bytes, so anything past eight is not one.
		if len(f.seqBuf) > 8 {
			f.flushAndReset()
			return
		}
		if b >= '0' && b <= '9' {
			// Check before updating to prevent overflow (OSC commands are 1-3 digits)
			if f.oscCmd > 99 {
				f.flushAndReset()
				return
			}
			f.oscCmd = f.oscCmd*10 + int(b-'0')
			return
		}
		if b == ';' {
			f.state = qfStateOSCSemi
			return
		}
		if b == 0x07 { // BEL - OSC without content, not a query
			f.flushAndReset()
			return
		}
		// Invalid, output it
		f.flushAndReset()

	case qfStateOSCSemi:
		f.seqBuf = append(f.seqBuf, b)
		if b == '?' {
			// This might be a query - check if it's OSC 10, 11, or 12
			if f.oscCmd == 10 || f.oscCmd == 11 || f.oscCmd == 12 {
				f.state = qfStateOSCQuery
				return
			}
			// Other OSC query (e.g., OSC 4;?), don't filter - treat as content
			f.state = qfStateOSCContent
			return
		}
		// An empty payload ends at its terminator like any other. Taking the
		// byte after the ";" as content, whatever it was, meant "ESC ] 0 ; BEL"
		// -- a shell clearing its title -- never closed, and everything the
		// command printed next was held behind it until the next BEL or ESC,
		// or the content bound.
		if b == 0x07 { // BEL - end of OSC
			f.flushAndReset()
			return
		}
		if b == 0x1b { // ESC - possible ST
			f.state = qfStateOSCContentEsc
			return
		}
		// Not a query (it's setting a value), continue to end of OSC
		f.state = qfStateOSCContent

	case qfStateOSCContent:
		f.seqBuf = append(f.seqBuf, b)
		if b == 0x07 { // BEL - end of OSC
			// Pass through the entire OSC sequence
			f.flushAndReset()
			return
		}
		if b == 0x1b { // ESC - possible ST
			f.state = qfStateOSCContentEsc
			return
		}
		if len(f.seqBuf) > 256 {
			f.flushAndReset()
		}

	case qfStateOSCContentEsc:
		if b == '\\' { // ST (String Terminator)
			f.seqBuf = append(f.seqBuf, b)
			// Pass through the entire OSC sequence
			f.flushAndReset()
			return
		}
		// Anything else ends the string: an ESC abandons an OSC whatever
		// follows it, and only ESC \ ends it as ST. Treating the ESC as
		// content let "ESC ] 0 ; t ESC [ 6 n BEL" through whole, so every
		// joiner's terminal answered the cursor-position query inside it into
		// the pty. The OSC before the ESC is not ours to filter, so it goes
		// out; the ESC starts a sequence again, and this byte is the first of
		// it.
		f.endStringAtESC()
		f.processByte(b)

	case qfStateOSCQuery:
		f.seqBuf = append(f.seqBuf, b)
		if b == 0x07 { // BEL - end of OSC query
			// This is a color query (OSC 10/11/12), filter it
			f.drop()
			return
		}
		if b == 0x1b { // ESC - possible ST
			f.state = qfStateOSCQueryEsc
			return
		}
		if len(f.seqBuf) > 32 {
			f.flushAndReset()
		}

	case qfStateOSCQueryEsc:
		if b == '\\' { // ST (String Terminator)
			f.seqBuf = append(f.seqBuf, b)
			// This is a color query (OSC 10/11/12), filter it
			f.drop()
			return
		}
		// Ended by the ESC, same as OSC content above: what we have is an
		// unterminated query, which is passed through as it always was, and
		// what follows the ESC is a new sequence rather than more of it.
		f.endStringAtESC()
		f.processByte(b)

	default:
		f.outBuf = append(f.outBuf, b)
	}
}

// escByte takes a byte after ESC, with or without intermediates. An ESC
// sequence is ESC, then intermediates (0x20–0x2F), then a final byte
// (0x30–0x7E), except that ESC [ starts a CSI and ESC ] an OSC instead.
func (f *TerminalQueryFilter) escByte(b byte) {
	if f.headControl(b) {
		return
	}
	switch {
	case b >= 0x80:
		// A byte of 0x80 or more, which the design leaves uncovered, gives
		// the head up as it does a CSI's: what is held goes out, and the rest
		// passes to its final byte.
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
		f.state = qfStateOSC
		f.oscCmd = 0
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
		// for. A byte of 0x80 or more, which the design leaves uncovered, is
		// given up on the same way.
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
	case b == 0x7f:
		// The terminal ignores DEL here, so it is dropped. It is never held,
		// so it doesn't count toward the head's bound either.
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

// hold adds b, which doesn't end the head, and moves to state next. A head
// that already holds bound bytes is given up on instead: it goes out with b,
// and the rest passes in state over, so a query padded past the bound passes,
// but the filter still knows where the sequence ends.
func (f *TerminalQueryFilter) hold(b byte, next queryFilterState, bound int, over queryFilterState) {
	if len(f.seqBuf) >= bound {
		f.passFrom(b, over)
		return
	}
	f.seqBuf = append(f.seqBuf, b)
	f.state = next
}

// passFrom emits the held head and b, and passes the rest of the sequence in
// state pass. The terminal is then inside a sequence the filter emitted
// unfinished.
func (f *TerminalQueryFilter) passFrom(b byte, pass queryFilterState) {
	f.seqBuf = append(f.seqBuf, b)
	f.flushAndReset()
	f.state = pass
}

// passByte takes a byte of a sequence the filter emitted unfinished: an ESC
// sequence or a CSI it gave up on, or a CSI a terminal ignores. Each byte goes
// out as it comes, and the final byte ends the sequence.
func (f *TerminalQueryFilter) passByte(b byte) {
	if b == 0x1b {
		f.endPassAtESC()
		return
	}
	f.outBuf = append(f.outBuf, b)
	final := b >= 0x40 && b <= 0x7e
	if f.state == qfStateEscOverBound {
		final = b >= 0x30 && b <= 0x7e
	}
	if final {
		f.state = qfStateNormal
	}
}

// endPassAtESC ends a sequence the filter emitted unfinished at an ESC in the
// input. The ESC starts a new sequence, held like any other, so the terminal
// hasn't seen the end of the emitted one, and the filter owes it a close
// until the held sequence settles it (settleClose). Without the close, a
// query dropped from behind an emitted head let whatever came next land
// inside that head: "ESC [1$2 ESC [6n X" became "ESC [1$2 X", which a
// terminal reads as one ignored CSI ending at the X.
func (f *TerminalQueryFilter) endPassAtESC() {
	f.closeOwed = true
	f.seqBuf = append(f.seqBuf[:0], 0x1b)
	f.state = qfStateEsc
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

// drop discards the held sequence: a query, or a head the input abandoned.
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

// endStringAtESC closes an OSC that a non-ST ESC ended. The string's own bytes
// go to outBuf; the trailing ESC stays held as the start of whatever sequence
// comes next, which the caller then feeds the current byte to. The string's
// own ESC, going out, is any close that was owed.
func (f *TerminalQueryFilter) endStringAtESC() {
	f.outBuf = append(f.outBuf, f.seqBuf[:len(f.seqBuf)-1]...)
	f.seqBuf = append(f.seqBuf[:0], 0x1b)
	f.state = qfStateEsc
	f.closeOwed = false
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
