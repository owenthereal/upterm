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
// terminator, a DCS to its header's final byte, and a kitty graphics command
// (an APC whose first byte is G) to the end of its control data, or to a BEL
// before it that settles it as a query. A DCS or APC that is a query is then
// dropped as it streams, to the string's end (drop mode), and one that isn't
// is passed as it streams, as a PM or SOS is. So a sixel or an image is never
// buffered, nor is a query's payload.
//
// A tmux passthrough wrapper, ESC P tmux; then a sequence with each ESC
// doubled, then ESC \, is held while an inner instance of this machine, fed
// the wrapped stream decoded, decides the first sequence in it. If that is no
// query, the wrapper passes byte for byte. If it is, the wrapper's head and
// the query are dropped, and the rest of the wrapper goes out as ordinary
// output, filtered from ground: a DEC terminal ends the wrapper's DCS at its
// first ESC and reads the rest live, so that removes exactly the query.
//
// Terminals disagree on where a malformed string ends. A DEC parser ends one
// at a CAN, a SUB or an ESC that isn't ST; kitty keeps any string open there,
// and tmux a DCS, and each takes what follows as more of it. So an OSC, a DCS
// header or an APC the filter is still holding when it ends one of those ways
// is dropped whole, query or not: passed through, "ESC ]4;0; CAN ;1;? BEL" is
// a palette query to kitty. What that costs is a malformed OSC's effect on a
// DEC terminal, such as a title ended by a stray ESC.
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
	// seen the end yet. endPassAtESC and wrapperByte set it; settleClose
	// settles it with ESC CAN, and flushAndReset when the held ESC goes out.
	closeOwed bool

	// wrapAt is how much of tmuxPrefix a DCS has matched in qfStateWrapMatch,
	// its header's final 't' first. The bytes are held with the header.
	wrapAt int

	// frame is how many bytes of seqBuf are a tmux wrapper's framing: its DCS
	// header as held, then "mux;". What follows them is the raw hold while the
	// wrapper is being decided, and the inner query's head, re-encoded, while
	// that query is being dropped.
	frame int

	// inner decides a tmux wrapper's first inner sequence, fed the decoded
	// stream from the wrapper's first inner ESC. It is allocated with the
	// first wrapper and reset for each one after, so a wrapper allocates
	// nothing once the filter has seen one. Its outBuf collects the control
	// bytes it forwards from inside a head, which the terminal executes there:
	// they go out if the head is dropped, and are already in place in the raw
	// bytes if it passes.
	inner *TerminalQueryFilter

	// nested marks an inner machine. A wrapper inside a wrapper isn't
	// classified (a stated limit), so where the filter would start one, an
	// inner machine passes it, and the outer wrapper passes with it.
	nested bool
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
	qfStateDCSEntry                      // holding ESC P (DCS-entry)
	qfStateDCSParam                      // holding ESC P and a prefix or parameter bytes
	qfStateDCSInter                      // holding a DCS header and its intermediates (0x20–0x2F)
	qfStateAPCEntry                      // holding ESC _, to see whether its first byte makes it a graphics command (G)
	qfStateAPC                           // holding ESC _ G and the control data after it, to its ';' or its end
	qfStateAPCEsc                        // holding an APC and an ESC: ST if '\' follows, else the APC ended there
	qfStateDrop                          // dropping a query string to its end, holding the head that decided it
	qfStateDropEsc                       // as qfStateDrop, holding an ESC too: ST if '\' follows, else the string ended there
	qfStateString                        // passing a DCS, a DCS-ignore, an APC, PM or SOS to its end
	qfStateWrapMatch                     // holding a DCS whose header ended in 't', while its data may yet complete tmuxPrefix
	qfStateWrapMatchEsc                  // as qfStateWrapMatch, holding an ESC too: ST if '\' follows, else the DCS ended there
	qfStateWrapLead                      // holding a tmux wrapper's framing and the bytes before its first inner ESC
	qfStateWrapLeadEsc                   // as qfStateWrapLead, holding a raw ESC whose pair is still to come
	qfStateWrapHead                      // holding a tmux wrapper while the inner machine decides its first inner sequence
	qfStateWrapHeadEsc                   // as qfStateWrapHead, holding a raw ESC whose pair is still to come
	qfStateWrapDrop                      // dropping a wrapper's first inner sequence, a query string, to its inner end
	qfStateWrapDropEsc                   // as qfStateWrapDrop, holding a raw ESC whose pair is still to come
	qfStateWrapper                       // passing a tmux wrapper to its unescaped ST
	qfStateWrapperEsc                    // holding an ESC inside a passing tmux wrapper, to see the byte it escapes

	// qfStateCount isn't a state. It counts them, kept last so a test can
	// range over every state (TestTerminalQueryFilter_EveryStateIsInOneList).
	qfStateCount
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

// The most an ESC sequence with intermediates, a CSI head and a DCS header are
// held for, framing included. The bound counts what is held before the final
// byte: a final byte that arrives with the head full is still classified, and
// the next byte that isn't one gives the head up, so it passes unclassified to
// its end. Queries are a handful of bytes; one padded past its bound passes,
// which the filter accepts so that what it holds stays bounded.
const (
	maxEscHeld = 8
	maxCSIHeld = 32
	maxDCSHeld = 32
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

// The most a kitty graphics command is held for, counted in raw bytes from its
// ESC _: the G, the control data, and the ';' or BEL that decides it, which is
// held with the rest. An ESC held to see whether '\' follows comes on top, as
// for an OSC. The next byte that would be held past the bound gives the
// command up before it is decided, the ';' or a BEL included: what is held
// goes out, and the rest passes unclassified to the string's end. So the head
// that decides a drop is never longer than the bound.
const maxAPCHeld = 256

// tmuxPrefix is what a DCS's first bytes are when it is a tmux passthrough
// wrapper: ESC P tmux; then a sequence with each ESC doubled, then ESC \.
const tmuxPrefix = "tmux;"

// The most a tmux wrapper is held for while its first inner sequence is
// decided, counted in raw bytes from its ESC P: the framing, the bytes before
// the first inner ESC, the inner sequence's head with its ESCs still doubled,
// and a raw ESC whose pair is still to come. The next raw byte that would add
// to the hold gives the wrapper up: what is held goes out, and the wrapper
// passes byte for byte to its end, its inner sequence unclassified. A byte
// that ends what is held, such as a cancel, is taken as it would be within
// the bound (endsWrapperHold), as a byte that ends any sequence is.
const maxWrapHeld = 256

// maxPendingBytes is the most the filter will ever be holding, and so the most
// Pending can return. Every state that accumulates gives up at a bound of its
// own, counted in raw bytes with the sequence's framing included: 8 of an ESC
// sequence with intermediates, 32 of a CSI head or a DCS header, 8 of an OSC
// number, 256 of an OSC, introducer through payload, 256 of a kitty graphics
// command, introducer through the ';' or BEL that decides it, and 256 of a
// tmux wrapper being decided, a raw ESC held among them. The largest is 256.
//
// On top of a bound, Pending can return more:
//   - an OSC or a graphics command held to its bound can still be waiting to
//     see whether the ESC that follows begins its ST, and that ESC is not
//     counted in the 256, so 257. A dropped string holds the head that decided
//     it and that ESC: a DCS header with its final byte, far below that, or a
//     graphics command's control data with its ';' or BEL, within its 256.
//   - a wrapper's inner drop holds the wrapper's framing and the inner query's
//     head, re-encoded, which come to no more than the raw bytes held when it
//     was decided, so 256 at most. On top of them come the inner parser's
//     pending ESC, the one that may begin the dropped string's ST, re-encoded
//     as the ESC ESC it arrived as (2), and a raw ESC whose pair is still to
//     come (1): 256 + 2 + 1 = 259 (Owen, 2026-10-11).
//
// It matters because Pending is replayed to every joining writer after the
// ring: what the filter holds is output no reader has seen yet, and it is held
// outside the ring's byte budget.
const maxPendingBytes = 259

// Pending returns the bytes that put a fresh filter in this one's state. Fed
// everything this filter has written, then Pending(), a fresh filter ends in the
// state this one is in: where it is in a sequence, the match so far against
// "tmux;" at the start of a DCS, where it is in a tmux wrapper and in the
// sequence the wrapper carries, whether it is dropping a string or passing a
// sequence it gave up on, and whether it owes a close. A joiner's filter takes
// its state from the result (MultiWriter.Append), and a newly promoted primary
// is handed it raw (hostSink.promote), unless the filter is Dropping, where
// SettleDrop takes its place. What it returns depends on the state:
//
//   - While deciding, the held bytes: a head, an OSC to its terminator, a DCS
//     header to its final byte, an APC's ESC _ before its first byte, or a
//     graphics command with its control data so far, BELs that asked nothing
//     among them.
//   - In drop mode, the head that decided the drop, and the ESC held to see
//     whether a '\' follows, if there is one. The head is a DCS header, or a
//     graphics command's control data with the ';' or BEL that decided it. A
//     joiner's filter fed the head drops the rest of the string as this one
//     does, and one that joins between a terminator's ESC and its '\' still
//     ends the string there.
//   - While a tmux wrapper is being decided, its raw bytes as held: the
//     framing, the bytes before its first inner ESC, and the inner sequence's
//     head with its ESCs still doubled, a raw ESC whose pair is still to come
//     included. A joiner's filter re-decodes them to the same state, the
//     control bytes the inner head forwarded included, which have not gone
//     out yet. While a DCS whose header ended in 't' is matching "tmux;", the
//     header and the match so far.
//   - While a wrapper's first inner sequence is dropped, the wrapper's framing,
//     the inner head that decided the drop with its ESC doubled, and then, in
//     that order, the inner parser's pending ESC as ESC ESC, if it holds one,
//     and a raw ESC whose pair is still to come, if there is one. The pending
//     ESC goes in though its raw pair is complete and leaves no raw ESC
//     unpaired, so a joiner still ends the inner string where this filter
//     does: without it, the joiner would drop what follows as payload. The
//     control bytes the inner head forwarded have gone out, and aren't in it.
//   - In a pass state, where the head went out with the stream, an ESC held to
//     see what the next byte makes of it, or nothing. A DCS, a DCS-ignore, an
//     APC past its ';' or one that isn't a graphics command, a PM or SOS, a
//     tmux wrapper passing, a CSI the terminal ignores and a sequence past its
//     bound are all in this state.
//   - With a close owed, the held sequence that will settle it. It begins with
//     the ESC that ended the emitted sequence, so the joiner's filter owes the
//     same close.
//
// The result restores a parse state; it does not recover history. It never
// contains a byte the filter discarded, a dropped string's payload among them,
// since those are gone and are not coming back, nor a C0 it forwarded, which
// went out ahead of the hold and would be sent twice. A dropped string's
// head is in it only as state, which a joiner's filter needs to drop the
// rest. It is a copy, and never longer than maxPendingBytes.
func (f *TerminalQueryFilter) Pending() []byte {
	return slices.Clone(f.seqBuf)
}

// Dropping reports whether the filter is discarding a query string, at top
// level or inside a tmux wrapper, that hasn't ended yet. Pending then holds
// the head that decided the drop, which must not reach a terminal that would
// answer it, so a sink promoted to primary now settles the drop with
// SettleDrop rather than handing Pending over.
func (f *TerminalQueryFilter) Dropping() bool {
	switch f.state {
	case qfStateDrop, qfStateDropEsc, qfStateWrapDrop, qfStateWrapDropEsc:
		return true
	}
	return false
}

// SettleDrop is the handoff for a sink promoted to primary while Dropping.
// The bytes already dropped can't be recovered, so the rest of that string
// is no use to the new primary; everything after it is. SettleDrop consumes
// from p only the rest of the string being dropped, and parses nothing
// after the string's end: the byte after a restarting ESC is not looked at
// as part of a new sequence. Nothing goes to the filter's writer.
//
//   - done reports whether the string ended within p. If not, n == len(p)
//     and raw is nil: all of p was part of the drop, and the filter is still
//     Dropping, for the next call.
//   - When it did, the caller writes raw, then p[n:], unfiltered, and never
//     uses the filter again.
//   - The general rule: the stream resumes at a raw resume point. If that
//     point is in p, it is p[n] and raw is nil. If it lies in bytes the
//     filter carried from an earlier write, raw holds the carried raw bytes
//     from that point on, and n is 0. Those are one or two raw ESCs, in a
//     new slice the caller owns.
//
// Where it ended fixes the resume point:
//   - at ST: just after the '\', so p[:n] ends with it;
//   - at CAN or SUB: at that byte;
//   - at an ESC that isn't ST: at that ESC. It's the carried byte when the
//     filter held it from the last write, so raw is "\x1b" and p[0] is the
//     byte after it.
//   - inside a wrapper: after an inner ST or the outer ST, at a CAN or SUB,
//     and at a lone raw ESC x, which ends the wrapper. An inner ESC that
//     isn't ST resumes at the second raw ESC of its pair, which is carried
//     when the pair completed in the last write. For example, promoted after
//     "\x1bPtmux;\x1b\x1bP+q544e\x1b\x1b" and given "[6nhello\x1b\\",
//     SettleDrop returns raw "\x1b", n 0, done true. An inner ESC that ends
//     the string by following a pending one resumes at the pending one's
//     second raw ESC, so raw can be "\x1b\x1b".
//
// A filter that isn't Dropping, a fresh one or one SettleDrop has already
// returned done for among them, has no string to settle: SettleDrop returns
// 0, nil and true, and the stream resumes at p[0].
func (f *TerminalQueryFilter) SettleDrop(p []byte) (n int, raw []byte, done bool) {
	if !f.Dropping() {
		return 0, nil, true
	}
	for i, b := range p {
		back, ended := f.dropEnd(b)
		if !ended {
			continue
		}
		f.seqBuf = f.seqBuf[:0]
		f.state = qfStateNormal
		if at := i - back; at >= 0 {
			return at, nil, true
		}
		// The resume point is back-i raw bytes before p, ESCs the drop held.
		return 0, slices.Repeat([]byte{0x1b}, back-i), true
	}
	return len(p), nil, false
}

// processByte processes a single byte, appending non-filtered output to f.outBuf.
func (f *TerminalQueryFilter) processByte(b byte) {
	// CAN and SUB end every sequence but a tmux wrapper past its first inner
	// ESC, which takes them as bytes of the stream it carries. After a raw ESC
	// in a wrapper one isn't: the ESC escapes neither an ESC nor a '\', so it
	// has ended the wrapper, and the cancel then cancels the ESC as it would
	// any held one. Before the first inner ESC one ends the wrapper (cancel).
	// A string being dropped takes them in dropEnd, which decides where it
	// ends.
	if (b == 0x18 || b == 0x1a) && f.state != qfStateNormal && f.state != qfStateWrapper &&
		f.state != qfStateWrapHead && !f.Dropping() {
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

	case qfStateDCSEntry, qfStateDCSParam, qfStateDCSInter:
		f.dcsByte(b)

	case qfStateAPCEntry, qfStateAPC:
		f.apcByte(b)

	case qfStateAPCEsc:
		f.apcEscByte(b)

	case qfStateDrop, qfStateDropEsc, qfStateWrapDrop, qfStateWrapDropEsc:
		f.dropByte(b)

	case qfStateWrapMatch, qfStateWrapMatchEsc:
		f.wrapMatchByte(b)

	case qfStateWrapLead, qfStateWrapLeadEsc, qfStateWrapHead, qfStateWrapHeadEsc:
		f.wrapHeldByte(b)

	case qfStateWrapper, qfStateWrapperEsc:
		f.wrapperByte(b)

	case qfStateEscOverBound, qfStateCSIIgnore, qfStateCSIOverBound,
		qfStateOSCOverBound, qfStateString:
		f.passByte(b)
	}
}

// cancel takes a CAN or SUB, which ends a sequence from any state on the DEC
// parser terminals implement; the terminal goes back to ground and executes
// it. Inside a tmux wrapper, from its first inner ESC on, they are bytes of
// the stream it carries instead (wrapHeldByte, wrapperByte), and get here only
// straight after a raw ESC, which has ended the wrapper. A string being
// dropped, at the top or in a wrapper, takes them in dropEnd.
func (f *TerminalQueryFilter) cancel(b byte) {
	switch {
	case f.holdsStringEsc():
		// The OSC, APC or DCS ended at its ESC already, a byte before the
		// cancel, so it is dropped as any held string ended there is, and the
		// cancel then cancels the ESC on its own.
		f.restartAtESC()
	case f.state == qfStateWrapLeadEsc, f.state == qfStateWrapHeadEsc:
		// So did the wrapper, which a raw ESC that escapes neither an ESC nor
		// a '\' ends, and it is dropped the same way.
		f.restartWrapperAtESC()
	case f.holdsString(), f.holdsHeader(), f.state == qfStateWrapLead:
		// A held OSC, DCS header or APC is dropped whole, query or not, and
		// none of it goes out with the cancel: kitty keeps a string open past
		// a CAN or SUB, so "ESC ]4;0; CAN ;1;? BEL" reaches it as a palette
		// query, and "ESC _ G i=1 CAN ,a=q;" as a graphics query. That holds
		// with a close owed too: kitty may have ended the emitted string
		// already, at a BEL in a DCS, and would read the held head as live.
		// Only the head's own ESC goes out, ahead of the cancel, as the close.
		// So is a DCS held while it may be a tmux wrapper, and a wrapper
		// before its first inner ESC, where a DEC terminal ends the DCS and
		// prints what follows (Owen, 2026-10-11). Taken as the wrapper's
		// payload instead, what followed was dropped with the wrapper when a
		// query came after it: "ESC P tmux; CAN hello ESC ESC [6n ESC \" lost
		// the hello.
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
	if (b < 0x20 || b >= 0x7f) && f.headControl(b) {
		return
	}
	switch {
	case b >= 0x80:
		// 0x80–0x9F, the 8-bit C1 controls, which the filter doesn't act on
		// (in UTF-8 they are continuation bytes far more often), give the
		// head up as they do a CSI's: what is held goes out, and the rest
		// passes to its final byte. 0xA0–0xFF never get here; headControl
		// drops them.
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
		// A DCS is held with its header, to the final byte that decides it.
		f.seqBuf = append(f.seqBuf, b)
		f.state = qfStateDCSEntry
	case f.state == qfStateEsc && b == '_':
		// An APC is held for its first byte, which says whether it is a
		// graphics command, and a graphics command for its control data.
		f.seqBuf = append(f.seqBuf, b)
		f.state = qfStateAPCEntry
	case f.state == qfStateEsc && (b == '^' || b == 'X'):
		// A PM or SOS goes out at once and passes as it streams.
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
	if (b < 0x20 || b >= 0x7f) && f.headControl(b) {
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
		// for. A byte of 0x80–0x9F, a C1 control the filter doesn't act on,
		// gives the head up the same way.
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
// here; processByte cancels on them first. It takes none of 0x20–0x7E, so its
// callers test for that range before calling it, and a head's printable
// bytes, nearly all of them, skip the call.
func (f *TerminalQueryFilter) headControl(b byte) bool {
	switch {
	case b == 0x1b:
		// An ESC abandons the head, and the terminal executes nothing of it,
		// so it is dropped rather than flushed. Flushed, it would splice onto
		// whatever goes out next: with the query after it dropped,
		// "ESC [6 ESC [6n hello" would reach the terminal as the CSI
		// "ESC [6h" and the text "ello". This ESC starts a new sequence.
		f.restartAtESC()
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
//
// A DEC terminal dispatches an OSC that ends there, but kitty keeps it open
// and reads on into what follows, so it is dropped whole, query or not.
// Passed through as it used to be, "ESC ]11; ESC [6n ? BEL" lost only the
// query and went out as "ESC ]11;? BEL", a colour query glued back together.
func (f *TerminalQueryFilter) oscEscByte(b byte) {
	if b == '\\' {
		query := oscQuery(f.seqBuf[:len(f.seqBuf)-1])
		f.seqBuf = append(f.seqBuf, b)
		f.decide(query)
		return
	}
	f.restartAtESC()
	f.escByte(b)
}

// dcsByte takes a byte of a DCS header: ESC P, then the CSI's grammar, an
// optional prefix (0x3C–0x3F), parameter bytes (0x30–0x39 and ';'),
// intermediates (0x20–0x2F), and a final byte (0x40–0x7E), where dcsQuery
// decides it. Out of that order, or with a ':' anywhere, a terminal puts the
// DCS in DCS-ignore.
//
// The bytes the terminal ignores in a header are dropped: C0, DEL and
// 0xA0–0xFF. They are never held, so they don't count toward the bound. Unlike
// inside a CSI, a terminal executes no C0 here, so the filter doesn't forward
// one either: forwarded, the CR in "ABC ESC P $ CR q m ESC \ X" would reach
// the terminal, which never executed one, when the query around it is dropped.
func (f *TerminalQueryFilter) dcsByte(b byte) {
	switch {
	case b >= 0x40 && b <= 0x7e:
		f.seqBuf = append(f.seqBuf, b)
		f.decideDCS()
	case b == 0x1b:
		// An ESC abandons the header, as it abandons a CSI head. The terminal
		// never hooked the DCS, and the held string ended abnormally, so it is
		// dropped whole, query or not, and a close owed from before it is
		// settled as for any drop. This ESC starts a new sequence.
		f.restartAtESC()
	case b < 0x20 || b == 0x7f || b >= 0xa0:
		// Ignored, so dropped. CAN and SUB never get here; processByte
		// cancels on them first.
	case b >= 0x80 || f.dcsIgnores(b):
		// A DCS-ignore dispatches nothing, so it is no query: what is held
		// goes out, and the rest passes as a string. Unlike a CSI-ignore it
		// doesn't end at a final-looking byte, only where any string ends, so
		// a query after it still owes it a close. A byte of 0x80–0x9F, a C1
		// control the filter doesn't act on, gives the header up the same way.
		f.passFrom(b, qfStateString)
	case b <= 0x2f:
		f.hold(b, qfStateDCSInter, maxDCSHeld, qfStateString)
	default: // a prefix or parameter byte, 0x30–0x3F
		f.hold(b, qfStateDCSParam, maxDCSHeld, qfStateString)
	}
}

// dcsIgnores reports whether b, a byte from 0x20 to 0x3F, puts a terminal in
// DCS-ignore from the current header state: a ':' anywhere, since a DCS has no
// sub-parameters, a prefix byte after a parameter, or a parameter or prefix
// byte after an intermediate.
func (f *TerminalQueryFilter) dcsIgnores(b byte) bool {
	switch f.state {
	case qfStateDCSEntry:
		return b == ':'
	case qfStateDCSParam:
		return b == ':' || b >= 0x3c && b <= 0x3f
	case qfStateDCSInter:
		return b >= 0x30 && b <= 0x3f
	}
	return false
}

// decideDCS decides a DCS at its header's final byte, already held. A query
// is dropped to the string's end, and anything else goes out with the
// payload passing behind it. A header that ends in 't' may be a tmux
// wrapper's, ESC P tmux;, whatever parameters or intermediates come before
// the 't', as tmux reads one, so it stays held while its data may yet
// complete tmuxPrefix (wrapMatchByte).
func (f *TerminalQueryFilter) decideDCS() {
	if dcsQuery(f.seqBuf) {
		f.dropToEnd()
		return
	}
	if f.seqBuf[len(f.seqBuf)-1] == 't' {
		f.state, f.wrapAt = qfStateWrapMatch, 1
		return
	}
	f.flushAndReset()
	f.state = qfStateString
}

// apcByte takes a byte of an APC the filter is holding. Its first byte says
// whether it is a kitty graphics command: a G is held, with the control data
// after it, the key=value pairs that run to the first ';'. Anything else is no
// graphics command, so the APC goes out with that byte and passes as it
// streams. That holds for a control byte too: the terminal hands an APC's
// control bytes to its handler as payload, so "ESC _ LF G a=q" is no graphics
// command.
//
// Every byte of the control data is held as payload, the control bytes and DEL
// included, and counted toward the bound. The ';' decides the command, and
// kitty, which ends any string at a BEL and takes control data without a ';',
// decides it at a BEL too. So the control data before each BEL is decided as
// kitty would read it: a query found there drops the command, and the bytes
// after the BEL, which a DEC terminal reads as more control data, can't undo
// that. A BEL that asks nothing is held as payload, as a DEC terminal takes it.
func (f *TerminalQueryFilter) apcByte(b byte) {
	switch {
	case b == 0x1b:
		// The APC ends here, cleanly if '\' follows. An APC that ends before
		// its first byte is empty, and no graphics command either.
		f.seqBuf = append(f.seqBuf, b)
		f.state = qfStateAPCEsc
	case f.state == qfStateAPCEntry && b == 'G':
		f.seqBuf = append(f.seqBuf, b)
		f.state = qfStateAPC
	case f.state == qfStateAPCEntry:
		f.passFrom(b, qfStateString)
	case len(f.seqBuf) >= maxAPCHeld:
		// The bound is full, so the command is given up on, unclassified,
		// whatever b is: a ';' or BEL held past it would leave a drop's head
		// longer than the bound.
		f.passFrom(b, qfStateString)
	case b == ';' || b == 0x07:
		query := apcQuery(f.seqBuf[len("\x1b_G"):])
		f.seqBuf = append(f.seqBuf, b)
		switch {
		case query:
			f.dropToEnd()
		case b == ';':
			// The payload follows, an image's data, so the command goes out
			// and the payload passes behind it.
			f.flushAndReset()
			f.state = qfStateString
		}
	default:
		f.seqBuf = append(f.seqBuf, b)
	}
}

// apcEscByte takes the byte after an ESC that ends an APC the filter is
// holding. A '\' makes the ESC ST, which ends the APC cleanly: a graphics
// command is decided on all of its control data, and an empty APC is none.
// Anything else means the APC ended at the ESC, a held string ended
// abnormally, so it is dropped whole, query or not, as an OSC is: kitty
// keeps it open past the ESC and reads on into what follows. The byte is the
// first after that ESC.
func (f *TerminalQueryFilter) apcEscByte(b byte) {
	if b == '\\' {
		query := f.seqBuf[2] == 'G' && apcQuery(f.seqBuf[len("\x1b_G"):len(f.seqBuf)-1])
		f.seqBuf = append(f.seqBuf, b)
		f.decide(query)
		return
	}
	f.restartAtESC()
	f.escByte(b)
}

// dropByte takes a raw byte of a query string being dropped, at the top or as
// a tmux wrapper's first inner sequence. Its payload is discarded as it
// streams, until dropEnd finds the string's end. The stream then resumes as
// ordinary output, from ground, at the point dropEnd names: the bytes from
// there on, the raw ESCs the drop held among them, are parsed afresh. Nothing
// of the string went out, so no close is owed either way.
//
// Payload, nearly all of a string, is discarded before dropEnd is called: in
// a drop with no ESC pending, raw or inner, any byte but an ESC, a CAN or a
// SUB is payload, which is what dropEnd would say of it too.
func (f *TerminalQueryFilter) dropByte(b byte) {
	if b != 0x1b && b != 0x18 && b != 0x1a &&
		(f.state == qfStateDrop || f.state == qfStateWrapDrop && f.inner.state == qfStateDrop) {
		return
	}
	back, ended := f.dropEnd(b)
	if !ended {
		return
	}
	f.seqBuf = f.seqBuf[:0]
	f.state = qfStateNormal
	for range back {
		f.processByte(0x1b)
	}
	if back >= 0 {
		f.processByte(b)
	}
}

// dropEnd takes b, the next raw byte of a query string being dropped, and
// decides only whether the string ends at it. It parses nothing after the
// end, so SettleDrop can hand the stream over from there untouched. While the
// string goes on, b is part of it and the drop moves on, an ESC held to see
// the byte after it. When it ends, back says where the stream resumes,
// counted in raw bytes back from b: -1 is after b, 0 at b, and 1 or 2 at a
// raw ESC before b, which the drop held.
//
// At the top, the resume point is:
//   - for ST, ESC \: after the '\', which goes with the string;
//   - for a CAN or SUB: at that byte, which goes out;
//   - for an ESC followed by anything else: at the ESC, which starts a new
//     sequence, as it does after any string.
//
// In a wrapper the inner end is read on decoded bytes, and the stream resumes
// with no more decoding, at:
//   - an inner ST, raw ESC ESC \: after the '\';
//   - a CAN or SUB: at that byte;
//   - an inner ESC that isn't ST, raw ESC ESC x: at the pair's second raw ESC,
//     which a DEC terminal reads as starting what follows. If x is itself a
//     raw ESC, paired by the next byte into a second inner ESC, that is two
//     raw ESCs back from the byte that pairs it, and the stream from there is
//     three ESCs;
//   - the outer ST: after it, as it ends both;
//   - a lone raw ESC x, which ends the wrapper: at that ESC.
//
// The inner machine holds the ESC that may begin the string's ST, as drop mode
// does at the top. Pending carries it as the ESC ESC it arrived as, and a raw
// ESC whose pair is still to come after it.
func (f *TerminalQueryFilter) dropEnd(b byte) (back int, ended bool) {
	switch f.state {
	case qfStateDrop:
		switch b {
		case 0x1b:
			f.seqBuf = append(f.seqBuf, b)
			f.state = qfStateDropEsc
		case 0x18, 0x1a:
			return 0, true
		}
		return 0, false
	case qfStateDropEsc:
		if b == '\\' {
			return -1, true
		}
		return 1, true
	case qfStateWrapDrop:
		switch {
		case b == 0x1b:
			f.seqBuf = append(f.seqBuf, b)
			f.state = qfStateWrapDropEsc
		case f.inner.state == qfStateDropEsc && b == '\\':
			return -1, true
		case f.inner.state == qfStateDropEsc:
			return 1, true
		case b == 0x18 || b == 0x1a:
			return 0, true
		}
		return 0, false
	}
	// qfStateWrapDropEsc: b is the byte after a raw ESC.
	switch {
	case b == '\\':
		return -1, true
	case b != 0x1b:
		return 1, true
	case f.inner.state == qfStateDropEsc:
		return 2, true
	}
	f.inner.processByte(b)
	f.seqBuf = append(f.seqBuf, b)
	f.state = qfStateWrapDrop
	return 0, false
}

// wrapMatchByte takes a byte of a DCS whose header ended in 't', held while
// its data may yet complete tmuxPrefix, as tmux reads a wrapper: any byte
// off, a control byte or a DEL included, and it is an ordinary DCS, which
// goes out and passes to its end. Held, it is a string like any other: ST
// ends it cleanly, and it goes out, and any other ESC ends it abnormally, so
// it is dropped whole and the ESC starts a new sequence. A CAN or SUB drops it
// in cancel.
//
// With all of tmuxPrefix, the wrapper begins, still held. On an inner
// machine, which reads a wrapper's stream, it is a wrapper inside a wrapper,
// which isn't classified: it goes out, and the outer wrapper passes with it.
func (f *TerminalQueryFilter) wrapMatchByte(b byte) {
	if f.state == qfStateWrapMatchEsc {
		if b == '\\' {
			f.seqBuf = append(f.seqBuf, b)
			f.flushAndReset()
			return
		}
		f.restartAtESC()
		f.escByte(b)
		return
	}
	switch {
	case b == 0x1b:
		f.seqBuf = append(f.seqBuf, b)
		f.state = qfStateWrapMatchEsc
	case b != tmuxPrefix[f.wrapAt] || f.nested && f.wrapAt+1 == len(tmuxPrefix):
		f.passFrom(b, qfStateString)
	case f.wrapAt+1 < len(tmuxPrefix):
		f.seqBuf = append(f.seqBuf, b)
		f.wrapAt++
	default:
		f.seqBuf = append(f.seqBuf, b)
		f.frame = len(f.seqBuf)
		if f.inner == nil {
			f.inner = &TerminalQueryFilter{
				w:      io.Discard,
				seqBuf: make([]byte, 0, maxWrapHeld),
				outBuf: make([]byte, 0, maxWrapHeld),
				nested: true,
			}
		}
		in := f.inner
		in.state, in.seqBuf, in.outBuf, in.closeOwed = qfStateNormal, in.seqBuf[:0], in.outBuf[:0], false
		f.state = qfStateWrapLead
	}
}

// wrapHeldByte takes a raw byte of a tmux wrapper the filter is holding while
// it decides the wrapper's first inner sequence. Every raw byte is held, so
// the wrapper can pass as it came. Raw bytes decode in pairs after an ESC, as
// tmux's DCS rules have it: ESC ESC is one inner ESC, ESC \ is the outer ST,
// which ends the wrapper, and any other ESC x ends the wrapper too, as a DEC
// terminal ends the DCS there (spec rule 11). So an ESC is held until the
// byte after it says which.
//
// The bytes before the first inner ESC are the wrapper's own: a DEC terminal
// takes them as payload of a DCS that does nothing, so they are held with it
// and go wherever it goes. From the first inner ESC on, the decoded stream
// runs through the inner machine (innerByte).
func (f *TerminalQueryFilter) wrapHeldByte(b byte) {
	if len(f.seqBuf) >= maxWrapHeld && !f.endsWrapperHold(b) {
		f.giveUpWrapper()
		f.processByte(b)
		return
	}
	f.seqBuf = append(f.seqBuf, b)
	switch f.state {
	case qfStateWrapLead, qfStateWrapHead:
		switch {
		case b == 0x1b && f.state == qfStateWrapLead:
			f.state = qfStateWrapLeadEsc
		case b == 0x1b:
			f.state = qfStateWrapHeadEsc
		case f.state == qfStateWrapHead:
			f.innerByte(b)
		}
	default: // the byte after a raw ESC
		switch b {
		case 0x1b:
			f.innerByte(b)
		case '\\':
			f.endWrapperAtST()
		default:
			// A lone ESC x ends the wrapper while it is held, so it is dropped
			// as a held string that ends abnormally is, and the ESC starts a
			// new sequence with x its next byte. Kept open, as tmux keeps it,
			// a malformed or interrupted wrapper let every query through until
			// the next unescaped ST.
			f.restartWrapperAtESC()
			f.escByte(b)
		}
	}
}

// endsWrapperHold reports whether b, arriving when a wrapper being decided is
// held to its bound, ends what is held rather than adding to it, so that it
// is taken as it would be within the bound, as a byte that ends any sequence
// is: after a raw ESC, the outer ST or a lone ESC x, which end the wrapper, or
// an inner ESC that abandons a head; after an inner ESC that may begin a
// string's ST, any byte but a raw ESC, which ends the string; or a cancel.
// Given up on there instead, a wrapped title an inner ESC had ended went out
// with the wrapper at the cancel after it, where a held string that ends
// abnormally is dropped (found by the fuzz test).
func (f *TerminalQueryFilter) endsWrapperHold(b byte) bool {
	switch f.state {
	case qfStateWrapLeadEsc:
		return b != 0x1b
	case qfStateWrapHeadEsc:
		return b != 0x1b || !f.inner.holdsString()
	case qfStateWrapHead:
		if f.inner.holdsStringEsc() {
			return b != 0x1b
		}
		return b == 0x18 || b == 0x1a
	}
	return false
}

// holding reports whether the filter holds a sequence it hasn't decided yet:
// a head, a DCS header, a string, or a string and the ESC that ended it.
//
// Every state is in exactly one of the lists the filter acts on: those four,
// passing, Dropping, a tmux wrapper's own, or ground
// (TestTerminalQueryFilter_EveryStateIsInOneList). innerByte reads an inner
// machine through them, so a state in one is taken as the rest of its list
// is, and a state added to none fails that test. innerByte once passed the
// wrapper on a state its own lists missed, with whatever query it held.
func (f *TerminalQueryFilter) holding() bool {
	return f.holdsHead() || f.holdsHeader() || f.holdsString() || f.holdsStringEsc()
}

// holdsHead reports whether the filter holds an ESC sequence or a CSI head,
// which an ESC abandons and a cancel sends out with it.
func (f *TerminalQueryFilter) holdsHead() bool {
	switch f.state {
	case qfStateEsc, qfStateEscInter, qfStateCSI, qfStateCSIParam, qfStateCSIInter:
		return true
	}
	return false
}

// holdsHeader reports whether the filter holds a DCS header, which an ESC
// abandons and a cancel drops whole.
func (f *TerminalQueryFilter) holdsHeader() bool {
	switch f.state {
	case qfStateDCSEntry, qfStateDCSParam, qfStateDCSInter:
		return true
	}
	return false
}

// holdsString reports whether the filter holds a string it hasn't decided,
// which takes an ESC in as the possible start of its ST: an OSC, a graphics
// command, or a DCS whose header ended in 't'.
func (f *TerminalQueryFilter) holdsString() bool {
	switch f.state {
	case qfStateOSCNum, qfStateOSC, qfStateAPCEntry, qfStateAPC, qfStateWrapMatch:
		return true
	}
	return false
}

// holdsStringEsc reports whether the filter holds such a string and the ESC
// that ended it: cleanly if '\' follows, which makes the ESC ST, and
// abnormally if anything else does.
func (f *TerminalQueryFilter) holdsStringEsc() bool {
	switch f.state {
	case qfStateOSCEsc, qfStateAPCEsc, qfStateWrapMatchEsc:
		return true
	}
	return false
}

// passing reports whether the filter is passing a sequence it emitted
// unfinished, to its end (passByte).
func (f *TerminalQueryFilter) passing() bool {
	switch f.state {
	case qfStateEscOverBound, qfStateCSIIgnore, qfStateCSIOverBound, qfStateOSCOverBound, qfStateString:
		return true
	}
	return false
}

// innerByte feeds the inner machine b, the next byte of a wrapper's decoded
// stream, whose raw bytes are already held, and acts on what it decides of
// the first inner sequence. Each family keeps its own classification point and
// its own end, as at the top: an ESC sequence and a CSI at the final byte, an
// OSC at its end, a DCS at its header's final byte, and a graphics command at
// its ';' or a BEL that asks.
//
//   - Still undecided, the wrapper stays held.
//   - Not a query, the wrapper passes byte for byte, and the inner machine is
//     no longer consulted, so a later inner sequence passes unclassified.
//   - A query decided at its end is dropped with the wrapper's head, and the
//     stream resumes as ordinary output after its last byte.
//   - A query string goes on being dropped to its inner end (dropByte).
//   - A held inner string that ends abnormally, or a head an inner ESC
//     abandons, is dropped as at the top, and the stream resumes at the
//     second raw ESC of the inner ESC that ended it, as ordinary output: a
//     DEC terminal reads ESC ESC as two ESCs, the first ending the string and
//     the second starting what follows.
//
// What a DEC terminal ended the DCS at is the wrapper's first raw ESC, so
// from the resume point on, the rest of the wrapper is what it reads live,
// and filtering it from ground removes exactly the inner query.
func (f *TerminalQueryFilter) innerByte(b byte) {
	in := f.inner
	f.state = qfStateWrapHead
	switch {
	case in.holdsStringEsc():
		if b != '\\' {
			// The inner string ended at the inner ESC before b, abnormally.
			// If b is an inner ESC too, the stream from that ESC's second raw
			// byte is three ESCs, which leave one held.
			f.restartWrapperAtESC()
			if b != 0x1b {
				f.processByte(b)
			}
			return
		}
	case in.holdsHead():
		switch b {
		case 0x1b:
			f.restartWrapperAtESC()
			return
		case 0x18, 0x1a:
			// A cancel makes an undecided head no query, as at the top,
			// where the head goes out with it: the wrapper passes.
			f.passWrapper()
			return
		}
	case in.holdsHeader():
		switch b {
		case 0x1b:
			f.restartWrapperAtESC()
			return
		case 0x18, 0x1a:
			f.cancelWrapper(b)
			return
		}
	default:
		// Before the first inner ESC, or a string the inner machine holds: an
		// OSC, a graphics command, or a DCS that may be a wrapper of its own.
		// An inner ESC is held there to see the byte after it, and a cancel
		// drops the string as at the top.
		if b == 0x18 || b == 0x1a {
			f.cancelWrapper(b)
			return
		}
	}
	n := len(in.outBuf)
	in.processByte(b)
	switch {
	case in.holding():
	case in.state == qfStateDrop:
		f.dropInner()
	case in.state == qfStateNormal && len(in.outBuf) == n:
		f.endWrapperHold()
	case in.state == qfStateNormal || in.passing():
		f.passWrapper()
	default:
		// An inner machine reaches no other state here: it enters DropEsc
		// only from Drop, which dropInner has taken, and no wrapper state,
		// since it passes a wrapper inside the wrapper at its "tmux;". A
		// state added to none of the lists (holding) would land here, so it
		// drops the wrapper rather than pass whatever query it holds.
		f.endWrapperHold()
	}
}

// endWrapperAtST takes the outer ST of a wrapper still being decided, already
// held. A wrapper with no inner sequence passes. A DEC terminal, which ended
// the wrapper's DCS at its first raw ESC, reads the outer ST as the ST of the
// inner string still open, so an inner OSC, graphics command or DCS matching
// tmuxPrefix is decided there as if its own ST had come: one that is no query
// passes with the wrapper. Anything else ends at the outer ST's ESC without
// being decided -- a head it abandons, or a string an inner ESC had already
// ended -- and is dropped with the wrapper, as a query is. The outer ST ends
// both, so nothing of the wrapper goes out.
func (f *TerminalQueryFilter) endWrapperAtST() {
	if f.state == qfStateWrapLeadEsc {
		f.flushAndReset()
		return
	}
	in := f.inner
	if in.holdsString() {
		n := len(in.outBuf)
		in.processByte(0x1b)
		in.processByte('\\')
		if len(in.outBuf) > n {
			f.flushAndReset()
			return
		}
	}
	f.endWrapperHold()
}

// passWrapper emits the wrapper held, through its latest raw byte, once its
// first inner sequence is no query, and passes the rest byte for byte
// (wrapperByte).
func (f *TerminalQueryFilter) passWrapper() {
	f.flushAndReset()
	f.state = qfStateWrapper
}

// giveUpWrapper gives up a wrapper held to its bound, before its first inner
// sequence is decided: what is held goes out, and the wrapper passes byte for
// byte, so a query in it passes, as one past any bound does. A raw ESC whose
// pair is still to come stays held, as it would in a passing wrapper.
func (f *TerminalQueryFilter) giveUpWrapper() {
	esc := f.state == qfStateWrapLeadEsc || f.state == qfStateWrapHeadEsc
	if esc {
		f.seqBuf = f.seqBuf[:len(f.seqBuf)-1]
	}
	f.passWrapper()
	if esc {
		f.seqBuf = append(f.seqBuf, 0x1b)
		f.state = qfStateWrapperEsc
	}
}

// endWrapperHold drops a wrapper held while it was being decided: its first
// inner sequence was a query, or ended where the terminal discards it. A
// close owed from before the wrapper is settled, as for any drop, and then the
// control bytes the inner machine forwarded from inside a head go out, which
// the terminal executed where they stood.
func (f *TerminalQueryFilter) endWrapperHold() {
	f.settleClose()
	f.outBuf = append(f.outBuf, f.inner.outBuf...)
	f.seqBuf = f.seqBuf[:0]
	f.state = qfStateNormal
}

// restartWrapperAtESC drops a wrapper held while it was being decided, at a
// raw ESC that ends it or ends its inner sequence, and holds that ESC as the
// start of a new sequence, read from ground as ordinary output.
func (f *TerminalQueryFilter) restartWrapperAtESC() {
	f.endWrapperHold()
	f.seqBuf = append(f.seqBuf, 0x1b)
	f.state = qfStateEsc
}

// cancelWrapper drops a wrapper held while it was being decided at a CAN or
// SUB that ends its held inner string, which is dropped as a held string is
// at the top. The cancel goes out, as ordinary output: with a close owed, the
// wrapper's own ESC goes out ahead of it as the close, as for any held string
// a cancel drops. Control bytes the inner machine forwarded go out first,
// after a close of their own, where the terminal executed them.
func (f *TerminalQueryFilter) cancelWrapper(b byte) {
	if len(f.inner.outBuf) > 0 {
		f.settleClose()
		f.outBuf = append(f.outBuf, f.inner.outBuf...)
	}
	keep := 0
	if f.closeOwed {
		keep = 1
	}
	f.seqBuf = append(f.seqBuf[:keep], b)
	f.flushAndReset()
}

// dropInner drops a wrapper whose first inner sequence is a query string, to
// the string's inner end: what was held is dropped, a close owed from before
// is settled, and the control bytes the inner machine forwarded go out, as
// endWrapperHold has it. What stays held, for Pending, is the wrapper's
// framing and the inner head that decided the drop, its ESC doubled again, so
// a joiner's filter fed them drops the rest as this one does. The bytes before
// the first inner ESC and the forwarded control bytes are left out: they
// change nothing a joiner needs, and the control bytes have gone out.
func (f *TerminalQueryFilter) dropInner() {
	f.settleClose()
	f.outBuf = append(f.outBuf, f.inner.outBuf...)
	f.seqBuf = f.seqBuf[:f.frame]
	for _, c := range f.inner.seqBuf {
		if c == 0x1b {
			f.seqBuf = append(f.seqBuf, 0x1b)
		}
		f.seqBuf = append(f.seqBuf, c)
	}
	f.state = qfStateWrapDrop
}

// wrapperByte takes a byte of a tmux wrapper that passes: its first inner
// sequence was no query, or it was given up at its bound. It follows tmux's
// own DCS rules for the pairs a well-formed wrapper is made of: ESC ESC is one
// ESC of the wrapped stream, so a doubled ESC doesn't end the wrapper, and
// only an unescaped ESC \ does. CAN and SUB are payload. The rest of the
// wrapped stream isn't classified, a stated limit: every byte goes out as it
// came, and the ESC is held, as in a passed string, only until the byte after
// it says what it escapes. Read by the DEC rules instead, every doubled ESC
// restarted a sequence and lost the first of the pair.
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
		if b == 0x7f || b >= 0xa0 {
			// The ESC drops the byte, as any ESC drops a DEL or a high byte
			// (headControl), so nothing that goes out says the wrapper has
			// ended, and a joiner's filter, still in the wrapper, would take
			// the held ESC for one escaping the next byte. So the close goes
			// out now, as before a C0, and the ESC stays held with nothing
			// owed.
			f.settleClose()
			return
		}
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

// drop discards the held sequence: a query, a head the input abandoned, or a
// held string that ended abnormally.
func (f *TerminalQueryFilter) drop() {
	f.seqBuf = f.seqBuf[:0]
	f.state = qfStateNormal
	f.settleClose()
}

// restartAtESC drops the held sequence at an ESC, and holds the ESC as the
// start of a new one. What is dropped is a head the ESC abandons, of which the
// terminal executes nothing, or a held string the ESC ends without being ST,
// which kitty would keep open. A close owed from before is settled, as for any
// drop.
func (f *TerminalQueryFilter) restartAtESC() {
	f.drop()
	f.seqBuf = append(f.seqBuf, 0x1b)
	f.state = qfStateEsc
}

// dropToEnd drops a query string to its end, once the head held in seqBuf has
// decided it: a DCS header, or a graphics command's control data with the ';'
// or BEL that decided it. The head stays held, for Pending: a joiner's filter
// fed it drops the rest of the string as this one does. Nothing of the string
// has gone out, so it owes no close, but a close owed from before it is
// settled now, as for any drop.
func (f *TerminalQueryFilter) dropToEnd() {
	f.settleClose()
	f.state = qfStateDrop
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
