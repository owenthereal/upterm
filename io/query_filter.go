package io

import (
	"io"
)

// TerminalQueryFilter wraps an io.Writer and filters out terminal query
// sequences from the output. This prevents queries sent by the host's shell
// from reaching connected clients, whose terminals would otherwise respond
// and pollute the PTY input.
//
// Filtered queries include:
//   - OSC 10/11/12 queries (foreground/background/cursor color): ESC ] N ; ? BEL/ST
//   - CSI 5 n (device status request)
//   - CSI 6 n (cursor position request)
//   - CSI c / CSI 0 c (primary device attributes)
//   - CSI > c / CSI > 0 c (secondary device attributes)
//   - CSI = c / CSI = 0 c (tertiary device attributes)
type TerminalQueryFilter struct {
	w      io.Writer
	state  queryFilterState
	seqBuf []byte // accumulates current sequence
	outBuf []byte // reusable output buffer to reduce allocations
	oscCmd int    // OSC command number being parsed
}

type queryFilterState int

const (
	qfStateNormal      queryFilterState = iota
	qfStateEsc                          // saw ESC
	qfStateCSI                          // saw ESC [
	qfStateCSIParam                     // parsing CSI parameters
	qfStateOSC                          // saw ESC ]
	qfStateOSCParam                     // saw OSC number
	qfStateOSCSemi                      // saw OSC number ;
	qfStateOSCQuery                     // saw OSC N ; ? (query for color)
	qfStateOSCQueryEsc                  // saw ESC in OSC query (possible ST)
	qfStateOSCContent                   // saw OSC N ; <non-?> (not a query, pass through)
	qfStateOSCContentEsc                // saw ESC in OSC content (possible ST)
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

// processByte processes a single byte, appending non-filtered output to f.outBuf.
func (f *TerminalQueryFilter) processByte(b byte) {
	switch f.state {
	case qfStateNormal:
		if b == 0x1b { // ESC
			f.state = qfStateEsc
			f.seqBuf = append(f.seqBuf[:0], b)
			return // Don't output yet, might be a query
		}
		f.outBuf = append(f.outBuf, b)

	case qfStateEsc:
		f.seqBuf = append(f.seqBuf, b)
		switch b {
		case '[': // CSI
			f.state = qfStateCSI
		case ']': // OSC
			f.state = qfStateOSC
			f.oscCmd = 0
		default:
			// Not a sequence we filter, output buffered
			f.flushAndReset()
		}

	case qfStateCSI:
		f.seqBuf = append(f.seqBuf, b)
		if b >= '0' && b <= '9' {
			f.state = qfStateCSIParam
			return
		}
		if b == '>' || b == '?' || b == '=' {
			f.state = qfStateCSIParam
			return
		}
		// Check for immediate CSI queries
		if b == 'c' {
			// CSI c - Primary Device Attributes query - FILTER
			f.state = qfStateNormal
			f.seqBuf = f.seqBuf[:0]
			return
		}
		// Other CSI sequence, not a query we filter
		f.flushAndReset()

	case qfStateCSIParam:
		f.seqBuf = append(f.seqBuf, b)
		if (b >= '0' && b <= '9') || b == ';' || b == '>' || b == '?' || b == '=' {
			if len(f.seqBuf) > 32 {
				f.flushAndReset()
			}
			return
		}
		// Final byte - check if it's a query
		if f.isCSIQuery(b) {
			f.state = qfStateNormal
			f.seqBuf = f.seqBuf[:0]
			return // Filter the query
		}
		// Not a query, output it
		f.flushAndReset()

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
		f.seqBuf = append(f.seqBuf, b)
		if b == '\\' { // ST (String Terminator)
			// Pass through the entire OSC sequence
			f.flushAndReset()
			return
		}
		// Not ST, continue as content (the ESC might be part of content)
		f.state = qfStateOSCContent

	case qfStateOSCQuery:
		f.seqBuf = append(f.seqBuf, b)
		if b == 0x07 { // BEL - end of OSC query
			// This is a color query (OSC 10/11/12), filter it
			f.state = qfStateNormal
			f.seqBuf = f.seqBuf[:0]
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
		f.seqBuf = append(f.seqBuf, b)
		if b == '\\' { // ST (String Terminator)
			// This is a color query (OSC 10/11/12), filter it
			f.state = qfStateNormal
			f.seqBuf = f.seqBuf[:0]
			return
		}
		// Not ST, output what we have
		f.flushAndReset()

	default:
		f.outBuf = append(f.outBuf, b)
	}
}

// isCSIQuery checks if the final byte indicates a CSI query we should filter.
func (f *TerminalQueryFilter) isCSIQuery(finalByte byte) bool {
	// seqBuf contains: ESC [ params finalByte
	// We need at least ESC [ finalByte (3 bytes)
	n := len(f.seqBuf)
	if n < 3 {
		return false
	}

	// Extract parameters (bytes between '[' and finalByte)
	params := f.seqBuf[2 : n-1]

	switch finalByte {
	case 'n':
		// CSI 5 n - Device Status Report
		// CSI 6 n - Cursor Position Request
		if len(params) == 1 && (params[0] == '5' || params[0] == '6') {
			return true
		}
	case 'c':
		// CSI c, CSI 0 c - Primary Device Attributes
		// CSI > c, CSI > 0 c - Secondary Device Attributes
		// CSI = c, CSI = 0 c - Tertiary Device Attributes
		if len(params) == 0 {
			return true
		}
		if len(params) == 1 && (params[0] == '0' || params[0] == '>' || params[0] == '=') {
			return true
		}
		if len(params) == 2 && ((params[0] == '>' && params[1] == '0') || (params[0] == '=' && params[1] == '0')) {
			return true
		}
	}
	return false
}

// flushAndReset appends buffered bytes to outBuf and resets state.
func (f *TerminalQueryFilter) flushAndReset() {
	f.outBuf = append(f.outBuf, f.seqBuf...)
	f.state = qfStateNormal
	f.seqBuf = f.seqBuf[:0]
}
