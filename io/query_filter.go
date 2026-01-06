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
//   - CSI 6 n (cursor position request)
//   - CSI 5 n (device status request)
//   - CSI c / CSI 0 c (primary device attributes)
//   - CSI > c / CSI > 0 c (secondary device attributes)
type TerminalQueryFilter struct {
	w      io.Writer
	state  queryFilterState
	seqBuf []byte // accumulates current sequence
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
	qfStateOSCQuery                     // saw OSC number ; ?
	qfStateOSCQueryEsc                  // saw ESC in OSC query (possible ST)
)

// NewTerminalQueryFilter creates a filter that removes terminal query
// sequences from output before writing to the underlying writer.
func NewTerminalQueryFilter(w io.Writer) *TerminalQueryFilter {
	return &TerminalQueryFilter{
		w:      w,
		seqBuf: make([]byte, 0, 64),
	}
}

func (f *TerminalQueryFilter) Write(p []byte) (int, error) {
	// Process each byte, filtering out query sequences
	output := make([]byte, 0, len(p))

	for _, b := range p {
		out, filter := f.processByte(b)
		if !filter {
			output = append(output, out...)
		}
	}

	// Write filtered output
	if len(output) > 0 {
		_, err := f.w.Write(output)
		if err != nil {
			return 0, err
		}
	}

	// Return original length to indicate all bytes were "processed"
	return len(p), nil
}

// processByte processes a single byte and returns bytes to output and whether to filter.
// Returns (bytes to write, should filter these bytes)
func (f *TerminalQueryFilter) processByte(b byte) ([]byte, bool) {
	switch f.state {
	case qfStateNormal:
		if b == 0x1b { // ESC
			f.state = qfStateEsc
			f.seqBuf = append(f.seqBuf[:0], b)
			return nil, false // Don't output yet, might be a query
		}
		return []byte{b}, false

	case qfStateEsc:
		f.seqBuf = append(f.seqBuf, b)
		switch b {
		case '[': // CSI
			f.state = qfStateCSI
			return nil, false
		case ']': // OSC
			f.state = qfStateOSC
			return nil, false
		default:
			// Not a sequence we filter, output buffered
			return f.flushAndReset(), false
		}

	case qfStateCSI:
		f.seqBuf = append(f.seqBuf, b)
		if b >= '0' && b <= '9' {
			f.state = qfStateCSIParam
			return nil, false
		}
		if b == '>' || b == '?' {
			f.state = qfStateCSIParam
			return nil, false
		}
		// Check for immediate CSI queries
		if b == 'c' {
			// CSI c - Primary Device Attributes query - FILTER
			f.state = qfStateNormal
			f.seqBuf = f.seqBuf[:0]
			return nil, true
		}
		if b == 'n' {
			// CSI n alone is not valid, but handle it
			return f.flushAndReset(), false
		}
		// Other CSI sequence, not a query we filter
		return f.flushAndReset(), false

	case qfStateCSIParam:
		f.seqBuf = append(f.seqBuf, b)
		if (b >= '0' && b <= '9') || b == ';' || b == '>' || b == '?' {
			if len(f.seqBuf) > 32 {
				return f.flushAndReset(), false
			}
			return nil, false
		}
		// Final byte - check if it's a query
		if f.isCSIQuery(b) {
			f.state = qfStateNormal
			f.seqBuf = f.seqBuf[:0]
			return nil, true // Filter the query
		}
		// Not a query, output it
		return f.flushAndReset(), false

	case qfStateOSC:
		f.seqBuf = append(f.seqBuf, b)
		if b >= '0' && b <= '9' {
			f.state = qfStateOSCParam
			return nil, false
		}
		// Invalid OSC, output it
		return f.flushAndReset(), false

	case qfStateOSCParam:
		f.seqBuf = append(f.seqBuf, b)
		if b >= '0' && b <= '9' {
			if len(f.seqBuf) > 8 {
				return f.flushAndReset(), false
			}
			return nil, false
		}
		if b == ';' {
			f.state = qfStateOSCSemi
			return nil, false
		}
		if b == 0x07 { // BEL - OSC without content, not a query
			return f.flushAndReset(), false
		}
		// Invalid, output it
		return f.flushAndReset(), false

	case qfStateOSCSemi:
		f.seqBuf = append(f.seqBuf, b)
		if b == '?' {
			// This is a query! Continue to see the terminator
			f.state = qfStateOSCQuery
			return nil, false
		}
		// Not a query (it's setting a value), output it
		// But we need to continue to the end of the OSC to output it properly
		// For simplicity, output what we have and reset
		return f.flushAndReset(), false

	case qfStateOSCQuery:
		f.seqBuf = append(f.seqBuf, b)
		if b == 0x07 { // BEL - end of OSC query
			// This is a query, filter it
			f.state = qfStateNormal
			f.seqBuf = f.seqBuf[:0]
			return nil, true
		}
		if b == 0x1b { // ESC - possible ST
			f.state = qfStateOSCQueryEsc
			return nil, false
		}
		if len(f.seqBuf) > 32 {
			return f.flushAndReset(), false
		}
		return nil, false

	case qfStateOSCQueryEsc:
		f.seqBuf = append(f.seqBuf, b)
		if b == '\\' { // ST (String Terminator)
			// This is a query, filter it
			f.state = qfStateNormal
			f.seqBuf = f.seqBuf[:0]
			return nil, true
		}
		// Not ST, output what we have
		return f.flushAndReset(), false
	}

	return []byte{b}, false
}

// isCSIQuery checks if the final byte indicates a CSI query we should filter.
func (f *TerminalQueryFilter) isCSIQuery(finalByte byte) bool {
	// Check the sequence content
	seq := string(f.seqBuf)

	switch finalByte {
	case 'n':
		// CSI 6 n - Cursor Position Request
		// CSI 5 n - Device Status Report
		if len(seq) >= 4 {
			// ESC [ 6 n or ESC [ 5 n
			param := seq[2 : len(seq)-1]
			if param == "6" || param == "5" {
				return true
			}
		}
	case 'c':
		// CSI c, CSI 0 c - Primary Device Attributes
		// CSI > c, CSI > 0 c - Secondary Device Attributes
		// CSI = c - Tertiary Device Attributes
		if len(seq) >= 3 {
			param := seq[2 : len(seq)-1]
			if param == "" || param == "0" || param == ">" || param == ">0" || param == "=" || param == "=0" {
				return true
			}
		}
	}
	return false
}

// flushAndReset returns buffered bytes and resets state.
func (f *TerminalQueryFilter) flushAndReset() []byte {
	result := make([]byte, len(f.seqBuf))
	copy(result, f.seqBuf)
	f.state = qfStateNormal
	f.seqBuf = f.seqBuf[:0]
	return result
}
