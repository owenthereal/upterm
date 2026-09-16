package attach

// EscapeFilter recognises ssh's detach convention in a stream of keystrokes:
// an escape byte at the start of a line followed by '.' detaches; followed by
// itself sends one literal escape byte; followed by anything else sends both.
// "Start of a line" is the beginning of input or the byte after a CR or LF —
// CR because a raw-mode terminal sends Enter as CR.
//
// Bytes after a detach are dropped: they were typed at a terminal that is no
// longer attached to anything.
type EscapeFilter struct {
	esc       byte
	lineStart bool
	pending   bool
}

// NewEscapeFilter returns a filter for esc. Zero disables it: Feed passes
// everything through.
func NewEscapeFilter(esc byte) *EscapeFilter {
	return &EscapeFilter{esc: esc, lineStart: true}
}

// Feed filters p, returning what should reach the session and whether the
// detach sequence completed. out may alias an internal buffer; copy it before
// the next call if it must be kept.
func (f *EscapeFilter) Feed(p []byte) (out []byte, detach bool) {
	if f.esc == 0 {
		return p, false
	}
	out = make([]byte, 0, len(p)+1)
	for _, b := range p {
		if f.pending {
			f.pending = false
			switch b {
			case '.':
				return out, true
			case f.esc:
				out = append(out, f.esc)
				f.lineStart = false
				continue
			default:
				out = append(out, f.esc)
				// fall through to ordinary handling of b, which is not at a line start
			}
			f.lineStart = false
		}
		if b == f.esc && f.lineStart {
			f.pending = true
			continue
		}
		out = append(out, b)
		f.lineStart = b == '\n' || b == '\r'
	}
	return out, false
}

// Flush returns a held escape byte, for the end of input.
func (f *EscapeFilter) Flush() []byte {
	if !f.pending {
		return nil
	}
	f.pending = false
	return []byte{f.esc}
}
