package attach

// EscapeAction is what an escape sequence asked for.
type EscapeAction int

const (
	// EscapeNone: nothing completed in this read.
	EscapeNone EscapeAction = iota
	// EscapeDetach: the caller should leave. Feed returns at once, so bytes
	// after the sequence are dropped — they were typed at a terminal that is
	// no longer attached to anything.
	EscapeDetach
	// EscapeSuspend: the caller should stop this process and resume the
	// attachment afterwards. Feed keeps going, so the rest of the read is
	// still the session's.
	EscapeSuspend
)

// EscapeFilter recognises ssh's detach and suspend conventions in a stream of
// keystrokes: an escape byte at the start of a line followed by '.' detaches;
// followed by '^Z' (0x1a) suspends, when suspend is enabled; followed by
// itself sends one literal escape byte; followed by anything else sends both.
// "Start of a line" is the beginning of input or the byte after a CR or LF —
// CR because a raw-mode terminal sends Enter as CR.
//
// Bytes after a detach are dropped: they were typed at a terminal that is no
// longer attached to anything. Bytes after a suspend are not: they are still
// the session's, queued for delivery once the process resumes.
type EscapeFilter struct {
	esc       byte
	suspend   bool
	lineStart bool
	pending   bool
}

// NewEscapeFilter returns a filter for esc. Zero disables it: Feed passes
// everything through. suspend says whether esc followed by ^Z is offered;
// when it is not, both bytes reach the session like any other unrecognised
// pair.
func NewEscapeFilter(esc byte, suspend bool) *EscapeFilter {
	return &EscapeFilter{esc: esc, suspend: suspend, lineStart: true}
}

// Feed filters p, returning what should reach the session and what escape
// sequence, if any, completed. out may alias an internal buffer; copy it
// before the next call if it must be kept.
func (f *EscapeFilter) Feed(p []byte) (out []byte, action EscapeAction) {
	if f.esc == 0 {
		return p, EscapeNone
	}
	out = make([]byte, 0, len(p)+1)
	for _, b := range p {
		if f.pending {
			f.pending = false
			switch b {
			case '.':
				return out, EscapeDetach
			case f.esc:
				out = append(out, f.esc)
				f.lineStart = false
				continue
			case 0x1a: // ^Z
				if f.suspend {
					// The sequence is consumed and the line is not: what
					// follows was typed at a line start, exactly as it was
					// before.
					f.lineStart = true
					action = EscapeSuspend
					continue
				}
				// Not offered here (no hook, or a platform with no job
				// control): both bytes are the session's, like any other
				// unrecognised pair.
				out = append(out, f.esc)
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
	return out, action
}

// Flush returns a held escape byte, for the end of input.
func (f *EscapeFilter) Flush() []byte {
	if !f.pending {
		return nil
	}
	f.pending = false
	return []byte{f.esc}
}
