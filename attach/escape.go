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
	// EscapeStatus: the caller should show the session's status and keys in
	// this terminal, and send the session nothing for it. Feed keeps going,
	// as for a suspend.
	EscapeStatus
	// EscapeApproval enters local review and discards the rest of this read.
	EscapeApproval
)

// EscapeFilter recognises ssh's detach, suspend and help conventions in a
// stream of keystrokes: an escape byte at the start of a line followed by '.'
// detaches; followed by '^Z' (0x1a) suspends, when suspend is enabled;
// followed by '?' asks for the session's status, when WithStatus offers it;
// followed by itself sends one literal escape byte; followed by anything else
// sends both. "Start of a line" is the beginning of input or the byte after a
// CR or LF — CR because a raw-mode terminal sends Enter as CR.
//
// Bytes after a detach are dropped: they were typed at a terminal that is no
// longer attached to anything. Bytes after a suspend or a status request are
// not: they are still the session's, queued for delivery as usual.
type EscapeFilter struct {
	esc      byte
	suspend  bool
	status   bool
	approval bool
	// remainder is classified, but never treated as keys, at review entry.
	remainder []byte
	lineStart bool
	pending   bool
}

// EscapeOption is a sequence an EscapeFilter offers beyond detach and suspend.
type EscapeOption func(*EscapeFilter)

// WithStatus offers esc followed by '?' as EscapeStatus. Without it the two
// bytes reach the session like any other unrecognised pair, which is what a
// client with no status of its own to show wants: join's filter is built
// without it.
func WithStatus() EscapeOption {
	return func(f *EscapeFilter) { f.status = true }
}

// WithApproval offers esc followed by a as a deliberate local review boundary.
func WithApproval() EscapeOption { return func(f *EscapeFilter) { f.approval = true } }

// NewEscapeFilter returns a filter for esc. Zero disables it: Feed passes
// everything through, ~? included. suspend says whether esc followed by ^Z is
// offered; when it is not, both bytes reach the session like any other
// unrecognised pair.
func NewEscapeFilter(esc byte, suspend bool, opts ...EscapeOption) *EscapeFilter {
	f := &EscapeFilter{esc: esc, suspend: suspend, lineStart: true}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// Feed filters p, returning what should reach the session and what escape
// sequence, if any, completed. out may alias an internal buffer; copy it
// before the next call if it must be kept.
//
// One action per read: a detach returns at once, and a suspend outranks a
// status request in the same read, since the suspend is the one that changes
// anything. Two escape sequences in one read do not come from a keyboard.
func (f *EscapeFilter) Feed(p []byte) (out []byte, action EscapeAction) {
	if f.esc == 0 {
		return p, EscapeNone
	}
	out = make([]byte, 0, len(p)+1)
	f.remainder = nil
	for i, b := range p {
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
			case 'a':
				if f.approval {
					f.lineStart = true
					f.remainder = p[i+1:]
					return out, EscapeApproval
				}
				out = append(out, f.esc)
			case '?':
				if f.status {
					// Nothing reaches the session, so the line it sees is
					// still at its start, and ~. works next, as after ~^Z.
					f.lineStart = true
					if action == EscapeNone {
						action = EscapeStatus
					}
					continue
				}
				// Not offered (join): both bytes are the session's.
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
