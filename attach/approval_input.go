package attach

import (
	"strconv"
	"strings"
)

const approvalSequenceLimit = 8192

// approvalInput only classifies incoming control sequences. It does not track
// a screen or interpret outgoing queries. String bodies and marked paste are
// never keys, including when their terminators arrive in a later read.
type approvalInput struct {
	sequence      []byte
	sequenceEpoch uint64
	kind          byte
	overflow      bool
	stringEscape  bool
	paste         bool
	interrupted   bool
	escapeExpired bool
}

func (p *approvalInput) inSequence() bool { return p.kind != 0 || p.paste }
func (p *approvalInput) loneEscape() bool { return p.kind == 'e' }
func (p *approvalInput) add(b byte) {
	if len(p.sequence) < approvalSequenceLimit && !p.overflow {
		p.sequence = append(p.sequence, b)
	} else {
		p.overflow = true
		p.sequence = nil
	}
}
func (p *approvalInput) reset() {
	p.sequence = nil
	p.kind = 0
	p.overflow = false
	p.stringEscape = false
	p.escapeExpired = false
}

func (p *approvalInput) feed(data []byte, epoch uint64) (program, keys []byte) {
	p.interrupted = false
	for _, b := range data {
		if p.kind == 0 {
			p.sequenceEpoch = epoch
			if b == 0x1b {
				p.kind = 'e'
				p.add(b)
				continue
			}
			// C1 bytes are sequence introducers too. UTF-8 text is not a confirmation.
			if b == 0x9b {
				p.kind = '['
				p.add(b)
				continue
			}
			if b == 0x9d || b == 0x90 || b == 0x9f {
				p.kind = ']'
				if b == 0x90 {
					p.kind = 'P'
				}
				if b == 0x9f {
					p.kind = '_'
				}
				p.add(b)
				continue
			}
			if !p.paste && b < 0x80 {
				keys = append(keys, b)
			} else {
				p.interrupted = true
			}
			continue
		}
		p.add(b)
		switch p.kind {
		case 'e':
			switch b {
			case 0x1b:
				p.reset()
				p.kind = 'e'
				p.sequenceEpoch = epoch
				p.add(b)
				p.interrupted = true
			case '[', ']', 'P', '_', 'O':
				p.kind = b
			case '^', 'X':
				p.kind = '_' // other ST-terminated strings; consume whole
			default:
				if p.escapeExpired {
					keys = append(keys, b)
				} else {
					p.interrupted = true
				}
				p.reset()
			}
		case '[', 'O':
			if b == 0x1b {
				// A new introducer cancels a malformed CSI, but its string body
				// must still be classified before any confirmation keystrokes.
				p.reset()
				p.kind = 'e'
				p.sequenceEpoch = epoch
				p.add(b)
				p.interrupted = true
				continue
			}
			if b >= 0x40 && b <= 0x7e {
				seq := string(p.sequence)
				kind := p.kind
				sequenceEpoch := p.sequenceEpoch
				valid := !p.overflow
				p.reset()
				if strings.HasSuffix(seq, "[200~") {
					p.paste = true
					p.interrupted = true
					continue
				}
				if strings.HasSuffix(seq, "[201~") {
					p.paste = false
					p.interrupted = true
					continue
				}
				if p.paste || !valid {
					p.interrupted = true
					continue
				}
				if kind == '[' {
					body := seq[1 : len(seq)-1]
					if seq[0] == 0x1b {
						body = seq[2 : len(seq)-1]
					}
					if approvalCSIReply(body, b) {
						program = append(program, seq...)
						p.interrupted = true
						continue
					}
					key, event := approvalEncodedKey(body, b)
					switch event {
					case approvalKeyRelease:
						// Releases are valid keyboard events, not edits or
						// malformed input. Preserve earlier decoded keys.
						continue
					case approvalKeyPress:
						// A later read cannot grant fresh ownership to a
						// key whose prefix was read before the boundary.
						if sequenceEpoch != epoch {
							p.interrupted = true
							continue
						}
						keys = append(keys, key)
						continue
					}
				}
				p.interrupted = true
			}
		case ']', 'P', '_':
			ended := b == 0x9c || (b == '\\' && p.stringEscape) || (p.kind == ']' && b == 7)
			p.stringEscape = b == 0x1b
			if ended {
				if !p.paste && !p.overflow {
					program = append(program, p.sequence...)
				}
				p.interrupted = true
				p.reset()
			}
		}
	}
	return
}

func approvalCSIReply(body string, final byte) bool {
	switch final {
	case 'c':
		return strings.HasPrefix(body, "?") || strings.HasPrefix(body, ">") || strings.HasPrefix(body, "=")
	case 'R':
		parts := strings.Split(strings.TrimPrefix(body, "?"), ";")
		if len(parts) != 2 {
			return false
		}
		for _, part := range parts {
			if _, err := strconv.ParseUint(part, 10, 32); err != nil {
				return false
			}
		}
		return true
	case 'y':
		return strings.HasPrefix(body, "?") && strings.HasSuffix(body, "$")
	case 'n':
		return body == "0" || body == "?0"
	}
	return false
}

// CSI-u/kitty press and repeat events, plus xterm modifyOtherKeys. Only
// ASCII characters participate in confirmation; Shift and Ctrl are decoded
// for uppercase codes and local Escape/Enter/backspace/suspend keys.
type approvalKeyEvent uint8

const (
	approvalKeyUnknown approvalKeyEvent = iota
	approvalKeyPress
	approvalKeyRelease
)

func approvalEncodedKey(body string, final byte) (byte, approvalKeyEvent) {
	fields := strings.Split(body, ";")
	code, mod := "", "1"
	if final == 'u' && len(fields) >= 1 && len(fields) <= 3 {
		code = fields[0]
		if len(fields) > 1 {
			mod = fields[1]
		}
	} else if final == '~' && len(fields) == 3 && fields[0] == "27" {
		code = fields[2]
		mod = fields[1]
	} else {
		return 0, approvalKeyUnknown
	}
	parts := strings.Split(mod, ":")
	if final == 'u' && len(parts) == 2 && parts[1] == "3" {
		// Releases also exist for keys/modifiers which are not confirmation
		// characters. Recognize them without exposing them as pressed keys.
		modifier, modErr := strconv.ParseUint(parts[0], 10, 16)
		point, keyErr := strconv.ParseUint(strings.Split(code, ":")[0], 10, 32)
		if modErr == nil && modifier > 0 && keyErr == nil && point <= 0x10ffff {
			return 0, approvalKeyRelease
		}
	}
	if len(parts) > 2 || (parts[0] != "1" && parts[0] != "2" && parts[0] != "5" && parts[0] != "6") {
		return 0, approvalKeyUnknown
	}
	if len(parts) == 2 && parts[1] != "1" && parts[1] != "2" {
		return 0, approvalKeyUnknown
	}
	points := strings.Split(code, ":")
	code = points[0]
	shift := parts[0] == "2" || parts[0] == "6"
	if shift && len(points) > 1 && points[1] != "" {
		code = points[1]
	}
	n, err := strconv.ParseUint(code, 10, 8)
	if err != nil || n >= 128 {
		return 0, approvalKeyUnknown
	}
	if shift && n >= 'a' && n <= 'z' {
		n -= 32
	}
	if parts[0] == "5" || parts[0] == "6" {
		if (n >= '@' && n <= '_') || (n >= 'a' && n <= 'z') {
			n &= 31
		} else {
			return 0, approvalKeyUnknown
		}
	}
	return byte(n), approvalKeyPress
}
