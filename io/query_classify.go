package io

// This file is the only place that knows what a terminal query is. The filter
// finds where each sequence starts and ends and hands its bytes to one
// classifier per kind (csiQuery, escQuery, oscQuery, dcsQuery and apcQuery
// here); it reads a sequence's bytes for its grammar alone, and never decides
// by a final byte, an OSC number or a graphics key whether the sequence is a
// query. A query is a sequence the terminal answers on its input, which the
// host's PTY would take for keystrokes, so the filter drops it on the way to a
// guest. Everything else must reach the guest unchanged.
//
// The families come from xterm's Control Sequences (ctlseqs) and kitty's
// keyboard and graphics protocols. The comments below number them, name the
// sequences each one asks with (DA, DSR, DECRQM and so on), and give the
// counter-cases each must let through. The classifiers are pure functions
// over the bytes the filter held, and none of them allocates: the filter calls
// them from Write, which makes no allocations in steady state.

// maxQueryNumber is where a number saturates. No family looks at a value near
// it, so a run of digits long enough to overflow an int can only land on a
// value no family matches, never wrap round to one that does.
const maxQueryNumber = 1 << 20

// addDigit appends the decimal digit d to the number v, saturating.
func addDigit(v int, d byte) int {
	return min(v*10+int(d-'0'), maxQueryNumber)
}

// csiParamInfo is what the families need from a parameter string.
type csiParamInfo struct {
	count int  // parameters, empty ones counted: "" is 0, "6" is 1, ";" is 2
	first int  // the first parameter's value; empty is 0
	sub   bool // a ':' appears: sub-parameters, which match no family
}

// parseCSIParams reads a CSI's parameter bytes (digits, ';' and ':', without
// the prefix) as numbers, the way a terminal does: "06" is 6, and an empty
// parameter is 0. Families 1, 3, 5 and 10 look at the first parameter only, so
// the rest are counted but not valued.
func parseCSIParams(params []byte) csiParamInfo {
	var info csiParamInfo
	if len(params) == 0 {
		return info
	}
	info.count = 1
	inFirst := true
	for _, c := range params {
		switch {
		case c == ';':
			info.count++
			inFirst = false
		case c == ':':
			// Nothing after a ':' belongs to the first parameter's own value.
			info.sub = true
			inFirst = false
		case c >= '0' && c <= '9' && inFirst:
			info.first = addDigit(info.first, c)
		}
	}
	return info
}

// csiQuery reports whether seq, a complete CSI as the filter holds it
// (ESC '[' prefix? params intermediates final, with no C0 or DEL inside), is
// a request in families 1 and 3–10.
//
// A rule that names no prefix or intermediates requires none, so `CSI ? 6 c`
// (family 1 wants no prefix, `>` or `=`) and `CSI 2 * x` (family 10 wants no
// intermediate on an `x`) are not queries. A sequence whose parts are out of
// order, such as a prefix byte after a parameter, puts a terminal in
// CSI-ignore, where it does nothing; it matches no family.
func csiQuery(seq []byte) bool {
	if len(seq) < 3 || seq[0] != 0x1b || seq[1] != '[' {
		return false
	}
	final := seq[len(seq)-1]
	if final < 0x40 || final > 0x7e {
		return false
	}
	body := seq[2 : len(seq)-1]

	// The prefix is only the byte right after '[', when it is 0x3C–0x3F: from
	// the second byte on, those same bytes are out of place.
	var prefix byte
	if len(body) > 0 && body[0] >= 0x3c && body[0] <= 0x3f {
		prefix, body = body[0], body[1:]
	}
	n := 0
	for n < len(body) && body[n] >= 0x30 && body[n] <= 0x3b {
		n++
	}
	params, rest := body[:n], body[n:]
	for _, c := range rest {
		if c < 0x20 || c > 0x2f {
			return false
		}
	}
	// Every family names at most one intermediate, so a CSI with two matches
	// none, and what is left is that one byte or none.
	var inter byte
	switch len(rest) {
	case 0:
	case 1:
		inter = rest[0]
	default:
		return false
	}
	info := parseCSIParams(params)
	if info.sub {
		return false
	}

	bare := inter == 0 && prefix == 0 // neither a prefix nor an intermediate
	switch final {
	case 'c': // 1: device attributes. `CSI ? 6 c` is a Linux console cursor.
		return inter == 0 && (prefix == 0 || prefix == '>' || prefix == '=') && info.first == 0
	case 'n': // 3: status reports. `CSI > 4 n` and `CSI 0 n` are not requests.
		return inter == 0 && (prefix == '?' || prefix == 0 && (info.first == 5 || info.first == 6))
	case 'p': // 4: DECRQM
		return inter == '$' && (prefix == 0 || prefix == '?')
	case 'q': // 5: XTVERSION
		return inter == 0 && prefix == '>' && info.first == 0
	case 't': // 6: window reports. `CSI 8;24;80 t` and `CSI 22;0 t` are not.
		switch info.first {
		case 11, 13, 14, 15, 16, 18, 19, 20, 21:
			return bare
		}
		return false
	case 'm', 'g': // 7: XTQMODKEYS and XTQFMTKEYS
		return inter == 0 && prefix == '?'
	case 'S':
		// 8: graphics attributes. Every action, the setters as well as the
		// reads, since each is answered. The bare `CSI 3 S` is scroll up.
		// 10: XTTITLEPOS.
		return (inter == 0 && prefix == '?') || (inter == '#' && prefix == 0 && info.count == 0)
	case 'u':
		// 9: the kitty keyboard query, with any parameters. kitty, Ghostty,
		// foot, Alacritty and iTerm2 answer `CSI ? 1 u` with the flags, as
		// they do a bare `CSI ? u`, without looking at the parameters, so each
		// form is a request. `CSI > 1 u`, `CSI < u`, `CSI = 1;1 u` and a bare
		// `CSI u` push, pop, set and restore.
		// 10: DECRQUPSS.
		return (inter == 0 && prefix == '?') || (inter == '&' && prefix == 0)
	case 'x': // 10: DECREQTPARM
		return bare && info.first <= 1
	case 'w': // 10: DECRQPSR
		return inter == '$' && prefix == 0
	case 'v': // 10: DECRQDE
		return inter == '"' && prefix == 0
	case 'y': // 10: DECRQCRA
		return inter == '*' && prefix == 0
	case '|': // 10: XTREPORTSGR and DECRQLP. `CSI 132 $ |` is DECSCPP.
		return (inter == '#' || inter == '\'') && prefix == 0
	case 'R': // 10: XTREPORTCOLORS
		return inter == '#' && prefix == 0 && info.count == 0
	}
	return false
}

// escQuery reports whether seq, a complete ESC sequence (ESC intermediates
// final), is a request: family 2, ESC Z (DECID). `ESC 7`, `ESC 8` and
// `ESC ( B` are not.
func escQuery(seq []byte) bool {
	return len(seq) == 2 && seq[0] == 0x1b && seq[1] == 'Z'
}

// oscIgnored reports whether the OSC state of a terminal's parser discards b:
// the C0 controls but for BEL (which ends the OSC), CAN, SUB and ESC (which
// leave it). DEL is not among them; an OSC collects it as payload.
func oscIgnored(b byte) bool {
	return b <= 0x06 || b >= 0x08 && b <= 0x17 || b == 0x19 || b >= 0x1c && b <= 0x1f
}

// oscView reads an OSC's bytes the way its terminal does, without the ones it
// ignores, and without copying them: `ESC ] 11;? LF` is a query because the LF
// is gone before the terminal sees a payload.
type oscView []byte

// next returns the next byte that counts, or false at the end.
func (v *oscView) next() (byte, bool) {
	for len(*v) > 0 {
		c := (*v)[0]
		*v = (*v)[1:]
		if !oscIgnored(c) {
			return c, true
		}
	}
	return 0, false
}

// field reads up to the next ';' or the end: the field's first byte (0 for an
// empty field), its length, and whether the end of the view ended it.
func (v *oscView) field() (first byte, length int, last bool) {
	for {
		c, ok := v.next()
		if !ok {
			return first, length, true
		}
		if c == ';' {
			return first, length, false
		}
		if length == 0 {
			first = c
		}
		length++
	}
}

// oscQuery reports whether seq, a complete OSC as held (ESC ']' then its
// number and payload, without the terminator), is a request in families
// 11–14. It reads the number and fields from a view with the control bytes the
// OSC state ignores (0x00–0x06, 0x08–0x17, 0x19, 0x1c–0x1f) removed.
//
// The number is read as one, so `011` is 11, and the fields are the payload
// split on ';' and numbered after it: in `ESC ] 52;c;?` field 1 is `c` and
// field 2 is `?`.
func oscQuery(seq []byte) bool {
	if len(seq) < 2 || seq[0] != 0x1b || seq[1] != ']' {
		return false
	}
	v := oscView(seq[2:])
	n, digits := 0, 0
	c, ok := v.next()
	for ok && c >= '0' && c <= '9' {
		n = addDigit(n, c)
		digits++
		c, ok = v.next()
	}
	// Anything but ';' or the end after the number makes it no number. The
	// terminal ignores such an OSC rather than dispatch it.
	if digits == 0 || ok && c != ';' {
		return false
	}

	switch {
	case n >= 60 && n <= 62: // 14: feature queries, whatever the payload
		return true
	case n == 4 || n == 5 || n >= 10 && n <= 19: // 11: colour queries
	case n == 52: // 12: clipboard read
	case n == 50: // 13: font query
	default:
		return false
	}
	if !ok { // no ';', so no fields
		return false
	}

	for k := 1; ; k++ {
		first, length, last := v.field()
		isQuery := length == 1 && first == '?'
		switch {
		case n == 52:
			// The data is the second field. The first is the selection, which
			// a request leaves as it likes (`OSC 52;;?` asks for the default).
			if k == 2 {
				return isQuery
			}
		case n == 50:
			// The font name starts with '?' in a query (`OSC 50;?+1`).
			return first == '?'
		case isQuery: // 4 and 10–19: any field asks, so a mixed OSC 4 is dropped whole
			return true
		}
		if last {
			return false
		}
	}
}

// dcsQuery reports whether header, a complete DCS header as held
// (ESC 'P' prefix? params intermediates final, with no C0 or DEL inside), is
// a request in family 15: DECRQSS ($ q), XTGETTCAP (+ q) or XTGETXRES (+ Q).
// Parameters don't matter.
//
// The header is all that decides: what follows it is the request's payload
// (the setting DECRQSS asks for, or XTGETTCAP's hex-encoded names), which the
// terminal answers whatever it holds. A prefix, which no request names, or a
// second intermediate matches no family, so the sixel `DCS 0;1;0 q`, XTSETTCAP
// `DCS + p` and the replies' own shapes (`DCS 1 $ r`, `DCS 1 + r`) are not
// requests. A header out of order, with a ':' or a parameter after an
// intermediate, puts a terminal in DCS-ignore; it matches no family either.
func dcsQuery(header []byte) bool {
	if len(header) < 4 || header[0] != 0x1b || header[1] != 'P' {
		return false
	}
	final := header[len(header)-1]
	body := header[2 : len(header)-1]
	n := 0
	for n < len(body) && (body[n] >= '0' && body[n] <= '9' || body[n] == ';') {
		n++
	}
	// What is left after the parameters must be the one intermediate. A
	// prefix or a ':' stops the parameters early, so it is left over too.
	if len(body)-n != 1 {
		return false
	}
	switch body[n] {
	case '$': // DECRQSS
		return final == 'q'
	case '+': // XTGETTCAP and XTGETXRES
		return final == 'q' || final == 'Q'
	}
	return false
}

// apcQuery reports whether control, the bytes of a kitty graphics command
// after "ESC _ G" up to (not including) its ';' or its end, has key 'a' with
// value 'q'. Keys are comma-separated key=value pairs; control bytes in it
// are part of the value, as the terminal hands them to the handler.
//
// This is family 16, kitty's graphics query (a=q), which asks the terminal
// whether it can show images. Any a=q pair counts, wherever it falls. A pair
// is that one exactly: "a=Q", "a =q" and "a=q CR" are not it, nor is
// "i=1 BEL a=q", which is one pair, whose key is i. `APC G a=T,f=100,i=1;…`
// transmits an image and asks nothing. The filter calls this at the ';' or
// the string's end, and before that at every BEL, on the bytes before the BEL,
// since kitty ends the string there.
func apcQuery(control []byte) bool {
	start := 0
	for i := 0; i <= len(control); i++ {
		if i == len(control) || control[i] == ',' {
			if string(control[start:i]) == "a=q" {
				return true
			}
			start = i + 1
		}
	}
	return false
}
