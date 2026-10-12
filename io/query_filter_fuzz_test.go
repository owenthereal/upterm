package io

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refAlphabet is the fuzz domain's alphabet: ESC and what follows one to start
// a CSI, an OSC or a string, or to end a string as ST; digits and the other
// parameter bytes, with ':'; the prefixes and the intermediates the families
// name, '+' among them for family 15's DCS requests, and the ESC intermediates
// '(', '!' and '#'; the final byte of every family, Q included for XTGETXRES,
// and B, h, l, H, J and G, which end common sequences that ask nothing; BEL,
// CAN and SUB, which end sequences, CR and LF, which stand for every other C0;
// DEL; and 'a' for text. Family 16's graphics commands are spelled from it
// too: G starts one, '=' and ',' join and separate its key=value pairs, 'i' is
// a key that asks nothing, and a=q asks, so "i=1,a=q" is in the domain as it
// is.
const refAlphabet = "\x1b[]P_^X\\0123456789;:?>=<$#*'&\" (!+," +
	"cnpqQtmgSuxwvy|RZBhlHJGi\x07\x18\x1a\r\n\x7fa"

// refDomainByte maps b into the fuzz domain: refAlphabet and the bytes
// 0xA0–0xFF. A byte of either is itself, so UTF-8 in text and in an OSC, and
// the high bytes a terminal ignores inside an ESC or CSI head or a DCS header,
// are fuzzed as they come. Any other ASCII byte becomes the alphabet's byte of
// its class in the DEC grammar, which every state parses as it would have
// parsed b: a C0 becomes CR, an intermediate SP, and a final byte 'a'. No
// family tells CR or SP apart from the bytes they stand for, and only family
// 16 tells 'a' apart, as the key that asks: a graphics pair whose key is
// mapped to 'a' can come to ask (f=q becomes a=q), but no pair stops asking,
// since a, = and q are in the alphabet. So a seed whose text has letters
// outside the alphabet keeps its structure, and its queries stay queries.
// Bytes 0x80–0x9F are outside the domain (C1 introducers aren't covered) and
// no class stands for them, so they are spread over the alphabet instead.
func refDomainByte(b byte) byte {
	switch {
	case strings.IndexByte(refAlphabet, b) >= 0, b >= 0xa0:
		return b
	case b >= 0x80:
		return refAlphabet[int(b-0x80)%len(refAlphabet)]
	case b < 0x20:
		return '\r'
	case b < 0x30:
		return ' '
	}
	return 'a' // 0x40–0x7E: 0x30–0x3F and DEL are all in the alphabet
}

// refGenerate maps a fuzzer's bytes onto the fuzz domain: the inputs outside
// the limits the filter states, on which it has to keep every property. Each
// byte is mapped into the domain (refDomainByte), then cut -- left out, with
// the bytes after it still taken -- if it would take the input out of the
// domain:
//   - a byte the filter would hold past a bound: past 8 bytes of an ESC
//     sequence with intermediates, 32 of a CSI head or a DCS header, 8 of an
//     OSC's number, 256 of an OSC or 256 of a graphics command's control
//     data. Past its bound a query passes, a limit the filter accepts, and a
//     sequence isn't known to be a query until it ends, so every sequence is
//     held to its bound;
//   - the ';' that would make a DCS a tmux wrapper (final byte 't', data from
//     "mux;"), which the filter passes byte for byte, query or not.
//
// Nothing else is changed, so an input already in the domain comes back as it
// was. Where a sequence starts and how much of it the filter holds is read
// from the reference parser, not the filter, so a filter that miscounted a
// hold couldn't move the domain to hide it.
func refGenerate(seed []byte) []byte {
	out := make([]byte, 0, len(seed))
	p := refParser{mode: refDEC, semiAt: -1, stEvent: -1}
	for _, b := range seed {
		c := refDomainByte(b)
		if p.pastBound(c, len(out)) || p.wraps(c) {
			continue
		}
		p.next(c, len(out))
		out = append(out, c)
	}
	return out
}

// pastBound reports whether c, at offset at, would have the filter hold the
// sequence being parsed past its bound. A bound counts raw bytes from the
// sequence's ESC, as the filter holds them: of an ESC sequence, a CSI head or
// a DCS header, the introducer and what the parser collects, and not the C0 it
// executes or ignores, or the DEL and the bytes 0xA0–0xFF it ignores; of an
// OSC, every byte up to its terminator, the control bytes it ignores
// included, but not one the escape state skipped before the ']'
// (refParser.strHeld). The ';' that ends an OSC's number isn't counted against
// the number's bound, and a byte that ends a sequence, a header's final byte
// among them, is never held past one. A graphics command (an APC whose payload
// starts with G) is held, counted the same way as an OSC, until a ';' or a
// BEL that asks (refAPCLatches) decides it, and the ';' or BEL is held with
// it, so it counts toward the bound: past it, the filter gives the command up
// before it decides. A byte that ends the string, an ESC, CAN or SUB, is never
// held past it. The numbers are written out here, not read from the filter's
// constants.
func (p *refParser) pastBound(c byte, at int) bool {
	t := refTable[c][p.state]
	collects := t.action == raCollect || t.action == raParam
	switch p.state {
	case rsEscape, rsEscapeIntermediate:
		return collects && 1+len(p.inter) >= 8
	case rsCSIEntry, rsCSIParam, rsCSIIntermediate, rsDCSEntry, rsDCSParam, rsDCSIntermediate:
		held := 2 + len(p.params) + len(p.inter)
		if p.prefix != 0 {
			held++
		}
		return collects && held >= 32
	case rsOSCString:
		held := p.strHeld(at)
		switch {
		case t.state != rsOSCString: // BEL, ESC, CAN or SUB ends it
			return false
		case p.semiAt < 0 && c != ';':
			return held >= 8
		}
		return held >= 256
	case rsSOSPMAPCString:
		if p.str.kind != refAPC || t.state != rsSOSPMAPCString || p.strHeld(at) < 256 {
			return false
		}
		control, ok := strings.CutPrefix(string(p.data), "G")
		return ok && !strings.Contains(control, ";") && !refAPCLatches(control)
	}
	return false
}

// wraps reports whether c is the ';' that would make the DCS being parsed a
// tmux wrapper, as refNoEffect knows one.
func (p *refParser) wraps(c byte) bool {
	return c == ';' && p.state == rsDCSPassthrough && p.str.final == 't' && string(p.data) == "mux"
}

// The fuzz seeds test what their rows say only if refGenerate leaves them
// alone. A filterCases row is in the domain when every byte of it is in
// refAlphabet or 0xA0–0xFF, it holds no tmux wrapper, and no sequence in it
// passes its bound; the rows that do are the seven named below, which pin the
// bounds themselves. refGenerate has to give every such row back unchanged.
//
// Most rows are outside the alphabet only for their text, such as the 'b' in
// "a" + query + "b". refDomainByte maps that text within its class, so the
// caps must cut nothing from those either, and the seed reaches the checks
// with the row's structure. The over-bound and wrapper rows must be cut. Rows
// with a C1 byte, 0x80 to 0x9F, are left out: those map anywhere in the
// alphabet. Every row out of the domain is pinned byte for byte by the
// filterCases tests.
func TestRefGenerate_KeepsInDomainSeeds(t *testing.T) {
	overBound := []string{
		"a drop after an over-bound head closes it",
		"a drop after an over-bound ESC sequence closes it",
		"an over-bound CSI passes to its final byte",
		"over-bound title closed with ESC CAN",
		"ignored CRs in the number trip the number guard",
		"an over-bound DCS header passes as a string",
		"an over-bound APC passes as a string",
	}
	identity, high := 0, 0
	for _, c := range filterCases {
		mapped := []byte(c.in)
		c1, upper := false, false
		for i, b := range mapped {
			c1 = c1 || b >= 0x80 && b < 0xa0
			upper = upper || b >= 0xa0
			mapped[i] = refDomainByte(b)
		}
		got := string(refGenerate([]byte(c.in)))
		switch {
		case slices.Contains(overBound, c.name) || strings.Contains(c.in, "tmux;"):
			require.NotEqual(t, string(mapped), got, "%s: out of the domain, so refGenerate cuts it", c.name)
		case c1:
		default:
			require.Equal(t, string(mapped), got, "%s: no sequence past its bound, so nothing is cut", c.name)
			if got == c.in {
				identity++
				if upper {
					high++
				}
			}
		}
	}
	require.NotZero(t, identity, "some rows are in the domain byte for byte")
	require.NotZero(t, high, "and some of those have a byte from 0xA0 to 0xFF")

	// The fuzz can only check what it can make: family 15's headers are in the
	// alphabet as they are, so the DCS requests reach the filter as requests.
	for _, q := range dcsQueryExamples {
		require.Equal(t, q, string(refGenerate([]byte(q))), "%q", q)
	}
	// And family 16's graphics query, latched at a BEL or decided at its ';'.
	for _, q := range []string{"\x1b_Gi=1,a=q\x07X;\x1b\\", "\x1b_Gi=1,a=q;\x1b\\"} {
		require.Equal(t, q, string(refGenerate([]byte(q))), "%q", q)
	}
}

// FuzzTerminalQueryFilter checks that, whatever refGenerate makes of the
// fuzzer's bytes, the filter keeps every property it promises a guest:
//   - it never panics;
//   - Pending never holds more than maxPendingBytes, after any byte;
//   - the output doesn't depend on how the input is split into writes;
//   - a joiner that takes what was emitted, then Pending, then the rest ends
//     where the filter does (continuationCheck, at one boundary);
//   - filtering the output again changes nothing, which a joiner's own filter
//     relies on, since it re-filters the ring;
//   - the reference parser finds no query in the output under any of the
//     three string-end models, and the same effects as the input's, less its
//     queries and the held strings the filter drops by policy (refCheck).
//
// The seeds are every filterCases input and four inputs the filter used to
// get wrong.
func FuzzTerminalQueryFilter(f *testing.F) {
	seeds := []string{"\x1b\x1b[6n", "\x1b[6\x1b[6n", "\x1b]0;t\x1b[6nhello", "\x1b]11;?\x1b[6n\x07"}
	for _, c := range filterCases {
		seeds = append(seeds, c.in)
	}
	for _, in := range seeds {
		// A seed is written in thirds, and continued just after its last ESC,
		// which most often falls inside a sequence the filter holds.
		n := uint(len(in))
		f.Add([]byte(in), n/3, 2*n/3, uint(strings.LastIndexByte(in, 0x1b)+1))
	}
	f.Fuzz(func(t *testing.T, seed []byte, i, j, k uint) {
		in := string(refGenerate(seed))
		whole := filterAll(in)

		var bytewise bytes.Buffer
		g := NewTerminalQueryFilter(&bytewise)
		for at := range len(in) {
			_, _ = g.Write([]byte{in[at]})
			if !assert.LessOrEqual(t, len(g.Pending()), maxPendingBytes, "Pending after byte %d of %q", at, in) {
				break
			}
		}
		assert.Equal(t, whole, bytewise.String(), "written byte by byte: %q", in)

		n := uint(len(in)) + 1
		a, b := int(min(i%n, j%n)), int(max(i%n, j%n))
		var split bytes.Buffer
		h := NewTerminalQueryFilter(&split)
		for _, w := range []string{in[:a], in[a:b], in[b:]} {
			_, _ = h.Write([]byte(w))
		}
		assert.Equal(t, whole, split.String(), "written split at %d and %d: %q", a, b, in)

		at := int(k % n)
		assert.Equal(t, whole, continuedAt(in, at), "continued at %d of %q", at, in)

		assert.Equal(t, whole, filterAll(whole), "filtered again: %q", in)

		assert.Empty(t, refCheck(in, filterAll))
	})
}

// Every guest's output goes through Write, so once its buffers have grown it
// allocates nothing, whatever the stream holds: text, a passed and a dropped
// CSI, an OSC held to its end, a DCS passed as it streams, and one dropped,
// and a graphics command passed after its ';', and one dropped.
func TestTerminalQueryFilter_DoesNotAllocate(t *testing.T) {
	f := NewTerminalQueryFilter(io.Discard)
	chunk := []byte("text \x1b[1mbold\x1b[m \x1b[6n \x1b]0;title\x07 \x1b[?2026$p \x1bPq#0\x1b\\ \x1bP+q544e\x1b\\ " +
		"\x1b_Ga=T,f=100;AAAA\x1b\\ \x1b_Gi=1,a=q;AAAA\x1b\\ more\r\n")
	_, _ = f.Write(chunk) // warm the reusable buffers
	require.Zero(t, testing.AllocsPerRun(100, func() { _, _ = f.Write(chunk) }))
}

// BenchmarkTerminalQueryFilter measures throughput on output dense with
// sequences, three in four of them queries, so the hot path is the parser's
// rather than plain text's.
func BenchmarkTerminalQueryFilter(b *testing.B) {
	data := bytes.Repeat([]byte("ab\x1b[6n\x1b[1mcd\x1b]11;?\x07ef\x1b[?2026$p"), 1<<16/32)
	f := NewTerminalQueryFilter(io.Discard)
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		_, _ = f.Write(data)
	}
}
