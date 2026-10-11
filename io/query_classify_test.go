package io

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The families' rows as exact sequences: CSIs complete, OSCs without their
// terminator. They are package-level so the filter's tests can build their
// cases from the same rows, and so a row added here is exercised by both.
var (
	// csiQueryExamples are requests, by family number.
	csiQueryExamples = []string{
		"\x1b[c", "\x1b[0c", "\x1b[00c", "\x1b[0;1c", "\x1b[;c", "\x1b[>c", "\x1b[>0c", "\x1b[=c", "\x1b[=0c", // 1
		"\x1b[5n", "\x1b[6n", "\x1b[06n", "\x1b[6;1n", "\x1b[?6n", "\x1b[?15n", "\x1b[?996n", // 3
		"\x1b[?2026$p", "\x1b[4$p", "\x1b[?1049$p", // 4
		"\x1b[>q", "\x1b[>0q", "\x1b[>00q", // 5
		"\x1b[11t", "\x1b[13t", "\x1b[13;2t", "\x1b[14t", "\x1b[14;2t", "\x1b[15t", "\x1b[16t",
		"\x1b[18t", "\x1b[19t", "\x1b[20t", "\x1b[21t", // 6
		"\x1b[?4m", "\x1b[?1g", // 7
		"\x1b[?1;1;0S", "\x1b[?2;1;0S", "\x1b[?1;3;256S", // 8, setters too
		"\x1b[?u", "\x1b[?0u", "\x1b[?1u", "\x1b[?1;2u", "\x1b[?;u", // 9, whatever the parameters
		"\x1b[x", "\x1b[0x", "\x1b[1x", "\x1b[01x", "\x1b[1$w", "\x1b[&u", "\x1b[\"v",
		"\x1b[1;1;1;1;24;80*y", "\x1b[1;1;24;80#|", "\x1b[1'|", "\x1b[#R", "\x1b[#S", // 10
	}

	// csiPassExamples are the counter-cases: sequences near a family
	// that a terminal answers nothing to, and so must reach a guest.
	csiPassExamples = []string{
		"\x1b[?6c", "\x1b[>4n", "\x1b[0n", "\x1b[!p", "\x1b[>1p", "\x1b[61\"p",
		"\x1b[?2026h", "\x1b[?2026l", "\x1b[2 q", "\x1b[1q", "\x1b[0q",
		"\x1b[8;24;80t", "\x1b[22;0t", "\x1b[23;0t", "\x1b[>0t", "\x1b[>4;2m", "\x1b[1m",
		"\x1b[38:2::255:0:0m", "\x1b[6:1n", "\x1b[3S", "\x1b[>1u", "\x1b[<u", "\x1b[=1;1u",
		"\x1b[u", "\x1b[2x", "\x1b[2*x", "\x1b[#{", "\x1b[132$|", "\x1b[1#Q", "\x1b[2J",
		"\x1b[10;20H", "\x1b[1$ p", "\x1b[?1:2u",
	}

	// oscQueryExamples are requests, by family number (11 to 14).
	oscQueryExamples = []string{
		"\x1b]4;1;?", "\x1b]4;0;rgb:00/00/00;1;?", "\x1b]5;0;?", "\x1b]10;?", "\x1b]11;?",
		"\x1b]12;?", "\x1b]17;?", "\x1b]19;?", "\x1b]10;?;?", "\x1b]011;?", "\x1b]11;?\n",
		"\x1b]1\n1;?", "\x1b]52;c;?", "\x1b]52;;?", "\x1b]50;?", "\x1b]50;?+1",
		"\x1b]60", "\x1b]61;allowColorOps", "\x1b]62;allowColorOps",
	}

	// oscPassExamples are the OSC counter-cases.
	oscPassExamples = []string{
		"\x1b]4;1;rgb:ff/00/00", "\x1b]104;1", "\x1b]11;rgb:00/00/00", "\x1b]52;c;SGVsbG8=",
		"\x1b]50;fixed", "\x1b]0;My Title", "\x1b]0;?", "\x1b]8;;https://example.com/?q=1",
		"\x1b]133;A", "\x1b]7;file://host/tmp", "\x1b]777;notify;Title;Body", "\x1b]0;",
		"\x1b]11;", "\x1b]20;?",
	}

	// dcsQueryExamples are family 15's requests, as complete headers: what
	// dcsQuery decides on, without the payload that follows.
	dcsQueryExamples = []string{
		"\x1bP$q", "\x1bP+q", "\x1bP+Q", // DECRQSS, XTGETTCAP, XTGETXRES
		"\x1bP1$q", "\x1bP0;1+q", "\x1bP;+Q", // whatever the parameters
	}

	// dcsPassExamples are the DCS counter-cases: headers near family 15 that
	// ask nothing, the replies' own shapes among them.
	dcsPassExamples = []string{
		"\x1bPq", "\x1bP0;1;0q", "\x1bP+p", "\x1bPt", "\x1bP@", // sixel, XTSETTCAP, tmux, kitty's remote control
		"\x1bP1$r", "\x1bP1+r", "\x1bP$Q", "\x1bP$t", // DECRPSS and XTGETTCAP's reply, and the neighbours
		"\x1bP?$q", "\x1bP>+q", // a prefix, which no request names
		"\x1bP$$q", "\x1bP $q", "\x1bP+$q", // two intermediates
	}
)

func TestCSIQuery_Families(t *testing.T) {
	for _, q := range csiQueryExamples {
		require.True(t, csiQuery([]byte(q)), "%q", q)
	}
	for _, c := range csiPassExamples {
		require.False(t, csiQuery([]byte(c)), "%q", c)
	}
}

// The rules the examples don't pin down: how numbers are read, what "no
// parameters" means, and how intermediates, sub-parameters and a malformed
// sequence rule a sequence out.
func TestCSIQuery_Boundaries(t *testing.T) {
	zeros := strings.Repeat("0", 40)
	nines := strings.Repeat("9", 40)
	for _, q := range []string{
		"\x1b[" + zeros + "6n",    // leading zeros are zeros
		"\x1b[" + zeros + "c",     // all of them is 0
		"\x1b[" + zeros + "1x",    // 1
		"\x1b[" + zeros + "13;2t", // 13
		"\x1b[?" + nines + "n",    // family 3 with the prefix takes any parameters
		"\x1b[?n",                 // or none
	} {
		require.True(t, csiQuery([]byte(q)), "%q", q)
	}
	for _, c := range []string{
		// A number saturates, rather than wrapping round to one a family wants.
		"\x1b[" + nines + "t", "\x1b[" + nines + "x", "\x1b[" + nines + "n",
		// Family 10's `# R` and `# S` take no parameters: none, not zero.
		"\x1b[#0R", "\x1b[#0S",
		// Two intermediates match no family, whichever they are.
		"\x1b[?2026$$p", "\x1b[?2026$ p", "\x1b[1$$w", "\x1b[ $w",
		// Sub-parameters match no family, however well the rest fits.
		"\x1b[0:1c", "\x1b[>0:1q", "\x1b[?6:1n", "\x1b[?1:1;3S", "\x1b[0:1x", "\x1b[13:1t",
		// A prefix after the first byte, or a parameter after an intermediate,
		// is out of order.
		"\x1b[?>6n", "\x1b[6?n", "\x1b[$6p",
		// Not a complete CSI.
		"\x1b[", "\x1b[\x1b[6n", "\x1b6n", "n", "",
	} {
		require.False(t, csiQuery([]byte(c)), "%q", c)
	}
}

func TestOSCQuery_Families(t *testing.T) {
	for _, q := range oscQueryExamples {
		require.True(t, oscQuery([]byte(q)), "%q", q)
	}
	for _, c := range oscPassExamples {
		require.False(t, oscQuery([]byte(c)), "%q", c)
	}
}

// The OSC rules the examples don't pin down: the bytes the OSC state ignores,
// a number that isn't one, and which field each family reads.
func TestOSCQuery_Boundaries(t *testing.T) {
	for _, q := range []string{
		"\x1b]\x001\x001;\x00?\x00",                // ignored bytes can sit anywhere
		"\x1b]52;\x08c;\x1f?\x0c",                  // in a field
		"\x1b]5\x1c0;\x19?",                        // or between the digits of the number
		"\x1b]4;1;?;2;rgb:00/00/00",                // one field of several is enough
		"\x1b]" + strings.Repeat("0", 40) + "11;?", // leading zeros are zeros
	} {
		require.True(t, oscQuery([]byte(q)), "%q", q)
	}
	for _, c := range []string{
		// No number, or a number that doesn't end at a ';'.
		"\x1b];?", "\x1b]", "\x1b]x;?", "\x1b]11x;?", "\x1b]1 1;?",
		// A number saturates, rather than wrapping round to a family.
		"\x1b]" + strings.Repeat("9", 40) + ";?",
		// A colour field is exactly ?, and DEL is payload, not an ignored byte.
		"\x1b]10;??", "\x1b]10;? ", "\x1b]10; ?", "\x1b]4;1;\x7f?",
		// OSC 52 asks in its second field, and OSC 50 in its first.
		"\x1b]52;?;c", "\x1b]52;c;?x", "\x1b]52;c;c;?", "\x1b]50;x;?", "\x1b]50;",
		// The numbers next to 60 to 62.
		"\x1b]6;?", "\x1b]63;?",
		// Not an OSC.
		"\x1b[11;?", "",
	} {
		require.False(t, oscQuery([]byte(c)), "%q", c)
	}
}

func TestESCQuery(t *testing.T) {
	require.True(t, escQuery([]byte("\x1bZ")))
	for _, c := range []string{"\x1b7", "\x1b8", "\x1b(B", "\x1b#8", "\x1b\\", "\x1bc", "\x1b Z", "\x1b(Z", "\x1b", "Z", ""} {
		require.False(t, escQuery([]byte(c)), "%q", c)
	}
}

func TestDCSQuery_Families(t *testing.T) {
	for _, q := range dcsQueryExamples {
		require.True(t, dcsQuery([]byte(q)), "%q", q)
	}
	for _, c := range dcsPassExamples {
		require.False(t, dcsQuery([]byte(c)), "%q", c)
	}
}

// The DCS rules the examples don't pin down: a header out of order is a
// DCS-ignore, which dispatches nothing, and only a whole header is decided.
func TestDCSQuery_Boundaries(t *testing.T) {
	require.True(t, dcsQuery([]byte("\x1bP"+strings.Repeat("9", 40)+"+q")), "a long parameter is still a parameter")
	for _, c := range []string{
		// A parameter after an intermediate, a ':', or a prefix after a
		// parameter: out of order, so a DCS-ignore.
		"\x1bP$1q", "\x1bP1:2+q", "\x1bP:+q", "\x1bP1?+q",
		// Not a complete header.
		"\x1bP", "\x1bP+", "\x1bP$", "\x1b[+q", "\x1b+q", "+q", "",
	} {
		require.False(t, dcsQuery([]byte(c)), "%q", c)
	}
}

func TestClassifiersDoNotAllocate(t *testing.T) {
	require.Zero(t, testing.AllocsPerRun(100, func() {
		_ = csiQuery([]byte("\x1b[1;1;1;1;24;80*y"))
		_ = oscQuery([]byte("\x1b]4;0;rgb:00/00/00;1;?"))
		_ = dcsQuery([]byte("\x1bP0;1+q"))
	}))
}

func TestParseCSIParams(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params string
		want   csiParamInfo
	}{
		{"empty", "", csiParamInfo{count: 0, first: 0}},
		{"one", "6", csiParamInfo{count: 1, first: 6}},
		{"two empty ones", ";", csiParamInfo{count: 2, first: 0}},
		{"leading zero", "06;1", csiParamInfo{count: 2, first: 6}},
		{"empty first", ";1", csiParamInfo{count: 2, first: 0}},
		{"trailing empty", "1;", csiParamInfo{count: 2, first: 1}},
		{"zeros then seven", strings.Repeat("0", 40) + "7", csiParamInfo{count: 1, first: 7}},
		{"nines saturate", strings.Repeat("9", 40), csiParamInfo{count: 1, first: 1 << 20}},
		{"only the first saturates", "1;" + strings.Repeat("9", 40), csiParamInfo{count: 2, first: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, parseCSIParams([]byte(tc.params)))
		})
	}

	// Sub-parameters only have to be noticed: no family looks past a ':'.
	for _, params := range []string{"6:1", "38:2::255:0:0", "1;2:3", ":"} {
		require.True(t, parseCSIParams([]byte(params)).sub, "%q", params)
	}
	for _, params := range []string{"", "6", ";", "1;2;3"} {
		require.False(t, parseCSIParams([]byte(params)).sub, "%q", params)
	}
}
