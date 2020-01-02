// Copyright 2014 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ansi provides ansi escape sequence processing as defined by the
// ECMA-48 standard "Control Functions for Coded Character Sets - Fifth Edition"
//
// From the standard:
//
//   Free printed copies of this standard can be ordered from:
//   ECMA
//   114 Rue du Rhône CH-1204 Geneva Switzerland
//   Fax: +41 22 849.60.01 Email: documents@ecma.ch
//   Files of this Standard can be freely downloaded from the ECMA web site
//   (www.ecma.ch). This site gives full information on ECMA, ECMA activities,
//   ECMA Standards and Technical Reports.
//
// Portions of the standared are included in the documentation for this package.
// The standard bears no copyright.
//
// Each escape sequence is represented by a string constant and a Sequence
// structure.  For the escape sequence named SEQ, SEQ is the string constant and
// SEQ_ is the related Sequence structure.  A mapping from a sequence string to
// its Sequence structure is provided in Table.
//
// Some escape sequences may contain parameters, for example "\033[4A".  This
// sequence contains the parameter "4".  The name of the sequences is "\033[A"
// (the parameter is missing).  The sequence "\033[1;2 c" is named "\033[ c" and
// has the parameters "1", and "2".
//
// The C1 control set has both a two byte and a single byte representation.  The
// two byte representation is an Escape followed by a byte in the range of 0x40
// to 0x5f.  They may also be specified by a single byte in the range of 0x80 -
// 0x9f.  This ansi package always names the C1 control set in the two byte
// form.
package ansi

// A Sequence specifies an ANSI (ECMA-48) Escape Sequence.
// If the default value of a parameter is -1 then that parameter must
// be specified (but following parameters may be defaulted).
type Sequence struct {
	Name     string   // Short name of the sequence
	Desc     string   // Description of the sequence
	Notation string   // Notation the sequence uses
	Type     Name     // Prefix type: ESC, CSI or ""
	NParam   int      // Number of parameters (-1 implies any number)
	MinParam int      // Minium number of parameters that must be present
	Defaults []string // Default values of parameters (if any)
	Code     []byte   // Code bytes
}

// A Name is the name of ansi escape sequence.
type Name string

// S returns a reference to the Sequence for n.
func (n Name) S() *Sequence {
	return Table[n]
}

// The remainder of this file was automatically generated from the ECMA-48
// standard.

// ANSI (ECMA-48) Sequences.
// These sequences do not include parameters or string termination sequences.
const (
	NUL    = Name("\000")     // Null
	SOH    = Name("\001")     // Start of Heading
	STX    = Name("\002")     // Start of Text
	ETX    = Name("\003")     // End of Text
	EOT    = Name("\004")     // End of Transmission
	ENQ    = Name("\005")     // Enquiry
	ACK    = Name("\006")     // Acknowledge
	BEL    = Name("\007")     // Bell
	BS     = Name("\010")     // Backspace
	HT     = Name("\011")     // Character Tabulation
	LF     = Name("\012")     // Line Feed
	VT     = Name("\013")     // Line Tabulation
	FF     = Name("\014")     // Form Feed
	CR     = Name("\015")     // Carriage Return
	SO     = Name("\016")     // Shift-Out
	SI     = Name("\017")     // Shift-In
	DLE    = Name("\020")     // Data Link Escape
	DC1    = Name("\021")     // Device Control One
	DC2    = Name("\022")     // Device Control Two
	DC3    = Name("\023")     // Device Control Three
	DC4    = Name("\024")     // Device Control Four
	NAK    = Name("\025")     // Negative Acknowledge
	SYN    = Name("\026")     // Synchronous Idle
	ETB    = Name("\027")     // End of Transmission Block
	CAN    = Name("\030")     // Cancel
	EM     = Name("\031")     // End of Medium
	SUB    = Name("\032")     // Substitute
	ESC    = Name("\033")     // Escape
	IS4    = Name("\034")     // Information Separator Four (FS - File Separator)
	IS3    = Name("\035")     // Information Separator Three (GS - Group Separator)
	IS2    = Name("\036")     // Information Separator Two (RS - Record Separator)
	IS1    = Name("\037")     // Information Separator One (US - Unit Separator)
	APC    = Name("\033_")    // Application Program Command
	BPH    = Name("\033B")    // Break Permitted Here
	CBT    = Name("\033[Z")   // Cursor Backward Tabulation
	CCH    = Name("\033T")    // Cancel Character
	CHA    = Name("\033[G")   // Cursor Character Absolute
	CHT    = Name("\033[I")   // Cursor Forward Tabulation
	CMD    = Name("\033d")    // Coding Method Delimiter
	CNL    = Name("\033[E")   // Cursor Next Line
	CPL    = Name("\033[F")   // Cursor Preceding Line
	CPR    = Name("\033[R")   // Active Position Report
	CSI    = Name("\033[")    // Control Sequence Introducer
	CTC    = Name("\033[W")   // Cursor Tabulation Control
	CUB    = Name("\033[D")   // Cursor Left
	CUD    = Name("\033[B")   // Cursor Down
	CUF    = Name("\033[C")   // Cursor Right
	CUP    = Name("\033[H")   // Cursor Position
	CUU    = Name("\033[A")   // Cursor Up
	CVT    = Name("\033[Y")   // Cursor Line Tabulation
	DA     = Name("\033[c")   // Device Attributes
	DAQ    = Name("\033[o")   // Define Area Qualification
	DCH    = Name("\033[P")   // Delete Character
	DCS    = Name("\033P")    // Device Control String
	DL     = Name("\033[M")   // Delete Line
	DMI    = Name("\033`")    // Disable Manual Input
	DSR    = Name("\033[n")   // Device Status Report
	DTA    = Name("\033[ T")  // Dimension Text Area
	EA     = Name("\033[O")   // Erase in Area
	ECH    = Name("\033[X")   // Erase Character
	ED     = Name("\033[J")   // Erase in Page
	EF     = Name("\033[N")   // Erase in Field
	EL     = Name("\033[K")   // Erase in Line
	EMI    = Name("\033b")    // Enable Manual Input
	EPA    = Name("\033W")    // End of Guarded Area
	ESA    = Name("\033G")    // End of Selected Area
	FNK    = Name("\033[ W")  // Function Key
	FNT    = Name("\033[ D")  // Font Selection
	GCC    = Name("\033[ _")  // Graphic Character Combination
	GSM    = Name("\033[ B")  // Graphic Size Modification
	GSS    = Name("\033[ C")  // Graphic Size Selection
	HPA    = Name("\033[`")   // Character Position Absolute
	HPB    = Name("\033[j")   // Character Position Backward
	HPR    = Name("\033[a")   // Character Position Forward
	HTJ    = Name("\033I")    // Character Tabulation With Justification
	HTS    = Name("\033H")    // Character Tabulation Set
	HVP    = Name("\033[f")   // Character and Line Position
	ICH    = Name("\033[@")   // Insert Character
	IDCS   = Name("\033[ O")  // Identify Device Control String
	IGS    = Name("\033[ M")  // Identify Graphic Subrepertoire
	IL     = Name("\033[L")   // Insert Line
	INT    = Name("\033a")    // Interrupt
	JFY    = Name("\033[ F")  // Justify
	LS1R   = Name("\033~")    // Locking-Shift One Right
	LS2    = Name("\033n")    // Locking-Shift Two
	LS2R   = Name("\033}")    // Locking-Shift Two Right
	LS3    = Name("\033o")    // Locking-Shift Three
	LS3R   = Name("\033|")    // Locking-Shift Three Right
	MC     = Name("\033[i")   // Media Copy
	MW     = Name("\033U")    // Message Waiting
	NBH    = Name("\033C")    // No Break Here
	NEL    = Name("\033E")    // Next Line
	NP     = Name("\033[U")   // Next Page
	OSC    = Name("\033]")    // Operating System Command
	PEC    = Name("\033[ Z")  // Presentation Expand or Contract
	PFS    = Name("\033[ J")  // Page Format Selection
	PLD    = Name("\033K")    // Partial Line Forward
	PLU    = Name("\033L")    // Partial Line Backward
	PM     = Name("\033^")    // Privacy Message
	PP     = Name("\033[V")   // Preceding Page
	PPA    = Name("\033[ P")  // Page Position Absolute
	PPB    = Name("\033[ R")  // Page Position Backward
	PPR    = Name("\033[ Q")  // Page Position Forward
	PTX    = Name("\033[\\")  // Parallel Texts
	PU1    = Name("\033Q")    // Private Use One
	PU2    = Name("\033R")    // Private Use Two
	QUAD   = Name("\033[ H")  // Quad
	REP    = Name("\033[b")   // Repeat
	RI     = Name("\033M")    // Reverse Line Feed
	RIS    = Name("\033c")    // Reset to Initial State
	RM     = Name("\033[l")   // Reset Mode
	SACS   = Name("\033[ \\") // Set Additional Character Separation
	SAPV   = Name("\033[ ]")  // Select Alternative Presentation Variants
	SCI    = Name("\033Z")    // Single Character Introducer
	SCO    = Name("\033[ e")  // Select Character Orientation
	SCP    = Name("\033[ k")  // Select Character Path
	SCS    = Name("\033[ g")  // Set Character Spacing
	SD     = Name("\033[T")   // Scroll Down
	SDS    = Name("\033[]")   // Start Directed String
	SEE    = Name("\033[Q")   // Select Editing Extent
	SEF    = Name("\033[ Y")  // Sheet Eject and Feed
	SGR    = Name("\033[m")   // Select Graphic Rendition
	SHS    = Name("\033[ K")  // Select Character Spacing
	SIMD   = Name("\033[^")   // Select Implicit Movement Direction
	SL     = Name("\033[ @")  // Scroll Left
	SLH    = Name("\033[ U")  // Set Line Home
	SLL    = Name("\033[ V")  // Set Line Limit
	SLS    = Name("\033[ h")  // Set Line Spacing
	SM     = Name("\033[h")   // Set Mode
	SOS    = Name("\033X")    // Start of String
	SPA    = Name("\033V")    // Start of Guarded Area
	SPD    = Name("\033[ S")  // Select Presentation Directions
	SPH    = Name("\033[ i")  // Set Page Home
	SPI    = Name("\033[ G")  // Spacing Increment
	SPL    = Name("\033[ j")  // Set Page Limit
	SPQR   = Name("\033[ X")  // Select Print Quality and Rapidity
	SR     = Name("\033[ A")  // Scroll Right
	SRCS   = Name("\033[ f")  // Set Reduced Character Separation
	SRS    = Name("\033[[")   // Start Reversed String
	SSA    = Name("\033F")    // Start of Selected Area
	SSU    = Name("\033[ I")  // Select Size Unit
	SSW    = Name("\033[ [")  // Set Space Width
	SS2    = Name("\033N")    // Single-Shift Two
	SS3    = Name("\033O")    // Single-Shift Three
	ST     = Name("\033\\")   // String Terminator
	STAB   = Name("\033[ ^")  // Selective Tabulation
	STS    = Name("\033S")    // Set Transmit State
	SU     = Name("\033[S")   // Scroll Up
	SVS    = Name("\033[ L")  // Select Line Spacing
	TAC    = Name("\033[ b")  // Tabulation Aligned Centred
	TALE   = Name("\033[ a")  // Tabulation Aligned Leading Edge
	TATE   = Name("\033[ `")  // Tabulation Aligned Trailing Edge
	TBC    = Name("\033[g")   // Tabulation Clear
	TCC    = Name("\033[ c")  // Tabulation Centred on Character
	TSR    = Name("\033[ d")  // Tabulation Stop Remove
	TSS    = Name("\033[ E")  // Thin Space Specification
	VPA    = Name("\033[d")   // Line Position Absolute
	VPB    = Name("\033[k")   // Line Position Backward
	VPR    = Name("\033[e")   // Line Position Forward
	VTS    = Name("\033J")    // Line Tabulation Set
	C0     = Name("\033!@")   // Control Set 0 Announcer
	C1     = Name("\033&@")   // Control Set 1 Announcer
	C1ALT1 = Name("\033 F")   // Control Set 1 Announcer Alternate 1
	C1ALT2 = Name("\033\"F")  // Control Set 1 Announcer Alternate 2
)

// NUL is used for media-fill or time-fill. NUL characters may be inserted
// into, or removed from, a data stream without affecting the information
// content of that stream, but such action may affect the information layout
// and/or the control of equipment.
var NUL_ = Sequence{
	Name: "NUL",
	Desc: "Null",
	Code: []byte(NUL),
}

// SOH is used to indicate the beginning of a heading.
//
// The use of SOH is defined in ISO 1745.
var SOH_ = Sequence{
	Name: "SOH",
	Desc: "Start of Heading",
	Code: []byte(SOH),
}

// STX is used to indicate the beginning of a text and the end of a heading.
//
// The use of STX is defined in ISO 1745.
var STX_ = Sequence{
	Name: "STX",
	Desc: "Start of Text",
	Code: []byte(STX),
}

// ETX is used to indicate the end of a text.
//
// The use of ETX is defined in ISO 1745.
var ETX_ = Sequence{
	Name: "ETX",
	Desc: "End of Text",
	Code: []byte(ETX),
}

// EOT is used to indicate the conclusion of the transmission of one or more
// texts.
//
// The use of EOT is defined in ISO 1745.
var EOT_ = Sequence{
	Name: "EOT",
	Desc: "End of Transmission",
	Code: []byte(EOT),
}

// ENQ is transmitted by a sender as a request for a response from a receiver.
//
// The use of ENQ is defined in ISO 1745.
var ENQ_ = Sequence{
	Name: "ENQ",
	Desc: "Enquiry",
	Code: []byte(ENQ),
}

// ACK is transmitted by a receiver as an affirmative response to the sender.
//
// The use of ACK is defined in ISO 1745.
var ACK_ = Sequence{
	Name: "ACK",
	Desc: "Acknowledge",
	Code: []byte(ACK),
}

// BEL is used when there is a need to call for attention; it may control alarm
// or attention devices.
var BEL_ = Sequence{
	Name: "BEL",
	Desc: "Bell",
	Code: []byte(BEL),
}

// BS causes the active data position to be moved one character position in the
// data component in the direction opposite to that of the implicit movement.
//
// The direction of the implicit movement depends on the parameter value of
// SELECT IMPLICIT MOVEMENT DIRECTION (SIMD).
var BS_ = Sequence{
	Name: "BS",
	Desc: "Backspace",
	Code: []byte(BS),
}

// HT causes the active presentation position to be moved to the following
// character tabulation stop in the presentation component.
//
// In addition, if that following character tabulation stop has been set by
// TABULATION ALIGN CENTRE (TAC), TABULATION ALIGN LEADING EDGE (TALE),
// TABULATION ALIGN TRAILING EDGE (TATE) or TABULATION CENTRED ON CHARACTER
// (TCC), HT indicates the beginning of a string of text which is to be
// positioned within a line according to the properties of that tabulation
// stop. The end of the string is indicated by the next occurrence of HT or
// CARRIAGE RETURN (CR) or NEXT LINE (NEL) in the data stream.
var HT_ = Sequence{
	Name: "HT",
	Desc: "Character Tabulation",
	Code: []byte(HT),
}

// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to PRESENTATION, LF causes
// the active presentation position to be moved to the corresponding character
// position of the following line in the presentation component.
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to DATA, LF causes the
// active data position to be moved to the corresponding character position of
// the following line in the data component.
var LF_ = Sequence{
	Name: "LF",
	Desc: "Line Feed",
	Code: []byte(LF),
}

// VT causes the active presentation position to be moved in the presentation
// component to the corresponding character position on the line at which the
// following line tabulation stop is set.
var VT_ = Sequence{
	Name: "VT",
	Desc: "Line Tabulation",
	Code: []byte(VT),
}

// FF causes the active presentation position to be moved to the corresponding
// character position of the line at the page home position of the next form or
// page in the presentation component. The page home position is established by
// the parameter value of SET PAGE HOME (SPH).
var FF_ = Sequence{
	Name: "FF",
	Desc: "Form Feed",
	Code: []byte(FF),
}

// The effect of CR depends on the setting of the DEVICE COMPONENT SELECT MODE
// (DCSM) and on the parameter value of SELECT IMPLICIT MOVEMENT DIRECTION
// (SIMD).
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to PRESENTATION and with
// the parameter value of SIMD equal to 0, CR causes the active presentation
// position to be moved to the line home position of the same line in the
// presentation component. The line home position is established by the
// parameter value of SET LINE HOME (SLH).
//
// With a parameter value of SIMD equal to 1, CR causes the active presentation
// position to be moved to the line limit position of the same line in the
// presentation component. The line limit position is established by the
// parameter value of SET LINE LIMIT (SLL).
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to DATA and with a
// parameter value of SIMD equal to 0, CR causes the active data position to be
// moved to the line home position of the same line in the data component. The
// line home position is established by the parameter value of SET LINE HOME
// (SLH).
//
// With a parameter value of SIMD equal to 1, CR causes the active data
// position to be moved to the line limit position of the same line in the data
// component. The line limit position is established by the parameter value of
// SET LINE LIMIT (SLL).
var CR_ = Sequence{
	Name: "CR",
	Desc: "Carriage Return",
	Code: []byte(CR),
}

// SO is used for code extension purposes. It causes the meanings of the bit
// combinations following it in the data stream to be changed.
//
// The use of SO is defined in Standard ECMA-35.
//
// NOTE
//
// SO is used in 7-bit environments only; in 8-bit environments LOCKING-SHIFT
// ONE (LS1) is used instead.
var SO_ = Sequence{
	Name: "SO",
	Desc: "Shift-Out",
	Code: []byte(SO),
}

// SI is used for code extension purposes. It causes the meanings of the bit
// combinations following it in the data stream to be changed.
//
// The use of SI is defined in Standard ECMA-35.
//
// NOTE
//
// SI is used in 7-bit environments only; in 8-bit environments LOCKING-SHIFT
// ZERO (LS0) is used instead.
var SI_ = Sequence{
	Name: "SI",
	Desc: "Shift-In",
	Code: []byte(SI),
}

// DLE is used exclusively to provide supplementary transmission control
// functions.
//
// The use of DLE is defined in ISO 1745.
var DLE_ = Sequence{
	Name: "DLE",
	Desc: "Data Link Escape",
	Code: []byte(DLE),
}

// DC1 is primarily intended for turning on or starting an ancillary device. If
// it is not required for this purpose, it may be used to restore a device to
// the basic mode of operation (see also DC2 and DC3), or any other device
// control function not provided by other DCs.
//
// NOTE
//
// When used for data flow control, DC1 is sometimes called "X-ON".
var DC1_ = Sequence{
	Name: "DC1",
	Desc: "Device Control One",
	Code: []byte(DC1),
}

// DC2 is primarily intended for turning on or starting an ancillary device. If
// it is not required for this purpose, it may be used to set a device to a
// special mode of operation (in which case DC1 is used to restore the device
// to the basic mode), or for any other device control function not provided by
// other DCs.
var DC2_ = Sequence{
	Name: "DC2",
	Desc: "Device Control Two",
	Code: []byte(DC2),
}

// DC3 is primarily intended for turning off or stopping an ancillary device.
// This function may be a secondary level stop, for example wait, pause,
// stand-by or halt (in which case DC1 is used to restore normal operation). If
// it is not required for this purpose, it may be used for any other device
// control function not provided by other DCs.
//
// NOTE
//
// When used for data flow control, DC3 is sometimes called "X-OFF".
var DC3_ = Sequence{
	Name: "DC3",
	Desc: "Device Control Three",
	Code: []byte(DC3),
}

// DC4 is primarily intended for turning off, stopping or interrupting an
// ancillary device. If it is not required for this purpose, it may be used for
// any other device control function not provided by other DCs.
var DC4_ = Sequence{
	Name: "DC4",
	Desc: "Device Control Four",
	Code: []byte(DC4),
}

// NAK is transmitted by a receiver as a negative response to the sender.
//
// The use of NAK is defined in ISO 1745.
var NAK_ = Sequence{
	Name: "NAK",
	Desc: "Negative Acknowledge",
	Code: []byte(NAK),
}

// SYN is used by a synchronous transmission system in the absence of any other
// character (idle condition) to provide a signal from which synchronism may be
// achieved or retained between data terminal equipment.
//
// The use of SYN is defined in ISO 1745.
var SYN_ = Sequence{
	Name: "SYN",
	Desc: "Synchronous Idle",
	Code: []byte(SYN),
}

// ETB is used to indicate the end of a block of data where the data are
// divided into such blocks for transmission purposes.
//
// The use of ETB is defined in ISO 1745.
var ETB_ = Sequence{
	Name: "ETB",
	Desc: "End of Transmission Block",
	Code: []byte(ETB),
}

// CAN is used to indicate that the data preceding it in the data stream is in
// error. As a result, this data shall be ignored. The specific meaning of this
// control function shall be defined for each application and/or between sender
// and recipient.
var CAN_ = Sequence{
	Name: "CAN",
	Desc: "Cancel",
	Code: []byte(CAN),
}

// EM is used to identify the physical end of a medium, or the end of the used
// portion of a medium, or the end of the wanted portion of data recorded on a
// medium.
var EM_ = Sequence{
	Name: "EM",
	Desc: "End of Medium",
	Code: []byte(EM),
}

// SUB is used in the place of a character that has been found to be invalid or
// in error. SUB is intended to be introduced by automatic means.
var SUB_ = Sequence{
	Name: "SUB",
	Desc: "Substitute",
	Code: []byte(SUB),
}

// ESC is used for code extension purposes. It causes the meanings of a limited
// number of bit combinations following it in the data stream to be changed.
//
// The use of ESC is defined in Standard ECMA-35.
var ESC_ = Sequence{
	Name: "ESC",
	Desc: "Escape",
	Code: []byte(ESC),
}

// IS4 is used to separate and qualify data logically; its specific meaning has
// to be defined for each application. If this control function is used in
// hierarchical order, it may delimit a data item called a file, see 8.2.10.
var IS4_ = Sequence{
	Name: "IS4",
	Desc: "Information Separator Four (FS - File Separator)",
	Code: []byte(IS4),
}

// IS3 is used to separate and qualify data logically; its specific meaning has
// to be defined for each application. If this control function is used in
// hierarchical order, it may delimit a data item called a group, see 8.2.10.
var IS3_ = Sequence{
	Name: "IS3",
	Desc: "Information Separator Three (GS - Group Separator)",
	Code: []byte(IS3),
}

// IS2 is used to separate and qualify data logically; its specific meaning has
// to be defined for each application. If this control function is used in
// hierarchical order, it may delimit a data item called a record, see 8.2.10.
var IS2_ = Sequence{
	Name: "IS2",
	Desc: "Information Separator Two (RS - Record Separator)",
	Code: []byte(IS2),
}

// IS1 is used to separate and qualify data logically; its specific meaning has
// to be defined for each application. If this control function is used in
// hierarchical order, it may delimit a data item called a unit, see 8.2.10.
var IS1_ = Sequence{
	Name: "IS1",
	Desc: "Information Separator One (US - Unit Separator)",
	Code: []byte(IS1),
}

// APC is used as the opening delimiter of a control string for application
// program use. The command string following may consist of bit combinations in
// the range 00/08 to 00/13 and 02/00 to 07/14. The control string is closed by
// the terminating delimiter STRING TERMINATOR (ST). The interpretation of the
// command string depends on the relevant application program.
var APC_ = Sequence{
	Name: "APC",
	Desc: "Application Program Command",
	Type: ESC,
	Code: []byte{'_'},
}

// BPH is used to indicate a point where a line break may occur when text is
// formatted. BPH may occur between two graphic characters, either or both of
// which may be SPACE.
var BPH_ = Sequence{
	Name: "BPH",
	Desc: "Break Permitted Here",
	Type: ESC,
	Code: []byte{'B'},
}

// CBT causes the active presentation position to be moved to the character
// position corresponding to the n-th preceding character tabulation stop in
// the presentation component, according to the character path, where n equals
// the value of Pn.
var CBT_ = Sequence{
	Name:     "CBT",
	Desc:     "Cursor Backward Tabulation",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'Z'},
}

// CCH is used to indicate that both the preceding graphic character in the
// data stream, (represented by one or more bit combinations) including SPACE,
// and the control function CCH itself are to be ignored for further
// interpretation of the data stream.
//
// If the character preceding CCH in the data stream is a control function
// (represented by one or more bit combinations), the effect of CCH is not
// defined by this Standard.
var CCH_ = Sequence{
	Name: "CCH",
	Desc: "Cancel Character",
	Type: ESC,
	Code: []byte{'T'},
}

// CHA causes the active presentation position to be moved to character
// position n in the active line in the presentation component, where n equals
// the value of Pn.
var CHA_ = Sequence{
	Name:     "CHA",
	Desc:     "Cursor Character Absolute",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'G'},
}

// CHT causes the active presentation position to be moved to the character
// position corresponding to the n-th following character tabulation stop in
// the presentation component, according to the character path, where n equals
// the value of Pn.
var CHT_ = Sequence{
	Name:     "CHT",
	Desc:     "Cursor Forward Tabulation",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'I'},
}

// CMD is used as the delimiter of a string of data coded according to Standard
// ECMA-35 and to switch to a general level of control.
//
// The use of CMD is not mandatory if the higher level protocol defines means
// of delimiting the string, for instance, by specifying the length of the
// string.
var CMD_ = Sequence{
	Name: "CMD",
	Desc: "Coding Method Delimiter",
	Type: ESC,
	Code: []byte{'d'},
}

// CNL causes the active presentation position to be moved to the first
// character position of the n-th following line in the presentation component,
// where n equals the value of Pn.
var CNL_ = Sequence{
	Name:     "CNL",
	Desc:     "Cursor Next Line",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'E'},
}

// CPL causes the active presentation position to be moved to the first
// character position of the n-th preceding line in the presentation component,
// where n equals the value of Pn.
var CPL_ = Sequence{
	Name:     "CPL",
	Desc:     "Cursor Preceding Line",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'F'},
}

// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to PRESENTATION, CPR is
// used to report the active presentation position of the sending device as
// residing in the presentation component at the n-th line position according
// to the line progression and at the m-th character position according to the
// character path, where n equals the value of Pn1 and m equals the value of
// Pn2.
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to DATA, CPR is used to
// report the active data position of the sending device as residing in the
// data component at the n-th line position according to the line progression
// and at the m-th character position according to the character progression,
// where n equals the value of Pn1 and m equals the value of Pn2.
//
// CPR may be solicited by a DEVICE STATUS REPORT (DSR) or be sent unsolicited.
var CPR_ = Sequence{
	Name:     "CPR",
	Desc:     "Active Position Report",
	Type:     CSI,
	Notation: "Pn1;Pn2",
	NParam:   2,
	Defaults: []string{"1", "1"},
	Code:     []byte{'R'},
}

// CSI is used as the first character of a control sequence, see 5.4.
var CSI_ = Sequence{
	Name: "CSI",
	Desc: "Control Sequence Introducer",
	Type: ESC,
	Code: []byte{'['},
}

// CTC causes one or more tabulation stops to be set or cleared in the
// presentation component, depending on the parameter values:
//
// 0 a character tabulation stop is set at the active presentation position
//
// 1 a line tabulation stop is set at the active line (the line that contains
// the active presentation position)
//
// 2 the character tabulation stop at the active presentation position is
// cleared
//
// 3 the line tabulation stop at the active line is cleared
//
// 4 all character tabulation stops in the active line are cleared
//
// 5 all character tabulation stops are cleared
//
// 6 all line tabulation stops are cleared
//
// In the case of parameter values 0, 2 or 4 the number of lines affected
// depends on the setting of the TABULATION STOP MODE (TSM).
var CTC_ = Sequence{
	Name:     "CTC",
	Desc:     "Cursor Tabulation Control",
	Type:     CSI,
	Notation: "Ps...",
	NParam:   -1,
	Defaults: []string{"0"},
	Code:     []byte{'W'},
}

// CUB causes the active presentation position to be moved leftwards in the
// presentation component by n character positions if the character path is
// horizontal, or by n line positions if the character path is vertical, where
// n equals the value of Pn.
var CUB_ = Sequence{
	Name:     "CUB",
	Desc:     "Cursor Left",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'D'},
}

// CUD causes the active presentation position to be moved downwards in the
// presentation component by n line positions if the character path is
// horizontal, or by n character positions if the character path is vertical,
// where n equals the value of Pn.
var CUD_ = Sequence{
	Name:     "CUD",
	Desc:     "Cursor Down",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'B'},
}

// CUF causes the active presentation position to be moved rightwards in the
// presentation component by n character positions if the character path is
// horizontal, or by n line positions if the character path is vertical, where
// n equals the value of Pn.
var CUF_ = Sequence{
	Name:     "CUF",
	Desc:     "Cursor Right",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'C'},
}

// CUP causes the active presentation position to be moved in the presentation
// component to the n-th line position according to the line progression and to
// the m-th character position according to the character path, where n equals
// the value of Pn1 and m equals the value of Pn2.
var CUP_ = Sequence{
	Name:     "CUP",
	Desc:     "Cursor Position",
	Type:     CSI,
	Notation: "Pn1;Pn2",
	NParam:   2,
	Defaults: []string{"1", "1"},
	Code:     []byte{'H'},
}

// CUU causes the active presentation position to be moved upwards in the
// presentation component by n line positions if the character path is
// horizontal, or by n character positions if the character path is vertical,
// where n equals the value of Pn.
var CUU_ = Sequence{
	Name:     "CUU",
	Desc:     "Cursor Up",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'A'},
}

// CVT causes the active presentation position to be moved to the corresponding
// character position of the line corresponding to the n-th following line
// tabulation stop in the presentation component, where n equals the value of
// Pn.
var CVT_ = Sequence{
	Name:     "CVT",
	Desc:     "Cursor Line Tabulation",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'Y'},
}

// With a parameter value not equal to 0, DA is used to identify the device
// which sends the DA. The parameter value is a device type identification code
// according to a register which is to be established. If the parameter value
// is 0, DA is used to request an identifying DA from a device.
var DA_ = Sequence{
	Name:     "DA",
	Desc:     "Device Attributes",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{'c'},
}

// DAQ is used to indicate that the active presentation position in the
// presentation component is the first character position of a qualified area.
// The last character position of the qualified area is the character position
// in the presentation component immediately preceding the first character
// position of the following qualified area.
//
// The parameter value designates the type of qualified area:
//
// 0 unprotected and unguarded
//
// 1 protected and guarded
//
// 2 graphic character input
//
// 3 numeric input
//
// 4 alphabetic input
//
// 5 input aligned on the last character position of the qualified area
//
// 6 fill with ZEROs
//
// 7 set a character tabulation stop at the active presentation position (the
// first character position of the qualified area) to indicate the beginning of
// a field
//
// 8 protected and unguarded
//
// 9 fill with SPACEs
//
// 10 input aligned on the first character position of the qualified area
//
// 11 the order of the character positions in the input field is reversed, i.e.
// the last position in each line becomes the first and vice versa; input
// begins at the new first position.
//
// This control function operates independently of the setting of the
// TABULATION STOP MODE (TSM). The character tabulation stop set by parameter
// value 7 applies to the active line only.
//
// NOTE
//
// The control functions for area definition (DAQ, EPA, ESA, SPA, SSA) should
// not be used within an SRS string or an SDS string.
var DAQ_ = Sequence{
	Name:     "DAQ",
	Desc:     "Define Area Qualification",
	Type:     CSI,
	Notation: "Ps...",
	NParam:   -1,
	Defaults: []string{"0"},
	Code:     []byte{'o'},
}

// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to PRESENTATION, DCH
// causes the contents of the active presentation position and, depending on
// the setting of the CHARACTER EDITING MODE (HEM), the contents of the n-1
// preceding or following character positions to be removed from the
// presentation component, where n equals the value of Pn. The resulting gap is
// closed by shifting the contents of the adjacent character positions towards
// the active presentation position. At the other end of the shifted part, n
// character positions are put into the erased state.
//
// The extent of the shifted part is established by SELECT EDITING EXTENT (SEE).
//
// The effect of DCH on the start or end of a selected area, the start or end
// of a qualified area, or a tabulation stop in the shifted part is not defined
// by this Standard.
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to DATA, DCH causes the
// contents of the active data position and, depending on the setting of the
// CHARACTER EDITING MODE (HEM), the contents of the n-1 preceding or following
// character positions to be removed from the data component, where n equals
// the value of Pn. The resulting gap is closed by shifting the contents of the
// adjacent character positions towards the active data position. At the other
// end of the shifted part, n character positions are put into the erased state.
var DCH_ = Sequence{
	Name:     "DCH",
	Desc:     "Delete Character",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'P'},
}

// DCS is used as the opening delimiter of a control string for device control
// use. The command string following may consist of bit combinations in the
// range 00/08 to 00/13 and 02/00 to 07/14. The control string is closed by the
// terminating delimiter STRING TERMINATOR (ST).
//
// The command string represents either one or more commands for the receiving
// device, or one or more status reports from the sending device. The purpose
// and the format of the command string are specified by the most recent
// occurrence of IDENTIFY DEVICE CONTROL STRING (IDCS), if any, or depend on
// the sending and/or the receiving device.
var DCS_ = Sequence{
	Name: "DCS",
	Desc: "Device Control String",
	Type: ESC,
	Code: []byte{'P'},
}

// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to PRESENTATION, DL causes
// the contents of the active line (the line that contains the active
// presentation position) and, depending on the setting of the LINE EDITING
// MODE (VEM), the contents of the n-1 preceding or following lines to be
// removed from the presentation component, where n equals the value of Pn. The
// resulting gap is closed by shifting the contents of a number of adjacent
// lines towards the active line. At the other end of the shifted part, n lines
// are put into the erased state.
//
// The active presentation position is moved to the line home position in the
// active line. The line home position is established by the parameter value of
// SET LINE HOME (SLH). If the TABULATION STOP MODE (TSM) is set to SINGLE,
// character tabulation stops are cleared in the lines that are put into the
// erased state.
//
// The extent of the shifted part is established by SELECT EDITING EXTENT (SEE).
//
// Any occurrences of the start or end of a selected area, the start or end of
// a qualified area, or a tabulation stop in the shifted part, are also shifted.
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to DATA, DL causes the
// contents of the active line (the line that contains the active data
// position) and, depending on the setting of the LINE EDITING MODE (VEM), the
// contents of the n-1 preceding or following lines to be removed from the data
// component, where n equals the value of Pn. The resulting gap is closed by
// shifting the contents of a number of adjacent lines towards the active line.
// At the other end of the shifted part, n lines are put into the erased state.
// The active data position is moved to the line home position in the active
// line. The line home position is established by the parameter value of SET
// LINE HOME (SLH).
var DL_ = Sequence{
	Name:     "DL",
	Desc:     "Delete Line",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'M'},
}

// DMI causes the manual input facilities of a device to be disabled.
var DMI_ = Sequence{
	Name: "DMI",
	Desc: "Disable Manual Input",
	Type: ESC,
	Code: []byte{'`'},
}

// DSR is used either to report the status of the sending device or to request
// a status report from the receiving device, depending on the parameter values:
//
// 0 ready, no malfunction detected
//
// 1 busy, another DSR must be requested later
//
// 2 busy, another DSR will be sent later
//
// 3 some malfunction detected, another DSR must be requested later
//
// 4 some malfunction detected, another DSR will be sent later
//
// 5 a DSR is requested
//
// 6 a report of the active presentation position or of the active data
// position in the form of ACTIVE POSITION REPORT (CPR) is requested
//
// DSR with parameter value 0, 1, 2, 3 or 4 may be sent either unsolicited or
// as a response to a request such as a DSR with a parameter value 5 or MESSAGE
// WAITING (MW).
var DSR_ = Sequence{
	Name:     "DSR",
	Desc:     "Device Status Report",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{'n'},
}

// DTA is used to establish the dimensions of the text area for subsequent
// pages.
//
// The established dimensions remain in effect until the next occurrence of DTA
// in the data stream.
//
// Pn1 specifies the dimension in the direction perpendicular to the line
// orientation
//
// Pn2 specifies the dimension in the direction parallel to the line orientation
//
// The unit in which the parameter value is expressed is that established by
// the parameter value of SELECT SIZE UNIT (SSU).
var DTA_ = Sequence{
	Name:     "DTA",
	Desc:     "Dimension Text Area",
	Type:     CSI,
	Notation: "Pn1;Pn2",
	NParam:   2,
	MinParam: 2,
	Code:     []byte{' ', 'T'},
}

// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to PRESENTATION, EA causes
// some or all character positions in the active qualified area (the qualified
// area in the presentation component which contains the active presentation
// position) to be put into the erased state, depending on the parameter values:
//
// 0 the active presentation position and the character positions up to the end
// of the qualified area are put into the erased state
//
// 1 the character positions from the beginning of the qualified area up to and
// including the active presentation position are put into the erased state
//
// 2 all character positions of the qualified area are put into the erased state
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to DATA, EA causes some or
// all character positions in the active qualified area (the qualified area in
// the data component which contains the active data position) to be put into
// the erased state, depending on the parameter values:
//
// 0 the active data position and the character positions up to the end of the
// qualified area are put into the erased state
//
// 1 the character positions from the beginning of the qualified area up to and
// including the active data position are put into the erased state
//
// 2 all character positions of the qualified area are put into the erased state
//
// Whether the character positions of protected areas are put into the erased
// state, or the character positions of unprotected areas only, depends on the
// setting of the ERASURE MODE (ERM).
var EA_ = Sequence{
	Name:     "EA",
	Desc:     "Erase in Area",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{'O'},
}

// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to PRESENTATION, ECH
// causes the active presentation position and the n-1 following character
// positions in the presentation component to be put into the erased state,
// where n equals the value of Pn.
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to DATA, ECH causes the
// active data position and the n-1 following character positions in the data
// component to be put into the erased state, where n equals the value of Pn.
//
// Whether the character positions of protected areas are put into the erased
// state, or the character positions of unprotected areas only, depends on the
// setting of the ERASURE MODE (ERM).
var ECH_ = Sequence{
	Name:     "ECH",
	Desc:     "Erase Character",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'X'},
}

// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to PRESENTATION, ED causes
// some or all character positions of the active page (the page which contains
// the active presentation position in the presentation component) to be put
// into the erased state, depending on the parameter values:
//
// 0 the active presentation position and the character positions up to the end
// of the page are put into the erased state
//
// 1 the character positions from the beginning of the page up to and including
// the active presentation position are put into the erased state
//
// 2 all character positions of the page are put into the erased state
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to DATA, ED causes some or
// all character positions of the active page (the page which contains the
// active data position in the data component) to be put into the erased state,
// depending on the parameter values:
//
// 0 the active data position and the character positions up to the end of the
// page are put into the erased state
//
// 1 the character positions from the beginning of the page up to and including
// the active data position are put into the erased state
//
// 2 all character positions of the page are put into the erased state
//
// Whether the character positions of protected areas are put into the erased
// state, or the character positions of unprotected areas only, depends on the
// setting of the ERASURE MODE (ERM).
var ED_ = Sequence{
	Name:     "ED",
	Desc:     "Erase in Page",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{'J'},
}

// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to PRESENTATION, EF causes
// some or all character positions of the active field (the field which
// contains the active presentation position in the presentation component) to
// be put into the erased state, depending on the parameter values:
//
// 0 the active presentation position and the character positions up to the end
// of the field are put into the erased state
//
// 1 the character positions from the beginning of the field up to and
// including the active presentation position are put into the erased state
//
// 2 all character positions of the field are put into the erased state
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to DATA, EF causes some or
// all character positions of the active field (the field which contains the
// active data position in the data component) to be put into the erased state,
// depending on the parameter values:
//
// 0 the active data position and the character positions up to the end of the
// field are put into the erased state
//
// 1 the character positions from the beginning of the field up to and
// including the active data position are put into the erased state
//
// 2 all character positions of the field are put into the erased state
//
// Whether the character positions of protected areas are put into the erased
// state, or the character positions of unprotected areas only, depends on the
// setting of the ERASURE MODE (ERM).
var EF_ = Sequence{
	Name:     "EF",
	Desc:     "Erase in Field",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{'N'},
}

// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to PRESENTATION, EL causes
// some or all character positions of the active line (the line which contains
// the active presentation position in the presentation component) to be put
// into the erased state, depending on the parameter values:
//
// 0 the active presentation position and the character positions up to the end
// of the line are put into the erased state
//
// 1 the character positions from the beginning of the line up to and including
// the active presentation position are put into the erased state
//
// 2 all character positions of the line are put into the erased state
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to DATA, EL causes some or
// all character positions of the active line (the line which contains the
// active data position in the data component) to be put into the erased state,
// depending on the parameter values:
//
// 0 the active data position and the character positions up to the end of the
// line are put into the erased state
//
// 1 the character positions from the beginning of the line up to and including
// the active data position are put into the erased state
//
// 2 all character positions of the line are put into the erased state
//
// Whether the character positions of protected areas are put into the erased
// state, or the character positions of unprotected areas only, depends on the
// setting of the ERASURE MODE (ERM).
var EL_ = Sequence{
	Name:     "EL",
	Desc:     "Erase in Line",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{'K'},
}

// EMI is used to enable the manual input facilities of a device.
var EMI_ = Sequence{
	Name: "EMI",
	Desc: "Enable Manual Input",
	Type: ESC,
	Code: []byte{'b'},
}

// EPA is used to indicate that the active presentation position is the last of
// a string of character positions in the presentation component, the contents
// of which are protected against manual alteration, are guarded against
// transmission or transfer, depending on the setting of the GUARDED AREA
// TRANSFER MODE (GATM), and may be protected against erasure, depending on the
// setting of the ERASURE MODE (ERM). The beginning of this string is indicated
// by START OF GUARDED AREA (SPA).
//
// NOTE
//
// The control functions for area definition (DAQ, EPA, ESA, SPA, SSA) should
// not be used within an SRS string or an SDS string.
var EPA_ = Sequence{
	Name: "EPA",
	Desc: "End of Guarded Area",
	Type: ESC,
	Code: []byte{'W'},
}

// ESA is used to indicate that the active presentation position is the last of
// a string of character positions in the presentation component, the contents
// of which are eligible to be transmitted in the form of a data stream or
// transferred to an auxiliary input/output device. The beginning of this
// string is indicated by START OF SELECTED AREA (SSA).
//
// NOTE
//
// The control function for area definition (DAQ, EPA, ESA, SPA, SSA) should
// not be used within an SRS string or an SDS string.
var ESA_ = Sequence{
	Name: "ESA",
	Desc: "End of Selected Area",
	Type: ESC,
	Code: []byte{'G'},
}

// FNK is a control function in which the parameter value identifies the
// function key which has been operated.
var FNK_ = Sequence{
	Name:     "FNK",
	Desc:     "Function Key",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', 'W'},
}

// FNT is used to identify the character font to be selected as primary or
// alternative font by subsequent occurrences of SELECT GRAPHIC RENDITION (SGR)
// in the data stream. Ps1 specifies the primary or alternative font concerned:
//
// 0 primary font
//
// 1 first alternative font
//
// 2 second alternative font
//
// 3 third alternative font
//
// 4 fourth alternative font
//
// 5 fifth alternative font
//
// 6 sixth alternative font
//
// 7 seventh alternative font
//
// 8 eighth alternative font
//
// 9 ninth alternative font
//
// Ps2 identifies the character font according to a register which is to be
// established.
var FNT_ = Sequence{
	Name:     "FNT",
	Desc:     "Font Selection",
	Type:     CSI,
	Notation: "Ps1;Ps2",
	NParam:   2,
	Defaults: []string{"0", "0"},
	Code:     []byte{' ', 'D'},
}

// GCC is used to indicate that two or more graphic characters are to be imaged
// as one single graphic symbol. GCC with a parameter value of 0 indicates that
// the following two graphic characters are to be imaged as one single graphic
// symbol; GCC with a parameter value of 1 and GCC with a parameter value of 2
// indicate respectively the beginning and the end of a string of graphic
// characters which are to be imaged as one single graphic symbol.
//
// NOTE
//
// GCC does not explicitly specify the relative sizes or placements of the
// component parts of a composite graphic symbol. In the simplest case, two
// components may be "half-width" and side-by-side. For
//
// example, in Japanese text a pair of characters may be presented
// side-by-side, and occupy the space of a normal-size Kanji character.
var GCC_ = Sequence{
	Name:     "GCC",
	Desc:     "Graphic Character Combination",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{' ', '_'},
}

// GSM is used to modify for subsequent text the height and/or the width of all
// primary and alternative fonts identified by FONT SELECTION (FNT) and
// established by GRAPHIC SIZE SELECTION (GSS). The established values remain
// in effect until the next occurrence of GSM or GSS in the data steam.
//
// Pn1 specifies the height as a percentage of the height established by GSS
//
// Pn2 specifies the width as a percentage of the width established by GSS
var GSM_ = Sequence{
	Name:     "GSM",
	Desc:     "Graphic Size Modification",
	Type:     CSI,
	Notation: "Pn1;Pn2",
	NParam:   2,
	Defaults: []string{"100", "100"},
	Code:     []byte{' ', 'B'},
}

// GSS is used to establish for subsequent text the height and the width of all
// primary and alternative fonts identified by FONT SELECTION (FNT). The
// established values remain in effect until the next occurrence of GSS in the
// data stream.
//
// Pn specifies the height, the width is implicitly defined by the height.
//
// The unit in which the parameter value is expressed is that established by
// the parameter value of SELECT SIZE UNIT (SSU).
var GSS_ = Sequence{
	Name:     "GSS",
	Desc:     "Graphic Size Selection",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', 'C'},
}

// HPA causes the active data position to be moved to character position n in
// the active line (the line in the data component that contains the active
// data position), where n equals the value of Pn.
var HPA_ = Sequence{
	Name:     "HPA",
	Desc:     "Character Position Absolute",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'`'},
}

// HPB causes the active data position to be moved by n character positions in
// the data component in the direction opposite to that of the character
// progression, where n equals the value of Pn.
var HPB_ = Sequence{
	Name:     "HPB",
	Desc:     "Character Position Backward",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'j'},
}

// HPR causes the active data position to be moved by n character positions in
// the data component in the direction of the character progression, where n
// equals the value of Pn.
var HPR_ = Sequence{
	Name:     "HPR",
	Desc:     "Character Position Forward",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'a'},
}

// HTJ causes the contents of the active field (the field in the presentation
// component that contains the active presentation position) to be shifted
// forward so that it ends at the character position preceding the following
// character tabulation stop. The active presentation position is moved to that
// following character tabulation stop. The character positions which precede
// the beginning of the shifted string are put into the erased state.
var HTJ_ = Sequence{
	Name: "HTJ",
	Desc: "Character Tabulation With Justification",
	Type: ESC,
	Code: []byte{'I'},
}

// HTS causes a character tabulation stop to be set at the active presentation
// position in the presentation component.
//
// The number of lines affected depends on the setting of the TABULATION STOP
// MODE (TSM).
var HTS_ = Sequence{
	Name: "HTS",
	Desc: "Character Tabulation Set",
	Type: ESC,
	Code: []byte{'H'},
}

// HVP causes the active data position to be moved in the data component to the
// n-th line position according to the line progression and to the m-th
// character position according to the character progression, where n equals
// the value of Pn1 and m equals the value of Pn2.
var HVP_ = Sequence{
	Name:     "HVP",
	Desc:     "Character and Line Position",
	Type:     CSI,
	Notation: "Pn1;Pn2",
	NParam:   2,
	Defaults: []string{"1", "1"},
	Code:     []byte{'f'},
}

// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to PRESENTATION, ICH is
// used to prepare the insertion of n characters, by putting into the erased
// state the active presentation position and, depending on the setting of the
// CHARACTER EDITING MODE (HEM), the n-1 preceding or following character
// positions in the presentation component, where n equals the value of Pn. The
// previous contents of the active presentation position and an adjacent string
// of character positions are shifted away from the active presentation
// position. The contents of n character positions at the other end of the
// shifted part are removed. The active presentation position is moved to the
// line home position in the active line. The line home position is established
// by the parameter value of SET LINE HOME (SLH).
//
// The extent of the shifted part is established by SELECT EDITING EXTENT (SEE).
//
// The effect of ICH on the start or end of a selected area, the start or end
// of a qualified area, or a tabulation stop in the shifted part, is not
// defined by this Standard.
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to DATA, ICH is used to
// prepare the insertion of n characters, by putting into the erased state the
// active data position and, depending on the setting of the CHARACTER EDITING
// MODE (HEM), the n-1 preceding or following character positions in the data
// component, where n equals the value of Pn. The previous contents of the
// active data position and an adjacent string of character positions are
// shifted away from the active data position. The contents of n character
// positions at the other end of the shifted part are removed. The active data
//
// position is moved to the line home position in the active line. The line
// home position is established by the parameter value of SET LINE HOME (SLH).
var ICH_ = Sequence{
	Name:     "ICH",
	Desc:     "Insert Character",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'@'},
}

// IDCS is used to specify the purpose and format of the command string of
// subsequent DEVICE CONTROL STRINGs (DCS). The specified purpose and format
// remain in effect until the next occurrence of IDCS in the data stream.
//
// The parameter values are
//
// 1 reserved for use with the DIAGNOSTIC state of the STATUS REPORT TRANSFER
// MODE (SRTM)
//
// 2 reserved for Dynamically Redefinable Character Sets (DRCS) according to
// Standard ECMA-35.
//
// The format and interpretation of the command string corresponding to these
// parameter values are to be defined in appropriate standards. If this control
// function is used to identify a private command string, a private parameter
// value shall be used.
var IDCS_ = Sequence{
	Name:     "IDCS",
	Desc:     "Identify Device Control String",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', 'O'},
}

// IGS is used to indicate that a repertoire of the graphic characters of
// ISO/IEC 10367 is used in the subsequent text.
//
// The parameter value of IGS identifies a graphic character repertoire
// registered in accordance with ISO/IEC 7350.
var IGS_ = Sequence{
	Name:     "IGS",
	Desc:     "Identify Graphic Subrepertoire",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', 'M'},
}

// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to PRESENTATION, IL is
// used to prepare the insertion of n lines, by putting into the erased state
// in the presentation component the active line (the line that contains the
// active presentation position) and, depending on the setting of the LINE
// EDITING MODE (VEM), the n-1 preceding or following lines, where n equals the
// value of Pn. The previous contents of the active line and of adjacent lines
// are shifted away from the active line. The contents of n lines at the other
// end of the shifted part are removed. The active presentation position is
// moved to the line home position in the active line. The line home position
// is established by the parameter value of SET LINE HOME (SLH).
//
// The extent of the shifted part is established by SELECT EDITING EXTENT (SEE).
//
// Any occurrences of the start or end of a selected area, the start or end of
// a qualified area, or a tabulation stop in the shifted part, are also shifted.
//
// If the TABULATION STOP MODE (TSM) is set to SINGLE, character tabulation
// stops are cleared in the lines that are put into the erased state.
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to DATA, IL is used to
// prepare the insertion of n lines, by putting into the erased state in the
// data component the active line (the line that contains the active data
// position) and, depending on the setting of the LINE EDITING MODE (VEM), the
// n-1 preceding or following lines, where n equals the value of Pn. The
// previous contents of the active line and of adjacent lines are shifted away
// from the active line. The contents of n lines at the other end of the
// shifted part are removed. The active data position is moved to the line home
// position in the active line. The line home position is established by the
// parameter value of SET LINE HOME (SLH).
var IL_ = Sequence{
	Name:     "IL",
	Desc:     "Insert Line",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'L'},
}

// INT is used to indicate to the receiving device that the current process is
// to be interrupted and an agreed procedure is to be initiated. This control
// function is applicable to either direction of transmission.
var INT_ = Sequence{
	Name: "INT",
	Desc: "Interrupt",
	Type: ESC,
	Code: []byte{'a'},
}

// JFY is used to indicate the beginning of a string of graphic characters in
// the presentation component that are to be justified according to the layout
// specified by the parameter values, see annex C:
//
// 0 no justification, end of justification of preceding text
//
// 1 word fill
//
// 2 word space
//
// 3 letter space
//
// 4 hyphenation
//
// 5 flush to line home position margin
//
// 6 centre between line home position and line limit position margins
//
// 7 flush to line limit position margin
//
// 8 Italian hyphenation
//
// The end of the string to be justified is indicated by the next occurrence of
// JFY in the data stream.
//
// The line home position is established by the parameter value of SET LINE
// HOME (SLH). The line limit position is established by the parameter value of
// SET LINE LIMIT (SLL).
var JFY_ = Sequence{
	Name:     "JFY",
	Desc:     "Justify",
	Type:     CSI,
	Notation: "Ps...",
	NParam:   -1,
	Defaults: []string{"0"},
	Code:     []byte{' ', 'F'},
}

// LS1R is used for code extension purposes. It causes the meanings of the bit
// combinations following it in the data stream to be changed.
//
// The use of LS1R is defined in Standard ECMA-35.
var LS1R_ = Sequence{
	Name: "LS1R",
	Desc: "Locking-Shift One Right",
	Type: ESC,
	Code: []byte{'~'},
}

// LS2 is used for code extension purposes. It causes the meanings of the bit
// combinations following it in the data stream to be changed.
//
// The use of LS2 is defined in Standard ECMA-35.
var LS2_ = Sequence{
	Name: "LS2",
	Desc: "Locking-Shift Two",
	Type: ESC,
	Code: []byte{'n'},
}

// LS2R is used for code extension purposes. It causes the meanings of the bit
// combinations following it in the data stream to be changed.
//
// The use of LS2R is defined in Standard ECMA-35.
var LS2R_ = Sequence{
	Name: "LS2R",
	Desc: "Locking-Shift Two Right",
	Type: ESC,
	Code: []byte{'}'},
}

// LS3 is used for code extension purposes. It causes the meanings of the bit
// combinations following it in the data stream to be changed.
//
// The use of LS3 is defined in Standard ECMA-35.
var LS3_ = Sequence{
	Name: "LS3",
	Desc: "Locking-Shift Three",
	Type: ESC,
	Code: []byte{'o'},
}

// LS3R is used for code extension purposes. It causes the meanings of the bit
// combinations following it in the data stream to be changed.
//
// The use of LS3R is defined in Standard ECMA-35.
var LS3R_ = Sequence{
	Name: "LS3R",
	Desc: "Locking-Shift Three Right",
	Type: ESC,
	Code: []byte{'|'},
}

// MC is used either to initiate a transfer of data from or to an auxiliary
// input/output device or to enable or disable the relay of the received data
// stream to an auxiliary input/output device, depending on the parameter value:
//
// 0 initiate transfer to a primary auxiliary device
//
// 1 initiate transfer from a primary auxiliary device
//
// 2 initiate transfer to a secondary auxiliary device
//
// 3 initiate transfer from a secondary auxiliary device
//
// 4 stop relay to a primary auxiliary device
//
// 5 start relay to a primary auxiliary device
//
// 6 stop relay to a secondary auxiliary device
//
// 7 start relay to a secondary auxiliary device
//
// This control function may not be used to switch on or off an auxiliary
// device.
var MC_ = Sequence{
	Name:     "MC",
	Desc:     "Media Copy",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{'i'},
}

// MW is used to set a message waiting indicator in the receiving device. An
// appropriate acknowledgement to the receipt of MW may be given by using
// DEVICE STATUS REPORT (DSR).
var MW_ = Sequence{
	Name: "MW",
	Desc: "Message Waiting",
	Type: ESC,
	Code: []byte{'U'},
}

// NBH is used to indicate a point where a line break shall not occur when text
// is formatted. NBH may occur between two graphic characters either or both of
// which may be SPACE.
var NBH_ = Sequence{
	Name: "NBH",
	Desc: "No Break Here",
	Type: ESC,
	Code: []byte{'C'},
}

// The effect of NEL depends on the setting of the DEVICE COMPONENT SELECT MODE
// (DCSM) and on the parameter value of SELECT IMPLICIT MOVEMENT DIRECTION
// (SIMD).
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to PRESENTATION and with a
// parameter value of SIMD equal to 0, NEL causes the active presentation
// position to be moved to the line home position of the following line in the
// presentation component. The line home position is established by the
// parameter value of SET LINE HOME (SLH).
//
// With a parameter value of SIMD equal to 1, NEL causes the active
// presentation position to be moved to the line limit position of the
// following line in the presentation component. The line limit position is
// established by the parameter value of SET LINE LIMIT (SLL).
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to DATA and with a
// parameter value of SIMD equal to 0, NEL causes the active data position to
// be moved to the line home position of the following line in the data
// component. The line home position is established by the parameter value of
// SET LINE HOME (SLH).
//
// With a parameter value of SIMD equal to 1, NEL causes the active data
// position to be moved to the line limit position of the following line in the
// data component. The line limit position is established by the parameter
// value of SET LINE LIMIT (SLL).
var NEL_ = Sequence{
	Name: "NEL",
	Desc: "Next Line",
	Type: ESC,
	Code: []byte{'E'},
}

// NP causes the n-th following page in the presentation component to be
// displayed, where n equals the value of Pn.
//
// The effect of this control function on the active presentation position is
// not defined by this Standard.
var NP_ = Sequence{
	Name:     "NP",
	Desc:     "Next Page",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'U'},
}

// OSC is used as the opening delimiter of a control string for operating
// system use. The command string following may consist of a sequence of bit
// combinations in the range 00/08 to 00/13 and 02/00 to 07/14. The control
// string is closed by the terminating delimiter STRING TERMINATOR (ST). The
// interpretation of the command string depends on the relevant operating
// system.
var OSC_ = Sequence{
	Name: "OSC",
	Desc: "Operating System Command",
	Type: ESC,
	Code: []byte{']'},
}

// PEC is used to establish the spacing and the extent of the graphic
// characters for subsequent text. The spacing is specified in the line as
// multiples of the spacing established by the most recent occurrence of SET
// CHARACTER SPACING (SCS) or of SELECT CHARACTER SPACING (SHS) or of SPACING
// INCREMENT (SPI) in the data stream. The extent of the characters is
// implicitly established by these
//
// control functions. The established spacing and the extent remain in effect
// until the next occurrence of PEC, of SCS, of SHS or of SPI in the data
// stream. The parameter values are
//
// 0 normal (as specified by SCS, SHS or SPI)
//
// 1 expanded (multiplied by a factor not greater than 2)
//
// 2 condensed (multiplied by a factor not less than 0,5)
var PEC_ = Sequence{
	Name:     "PEC",
	Desc:     "Presentation Expand or Contract",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{' ', 'Z'},
}

// PFS is used to establish the available area for the imaging of pages of text
// based on paper size. The pages are introduced by the subsequent occurrence
// of FORM FEED (FF) in the data stream.
//
// The established image area remains in effect until the next occurrence of
// PFS in the data stream. The parameter values are (see also annex E):
//
// 0 tall basic text communication format
//
// 1 wide basic text communication format
//
// 2 tall basic A4 format
//
// 3 wide basic A4 format
//
// 4 tall North American letter format
//
// 5 wide North American letter format
//
// 6 tall extended A4 format
//
// 7 wide extended A4 format
//
// 8 tall North American legal format
//
// 9 wide North American legal format
//
// 10 A4 short lines format
//
// 11 A4 long lines format
//
// 12 B5 short lines format
//
// 13 B5 long lines format
//
// 14 B4 short lines format
//
// 15 B4 long lines format
//
// The page home position is established by the parameter value of SET PAGE
// HOME (SPH), the page limit position is established by the parameter value of
// SET PAGE LIMIT (SPL).
var PFS_ = Sequence{
	Name:     "PFS",
	Desc:     "Page Format Selection",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{' ', 'J'},
}

// PLD causes the active presentation position to be moved in the presentation
// component to the corresponding position of an imaginary line with a partial
// offset in the direction of the line progression. This offset should be
// sufficient either to image following characters as subscripts until the
// first following occurrence of PARTIAL LINE BACKWARD (PLU) in the data
// stream, or, if preceding characters were imaged as superscripts, to restore
// imaging of following characters to the active line (the line that contains
// the active presentation position).
//
// Any interactions between PLD and format effectors other than PLU are not
// defined by this Standard.
var PLD_ = Sequence{
	Name: "PLD",
	Desc: "Partial Line Forward",
	Type: ESC,
	Code: []byte{'K'},
}

// PLU causes the active presentation position to be moved in the presentation
// component to the corresponding position of an imaginary line with a partial
// offset in the direction opposite to that of the line progression. This
// offset should be sufficient either to image following characters as
// superscripts until the first following occurrence of PARTIAL LINE FORWARD
// (PLD) in the data stream, or, if preceding characters were imaged as
// subscripts, to restore imaging of following characters to the active line
// (the line that contains the active presentation position).
//
// Any interactions between PLU and format effectors other than PLD are not
// defined by this Standard.
var PLU_ = Sequence{
	Name: "PLU",
	Desc: "Partial Line Backward",
	Type: ESC,
	Code: []byte{'L'},
}

// PM is used as the opening delimiter of a control string for privacy message
// use. The command string following may consist of a sequence of bit
// combinations in the range 00/08 to 00/13 and 02/00 to 07/14. The control
// string is closed by the terminating delimiter STRING TERMINATOR (ST). The
// interpretation of the command string depends on the relevant privacy
// discipline.
var PM_ = Sequence{
	Name: "PM",
	Desc: "Privacy Message",
	Type: ESC,
	Code: []byte{'^'},
}

// PP causes the n-th preceding page in the presentation component to be
// displayed, where n equals the value of Pn. The effect of this control
// function on the active presentation position is not defined by this Standard.
var PP_ = Sequence{
	Name:     "PP",
	Desc:     "Preceding Page",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'V'},
}

// PPA causes the active data position to be moved in the data component to the
// corresponding character position on the n-th page, where n equals the value
// of Pn.
var PPA_ = Sequence{
	Name:     "PPA",
	Desc:     "Page Position Absolute",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{' ', 'P'},
}

// PPB causes the active data position to be moved in the data component to the
// corresponding character position on the n-th preceding page, where n equals
// the value of Pn.
var PPB_ = Sequence{
	Name:     "PPB",
	Desc:     "Page Position Backward",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{' ', 'R'},
}

// PPR causes the active data position to be moved in the data component to the
// corresponding character position on the n-th following page, where n equals
// the value of Pn.
var PPR_ = Sequence{
	Name:     "PPR",
	Desc:     "Page Position Forward",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{' ', 'Q'},
}

// PTX is used to delimit strings of graphic characters that are communicated
// one after another in the data stream but that are intended to be presented
// in parallel with one another, usually in adjacent lines.
//
// The parameter values are
//
// 0 end of parallel texts
//
// 1 beginning of a string of principal parallel text
//
// 2 beginning of a string of supplementary parallel text
//
// 3 beginning of a string of supplementary Japanese phonetic annotation
//
// 4 beginning of a string of supplementary Chinese phonetic annotation
//
// 5 end of a string of supplementary phonetic annotations
//
// PTX with a parameter value of 1 indicates the beginning of the string of
// principal text intended to be presented in parallel with one or more strings
// of supplementary text.
//
// PTX with a parameter value of 2, 3 or 4 indicates the beginning of a string
// of supplementary text that is intended to be presented in parallel with
// either a string of principal text or the immediately preceding string of
// supplementary text, if any; at the same time it indicates the end of the
// preceding string of principal text or of the immediately preceding string of
// supplementary text, if any. The end of a string of supplementary text is
// indicated by a subsequent occurrence of PTX with a parameter value other
// than 1.
//
// PTX with a parameter value of 0 indicates the end of the strings of text
// intended to be presented in parallel with one another.
//
// NOTE
//
// PTX does not explicitly specify the relative placement of the strings of
// principal and supplementary parallel texts, or the relative sizes of graphic
// characters in the strings of parallel text. A string of supplementary text
// is normally presented in a line adjacent to the line containing the string
// of principal text, or adjacent to the line containing the immediately
// preceding string of supplementary text, if any. The first graphic character
// of the string of principal text and the first graphic character of a string
// of supplementary text are normally presented in the same position of their
// respective lines. However, a string of supplementary text longer (when
// presented) than the associated string of principal text may be centred on
// that string. In the case of long strings of text, such as paragraphs in
// different languages, the strings may be presented in successive lines in
// parallel columns, with their beginnings aligned with one another and the
// shorter of the paragraphs followed by an appropriate amount of "white space".
//
// Japanese phonetic annotation typically consists of a few half-size or
// smaller Kana characters which indicate the pronunciation or interpretation
// of one or more Kanji characters and are presented above those Kanji
// characters if the character path is horizontal, or to the right of them if
// the character path is vertical.
//
// Chinese phonetic annotation typically consists of a few Pinyin characters
// which indicate the pronunciation of one or more Hanzi characters and are
// presented above those Hanzi characters. Alternatively, the Pinyin characters
// may be presented in the same line as the Hanzi characters and following the
// respective Hanzi characters. The Pinyin characters will then be presented
// within enclosing pairs of parentheses.
var PTX_ = Sequence{
	Name:     "PTX",
	Desc:     "Parallel Texts",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{'\\'},
}

// PU1 is reserved for a function without standardized meaning for private use
// as required, subject to the prior agreement between the sender and the
// recipient of the data.
var PU1_ = Sequence{
	Name: "PU1",
	Desc: "Private Use One",
	Type: ESC,
	Code: []byte{'Q'},
}

// PU2 is reserved for a function without standardized meaning for private use
// as required, subject to the prior agreement between the sender and the
// recipient of the data.
var PU2_ = Sequence{
	Name: "PU2",
	Desc: "Private Use Two",
	Type: ESC,
	Code: []byte{'R'},
}

// QUAD is used to indicate the end of a string of graphic characters that are
// to be positioned on a single line according to the layout specified by the
// parameter values, see annex C:
//
// 0 flush to line home position margin
//
// 1 flush to line home position margin and fill with leader
//
// 2 centre between line home position and line limit position margins
//
// 3 centre between line home position and line limit position margins and fill
// with leader
//
// 4 flush to line limit position margin
//
// 5 flush to line limit position margin and fill with leader
//
// 6 flush to both margins
//
// The beginning of the string to be positioned is indicated by the preceding
// occurrence in the data stream of either QUAD or one of the following
// formator functions: FORM FEED (FF), CHARACTER AND LINE POSITION (HVP), LINE
// FEED (LF), NEXT LINE (NEL), PAGE POSITION ABSOLUTE (PPA), PAGE POSITION
// BACKWARD (PPB), PAGE POSITION FORWARD (PPR), REVERSE LINE FEED (RI), LINE
// POSITION ABSOLUTE (VPA), LINE POSITION BACKWARD (VPB), LINE POSITION FORWARD
// (VPR), or LINE TABULATION (VT).
//
// The line home position is established by the parameter value of SET LINE
// HOME (SLH). The line limit position is established by the parameter value of
// SET LINE LIMIT (SLL).
var QUAD_ = Sequence{
	Name:     "QUAD",
	Desc:     "Quad",
	Type:     CSI,
	Notation: "Ps...",
	NParam:   -1,
	Defaults: []string{"0"},
	Code:     []byte{' ', 'H'},
}

// REP is used to indicate that the preceding character in the data stream, if
// it is a graphic character (represented by one or more bit combinations)
// including SPACE, is to be repeated n times, where n equals the value of Pn.
// If the character preceding REP is a control function or part of a control
// function, the effect of REP is not defined by this Standard.
var REP_ = Sequence{
	Name:     "REP",
	Desc:     "Repeat",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'b'},
}

// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to PRESENTATION, RI causes
// the active presentation position to be moved in the presentation component
// to the corresponding character position of the preceding line.
//
// If the DEVICE COMPONENT SELECT MODE (DCSM) is set to DATA, RI causes the
// active data position to be moved in the data component to the corresponding
// character position of the preceding line.
var RI_ = Sequence{
	Name: "RI",
	Desc: "Reverse Line Feed",
	Type: ESC,
	Code: []byte{'M'},
}

// RIS causes a device to be reset to its initial state, i.e. the state it has
// after it is made operational. This may imply, if applicable: clear
// tabulation stops, remove qualified areas, reset graphic rendition, put all
// character positions into the erased state, move the active presentation
// position to the first position of the first line in the presentation
// component, move the active data position to the first character position of
// the first line in the data component, set the modes into the reset state,
// etc.
var RIS_ = Sequence{
	Name: "RIS",
	Desc: "Reset to Initial State",
	Type: ESC,
	Code: []byte{'c'},
}

// RM causes the modes of the receiving device to be reset as specified by the
// parameter values:
//
// 1 GUARDED AREA TRANSFER MODE (GATM)
//
// 2 KEYBOARD ACTION MODE (KAM)
//
// 3 CONTROL REPRESENTATION MODE (CRM)
//
// 4 INSERTION REPLACEMENT MODE (IRM)
//
// 5 STATUS REPORT TRANSFER MODE (SRTM)
//
// 6 ERASURE MODE (ERM)
//
// 7 LINE EDITING MODE (VEM)
//
// 8 BI-DIRECTIONAL SUPPORT MODE (BDSM)
//
// 9 DEVICE COMPONENT SELECT MODE (DCSM)
//
// 10 CHARACTER EDITING MODE (HEM)
//
// 11 POSITIONING UNIT MODE (PUM) (see F.4.1 in annex F)
//
// 12 SEND/RECEIVE MODE (SRM)
//
// 13 FORMAT EFFECTOR ACTION MODE (FEAM)
//
// 14 FORMAT EFFECTOR TRANSFER MODE (FETM)
//
// 15 MULTIPLE AREA TRANSFER MODE (MATM)
//
// 16 TRANSFER TERMINATION MODE (TTM)
//
// 17 SELECTED AREA TRANSFER MODE (SATM)
//
// 18 TABULATION STOP MODE (TSM)
//
// 19 (Shall not be used; see F.5.1 in annex F)
//
// 20 (Shall not be used; see F.5.2 in annex F)
//
// 21 GRAPHIC RENDITION COMBINATION MODE (GRCM)
//
// 22 ZERO DEFAULT MODE (ZDM) (see F.4.2 in annex F)
//
// NOTE
//
// Private modes may be implemented using private parameters, see 5.4.1 and 7.4.
var RM_ = Sequence{
	Name:     "RM",
	Desc:     "Reset Mode",
	Type:     CSI,
	Notation: "Ps...",
	NParam:   -1,
	Code:     []byte{'l'},
}

// SACS is used to establish extra inter-character escapement for subsequent
// text. The established extra escapement remains in effect until the next
// occurrence of SACS or of SET REDUCED CHARACTER SEPARATION (SRCS) in the data
// stream or until it is reset to the default value by a subsequent occurrence
// of CARRIAGE RETURN/LINE FEED (CR LF) or of NEXT LINE (NEL) in the data
// stream, see annex C.
//
// Pn specifies the number of units by which the inter-character escapement is
// enlarged.
//
// The unit in which the parameter value is expressed is that established by
// the parameter value of SELECT SIZE UNIT (SSU).
var SACS_ = Sequence{
	Name:     "SACS",
	Desc:     "Set Additional Character Separation",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{' ', '\\'},
}

// SAPV is used to specify one or more variants for the presentation of
// subsequent text. The parameter values are
//
// 0 default presentation (implementation-defined); cancels the effect of any
// preceding occurrence of SAPV in the data stream
//
// 1 the decimal digits are presented by means of the graphic symbols used in
// the Latin script
//
// 2 the decimal digits are presented by means of the graphic symbols used in
// the Arabic script, i.e. the Hindi symbols
//
// 3 when the direction of the character path is right-to-left, each of the
// graphic characters in the graphic character set(s) in use which is one of a
// left/right-handed pair (parentheses, square brackets, curly brackets,
// greater-than/less-than signs, etc.) is presented as "mirrored", i.e. as the
// other member of the pair. For example, the coded graphic character given the
// name LEFT PARENTHESIS is presented as RIGHT PARENTHESIS, and vice versa
//
// 4 when the direction of the character path is right-to-left, all graphic
// characters which represent operators and delimiters in mathematical formulae
// and which are not symmetrical about a vertical axis are presented as
// mirrored about that vertical axis
//
// 5 the following graphic character is presented in its isolated form
//
// 6 the following graphic character is presented in its initial form
//
// 7 the following graphic character is presented in its medial form
//
// 8 the following graphic character is presented in its final form
//
// 9 where the bit combination 02/14 is intended to represent a decimal mark in
// a decimal number it shall be presented by means of the graphic symbol FULL
// STOP
//
// 10 where the bit combination 02/14 is intended to represent a decimal mark
// in a decimal number it shall be presented by means of the graphic symbol
// COMMA
//
// 11 vowels are presented above or below the preceding character
//
// 12 vowels are presented after the preceding character
//
// 13 contextual shape determination of Arabic scripts, including the LAM-ALEPH
// ligature but excluding all other Arabic ligatures
//
// 14 contextual shape determination of Arabic scripts, excluding all Arabic
// ligatures
//
// 15 cancels the effect of parameter values 3 and 4
//
// 16 vowels are not presented
//
// 17 when the string direction is right-to-left, the italicized characters are
// slanted to the left; when the string direction is left-to-right, the
// italicized characters are slanted to the right
//
// 18 contextual shape determination of Arabic scripts is not used, the graphic
// characters - including the digits - are presented in the form they are
// stored (Pass-through)
//
// 19 contextual shape determination of Arabic scripts is not used, the graphic
// characters- excluding the digits - are presented in the form they are stored
// (Pass-through)
//
// 20 the graphic symbols used to present the decimal digits are device
// dependent
//
// 21 establishes the effect of parameter values 5, 6, 7, and 8 for the
// following graphic characters until cancelled
//
// 22 cancels the effect of parameter value 21, i.e. re-establishes the effect
// of parameter values 5, 6, 7, and 8 for the next single graphic character
// only.
var SAPV_ = Sequence{
	Name:     "SAPV",
	Desc:     "Select Alternative Presentation Variants",
	Type:     CSI,
	Notation: "Ps...",
	NParam:   -1,
	Defaults: []string{"0"},
	Code:     []byte{' ', ']'},
}

// SCI and the bit combination following it are used to represent a control
// function or a graphic character. The bit combination following SCI must be
// from 00/08 to 00/13 or 02/00 to 07/14. The use of SCI is reserved for future
// standardization.
var SCI_ = Sequence{
	Name: "SCI",
	Desc: "Single Character Introducer",
	Type: ESC,
	Code: []byte{'Z'},
}

// SCO is used to establish the amount of rotation of the graphic characters
// following in the data stream. The established value remains in effect until
// the next occurrence of SCO in the data stream.
//
// The parameter values are 0 0°
//
// 1 45°
//
// 2 90°
//
// 3 135° 4 180° 5 225° 6 270° 7 315°
//
// is positive, i.e. counter-clockwise and applies to the normal presentation
// of the graphic
//
// Rotation
//
// characters along the character path. The centre of rotation of the affected
// graphic characters is not defined by this Standard.
var SCO_ = Sequence{
	Name:     "SCO",
	Desc:     "Select Character Orientation",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{' ', 'e'},
}

// SCP is used to select the character path, relative to the line orientation,
// for the active line (the line that contains the active presentation
// position) and subsequent lines in the presentation component. It is also
// used to update the content of the active line in the presentation component
// and the content of the active line (the line that contains the active data
// position) in the data component. This takes effect immediately.
//
// Ps1 specifies the character path:
//
// 1 left-to-right (in the case of horizontal line orientation), or
// top-to-bottom (in the case of vertical line orientation)
//
// 2 right-to-left (in the case of horizontal line orientation), or
// bottom-to-top (in the case of vertical line orientation)
//
// Ps2 specifies the effect on the content of the presentation component and
// the content of the data component:
//
// 0 undefined (implementation-dependent)
//
// NOTE
//
// This may also permit the effect to take place after the next occurrence of
// CR, NEL or any control function which initiates an absolute movement of the
// active presentation position or the active data position.
//
// 1 the content of the active line in the presentation component (the line
// that contains the active presentation position) is updated to correspond to
// the content of the active line in the data component (the line that contains
// the active data position) according to the newly established character path
// characteristics in the presentation component; the active data position is
// moved to the first character position in the active line in the data
// component, the active presentation position in the presentation component is
// updated accordingly
//
// 2 the content of the active line in the data component (the line that
// contains the active data position) is updated to correspond to the content
// of the active line in the presentation component (the line that contains the
// active presentation position) according to the newly established character
// path characteristics of the presentation component; the active presentation
// position is moved to the first character position in the active line in the
// presentation component, the active data position in the data component is
// updated accordingly.
var SCP_ = Sequence{
	Name:     "SCP",
	Desc:     "Select Character Path",
	Type:     CSI,
	Notation: "Ps1;Ps2",
	NParam:   2,
	MinParam: 2,
	Code:     []byte{' ', 'k'},
}

// SCS is used to establish the character spacing for subsequent text. The
// established spacing remains in effect until the next occurrence of SCS, or
// of SELECT CHARACTER SPACING (SHS) or of SPACING INCREMENT (SPI) in the data
// stream, see annex C.
//
// Pn specifies the character spacing.
//
// The unit in which the parameter value is expressed is that established by
// the parameter value of SELECT SIZE UNIT (SSU).
var SCS_ = Sequence{
	Name:     "SCS",
	Desc:     "Set Character Spacing",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', 'g'},
}

// SD causes the data in the presentation component to be moved by n line
// positions if the line orientation is horizontal, or by n character positions
// if the line orientation is vertical, such that the data appear to move down;
// where n equals the value of Pn.
//
// The active presentation position is not affected by this control function.
var SD_ = Sequence{
	Name:     "SD",
	Desc:     "Scroll Down",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'T'},
}

// SDS is used to establish in the data component the beginning and the end of
// a string of characters as well as the direction of the string. This
// direction may be different from that currently established. The indicated
// string follows the preceding text. The established character progression is
// not affected.
//
// The beginning of a directed string is indicated by SDS with a parameter
// value not equal to 0. A directed string may contain one or more nested
// strings. These nested strings may be directed strings the beginnings of
// which are indicated by SDS with a parameter value not equal to 0, or
// reversed strings the beginnings of which are indicated by START REVERSED
// STRING (SRS) with a parameter value of 1. Every beginning of such a string
// invokes the next deeper level of nesting.
//
// This Standard does not define the location of the active data position
// within any such nested string.
//
// The end of a directed string is indicated by SDS with a parameter value of
// 0. Every end of such a string re-establishes the next higher level of
// nesting (the one in effect prior to the string just ended). The direction is
// re-established to that in effect prior to the string just ended. The active
// data position is moved to the character position following the characters of
// the string just ended.
//
// The parameter values are:
//
// 0 end of a directed string; re-establish the previous direction
//
// 1 start of a directed string; establish the direction left-to-right
//
// 2 start of a directed string; establish the direction right-to-left
//
// NOTE 1
//
// The effect of receiving a CVT, HT, SCP, SPD or VT control function within an
// SDS string is not defined by this Standard.
//
// NOTE 2
//
// The control functions for area definition (DAQ, EPA, ESA, SPA, SSA) should
// not be used within an SDS string.
var SDS_ = Sequence{
	Name:     "SDS",
	Desc:     "Start Directed String",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{']'},
}

// SEE is used to establish the editing extent for subsequent character or line
// insertion or deletion. The established extent remains in effect until the
// next occurrence of SEE in the data stream. The editing extent depends on the
// parameter value:
//
// 0 the shifted part is limited to the active page in the presentation
// component
//
// 1 the shifted part is limited to the active line in the presentation
// component
//
// 2 the shifted part is limited to the active field in the presentation
// component
//
// 3 the shifted part is limited to the active qualified area
//
// 4 the shifted part consists of the relevant part of the entire presentation
// component.
var SEE_ = Sequence{
	Name:     "SEE",
	Desc:     "Select Editing Extent",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{'Q'},
}

// SEF causes a sheet of paper to be ejected from a printing device into a
// specified output stacker and another sheet to be loaded into the printing
// device from a specified paper bin.
//
// Parameter values of Ps1 are:
//
// 0 eject sheet, no new sheet loaded
//
// 1 eject sheet and load another from bin 1
//
// 2 eject sheet and load another from bin 2
//
// . . .
//
// n eject sheet and load another from bin n Parameter values of Ps2 are:
//
// 0 eject sheet, no stacker specified
//
// 1 eject sheet into stacker 1
//
// 2 eject sheet into stacker 2
//
// . . .
//
// n eject sheet into stacker n
var SEF_ = Sequence{
	Name:     "SEF",
	Desc:     "Sheet Eject and Feed",
	Type:     CSI,
	Notation: "Ps1;Ps2",
	NParam:   2,
	Defaults: []string{"0", "0"},
	Code:     []byte{' ', 'Y'},
}

// SGR is used to establish one or more graphic rendition aspects for
// subsequent text. The established aspects remain in effect until the next
// occurrence of SGR in the data stream, depending on the setting of the
// GRAPHIC RENDITION COMBINATION MODE (GRCM). Each graphic rendition aspect is
// specified by a parameter value:
//
// 0 default rendition (implementation-defined), cancels the effect of any
// preceding occurrence of SGR in the data stream regardless of the setting of
// the GRAPHIC RENDITION COMBINATION MODE (GRCM)
//
// 1 bold or increased intensity
//
// 2 faint, decreased intensity or second colour
//
// 3 italicized
//
// 4 singly underlined
//
// 5 slowly blinking (less then 150 per minute)
//
// 6 rapidly blinking (150 per minute or more)
//
// 7 negative image
//
// 8 concealed characters
//
// 9 crossed-out (characters still legible but marked as to be deleted)
//
// 10 primary (default) font
//
// 11 first alternative font
//
// 12 second alternative font
//
// 13 third alternative font
//
// 14 fourth alternative font
//
// 15 fifth alternative font
//
// 16 sixth alternative font
//
// 17 seventh alternative font
//
// 18 eighth alternative font
//
// 19 ninth alternative font
//
// 20 Fraktur (Gothic)
//
// 21 doubly underlined
//
// 22 normal colour or normal intensity (neither bold nor faint)
//
// 23 not italicized, not fraktur
//
// 24 not underlined (neither singly nor doubly)
//
// 25 steady (not blinking)
//
// 26 (reserved for proportional spacing as specified in CCITT Recommendation
// T.61)
//
// 27 positive image
//
// 28 revealed characters
//
// 29 not crossed out 30 black display 31 red display
//
// 32 green display 33 yellow display 34 blue display
//
// 35 magenta display
//
// 36 cyan display
//
// 37 white display
//
// 38 (reserved for future standardization; intended for setting character
// foreground colour as specified in ISO 8613-6 [CCITT Recommendation T.416])
//
// 39 default display colour (implementation-defined) 40 black background
//
// 41 red background
//
// 42 green background
//
// 43 yellow background 44 blue background
//
// 45 magenta background 46 cyan background
//
// 47 white background
//
// 48 (reserved for future standardization; intended for setting character
// background colour as specified in ISO 8613-6 [CCITT Recommendation T.416])
//
// 49 default background colour (implementation-defined)
//
// 50 (reserved for cancelling the effect of the rendering aspect established
// by parameter value 26) 51 framed
//
// 52 encircled
//
// 53 overlined
//
// 54 not framed, not encircled
//
// 55 not overlined
//
// 56 (reserved for future standardization)
//
// 57 (reserved for future standardization)
//
// 58 (reserved for future standardization)
//
// 59 (reserved for future standardization)
//
// 60 ideogram underline or right side line
//
// 61 ideogram double underline or double line on the right side
//
// 62 ideogram overline or left side line
//
// 63 ideogram double overline or double line on the left side
//
// 64 ideogram stress marking
//
// 65 cancels the effect of the rendition aspects established by parameter
// values 60 to 64
//
// 0 1 2 3 4 5 6
//
// 10 characters per 25,4 mm 12 characters per 25,4 mm 15 characters per 25,4 mm
//
// 6 characters per 25,4 mm 3 characters per 25,4 mm 9 characters per 50,8 mm 4
// characters per 25,4 mm
//
// NOTE
//
// The usable combinations of parameter values are determined by the
// implementation.
var SGR_ = Sequence{
	Name:     "SGR",
	Desc:     "Select Graphic Rendition",
	Type:     CSI,
	Notation: "Ps...",
	NParam:   -1,
	Defaults: []string{"0"},
	Code:     []byte{'m'},
}

// SHS is used to establish the character spacing for subsequent text. The
// established spacing remains in effect until the next occurrence of SHS or of
// SET CHARACTER SPACING (SCS) or of SPACING INCREMENT (SPI) in the data
// stream. The parameter values are
var SHS_ = Sequence{
	Name:     "SHS",
	Desc:     "Select Character Spacing",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{' ', 'K'},
}

// SIMD is used to select the direction of implicit movement of the data
// position relative to the character progression. The direction selected
// remains in effect until the next occurrence of SIMD.
//
// The parameter values are:
//
// 0 the direction of implicit movement is the same as that of the character
// progression
//
// 1 the direction of implicit movement is opposite to that of the character
// progression.
var SIMD_ = Sequence{
	Name:     "SIMD",
	Desc:     "Select Implicit Movement Direction",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{'^'},
}

// SL causes the data in the presentation component to be moved by n character
// positions if the line orientation is horizontal, or by n line positions if
// the line orientation is vertical, such that the data appear to move to the
// left; where n equals the value of Pn.
//
// The active presentation position is not affected by this control function.
var SL_ = Sequence{
	Name:     "SL",
	Desc:     "Scroll Left",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{' ', '@'},
}

// If the DEVICE COMPONENT SELECT MODE is set to PRESENTATION, SLH is used to
// establish at character position n in the active line (the line that contains
// the active presentation position) and lines of subsequent text in the
// presentation component the position to which the active presentation
// position will be moved by subsequent occurrences of CARRIAGE RETURN (CR),
// DELETE LINE (DL), INSERT LINE (IL) or NEXT LINE (NEL) in the data stream;
// where n equals the value of Pn. In the case of a device without data
// component, it is also the position ahead of which no implicit movement of
// the active presentation position shall occur.
//
// If the DEVICE COMPONENT SELECT MODE is set to DATA, SLH is used to establish
// at character position n in the active line (the line that contains the
// active data position) and lines of subsequent text in the data component the
// position to which the active data position will be moved by subsequent
// occurrences of CARRIAGE RETURN (CR), DELETE LINE (DL), INSERT LINE (IL) or
// NEXT LINE (NEL) in the data stream; where n equals the value of Pn. It is
// also the position ahead of which no implicit movement of the active data
// position shall occur.
//
// The established position is called the line home position and remains in
// effect until the next occurrence of SLH in the data stream.
var SLH_ = Sequence{
	Name:     "SLH",
	Desc:     "Set Line Home",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', 'U'},
}

// If the DEVICE COMPONENT SELECT MODE is set to PRESENTATION, SLL is used to
// establish at character position n in the active line (the line that contains
// the active presentation position) and lines of subsequent text in the
// presentation component the position to which the active presentation
// position will be moved by subsequent occurrences of CARRIAGE RETURN (CR), or
// NEXT LINE (NEL) in the data stream if the parameter value of SELECT IMPLICIT
// MOVEMENT DIRECTION (SIMD) is equal to 1; where n equals the value of Pn. In
// the case of a device without data component, it is also the position beyond
// which no implicit movement of the active presentation position shall occur.
//
// If the DEVICE COMPONENT SELECT MODE is set to DATA, SLL is used to establish
// at character position n in the active line (the line that contains the
// active data position) and lines of subsequent text in the data component the
// position beyond which no implicit movement of the active data position shall
// occur. It is also the position in the data component to which the active
// data position will be moved by subsequent occurrences of CR or NEL in the
// data stream, if the parameter value of SELECT IMPLICIT MOVEMENT DIRECTION
// (SIMD) is equal to 1.
//
// The established position is called the line limit position and remains in
// effect until the next occurrence of SLL in the data stream.
var SLL_ = Sequence{
	Name:     "SLL",
	Desc:     "Set Line Limit",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', 'V'},
}

// SLS is used to establish the line spacing for subsequent text. The
// established spacing remains in effect until the next occurrence of SLS or of
// SELECT LINE SPACING (SVS) or of SPACING INCREMENT (SPI) in the data stream.
//
// Pn specifies the line spacing.
//
// The unit in which the parameter value is expressed is that established by
// the parameter value of SELECT SIZE UNIT (SSU).
var SLS_ = Sequence{
	Name:     "SLS",
	Desc:     "Set Line Spacing",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', 'h'},
}

// SM causes the modes of the receiving device to be set as specified by the
// parameter values:
//
// 1 GUARDED AREA TRANSFER MODE (GATM)
//
// 2 KEYBOARD ACTION MODE (KAM)
//
// 3 CONTROL REPRESENTATION MODE (CRM)
//
// 4 INSERTION REPLACEMENT MODE (IRM)
//
// 5 STATUS REPORT TRANSFER MODE (SRTM)
//
// 6 ERASURE MODE (ERM)
//
// 7 LINE EDITING MODE (VEM)
//
// 8 BI-DIRECTIONAL SUPPORT MODE (BDSM)
//
// 9 DEVICE COMPONENT SELECT MODE (DCSM)
//
// 10 CHARACTER EDITING MODE (HEM)
//
// 11 POSITIONING UNIT MODE (PUM) (see F.4.1 in annex F)
//
// 12 SEND/RECEIVE MODE (SRM)
//
// 13 FORMAT EFFECTOR ACTION MODE (FEAM)
//
// 14 FORMAT EFFECTOR TRANSFER MODE (FETM)
//
// 15 MULTIPLE AREA TRANSFER MODE (MATM)
//
// 16 TRANSFER TERMINATION MODE (TTM)
//
// 17 SELECTED AREA TRANSFER MODE (SATM)
//
// 18 TABULATION STOP MODE (TSM)
//
// 19 (Shall not be used; see F.5.1 in annex F)
//
// 20 (Shall not be used; see F.5.2 in annex F)
//
// 21 GRAPHIC RENDITION COMBINATION (GRCM)
//
// 22 ZERO DEFAULT MODE (ZDM) (see F.4.2 in annex F)
//
// NOTE
//
// Private modes may be implemented using private parameters, see 5.4.1 and 7.4.
var SM_ = Sequence{
	Name:     "SM",
	Desc:     "Set Mode",
	Type:     CSI,
	Notation: "Ps...",
	NParam:   -1,
	Code:     []byte{'h'},
}

// SOS is used as the opening delimiter of a control string. The character
// string following may consist of any bit combination, except those
// representing SOS or STRING TERMINATOR (ST). The control string is closed by
// the terminating delimiter STRING TERMINATOR (ST). The interpretation of the
// character string depends on the application.
var SOS_ = Sequence{
	Name: "SOS",
	Desc: "Start of String",
	Type: ESC,
	Code: []byte{'X'},
}

// SPA is used to indicate that the active presentation position is the first
// of a string of character positions in the presentation component, the
// contents of which are protected against manual alteration, are guarded
// against transmission or transfer, depending on the setting of the GUARDED
// AREA TRANSFER MODE (GATM) and may be protected against erasure, depending on
// the setting of the ERASURE MODE (ERM). The end of this string is indicated
// by END OF GUARDED AREA (EPA).
//
// NOTE
//
// The control functions for area definition (DAQ, EPA, ESA, SPA, SSA) should
// not be used within an SRS string or an SDS string.
var SPA_ = Sequence{
	Name: "SPA",
	Desc: "Start of Guarded Area",
	Type: ESC,
	Code: []byte{'V'},
}

// SPD is used to select the line orientation, the line progression, and the
// character path in the presentation component. It is also used to update the
// content of the presentation component and the content of the data component.
// This takes effect immediately.
//
// Ps1 specifies the line orientation, the line progression and the character
// path:
//
// 0 line orientation: line progression: character path:
//
// 1 line orientation: line progression: character path:
//
// 2 line orientation: line progression: character path:
//
// 3 line orientation: line progression: character path:
//
// 4 line orientation: line progression: character path:
//
// 5 line orientation: line progression: character path:
//
// horizontal top-to-bottom left-to-right
//
// vertical right-to-left top-to-bottom
//
// vertical left-to-right top-to-bottom
//
// horizontal top-to-bottom right-to-left
//
// vertical left-to-right bottom-to-top
//
// horizontal bottom-to-top right-to-left
//
// 6 line orientation: line progression: character path:
//
// 7 line orientation: line progression: character path:
//
// horizontal bottom-to-top left-to-right
//
// vertical right-to-left bottom-to-top
//
// Ps2 specifies the effect on the content of the presentation component and
// the content of the data component:
//
// 0 undefined (implementation-dependent)
//
// NOTE
//
// This may also permit the effect to take place after the next occurrence of
// CR, FF or any control function which initiates an absolute movement of the
// active presentation position or the active data position.
//
// 1 the content of the presentation component is updated to correspond to the
// content of the data component according to the newly established
// characteristics of the presentation component; the active data position is
// moved to the first character position in the first line in the data
// component, the active presentation position in the presentation component is
// updated accordingly
//
// 2 the content of the data component is updated to correspond to the content
// of the presentation component according to the newly established
// characteristics of the presentation component; the active presentation
// position is moved to the first character position in the first line in the
// presentation component, the active data position in the data component is
// updated accordingly.
var SPD_ = Sequence{
	Name:     "SPD",
	Desc:     "Select Presentation Directions",
	Type:     CSI,
	Notation: "Ps1;Ps2",
	NParam:   2,
	Defaults: []string{"0", "0"},
	Code:     []byte{' ', 'S'},
}

// If the DEVICE COMPONENT SELECT MODE is set to PRESENTATION, SPH is used to
// establish at line position n in the active page (the page that contains the
// active presentation position) and subsequent pages in the presentation
// component the position to which the active presentation position will be
// moved by subsequent occurrences of FORM FEED (FF) in the data stream; where
// n equals the value of Pn. In the case of a device without data component, it
// is also the position ahead of which no implicit movement of the active
// presentation position shall occur.
//
// If the DEVICE COMPONENT SELECT MODE is set to DATA, SPH is used to establish
// at line position n in the active page (the page that contains the active
// data position) and subsequent pages in the data component the position to
// which the active data position will be moved by subsequent occurrences of
// FORM FEED (FF) in the data stream; where n equals the value of Pn. It is
// also the position ahead of which no implicit movement of the active
// presentation position shall occur.
//
// The established position is called the page home position and remains in
// effect until the next occurrence of SPH in the data stream.
var SPH_ = Sequence{
	Name:     "SPH",
	Desc:     "Set Page Home",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', 'i'},
}

// SPI is used to establish the line spacing and the character spacing for
// subsequent text. The established line spacing remains in effect until the
// next occurrence of SPI or of SET LINE SPACING (SLS) or of SELECT LINE
// SPACING (SVS) in the data stream. The established character spacing remains
// in effect until the next occurrence of SET CHARACTER SPACING (SCS) or of
// SELECT CHARACTER SPACING (SHS) in the data stream, see annex C.
//
// Pn1 specifies the line spacing
//
// Pn2 specifies the character spacing
//
// The unit in which the parameter values are expressed is that established by
// the parameter value of SELECT SIZE UNIT (SSU).
var SPI_ = Sequence{
	Name:     "SPI",
	Desc:     "Spacing Increment",
	Type:     CSI,
	Notation: "Pn1;Pn2",
	NParam:   2,
	MinParam: 2,
	Code:     []byte{' ', 'G'},
}

// If the DEVICE COMPONENT SELECT MODE is set to PRESENTATION, SPL is used to
// establish at line position n in the active page (the page that contains the
// active presentation position) and pages of subsequent text in the
// presentation component the position beyond which the active presentation
// position can normally not be moved; where n equals the value of Pn. In the
// case of a device without data component, it is also the position beyond
// which no implicit movement of the active presentation position shall occur.
//
// If the DEVICE COMPONENT SELECT MODE is set to DATA, SPL is used to establish
// at line position n in the active page (the page that contains the active
// data position) and pages of subsequent text in the data component the
// position beyond which no implicit movement of the active data position shall
// occur.
//
// The established position is called the page limit position and remains in
// effect until the next occurrence of SPL in the data stream.
var SPL_ = Sequence{
	Name:     "SPL",
	Desc:     "Set Page Limit",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', 'j'},
}

// SPQR is used to select the relative print quality and the print speed for
// devices the output quality and speed of which are inversely related. The
// selected values remain in effect until the next occurrence of SPQR in the
// data stream. The parameter values are
//
// 0 highest available print quality, low print speed
//
// 1 medium print quality, medium print speed
//
// 2 draft print quality, highest available print speed
var SPQR_ = Sequence{
	Name:     "SPQR",
	Desc:     "Select Print Quality and Rapidity",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{' ', 'X'},
}

// SR causes the data in the presentation component to be moved by n character
// positions if the line orientation is horizontal, or by n line positions if
// the line orientation is vertical, such that the data appear to move to the
// right; where n equals the value of Pn.
//
// The active presentation position is not affected by this control function.
var SR_ = Sequence{
	Name:     "SR",
	Desc:     "Scroll Right",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{' ', 'A'},
}

// SRCS is used to establish reduced inter-character escapement for subsequent
// text. The established reduced escapement remains in effect until the next
// occurrence of SRCS or of SET ADDITIONAL CHARACTER SEPARATION (SACS) in the
// data stream or until it is reset to the default value by a subsequent
// occurrence of CARRIAGE RETURN/LINE FEED (CR/LF) or of NEXT LINE (NEL) in the
// data stream, see annex C.
//
// Pn specifies the number of units by which the inter-character escapement is
// reduced.
//
// The unit in which the parameter values are expressed is that established by
// the parameter value of SELECT SIZE UNIT (SSU).
var SRCS_ = Sequence{
	Name:     "SRCS",
	Desc:     "Set Reduced Character Separation",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{' ', 'f'},
}

// SRS is used to establish in the data component the beginning and the end of
// a string of characters as well as the direction of the string. This
// direction is opposite to that currently established. The indicated string
// follows the preceding text. The established character progression is not
// affected.
//
// The beginning of a reversed string is indicated by SRS with a parameter
// value of 1. A reversed string may contain one or more nested strings. These
// nested strings may be reversed strings the beginnings of which are indicated
// by SRS with a parameter value of 1, or directed strings the beginnings of
// which are indicated by START DIRECTED STRING (SDS) with a parameter value
// not equal to 0. Every beginning of such a string invokes the next deeper
// level of nesting.
//
// This Standard does not define the location of the active data position
// within any such nested string.
//
// The end of a reversed string is indicated by SRS with a parameter value of
// 0. Every end of such a string re-establishes the next higher level of
// nesting (the one in effect prior to the string just ended). The direction is
// re-established to that in effect prior to the string just ended. The active
// data position is moved to the character position following the characters of
// the string just ended.
//
// The parameter values are:
//
// 0 end of a reversed string; re-establish the previous direction
//
// 1 beginning of a reversed string; reverse the direction.
//
// NOTE 1
//
// The effect of receiving a CVT, HT, SCP, SPD or VT control function within an
// SRS string is not defined by this Standard.
//
// NOTE 2
//
// The control functions for area definition (DAQ, EPA, ESA, SPA, SSA) should
// not be used within an SRS string.
var SRS_ = Sequence{
	Name:     "SRS",
	Desc:     "Start Reversed String",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{'['},
}

// SSA is used to indicate that the active presentation position is the first
// of a string of character positions in the presentation component, the
// contents of which are eligible to be transmitted in the form of a data
// stream or transferred to an auxiliary input/output device.
//
// The end of this string is indicated by END OF SELECTED AREA (ESA). The
// string of characters actually transmitted or transferred depends on the
// setting of the GUARDED AREA TRANSFER MODE (GATM) and on any guarded areas
// established by DEFINE AREA QUALIFICATION (DAQ), or by START OF GUARDED AREA
// (SPA) and END OF GUARDED AREA (EPA).
//
// NOTE
//
// The control functions for area definition (DAQ, EPA, ESA, SPA, SSA) should
// not be used within an SRS string or an SDS string.
var SSA_ = Sequence{
	Name: "SSA",
	Desc: "Start of Selected Area",
	Type: ESC,
	Code: []byte{'F'},
}

// SSU is used to establish the unit in which the numeric parameters of certain
// control functions are expressed. The established unit remains in effect
// until the next occurrence of SSU in the data stream.
//
// The parameter values are
//
// 0 CHARACTER - The dimensions of this unit are device-dependent
//
// 1 MILLIMETRE
//
// 2 COMPUTER DECIPOINT - 0,035 28 mm (1/720 of 25,4 mm)
//
// 3 DECIDIDOT - 0,037 59 mm (10/266 mm)
//
// 4 MIL-0,0254mm(1/1000of25,4mm)
//
// 5 BASIC MEASURING UNIT (BMU) - 0,021 17 mm (1/1 200 of 25,4 mm)
//
// 6 MICROMETRE - 0,001 mm
//
// 7 PIXEL - The smallest increment that can be specified in a device
//
// 8 DECIPOINT - 0,035 14 mm (35/996 mm)
var SSU_ = Sequence{
	Name:     "SSU",
	Desc:     "Select Size Unit",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{' ', 'I'},
}

// SSW is used to establish for subsequent text the character escapement
// associated with the character SPACE. The established escapement remains in
// effect until the next occurrence of SSW in the data stream or until it is
// reset to the default value by a subsequent occurrence of CARRIAGE
// RETURN/LINE FEED (CR/LF), CARRIAGE RETURN/FORM FEED (CR/FF), or of NEXT LINE
// (NEL) in the data stream, see annex C.
//
// Pn specifies the escapement.
//
// The unit in which the parameter value is expressed is that established by
// the parameter value of SELECT SIZE UNIT (SSU).
//
// The default character escapement of SPACE is specified by the most recent
// occurrence of SET CHARACTER SPACING (SCS) or of SELECT CHARACTER SPACING
// (SHS) or of SELECT SPACING INCREMENT (SPI) in the data stream if the current
// font has constant spacing, or is specified by the nominal width of the
// character SPACE in the current font if that font has proportional spacing.
var SSW_ = Sequence{
	Name:     "SSW",
	Desc:     "Set Space Width",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', '['},
}

// SS2 is used for code extension purposes. It causes the meanings of the bit
// combinations following it in the data stream to be changed.
//
// The use of SS2 is defined in Standard ECMA-35.
var SS2_ = Sequence{
	Name: "SS2",
	Desc: "Single-Shift Two",
	Type: ESC,
	Code: []byte{'N'},
}

// SS3 is used for code extension purposes. It causes the meanings of the bit
// combinations following it in the data stream to be changed.
//
// The use of SS3 is defined in Standard ECMA-35.
var SS3_ = Sequence{
	Name: "SS3",
	Desc: "Single-Shift Three",
	Type: ESC,
	Code: []byte{'O'},
}

// ST is used as the closing delimiter of a control string opened by
// APPLICATION PROGRAM COMMAND (APC), DEVICE CONTROL STRING (DCS), OPERATING
// SYSTEM COMMAND (OSC), PRIVACY MESSAGE (PM), or START OF STRING (SOS).
var ST_ = Sequence{
	Name: "ST",
	Desc: "String Terminator",
	Type: ESC,
	Code: []byte{'\\'},
}

// STAB causes subsequent text in the presentation component to be aligned
// according to the position and the properties of a tabulation stop which is
// selected from a list according to the value of the parameter Ps.
//
// The use of this control function and means of specifying a list of
// tabulation stops to be referenced by the control function are specified in
// other standards, for example ISO 8613-6.
var STAB_ = Sequence{
	Name:     "STAB",
	Desc:     "Selective Tabulation",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', '^'},
}

// STS is used to establish the transmit state in the receiving device. In this
// state the transmission of data from the device is possible.
//
// The actual initiation of transmission of data is performed by a data
// communication or input/output interface control procedure which is outside
// the scope of this Standard.
//
// The transmit state is established either by STS appearing in the received
// data stream or by the operation of an appropriate key on a keyboard.
var STS_ = Sequence{
	Name: "STS",
	Desc: "Set Transmit State",
	Type: ESC,
	Code: []byte{'S'},
}

// SU causes the data in the presentation component to be moved by n line
// positions if the line orientation is horizontal, or by n character positions
// if the line orientation is vertical, such that the data appear to move up;
// where n equals the value of Pn.
//
// The active presentation position is not affected by this control function.
var SU_ = Sequence{
	Name:     "SU",
	Desc:     "Scroll Up",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'S'},
}

// SVS is used to establish the line spacing for subsequent text. The
// established spacing remains in effect until the next occurrence of SVS or of
// SET LINE SPACING (SLS) or of SPACING INCREMENT (SPI) in the data stream. The
// parameter values are:
//
// 0 6 lines per 25,4 mm
//
// 1 4 lines per 25,4 mm
//
// 2 3 lines per 25,4 mm
//
// 3 12 lines per 25,4 mm
//
// 4 8 lines per 25,4 mm
//
// 5 6 lines per 30,0 mm
//
// 6 4 lines per 30,0 mm
//
// 7 3 lines per 30,0 mm
//
// 8 12 lines per 30,0 mm
//
// 9 2 lines per 25,4 mm
var SVS_ = Sequence{
	Name:     "SVS",
	Desc:     "Select Line Spacing",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{' ', 'L'},
}

// TAC causes a character tabulation stop calling for centring to be set at
// character position n in the active line (the line that contains the active
// presentation position) and lines of subsequent text in the presentation
// component, where n equals the value of Pn. TAC causes the replacement of any
// tabulation stop previously set at that character position, but does not
// affect other tabulation stops.
//
// A text string centred upon a tabulation stop set by TAC will be positioned
// so that the (trailing edge of the) first graphic character and the (leading
// edge of the) last graphic character are at approximately equal distances
// from the tabulation stop.
var TAC_ = Sequence{
	Name:     "TAC",
	Desc:     "Tabulation Aligned Centred",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', 'b'},
}

// TALE causes a character tabulation stop calling for leading edge alignment
// to be set at character position n in the active line (the line that contains
// the active presentation position) and lines of subsequent text in the
// presentation component, where n equals the value of Pn. TALE causes the
// replacement of any tabulation stop previously set at that character
// position, but does not affect other tabulation stops.
//
// A text string aligned with a tabulation stop set by TALE will be positioned
// so that the (leading edge of the) last graphic character of the string is
// placed at the tabulation stop.
var TALE_ = Sequence{
	Name:     "TALE",
	Desc:     "Tabulation Aligned Leading Edge",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', 'a'},
}

// TATE causes a character tabulation stop calling for trailing edge alignment
// to be set at character position n in the active line (the line that contains
// the active presentation position) and lines of subsequent text in the
// presentation component, where n equals the value of Pn. TATE causes the
// replacement of any tabulation stop previously set at that character
// position, but does not affect other tabulation stops.
//
// A text string aligned with a tabulation stop set by TATE will be positioned
// so that the (trailing edge of the) first graphic character of the string is
// placed at the tabulation stop.
var TATE_ = Sequence{
	Name:     "TATE",
	Desc:     "Tabulation Aligned Trailing Edge",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', '`'},
}

// TBC causes one or more tabulation stops in the presentation component to be
// cleared, depending on the parameter value:
//
// 0 the character tabulation stop at the active presentation position is
// cleared
//
// 1 the line tabulation stop at the active line is cleared
//
// 2 all character tabulation stops in the active line are cleared
//
// 3 all character tabulation stops are cleared
//
// 4 all line tabulation stops are cleared
//
// 5 all tabulation stops are cleared
//
// In the case of parameter value 0 or 2 the number of lines affected depends
// on the setting of the TABULATION STOP MODE (TSM)
var TBC_ = Sequence{
	Name:     "TBC",
	Desc:     "Tabulation Clear",
	Type:     CSI,
	Notation: "Ps",
	NParam:   1,
	Defaults: []string{"0"},
	Code:     []byte{'g'},
}

// TCC causes a character tabulation stop calling for alignment of a target
// graphic character to be set at character position n in the active line (the
// line that contains the active presentation position) and lines of subsequent
// text in the presentation component, where n equals the value of Pn1, and the
// target character about which centring is to be performed is specified by
// Pn2. TCC causes the replacement of any tabulation stop previously set at
// that character position, but does not affect other tabulation stops.
//
// The positioning of a text string aligned with a tabulation stop set by TCC
// will be determined by the first occurrence in the string of the target
// graphic character; that character will be centred upon the tabulation stop.
// If the target character does not occur within the string, then the trailing
// edge of the first character of the string will be positioned at the
// tabulation stop.
//
// The value of Pn2 indicates the code table position (binary value) of the
// target character in the currently invoked code. For a 7-bit code, the
// permissible range of values is 32 to 127; for an 8-bit code, the permissible
// range of values is 32 to 127 and 160 to 255.
var TCC_ = Sequence{
	Name:     "TCC",
	Desc:     "Tabulation Centred on Character",
	Type:     CSI,
	Notation: "Pn1;Pn2",
	NParam:   2,
	MinParam: 1,
	Defaults: []string{"", "32"},
	Code:     []byte{' ', 'c'},
}

// TSR causes any character tabulation stop at character position n in the
// active line (the line that contains the active presentation position) and
// lines of subsequent text in the presentation component to be cleared, but
// does not affect other tabulation stops. n equals the value of Pn.
var TSR_ = Sequence{
	Name:     "TSR",
	Desc:     "Tabulation Stop Remove",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', 'd'},
}

// TSS is used to establish the width of a thin space for subsequent text. The
// established width remains in effect until the next occurrence of TSS in the
// data stream, see annex C.
//
// Pn specifies the width of the thin space.
//
// The unit in which the parameter value is expressed is that established by
// the parameter value of SELECT SIZE UNIT (SSU).
var TSS_ = Sequence{
	Name:     "TSS",
	Desc:     "Thin Space Specification",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	MinParam: 1,
	Code:     []byte{' ', 'E'},
}

// VPA causes the active data position to be moved to line position n in the
// data component in a direction parallel to the line progression, where n
// equals the value of Pn.
var VPA_ = Sequence{
	Name:     "VPA",
	Desc:     "Line Position Absolute",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'d'},
}

// VPB causes the active data position to be moved by n line positions in the
// data component in a direction opposite to that of the line progression,
// where n equals the value of Pn.
var VPB_ = Sequence{
	Name:     "VPB",
	Desc:     "Line Position Backward",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'k'},
}

// VPR causes the active data position to be moved by n line positions in the
// data component in a direction parallel to the line progression, where n
// equals the value of Pn.
var VPR_ = Sequence{
	Name:     "VPR",
	Desc:     "Line Position Forward",
	Type:     CSI,
	Notation: "Pn",
	NParam:   1,
	Defaults: []string{"1"},
	Code:     []byte{'e'},
}

// VTS causes a line tabulation stop to be set at the active line (the line
// that contains the active presentation position).
var VTS_ = Sequence{
	Name: "VTS",
	Desc: "Line Tabulation Set",
	Type: ESC,
	Code: []byte{'J'},
}

// C0 is the 3-character escape sequence designating and invoking the C0 set.
//
// NOTE 1
//
// The use of this escape sequence implies that all control functions of this
// C0 set must be implemented.
//
// NOTE 2
//
// It is assumed that even with no invoked C0 set the control character ESCAPE
// is available and is represented by bit combination 01/11.
//
// This sequence is described, but not named in ECMA-48.
var C0_ = Sequence{
	Name: "C0",
	Desc: "Control Set 0 Announcer",
	Type: ESC,
	Code: []byte{'!', '@'},
}

// C1 is the 3-character escape sequence designating and invoking the C1 set.
//
// NOTE:
//
// The use of this escape sequence implies that all control characters of this
// C1 set must be implemented.
//
// This sequence is described, but not named in ECMA-48.
var C1_ = Sequence{
	Name: "C1",
	Desc: "Control Set 1 Announcer",
	Type: ESC,
	Code: []byte{'&', '@'},
}

// C1ALT1, according to Standard ECMA-35, announces the control functions of
// the C1 set are represented by ESC Fe sequences as in a 7-bit code.
//
// This sequence is described, but not named in ECMA-48.
var C1ALT1_ = Sequence{
	Name: "C1ALT1",
	Desc: "Control Set 1 Announcer Alternate 1",
	Type: ESC,
	Code: []byte{' ', 'F'},
}

// C1LAT2 is an alternate 3-character escape sequence designating and invoking
// the C1 set.
//
// NOTE:
//
// The use of this escape sequence implies that all control characters of this
// C1 set must be implemented.
//
// This sequence is described, but not named in ECMA-48.
var C1ALT2_ = Sequence{
	Name: "C1ALT2",
	Desc: "Control Set 1 Announcer Alternate 2",
	Type: ESC,
	Code: []byte{'"', 'F'},
}

// Table maps escape sequence Names to the corresponding Sequence.
// The sequence does not include parameters or string termination sequences.
var Table = map[Name]*Sequence{
	NUL:    &NUL_,
	SOH:    &SOH_,
	STX:    &STX_,
	ETX:    &ETX_,
	EOT:    &EOT_,
	ENQ:    &ENQ_,
	ACK:    &ACK_,
	BEL:    &BEL_,
	BS:     &BS_,
	HT:     &HT_,
	LF:     &LF_,
	VT:     &VT_,
	FF:     &FF_,
	CR:     &CR_,
	SO:     &SO_,
	SI:     &SI_,
	DLE:    &DLE_,
	DC1:    &DC1_,
	DC2:    &DC2_,
	DC3:    &DC3_,
	DC4:    &DC4_,
	NAK:    &NAK_,
	SYN:    &SYN_,
	ETB:    &ETB_,
	CAN:    &CAN_,
	EM:     &EM_,
	SUB:    &SUB_,
	ESC:    &ESC_,
	IS4:    &IS4_,
	IS3:    &IS3_,
	IS2:    &IS2_,
	IS1:    &IS1_,
	APC:    &APC_,
	"\237": &APC_,
	BPH:    &BPH_,
	"\202": &BPH_,
	CBT:    &CBT_,
	CCH:    &CCH_,
	"\224": &CCH_,
	CHA:    &CHA_,
	CHT:    &CHT_,
	CMD:    &CMD_,
	CNL:    &CNL_,
	CPL:    &CPL_,
	CPR:    &CPR_,
	CSI:    &CSI_,
	"\233": &CSI_,
	CTC:    &CTC_,
	CUB:    &CUB_,
	CUD:    &CUD_,
	CUF:    &CUF_,
	CUP:    &CUP_,
	CUU:    &CUU_,
	CVT:    &CVT_,
	DA:     &DA_,
	DAQ:    &DAQ_,
	DCH:    &DCH_,
	DCS:    &DCS_,
	"\220": &DCS_,
	DL:     &DL_,
	DMI:    &DMI_,
	DSR:    &DSR_,
	DTA:    &DTA_,
	EA:     &EA_,
	ECH:    &ECH_,
	ED:     &ED_,
	EF:     &EF_,
	EL:     &EL_,
	EMI:    &EMI_,
	EPA:    &EPA_,
	"\227": &EPA_,
	ESA:    &ESA_,
	"\207": &ESA_,
	FNK:    &FNK_,
	FNT:    &FNT_,
	GCC:    &GCC_,
	GSM:    &GSM_,
	GSS:    &GSS_,
	HPA:    &HPA_,
	HPB:    &HPB_,
	HPR:    &HPR_,
	HTJ:    &HTJ_,
	"\211": &HTJ_,
	HTS:    &HTS_,
	"\210": &HTS_,
	HVP:    &HVP_,
	ICH:    &ICH_,
	IDCS:   &IDCS_,
	IGS:    &IGS_,
	IL:     &IL_,
	INT:    &INT_,
	JFY:    &JFY_,
	LS1R:   &LS1R_,
	LS2:    &LS2_,
	LS2R:   &LS2R_,
	LS3:    &LS3_,
	LS3R:   &LS3R_,
	MC:     &MC_,
	MW:     &MW_,
	"\225": &MW_,
	NBH:    &NBH_,
	"\203": &NBH_,
	NEL:    &NEL_,
	"\205": &NEL_,
	NP:     &NP_,
	OSC:    &OSC_,
	"\235": &OSC_,
	PEC:    &PEC_,
	PFS:    &PFS_,
	PLD:    &PLD_,
	"\213": &PLD_,
	PLU:    &PLU_,
	"\214": &PLU_,
	PM:     &PM_,
	"\236": &PM_,
	PP:     &PP_,
	PPA:    &PPA_,
	PPB:    &PPB_,
	PPR:    &PPR_,
	PTX:    &PTX_,
	PU1:    &PU1_,
	"\221": &PU1_,
	PU2:    &PU2_,
	"\222": &PU2_,
	QUAD:   &QUAD_,
	REP:    &REP_,
	RI:     &RI_,
	"\215": &RI_,
	RIS:    &RIS_,
	RM:     &RM_,
	SACS:   &SACS_,
	SAPV:   &SAPV_,
	SCI:    &SCI_,
	"\232": &SCI_,
	SCO:    &SCO_,
	SCP:    &SCP_,
	SCS:    &SCS_,
	SD:     &SD_,
	SDS:    &SDS_,
	SEE:    &SEE_,
	SEF:    &SEF_,
	SGR:    &SGR_,
	SHS:    &SHS_,
	SIMD:   &SIMD_,
	SL:     &SL_,
	SLH:    &SLH_,
	SLL:    &SLL_,
	SLS:    &SLS_,
	SM:     &SM_,
	SOS:    &SOS_,
	"\230": &SOS_,
	SPA:    &SPA_,
	"\226": &SPA_,
	SPD:    &SPD_,
	SPH:    &SPH_,
	SPI:    &SPI_,
	SPL:    &SPL_,
	SPQR:   &SPQR_,
	SR:     &SR_,
	SRCS:   &SRCS_,
	SRS:    &SRS_,
	SSA:    &SSA_,
	"\206": &SSA_,
	SSU:    &SSU_,
	SSW:    &SSW_,
	SS2:    &SS2_,
	"\216": &SS2_,
	SS3:    &SS3_,
	"\217": &SS3_,
	ST:     &ST_,
	"\234": &ST_,
	STAB:   &STAB_,
	STS:    &STS_,
	"\223": &STS_,
	SU:     &SU_,
	SVS:    &SVS_,
	TAC:    &TAC_,
	TALE:   &TALE_,
	TATE:   &TATE_,
	TBC:    &TBC_,
	TCC:    &TCC_,
	TSR:    &TSR_,
	TSS:    &TSS_,
	VPA:    &VPA_,
	VPB:    &VPB_,
	VPR:    &VPR_,
	VTS:    &VTS_,
	"\212": &VTS_,
	C0:     &C0_,
	C1:     &C1_,
	C1ALT1: &C1ALT1_,
	C1ALT2: &C1ALT2_,
}
