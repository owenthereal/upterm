// Copyright 2014 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ansi

// SGR (SELECT GRAPHIC RENDITION) parameters.
// SGR is most commonly used to set the color of the text.
const (
	Normal = iota
	Bold   // bold or increased intensity
	Faint  // faint, decreased intensity or second colour
	Italics
	Underline
	Blink
	FastBlink
	Inverse
	Hidden
	Strikeout
	PrimaryFont
	AltFont1
	AltFont2
	AltFont3
	AltFont4
	AltFont5
	AltFont6
	AltFont7
	AltFont8
	AltFont9
	Gothic // fraktur
	DoubleUnderline
	NormalColor // normal colour or normal intensity (neither bold nor faint)
	NotItalics  // not italicized, not fraktur
	NotUnderlined
	Steady     // not Blink or FastBlink
	Reserved26 // reserved for proportional spacing as specified in CCITT Recommendation T.61
	NotInverse // Positive
	NotHidden  // Revealed
	NotStrikeout
	Black
	Red
	Green
	Yellow
	Blue
	Magenta
	Cyan
	White
	Reserved38 // intended for setting character foreground colour as specified in ISO 8613-6 [CCITT Recommendation T.416]
	Default    // default display colour (implementation-defined)
	BlackBackground
	RedBackground
	GreenBackground
	YellowBackground
	BlueBackground
	MagentaBackground
	CyanBackground
	WhiteBackground
	Reserved48        // reserved for future standardization; intended for setting character background colour as specified in ISO 8613-6 [CCITT Recommendation T.416]
	DefaultBackground // default background colour (implementation-defined)
	Reserved50        // reserved for cancelling the effect of the rendering aspect established by parameter value 26
	Framed
	Encircled
	Overlined
	NotFramed // NotEncircled
	NotOverlined
	Reserved56
	Reserved57
	Reserved58
	Reserved59
	IdeogramUnderline       // ideogram underline or right side line
	IdeogramDoubleUnderline // ideogram double underline or double line on the right side
	IdeogramOverline        // ideogram overline or left side line
	IdeogramDoubleOverline  // ideogram double overline or double line on the left side
	IdeogramStress          // ideogram stress marking
	IdeogramCancel          // cancels the effect of the rendition aspects established by parameter values IdeogramUnderline to IdeogramStress
	reserved66              // This should be 66
)

// Preformated escape sequences for specific colors:
const (
	NormalText       = "\033[0m" // Turn off all attributes
	BlackText        = "\033[30m"
	RedText          = "\033[31m"
	GreenText        = "\033[32m"
	YellowText       = "\033[33m"
	BlueText         = "\033[34m"
	MagentaText      = "\033[35m"
	CyanText         = "\033[36m"
	WhiteText        = "\033[37m"
	DefaultColorText = "\033[39m" // Normal text color
	BoldText         = "\033[1m"
	BoldBlackText    = "\033[1;30m"
	BoldRedText      = "\033[1;31m"
	BoldGreenText    = "\033[1;32m"
	BoldYellowText   = "\033[1;33m"
	BoldBlueText     = "\033[1;34m"
	BoldMagentaText  = "\033[1;35m"
	BoldCyanText     = "\033[1;36m"
	FaintText        = "\033[2m"
	FaintBlackText   = "\033[2;30m"
	FaintRedText     = "\033[2;31m"
	FaintGreenText   = "\033[2;32m"
	FaintYellowText  = "\033[2;33m"
	FaintBlueText    = "\033[2;34m"
	FaintMagentaText = "\033[2;35m"
	FaintCyanText    = "\033[2;36m"
	FaintWhiteText   = "\033[2;37m"
	DefaultText      = "\033[22;39m" // Normal text color and intensity
)

// SM (SET MODE) an RM (RESET MODE) parameters
const (
	GATM = 1  // GUARDED AREA TRANSFER MODE
	KAM  = 2  // KEYBOARD ACTION MODE
	CRM  = 3  // CONTROL REPRESENTATION MODE
	IRM  = 4  // INSERTION REPLACEMENT MODE
	SRTM = 5  // STATUS REPORT TRANSFER MODE
	ERM  = 6  // ERASURE MODE
	VEM  = 7  // LINE EDITING MODE
	BDSM = 8  // BI-DIRECTIONAL SUPPORT MODE
	DCSM = 9  // DEVICE COMPONENT SELECT MODE
	HEM  = 10 // CHARACTER EDITING MODE
	PUM  = 11 // POSITIONING UNIT MODE (see F.4.1 in annex F)
	SRM  = 12 // SEND/RECEIVE MODE
	FEAM = 13 // FORMAT EFFECTOR ACTION MODE
	FETM = 14 // FORMAT EFFECTOR TRANSFER MODE
	MATM = 15 // MULTIPLE AREA TRANSFER MODE
	TTM  = 16 // TRANSFER TERMINATION MODE
	SATM = 17 // SELECTED AREA TRANSFER MODE
	TSM  = 18 // TABULATION STOP MODE
	GRCM = 21 // GRAPHIC RENDITION COMBINATION
	ZDM  = 22 // ZERO DEFAULT MODE (see F.4.2 in annex F)
)
