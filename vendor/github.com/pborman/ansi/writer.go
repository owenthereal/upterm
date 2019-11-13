// Copyright 2014 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ansi

import (
	"fmt"
	"io"
)

// A Writer is an io.Writer that adjusts its graphics state, if necessary,
// before writing to the stream.  It can used to easily emit colored text.
type Writer struct {
	fg        int    // foreground (text) color
	bg        int    // background color
	intensity int    // bold, faint, normal
	s         *state // underlying io.Writer and its current graphics state
}

// A state maintains state about a stream's actual graphic state.
type state struct {
	w         io.Writer
	fg        int // foreground (text) color
	bg        int // background color
	intensity int // bold, faint, normal
	nocolor   bool
}

// NewWriter returns a new Writer that maintains color and intensity.
// By using the attribute methods, the color and intensity of the text
// written can be changed.  For example:
//
//   w.Red().Bold().WriteString("This is in bold red")
//   w.Faint().WriteString("This text ix faint")
//
// These writers may also be saved:
//
//  red := w.Red().Bold()
//  blue := w.Blue()
//  normal := w.Reset()
//
//  red.WriteString("This is bold red text")
//  normal.WriteString("This is normal text")
//  blue.WriteString("This is blue text")
func NewWriter(w io.Writer) *Writer {
	return &Writer{s: &state{w: w}}
}

// NoColor turns off coloring. If text is currently colored the sequence
// to disable color is sent.
func (w *Writer) NoColor() {
	if !w.s.nocolor {
		if w.s.bg|w.s.fg|w.s.intensity != 0 {
			w.ForceReset()
		}
		w.s.nocolor = true
	}
}

// Colorize enables coloring.
func (w *Writer) Colorize() {
	if w.s.nocolor {
		w.s.nocolor = false
		w.Set()
	}
}

// Write writes in to w, prefixing it with an SGR escape sequence, if
// necessary.  It returns the total number of bytes written and any
// error encountered while writing.
func (w *Writer) Write(in []byte) (int, error) {
	p := w.s // primary Writer
	if p.nocolor {
		return p.w.Write(in)
	}
	var modes []byte

	if p.bg|p.fg|p.intensity != 0 && w.bg|w.fg|w.intensity == 0 {
		p.bg = 0
		p.fg = 0
		p.intensity = 0
		modes = []byte{'0'}
	}
	if p.intensity != w.intensity {
		if len(modes) > 0 {
			modes = append(modes, ';')
		}
		if w.intensity == 0 {
			w.intensity = NormalColor
		}
		// It appears that if we are faint then the bold attribute
		// does not take, so we need to clear the intensity before
		// changing to bold.  I am making the assumption that higher
		// intensity values take precedence over lower ones.
		if p.intensity > w.intensity && p.intensity != NormalColor {
			modes = append(append(modes, itoa(NormalColor)...), ';')
		}
		modes = append(modes, itoa(w.intensity)...)
		p.intensity = w.intensity
	}
	if p.fg != w.fg {
		if len(modes) > 0 {
			modes = append(modes, ';')
		}
		fg := w.fg
		if fg == 0 {
			fg = Default
		}
		modes = append(modes, itoa(fg)...)
		p.fg = fg
	}
	if p.bg != w.bg {
		if len(modes) > 0 {
			modes = append(modes, ';')
		}
		bg := w.bg
		if bg == 0 {
			bg = DefaultBackground
		}
		modes = append(modes, itoa(bg)...)
		p.bg = bg
	}
	if len(modes) > 0 {
		modes = append(append([]byte{'\033', '['}, modes...), 'm')
		in = append(modes, in...)
	}
	return p.w.Write(in)
}

// WriteString writes in to w, prefixing it with an SGR escape sequence, if
// necessary, and appending an SGR escape sequence to reset the graphics
// state to what it was before the call to WriteString.
func (w *Writer) WriteString(in string) (int, error) {
	old := &Writer{
		s:         w.s,
		fg:        w.s.fg,
		bg:        w.s.bg,
		intensity: w.s.intensity,
	}
	n, err := w.Write([]byte(in))
	if err != nil {
		return n, err
	}
	n2, err := old.Set()
	return n + n2, err

}

// Set writes, if necessary, the SGR escape sequence to w to set the current
// graphics mode.
func (w *Writer) Set() (int, error) { return w.Write(nil) }

// ForceSet writes the SGR escape sequence to w
func (w *Writer) ForceSet() (int, error) {
	w = w.copy()
	w.s.bg = -1
	w.s.fg = -1
	w.s.intensity = -1
	return w.Write(nil)
}

// SetColor returns a Writer that sets the drawing color to color.
func (w *Writer) SetColor(fg int) *Writer {
	if fg < 30 || fg > 39 {
		return w // invalid foreground color
	}
	if w.fg == fg {
		return w
	}
	w = w.copy()
	w.fg = fg
	return w
}

// SetBackground returns a Writer that sets the background color to color.
func (w *Writer) SetBackground(bg int) *Writer {
	// Convert foreground colors into background colors so Black
	// can be passed as well as BlackBackground
	if bg >= 30 && bg <= 39 {
		bg += 10
	}
	if bg < 40 || bg > 49 {
		return w // invalid background color
	}
	if w.bg == bg {
		return w
	}
	w = w.copy()
	w.bg = bg
	return w
}

// SetIntensity returns a Writer that sets the intensity to intensity.
func (w *Writer) SetIntensity(intensity int) *Writer {
	switch intensity {
	case Bold, Faint, NormalColor:
	case Default:
		intensity = NormalColor
	default:
		return w
	}
	if w.intensity == intensity {
		return w
	}
	w = w.copy()
	w.intensity = intensity
	return w
}

func (w *Writer) Black() *Writer   { return w.SetColor(Black) }
func (w *Writer) Red() *Writer     { return w.SetColor(Red) }
func (w *Writer) Green() *Writer   { return w.SetColor(Green) }
func (w *Writer) Yellow() *Writer  { return w.SetColor(Yellow) }
func (w *Writer) Blue() *Writer    { return w.SetColor(Blue) }
func (w *Writer) Magenta() *Writer { return w.SetColor(Magenta) }
func (w *Writer) Cyan() *Writer    { return w.SetColor(Cyan) }
func (w *Writer) White() *Writer   { return w.SetColor(White) }

// Default returns a Writer that sets the text color to the default.
func (w *Writer) Default() *Writer { return w.SetColor(Default) }

func (w *Writer) Bold() *Writer  { return w.SetIntensity(Bold) }
func (w *Writer) Faint() *Writer { return w.SetIntensity(Faint) }

// Normal returns a Writer that sets the intensity to normal (not faint or
// bold).
func (w *Writer) Normal() *Writer { return w.SetIntensity(NormalColor) }

// Reset returns a Writer that resets all graphics modes.
func (w *Writer) Reset() *Writer {
	if w.bg|w.fg|w.intensity == 0 {
		return w
	}
	w = w.copy()
	w.intensity = 0
	w.fg = 0
	w.bg = 0
	return w
}

// ForceReset forces an SGR escape sequence to set the graphics mode back
// to the default.
func (w *Writer) ForceReset() {
	w.s.bg = -1
	w.s.fg = -1
	w.s.intensity = -1
	w.Reset().Set()
}

// copy returns a new copy of w with its p pointer pointing to the original
// writer.
func (w *Writer) copy() *Writer {
	n := *w
	return &n
}

func (w *Writer) Print(a ...interface{}) (int, error) {
	return fmt.Fprint(w, a...)
}

func (w *Writer) Printf(format string, a ...interface{}) (int, error) {
	return fmt.Fprintf(w, format, a...)
}

func (w *Writer) Println(a ...interface{}) (int, error) {
	return fmt.Fprintln(w, a...)
}
