// Copyright 2014 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ansi

import "strconv"

// itoa converts the binary value n into an ascii byte slice.  Negative
// values produce an empty slice.
func itoa(n int) []byte {
	if n < 0 {
		return []byte{}
	}
	return []byte(strconv.Itoa(n))
}

// Format formats the escape sequence s with the provided parameters.
// If more parameters are provided than required, the extra parameters
// are silently ignored.
// TODO(borman): add support for non-numeric parameters, multi-part parameters
// and extension parameters.
func (s *Sequence) Format(params ...int) []byte {
	b := make([]byte, 0, 16) // Most sequences are under 16 bytes
	switch s.Type {
	case ESC:
		b = append(b, '\033')
	case CSI:
		b = append(b, '\033', '[')
	}
	if s.NParam >= 0 && len(params) > s.NParam {
		params = params[:s.NParam]
	}
	if len(params) > 0 {
		b = append(b, itoa(params[0])...)
		for _, p := range params[1:] {
			b = append(b, ';')
			b = append(b, itoa(p)...)
		}
	}
	return append(b, s.Code...)
}
