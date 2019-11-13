// Copyright 2014 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ansi

// Sepcials is a map of escape sequences to special processing functions.
// Special processing is done just prior to the Decode function returning.
// The special processing function takes two arugments, the slice of unprocessed
// bytes that followed the escape sequence, and the generated S structure for
// the sequence.  The function is free to modify the contents of S as well as
// consume additional bytes of data.  It returns any bytes not processed.
var Specials = map[Name]func([]byte, *S) []byte{
	SS2: grab1,
	SS3: grab1,
}

// grab1 grabs one byte from out and adds it as a parameter to the sequence.
// This function is to support the SS2 and SS3 escape sequences, each of which
// consume one additional byte.
func grab1(in []byte, s *S) []byte {
	if len(in) > 0 {
		s.Params = append(s.Params, string(in[0:1]))
		in = in[1:]
	}
	return in
}
