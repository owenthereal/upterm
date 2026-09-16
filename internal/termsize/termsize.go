// Package termsize is a terminal geometry shared by the CLI and the host. It
// lives at the module root's internal/ rather than under host/internal so that
// cmd/ may import it: Go's internal rule confines host/internal to the tree
// under host/.
package termsize

import (
	"fmt"
	"strconv"
	"strings"
)

// Max is the largest dimension a pty winsize can carry: both fields are
// uint16 on every platform this runs on.
const Max = 65535

// Default is the geometry a session opens with when nothing better is known.
// 80x24 is the only size every terminal application copes with.
var Default = Size{Cols: 80, Rows: 24}

// Size is a terminal geometry. The zero value means "unspecified".
type Size struct {
	Cols, Rows int
}

// Valid reports whether both dimensions are usable. A half-specified size is
// not a size: opening a zero-column pty is worse than falling back.
func (s Size) Valid() bool {
	return s.Cols > 0 && s.Rows > 0 && s.Cols <= Max && s.Rows <= Max
}

func (s Size) String() string { return fmt.Sprintf("%dx%d", s.Cols, s.Rows) }

// Parse reads a COLSxROWS geometry.
func Parse(s string) (Size, error) {
	cols, rows, ok := strings.Cut(s, "x")
	if !ok {
		return Size{}, fmt.Errorf("invalid size %q: want COLSxROWS, e.g. 132x43", s)
	}

	c, err := dimension(cols)
	if err != nil {
		return Size{}, fmt.Errorf("invalid size %q: columns: %w", s, err)
	}
	r, err := dimension(rows)
	if err != nil {
		return Size{}, fmt.Errorf("invalid size %q: rows: %w", s, err)
	}

	return Size{Cols: c, Rows: r}, nil
}

func dimension(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("must be an integer")
	}
	if n <= 0 {
		return 0, fmt.Errorf("must be positive")
	}
	if n > Max {
		return 0, fmt.Errorf("must be at most %d", Max)
	}
	return n, nil
}
