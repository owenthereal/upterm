//go:build windows

package tty

import (
	"os"

	"github.com/owenthereal/upterm/internal/termsize"
	"golang.org/x/term"
)

// Size reports f's geometry. It fails for anything that is not a terminal.
func Size(f *os.File) (termsize.Size, error) {
	w, h, err := term.GetSize(int(f.Fd()))
	if err != nil {
		return termsize.Size{}, err
	}
	return termsize.Size{Cols: w, Rows: h}, nil
}
