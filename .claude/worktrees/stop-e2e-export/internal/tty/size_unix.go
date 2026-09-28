//go:build !windows

package tty

import (
	"os"

	ptylib "github.com/creack/pty"
	"github.com/owenthereal/upterm/internal/termsize"
)

// Size reports f's geometry. It fails for anything that is not a terminal.
func Size(f *os.File) (termsize.Size, error) {
	rows, cols, err := ptylib.Getsize(f)
	if err != nil {
		return termsize.Size{}, err
	}
	return termsize.Size{Cols: cols, Rows: rows}, nil
}
