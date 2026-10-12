package command

import (
	"os"

	"golang.org/x/sys/windows"
)

// flushInput drops what was typed at the console f and not yet read.
func flushInput(f *os.File) error {
	return windows.FlushConsoleInputBuffer(windows.Handle(f.Fd()))
}
