package command

import (
	"os"

	"golang.org/x/sys/windows"
)

// echoOff is passphrasePrompt.echoOff for the console f. It clears
// ENABLE_ECHO_INPUT, and keeps the line read whole and Ctrl-C a signal, as
// term.ReadPassword does. The restore puts back the mode it found.
func echoOff(f *os.File) func() (func(), error) {
	return func() (func(), error) {
		h := windows.Handle(f.Fd())
		var mode uint32
		if err := windows.GetConsoleMode(h, &mode); err != nil {
			return nil, err
		}
		quiet := mode&^windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT | windows.ENABLE_LINE_INPUT
		if err := windows.SetConsoleMode(h, quiet); err != nil {
			return nil, err
		}
		return func() { _ = windows.SetConsoleMode(h, mode) }, nil
	}
}
