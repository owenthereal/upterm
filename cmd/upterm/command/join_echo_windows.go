package command

import (
	"os"

	"golang.org/x/sys/windows"
)

// lineEndsCRLF is passphrasePrompt.crlf: the console's line input, which
// echoOff keeps, hands a line over with its Enter as "\r\n".
const lineEndsCRLF = true

// echoOff is passphrasePrompt.echoOff for the console f. It clears
// ENABLE_ECHO_INPUT. It sets ENABLE_LINE_INPUT, so that the console edits the
// line and hands it over whole, and ENABLE_PROCESSED_INPUT, so that Ctrl-C is
// a signal. term.ReadPassword clears line input instead and edits the line
// itself. The restore puts back the mode it found.
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
