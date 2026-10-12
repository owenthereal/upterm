//go:build !windows

package command

import (
	"os"

	"golang.org/x/sys/unix"
)

// lineEndsCRLF is passphrasePrompt.crlf: with ICRNL, which echoOff sets,
// the terminal's Enter is '\n' alone.
const lineEndsCRLF = false

// echoOff is passphrasePrompt.echoOff for the terminal f. It clears ECHO,
// and keeps the line read whole and Ctrl-C a signal, as term.ReadPassword
// does; in the cooked mode a prompt runs in, that changes nothing else. The
// restore puts back the modes it found.
func echoOff(f *os.File) func() (func(), error) {
	return func() (func(), error) {
		fd := int(f.Fd())
		orig, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
		if err != nil {
			return nil, err
		}
		quiet := *orig
		quiet.Lflag &^= unix.ECHO
		quiet.Lflag |= unix.ICANON | unix.ISIG
		quiet.Iflag |= unix.ICRNL
		if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, &quiet); err != nil {
			return nil, err
		}
		return func() { _ = unix.IoctlSetTermios(fd, ioctlWriteTermios, orig) }, nil
	}
}
