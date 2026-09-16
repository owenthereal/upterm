//go:build linux

package internal

import "golang.org/x/sys/unix"

// tcgetpgrp returns the foreground process group of the terminal on fd.
//
// The 32-bit read, not IoctlGetInt: the kernel writes a 4-byte pid_t, and
// IoctlGetInt reads into a Go int. s390x is big-endian and a release
// architecture, and there the value would land in the high half of that int —
// so the comparison in ownsTerminal could never succeed and upterm would
// decide it never owns its terminal.
func tcgetpgrp(fd int) (int, error) {
	pgrp, err := unix.IoctlGetUint32(fd, unix.TIOCGPGRP)
	if err != nil {
		return 0, err
	}
	return int(pgrp), nil
}
