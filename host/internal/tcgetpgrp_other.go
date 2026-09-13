//go:build !linux && !windows

package internal

import "golang.org/x/sys/unix"

// tcgetpgrp returns the foreground process group of the terminal on fd.
//
// IoctlGetInt reads into a Go int, which is wider than the 4-byte pid_t the
// kernel writes. That is exact here because every non-Linux target upterm
// ships is little-endian — darwin on amd64 and arm64 — so the pid_t lands in
// the low half of a zeroed int. Linux uses the 32-bit read instead, because
// s390x is big-endian and is a release architecture there.
func tcgetpgrp(fd int) (int, error) {
	return unix.IoctlGetInt(fd, unix.TIOCGPGRP)
}
