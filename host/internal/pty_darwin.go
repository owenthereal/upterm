//go:build darwin

package internal

import "golang.org/x/sys/unix"

// FlushOutput discards the tty's output queue: bytes the command wrote that
// nothing has read off the master. XNU will not let a session leader finish
// exiting while its controlling terminal's output queue holds anything
// (proc_exit's ttywait), so terminate calls this just before it closes the
// master; see terminate for why the close alone cannot release that leader
// while a client's input write is parked on the master. The input queue is
// left alone -- that parked write is what the leader's exit, once it
// completes, fails.
//
// Through control, never the RWMutex: an abandoned read holds the read lock
// and a pending Close is queued for the write lock, and a flush that waited
// on either would stall the very escalation it exists to unstick. Once the
// close reaches the file, control reports os.ErrClosed; until then a read
// still parked on the master takes whatever is queued. Either way a later
// flush would have nothing useful to do, which is why terminate flushes
// before the close and never after it.
func (pty *pty) FlushOutput() error {
	// FWRITE from <sys/fcntl.h>, which x/sys/unix does not export:
	// TIOCFLUSH's selector for the output queue alone.
	const fwrite = 0x2
	return pty.control(func(fd uintptr) error {
		return unix.IoctlSetPointerInt(int(fd), unix.TIOCFLUSH, fwrite)
	})
}
