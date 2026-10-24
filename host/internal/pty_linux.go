package internal

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// preparePTYMaster transfers the master to a new Go File whose descriptor is
// nonblocking when it enters the runtime poller. Fd-based setup has marked the
// original File blocking; resetting its descriptor flags alone cannot undo that.
func preparePTYMaster(f *os.File) (*os.File, error) {
	defer func() { _ = f.Close() }()
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd int
	var dupErr error
	if err := rc.Control(func(original uintptr) {
		fd, dupErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0)
	}); err != nil {
		return nil, err
	}
	if dupErr != nil {
		return nil, dupErr
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	prepared := os.NewFile(uintptr(fd), f.Name())
	if err := prepared.SetWriteDeadline(time.Time{}); err != nil {
		_ = prepared.Close()
		return nil, err
	}
	return prepared, nil
}

// Close must reach the poller without waiting for a Read that Close releases.
func readPTY(p *pty, b []byte) (int, error) { return p.File.Read(b) }
func closePTY(p *pty) error                 { return p.File.Close() }

func initPTYInput(p *pty) { p.input = newPTYInput(p.File) }

func (p *pty) WriteContext(ctx context.Context, b []byte) (int, error) {
	return p.input.WriteContext(ctx, b)
}

func (p *pty) Write(b []byte) (int, error) {
	return p.WriteContext(context.Background(), b)
}
