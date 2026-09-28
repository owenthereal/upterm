//go:build !windows

package sessiondir

import (
	"errors"
	"os"
	"syscall"
)

// tryLock takes an exclusive advisory lock without blocking. A lock held by
// someone else is reported as false, not as an error.
func tryLock(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return false, err
}

func unlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
