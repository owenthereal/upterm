//go:build windows

package sessiondir

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// readFileShareDelete reads a file without preventing its replacement.
//
// os.ReadFile goes through syscall.Open, which omits FILE_SHARE_DELETE, so an
// overlapping reader makes the publisher's rename fail. Opening with all three
// share modes lets a reader and an atomic replacement coexist, which is the
// behavior every other platform gives for free.
func readFileShareDelete(path string) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	h, err := windows.CreateFile(
		p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		// Map to the errors callers already branch on, notably os.IsNotExist.
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	f := os.NewFile(uintptr(h), path)
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}
