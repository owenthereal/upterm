package command

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// runningBinary is the file upgrade replaces: this process's executable with
// symlinks resolved. PATH is never consulted; the first upterm on it may be
// another copy. A var so tests never point upgrade at the test binary.
var runningBinary = func() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}

	return resolveTarget(exe)
}

// resolveTarget is path with its symlinks resolved, so a link in bin/ is
// replaced through, not instead of, the file it points to.
func resolveTarget(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

// writableDir returns nil when a file can be created beside path, which is
// what replacing it takes: the new binary is written next to the old one and
// renamed over it. Otherwise it returns why not. A var so a test can make
// any directory fail for any reason.
var writableDir = func(path string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".upterm-writable-")
	if err != nil {
		return err
	}

	_ = f.Close()
	_ = os.Remove(f.Name())

	return nil
}

// unwritableLine is what upgrade says when no package manager is known to own
// target and writableDir failed with err. It names no installer, since upterm
// hasn't confirmed one. Only a permission error earns the advice about
// package managers and permission; for any other cause (a read-only file
// system, a full disk) that advice would be a guess, so the line gives the
// system's reason alone.
func unwritableLine(target string, err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Sprintf("can't replace %s: permission denied. If a package manager installed it, upgrade it there; otherwise rerun with permission to write %s", target, filepath.Dir(target))
	}

	// The reason is the system's, not the *PathError around it, which
	// names upterm's temporary file.
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}

	return fmt.Sprintf("can't replace %s: %s", target, err)
}
