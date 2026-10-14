package command

import (
	"fmt"
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

// writableDir reports whether a file can be created beside path, which is
// what replacing it takes: the new binary is written next to the old one and
// renamed over it.
func writableDir(path string) bool {
	f, err := os.CreateTemp(filepath.Dir(path), ".upterm-writable-")
	if err != nil {
		return false
	}

	_ = f.Close()
	_ = os.Remove(f.Name())

	return true
}

// unwritableLine is what upgrade says when no package manager is known to own
// target and the directory it sits in can't be written. It names no installer,
// since upterm hasn't confirmed one.
func unwritableLine(target string) string {
	return fmt.Sprintf("can't replace %s: permission denied. If a package manager installed it, upgrade it there; otherwise rerun with permission to write %s", target, filepath.Dir(target))
}
