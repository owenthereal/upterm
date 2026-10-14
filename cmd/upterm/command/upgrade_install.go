package command

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/owenthereal/upterm/internal/version"
	"golang.org/x/term"
)

// renameFile is os.Rename; a var so a test can fail one rename.
var renameFile = os.Rename

// binaryName is the file in a release archive that holds the upterm binary.
func binaryName(goos string) string {
	if goos == "windows" {
		return "upterm.exe"
	}

	return "upterm"
}

// installBinary takes the upterm binary at the root of the .tar.gz archive,
// writes it beside target as target+".new" and renames it over target. No
// other file in the archive is written, and whatever target is called, that
// is the file replaced. A failure leaves target as it was, with nothing left
// beside it. On Windows target is set aside as target+".old" first, since
// that is allowed while it runs; see replaceRunning.
func installBinary(archive, target, goos string) (err error) {
	tmp := target + ".new"
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()

	if err := extractBinary(archive, binaryName(goos), tmp); err != nil {
		return err
	}

	if goos == "windows" {
		return replaceRunning(tmp, target)
	}

	return renameFile(tmp, target)
}

// extractBinary writes the file named name at the root of the .tar.gz archive
// to dst.
func extractBinary(archive, name, dst string) error {
	f, err := os.Open(archive)
	if err != nil {
		return fmt.Errorf("opening the archive: %w", err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("reading the archive: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("the archive has no %s at its root", name)
		}
		if err != nil {
			return fmt.Errorf("reading the archive: %w", err)
		}

		if h.Name == name && h.Typeflag == tar.TypeReg {
			return writeExecutable(dst, tr)
		}
	}
}

// writeExecutable creates path, which must not exist or is replaced, with
// mode 0755 whatever the umask, and fills it from r. A file left by an
// interrupted install is removed first, so nothing is written through it.
func writeExecutable(path string, r io.Reader) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}

	err = f.Chmod(0o755)
	if err == nil {
		_, err = io.Copy(f, archiveReader{r})
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}

	return err
}

// archiveReader says "reading the archive" of the errors it gets from r, so
// io.Copy's can be told from those of writing the file.
type archiveReader struct{ io.Reader }

func (r archiveReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		err = fmt.Errorf("reading the archive: %w", err)
	}

	return n, err
}

// replaceRunning renames tmp over target, which may be running. Windows
// refuses to overwrite or delete a running .exe but lets it be renamed, so
// target is set aside as target+".old" first and the next upgrade removes it.
// If tmp can't take its place, target is put back.
func replaceRunning(tmp, target string) error {
	old := target + ".old"
	if err := renameFile(target, old); err != nil {
		return err
	}

	if err := renameFile(tmp, target); err != nil {
		if rerr := renameFile(old, target); rerr != nil {
			return fmt.Errorf("%w; the previous upterm is at %s and couldn't be put back: %v", err, old, rerr)
		}

		return err
	}

	return nil
}

// removeStaleOld removes the binary a previous upgrade set aside, which on
// Windows could not be deleted while it was running. It is only ever made
// there, so elsewhere a file by that name is not upterm's to remove.
func removeStaleOld(target, goos string) {
	if goos == "windows" {
		_ = os.Remove(target + ".old")
	}
}

// outcomeLine is what upgrade says for going from cur to next: which way it
// went, or that there was nowhere to go.
func outcomeLine(cur, next string) string {
	switch c := compareVersions(cur, next); {
	case c < 0:
		return fmt.Sprintf("Upgraded upterm %s to %s", cur, next)
	case c > 0:
		return fmt.Sprintf("Downgraded upterm %s to %s", cur, next)
	default:
		return fmt.Sprintf("upterm is already %s", cur)
	}
}

// compareVersions is negative when cur is older than next, positive when it is
// newer and zero when they are the same version. A dev build is older than any
// release, and a version that doesn't parse is older than one that does. Of
// two builds of one version, the one with build metadata (a source build marked
// +dirty, say) is not the release itself, and is the older.
func compareVersions(cur, next string) int {
	if cur == next {
		return 0
	}

	c, err := version.Parse(cur)
	if err != nil {
		return -1
	}

	n, err := version.Parse(next)
	if err != nil {
		return 1
	}

	if d := c.Compare(n); d != 0 {
		return d
	}

	switch {
	case c.Metadata() != "" && n.Metadata() == "":
		return -1
	case c.Metadata() == "" && n.Metadata() != "":
		return 1
	}

	return 0
}

// isTerminal reports whether f is a terminal, the only place cursor and
// progress escapes belong.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// hideCursorIfTerminal hides the cursor when f is a terminal and returns the
// function that shows it again. For anything else, a pipe or a file, it
// writes nothing and the function does nothing.
func hideCursorIfTerminal(f *os.File) func() {
	if !isTerminal(f) {
		return func() {}
	}

	_, _ = fmt.Fprint(f, "\033[?25l")

	return func() { _, _ = fmt.Fprint(f, "\033[?25h") }
}
