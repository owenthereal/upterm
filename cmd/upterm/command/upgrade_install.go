package command

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/owenthereal/upterm/internal/version"
	"golang.org/x/term"
)

// maxBinarySize is the most upgrade will write for the binary, in bytes. It
// is far above any real build, and keeps an archive that claims otherwise from
// filling the disk.
const maxBinarySize = 256 << 20

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
// writes it beside target under a name of its own (see uniqueFile) and renames
// it over target. No other file in the archive is written, and whatever target
// is called, that is the file replaced. The archive is read to its end first,
// so a damaged one replaces nothing. A failure leaves target as it was, with
// nothing left beside it, except on Windows when target can't be put back
// after being set aside (the rename that does so is allowed while it runs);
// see replaceRunning.
func installBinary(archive, target, goos string) (err error) {
	staged, err := uniqueFile(target, "new")
	if err != nil {
		return err
	}
	tmp := staged.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()

	err = extractBinary(archive, binaryName(goos), staged)
	if cerr := staged.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}

	if goos == "windows" {
		return replaceRunning(tmp, target)
	}

	return renameFile(tmp, target)
}

// uniqueFile creates and opens a new file beside target, named
// .<target's name>.<16 hex digits>.<ext>, with mode 0600. The name is taken
// only if no file has it, so every caller gets a file of its own: two upgrades
// running at once can't share one, and nothing that exists is opened,
// written through or replaced.
func uniqueFile(target, ext string) (*os.File, error) {
	dir, base := filepath.Dir(target), filepath.Base(target)

	for range 10 {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}

		name := "." + base + "." + hex.EncodeToString(random[:]) + "." + ext
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if !errors.Is(err, fs.ErrExist) {
			return f, err
		}
	}

	return nil, fmt.Errorf("no unused name beside %s", target)
}

// extractBinary writes the file named name at the root of the .tar.gz archive
// to dst, and reads the rest of the archive. It leaves dst open.
func extractBinary(archive, name string, dst *os.File) error {
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

		if h.Name != name || h.Typeflag != tar.TypeReg {
			continue
		}

		// The entry's reader yields no more than its header says.
		if h.Size > maxBinarySize {
			return fmt.Errorf("%s in the archive is over %d MiB", name, maxBinarySize>>20)
		}
		if err := writeExecutable(dst, tr); err != nil {
			return err
		}

		// The tar reader stops at the end of the entry, but gzip checks its
		// checksum and length only at the end of the stream.
		if _, err := io.Copy(io.Discard, gz); err != nil {
			return fmt.Errorf("reading the archive: %w", err)
		}

		return nil
	}
}

// writeExecutable gives f mode 0755 whatever the umask, fills it from r and
// syncs it. The caller closes it.
func writeExecutable(f *os.File, r io.Reader) error {
	if err := f.Chmod(0o755); err != nil {
		return err
	}

	if _, err := io.Copy(f, archiveReader{r}); err != nil {
		return err
	}

	// On disk before it is renamed into place, so a crash can't leave the
	// name pointing at a file that never got its contents.
	return f.Sync()
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
// target is set aside first, under a name of its own that the next upgrade
// removes (see removeStaleOld). If tmp can't take its place, target is put
// back.
func replaceRunning(tmp, target string) error {
	// The file reserves the name; renaming target onto it replaces it.
	reserved, err := uniqueFile(target, "old")
	if err != nil {
		return err
	}
	old := reserved.Name()
	if err := reserved.Close(); err != nil {
		_ = os.Remove(old)
		return err
	}

	if err := renameFile(target, old); err != nil {
		_ = os.Remove(old)
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

// removeStaleOld removes the binaries earlier upgrades set aside beside
// target, which on Windows could not be deleted while they were running. Only
// the files named as replaceRunning names them are removed: a backup a user
// keeps as target+".old" is not upterm's. They are only ever made on Windows,
// so elsewhere nothing is removed.
func removeStaleOld(target, goos string) {
	if goos != "windows" {
		return
	}

	dir := filepath.Dir(target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	setAside := regexp.MustCompile(`^\.` + regexp.QuoteMeta(filepath.Base(target)) + `\.[0-9a-f]{16}\.old$`)
	for _, e := range entries {
		if e.Type().IsRegular() && setAside.MatchString(e.Name()) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
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
